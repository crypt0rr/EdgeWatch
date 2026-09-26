package web

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// defaultTenantStore returns the store of the default tenant, the tenant
// that every session resolves to while there is one tenant. Tests that call
// a handler directly pass it where the API router passes the request's
// tenant store.
func defaultTenantStore(server *Server) *store.TenantStore {
	return server.Store.Tenant(store.DefaultTenantScope())
}

// crossTenantScopeUses returns the places in the source where web code
// reaches past the session's tenant: the daemon's cross-tenant store
// (Store.System) and the host scope lookup (Store.TenantScopeByID).
func crossTenantScopeUses(fset *token.FileSet, file *ast.File) []string {
	var uses []string
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "System", "TenantScopeByID":
			uses = append(uses, fset.Position(selector.Sel.Pos()).String()+": "+selector.Sel.Name)
		}
		return true
	})
	return uses
}

// Web handlers take their tenant from the session through requestTenant.
// The daemon's cross-tenant store and the host scope lookup would let a
// request choose another tenant's data, so no web code may use them.
func TestWebCodeUsesOnlyTheSessionTenant(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var uses []string
	checked := 0
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		uses = append(uses, crossTenantScopeUses(fset, file)...)
	}
	if checked == 0 {
		t.Fatal("no web source files were checked")
	}
	sort.Strings(uses)
	for _, use := range uses {
		t.Errorf("%s: web code must use the tenant store from requestTenant, not the daemon or host scopes", use)
	}
}

// The check finds both kinds of use, so a clean result above means
// something.
func TestCrossTenantScopeCheckFindsUses(t *testing.T) {
	const source = `package web

func leak(s *Server) {
	_ = s.Store.System()
	_, _ = s.Store.TenantScopeByID(nil, "other")
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "leak.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	uses := crossTenantScopeUses(fset, file)
	if len(uses) != 2 || !strings.HasSuffix(uses[0], ": System") || !strings.HasSuffix(uses[1], ": TenantScopeByID") {
		t.Fatalf("uses = %q, want System and TenantScopeByID", uses)
	}
}

// Every role resolves to the default tenant, and the handlers that read
// tenant data receive its store. An account without an active tenant is
// refused before any such handler runs, while its own account routes keep
// working. A failed lookup is an internal error rather than an empty tenant.
// The cases share one server, because opening a database is the slow part.
func TestRequestTenant(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{Name: "tenant-job", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}})
	if _, err := db.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	sessions := map[string]store.Session{store.RoleAdministrator: admin}
	for _, role := range []string{store.RoleOperator, store.RoleViewer} {
		user, err := db.CreateUser(ctx, store.User{Username: "tenant-" + role, DisplayName: role, Role: role, PasswordHash: "unused-hash", Enabled: true}, store.AuditEntry{})
		if err != nil {
			t.Fatal(err)
		}
		sessions[role] = store.Session{UserID: user.ID, Username: user.Username, Role: role}
	}
	for role, session := range sessions {
		ts, ok := server.requestTenant(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil), session)
		if !ok {
			t.Fatalf("%s: no tenant store", role)
		}
		jobs, err := ts.ListJobs(ctx, false)
		if err != nil || len(jobs) != 1 || jobs[0].Job.Name != "tenant-job" {
			t.Fatalf("%s: jobs = %+v, %v", role, jobs, err)
		}
	}

	raw := "tenant-api-session"
	now := time.Now().UTC()
	if err := db.CreateSessionForUserWithAudit(ctx, admin.UserID, digest(raw), "tenant-csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	call := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.AddCookie(&http.Cookie{Name: "edgewatch_session", Value: raw})
		req.Header.Set("X-CSRF-Token", "tenant-csrf")
		rec := httptest.NewRecorder()
		server.api(rec, req)
		return rec
	}
	if rec := call(http.MethodGet, "/api/v1/jobs"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "tenant-job") {
		t.Fatalf("active tenant: GET /jobs = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE tenants SET state='disabled' WHERE id=?`, store.DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/jobs", "/api/v1/jobs/schedule-suggestion?schedule=0+*+*+*+*&timezone=UTC", "/api/v1/status"} {
		rec := call(http.MethodGet, path)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"forbidden"`) {
			t.Fatalf("disabled tenant: GET %s = %d: %s", path, rec.Code, rec.Body.String())
		}
	}
	if rec := call(http.MethodPost, "/api/v1/auth/activity"); rec.Code != http.StatusNoContent {
		t.Fatalf("disabled tenant: account activity = %d: %s", rec.Code, rec.Body.String())
	}

	platform := httptest.NewRecorder()
	if _, ok := server.requestTenant(platform, httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil), store.Session{UserID: "platform", Role: store.RolePlatformAdmin}); ok || platform.Code != http.StatusForbidden {
		t.Fatalf("platform administrator = %d, %v", platform.Code, ok)
	}

	_ = db.Close()
	closed := httptest.NewRecorder()
	if _, ok := server.requestTenant(closed, httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil), admin); ok || closed.Code != http.StatusInternalServerError {
		t.Fatalf("closed store = %d, %v", closed.Code, ok)
	}
}
