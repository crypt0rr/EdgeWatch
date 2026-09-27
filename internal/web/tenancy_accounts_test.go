package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// cheapPasswordHash returns an Argon2id hash of the password with the least
// work that password verification accepts, so a test can confirm passwords
// many times without the cost of the production parameters.
func cheapPasswordHash(password string) string {
	salt := []byte("tenant-accounts-salt")
	key := argon2.IDKey([]byte(password), salt, 1, 8, 1, 32)
	encoding := base64.RawStdEncoding
	return fmt.Sprintf("$ew$argon2id$v=19$m=8,t=1,p=1$%s$%s", encoding.EncodeToString(salt), encoding.EncodeToString(key))
}

const (
	// tenantAccountsOtherID is the second tenant of the accounts fixture.
	tenantAccountsOtherID = "00000000-0000-0000-0000-000000000200"
	// tenantAccountsPassword is the administrators' password.
	tenantAccountsPassword = "administrator password"
)

// tenantAccountsFixture is a server with two tenants. The default tenant,
// "own", has an administrator and an operator; the other tenant has an
// administrator and a viewer. Each administrator and the operator are
// signed in, under the account names "own", "other", and "operator".
type tenantAccountsFixture struct {
	server                             *Server
	db                                 *store.Store
	own, other                         *store.TenantStore
	adminA, operatorA, adminB, viewerB store.User
	cookies                            map[string]string
}

func newTenantAccountsFixture(t *testing.T) tenantAccountsFixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	application, err := app.New(cfg, db, "missing-nmap", logger)
	if err != nil {
		t.Fatal(err)
	}
	f := tenantAccountsFixture{server: NewServer(application, db, logger), db: db, cookies: map[string]string{}}
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, tenantAccountsOtherID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	f.own = defaultTenantStore(f.server)
	otherScope, err := db.TenantScopeByID(ctx, tenantAccountsOtherID)
	if err != nil {
		t.Fatal(err)
	}
	f.other = db.Tenant(otherScope)
	hash := cheapPasswordHash(tenantAccountsPassword)
	create := func(ts *store.TenantStore, username, role, passwordHash string) store.User {
		t.Helper()
		user, err := ts.CreateUser(ctx, store.User{Username: username, Role: role, PasswordHash: passwordHash, Enabled: true}, store.AuditEntry{})
		if err != nil {
			t.Fatal(err)
		}
		return user
	}
	f.adminA = create(f.own, "admin-a", store.RoleAdministrator, hash)
	f.operatorA = create(f.own, "operator-a", store.RoleOperator, "unused-hash")
	f.adminB = create(f.other, "admin-b", store.RoleAdministrator, hash)
	f.viewerB = create(f.other, "viewer-b", store.RoleViewer, "unused-hash")
	for name, userID := range map[string]string{"own": f.adminA.ID, "other": f.adminB.ID, "operator": f.operatorA.ID} {
		raw := "tenant-accounts-" + name
		if err := db.CreateSessionForUserWithAudit(ctx, userID, digest(raw), "csrf-"+name, now, now.Add(time.Hour), "", ""); err != nil {
			t.Fatal(err)
		}
		f.cookies[name] = raw
	}
	enrollAdministratorsInTOTP(t, db)
	return f
}

// call sends an API request as the signed-in account.
func (f tenantAccountsFixture) call(account, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9000"
	req.AddCookie(&http.Cookie{Name: "edgewatch_session", Value: f.cookies[account]})
	req.Header.Set("X-CSRF-Token", "csrf-"+account)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.server.api(rec, req)
	return rec
}

// The /users routes and the account's own routes act only on the session's
// tenant. An administrator of another tenant does not see the first
// tenant's accounts in the list, and every route on one of them is not
// found, with the same response as an unknown ID; the account, its
// sessions, its links, and the first tenant's audit are unchanged. A
// username that the first tenant holds is not available, without naming the
// tenant. The second tenant's own account routes, self-service, and job
// writes work, and their audit records belong to it.
func TestUserRoutesUseTheSessionTenant(t *testing.T) {
	ctx := context.Background()
	f := newTenantAccountsFixture(t)
	db, own, call := f.db, f.own, f.call
	adminA, operatorA, viewerB := f.adminA, f.operatorA, f.viewerB
	const unknownUserID = "00000000-0000-0000-0000-00000000dead"
	password := tenantAccountsPassword
	now := time.Now().UTC()
	if err := own.CreateUserInvite(ctx, "invite-operator-a", operatorA.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	count := func(query string, args ...any) int {
		t.Helper()
		var n int
		if err := db.DB.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// snapshot holds what a route could change on tenant A's operator:
	// the account, its sessions and links, and tenant A's audit.
	snapshot := func() []any {
		t.Helper()
		user, err := own.GetUser(ctx, operatorA.ID)
		if err != nil {
			t.Fatal(err)
		}
		return []any{
			user.Summary(),
			count(`SELECT COUNT(*) FROM sessions WHERE user_id=?`, operatorA.ID),
			count(`SELECT COUNT(*) FROM user_invites WHERE user_id=? AND used_at IS NULL`, operatorA.ID),
			count(`SELECT COUNT(*) FROM security_audit WHERE tenant_id=?`, store.DefaultTenantID),
		}
	}
	lastAudit := func(action string) [2]string {
		t.Helper()
		var record [2]string
		if err := db.DB.QueryRowContext(ctx, `SELECT COALESCE(tenant_id,'<null>'),actor_kind FROM security_audit WHERE action=? ORDER BY id DESC LIMIT 1`, action).Scan(&record[0], &record[1]); err != nil {
			t.Fatalf("audit record %s: %v", action, err)
		}
		return record
	}
	listed := func(account string) []string {
		t.Helper()
		rec := call(account, http.MethodGet, "/api/v1/users", "")
		var body struct {
			Users []store.UserSummary `json:"users"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			t.Fatalf("%s: GET /users = %d: %s", account, rec.Code, rec.Body.String())
		}
		names := []string{}
		for _, user := range body.Users {
			names = append(names, user.Username)
		}
		return names
	}

	if got, want := listed("other"), []string{"admin-b", "viewer-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("other tenant's users = %v, want %v", got, want)
	}
	if got, want := listed("own"), []string{"admin-a", "operator-a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("own tenant's users = %v, want %v", got, want)
	}

	passwordBody := `{"password":"` + password + `"}`
	before := snapshot()
	audits := count(`SELECT COUNT(*) FROM security_audit`)
	for _, route := range []struct{ method, suffix, body string }{
		{http.MethodGet, "", ""},
		{http.MethodPatch, "", `{"display_name":"Renamed","role":"viewer","enabled":false,"password":"` + password + `"}`},
		{http.MethodPost, "/activation", passwordBody},
		{http.MethodDelete, "/activation", passwordBody},
		{http.MethodPost, "/password-reset", passwordBody},
		{http.MethodDelete, "/sessions", passwordBody},
	} {
		foreign := call("other", route.method, "/api/v1/users/"+operatorA.ID+route.suffix, route.body)
		unknown := call("other", route.method, "/api/v1/users/"+unknownUserID+route.suffix, route.body)
		if foreign.Code != http.StatusNotFound || unknown.Code != http.StatusNotFound || foreign.Body.String() != unknown.Body.String() {
			t.Errorf("other tenant: %s /users/{id}%s = %d %q, unknown ID = %d %q; want the same 404", route.method, route.suffix, foreign.Code, foreign.Body.String(), unknown.Code, unknown.Body.String())
		}
	}
	if after := snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatalf("another tenant's routes changed tenant A's operator:\nbefore %+v\nafter  %+v", before, after)
	}
	if got := count(`SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("refused routes recorded %d audit records", got-audits)
	}
	// Tenant A does not reach tenant B's accounts either.
	foreign := call("own", http.MethodGet, "/api/v1/users/"+viewerB.ID, "")
	unknown := call("own", http.MethodGet, "/api/v1/users/"+unknownUserID, "")
	if foreign.Code != http.StatusNotFound || foreign.Body.String() != unknown.Body.String() {
		t.Fatalf("own tenant: GET tenant B's user = %d %q, unknown = %q", foreign.Code, foreign.Body.String(), unknown.Body.String())
	}

	// Usernames are unique across tenants, and the conflict names no tenant.
	conflict := call("other", http.MethodPost, "/api/v1/users", `{"username":"Operator-A","display_name":"Taken","role":"viewer","password":"`+password+`"}`)
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "username is not available") || strings.Contains(conflict.Body.String(), store.DefaultTenantID) {
		t.Fatalf("other tenant: create a username tenant A holds = %d: %s", conflict.Code, conflict.Body.String())
	}

	// Tenant B's own account routes work, and their records belong to B.
	if rec := call("other", http.MethodPatch, "/api/v1/users/"+viewerB.ID, `{"display_name":"Viewer B"}`); rec.Code != http.StatusOK {
		t.Fatalf("other tenant: rename its own viewer = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("other", http.MethodPost, "/api/v1/users/"+viewerB.ID+"/password-reset", passwordBody); rec.Code != http.StatusOK {
		t.Fatalf("other tenant: reset its own viewer = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("other", http.MethodPut, "/api/v1/auth/display-name", `{"display_name":"Admin B"}`); rec.Code != http.StatusOK {
		t.Fatalf("other tenant: change its own display name = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("other", http.MethodGet, "/api/v1/auth/session", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"display_name":"Admin B"`) {
		t.Fatalf("other tenant: session = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("other", http.MethodPost, "/api/v1/jobs", `{"name":"tenant-b-job","schedule":"0 * * * *","timezone":"UTC","targets":["192.0.2.20"],"tcp":{"ports":"1","mode":"connect","engine":"nmap"}}`); rec.Code != http.StatusCreated {
		t.Fatalf("other tenant: create a job = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("other", http.MethodDelete, "/api/v1/auth/sessions", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("other tenant: revoke its own sessions = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("other", http.MethodGet, "/api/v1/auth/session", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other tenant: session after revoking it = %d: %s", rec.Code, rec.Body.String())
	}
	for _, action := range []string{"user.updated", "user.password_reset_issued", "user.display_name_changed", "job.created", "admin.sessions_revoked"} {
		if got, want := lastAudit(action), [2]string{tenantAccountsOtherID, store.AuditActorUnit}; got != want {
			t.Errorf("%s audit record = %v, want %v", action, got, want)
		}
	}
	if after := snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatalf("tenant B's own routes changed tenant A's operator:\nbefore %+v\nafter  %+v", before, after)
	}
	if user, err := own.GetUser(ctx, adminA.ID); err != nil || user.DisplayName != "admin-a" {
		t.Fatalf("tenant A's administrator = %+v, %v", user, err)
	}
	if rec := call("own", http.MethodGet, "/api/v1/auth/session", ""); rec.Code != http.StatusOK {
		t.Fatalf("own tenant: session after tenant B revoked its own = %d: %s", rec.Code, rec.Body.String())
	}
}

// statusBody returns the decoded /status response of the signed-in account.
func (f tenantAccountsFixture) statusBody(t *testing.T, account string) map[string]any {
	t.Helper()
	rec := f.call(account, http.MethodGet, "/api/v1/status", "")
	var body map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
		t.Fatalf("%s: GET /status = %d: %s", account, rec.Code, rec.Body.String())
	}
	return body
}

// jsonValue returns the value as decoded JSON, so it compares with a
// decoded response.
func jsonValue(t *testing.T, value any) any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

// /status shows an administrator the telemetry and notification counts of
// the session's tenant only. While the default tenant holds all the data,
// its view is the one the deployment-wide sources give, with the same keys:
// the deployment telemetry, database size included, and the notifier's
// status of the default tenant's destinations. Another tenant's view counts
// its own jobs and destinations and leaves out the database size.
func TestStatusUsesTheSessionTenant(t *testing.T) {
	ctx := context.Background()
	f := newTenantAccountsFixture(t)
	job := config.Job{Name: "edge", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "22", Mode: "connect"}}
	for _, name := range []string{"edge", "edge-two"} {
		job.Name = name
		if _, err := f.own.CreateJob(ctx, config.NormalizeJob(job)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.own.CreateManagedNotification(ctx, "", "ops", "generic", []byte("sealed"), []byte("nonce"), true); err != nil {
		t.Fatal(err)
	}

	own := f.statusBody(t, "own")
	deployment, err := f.db.System().DeploymentTelemetry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := jsonValue(t, deployment).(map[string]any)
	got, _ := own["telemetry"].(map[string]any)
	delete(want, "collected_at")
	delete(got, "collected_at")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default tenant's telemetry = %v, want the deployment's %v", got, want)
	}
	// The default tenant's status is what /status reported before it took
	// the session's tenant.
	status, err := f.server.App.Notifier.Tenant(f.own).Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	notifications := jsonValue(t, status)
	if !reflect.DeepEqual(own["notifications"], notifications) {
		t.Fatalf("default tenant's notifications = %v, want %v", own["notifications"], notifications)
	}
	if active := notifications.(map[string]any)["active"]; own["notification_destinations"] != active || own["notifications"].(map[string]any)["managed"] != float64(1) {
		t.Fatalf("default tenant's destinations = %v, %v; want %v active of 1", own["notification_destinations"], own["notifications"], active)
	}

	job.Name = "edge"
	if _, err := f.other.CreateJob(ctx, config.NormalizeJob(job)); err != nil {
		t.Fatal(err)
	}
	other := f.statusBody(t, "other")
	telemetry, _ := other["telemetry"].(map[string]any)
	if telemetry["jobs"] != float64(1) || telemetry["events"] != float64(0) {
		t.Fatalf("other tenant's telemetry = %v, want its one job only", telemetry)
	}
	if _, ok := telemetry["database_bytes"]; ok {
		t.Fatalf("other tenant's telemetry has the database size: %v", telemetry)
	}
	counts, _ := other["notifications"].(map[string]any)
	if counts["managed"] != float64(0) || other["notification_destinations"] != float64(0) {
		t.Fatalf("other tenant's notifications = %v, %v; want none", counts, other["notification_destinations"])
	}
	// Each tenant's telemetry is cached on its own: the default tenant's
	// view still counts its two jobs.
	if telemetry := f.statusBody(t, "own")["telemetry"].(map[string]any); telemetry["jobs"] != float64(2) {
		t.Fatalf("default tenant's telemetry after the other's = %v", telemetry)
	}
}

// The status telemetry is cached for each tenant: a second read within the
// cache lifetime returns the first value, a tenant never gets another's, a
// store without a tenant is refused, and a request that waits for another
// request's refresh stops when its context ends or takes the refreshed
// value.
func TestTenantTelemetryCache(t *testing.T) {
	ctx := context.Background()
	f := newTenantAccountsFixture(t)
	first, err := f.server.cachedTenantTelemetry(ctx, f.own)
	if err != nil || first.DatabaseBytes <= 0 {
		t.Fatalf("default tenant's telemetry = %+v, %v", first, err)
	}
	if again, err := f.server.cachedTenantTelemetry(ctx, f.own); err != nil || !again.CollectedAt.Equal(first.CollectedAt) {
		t.Fatalf("cached telemetry = %+v, %v; want %+v", again, err, first)
	}
	if other, err := f.server.cachedTenantTelemetry(ctx, f.other); err != nil || other.DatabaseBytes != 0 {
		t.Fatalf("other tenant's telemetry = %+v, %v", other, err)
	}
	if _, err := f.server.cachedTenantTelemetry(ctx, nil); !errors.Is(err, store.ErrNoTenantScope) {
		t.Fatalf("telemetry without a tenant = %v", err)
	}

	// Another request is refreshing the other tenant's value.
	f.server.telemetryMu.Lock()
	entry := f.server.telemetry[tenantAccountsOtherID]
	entry.valid, entry.running, entry.done = false, true, make(chan struct{})
	f.server.telemetryMu.Unlock()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.server.cachedTenantTelemetry(canceled, f.other); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting with a canceled context = %v", err)
	}
	waited := make(chan store.TenantTelemetry)
	go func() {
		value, _ := f.server.cachedTenantTelemetry(ctx, f.other)
		waited <- value
	}()
	refreshed := store.TenantTelemetry{Jobs: 7, CollectedAt: time.Now().UTC()}
	f.server.telemetryMu.Lock()
	entry.value, entry.at, entry.valid, entry.running = refreshed, time.Now(), true, false
	close(entry.done)
	f.server.telemetryMu.Unlock()
	if value := <-waited; value != refreshed {
		t.Fatalf("waiting request = %+v, want the refreshed %+v", value, refreshed)
	}
}

// The unauthenticated setup status reports whether the legacy /public page,
// the default tenant's, is published. The flag is always present, false
// until the default tenant enables its page, whatever another tenant does
// with its own page.
func TestSetupStatusReportsTheDefaultPublicPage(t *testing.T) {
	ctx := context.Background()
	f := newTenantAccountsFixture(t)
	flag := func() any {
		t.Helper()
		rec := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil)
		request.RemoteAddr = "127.0.0.1:9001"
		f.server.setupStatus(rec, request)
		var body map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			t.Fatalf("setup status = %d: %s", rec.Code, rec.Body.String())
		}
		value, ok := body["public_dashboard_enabled"]
		if !ok {
			t.Fatalf("setup status has no public_dashboard_enabled: %v", body)
		}
		return value
	}
	if got := flag(); got != false {
		t.Fatalf("fresh page: public_dashboard_enabled = %v", got)
	}
	if err := f.other.SavePublicDashboard(ctx, store.PublicDashboard{Enabled: true, Title: "Other"}, nil, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if got := flag(); got != false {
		t.Fatalf("another tenant's published page: public_dashboard_enabled = %v", got)
	}
	for _, enabled := range []bool{true, false} {
		if err := f.own.SavePublicDashboard(ctx, store.PublicDashboard{Enabled: enabled, Title: "EdgeWatch public status"}, nil, store.AuditEntry{}); err != nil {
			t.Fatal(err)
		}
		if got := flag(); got != enabled {
			t.Fatalf("default page enabled=%v: public_dashboard_enabled = %v", enabled, got)
		}
	}
}
