package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// publicTenantBPage is tenant B's page in the public tenant fixture: the
// default tenant's page with B's title, introduction and ports.
var publicTenantBPage = strings.NewReplacer("Tenant A status", "Tenant B status", `"introduction":"A"`, `"introduction":"B"`, `"port":443,"service":"https"`, `"port":22,"service":"ssh"`, `"port":443`, `"port":22`).Replace(publicTenantAPage)

// getPublicPath requests path as an anonymous client through the server's
// HTTP handler, so the request takes the same route as a browser's.
func (f publicTenantFixture) getPublicPath(path, remote string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.RemoteAddr = remote
	recorder := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(recorder, request)
	return recorder
}

// A unit's slug page shows only what that unit published, although the
// default tenant publishes the same addresses from a job of the same name.
// The legacy URL keeps serving the default tenant's page byte for byte, and
// the default tenant's own slug serves the same page.
func TestPublicSlugPageServesOnlyItsUnit(t *testing.T) {
	f := newPublicTenantFixture(t)
	for i, check := range []struct{ path, want string }{
		{"/api/public/v1/dashboard", publicTenantAPage},
		{"/api/public/v1/dashboard/", publicTenantAPage},
		{"/api/public/v1/dashboard/other", publicTenantBPage},
		{"/api/public/v1/dashboard/other/", publicTenantBPage},
		{"/api/public/v1/dashboard/default", publicTenantAPage},
	} {
		rec := f.getPublicPath(check.path, fmt.Sprintf("198.51.100.80:%d", 1000+i))
		if rec.Code != http.StatusOK || rec.Body.String() != check.want {
			t.Fatalf("%s = %d:\n%s\nwant\n%s", check.path, rec.Code, rec.Body.String(), check.want)
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Robots-Tag") != "noindex, nofollow" {
			t.Fatalf("%s headers = %v", check.path, rec.Header())
		}
		for _, leaked := range []string{"secret-product", "1.0", f.jobA, f.jobB} {
			if strings.Contains(rec.Body.String(), leaked) {
				t.Fatalf("%s leaked %q", check.path, leaked)
			}
		}
	}
	// Other paths and methods stay unknown endpoints, as before units.
	for _, check := range []struct{ method, path string }{
		{http.MethodGet, "/api/public/v1/dashboard//"},
		{http.MethodGet, "/api/public/v1/status"},
		{http.MethodPost, "/api/public/v1/dashboard/other"},
		{http.MethodHead, "/api/public/v1/dashboard"},
	} {
		request := httptest.NewRequest(check.method, check.path, nil)
		request.RemoteAddr = "198.51.100.81:1000"
		rec := httptest.NewRecorder()
		f.server.publicAPI(rec, request)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"not_found"`) {
			t.Fatalf("%s %s = %d: %s", check.method, check.path, rec.Code, rec.Body.String())
		}
	}
}

// publicAnswer is what an anonymous client can observe of a response.
type publicAnswer struct {
	Code    int
	Body    string
	Headers string
}

func observePublicAnswer(rec *httptest.ResponseRecorder) publicAnswer {
	headers := rec.Header().Clone()
	// Every response carries its own request ID.
	headers.Del("X-Request-ID")
	raw, _ := json.Marshal(headers)
	return publicAnswer{Code: rec.Code, Body: rec.Body.String(), Headers: string(raw)}
}

// A slug page that is not published answers exactly as the default tenant's
// page when that page is not enabled: an unknown slug, a slug that cannot
// name a unit, a withdrawn page, a unit without a page, a paused unit, a unit
// being deleted, and a deleted unit. Nothing tells whether a unit has the
// slug.
func TestPublicSlugPagesThatAreNotPublishedAreIndistinguishable(t *testing.T) {
	ctx := context.Background()
	f := newPublicTenantFixture(t)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	units := []struct{ id, slug, state string }{
		{"00000000-0000-0000-0000-000000000301", "paused", "disabled"},
		{"00000000-0000-0000-0000-000000000302", "withdrawn", "active"},
		{"00000000-0000-0000-0000-000000000303", "leaving", "deleting"},
		{"00000000-0000-0000-0000-000000000304", "gone", "deleted"},
		{"00000000-0000-0000-0000-000000000305", "no-page", "active"},
	}
	for _, unit := range units {
		if _, err := f.db.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,?,?,?,?)`, unit.id, "Unit "+unit.slug, unit.slug, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if unit.slug == "no-page" {
			continue
		}
		scope, err := f.db.TenantScopeByID(ctx, unit.id)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.db.Tenant(scope).SavePublicDashboard(ctx, store.PublicDashboard{Enabled: unit.slug != "withdrawn", Title: "Unit " + unit.slug}, nil, store.AuditEntry{}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, unit.state, unit.id); err != nil {
			t.Fatal(err)
		}
	}
	answers := map[string]publicAnswer{}
	for i, slug := range []string{"nobody", "Bad_Slug", "x", "admin", strings.Repeat("a", 41), "paused", "withdrawn", "leaving", "gone", "no-page", "other%2Fx"} {
		rec := f.getPublicPath("/api/public/v1/dashboard/"+slug, fmt.Sprintf("198.51.100.82:%d", 1000+i))
		answers[slug] = observePublicAnswer(rec)
	}

	// The reference: the default tenant's page, withdrawn.
	if err := defaultTenantStore(f.server).SavePublicDashboard(ctx, store.PublicDashboard{Enabled: false, Title: "Tenant A status"}, nil, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	f.server.invalidatePublicPage(store.DefaultPublicScope())
	want := observePublicAnswer(f.getPublicPath("/api/public/v1/dashboard", "198.51.100.84:1000"))
	if want.Code != http.StatusNotFound || !strings.Contains(want.Body, `"public_disabled"`) {
		t.Fatalf("withdrawn default page = %+v", want)
	}
	for slug, got := range answers {
		if got != want {
			t.Errorf("slug %q answered\n%+v\nwant the withdrawn default page's\n%+v", slug, got, want)
		}
	}
}

// Each page has its own rate-limit bucket for a client: a client that
// exhausted one page's budget still reaches every other page, and a slug
// without a page is limited as a published one is.
func TestPublicSlugPagesHaveTheirOwnRateLimit(t *testing.T) {
	f := newPublicTenantFixture(t)
	const client = "198.51.100.85:1000"
	exhaust := func(path string, status int) {
		t.Helper()
		for i := 0; i < 120; i++ {
			if rec := f.getPublicPath(path, client); rec.Code != status {
				t.Fatalf("%s request %d = %d: %s", path, i+1, rec.Code, rec.Body.String())
			}
		}
		rec := f.getPublicPath(path, client)
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" || !strings.Contains(rec.Body.String(), `"rate_limited"`) {
			t.Fatalf("%s after its budget = %d %v: %s", path, rec.Code, rec.Header(), rec.Body.String())
		}
	}
	// Each exhaust starts with a full budget: the pages before it did not
	// spend it.
	exhaust("/api/public/v1/dashboard", http.StatusOK)
	exhaust("/api/public/v1/dashboard/other", http.StatusOK)
	// A slug without a page has a budget of its own, exactly like a page.
	exhaust("/api/public/v1/dashboard/nobody", http.StatusNotFound)
	// Addresses that cannot name a unit share one bucket.
	exhaust("/api/public/v1/dashboard/Bad_Slug", http.StatusNotFound)
	if rec := f.getPublicPath("/api/public/v1/dashboard/"+strings.Repeat("b", 64), client); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("another malformed slug = %d: %s", rec.Code, rec.Body.String())
	}
	// The default tenant's slug is a page of its own, apart from the legacy
	// URL that serves the same content.
	if rec := f.getPublicPath("/api/public/v1/dashboard/default", client); rec.Code != http.StatusOK || rec.Body.String() != publicTenantAPage {
		t.Fatalf("default tenant's slug after the legacy URL's budget = %d: %s", rec.Code, rec.Body.String())
	}
	// Another client is not limited by this one.
	if rec := f.getPublicPath("/api/public/v1/dashboard/other", "198.51.100.86:1000"); rec.Code != http.StatusOK {
		t.Fatalf("another client = %d: %s", rec.Code, rec.Body.String())
	}
}

// publicUnitAdministrators signs in the default tenant's administrator and an
// administrator of tenant B, and returns a client for the public status
// editor of each: "own" and "other".
func publicUnitAdministrators(t *testing.T, f publicTenantFixture) func(account, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := context.Background()
	other, err := defaultTenant(f.db).CreateUser(ctx, store.User{Username: "other-admin", DisplayName: "Other", Role: store.RoleAdministrator, PasswordHash: "unused-hash", Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE users SET tenant_id=? WHERE id=?`, publicTenantB, other.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for name, userID := range map[string]string{"own": f.admin.UserID, "other": other.ID} {
		if err := f.db.CreateSessionForUserWithAudit(ctx, userID, digest("unit-public-"+name), "csrf-"+name, now, now.Add(time.Hour), "", ""); err != nil {
			t.Fatal(err)
		}
	}
	enrollAdministratorsInTOTP(t, f.db)
	return func(account, method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/public-dashboard", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "edgewatch_session", Value: "unit-public-" + account})
		req.Header.Set("X-CSRF-Token", "csrf-"+account)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		f.server.api(rec, req)
		return rec
	}
}

// A unit's save drops only its own page's cache and generation. The other
// pages keep serving their cached payload, and a build of another page in
// flight during the save is neither discarded nor rebuilt.
func TestPublicPageSaveKeepsOtherUnitsCache(t *testing.T) {
	ctx := context.Background()
	f := newPublicTenantFixture(t)
	editor := publicUnitAdministrators(t, f)
	scopeB, err := f.db.PublicScopeBySlug(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	save := func(account, title string) {
		t.Helper()
		rec := editor(account, http.MethodGet, "")
		var loaded struct {
			publicDashboardConfigResponse
			Hosts []publicDashboardHostPayload `json:"hosts"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &loaded) != nil {
			t.Fatalf("%s: GET = %d: %s", account, rec.Code, rec.Body.String())
		}
		hosts := make([]string, 0, len(loaded.Hosts))
		for _, host := range loaded.Hosts {
			hosts = append(hosts, fmt.Sprintf(`{"job_id":%q,"address":%q}`, host.JobID, host.Address))
		}
		body := fmt.Sprintf(`{"enabled":true,"title":%q,"introduction":%q,"hosts":[%s],"updated_at":%q}`, title, loaded.Introduction, strings.Join(hosts, ","), loaded.UpdatedAt)
		if rec := editor(account, http.MethodPut, body); rec.Code != http.StatusOK {
			t.Fatalf("%s: PUT = %d: %s", account, rec.Code, rec.Body.String())
		}
	}
	cached := func(scope store.PublicScope) string {
		payload, ok := f.server.cachedPublicPageResponse(scope)
		if !ok {
			return ""
		}
		return string(payload) + "\n"
	}
	for _, path := range []string{"/api/public/v1/dashboard", "/api/public/v1/dashboard/other"} {
		if rec := f.getPublicPath(path, "198.51.100.87:1000"); rec.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", path, rec.Code, rec.Body.String())
		}
	}

	// Tenant B saves: its own page is rebuilt, the default page's cache and
	// generation stay.
	generationA := f.server.publicPageGeneration(store.DefaultPublicScope())
	save("other", "Tenant B saved")
	if got := cached(store.DefaultPublicScope()); got != publicTenantAPage {
		t.Fatalf("default page cache after tenant B's save = %q", got)
	}
	if got := cached(scopeB); got != "" {
		t.Fatalf("tenant B's cache survived its own save: %s", got)
	}
	if got := f.server.publicPageGeneration(store.DefaultPublicScope()); got != generationA {
		t.Fatalf("default page generation moved from %d to %d", generationA, got)
	}
	pageB := f.getPublicPath("/api/public/v1/dashboard/other", "198.51.100.87:1001")
	if pageB.Code != http.StatusOK || !strings.HasPrefix(pageB.Body.String(), `{"title":"Tenant B saved","introduction":"B"`) || strings.Contains(pageB.Body.String(), `"port":443`) {
		t.Fatalf("tenant B's page after its save = %d: %s", pageB.Code, pageB.Body.String())
	}
	savedB := pageB.Body.String()

	// The default tenant saves: tenant B's cache and generation stay.
	generationB := f.server.publicPageGeneration(scopeB)
	save("own", "Tenant A saved")
	if got := cached(scopeB); got != savedB {
		t.Fatalf("tenant B's cache after the default tenant's save = %q, want %q", got, savedB)
	}
	if got := cached(store.DefaultPublicScope()); got != "" {
		t.Fatalf("default page cache survived its own save: %s", got)
	}
	if got := f.server.publicPageGeneration(scopeB); got != generationB {
		t.Fatalf("tenant B's generation moved from %d to %d", generationB, got)
	}

	// A build of the default page in flight while tenant B saves completes
	// and is served; it is built once.
	f.server.invalidatePublicPage(store.DefaultPublicScope())
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	builds := 0
	f.server.publicDashboardBuildFunc = func(_ context.Context, dashboard store.PublicDashboard) (publicDashboardResponse, error) {
		mu.Lock()
		builds++
		mu.Unlock()
		once.Do(func() { close(started) })
		<-release
		return publicDashboardResponse{Title: dashboard.Title, Hosts: []publicHostResponse{}}, nil
	}
	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() { responses <- f.getPublicPath("/api/public/v1/dashboard", "198.51.100.87:1002") }()
	<-started
	f.server.invalidatePublicPage(scopeB)
	close(release)
	rec := awaitPublicResponse(t, responses)
	mu.Lock()
	defer mu.Unlock()
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"title":"Tenant A saved"`) || builds != 1 {
		t.Fatalf("default page built during tenant B's save = %d (builds %d): %s", rec.Code, builds, rec.Body.String())
	}
}
