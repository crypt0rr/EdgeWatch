package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// The public status tests written before tenant scopes call these helpers.
// Each reads the default tenant's page, as the legacy public URLs do.

func (s *Server) cachedPublicDashboardResponse() ([]byte, bool) {
	return s.cachedPublicPageResponse(store.DefaultPublicScope())
}

func (s *Server) cachedPublicDashboardPayload(ctx context.Context, generation uint64, dashboard store.PublicDashboard) ([]byte, error) {
	return s.cachedPublicPagePayload(ctx, store.DefaultPublicScope(), generation, dashboard)
}

func (s *Server) publicDashboardGeneration() uint64 {
	return s.publicPageGeneration(store.DefaultPublicScope())
}

func (s *Server) invalidatePublicDashboardCache() {
	s.invalidatePublicPage(store.DefaultPublicScope())
}

func (s *Server) publicDashboardResponse(ctx context.Context, dashboard store.PublicDashboard) (publicDashboardResponse, error) {
	return s.publicPageResponse(ctx, s.Store.Public(store.DefaultPublicScope()), dashboard)
}

func (s *Server) latestLegacyPublicHosts(ctx context.Context, selections []store.PublicDashboardHost) (map[string]store.PublicDashboardHostResult, error) {
	return legacyPublicHosts(ctx, s.Store.Public(store.DefaultPublicScope()), selections)
}

func (s *Server) latestPublishedHost(ctx context.Context, jobID, address string) (store.ScanHost, error) {
	lookup, err := s.loadPublishedHosts(ctx, s.Store.Public(store.DefaultPublicScope()), []store.PublicDashboardHost{{JobID: jobID, Address: address}}, false)
	if err != nil {
		return store.ScanHost{}, err
	}
	if item, ok := lookup[publicSelectionKey(jobID, canonicalHostAddress(address))]; ok {
		return item.Host, nil
	}
	return store.ScanHost{}, store.ErrNotFound
}

func (s *Server) latestLegacyPublicHost(ctx context.Context, jobID, address string) (store.ScanHost, model.ScanSummary, error) {
	results, err := s.latestLegacyPublicHosts(ctx, []store.PublicDashboardHost{{JobID: jobID, Address: address}})
	if err != nil {
		return store.ScanHost{}, model.ScanSummary{}, err
	}
	if item, ok := results[publicSelectionKey(jobID, address)]; ok {
		return item.Host, item.Summary, nil
	}
	return store.ScanHost{}, model.ScanSummary{}, store.ErrNotFound
}

// publicTenantB is a tenant that the tests create directly in SQL, because
// no product API creates one yet. Its slug is "other".
const publicTenantB = "00000000-0000-0000-0000-000000000200"

// publicTenantAddresses are the addresses that both tenants' "edge" jobs
// observed and publish: an indexed private host, a private host seen only by
// a legacy scan, and an indexed public host with cached registration data.
var publicTenantAddresses = []string{"198.51.100.10", "198.51.100.11", "8.8.8.8"}

// publicTenantFixture is a server whose two tenants look alike: each has a
// job named "edge" that observed the same addresses, and an enabled public
// page that publishes them. Tenant A, the default tenant, found port 443
// (https) open on every address; tenant B found port 22 (ssh), so a leak of
// either shows in a response.
type publicTenantFixture struct {
	server     *Server
	db         *store.Store
	admin      store.Session
	jobA, jobB string
	scopeB     store.TenantScope
}

func newPublicTenantFixture(t *testing.T) publicTenantFixture {
	t.Helper()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, publicTenantB, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	scopeB, err := db.TenantScopeByID(ctx, publicTenantB)
	if err != nil {
		t.Fatal(err)
	}
	f := publicTenantFixture{server: server, db: db, admin: admin, scopeB: scopeB}
	finished := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []struct {
		ts                  *store.TenantStore
		id                  *string
		title, introduction string
		port                int
		service             string
	}{{defaultTenantStore(server), &f.jobA, "Tenant A status", "A", 443, "https"}, {db.Tenant(scopeB), &f.jobB, "Tenant B status", "B", 22, "ssh"}} {
		job := config.NormalizeJob(config.Job{Name: "edge", Schedule: "0 * * * *", Timezone: "UTC", Targets: publicTenantAddresses, TCP: &config.Protocol{Ports: "22,443", Mode: "connect"}})
		record, err := tenant.ts.CreateJob(ctx, job)
		if err != nil {
			t.Fatal(err)
		}
		*tenant.id = record.ID
		port := model.PortObservation{Port: tenant.port, State: "open", Service: &model.ServiceObservation{Name: tenant.service, Product: "secret-product", Version: "1.0"}}
		host := func(address string) model.HostObservation {
			return model.HostObservation{Address: address, AddressFamily: "IPv4", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "22,443", ScannedPortCount: 2, Ports: []model.PortObservation{port}}}}
		}
		legacy := model.Scan{ID: record.ID + "-legacy", JobID: record.ID, JobRevision: record.Revision, Job: "edge", StartedAt: finished.Add(-2 * time.Hour), FinishedAt: finished.Add(-time.Hour), Status: "success",
			Snapshot: model.Snapshot{Units: []model.Unit{{Target: "198.51.100.11", Addresses: []string{"198.51.100.11"}, Protocol: "tcp", Ports: []model.PortState{{Port: tenant.port, State: "open", Service: tenant.service}}}}}}
		indexed := model.Scan{ID: record.ID + "-indexed", JobID: record.ID, JobRevision: record.Revision, Job: "edge", StartedAt: finished.Add(-time.Minute), FinishedAt: finished, Status: "success",
			Snapshot: model.Snapshot{Hosts: []model.HostObservation{host("198.51.100.10"), host("8.8.8.8")}}}
		for _, scan := range []model.Scan{legacy, indexed} {
			if err := db.System().SaveScan(ctx, scan); err != nil {
				t.Fatal(err)
			}
		}
		hosts := make([]store.PublicDashboardHost, 0, len(publicTenantAddresses))
		for _, address := range publicTenantAddresses {
			hosts = append(hosts, store.PublicDashboardHost{JobID: record.ID, Address: address})
		}
		if err := tenant.ts.SavePublicDashboard(ctx, store.PublicDashboard{Enabled: true, Title: tenant.title, Introduction: tenant.introduction}, hosts, store.AuditEntry{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE public_dashboards SET updated_at='2026-09-21T08:00:00Z'`); err != nil {
		t.Fatal(err)
	}
	if err := db.PutRDAPCache(ctx, store.RDAPCacheEntry{Address: "8.8.8.8", Payload: []byte(`{"status":"success","network_name":"Example"}`), FetchedAt: finished, ExpiresAt: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), StaleUntil: time.Date(2100, 1, 2, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	return f
}

// getPublicPage requests the page of the scope as an anonymous client: the
// default tenant's through the legacy URL, and another tenant's through the
// scope itself, as if it had been resolved before the request.
func (f publicTenantFixture) getPublicPage(scope store.PublicScope, remote string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/api/public/v1/dashboard", nil)
	request.RemoteAddr = remote
	recorder := httptest.NewRecorder()
	if scope == store.DefaultPublicScope() {
		f.server.publicAPI(recorder, request)
	} else {
		f.server.servePublicPage(recorder, request, "public-dashboard/test", func(context.Context) (store.PublicScope, error) { return scope, nil })
	}
	return recorder
}

// publicTenantAPage is the default tenant's page exactly as the public API
// returned it before tenant scopes, recorded on that code.
const publicTenantAPage = `{"title":"Tenant A status","introduction":"A","updated_at":"2026-09-21T08:00:00Z","hosts":[{"job":"edge","address":"198.51.100.10","address_family":"IPv4","public":false,"private":true,"last_successful_scan":"2026-09-20T12:00:00Z","open_ports":[{"protocol":"tcp","port":443,"service":"https"}]},{"job":"edge","address":"198.51.100.11","address_family":"IPv4","public":false,"private":true,"last_successful_scan":"2026-09-20T11:00:00Z","open_ports":[{"protocol":"tcp","port":443}]},{"job":"edge","address":"8.8.8.8","address_family":"IPv4","public":true,"private":false,"last_successful_scan":"2026-09-20T12:00:00Z","open_ports":[{"protocol":"tcp","port":443,"service":"https"}],"rdap":{"status":"success","network_name":"Example","fetched_at":"2026-09-20T12:00:00Z"}}]}` + "\n"

// The legacy public URLs serve the default tenant's page byte for byte as
// before, although another tenant publishes the same addresses from a job
// with the same name. The other tenant's page, read through its own scope,
// shows only its own observations.
func TestPublicAPIServesTheDefaultTenantUnchanged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPublicTenantFixture(t)
	for i, path := range []string{"/api/public/v1/dashboard", "/api/public/v1/dashboard/"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.RemoteAddr = "198.51.100.70:1000"
		recorder := httptest.NewRecorder()
		f.server.publicAPI(recorder, request)
		if recorder.Code != http.StatusOK || recorder.Body.String() != publicTenantAPage {
			t.Fatalf("request %d: default page = %d:\n%s\nwant\n%s", i, recorder.Code, recorder.Body.String(), publicTenantAPage)
		}
	}
	scopeB, err := f.db.PublicScopeBySlug(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	pageB := f.getPublicPage(scopeB, "198.51.100.71:1000")
	want := strings.NewReplacer("Tenant A status", "Tenant B status", `"introduction":"A"`, `"introduction":"B"`, `"port":443,"service":"https"`, `"port":22,"service":"ssh"`, `"port":443`, `"port":22`).Replace(publicTenantAPage)
	if pageB.Code != http.StatusOK || pageB.Body.String() != want {
		t.Fatalf("tenant B's page = %d:\n%s\nwant\n%s", pageB.Code, pageB.Body.String(), want)
	}
	for _, leaked := range []string{"secret-product", "1.0", f.jobA, f.jobB} {
		if strings.Contains(publicTenantAPage+pageB.Body.String(), leaked) {
			t.Fatalf("a public page leaked %q", leaked)
		}
	}

	// A paused tenant's page, or a withdrawn one, is not served, although
	// the scope was resolved while it was published.
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET state='disabled' WHERE id=?`, publicTenantB); err != nil {
		t.Fatal(err)
	}
	f.server.invalidatePublicPage(scopeB)
	if rec := f.getPublicPage(scopeB, "198.51.100.71:1001"); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "public_disabled") {
		t.Fatalf("paused tenant's page = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := f.getPublicPage(store.DefaultPublicScope(), "198.51.100.70:1001"); rec.Code != http.StatusOK || rec.Body.String() != publicTenantAPage {
		t.Fatalf("default page with another tenant paused = %d: %s", rec.Code, rec.Body.String())
	}
}

// The public status route reads and saves the page of the session's tenant.
// Another tenant's administrator sees their own page, not the default
// tenant's, and publishing a host of the default tenant's job fails exactly
// as a host of an unknown job does. Their saves leave the default tenant's
// page, and the public API that serves it, unchanged.
func TestPublicDashboardRouteUsesTheSessionTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPublicTenantFixture(t)
	other, err := storetest.CreateUser(ctx, f.db, store.DefaultTenantScope(), store.User{Username: "other-admin", DisplayName: "Other", Role: store.RoleAdministrator, PasswordHash: "unused-hash", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE users SET tenant_id=? WHERE id=?`, publicTenantB, other.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cookies := map[string]string{}
	for name, userID := range map[string]string{"own": f.admin.UserID, "other": other.ID} {
		raw := "tenant-public-" + name
		if err := storetest.CreateSession(ctx, f.db, userID, digest(raw), "csrf-"+name, now, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		cookies[name] = raw
	}
	enrollAdministratorsInTOTP(t, f.db)
	call := func(account, method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/public-dashboard", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "edgewatch_session", Value: cookies[account]})
		req.Header.Set("X-CSRF-Token", "csrf-"+account)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		f.server.api(rec, req)
		return rec
	}
	page := func(account string) (string, publicDashboardConfigResponse) {
		t.Helper()
		rec := call(account, http.MethodGet, "")
		var loaded publicDashboardConfigResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &loaded) != nil {
			t.Fatalf("%s tenant: GET = %d: %s", account, rec.Code, rec.Body.String())
		}
		return rec.Body.String(), loaded
	}
	ownBefore, _ := page("own")
	if !strings.Contains(ownBefore, "Tenant A status") || !strings.Contains(ownBefore, f.jobA) || strings.Contains(ownBefore, f.jobB) {
		t.Fatalf("default tenant's page = %s", ownBefore)
	}
	otherBody, otherPage := page("other")
	if !strings.Contains(otherBody, "Tenant B status") || !strings.Contains(otherBody, f.jobB) || strings.Contains(otherBody, f.jobA) {
		t.Fatalf("other tenant's page = %s", otherBody)
	}

	save := func(job, address string) *httptest.ResponseRecorder {
		return call("other", http.MethodPut, `{"enabled":true,"title":"Tenant B saved","hosts":[{"job_id":"`+job+`","address":"`+address+`"}],"updated_at":"`+otherPage.UpdatedAt+`"}`)
	}
	for _, address := range publicTenantAddresses {
		leaked, unknown := save(f.jobA, address), save("00000000-0000-0000-0000-00000000dead", address)
		if leaked.Code != http.StatusBadRequest || leaked.Body.String() != unknown.Body.String() {
			t.Errorf("other tenant published the default tenant's %s = %d %s; unknown job = %d %s", address, leaked.Code, leaked.Body.String(), unknown.Code, unknown.Body.String())
		}
	}
	if body, _ := page("other"); body != otherBody {
		t.Fatalf("a refused save changed the other tenant's page: %s", body)
	}
	if rec := save(f.jobB, "8.8.8.8"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Tenant B saved") || strings.Contains(rec.Body.String(), f.jobA) {
		t.Fatalf("other tenant's own save = %d: %s", rec.Code, rec.Body.String())
	}
	if body, _ := page("own"); body != ownBefore {
		t.Fatalf("the other tenant's save changed the default tenant's page:\n%s\nwant\n%s", body, ownBefore)
	}
	if rec := f.getPublicPage(store.DefaultPublicScope(), "198.51.100.72:1000"); rec.Code != http.StatusOK || rec.Body.String() != publicTenantAPage {
		t.Fatalf("default page after the other tenant's save = %d: %s", rec.Code, rec.Body.String())
	}
}

// Each public scope has its own cache: a page cached for one tenant is never
// served for another, and invalidating one page leaves every other page's
// cache in place. With one tenant, the default page keeps the server's single
// cache.
func TestPublicPageCacheIsKeyedPerScope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPublicTenantFixture(t)
	scopeB, err := f.db.PublicScopeBySlug(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	pageA := f.getPublicPage(store.DefaultPublicScope(), "198.51.100.73:1000").Body.String()
	if payload, ok := f.server.cachedPublicPageResponse(store.DefaultPublicScope()); !ok || string(payload)+"\n" != pageA {
		t.Fatalf("default page cache = %s, %v", payload, ok)
	}
	if payload, ok := f.server.cachedPublicPageResponse(scopeB); ok {
		t.Fatalf("tenant B's scope was served the default page's cache: %s", payload)
	}
	pageB := f.getPublicPage(scopeB, "198.51.100.73:1001").Body.String()
	if pageA == pageB || !strings.Contains(pageB, "Tenant B status") {
		t.Fatalf("tenant B's page = %s", pageB)
	}
	for scope, want := range map[store.PublicScope]string{store.DefaultPublicScope(): pageA, scopeB: pageB} {
		if payload, ok := f.server.cachedPublicPageResponse(scope); !ok || string(payload)+"\n" != want {
			t.Errorf("tenant %s: cached page = %s, %v; want %s", scope.TenantID(), payload, ok, want)
		}
	}
	f.server.publicCacheMu.Lock()
	defaultEntry, pages := f.server.publicCache, len(f.server.publicPages)
	f.server.publicCacheMu.Unlock()
	if defaultEntry == nil || pages != 1 {
		t.Fatalf("default page cache = %v, other pages = %d", defaultEntry, pages)
	}
	for _, step := range []struct {
		invalidated, kept store.PublicScope
		keptPage          string
	}{{scopeB, store.DefaultPublicScope(), pageA}, {store.DefaultPublicScope(), scopeB, pageB}} {
		// Both pages are cached before the save.
		for _, scope := range []store.PublicScope{store.DefaultPublicScope(), scopeB} {
			if rec := f.getPublicPage(scope, "198.51.100.73:1002"); rec.Code != http.StatusOK {
				t.Fatalf("tenant %s: page = %d: %s", scope.TenantID(), rec.Code, rec.Body.String())
			}
		}
		before := f.server.publicPageGeneration(step.kept)
		f.server.invalidatePublicPage(step.invalidated)
		if payload, ok := f.server.cachedPublicPageResponse(step.invalidated); ok {
			t.Errorf("tenant %s: page served after its save: %s", step.invalidated.TenantID(), payload)
		}
		if payload, ok := f.server.cachedPublicPageResponse(step.kept); !ok || string(payload)+"\n" != step.keptPage {
			t.Errorf("tenant %s: cache after another page's save = %s, %v; want %s", step.kept.TenantID(), payload, ok, step.keptPage)
		}
		if after := f.server.publicPageGeneration(step.kept); after != before {
			t.Errorf("tenant %s: generation moved from %d to %d on another page's save", step.kept.TenantID(), before, after)
		}
	}
}
