package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// blockFirstPublicBuild makes the first shared cache fill wait for release,
// as a slow store would, and renders later fills immediately.
func blockFirstPublicBuild(server *Server) (started <-chan struct{}, release chan<- struct{}, calls *atomic.Int32) {
	startedCh := make(chan struct{})
	releaseCh := make(chan struct{})
	var count atomic.Int32
	server.publicDashboardBuildFunc = func(ctx context.Context, dashboard store.PublicDashboard) (publicDashboardResponse, error) {
		if count.Add(1) == 1 {
			close(startedCh)
			select {
			case <-releaseCh:
			case <-ctx.Done():
				return publicDashboardResponse{}, ctx.Err()
			}
		}
		return publicDashboardResponse{Title: dashboard.Title, Introduction: dashboard.Introduction, Hosts: []publicHostResponse{}}, nil
	}
	return startedCh, releaseCh, &count
}

func anonymousPublicRequest(server *Server, remote string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/api/public/v1/dashboard", nil)
	request.RemoteAddr = remote
	recorder := httptest.NewRecorder()
	server.publicAPI(recorder, request)
	return recorder
}

// savePublicationAsAdministrator performs the admin save sequence: commit the
// publication, then invalidate the anonymous cache.
func savePublicationAsAdministrator(t *testing.T, server *Server, dashboard store.PublicDashboard) {
	t.Helper()
	if err := server.Store.SavePublicDashboard(context.Background(), dashboard, nil, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	server.invalidatePublicDashboardCache()
}

func awaitPublicResponse(t *testing.T, responses <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case response := <-responses:
		return response
	case <-time.After(5 * time.Second):
		t.Fatal("anonymous public request did not finish")
		return nil
	}
}

func TestInFlightPublicBuildCannotRepublishAWithdrawnPage(t *testing.T) {
	server, db, _ := newUsersTestServer(t)
	if err := db.SavePublicDashboard(context.Background(), store.PublicDashboard{Enabled: true, Title: "published-v1"}, nil, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	started, release, calls := blockFirstPublicBuild(server)
	inFlight := make(chan *httptest.ResponseRecorder, 1)
	go func() { inFlight <- anonymousPublicRequest(server, "198.51.100.30:1000") }()
	<-started

	savePublicationAsAdministrator(t, server, store.PublicDashboard{Enabled: false, Title: "published-v1"})
	if response := anonymousPublicRequest(server, "198.51.100.31:1000"); response.Code != http.StatusNotFound {
		t.Fatalf("request during the blocked build = %d: %s", response.Code, response.Body.String())
	}
	close(release)

	// The request that read the page before the save re-reads it instead of
	// rebuilding the withdrawn publication.
	if response := awaitPublicResponse(t, inFlight); response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "published-v1") {
		t.Fatalf("in-flight request after the save = %d: %s", response.Code, response.Body.String())
	}
	for i := 0; i < 3; i++ {
		if response := anonymousPublicRequest(server, "198.51.100.32:1000"); response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "published-v1") {
			t.Fatalf("request %d after the save = %d: %s", i+1, response.Code, response.Body.String())
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("builds after withdrawal = %d, want only the original shared build", got)
	}
}

func TestInFlightPublicBuildCannotServeAReplacedPublication(t *testing.T) {
	server, db, _ := newUsersTestServer(t)
	if err := db.SavePublicDashboard(context.Background(), store.PublicDashboard{Enabled: true, Title: "published-v1", Introduction: "old introduction"}, nil, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	started, release, _ := blockFirstPublicBuild(server)
	inFlight := make(chan *httptest.ResponseRecorder, 1)
	go func() { inFlight <- anonymousPublicRequest(server, "198.51.100.40:1000") }()
	<-started

	savePublicationAsAdministrator(t, server, store.PublicDashboard{Enabled: true, Title: "published-v2", Introduction: "new introduction"})
	close(release)

	check := func(name string, response *httptest.ResponseRecorder) {
		t.Helper()
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "published-v2") || strings.Contains(response.Body.String(), "published-v1") || strings.Contains(response.Body.String(), "old introduction") {
			t.Fatalf("%s = %d: %s", name, response.Code, response.Body.String())
		}
	}
	check("in-flight request", awaitPublicResponse(t, inFlight))
	for i := 0; i < 3; i++ {
		check("later request", anonymousPublicRequest(server, "198.51.100.41:1000"))
	}
}

// publicDashboardToken returns the updated_at concurrency token that an
// editor would send back from its GET of the public-status configuration.
func publicDashboardToken(t *testing.T, server *Server, admin store.Session) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.publicDashboardRoute(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/public-dashboard", nil), admin)
	if recorder.Code != http.StatusOK {
		t.Fatalf("public dashboard GET = %d: %s", recorder.Code, recorder.Body.String())
	}
	var loaded struct {
		UpdatedAt string `json:"updated_at"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &loaded); err != nil || loaded.UpdatedAt == "" {
		t.Fatalf("public dashboard GET has no updated_at token: %s (%v)", recorder.Body.String(), err)
	}
	return loaded.UpdatedAt
}

type publicDashboardConfigResponse struct {
	Enabled      bool   `json:"enabled"`
	Title        string `json:"title"`
	Introduction string `json:"introduction"`
	UpdatedAt    string `json:"updated_at"`
}

func TestPublicDashboardEditorRejectsStaleSaves(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	get := func() publicDashboardConfigResponse {
		t.Helper()
		recorder := httptest.NewRecorder()
		server.publicDashboardRoute(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/public-dashboard", nil), admin)
		if recorder.Code != http.StatusOK {
			t.Fatalf("public dashboard GET = %d: %s", recorder.Code, recorder.Body.String())
		}
		var loaded publicDashboardConfigResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &loaded); err != nil {
			t.Fatal(err)
		}
		return loaded
	}
	put := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/api/v1/public-dashboard", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		server.publicDashboardRoute(recorder, request, admin)
		return recorder
	}
	saved := func(recorder *httptest.ResponseRecorder) publicDashboardConfigResponse {
		t.Helper()
		if recorder.Code != http.StatusOK {
			t.Fatalf("public dashboard PUT = %d: %s", recorder.Code, recorder.Body.String())
		}
		var result publicDashboardConfigResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}

	// Administrator A publishes the page.
	initial := get()
	published := saved(put(`{"enabled":true,"title":"Status","introduction":"v1","hosts":[],"updated_at":"` + initial.UpdatedAt + `"}`))
	if published.UpdatedAt == "" || published.UpdatedAt == initial.UpdatedAt {
		t.Fatalf("save did not advance the concurrency token: %q -> %q", initial.UpdatedAt, published.UpdatedAt)
	}
	// Administrator B opens the editor while the page is published.
	stale := get()
	if !stale.Enabled || stale.UpdatedAt != published.UpdatedAt {
		t.Fatalf("editor view = %#v, want the published state", stale)
	}
	// A withdraws the page.
	withdrawn := saved(put(`{"enabled":false,"title":"Status","introduction":"v1","hosts":[],"updated_at":"` + published.UpdatedAt + `"}`))

	// B's save from the outdated view must not re-publish the page.
	conflict := put(`{"enabled":true,"title":"Status","introduction":"edited by B","hosts":[],"updated_at":"` + stale.UpdatedAt + `"}`)
	if body := decodeAPIError(t, conflict); conflict.Code != http.StatusConflict || body.Error.Code != "conflict" {
		t.Fatalf("stale save = %d %#v, want 409 conflict", conflict.Code, body.Error)
	}
	for name, body := range map[string]string{
		"missing token":   `{"enabled":true,"title":"Status","introduction":"edited by B","hosts":[]}`,
		"malformed token": `{"enabled":true,"title":"Status","introduction":"edited by B","hosts":[],"updated_at":"yesterday"}`,
	} {
		if recorder := put(body); recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s save = %d: %s", name, recorder.Code, recorder.Body.String())
		}
	}
	current, err := db.GetPublicDashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.Enabled || current.Introduction != "v1" {
		t.Fatalf("rejected saves changed the publication: %#v", current)
	}
	if response := anonymousPublicRequest(server, "198.51.100.50:1000"); response.Code != http.StatusNotFound {
		t.Fatalf("anonymous request after rejected save = %d: %s", response.Code, response.Body.String())
	}

	// After reloading, B saves on top of the current state.
	reloaded := get()
	if reloaded.UpdatedAt != withdrawn.UpdatedAt || reloaded.Enabled {
		t.Fatalf("reloaded view = %#v, want the withdrawn state", reloaded)
	}
	edited := saved(put(`{"enabled":false,"title":"Status","introduction":"edited by B","hosts":[],"updated_at":"` + reloaded.UpdatedAt + `"}`))
	if edited.Introduction != "edited by B" || edited.Enabled || edited.UpdatedAt == reloaded.UpdatedAt {
		t.Fatalf("save after reload = %#v", edited)
	}
}

func TestPublicDashboardSaveStaysAdministratorOnly(t *testing.T) {
	ctx := context.Background()
	server, db, _ := newUsersTestServer(t)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	token := publicDashboardToken(t, server, store.Session{UserID: store.LegacyAdminUserID, Username: "admin", Role: store.RoleAdministrator})
	now := time.Now().UTC()
	for _, role := range []string{store.RoleOperator, store.RoleViewer} {
		user, err := db.CreateUser(ctx, store.User{Username: "public-" + role, DisplayName: role, Role: role, PasswordHash: "unused-hash", Enabled: true}, store.AuditEntry{})
		if err != nil {
			t.Fatal(err)
		}
		raw := "public-dashboard-" + role
		if err := db.CreateSessionForUserWithAudit(ctx, user.ID, digest(raw), "csrf-"+role, now, now.Add(time.Hour), "", ""); err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPut, httpServer.URL+"/api/v1/public-dashboard", strings.NewReader(`{"enabled":true,"title":"Status","hosts":[],"updated_at":"`+token+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", "csrf-"+role)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("%s public dashboard save = %d, want 403", role, response.StatusCode)
		}
	}
	current, err := db.GetPublicDashboard(ctx)
	if err != nil || current.Enabled {
		t.Fatalf("denied saves changed the publication: %#v (%v)", current, err)
	}
}
