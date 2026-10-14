package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestApplicationUpdateStatusIsAuthenticatedAndRedactsSetupState(t *testing.T) {
	t.Parallel()
	server, db, admin := newUsersTestServer(t)
	server.Version = "v1.0.0"
	ctx := context.Background()
	if _, err := db.Platform().RecordInstalledVersion(ctx, "v1.0.0", "", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Platform().RecordReleaseCheck(ctx, "v1.0.0", "v1.1.0", "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.1.0", "1.1", "2026-09-07T12:00:00Z", `"etag"`, false, nil); err != nil {
		t.Fatal(err)
	}
	status := server.applicationUpdateStatus(ctx)
	if status.Status != "update_available" || !status.Available || status.LatestVersion != "v1.1.0" {
		t.Fatalf("application update status=%#v", status)
	}
	private := httptest.NewRecorder()
	server.adminStatus(private, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil), admin, defaultTenantStore(server))
	if private.Code != http.StatusOK || !strings.Contains(private.Body.String(), `"updates"`) || !strings.Contains(private.Body.String(), `"latest_version":"v1.1.0"`) {
		t.Fatalf("authenticated status=%d %s", private.Code, private.Body.String())
	}
	public := httptest.NewRecorder()
	server.setupStatus(public, httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil))
	if public.Code != http.StatusOK || strings.Contains(public.Body.String(), `"version"`) || strings.Contains(public.Body.String(), "latest_version") || strings.Contains(public.Body.String(), "release_url") {
		t.Fatalf("setup status leaked release state: %s", public.Body.String())
	}
	enabled := false
	server.App.Config.Updates.Enabled = &enabled
	disabled := server.applicationUpdateStatus(ctx)
	if disabled.Status != "disabled" || disabled.Enabled {
		t.Fatalf("disabled update status=%#v", disabled)
	}
}

// A single-unit installation keeps showing its update alert in /events and
// its failed update delivery in /status, now as the default unit's own
// copy. The platform's copy of the alert is not the unit's.
func TestEventsShowTheDefaultUnitsUpdateAlert(t *testing.T) {
	t.Parallel()
	server, db, admin := newUsersTestServer(t)
	ctx := context.Background()
	if _, err := db.Platform().RecordInstalledVersion(ctx, "v1.0.0", "", false, nil); err != nil {
		t.Fatal(err)
	}
	routes := []store.UpdateAlertRoute{{}, {TenantID: store.DefaultTenantID, Destinations: []string{"deployment-updates"}}}
	if events, err := db.Platform().RecordReleaseCheck(ctx, "v1.0.0", "v1.1.0", "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.1.0", "1.1", "2026-09-07T12:00:00Z", `"etag"`, true, routes); err != nil || len(events) != 2 {
		t.Fatalf("update alert = %v, %v", events, err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE outbox SET attempts=8,terminal_at=next_at`); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.listEvents(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil), defaultTenantStore(server), "")
	var listed struct {
		Events []struct {
			Type          string `json:"type"`
			LatestVersion string `json:"latest_version"`
		} `json:"events"`
	}
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &listed) != nil {
		t.Fatalf("events = %d: %s", recorder.Code, recorder.Body.String())
	}
	if len(listed.Events) != 1 || listed.Events[0].Type != "application-update-available" || listed.Events[0].LatestVersion != "v1.1.0" {
		t.Fatalf("events = %+v, want the update alert once", listed.Events)
	}
	status := httptest.NewRecorder()
	server.adminStatus(status, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil), admin, defaultTenantStore(server))
	var body struct {
		Telemetry struct {
			Events       int `json:"events"`
			OutboxFailed int `json:"outbox_failed"`
		} `json:"telemetry"`
	}
	if status.Code != http.StatusOK || json.Unmarshal(status.Body.Bytes(), &body) != nil {
		t.Fatalf("status = %d: %s", status.Code, status.Body.String())
	}
	if body.Telemetry.Events != 1 || body.Telemetry.OutboxFailed != 1 {
		t.Fatalf("status telemetry = %+v, want the update alert and its failed delivery once", body.Telemetry)
	}
}

func TestSetupStatusHidesVersionBeforeSetupAndIsRateLimited(t *testing.T) {
	t.Parallel()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(a, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.Version = "v9.9.9"
	request := httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil)
	request.RemoteAddr = "198.51.100.90:1234"
	first := httptest.NewRecorder()
	server.setupStatus(first, request)
	if first.Code != http.StatusOK || strings.Contains(first.Body.String(), `"version"`) {
		t.Fatalf("pre-setup status exposed version: %d %s", first.Code, first.Body.String())
	}
	for i := 0; i < 119; i++ {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil)
		req.RemoteAddr = "198.51.100.90:1234"
		server.setupStatus(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("setup status request %d = %d: %s", i+2, recorder.Code, recorder.Body.String())
		}
	}
	limited := httptest.NewRecorder()
	server.setupStatus(limited, request)
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") != "60" {
		t.Fatalf("setup status was not throttled: %d headers=%v body=%s", limited.Code, limited.Header(), limited.Body.String())
	}
}

func TestApplicationUpdateStatusCoversVersionStateMatrix(t *testing.T) {
	t.Parallel()
	server, db, _ := newUsersTestServer(t)
	ctx := context.Background()
	server.Version = "v1.2.0"
	for _, tc := range []struct {
		name   string
		latest string
		check  string
		want   string
	}{
		{name: "up to date", latest: "v1.2.0", check: "ok", want: "up_to_date"},
		{name: "ahead", latest: "v1.1.0", check: "ok", want: "ahead"},
		{name: "failed", latest: "v1.3.0", check: "failed", want: "check_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.Platform().RecordReleaseCheck(ctx, server.Version, tc.latest, "", "", "", "", false, nil); err != nil {
				t.Fatal(err)
			}
			if tc.check == "failed" {
				if err := db.Platform().RecordReleaseCheckFailure(ctx, "registry unavailable"); err != nil {
					t.Fatal(err)
				}
			}
			status := server.applicationUpdateStatus(ctx)
			if status.Status != tc.want {
				t.Fatalf("status = %#v, want %q", status, tc.want)
			}
		})
	}
	server.Version = "dev"
	if status := server.applicationUpdateStatus(ctx); status.Status != "development_build" {
		t.Fatalf("development status = %#v", status)
	}
}

func TestTenantUpdateStatusRedactsPlatformDiagnostics(t *testing.T) {
	t.Parallel()

	f := newPlatformFixture(t)
	server := f.server
	server.Version = "v1.0.0"
	ctx := context.Background()
	platform := f.db.Platform()
	accounts := []statusAccount{
		{name: actorAdminA, session: f.sessions[actorAdminA].session, ts: f.a},
		{name: actorOperatorA, session: f.sessions[actorOperatorA].session, ts: f.a},
		{name: actorViewerA, session: f.sessions[actorViewerA].session, ts: f.a},
		{name: actorAdminB, session: f.sessions[actorAdminB].session, ts: f.b},
	}
	actors := []string{actorAdminA, actorOperatorA, actorViewerA, actorAdminB}
	for _, diagnostic := range []string{
		"proxyconnect tcp: dial tcp 10.20.30.40:3128: connect: connection refused",
		"lookup api.github.com on 10.0.0.2:53: no such host",
		"dial tcp 198.51.100.9:443: i/o timeout",
		"x509: certificate signed by unknown authority",
	} {
		t.Run(diagnostic, func(t *testing.T) {
			if _, err := platform.RecordReleaseCheck(ctx, server.Version, "v1.1.0", "https://example.invalid/release", "EdgeWatch v1.1.0", "2026-10-14T12:00:00Z", `"etag"`, false, nil); err != nil {
				t.Fatal(err)
			}
			if err := platform.RecordReleaseCheckFailure(ctx, diagnostic); err != nil {
				t.Fatal(err)
			}

			// Exercise the real authenticated API for every tenant role. The
			// hidden legacy map handlers below remain byte-for-byte compatible
			// with these safe tenant responses.
			for _, actor := range actors {
				response := f.call(t, actor, http.MethodGet, "/status", "")
				if response.Code != http.StatusOK {
					t.Fatalf("tenant status for %s = %d: %s", actor, response.Code, response.Body.String())
				}
				var body struct {
					Updates struct {
						Error string `json:"error"`
					} `json:"updates"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.Updates.Error != "update_check_failed" || strings.Contains(response.Body.String(), diagnostic) {
					t.Errorf("tenant status for %s exposed unsafe update error: %s", actor, response.Body.String())
				}
			}
			compareStatuses(t, server, "failed release check", accounts)

			response := f.call(t, actorPlatform, http.MethodGet, "/platform/status", "")
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), diagnostic) {
				t.Fatalf("platform status did not retain raw diagnostic: %d %s", response.Code, response.Body.String())
			}
			var platformBody struct {
				Updates struct {
					Error string `json:"error"`
				} `json:"updates"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &platformBody); err != nil {
				t.Fatal(err)
			}
			if platformBody.Updates.Error != diagnostic {
				t.Fatalf("platform update error = %q, want raw diagnostic %q", platformBody.Updates.Error, diagnostic)
			}

			if diagnostic == "proxyconnect tcp: dial tcp 10.20.30.40:3128: connect: connection refused" {
				for _, path := range []string{"/api/v1/setup/status", "/api/public/v1/dashboard"} {
					request := httptest.NewRequest(http.MethodGet, path, nil)
					request.RemoteAddr = "198.51.100.44:9000"
					public := httptest.NewRecorder()
					server.api(public, request)
					if strings.Contains(public.Body.String(), diagnostic) {
						t.Errorf("anonymous %s response exposed update diagnostic: %s", path, public.Body.String())
					}
				}
			}
		})
	}

	if _, err := platform.RecordReleaseCheck(ctx, server.Version, "v1.1.0", "https://example.invalid/release", "EdgeWatch v1.1.0", "2026-10-14T12:00:00Z", `"etag"`, false, nil); err != nil {
		t.Fatal(err)
	}
	for _, actor := range actors {
		response := f.call(t, actor, http.MethodGet, "/status", "")
		var body struct {
			Updates struct {
				Error string `json:"error"`
			} `json:"updates"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Updates.Error != "" {
			t.Errorf("successful update status for %s contains an error: %d %s", actor, response.Code, response.Body.String())
		}
	}
}

func TestWithAuthRejectsMissingSessionWithoutCallingHandler(t *testing.T) {
	t.Parallel()
	server, _, _ := newUsersTestServer(t)
	called := false
	recorder := httptest.NewRecorder()
	server.withAuth(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil), func(http.ResponseWriter, *http.Request, store.Session) {
		called = true
	})
	if recorder.Code != http.StatusUnauthorized || called || !strings.Contains(recorder.Body.String(), "authentication required") {
		t.Fatalf("withAuth response = %d called=%v body=%s", recorder.Code, called, recorder.Body.String())
	}
}
