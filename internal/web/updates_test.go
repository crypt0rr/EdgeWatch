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
	if status["status"] != "update_available" || status["available"] != true || status["latest_version"] != "v1.1.0" {
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
	if disabled["status"] != "disabled" || disabled["enabled"] != false {
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
			if status["status"] != tc.want {
				t.Fatalf("status = %#v, want %q", status, tc.want)
			}
		})
	}
	server.Version = "dev"
	if status := server.applicationUpdateStatus(ctx); status["status"] != "development_build" {
		t.Fatalf("development status = %#v", status)
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
