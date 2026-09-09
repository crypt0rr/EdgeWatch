package web

import (
	"context"
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
	server, db, admin := newUsersTestServer(t)
	server.Version = "v1.0.0"
	ctx := context.Background()
	if _, err := db.RecordInstalledVersion(ctx, "v1.0.0", "", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordReleaseCheck(ctx, "v1.0.0", "v1.1.0", "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.1.0", "1.1", "2026-09-07T12:00:00Z", `"etag"`, false, nil); err != nil {
		t.Fatal(err)
	}
	status := server.applicationUpdateStatus(ctx)
	if status["status"] != "update_available" || status["available"] != true || status["latest_version"] != "v1.1.0" {
		t.Fatalf("application update status=%#v", status)
	}
	private := httptest.NewRecorder()
	server.adminStatus(private, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil), admin)
	if private.Code != http.StatusOK || !strings.Contains(private.Body.String(), `"updates"`) || !strings.Contains(private.Body.String(), `"latest_version":"v1.1.0"`) {
		t.Fatalf("authenticated status=%d %s", private.Code, private.Body.String())
	}
	public := httptest.NewRecorder()
	server.setupStatus(public, httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil))
	if public.Code != http.StatusOK || strings.Contains(public.Body.String(), "latest_version") || strings.Contains(public.Body.String(), "release_url") {
		t.Fatalf("setup status leaked release state: %s", public.Body.String())
	}
	enabled := false
	server.App.Config.Updates.Enabled = &enabled
	disabled := server.applicationUpdateStatus(ctx)
	if disabled["status"] != "disabled" || disabled["enabled"] != false {
		t.Fatalf("disabled update status=%#v", disabled)
	}
}

func TestSetupStatusHidesVersionBeforeSetupAndIsRateLimited(t *testing.T) {
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
