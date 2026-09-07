package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
