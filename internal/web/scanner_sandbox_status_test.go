package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestAdminStatusReportsTheScannerSandbox(t *testing.T) {
	t.Parallel()
	server, db, admin := newUsersTestServer(t)
	viewerUser, err := storetest.CreateUser(context.Background(), db, store.DefaultTenantScope(), store.User{Username: "viewer", DisplayName: "Read only", Role: store.RoleViewer, PasswordHash: "hash", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	status := func(session store.Session) map[string]json.RawMessage {
		t.Helper()
		rec := httptest.NewRecorder()
		server.adminStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil), session, defaultTenantStore(server))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	// The test application has no sandbox policy, so its scanner processes
	// start unconfined.
	var sandbox struct {
		Mode  string `json:"mode"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(status(admin)["scanner_sandbox"], &sandbox); err != nil || sandbox.State != "disabled" {
		t.Fatalf("administrator scanner_sandbox = %+v (%v), want disabled", sandbox, err)
	}
	if err := json.Unmarshal(status(admin)["notification_sandbox"], &sandbox); err != nil || sandbox.State != "disabled" {
		t.Fatalf("administrator notification_sandbox = %+v (%v), want disabled", sandbox, err)
	}
	viewer := store.Session{UserID: viewerUser.ID, Username: viewerUser.Username, Role: store.RoleViewer}
	for _, key := range []string{"scanner_sandbox", "notification_sandbox"} {
		if _, ok := status(viewer)[key]; ok {
			t.Fatalf("a viewer's status names %s", key)
		}
	}
}

func TestAdminStatusReportsScannerPoolWithoutAStableUID(t *testing.T) {
	t.Parallel()
	server, db, admin := newUsersTestServer(t)
	confined, err := app.NewWithOptions(server.App.Config, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)), app.Options{Sandbox: sandbox.NewEnforced()})
	if err != nil {
		t.Fatal(err)
	}
	server.App = confined
	rec := httptest.NewRecorder()
	server.adminStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil), admin, defaultTenantStore(server))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Scanner struct {
			UID          *int                               `json:"uid"`
			GID          *int                               `json:"gid"`
			ProcessUID   *int                               `json:"process_uid"`
			IdentityPool *sandbox.ScannerIdentityPoolStatus `json:"identity_pool"`
			Seccomp      sandbox.SeccompStatus              `json:"seccomp"`
		} `json:"scanner_sandbox"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Scanner.UID != nil || body.Scanner.GID != nil || body.Scanner.ProcessUID != nil {
		t.Fatalf("scanner status exposes a stable UID: %+v", body.Scanner)
	}
	pool := body.Scanner.IdentityPool
	if pool == nil || pool.State != sandbox.StateEnforced || pool.Strategy != "per_invocation" || pool.UIDStart != sandbox.ScannerIdentityPoolUIDStart || pool.UIDEnd != sandbox.ScannerIdentityPoolUIDEnd || pool.MaxParallel != sandbox.ScannerIdentityPoolCapacity {
		t.Fatalf("scanner identity pool = %+v", pool)
	}
	if body.Scanner.Seccomp.State != sandbox.StateEnforced {
		t.Fatalf("scanner seccomp = %+v, want independently enforced", body.Scanner.Seccomp)
	}
}
