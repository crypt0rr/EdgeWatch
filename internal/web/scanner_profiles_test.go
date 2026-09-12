package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestOperatorCannotSelectSupersededScannerProfileRevision(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	profile, err := db.CreateScannerProfile(ctx, "Revision guard", "", config.ScannerProfile{Engine: config.EngineNmap}, admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateScannerProfile(ctx, profile.ID, profile.Revision, profile.Name, "current", config.ScannerProfile{Engine: config.EngineNmap, Description: "current"}, admin.Username); err != nil {
		t.Fatal(err)
	}

	operator := admin
	operator.Role = store.RoleOperator
	historical := &config.Job{TCP: &config.Protocol{ProfileID: profile.ID, ProfileRevision: 1}}
	if err := server.applySelectedScannerProfile(ctx, historical, false, auth.HasPermission(operator, auth.PermissionScannerProfilesManage)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("operator historical profile selection error = %v, want conflict", err)
	}

	current := &config.Job{TCP: &config.Protocol{ProfileID: profile.ID, ProfileRevision: 2}}
	if err := server.applySelectedScannerProfile(ctx, current, false, true); err != nil {
		t.Fatalf("administrator current profile selection: %v", err)
	}
	if current.TCP.ProfileRevision != 2 || current.TCP.Engine != config.EngineNmap {
		t.Fatalf("current profile selection = %#v", current.TCP)
	}

	// The administrator-only capability is what allows an intentional rollback;
	// the operator session above must not be able to use the same revision.
	rollback := &config.Job{TCP: &config.Protocol{ProfileID: profile.ID, ProfileRevision: 1}}
	if err := server.applySelectedScannerProfile(ctx, rollback, false, auth.HasPermission(admin, auth.PermissionScannerProfilesManage)); err != nil {
		t.Fatalf("administrator rollback selection: %v", err)
	}
}

func TestScannerProfileMutationsMapAuditUnavailableToServiceUnavailable(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	profile, err := db.CreateScannerProfile(ctx, "Audit guarded", "", config.ScannerProfile{Engine: config.EngineNmap}, admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `CREATE TRIGGER fail_scanner_profile_audit BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.ExecContext(ctx, `DROP TRIGGER fail_scanner_profile_audit`) })

	call := func(method, rest, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, "/api/v1/scanner-profiles/"+rest, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		server.scannerProfilesRoute(recorder, request, admin, rest)
		return recorder
	}
	assertAuditUnavailable := func(name string, recorder *httptest.ResponseRecorder) {
		t.Helper()
		if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"code":"audit_unavailable"`) {
			t.Fatalf("%s response = %d %s", name, recorder.Code, recorder.Body.String())
		}
	}

	assertAuditUnavailable("create", call(http.MethodPost, "", `{"name":"new profile","engine":"nmap","password":"administrator password"}`))
	assertAuditUnavailable("update", call(http.MethodPut, profile.ID, `{"name":"updated profile","engine":"nmap","password":"administrator password","revision":1}`))
	assertAuditUnavailable("archive", call(http.MethodDelete, profile.ID, `{"password":"administrator password","revision":1}`))
}
