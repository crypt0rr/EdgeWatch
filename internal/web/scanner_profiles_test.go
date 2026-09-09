package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
)

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
