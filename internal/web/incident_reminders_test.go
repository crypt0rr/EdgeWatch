package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/auth"
)

func TestIncidentReminderSettingRequiresAdministratorPassword(t *testing.T) {
	server, db, admin := newUsersTestServer(t)
	ts := defaultTenantStore(server)
	if got := requiredPermission("/notifications/incident-reminders", http.MethodPut); got != auth.PermissionNotificationsManage {
		t.Fatalf("reminder permission=%q", got)
	}
	get := func() bool {
		t.Helper()
		enabled, err := ts.IncidentRemindersEnabled(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return enabled
	}
	if !get() {
		t.Fatal("reminders must default on")
	}
	for _, test := range []struct {
		body string
		want int
	}{
		{`{"password":"administrator password"}`, http.StatusBadRequest},
		{`{"enabled":false}`, http.StatusBadRequest},
		{`{"enabled":false,"password":"wrong password"}`, http.StatusUnauthorized},
	} {
		rec := httptest.NewRecorder()
		server.updateIncidentReminders(rec, routingRequest(t, http.MethodPut, "/api/v1/notifications/incident-reminders", test.body), admin, ts)
		if rec.Code != test.want || !get() {
			t.Fatalf("body %s: status=%d response=%s setting=%t", test.body, rec.Code, rec.Body.String(), get())
		}
	}
	rec := httptest.NewRecorder()
	server.updateIncidentReminders(rec, routingRequest(t, http.MethodPut, "/api/v1/notifications/incident-reminders", `{"enabled":false,"password":"administrator password"}`), admin, ts)
	if rec.Code != http.StatusOK || get() {
		t.Fatalf("disable reminder: %d %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.Enabled {
		t.Fatalf("response=%s, %v", rec.Body.String(), err)
	}
	listed := httptest.NewRecorder()
	server.listNotificationDestinations(listed, routingRequest(t, http.MethodGet, "/api/v1/notifications/destinations", ""), ts)
	var view struct {
		Enabled bool `json:"incident_reminders_enabled"`
	}
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &view) != nil || view.Enabled {
		t.Fatalf("listed setting: %d %s", listed.Code, listed.Body.String())
	}
	var audits int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action='notifications.incident_reminders_changed'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit count=%d, %v", audits, err)
	}
}
