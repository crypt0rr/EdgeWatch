package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
)

func TestIncidentReminderSettingRequiresAdministratorPassword(t *testing.T) {
	server, db, admin := newUsersTestServer(t)
	ts := defaultTenantStore(server)
	if got := requiredPermission("/notifications/incident-reminders", http.MethodPut); got != auth.PermissionNotificationsManage {
		t.Fatalf("reminder permission=%q", got)
	}
	get := func() (bool, string) {
		t.Helper()
		settings, err := ts.IncidentReminderSettings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return settings.Enabled, settings.Cadence
	}
	if enabled, cadence := get(); !enabled || cadence != "every_scan" {
		t.Fatalf("reminders must default to on/every_scan, got enabled=%t cadence=%q", enabled, cadence)
	}
	for _, test := range []struct {
		body string
		want int
	}{
		{`{"password":"administrator password"}`, http.StatusBadRequest},
		{`{"enabled":false}`, http.StatusBadRequest},
		{`{"enabled":false,"password":"wrong password"}`, http.StatusUnauthorized},
		{`{"cadence":"weekly","password":"administrator password"}`, http.StatusBadRequest},
	} {
		rec := httptest.NewRecorder()
		server.updateIncidentReminders(rec, routingRequest(t, http.MethodPut, "/api/v1/notifications/incident-reminders", test.body), admin, ts)
		if rec.Code != test.want {
			t.Fatalf("body %s: status=%d response=%s", test.body, rec.Code, rec.Body.String())
		}
		if enabled, cadence := get(); !enabled || cadence != "every_scan" {
			t.Fatalf("body %s changed settings: enabled=%t cadence=%q", test.body, enabled, cadence)
		}
	}
	rec := httptest.NewRecorder()
	server.updateIncidentReminders(rec, routingRequest(t, http.MethodPut, "/api/v1/notifications/incident-reminders", `{"enabled":false,"password":"administrator password"}`), admin, ts)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable reminder: %d %s", rec.Code, rec.Body.String())
	}
	if enabled, cadence := get(); enabled || cadence != "every_scan" {
		t.Fatalf("disable changed to enabled=%t cadence=%q", enabled, cadence)
	}
	var result struct {
		Enabled bool   `json:"enabled"`
		Cadence string `json:"cadence"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.Enabled || result.Cadence != "every_scan" {
		t.Fatalf("response=%s, %v", rec.Body.String(), err)
	}
	setCadence := httptest.NewRecorder()
	server.updateIncidentReminders(setCadence, routingRequest(t, http.MethodPut, "/api/v1/notifications/incident-reminders", `{"cadence":"daily","password":"administrator password"}`), admin, ts)
	if setCadence.Code != http.StatusOK {
		t.Fatalf("set cadence: %d %s", setCadence.Code, setCadence.Body.String())
	}
	var cadenceResult struct {
		Enabled bool   `json:"enabled"`
		Cadence string `json:"cadence"`
	}
	if err := json.Unmarshal(setCadence.Body.Bytes(), &cadenceResult); err != nil || cadenceResult.Enabled || cadenceResult.Cadence != "daily" {
		t.Fatalf("cadence response=%s, %v", setCadence.Body.String(), err)
	}
	listed := httptest.NewRecorder()
	server.listNotificationDestinations(listed, routingRequest(t, http.MethodGet, "/api/v1/notifications/destinations", ""), ts)
	var view struct {
		Enabled bool   `json:"incident_reminders_enabled"`
		Cadence string `json:"incident_reminder_cadence"`
	}
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &view) != nil || view.Enabled || view.Cadence != "daily" {
		t.Fatalf("listed setting: %d %s", listed.Code, listed.Body.String())
	}
	var audits int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action='notifications.incident_reminders_changed'`).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("audit count=%d, %v", audits, err)
	}
}

func TestIncidentReminderSettingAPIIsRouted(t *testing.T) {
	server, db, admin := newUsersTestServer(t)
	ctx := context.Background()
	const raw, csrf = "incident-reminder-route-session", "incident-reminder-route-csrf"
	now := time.Now().UTC()
	if err := db.CreateSessionForUserWithAudit(ctx, admin.UserID, digest(raw), csrf, now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/notifications/incident-reminders", strings.NewReader(`{"enabled":false,"password":"administrator password"}`))
	request.RemoteAddr = "127.0.0.1:9100"
	request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
	request.Header.Set("X-CSRF-Token", csrf)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.api(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("incident reminder route status = %d: %s", response.Code, response.Body.String())
	}
	if settings, err := defaultTenantStore(server).IncidentReminderSettings(ctx); err != nil || settings.Enabled || settings.Cadence != "every_scan" {
		t.Fatalf("routed settings = %+v, %v; want disabled/every_scan", settings, err)
	}
}
