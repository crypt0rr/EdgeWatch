package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestSessionExposesConfiguredDeploymentTimezone(t *testing.T) {
	server, _, admin := newUsersTestServer(t)
	readSession := func() map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		server.session(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil), admin)
		if rec.Code != http.StatusOK {
			t.Fatalf("session = %d: %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	if got := readSession()["timezone"]; got != "" {
		t.Fatalf("unconfigured session timezone = %#v, want empty so browsers keep their own zone", got)
	}
	server.App.Config.Timezone = " Europe/Amsterdam "
	if got := readSession()["timezone"]; got != "Europe/Amsterdam" {
		t.Fatalf("configured session timezone = %#v", got)
	}
	if (&Server{}).deploymentTimezone() != "" {
		t.Fatal("server without application config reported a timezone")
	}
}

func TestNewJobsDefaultToConfiguredDeploymentTimezone(t *testing.T) {
	server, db, admin := newUsersTestServer(t)
	create := func(name, timezone string) store.JobRecord {
		t.Helper()
		payload := map[string]any{"name": name, "schedule": "0 3 * * *", "targets": []string{"192.0.2.1"}, "tcp": map[string]any{"ports": "22", "mode": "connect"}}
		if timezone != "" {
			payload["timezone"] = timezone
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.createJob(rec, req, admin)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %s = %d: %s", name, rec.Code, rec.Body.String())
		}
		record, err := db.GetJobByName(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	if got := create("legacy-default", "").Job.Timezone; got != "UTC" {
		t.Fatalf("job without deployment timezone = %q, want UTC", got)
	}
	server.App.Config.Timezone = "Europe/Amsterdam"
	if got := create("deployment-default", "").Job.Timezone; got != "Europe/Amsterdam" {
		t.Fatalf("job without explicit timezone = %q, want the configured deployment timezone", got)
	}
	if got := create("explicit-zone", "America/New_York").Job.Timezone; got != "America/New_York" {
		t.Fatalf("explicit job timezone = %q, want it preserved", got)
	}
}

func TestDeploymentTimezoneStaysOutOfUnauthenticatedResponses(t *testing.T) {
	server, db, _ := newUsersTestServer(t)
	server.App.Config.Timezone = "Asia/Kathmandu"
	if err := db.SavePublicDashboard(context.Background(), store.PublicDashboard{Enabled: true, Title: "Public"}, nil, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	setup := httptest.NewRecorder()
	server.setupStatus(setup, httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil))
	public := httptest.NewRecorder()
	publicReq := httptest.NewRequest(http.MethodGet, "/api/public/v1/dashboard", nil)
	publicReq.RemoteAddr = "192.0.2.50:4000"
	server.publicAPI(public, publicReq)
	if public.Code != http.StatusOK {
		t.Fatalf("public dashboard = %d: %s", public.Code, public.Body.String())
	}
	for name, body := range map[string]string{"setup status": setup.Body.String(), "public dashboard": public.Body.String()} {
		if strings.Contains(body, "Kathmandu") || strings.Contains(body, "timezone") {
			t.Fatalf("%s exposed the deployment timezone: %s", name, body)
		}
	}
}
