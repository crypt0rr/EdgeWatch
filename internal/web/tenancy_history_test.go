package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The history routes and incident actions use the session's tenant. Both
// tenants have a job named "edge" that watches the same address, so both
// have an incident with the same key. An account of the second tenant sees
// only its own scans, events and incidents, also when it filters by the
// shared job name, and an incident action on the first tenant's job is
// answered as for an unknown job and changes nothing. The cases share one
// server, because opening a database is the slow part.
func TestHistoryRoutesUseTheSessionTenant(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{Name: "edge", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"}})
	jobA, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	const otherTenantID = "00000000-0000-0000-0000-000000000200"
	const jobB = "00000000-0000-0000-0000-000000000b01"
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	for _, statement := range []string{
		`INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES('` + otherTenantID + `','Other','other','` + stamp + `','` + stamp + `')`,
		`INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) SELECT '` + jobB + `','` + otherTenantID + `',name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs WHERE id='` + jobA.ID + `'`,
		`INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) SELECT '` + jobB + `',revision,definition_json,security_hash,created_at FROM job_revisions WHERE job_id='` + jobA.ID + `'`,
	} {
		if _, err := db.DB.ExecContext(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	key := "port|192.0.2.10|tcp|443"
	change := model.Change{Key: key, Kind: "port", Target: "192.0.2.10", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}
	for jobID, marker := range map[string]string{jobA.ID: "tenant-a", jobB: "tenant-b"} {
		if err := db.System().SaveScan(ctx, model.Scan{ID: "scan-" + marker, JobID: jobID, Job: "edge", StartedAt: now.Add(-time.Minute), FinishedAt: now, Status: "success"}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.System().UpdateRuntime(ctx, jobID, func(state *model.JobState) ([]model.Event, error) {
			state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.10", Protocol: "tcp", Ports: "443"}}}
			state.Incidents[key] = model.Incident{Change: change, ScanID: "scan-" + marker, OpenedAt: now, LastSeenAt: now}
			return []model.Event{{Type: "changes-detected", Job: "edge", ScanID: "scan-" + marker, Message: "event-" + marker, CreatedAt: now}}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	other, err := defaultTenant(db).CreateUser(ctx, store.User{Username: "other-admin", DisplayName: "Other", Role: store.RoleAdministrator, PasswordHash: "unused-hash", Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE users SET tenant_id=? WHERE id=?`, otherTenantID, other.ID); err != nil {
		t.Fatal(err)
	}
	cookies := map[string]string{}
	for name, userID := range map[string]string{"a": admin.UserID, "b": other.ID} {
		raw := "tenant-history-" + name
		if err := db.CreateSessionForUserWithAudit(ctx, userID, digest(raw), "csrf-"+name, now, now.Add(time.Hour), "", ""); err != nil {
			t.Fatal(err)
		}
		cookies[name] = raw
	}
	call := func(account, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "edgewatch_session", Value: cookies[account]})
		req.Header.Set("X-CSRF-Token", "csrf-"+account)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		server.api(rec, req)
		return rec
	}

	// Each tenant reads only its own history, and the job name filter does
	// not reach the other tenant's job of the same name.
	own := map[string]string{"a": "tenant-a", "b": "tenant-b"}
	ownJob := map[string]string{"a": jobA.ID, "b": jobB}
	for account, other := range map[string]string{"a": "b", "b": "a"} {
		for _, path := range []string{"/api/v1/scans", "/api/v1/scans?job=edge", "/api/v1/events", "/api/v1/events?job=edge", "/api/v1/events?job_id=" + ownJob[account], "/api/v1/incidents"} {
			rec := call(account, http.MethodGet, path, "")
			body := rec.Body.String()
			if rec.Code != http.StatusOK || !strings.Contains(body, own[account]) || strings.Contains(body, own[other]) || strings.Contains(body, ownJob[other]) {
				t.Errorf("tenant %s: GET %s = %d: %s", account, path, rec.Code, body)
			}
		}
		// Another tenant's job ID reads as an unknown job: no events.
		for _, jobID := range []string{ownJob[other], "00000000-0000-0000-0000-00000000dead"} {
			rec := call(account, http.MethodGet, "/api/v1/events?job_id="+jobID, "")
			var got struct {
				Events     []json.RawMessage `json:"events"`
				Pagination struct {
					Total int `json:"total"`
				} `json:"pagination"`
			}
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || len(got.Events) != 0 || got.Pagination.Total != 0 {
				t.Errorf("tenant %s: events of job %s = %d: %s", account, jobID, rec.Code, rec.Body.String())
			}
		}
	}

	// An incident action on tenant A's job, from tenant B, gets the response
	// of an unknown job, byte for byte, and changes nothing. Tenant B's own
	// incident with the same key can still be accepted.
	raw, err := json.Marshal(map[string]any{"key": key, "expected_change": change})
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, action := range []string{"accept", "suppress"} {
		unknown := call("b", http.MethodPost, "/api/v1/jobs/00000000-0000-0000-0000-00000000dead/incidents/"+action, body)
		foreign := call("b", http.MethodPost, "/api/v1/jobs/"+jobA.ID+"/incidents/"+action, body)
		if foreign.Code != http.StatusNotFound || foreign.Code != unknown.Code || foreign.Body.String() != unknown.Body.String() {
			t.Fatalf("%s tenant A's incident from tenant B = %d %s; unknown job = %d %s", action, foreign.Code, foreign.Body.String(), unknown.Code, unknown.Body.String())
		}
	}
	if rec := call("b", http.MethodPost, "/api/v1/jobs/"+jobB+"/incidents/accept", body); rec.Code != http.StatusNoContent {
		t.Fatalf("accept tenant B's own incident = %d: %s", rec.Code, rec.Body.String())
	}
	tenantA := db.Tenant(store.DefaultTenantScope())
	incidents, err := tenantA.ListJobIncidentsPage(ctx, jobA.ID, 10, 0)
	if err != nil || incidents.Total != 1 || incidents.Items[0].Change != change {
		t.Fatalf("tenant A's incidents after tenant B's actions = %+v, %v", incidents, err)
	}
	events, err := tenantA.ListJobEventsPage(ctx, jobA.ID, 10, 0)
	if err != nil || events.Total != 1 || events.Items[0].Message != "event-tenant-a" {
		t.Fatalf("tenant A's events after tenant B's actions = %+v, %v", events, err)
	}
	if rec := call("b", http.MethodGet, "/api/v1/incidents", ""); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("tenant B's incidents after its accept = %d: %s", rec.Code, rec.Body.String())
	}
}
