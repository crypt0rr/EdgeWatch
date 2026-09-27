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
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The scan cycle routes read and discard cycles through the session's
// tenant. Both tenants have a job named "edge" with a paused cycle. An
// account of the second tenant sees only its own cycle on its job page,
// its job list and its cycle route. It gets exactly the response for an
// unknown job when it names the first tenant's job, and exactly the
// response for an unknown cycle when it discards the first tenant's cycle
// under its own job, which leaves that cycle unchanged.
func TestScanCycleRoutesUseTheSessionTenant(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{Name: "edge", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect", Engine: config.EngineNmap}})
	own := defaultTenantStore(server)
	jobA, err := own.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	const (
		otherTenantID = "00000000-0000-0000-0000-000000000200"
		jobB          = "00000000-0000-0000-0000-000000000b01"
		unknownJob    = "00000000-0000-0000-0000-00000000dead"
		cycleA        = "cycle-tenant-a"
		cycleB        = "cycle-tenant-b"
	)
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, []any{otherTenantID, stamp, stamp}},
		// Tenant B's job is a copy of tenant A's, with the same name.
		{`INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) SELECT ?,?,name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs WHERE id=?`, []any{jobB, otherTenantID, jobA.ID}},
		{`INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) SELECT ?,revision,definition_json,security_hash,created_at FROM job_revisions WHERE job_id=?`, []any{jobB, jobA.ID}},
	} {
		if _, err := db.DB.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for jobID, cycleID := range map[string]string{jobA.ID: cycleA, jobB: cycleB} {
		unit := scanner.WorkUnit{Sequence: 0, Engine: config.EngineNmap, Protocol: "tcp", Family: 4, Addresses: []string{"192.0.2.10"}, Ports: "443", PortCount: 1, Probes: 1}
		plan := scanner.WorkPlan{CreatedAt: now, Job: jobA.Job, Scopes: []model.Scope{{Target: "192.0.2.10", Protocol: "tcp", Ports: "443"}}, Units: []scanner.WorkUnit{unit}}
		if _, err := db.System().CreateScanCycle(ctx, store.ScanCycleRecord{ID: cycleID, JobID: jobID, Job: "edge", JobRevision: jobA.Revision, ConfigHash: job.SecurityHash(), Plan: plan}); err != nil {
			t.Fatal(err)
		}
	}
	other, err := defaultTenant(db).CreateUser(ctx, store.User{Username: "other-cycle-admin", DisplayName: "Other", Role: store.RoleAdministrator, PasswordHash: "unused-hash", Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE users SET tenant_id=? WHERE id=?`, otherTenantID, other.ID); err != nil {
		t.Fatal(err)
	}
	cookies := map[string]string{}
	for name, userID := range map[string]string{"a": admin.UserID, "b": other.ID} {
		raw := "tenant-cycle-" + name
		if err := db.CreateSessionForUserWithAudit(ctx, userID, digest(raw), "csrf-"+name, now, now.Add(time.Hour), "", ""); err != nil {
			t.Fatal(err)
		}
		cookies[name] = raw
	}
	call := func(account, method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.AddCookie(&http.Cookie{Name: "edgewatch_session", Value: cookies[account]})
		req.Header.Set("X-CSRF-Token", "csrf-"+account)
		rec := httptest.NewRecorder()
		server.api(rec, req)
		return rec
	}
	// cycleOf returns the ID of the cycle that a job response shows.
	cycleOf := func(label string, raw []byte) string {
		t.Helper()
		var body struct {
			ScanCycle *struct {
				ID    string `json:"id"`
				JobID string `json:"job_id"`
			} `json:"scan_cycle"`
			Cycle *struct {
				ID    string `json:"id"`
				JobID string `json:"job_id"`
			} `json:"cycle"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("%s: %v: %s", label, err, raw)
		}
		switch {
		case body.ScanCycle != nil:
			return body.ScanCycle.ID + "@" + body.ScanCycle.JobID
		case body.Cycle != nil:
			return body.Cycle.ID + "@" + body.Cycle.JobID
		}
		return ""
	}
	cycleA0, err := own.GetScanCycle(ctx, cycleA)
	if err != nil {
		t.Fatal(err)
	}

	// Each tenant's job page, job list and cycle route show its own cycle.
	for account, want := range map[string]struct{ job, cycle, other string }{"a": {jobA.ID, cycleA, cycleB}, "b": {jobB, cycleB, cycleA}} {
		for _, path := range []string{"/api/v1/jobs/" + want.job, "/api/v1/jobs/" + want.job + "/scan-cycle"} {
			rec := call(account, http.MethodGet, path)
			if got := cycleOf(path, rec.Body.Bytes()); rec.Code != http.StatusOK || got != want.cycle+"@"+want.job {
				t.Errorf("tenant %s: GET %s = %d, cycle %q: %s", account, path, rec.Code, got, rec.Body.String())
			}
		}
		rec := call(account, http.MethodGet, "/api/v1/jobs")
		if body := rec.Body.String(); rec.Code != http.StatusOK || !strings.Contains(body, `"id":"`+want.cycle+`"`) || strings.Contains(body, want.other) {
			t.Errorf("tenant %s: GET /jobs = %d: %s", account, rec.Code, body)
		}
	}

	// Tenant A's job is an unknown job to tenant B, and tenant A's cycle an
	// unknown cycle under B's own job.
	for _, pair := range []struct{ method, foreign, unknown string }{
		{http.MethodGet, "/api/v1/jobs/" + jobA.ID + "/scan-cycle", "/api/v1/jobs/" + unknownJob + "/scan-cycle"},
		{http.MethodDelete, "/api/v1/jobs/" + jobA.ID + "/scan-cycle/" + cycleA, "/api/v1/jobs/" + unknownJob + "/scan-cycle/" + cycleA},
		{http.MethodDelete, "/api/v1/jobs/" + jobB + "/scan-cycle/" + cycleA, "/api/v1/jobs/" + jobB + "/scan-cycle/cycle-unknown"},
	} {
		unknown := call("b", pair.method, pair.unknown)
		foreign := call("b", pair.method, pair.foreign)
		if foreign.Code != http.StatusNotFound || foreign.Code != unknown.Code || foreign.Body.String() != unknown.Body.String() {
			t.Errorf("tenant B: %s %s = %d %s; unknown = %d %s", pair.method, pair.foreign, foreign.Code, foreign.Body.String(), unknown.Code, unknown.Body.String())
		}
	}
	if cycle, err := own.GetScanCycle(ctx, cycleA); err != nil || cycle.Status != "paused" || !cycle.UpdatedAt.Equal(cycleA0.UpdatedAt) || cycle.TotalUnits != 1 {
		t.Fatalf("tenant A's cycle after tenant B's requests = %+v, %v", cycle, err)
	}

	// Tenant B discards its own cycle; tenant A's is unchanged.
	if rec := call("b", http.MethodDelete, "/api/v1/jobs/"+jobB+"/scan-cycle/"+cycleB); rec.Code != http.StatusNoContent {
		t.Fatalf("tenant B: discard its own cycle = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("b", http.MethodGet, "/api/v1/jobs/"+jobB+"/scan-cycle"); rec.Code != http.StatusOK || cycleOf("cycle", rec.Body.Bytes()) != "" {
		t.Errorf("tenant B: cycle after its discard = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("a", http.MethodGet, "/api/v1/jobs/"+jobA.ID+"/scan-cycle"); rec.Code != http.StatusOK || cycleOf("cycle", rec.Body.Bytes()) != cycleA+"@"+jobA.ID {
		t.Errorf("tenant A: cycle after tenant B's discard = %d: %s", rec.Code, rec.Body.String())
	}
	if cycle, err := own.GetScanCycle(ctx, cycleA); err != nil || cycle.Status != "paused" || !cycle.UpdatedAt.Equal(cycleA0.UpdatedAt) {
		t.Fatalf("tenant A's cycle after tenant B's discard = %+v, %v", cycle, err)
	}
}
