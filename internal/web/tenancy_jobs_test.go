package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The job writes reach the job named in the path only within the session's
// tenant. An administrator of another tenant cannot update, archive,
// restore, pause, resume, run, or delete the job by ID: each request is not
// found, and the job and its revisions are unchanged. A job that
// administrator creates belongs to their tenant, even with a name the first
// tenant already uses.
func TestJobWritesUseTheSessionTenant(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	newJob := func(name string) config.Job {
		return config.NormalizeJob(config.Job{Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "1", Mode: "connect", Engine: config.EngineNmap}})
	}
	own := defaultTenantStore(server)
	active, err := own.CreateJob(ctx, newJob("tenant-a-job"))
	if err != nil {
		t.Fatal(err)
	}
	archived, err := own.CreateJob(ctx, newJob("tenant-a-archived"))
	if err != nil {
		t.Fatal(err)
	}
	if err := own.SetJobArchived(ctx, archived.ID, true); err != nil {
		t.Fatal(err)
	}
	const otherTenantID = "00000000-0000-0000-0000-000000000200"
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, otherTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	other, err := db.CreateUser(ctx, store.User{Username: "other-admin", DisplayName: "Other", Role: store.RoleAdministrator, PasswordHash: "unused-hash", Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE users SET tenant_id=? WHERE id=?`, otherTenantID, other.ID); err != nil {
		t.Fatal(err)
	}
	cookies := map[string]string{}
	for name, userID := range map[string]string{"own": admin.UserID, "other": other.ID} {
		raw := "tenant-write-" + name
		if err := db.CreateSessionForUserWithAudit(ctx, userID, digest(raw), "csrf-"+name, now, now.Add(time.Hour), "", ""); err != nil {
			t.Fatal(err)
		}
		cookies[name] = raw
	}
	call := func(account, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "edgewatch_session", Value: cookies[account]})
		req.Header.Set("X-CSRF-Token", "csrf-"+account)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.api(rec, req)
		return rec
	}
	// snapshot holds what a write would change: each job's record and its
	// revision history.
	snapshot := func() map[string]any {
		out := map[string]any{}
		for _, id := range []string{active.ID, archived.ID} {
			record, err := own.GetJob(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			var revisions int
			if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_revisions WHERE job_id=?`, id).Scan(&revisions); err != nil {
				t.Fatal(err)
			}
			out[id] = []any{record, revisions}
		}
		return out
	}
	update := fromConfig(active.Job)
	update.Revision = active.Revision
	update.Schedule = "30 * * * *"
	updateBody, err := json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	jobs := "/api/v1/jobs/"
	before := snapshot()
	for _, write := range []struct{ method, path, body string }{
		{http.MethodPut, jobs + active.ID, string(updateBody)},
		{http.MethodPost, jobs + active.ID + "/archive", `{"revision":1}`},
		{http.MethodDelete, jobs + active.ID, `{"revision":1}`},
		{http.MethodPost, jobs + archived.ID + "/restore", `{"revision":2}`},
		{http.MethodPost, jobs + active.ID + "/pause", `{"revision":1}`},
		{http.MethodPost, jobs + active.ID + "/resume", `{"revision":1}`},
		{http.MethodPost, jobs + active.ID + "/run", ``},
		{http.MethodDelete, jobs + archived.ID + "?permanent=true", `{"confirm_name":"tenant-a-archived"}`},
	} {
		if rec := call("other", write.method, write.path, write.body); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "job not found") {
			t.Errorf("other tenant: %s %s = %d: %s", write.method, write.path, rec.Code, rec.Body.String())
		}
	}
	if after := snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatalf("another tenant's writes changed the jobs:\nbefore %+v\nafter  %+v", before, after)
	}

	// The same writes by the job's own tenant still work.
	if rec := call("own", http.MethodPost, jobs+active.ID+"/pause", `{"revision":1}`); rec.Code != http.StatusNoContent {
		t.Fatalf("own tenant: pause = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("own", http.MethodPost, jobs+active.ID+"/archive", `{"revision":2}`); rec.Code != http.StatusNoContent {
		t.Fatalf("own tenant: archive = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("own", http.MethodDelete, jobs+archived.ID+"?permanent=true", `{"confirm_name":"tenant-a-archived"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("own tenant: permanent delete = %d: %s", rec.Code, rec.Body.String())
	}

	rec := call("other", http.MethodPost, "/api/v1/jobs", `{"name":"tenant-a-job","schedule":"0 * * * *","timezone":"UTC","targets":["192.0.2.20"],"tcp":{"ports":"1","mode":"connect","engine":"nmap"}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("other tenant: create a job with a name in use by the first tenant = %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("created job = %s, %v", rec.Body.String(), err)
	}
	if strings.Contains(rec.Body.String(), otherTenantID) {
		t.Fatalf("the job response exposes its tenant: %s", rec.Body.String())
	}
	var owner string
	if err := db.DB.QueryRowContext(ctx, `SELECT tenant_id FROM jobs WHERE id=?`, created.ID).Scan(&owner); err != nil || owner != otherTenantID {
		t.Fatalf("created job's tenant = %q, %v", owner, err)
	}
	if rec := call("own", http.MethodGet, jobs+created.ID, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("own tenant: GET the other tenant's job = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("own", http.MethodPost, jobs+created.ID+"/pause", `{"revision":1}`); rec.Code != http.StatusNotFound {
		t.Fatalf("own tenant: pause the other tenant's job = %d: %s", rec.Code, rec.Body.String())
	}
}

// A job that the tenant no longer has when the scan lease check of an update
// or a manual run looks at it, because it was deleted after the router
// loaded it, is not found, as it would be by the write itself. (In the
// default tenant an ID without a job is a config.yaml job's lease key, which
// is simply not leased.)
func TestJobWritesReportAJobDeletedSinceLookupAsNotFound(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	const otherTenantID = "00000000-0000-0000-0000-000000000200"
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, otherTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	scope, err := db.TenantScopeByID(ctx, otherTenantID)
	if err != nil {
		t.Fatal(err)
	}
	ts := db.Tenant(scope)
	record, err := ts.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "deleted-since-lookup", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "1", Mode: "connect", Engine: config.EngineNmap}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.SetJobArchived(ctx, record.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := ts.DeleteJob(ctx, record.ID); err != nil {
		t.Fatal(err)
	}
	payload := fromConfig(record.Job)
	payload.Revision = record.Revision
	update := jobUpdateRequest{payload: payload, job: record.Job}
	updated := httptest.NewRecorder()
	server.updateJob(updated, jobWriteRequest(http.MethodPut, "/api/v1/jobs/"+record.ID, "", "stale-update"), admin, ts, record, update)
	if updated.Code != http.StatusNotFound || !strings.Contains(updated.Body.String(), "job not found") {
		t.Fatalf("update = %d: %s", updated.Code, updated.Body.String())
	}
	run := httptest.NewRecorder()
	server.runJob(run, jobWriteRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/run", "", "stale-run"), admin, ts, record)
	if run.Code != http.StatusNotFound || !strings.Contains(run.Body.String(), "job not found") {
		t.Fatalf("run = %d: %s", run.Code, run.Body.String())
	}
}
