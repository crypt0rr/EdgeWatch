package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// A manual run whose tenant's probe budget cannot be read is refused, never
// checked against the deployment's budget instead. A tenant that is gone is
// not found; a failed read is an internal error that keeps its storage
// detail out of the response. Neither run starts.
func TestRunRefusesAJobWhoseProbeBudgetCannotBeRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	newJob := func(ts *store.TenantStore, name string) store.JobRecord {
		t.Helper()
		record, err := ts.CreateJob(ctx, config.NormalizeJob(config.Job{Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "1", Mode: "connect", Engine: config.EngineNmap}}))
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	run := func(ts *store.TenantStore, record store.JobRecord) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		server.runJob(rec, httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/jobs/"+record.ID+"/run", nil), admin, ts, record)
		if active, err := ts.JobActive(ctx, record.ID); err == nil && active {
			t.Fatal("a refused run holds a scan lease")
		}
		return rec
	}

	const otherTenantID = "00000000-0000-0000-0000-000000000200"
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, otherTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	scope, err := db.TenantScopeByID(ctx, otherTenantID)
	if err != nil {
		t.Fatal(err)
	}
	other := db.Tenant(scope)
	otherJob := newJob(other, "other-tenant-job")
	if _, err := db.DB.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, store.TenantStateDeleted, otherTenantID); err != nil {
		t.Fatal(err)
	}
	if rec := run(other, otherJob); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "job not found") {
		t.Fatalf("run in a deleted tenant = %d: %s", rec.Code, rec.Body.String())
	}

	own := defaultTenantStore(server)
	ownJob := newJob(own, "own-tenant-job")
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE tenants RENAME COLUMN high_cost_ceiling TO unreadable_ceiling`); err != nil {
		t.Fatal(err)
	}
	rec := run(own, ownJob)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "ceiling") || strings.Contains(rec.Body.String(), "column") || strings.Contains(rec.Body.String(), "probe budget") {
		t.Fatalf("run with an unreadable budget = %d: %s", rec.Code, rec.Body.String())
	}
	if scans, err := own.ListJobScans(ctx, ownJob.ID, 10); err != nil || len(scans) != 0 {
		t.Fatalf("a refused run recorded scans: %d, %v", len(scans), err)
	}
}
