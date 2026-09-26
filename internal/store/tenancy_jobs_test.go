package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
)

// The job writes and JobActive join the leak suite from here, so each store
// slice keeps its leak cases in its own file.
func init() {
	for name, leak := range jobLeakCases {
		if _, duplicate := tenantStoreLeakCases[name]; duplicate {
			panic("two leak cases for TenantStore." + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

// tenantJobTables are the tables that hold a tenant's jobs and the rows that
// belong to them, each with the predicate that selects the tenant's rows.
var tenantJobTables = []struct{ table, predicate string }{
	{"jobs", "tenant_id=?1"},
	{"job_revisions", "job_id IN (SELECT id FROM jobs WHERE tenant_id=?1)"},
	{"job_runtime", "job_id IN (SELECT id FROM jobs WHERE tenant_id=?1)"},
	{"job_runtime_meta", "job_id IN (SELECT id FROM jobs WHERE tenant_id=?1)"},
	{"job_silence_state", "job_id IN (SELECT id FROM jobs WHERE tenant_id=?1)"},
	{"runtime_incidents", "job_id IN (SELECT id FROM jobs WHERE tenant_id=?1)"},
	{"baseline_hosts", "job_id IN (SELECT id FROM jobs WHERE tenant_id=?1)"},
	{"scan_cycles", "job_id IN (SELECT id FROM jobs WHERE tenant_id=?1)"},
	{"scans", "tenant_id=?1"},
	{"events", "tenant_id=?1"},
	{"outbox", "tenant_id=?1"},
	{"security_audit", "tenant_id=?1"},
}

// tenantJobDigest returns a digest of every row of tenantJobTables that
// belongs to the tenant, so a test can show that a write through another
// tenant left them unchanged, its audit records included: a TenantStore
// records its audit in its own tenant.
func tenantJobDigest(t *testing.T, s *Store, tenant TenantScope) string {
	t.Helper()
	digest := sha256.New()
	for _, source := range tenantJobTables {
		fmt.Fprintf(digest, "%s:%s\n", source.table, tenantRows(t, s, source.table, source.predicate, tenant))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// tenantRows returns the tenant's rows of one table as text.
func tenantRows(t *testing.T, s *Store, table, predicate string, tenant TenantScope) string {
	t.Helper()
	rows, err := s.DB.Query(`SELECT * FROM `+table+` WHERE `+predicate+` ORDER BY rowid`, tenant.ID())
	if err != nil {
		t.Fatalf("%s: %v", table, err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	values := make([]any, len(columns))
	pointers := make([]any, len(columns))
	for i := range values {
		pointers[i] = &values[i]
	}
	text := ""
	for rows.Next() {
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		text += fmt.Sprintf("%q\n", values)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return text
}

// tenantJobWrite is one write to a job. It stands in for each variant of a
// write, so a helper can check every variant the same way.
type tenantJobWrite func(ts *TenantStore, id string) error

// assertTenantWritesOnlyItsJobs runs the write through tenant B against
// each of tenant A's jobs, then against B's own job. Each of A's jobs is
// not found, exactly as an unknown ID, and A's rows are unchanged, although
// the write names A's current revision. B's own job is written.
func assertTenantWritesOnlyItsJobs(t *testing.T, f tenantFixture, write tenantJobWrite, own string, check func(JobRecord)) {
	t.Helper()
	ctx := context.Background()
	before := tenantJobDigest(t, f.store, f.a)
	for _, id := range []string{f.jobA, f.archivedA, "00000000-0000-0000-0000-00000000dead"} {
		if err := write(f.store.Tenant(f.b), id); !errors.Is(err, ErrNotFound) {
			t.Errorf("tenant B wrote job %s: %v, want ErrNotFound", id, err)
		}
	}
	if after := tenantJobDigest(t, f.store, f.a); after != before {
		t.Fatal("a write through tenant B changed tenant A's rows")
	}
	if err := write(f.store.Tenant(f.b), own); err != nil {
		t.Fatalf("tenant B's own job %s: %v", own, err)
	}
	if check != nil {
		record, err := f.store.Tenant(f.b).GetJob(ctx, own)
		if err != nil {
			t.Fatal(err)
		}
		check(record)
	}
	if after := tenantJobDigest(t, f.store, f.a); after != before {
		t.Fatal("tenant B's write to its own job changed tenant A's rows")
	}
}

// assertTenantCreatesJobs creates a job through each tenant with a name
// that both tenants use. Each job belongs to the tenant that created it,
// and a name that the same tenant already uses is still refused.
func assertTenantCreatesJobs(t *testing.T, f tenantFixture, create func(ts *TenantStore, job config.Job) (JobRecord, error), enabled bool) {
	t.Helper()
	ctx := context.Background()
	created := map[TenantScope]JobRecord{}
	for _, scope := range []TenantScope{f.a, f.b} {
		before := tenantJobDigest(t, f.store, f.a)
		record, err := create(f.store.Tenant(scope), testJob("edge-new"))
		if err != nil {
			t.Fatalf("tenant %s: create: %v", scope.ID(), err)
		}
		if record.TenantID != scope.ID() || record.Enabled != enabled || record.Revision != 1 {
			t.Fatalf("tenant %s: created %+v", scope.ID(), record)
		}
		if scope == f.b && tenantJobDigest(t, f.store, f.a) != before {
			t.Fatal("creating tenant B's job changed tenant A's rows")
		}
		created[scope] = record
	}
	for scope, want := range created {
		record, err := f.store.Tenant(scope).GetJobByName(ctx, "edge-new")
		if err != nil || record.ID != want.ID || record.TenantID != scope.ID() || record.Enabled != enabled {
			t.Errorf("tenant %s: job edge-new = %+v, %v; want %s", scope.ID(), record, err, want.ID)
		}
		var revisions int
		if err := f.store.DB.QueryRow(`SELECT COUNT(*) FROM job_revisions WHERE job_id=?`, want.ID).Scan(&revisions); err != nil || revisions != 1 {
			t.Errorf("tenant %s: %d revisions, %v", scope.ID(), revisions, err)
		}
	}
	if _, err := create(f.store.Tenant(f.b), testJob("edge")); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("tenant B created a second job named edge: %v", err)
	}
}

// scopeChangedJob is the fixture's "edge" job with another target, so an
// update must reset the job's baseline.
func scopeChangedJob() config.Job {
	job := testJob("edge")
	job.Targets = []string{"127.0.0.2"}
	return config.NormalizeJob(job)
}

// assertTenantUpdatesOnlyItsJobs runs a rebaselining update through tenant
// B. On A's jobs it is not found and resets nothing; on B's own job it
// resets B's baseline and records the reset event in tenant B.
func assertTenantUpdatesOnlyItsJobs(t *testing.T, f tenantFixture, update func(ts *TenantStore, id string, job config.Job) (JobRecord, error)) {
	t.Helper()
	write := func(ts *TenantStore, id string) error {
		record, err := update(ts, id, scopeChangedJob())
		if err == nil && (record.TenantID != ts.scope.ID() || record.Revision != 2) {
			return fmt.Errorf("updated %+v", record)
		}
		return err
	}
	assertTenantWritesOnlyItsJobs(t, f, write, f.jobB, func(record JobRecord) {
		if record.Revision != 2 || record.TenantID != f.b.ID() || !reflect.DeepEqual(record.Job.Targets, []string{"127.0.0.2"}) {
			t.Errorf("tenant B's job after the update = %+v", record)
		}
	})
	var runtimes, resets int
	if err := f.store.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM job_runtime WHERE job_id=?1),(SELECT COUNT(*) FROM events WHERE job_id=?1 AND type='baseline-reset' AND tenant_id=?2)`, f.jobB, f.b.ID()).Scan(&runtimes, &resets); err != nil || runtimes != 1 || resets != 1 {
		t.Errorf("tenant B's reset: %d runtime rows, %d reset events, %v", runtimes, resets, err)
	}
}

// assertTenantArchivesOnlyItsJobs archives A's active job and restores A's
// archived job through tenant B, then archives B's own job.
func assertTenantArchivesOnlyItsJobs(t *testing.T, f tenantFixture, set func(ts *TenantStore, id string, archived bool) error) {
	t.Helper()
	write := func(ts *TenantStore, id string) error { return set(ts, id, id != f.archivedA) }
	assertTenantWritesOnlyItsJobs(t, f, write, f.jobB, func(record JobRecord) {
		if !record.Archived || record.Enabled || record.Revision != 2 {
			t.Errorf("tenant B's job after archiving = %+v", record)
		}
	})
}

// assertTenantPausesOnlyItsJobs pauses A's jobs through tenant B, then
// pauses B's own job.
func assertTenantPausesOnlyItsJobs(t *testing.T, f tenantFixture, set func(ts *TenantStore, id string, enabled bool) error) {
	t.Helper()
	write := func(ts *TenantStore, id string) error { return set(ts, id, false) }
	assertTenantWritesOnlyItsJobs(t, f, write, f.jobB, func(record JobRecord) {
		if record.Enabled || record.Archived || record.Revision != 2 {
			t.Errorf("tenant B's job after pausing = %+v", record)
		}
	})
}

// assertTenantDeletesOnlyItsJobs deletes A's jobs through tenant B, then
// B's own archived job. A's archived job has no history, so only the tenant
// predicate keeps B from deleting it.
func assertTenantDeletesOnlyItsJobs(t *testing.T, f tenantFixture, remove tenantJobWrite) {
	t.Helper()
	assertTenantWritesOnlyItsJobs(t, f, remove, f.archivedB, nil)
	if _, err := f.store.Tenant(f.b).GetJob(context.Background(), f.archivedB); !errors.Is(err, ErrNotFound) {
		t.Errorf("tenant B's deleted job: %v", err)
	}
}

var jobAudit = AuditEntry{Action: "job.test", ActorUsername: "tenant-test"}

// jobLeakCases hold the leak cases of the job writes and JobActive.
var jobLeakCases = map[string]tenantLeakCase{
	"CreateJob": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantCreatesJobs(t, f, func(ts *TenantStore, job config.Job) (JobRecord, error) {
			return ts.CreateJob(context.Background(), job)
		}, true)
	}},
	"CreateJobWithEnabled": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantCreatesJobs(t, f, func(ts *TenantStore, job config.Job) (JobRecord, error) {
			return ts.CreateJobWithEnabled(context.Background(), job, false)
		}, false)
	}},
	"CreateJobWithEnabledAndAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantCreatesJobs(t, f, func(ts *TenantStore, job config.Job) (JobRecord, error) {
			return ts.CreateJobWithEnabledAndAudit(context.Background(), job, true, jobAudit)
		}, true)
	}},
	"UpdateJob": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantUpdatesOnlyItsJobs(t, f, func(ts *TenantStore, id string, job config.Job) (JobRecord, error) {
			record, _, err := ts.UpdateJob(context.Background(), id, 1, job, true, false, true)
			return record, err
		})
	}},
	"UpdateJobWithEvents": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantUpdatesOnlyItsJobs(t, f, func(ts *TenantStore, id string, job config.Job) (JobRecord, error) {
			record, _, _, err := ts.UpdateJobWithEvents(context.Background(), id, 1, job, true, false, true)
			return record, err
		})
	}},
	"UpdateJobWithEventsWithOutbox": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantUpdatesOnlyItsJobs(t, f, func(ts *TenantStore, id string, job config.Job) (JobRecord, error) {
			record, _, _, err := ts.UpdateJobWithEventsWithOutbox(context.Background(), id, 1, job, true, false, true, nil)
			return record, err
		})
	}},
	"UpdateJobWithEventsWithOutboxAndAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantUpdatesOnlyItsJobs(t, f, func(ts *TenantStore, id string, job config.Job) (JobRecord, error) {
			record, _, _, err := ts.UpdateJobWithEventsWithOutboxAndAudit(context.Background(), id, 1, job, true, false, true, nil, jobAudit)
			return record, err
		})
	}},
	"SetJobArchived": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantArchivesOnlyItsJobs(t, f, func(ts *TenantStore, id string, archived bool) error {
			return ts.SetJobArchived(context.Background(), id, archived)
		})
	}},
	"SetJobArchivedWithRevision": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantArchivesOnlyItsJobs(t, f, func(ts *TenantStore, id string, archived bool) error {
			return ts.SetJobArchivedWithRevision(context.Background(), id, archived, 1)
		})
	}},
	"SetJobArchivedWithRevisionAndAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantArchivesOnlyItsJobs(t, f, func(ts *TenantStore, id string, archived bool) error {
			return ts.SetJobArchivedWithRevisionAndAudit(context.Background(), id, archived, 1, jobAudit)
		})
	}},
	"SetJobEnabled": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantPausesOnlyItsJobs(t, f, func(ts *TenantStore, id string, enabled bool) error {
			return ts.SetJobEnabled(context.Background(), id, enabled)
		})
	}},
	"SetJobEnabledWithRevision": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantPausesOnlyItsJobs(t, f, func(ts *TenantStore, id string, enabled bool) error {
			return ts.SetJobEnabledWithRevision(context.Background(), id, enabled, 1)
		})
	}},
	"SetJobEnabledWithRevisionAndAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantPausesOnlyItsJobs(t, f, func(ts *TenantStore, id string, enabled bool) error {
			return ts.SetJobEnabledWithRevisionAndAudit(context.Background(), id, enabled, 1, jobAudit)
		})
	}},
	"DeleteJob": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantDeletesOnlyItsJobs(t, f, func(ts *TenantStore, id string) error {
			return ts.DeleteJob(context.Background(), id)
		})
	}},
	"DeleteJobWithAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantDeletesOnlyItsJobs(t, f, func(ts *TenantStore, id string) error {
			return ts.DeleteJobWithAudit(context.Background(), id, jobAudit)
		})
	}},
	// A tenant sees the scan lease of its own jobs only. A lease key without
	// a jobs row is a config.yaml job's name, which belongs to the default
	// tenant.
	"JobActive": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		expires := time.Now().Add(time.Hour)
		for _, job := range []string{f.jobA, f.jobB, "config-job"} {
			if err := f.store.AcquireJobLease(ctx, job, "owner/"+job, expires); err != nil {
				t.Fatal(err)
			}
		}
		for _, check := range []struct {
			scope  TenantScope
			id     string
			active bool
			found  bool
		}{
			{f.b, f.jobA, false, false},
			{f.b, f.archivedA, false, false},
			{f.b, "config-job", false, false},
			{f.b, "unknown-job", false, false},
			{f.b, f.jobB, true, true},
			{f.b, f.archivedB, false, true},
			{f.a, f.jobB, false, false},
			{f.a, f.jobA, true, true},
			{f.a, "config-job", true, true},
			{f.a, "unknown-job", false, true},
		} {
			active, err := f.store.Tenant(check.scope).JobActive(ctx, check.id)
			if check.found != !errors.Is(err, ErrNotFound) || (check.found && err != nil) || active != check.active {
				t.Errorf("tenant %s: job %s active = %v, %v; want %v, found %v", check.scope.ID(), check.id, active, err, check.active, check.found)
			}
		}
	}},
}

// The deprecated Store wrappers of the job writes act on the default tenant
// only: tenant B's jobs are not found through them, and a job they create
// belongs to the default tenant.
func TestDeprecatedJobWritesUseTheDefaultTenant(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	s := f.store
	before := tenantJobDigest(t, s, f.b)
	for name, write := range map[string]func() error{
		"UpdateJob": func() error {
			_, _, err := s.UpdateJob(ctx, f.jobB, 1, scopeChangedJob(), true, false, true)
			return err
		},
		"UpdateJobWithEvents": func() error {
			_, _, _, err := s.UpdateJobWithEvents(ctx, f.jobB, 1, scopeChangedJob(), true, false, true)
			return err
		},
		"UpdateJobWithEventsWithOutbox": func() error {
			_, _, _, err := s.UpdateJobWithEventsWithOutbox(ctx, f.jobB, 1, scopeChangedJob(), true, false, true, nil)
			return err
		},
		"UpdateJobWithEventsWithOutboxAndAudit": func() error {
			_, _, _, err := s.UpdateJobWithEventsWithOutboxAndAudit(ctx, f.jobB, 1, scopeChangedJob(), true, false, true, nil, jobAudit)
			return err
		},
		"SetJobArchived":                     func() error { return s.SetJobArchived(ctx, f.jobB, true) },
		"SetJobArchivedWithRevision":         func() error { return s.SetJobArchivedWithRevision(ctx, f.jobB, true, 1) },
		"SetJobArchivedWithRevisionAndAudit": func() error { return s.SetJobArchivedWithRevisionAndAudit(ctx, f.jobB, true, 1, jobAudit) },
		"SetJobEnabled":                      func() error { return s.SetJobEnabled(ctx, f.jobB, false) },
		"SetJobEnabledWithRevision":          func() error { return s.SetJobEnabledWithRevision(ctx, f.jobB, false, 1) },
		"SetJobEnabledWithRevisionAndAudit":  func() error { return s.SetJobEnabledWithRevisionAndAudit(ctx, f.jobB, false, 1, jobAudit) },
		"DeleteJob":                          func() error { return s.DeleteJob(ctx, f.archivedB) },
		"DeleteJobWithAudit":                 func() error { return s.DeleteJobWithAudit(ctx, f.archivedB, jobAudit) },
		"JobActive": func() error {
			_, err := s.JobActive(ctx, f.jobB)
			return err
		},
	} {
		if err := write(); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s reached tenant B's job: %v", name, err)
		}
	}
	if after := tenantJobDigest(t, s, f.b); after != before {
		t.Fatal("a deprecated Store write changed tenant B's rows")
	}
	for name, create := range map[string]func(config.Job) (JobRecord, error){
		"CreateJob":            func(job config.Job) (JobRecord, error) { return s.CreateJob(ctx, job) },
		"CreateJobWithEnabled": func(job config.Job) (JobRecord, error) { return s.CreateJobWithEnabled(ctx, job, true) },
		"CreateJobWithEnabledAndAudit": func(job config.Job) (JobRecord, error) {
			return s.CreateJobWithEnabledAndAudit(ctx, job, true, jobAudit)
		},
	} {
		record, err := create(testJob("default-" + name))
		if err != nil || record.TenantID != DefaultTenantID {
			t.Fatalf("%s = %+v, %v", name, record, err)
		}
		if _, err := s.Tenant(f.a).GetJob(ctx, record.ID); err != nil {
			t.Errorf("%s: the default tenant does not own the job: %v", name, err)
		}
	}
}
