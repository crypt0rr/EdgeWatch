package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func reconstructSchema79(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, statement := range []string{
		`DROP INDEX IF EXISTS ` + scansTimeoutCycleKeyIndex,
		`DROP INDEX IF EXISTS ` + scansTimeoutConfigKeyIndex,
		`ALTER TABLE scans DROP COLUMN cycle_execution_hash`,
		`PRAGMA user_version=79`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("reconstruct schema 79 with %s: %v", statement, err)
		}
	}
}

func TestMigration80IndexesTimeoutHistoryKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("schema-80"))
	if err != nil {
		t.Fatal(err)
	}
	finished := time.Date(2026, time.October, 27, 12, 0, 0, 0, time.UTC)
	cycleID := "schema-80-cycle"
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,total_units,total_probes,started_at,updated_at,expires_at,finished_at)
		VALUES(?,?,?,?,?,?,'{}','paused',0,0,?,?,?,?)`, cycleID, job.ID, job.Job.Name, job.Revision, job.Job.SecurityHash(), job.Job.ExecutionHash(), sqliteTimestamp(finished.Add(-time.Hour)), sqliteTimestamp(finished), sqliteTimestamp(finished), sqliteTimestamp(finished)); err != nil {
		t.Fatal(err)
	}
	if err := s.System().SaveScan(ctx, model.Scan{
		ID: "schema-80-scan", JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		StartedAt: finished.Add(-time.Minute), FinishedAt: finished, Status: "timed_out", CycleID: cycleID,
	}); err != nil {
		t.Fatal(err)
	}
	reconstructSchema79(t, s.DB)
	if conditionalMigrationStatements[80] == nil {
		t.Fatal("schema 80 conditional migration is not registered")
	}
	if err := applyMigration(ctx, s.DB, 80, migration80Statements()); err != nil {
		t.Fatalf("apply schema 80: %v", err)
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 80 {
		t.Fatalf("schema version = %d, want 80", got)
	}
	var executionHash string
	if err := s.DB.QueryRowContext(ctx, `SELECT cycle_execution_hash FROM scans WHERE id='schema-80-scan'`).Scan(&executionHash); err != nil || executionHash != job.Job.ExecutionHash() {
		t.Fatalf("backfilled cycle execution hash = %q, err %v; want %q", executionHash, err, job.Job.ExecutionHash())
	}
	for _, index := range []struct{ name, definition string }{
		{scansTimeoutCycleKeyIndex, "(tenant_id,job_id,cycle_execution_hash,finished_at DESC,id DESC,status,cycle_id) WHERE cycle_id<>''"},
		{scansTimeoutConfigKeyIndex, "(tenant_id,job_id,config_hash,scanner_profile_id,scanner_profile_revision,finished_at DESC,id DESC,status) WHERE cycle_id=''"},
	} {
		var definition string
		if err := s.DB.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='index' AND name=?`, index.name).Scan(&definition); err != nil {
			t.Fatalf("read %s: %v", index.name, err)
		}
		if !strings.Contains(definition, index.definition) {
			t.Errorf("index definition for %s = %q; want %q", index.name, definition, index.definition)
		}
	}
	if err := reapplyMigration(t, s.DB, 80, migration80Statements()); err != nil {
		t.Fatalf("reapply schema 80: %v", err)
	}
}

func TestLatestScanRunsTimedOutUsesBoundedKeyedLookups(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	defer s.Close()
	plan := explainPlan(t, s.DB, latestScanRunsTimedOutSQL, `[]`, DefaultTenantID, 44, 11)
	joined := strings.Join(plan, " | ")
	for _, want := range []string{
		"SEARCH s USING COVERING INDEX " + scansTimeoutCycleKeyIndex + " (tenant_id=? AND job_id=? AND cycle_execution_hash=?)",
		"SEARCH s USING COVERING INDEX " + scansTimeoutConfigKeyIndex + " (tenant_id=? AND job_id=? AND config_hash=? AND scanner_profile_id=? AND scanner_profile_revision=?)",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("timeout query plan lacks keyed lookup %q: %s", want, joined)
		}
	}
	for _, step := range plan {
		if strings.HasPrefix(step, "SCAN s") {
			t.Errorf("timeout query scans retained scan history: %s", joined)
		}
	}
}

func TestLatestScanRunsTimedOutMissingKeyDoesNotWalkLargeHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("large-timeout-history"))
	if err != nil {
		t.Fatal(err)
	}
	key := NewScanDurationKey(job)
	const rows = 129600 // One scan per minute for 90 days.
	result, err := s.DB.ExecContext(ctx, `WITH RECURSIVE sequence(n) AS (
		VALUES(1) UNION ALL SELECT n+1 FROM sequence WHERE n<?
	)
	INSERT INTO scans(id,job,job_id,started_at,finished_at,status,config_hash,snapshot_json,scanner_profile_id,scanner_profile_revision,tenant_id)
		SELECT printf('other-settings-%06d',n),?,?,'2026-01-01T00:00:00Z','2026-01-01T00:01:00Z','success','other-settings',X'7B7D',?,?,?
		FROM sequence`, rows, job.Job.Name, job.ID, key.ScannerProfileID, key.ScannerProfileRevision, tenant.scope.id)
	if err != nil {
		t.Fatalf("insert %d unrelated history rows: %v", rows, err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != rows {
		t.Fatalf("inserted history rows = %d, err %v; want %d", changed, err, rows)
	}
	latest, err := tenant.LatestScanRunsTimedOut(ctx, []ScanDurationKey{key}, 11)
	if err != nil || latest[job.ID] {
		t.Fatalf("missing settings key among %d newer rows = %v, %v; want false", rows, latest, err)
	}
	plan := explainPlan(t, s.DB, latestScanRunsTimedOutSQL, `[]`, tenant.scope.id, 44, 11)
	for _, step := range plan {
		if strings.HasPrefix(step, "SCAN s") {
			t.Fatalf("missing-key query plan walks history after %d rows: %s", rows, strings.Join(plan, " | "))
		}
	}
}
