package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	_ "modernc.org/sqlite"
)

func testJob(name string) config.Job {
	return config.NormalizeJob(config.Job{
		Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"},
		TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute),
		Timing: "balanced", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	})
}

func TestManagedJobRevisionAndScopeConfirmation(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("one"))
	if err != nil {
		t.Fatal(err)
	}
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, false); !errors.Is(err, ErrRebaselineRequired) {
		t.Fatalf("expected rebaseline confirmation, got %v", err)
	}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision-1, record.Job, true, false, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected revision conflict, got %v", err)
	}
	updated, scopeChanged, err := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, true)
	if err != nil || !scopeChanged || updated.Revision != 2 {
		t.Fatalf("update %#v changed=%v err=%v", updated, scopeChanged, err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline != nil || state.BaselineScanID != "" {
		t.Fatalf("scope update did not clear runtime state: %#v", state)
	}
	events, err := s.ListJobEvents(ctx, record.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "baseline-reset" {
		t.Fatalf("scope update did not persist reset event: %#v", events)
	}
	staleScan := model.Scan{
		ID: "stale-approval", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "success",
		ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{},
	}
	if err := s.SaveScan(ctx, staleScan); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveRuntime(ctx, record.ID, updated.Job.Name, staleScan); err == nil {
		t.Fatal("stale scan was approved after the job scope changed")
	}
	if err := s.AcquireJobLeaseForRevision(ctx, record.ID, "stale-scan", 1, time.Now().Add(time.Minute)); !errors.Is(err, ErrJobRevisionChanged) {
		t.Fatalf("stale revision acquired a lease: %v", err)
	}
}

func TestManagedScopeEditIsBlockedWhileScanning(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("busy"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireJobLease(ctx, record.ID, "scan-1", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	defer s.ReleaseJobLease(ctx, record.ID, "scan-1")
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, true); !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("expected active scan guard, got %v", err)
	}
}

func TestManagedRuntimeIsolatedFromLegacyState(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("legacy-name"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateState(ctx, "legacy-name", func(state *model.JobState) ([]model.Event, error) { state.BaselineScanID = "old"; return nil, nil }); err != nil {
		t.Fatal(err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "" {
		t.Fatalf("managed runtime inherited legacy state: %#v", state)
	}
}

func TestManagedEventsAreIsolatedFromLegacyName(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("same-name"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := s.UpdateState(ctx, record.Job.Name, func(state *model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "legacy", Job: record.Job.Name, CreatedAt: now}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "managed", Job: record.Job.Name, CreatedAt: now.Add(time.Second)}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ListJobEvents(ctx, record.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "managed" || events[0].JobID != record.ID {
		t.Fatalf("unexpected managed events %#v", events)
	}
}

func TestExistingSchemaMigratesWithWebTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	// Open creates the v1-compatible tables and upgrades them in one call. The
	// assertion below also protects future migrations from silently skipping the
	// nullable scan identity columns required for legacy rows.
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version int
	if err := s.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version %d", version)
	}
	for _, table := range []string{"jobs", "job_revisions", "job_runtime", "admins", "sessions", "recovery_codes", "security_audit", "setup_tokens"} {
		var name string
		if err := s.DB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name); err != nil {
			t.Fatalf("missing %s: %v", table, err)
		}
	}
}

func TestV1DatabaseAddsManagedColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(legacySchema + "\nPRAGMA user_version = 1;"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name IN ('job_id','job_revision')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected managed scan columns, got %d", count)
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name='job_id'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected managed event column, got %d", count)
	}
}
