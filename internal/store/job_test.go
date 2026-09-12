package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
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

func TestCreateJobWithEnabledPersistsPausedStateAtomically(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJobWithEnabled(ctx, testJob("paused"), false)
	if err != nil {
		t.Fatal(err)
	}
	if record.Revision != 1 || record.Enabled {
		t.Fatalf("created job state = %#v, want disabled revision 1", record)
	}
	stored, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != 1 || stored.Enabled {
		t.Fatalf("stored job state = %#v, want disabled revision 1", stored)
	}
	var revisions int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_revisions WHERE job_id=?`, record.ID).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if revisions != 1 {
		t.Fatalf("revision count = %d, want 1", revisions)
	}
}

func TestManagedJobsHonorConfiguredTargetExclusions(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateJob(ctx, testJob("blocked")); err == nil || !strings.Contains(err.Error(), "excluded") {
		t.Fatalf("excluded managed target was accepted: %v", err)
	}
	if err := s.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateJob(ctx, testJob("allowed")); err != nil {
		t.Fatalf("explicit empty exclusion override rejected managed target: %v", err)
	}
}

func TestAuditedMutationsRollBackWhenAuditInsertFails(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	base, err := s.CreateJob(ctx, testJob("audited-base"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_audited_mutation BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateJobWithEnabledAndAudit(ctx, testJob("audited-new"), true, AuditEntry{Action: "job.created", Detail: "audited-new"}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("expected audited create failure, got %v", err)
	}
	if _, err := s.GetJobByName(ctx, "audited-new"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("job committed despite audit failure: %v", err)
	}

	updated := base.Job
	updated.Name = "audited-renamed"
	if _, _, _, err := s.UpdateJobWithEventsWithOutboxAndAudit(ctx, base.ID, base.Revision, updated, true, false, false, nil, AuditEntry{Action: "job.updated", Detail: base.ID}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("expected audited update failure, got %v", err)
	}
	current, err := s.GetJob(ctx, base.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != base.Revision || current.Job.Name != base.Job.Name {
		t.Fatalf("job changed despite audit failure: %#v", current)
	}

	if _, err := s.UpdateRuntime(ctx, base.ID, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "baseline"
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetRuntimeWithOutboxAndAudit(ctx, base.ID, base.Job.Name, nil, AuditEntry{Action: "baseline.reset", Detail: base.ID}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("expected audited reset failure, got %v", err)
	}
	state, err := s.RuntimeState(ctx, base.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "baseline" {
		t.Fatalf("baseline reset committed despite audit failure: %#v", state)
	}
}

func TestManagedJobRevisionAndScopeConfirmation(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("one"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceBaselineHostProjection(ctx, record.ID, model.Snapshot{Hosts: []model.HostObservation{{Address: "127.0.0.1", Status: "up"}}}); err != nil {
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
	if exists, err := s.BaselineHostProjectionExists(ctx, record.ID); err != nil || exists {
		t.Fatalf("scope update left the old baseline host projection: exists=%v err=%v", exists, err)
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
	if err := s.SetJobArchivedWithRevision(ctx, record.ID, true, record.Revision); !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("expected active archive guard, got %v", err)
	}
	if err := s.SetJobEnabledWithRevision(ctx, record.ID, false, record.Revision); !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("expected active pause guard, got %v", err)
	}
}

func TestJobLifecycleChangesInvalidateStaleEditors(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobEnabled(ctx, record.ID, false); err != nil {
		t.Fatal(err)
	}
	if current, err := s.GetJob(ctx, record.ID); err != nil {
		t.Fatal(err)
	} else if current.Revision != record.Revision+1 || current.Enabled {
		t.Fatalf("pause did not create a new revision: %#v", current)
	}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision, record.Job, true, false, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale edit after pause was accepted: %v", err)
	}

	if err := s.SetJobArchived(ctx, record.ID, true); err != nil {
		t.Fatal(err)
	}
	archived, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if archived.Revision != record.Revision+2 || !archived.Archived || archived.Enabled {
		t.Fatalf("archive did not create a new revision: %#v", archived)
	}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision+1, record.Job, false, false, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale edit after archive was accepted: %v", err)
	}
	if err := s.SetJobArchived(ctx, record.ID, false); err != nil {
		t.Fatal(err)
	}
	restored, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Revision != record.Revision+3 || restored.Archived || restored.Enabled {
		t.Fatalf("restore changed unexpected lifecycle state: %#v", restored)
	}
}

func TestLifecycleActionsRequireCurrentRevision(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("lifecycle-actions"))
	if err != nil {
		t.Fatal(err)
	}
	changed := record.Job
	changed.Timeout = config.Duration(2 * time.Minute)
	updated, _, err := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobArchivedWithRevision(ctx, record.ID, true, record.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale archive was accepted: %v", err)
	}
	if err := s.SetJobArchivedWithRevision(ctx, record.ID, true, updated.Revision); err != nil {
		t.Fatalf("current archive failed: %v", err)
	}
	if err := s.SetJobArchivedWithRevision(ctx, record.ID, false, updated.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale restore was accepted: %v", err)
	}
	archived, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobArchivedWithRevision(ctx, record.ID, false, archived.Revision); err != nil {
		t.Fatalf("current restore failed: %v", err)
	}
	restored, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobEnabledWithRevision(ctx, record.ID, true, restored.Revision); err != nil {
		t.Fatalf("current resume failed: %v", err)
	}
	if err := s.SetJobEnabledWithRevision(ctx, record.ID, false, restored.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale pause was accepted: %v", err)
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

func TestManagedRuntimeRejectsSupersededSecurityScope(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("superseded"))
	if err != nil {
		t.Fatal(err)
	}
	oldHash := record.Job.SecurityHash()
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateRuntimeForScan(ctx, record.ID, oldHash, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "stale"
		return nil, nil
	}); !errors.Is(err, ErrJobRevisionChanged) {
		t.Fatalf("superseded scan changed runtime state: %v", err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "" {
		t.Fatalf("stale scan mutated current runtime: %#v", state)
	}
}

func TestManagedRuntimeAcceptsLifecycleRevisionWithSameScope(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("lifecycle-runtime"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobEnabled(ctx, record.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateRuntimeForScan(ctx, record.ID, record.Job.SecurityHash(), func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "lifecycle-scan"
		return nil, nil
	}); err != nil {
		t.Fatalf("lifecycle-only revision rejected a compatible scan: %v", err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "lifecycle-scan" {
		t.Fatalf("compatible scan did not update runtime: %#v", state)
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
	for _, table := range []string{"jobs", "job_revisions", "job_runtime", "admins", "users", "user_invites", "sessions", "recovery_codes", "security_audit", "setup_tokens", "managed_notifications", "rdap_cache", "scan_hosts", "latest_scan_hosts", "scan_host_search", "latest_host_search", "notification_delivery_health", "scan_cycles", "scan_cycle_units", "scan_cycle_discovery_checkpoints", "public_dashboard", "public_dashboard_hosts", "application_update_state", "sse_event_cursor", "startup_state"} {
		var name string
		if err := s.DB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name); err != nil {
			t.Fatalf("missing %s: %v", table, err)
		}
	}
	var columns int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('admins') WHERE name='display_name'`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 1 {
		t.Fatalf("administrator display_name column count = %d", columns)
	}
	var defaultValue string
	if err := s.DB.QueryRow(`SELECT dflt_value FROM pragma_table_info('admins') WHERE name='display_name'`).Scan(&defaultValue); err != nil {
		t.Fatal(err)
	}
	if defaultValue != "'admin'" {
		t.Fatalf("administrator display_name default = %q", defaultValue)
	}
	now := time.Now().UTC()
	if err := s.SaveAdmin(context.Background(), Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	admin, err := s.GetAdmin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if admin.DisplayName != "admin" {
		t.Fatalf("default administrator display name = %q", admin.DisplayName)
	}
	admin.DisplayName = "Ada Lovelace"
	if err := s.SaveAdmin(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	admin, err = s.GetAdmin(context.Background())
	if err != nil || admin.DisplayName != "Ada Lovelace" {
		t.Fatalf("saved administrator display name = %q, err=%v", admin.DisplayName, err)
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

func TestV9DatabaseAddsSetupTokenIssueTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v9.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE setup_tokens (id INTEGER PRIMARY KEY CHECK(id=1), token_hash TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT); PRAGMA user_version = 8;`); err != nil {
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
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('setup_tokens') WHERE name='issued_at'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("issued_at column count = %d", count)
	}
}

func TestV10DatabaseAddsAdministratorDisplayName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v10.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE admins (
 id INTEGER PRIMARY KEY CHECK(id=1),
 username TEXT NOT NULL DEFAULT 'admin',
 password_hash TEXT NOT NULL,
 totp_secret TEXT NOT NULL DEFAULT '',
 totp_enabled INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
); PRAGMA user_version = 10;`); err != nil {
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
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('admins') WHERE name='display_name'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("display_name column count = %d", count)
	}
	var defaultValue string
	if err := s.DB.QueryRow(`SELECT dflt_value FROM pragma_table_info('admins') WHERE name='display_name'`).Scan(&defaultValue); err != nil {
		t.Fatal(err)
	}
	if defaultValue != "'admin'" {
		t.Fatalf("display_name default = %q", defaultValue)
	}
}

func TestV11DatabaseMigratesAdministratorIdentityAndLegacySessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v11.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.Exec(`
CREATE TABLE admins (
 id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL DEFAULT 'admin',
 password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL DEFAULT '',
 totp_enabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT 'admin'
);
INSERT INTO admins(id,username,password_hash,totp_secret,totp_enabled,created_at,updated_at,display_name) VALUES(1,'legacy-admin','hash','',0,?,?, 'Legacy Admin');
CREATE TABLE sessions (id_hash TEXT PRIMARY KEY, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, expires_at TEXT NOT NULL, csrf_token TEXT NOT NULL);
INSERT INTO sessions(id_hash,created_at,last_seen_at,expires_at,csrf_token) VALUES('session-hash',?,?,?,'csrf');
CREATE TABLE recovery_codes (id_hash TEXT PRIMARY KEY, used_at TEXT);
INSERT INTO recovery_codes(id_hash,used_at) VALUES('recovery-hash',NULL);
CREATE TABLE security_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
PRAGMA user_version = 11;`, now, now, now)
	if err != nil {
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
	user, err := s.GetUserByUsername(context.Background(), "legacy-admin")
	if err != nil || user.ID != LegacyAdminUserID || user.DisplayName != "Legacy Admin" || user.Role != RoleAdministrator {
		t.Fatalf("migrated administrator = %#v, err=%v", user, err)
	}
	var userID string
	if err := s.DB.QueryRow(`SELECT user_id FROM sessions WHERE id_hash='session-hash'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if userID != LegacyAdminUserID {
		t.Fatalf("migrated session user_id = %q", userID)
	}
	if err := s.DB.QueryRow(`SELECT user_id FROM recovery_codes WHERE id_hash='recovery-hash'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if userID != LegacyAdminUserID {
		t.Fatalf("migrated recovery user_id = %q", userID)
	}
	var updated string
	if err := s.DB.QueryRow(`SELECT updated_at FROM public_dashboard WHERE id=1`).Scan(&updated); err != nil {
		t.Fatal(err)
	}
	if scanTime(updated).IsZero() {
		t.Fatalf("public dashboard timestamp was not parsed: %q", updated)
	}
}
