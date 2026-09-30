package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// legacyPurgeMaintenanceRow returns the checkpoint of the cleanup after
// deleted tenants, and whether the database has one.
func legacyPurgeMaintenanceRow(t *testing.T, s *Store) (FTSBackfillProgress, bool) {
	t.Helper()
	var row FTSBackfillProgress
	var initialized, complete int
	err := s.DB.QueryRow(`SELECT table_name,last_rowid,processed_rows,initialized,complete,updated_at FROM fts_backfill_state WHERE table_name=?`, legacyPurgeMaintenanceState).Scan(&row.TableName, &row.LastRowID, &row.ProcessedRows, &initialized, &complete, &row.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return row, false
	}
	if err != nil {
		t.Fatal(err)
	}
	row.Initialized, row.Complete = initialized != 0, complete != 0
	return row, true
}

// reopenAtSchema54 turns the store's database back into a schema 54 one and
// opens it again, as the first start of this release after an upgrade does.
func reopenAtSchema54(t *testing.T, s *Store) *Store {
	t.Helper()
	if _, err := s.DB.Exec(`PRAGMA user_version=54`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Open(s.Path)
	if err != nil {
		t.Fatalf("upgrade from schema 54: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	return upgraded
}

// legacyPurgeMaintenancePosition returns the position of a phase of the
// cleanup after deleted tenants, as its checkpoint row records it. The
// checkpoint phase is the last.
func legacyPurgeMaintenancePosition(phase string) int64 {
	return int64(slices.Index(legacyPurgeMaintenancePhases(), phase))
}

// insertTenantInState adds a tenant in the state and purge phase given.
func insertTenantInState(t *testing.T, s *Store, id, state, phase string) {
	t.Helper()
	stamp := sqliteTimestamp(time.Now())
	if _, err := s.DB.Exec(`INSERT INTO tenants(id,name,slug,state,purge_phase,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`, id, "Unit "+id, "unit-"+id, state, phase, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

// A fresh install, which the template of openTestStore is, and an upgrade
// of a database without a deleted tenant get no cleanup. An upgrade of a
// database with one records the cleanup as pending, and sends a purge that
// was already compacting the search indexes back to its verify phase.
func TestMigration55RecordsTheCleanupOnlyWhenATenantWasDeleted(t *testing.T) {
	if _, ok := legacyPurgeMaintenanceRow(t, openTestStore(t)); ok {
		t.Fatal("a fresh install records a cleanup after deleted tenants")
	}

	phases := map[string]string{"compacting": tenantPurgePhaseCompact + "latest_host_search", "checkpointing": tenantPurgePhaseCheckpoint, "erasing": "scans", "verifying": tenantPurgePhaseVerify}
	insertOthers := func(t *testing.T, s *Store) {
		t.Helper()
		insertTenantInState(t, s, "active", TenantStateActive, "")
		insertTenantInState(t, s, "disabled", TenantStateDisabled, "")
		for id, phase := range phases {
			insertTenantInState(t, s, id, TenantStateDeleting, phase)
		}
	}
	purgePhase := func(t *testing.T, s *Store, id string) string {
		t.Helper()
		var phase string
		if err := s.DB.QueryRow(`SELECT purge_phase FROM tenants WHERE id=?`, id).Scan(&phase); err != nil {
			t.Fatal(err)
		}
		return phase
	}

	s := openTestStore(t)
	insertOthers(t, s)
	upgraded := reopenAtSchema54(t, s)
	if _, ok := legacyPurgeMaintenanceRow(t, upgraded); ok {
		t.Fatal("an upgrade without a deleted tenant records a cleanup")
	}
	for id, phase := range phases {
		if got := purgePhase(t, upgraded, id); got != phase {
			t.Errorf("an upgrade without a deleted tenant moved tenant %s from phase %s to %s", id, phase, got)
		}
	}

	s = openTestStore(t)
	insertOthers(t, s)
	insertTenantInState(t, s, "deleted", TenantStateDeleted, tenantPurgePhaseComplete)
	upgraded = reopenAtSchema54(t, s)
	row, ok := legacyPurgeMaintenanceRow(t, upgraded)
	if !ok || row.Complete || row.Initialized || row.LastRowID != 0 || row.ProcessedRows != 0 || row.UpdatedAt == "" {
		t.Fatalf("the cleanup after an upgrade with a deleted tenant = %+v, %v; want it pending", row, ok)
	}
	for id, want := range map[string]string{"compacting": tenantPurgePhaseVerify, "checkpointing": tenantPurgePhaseVerify, "erasing": "scans", "verifying": tenantPurgePhaseVerify} {
		if got := purgePhase(t, upgraded, id); got != want {
			t.Errorf("tenant %s is in phase %s after the upgrade, want %s", id, got, want)
		}
	}
}

// The migration can run again: a cleanup that is pending, with its
// progress, or complete stays as it is.
func TestMigration55IsANoOpWhenRepeated(t *testing.T) {
	s := openTestStore(t)
	insertTenantInState(t, s, "deleted", TenantStateDeleted, tenantPurgePhaseComplete)
	s = reopenAtSchema54(t, s)
	for _, progress := range []string{
		`UPDATE fts_backfill_state SET last_rowid=2,processed_rows=1,initialized=1,updated_at='2026-09-29T10:00:00Z' WHERE table_name='` + legacyPurgeMaintenanceState + `'`,
		`UPDATE fts_backfill_state SET last_rowid=4,processed_rows=4,complete=1,updated_at='2026-09-29T11:00:00Z' WHERE table_name='` + legacyPurgeMaintenanceState + `'`,
	} {
		if _, err := s.DB.Exec(progress); err != nil {
			t.Fatal(err)
		}
		before, _ := legacyPurgeMaintenanceRow(t, s)
		s = reopenAtSchema54(t, s)
		if after, ok := legacyPurgeMaintenanceRow(t, s); !ok || after != before {
			t.Fatalf("repeating migration 55 changed the cleanup from %+v to %+v", before, after)
		}
	}
}

// legacyTombstoneWithResidue makes tenant B a tombstone as the releases
// before schema 55 could leave it, and then runs the schema 55 migration:
// its rows are erased, but its search terms are still in the segments of
// every search index, and a reader, which the caller ends, keeps copies of
// its rows in the write-ahead log.
func legacyTombstoneWithResidue(t *testing.T) (tenantFixture, *sql.Tx) {
	t.Helper()
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	seedTenantPurgeMarker(t, f)
	requestSecondTenantDeletion(t, f)
	shortenBusyTimeout(t, f.store)
	reader := openSnapshot(t, f.store)
	// The purge erases the rows, but its budget is spent before the
	// compaction, and the reader keeps its checkpoint from truncating the
	// log. The earlier releases made the tombstone at that point.
	results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, maintenanceBudget: spentBudget})
	if err != nil || len(results) != 1 || !results[0].MaintenancePending || !results[0].CheckpointBusy {
		t.Fatalf("erase tenant B = %+v, %v", results, err)
	}
	if _, err := f.store.DB.Exec(`UPDATE tenants SET state=?,purge_phase=? WHERE id=?`, TenantStateDeleted, tenantPurgePhaseComplete, secondTenantID); err != nil {
		t.Fatal(err)
	}
	if err := applyMigration(f.store.DB, 55, migration55Statements()); err != nil {
		t.Fatal(err)
	}
	if row, ok := legacyPurgeMaintenanceRow(t, f.store); !ok || row.Complete {
		t.Fatalf("the cleanup after the upgrade = %+v, %v; want it pending", row, ok)
	}
	for _, index := range tenantPurgeSearchIndexes {
		if trigramBlocks(t, f.store, index) == 0 {
			t.Fatalf("%s holds no term of the erased rows; the test shows nothing", index)
		}
	}
	if _, copies := walMarkers(t, f.store); copies == 0 {
		t.Fatal("the write-ahead log holds no copy of the erased rows; the test shows nothing")
	}
	return f, reader
}

// backupCopies returns the copies of tenantPurgeTrigram in a backup made
// now.
func backupCopies(t *testing.T, s *Store) int {
	t.Helper()
	backup := filepath.Join(t.TempDir(), "backup.db")
	if _, err := s.DB.Exec(`VACUUM INTO ?`, backup); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(data, []byte(tenantPurgeTrigram))
}

// After the upgrade, one pass of the cleanup compacts every search index
// and truncates the log: no index, no backup and not the log holds a copy
// of the erased rows any more, and the cleanup is complete and does not run
// again. A backup taken before it still holds them.
func TestLegacyPurgeMaintenanceErasesWhatAnEarlierReleaseLeft(t *testing.T) {
	ctx := context.Background()
	f, reader := legacyTombstoneWithResidue(t)
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	if copies := backupCopies(t, f.store); copies == 0 {
		t.Fatal("a backup before the cleanup holds no term of the erased rows")
	}

	var merged mergeLog
	result, err := f.store.System().runLegacyPurgeMaintenance(ctx, tenantPurgeOptions{afterMerge: merged.afterMerge})
	if err != nil || result != (LegacyPurgeMaintenanceResult{Pending: true, Started: true, Phase: tenantPurgePhaseComplete, Complete: true}) {
		t.Fatalf("cleanup = %+v, %v; want it started and complete", result, err)
	}
	if !slices.Equal(merged.started, tenantPurgeSearchIndexes) {
		t.Fatalf("the cleanup started merges of %v, want every index", merged.started)
	}
	assertNothingOfTheMarkerLeft(t, f.store)
	last := legacyPurgeMaintenancePosition(tenantPurgePhaseCheckpoint)
	if row, ok := legacyPurgeMaintenanceRow(t, f.store); !ok || !row.Complete || !row.Initialized || row.LastRowID != last || row.ProcessedRows != last {
		t.Fatalf("the finished cleanup = %+v, %v", row, ok)
	}
	if result, err := f.store.System().RunLegacyPurgeMaintenance(ctx); err != nil || result != (LegacyPurgeMaintenanceResult{}) {
		t.Fatalf("a pass after the cleanup = %+v, %v; want nothing", result, err)
	}
}

// A reader that holds an older snapshot keeps the cleanup's checkpoint
// busy: the pass has compacted the indexes but leaves the cleanup pending
// in its checkpoint phase, with the log still holding the erased rows. The
// next pass, without the reader, truncates the log and merges nothing.
func TestLegacyPurgeMaintenanceRetriesABusyCheckpoint(t *testing.T) {
	ctx := context.Background()
	f, reader := legacyTombstoneWithResidue(t)
	result, err := f.store.System().RunLegacyPurgeMaintenance(ctx)
	if err != nil || result != (LegacyPurgeMaintenanceResult{Pending: true, Started: true, Phase: tenantPurgePhaseCheckpoint, CheckpointBusy: true}) {
		t.Fatalf("cleanup with a reader open = %+v, %v; want the checkpoint pending", result, err)
	}
	last := legacyPurgeMaintenancePosition(tenantPurgePhaseCheckpoint)
	if row, ok := legacyPurgeMaintenanceRow(t, f.store); !ok || row.Complete || row.LastRowID != last || row.ProcessedRows != last-1 {
		t.Fatalf("the cleanup whose checkpoint was busy = %+v, %v", row, ok)
	}
	for _, index := range tenantPurgeSearchIndexes {
		if blocks := trigramBlocks(t, f.store, index); blocks != 0 {
			t.Errorf("%s holds a term of the erased rows in %d blocks after its compaction", index, blocks)
		}
	}
	if _, copies := walMarkers(t, f.store); copies == 0 {
		t.Fatal("the busy checkpoint truncated the log")
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}

	var merged mergeLog
	result, err = f.store.System().runLegacyPurgeMaintenance(ctx, tenantPurgeOptions{afterMerge: merged.afterMerge})
	if err != nil || result != (LegacyPurgeMaintenanceResult{Pending: true, Phase: tenantPurgePhaseComplete, Complete: true}) {
		t.Fatalf("the next pass = %+v, %v; want the cleanup complete", result, err)
	}
	if len(merged.started) != 0 || len(merged.continued) != 0 {
		t.Fatalf("the checkpoint phase merged %+v", merged)
	}
	assertNothingOfTheMarkerLeft(t, f.store)
}

// A pass whose budget runs out during the compaction leaves the cleanup at
// the index it reached, and still truncates the log. After a restart the
// next pass continues that index's merge rather than starting it over,
// starts the others, and completes the cleanup. edgewatch health reports
// the cleanup and its progress while it is pending, and edgewatch verify
// lists its checkpoint.
func TestLegacyPurgeMaintenanceResumesAfterASpentBudgetAndARestart(t *testing.T) {
	ctx := context.Background()
	f, reader := legacyTombstoneWithResidue(t)
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := f.store.System().AcquireLease(ctx, "daemon"); err != nil {
		t.Fatal(err)
	}
	total := legacyPurgeMaintenancePosition(tenantPurgePhaseCheckpoint)
	assertLegacyPurgeMaintenanceReported(t, f.store, &MaintenanceStatus{Phase: legacyPurgeMaintenancePhase, Progress: 0, Total: total})

	var spent mergeLog
	var spend context.CancelFunc
	result, err := f.store.System().runLegacyPurgeMaintenance(ctx, tenantPurgeOptions{maintenanceBudget: func(ctx context.Context) (context.Context, context.CancelFunc) {
		budget, cancel := context.WithCancel(ctx)
		spend = cancel
		return budget, cancel
	}, afterMerge: func(ctx context.Context, index string, pages int) error {
		// The budget runs out after the first merge.
		_ = spent.afterMerge(ctx, index, pages)
		spend()
		return ctx.Err()
	}})
	first := tenantPurgePhaseCompact + tenantPurgeSearchIndexes[0]
	if err != nil || result != (LegacyPurgeMaintenanceResult{Pending: true, Started: true, Phase: first}) {
		t.Fatalf("cleanup past its budget = %+v, %v; want it pending at %s", result, err, first)
	}
	if !slices.Equal(spent.started, tenantPurgeSearchIndexes[:1]) || len(spent.continued) != 0 {
		t.Fatalf("the pass merged %+v before its budget ran out", spent)
	}
	for _, index := range tenantPurgeSearchIndexes[1:] {
		if trigramBlocks(t, f.store, index) == 0 {
			t.Fatalf("%s holds no term of the erased rows before its compaction; the test shows nothing", index)
		}
	}
	if _, copies := walMarkers(t, f.store); copies != 0 {
		t.Fatalf("the log holds %d copies of the erased rows after a pass whose budget ran out", copies)
	}
	assertLegacyPurgeMaintenanceReported(t, f.store, &MaintenanceStatus{Phase: legacyPurgeMaintenancePhase + ":" + first, Progress: 0, Total: total})

	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(f.store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	var merged mergeLog
	result, err = restarted.System().runLegacyPurgeMaintenance(ctx, tenantPurgeOptions{afterMerge: merged.afterMerge})
	if err != nil || result != (LegacyPurgeMaintenanceResult{Pending: true, Phase: tenantPurgePhaseComplete, Complete: true}) {
		t.Fatalf("the pass after the restart = %+v, %v; want the cleanup complete", result, err)
	}
	if !slices.Equal(merged.started, tenantPurgeSearchIndexes[1:]) {
		t.Fatalf("the pass after the restart started merges of %v, want %v", merged.started, tenantPurgeSearchIndexes[1:])
	}
	assertNothingOfTheMarkerLeft(t, restarted)
	if err := restarted.System().AcquireLease(ctx, "daemon"); err != nil {
		t.Fatal(err)
	}
	assertLegacyPurgeMaintenanceReported(t, restarted, nil)
}

// assertLegacyPurgeMaintenanceReported checks what edgewatch health and
// edgewatch verify report of the cleanup: want is the pending cleanup, or
// nil once it is complete.
func assertLegacyPurgeMaintenanceReported(t *testing.T, s *Store, want *MaintenanceStatus) {
	t.Helper()
	ctx := context.Background()
	health, err := s.System().HealthStatus(ctx)
	if err != nil || health.Status != "ready" {
		t.Fatalf("health = %+v, %v", health, err)
	}
	switch {
	case want == nil && health.Maintenance != nil:
		t.Fatalf("health reports the complete cleanup: %+v", health.Maintenance)
	case want != nil && (health.Maintenance == nil || health.Maintenance.Phase != want.Phase || health.Maintenance.Progress != want.Progress || health.Maintenance.Total != want.Total || health.Maintenance.UpdatedAt.IsZero()):
		t.Fatalf("health reports the cleanup as %+v, want %+v", health.Maintenance, want)
	}
	encoded, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	if reported := strings.Contains(string(encoded), `"maintenance":{"phase":"`+legacyPurgeMaintenancePhase); reported != (want != nil) {
		t.Fatalf("health output %s", encoded)
	}

	readOnly, err := OpenReadOnlyExistingContext(ctx, s.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	verification, err := readOnly.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	listed := false
	for _, progress := range verification.FTSBackfill {
		if progress.TableName == legacyPurgeMaintenanceState {
			listed = progress.Complete == (want == nil) && (want == nil || progress.ProcessedRows == want.Progress)
		}
	}
	if !listed {
		t.Fatalf("verify lists %+v, want the cleanup's checkpoint", verification.FTSBackfill)
	}
}

// While a tenant is being deleted, the cleanup waits. That tenant's purge
// compacts every index and truncates the log once its rows are erased, and
// the transaction of its tombstone completes the cleanup too: nothing of
// the tenant that an earlier release deleted is left either.
func TestLegacyPurgeMaintenanceWaitsForAUnitPurgeThatCompletesIt(t *testing.T) {
	ctx := context.Background()
	f, reader := legacyTombstoneWithResidue(t)
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	third, err := f.store.Platform().CreateTenant(ctx, "Third", "third", AuditEntry{ActorUserID: platformAdminID})
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := f.store.Platform().DisableTenant(ctx, third.ID, third.Revision, AuditEntry{ActorUserID: platformAdminID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Platform().RequestTenantDeletion(ctx, third.ID, disabled.Name, AuditEntry{ActorUserID: platformAdminID}); err != nil {
		t.Fatal(err)
	}
	result, err := f.store.System().RunLegacyPurgeMaintenance(ctx)
	if err != nil || result != (LegacyPurgeMaintenanceResult{Pending: true, Deferred: true}) {
		t.Fatalf("cleanup while a tenant is being deleted = %+v, %v; want it deferred", result, err)
	}
	if row, ok := legacyPurgeMaintenanceRow(t, f.store); !ok || row.Initialized || row.LastRowID != 0 {
		t.Fatalf("the deferred cleanup = %+v, %v; want it untouched", row, ok)
	}

	results, err := f.store.System().PurgeDeletingTenants(ctx)
	if err != nil || len(results) != 1 || results[0].TenantID != third.ID || !results[0].Complete || !results[0].LegacyMaintenanceCompleted {
		t.Fatalf("purge of the third tenant = %+v, %v; want it to complete the cleanup", results, err)
	}
	if row, ok := legacyPurgeMaintenanceRow(t, f.store); !ok || !row.Complete || row.ProcessedRows != legacyPurgeMaintenancePosition(tenantPurgePhaseCheckpoint) {
		t.Fatalf("the cleanup after the purge = %+v, %v", row, ok)
	}
	if result, err := f.store.System().RunLegacyPurgeMaintenance(ctx); err != nil || result.Pending {
		t.Fatalf("a pass after the purge = %+v, %v; want nothing pending", result, err)
	}
	assertNothingOfTheMarkerLeft(t, f.store)

	// A purge without a pending cleanup completes none.
	fourth, err := f.store.Platform().CreateTenant(ctx, "Fourth", "fourth", AuditEntry{ActorUserID: platformAdminID})
	if err != nil {
		t.Fatal(err)
	}
	if disabled, err = f.store.Platform().DisableTenant(ctx, fourth.ID, fourth.Revision, AuditEntry{ActorUserID: platformAdminID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Platform().RequestTenantDeletion(ctx, fourth.ID, disabled.Name, AuditEntry{ActorUserID: platformAdminID}); err != nil {
		t.Fatal(err)
	}
	if results, err := f.store.System().PurgeDeletingTenants(ctx); err != nil || len(results) != 1 || !results[0].Complete || results[0].LegacyMaintenanceCompleted {
		t.Fatalf("purge of the fourth tenant = %+v, %v", results, err)
	}
}

// A cleanup that is no longer pending when a pass records its progress
// stops the pass, a database error is returned, and a phase that the
// cleanup does not know starts it over.
func TestLegacyPurgeMaintenanceStopsWhenItIsNoLongerPending(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	insertTenantInState(t, s, "deleted", TenantStateDeleted, tenantPurgePhaseComplete)
	if err := applyMigration(s.DB, 55, migration55Statements()); err != nil {
		t.Fatal(err)
	}
	complete := `UPDATE fts_backfill_state SET complete=1 WHERE table_name='` + legacyPurgeMaintenanceState + `'`
	result, err := s.System().runLegacyPurgeMaintenance(ctx, tenantPurgeOptions{afterMerge: func(ctx context.Context, _ string, _ int) error {
		_, err := s.DB.ExecContext(ctx, complete)
		return err
	}})
	if !errors.Is(err, ErrConflict) || result.Complete {
		t.Fatalf("cleanup that another pass completed = %+v, %v", result, err)
	}

	// The cleanup completes in its checkpoint phase, without recording a
	// phase, before the pass does.
	if _, err := s.DB.Exec(`UPDATE fts_backfill_state SET complete=0,initialized=0,last_rowid=? WHERE table_name=?`, legacyPurgeMaintenancePosition(tenantPurgePhaseCheckpoint), legacyPurgeMaintenanceState); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER complete_on_start AFTER UPDATE OF initialized ON fts_backfill_state WHEN NEW.table_name='` + legacyPurgeMaintenanceState + `' BEGIN ` + complete + `; END`); err != nil {
		t.Fatal(err)
	}
	if result, err := s.System().RunLegacyPurgeMaintenance(ctx); !errors.Is(err, ErrConflict) || result.Complete || result.Phase != tenantPurgePhaseCheckpoint {
		t.Fatalf("cleanup completed during its checkpoint phase = %+v, %v", result, err)
	}
	if _, err := s.DB.Exec(`DROP TRIGGER complete_on_start`); err != nil {
		t.Fatal(err)
	}

	// A position past the last phase starts the cleanup over.
	if _, err := s.DB.Exec(`UPDATE fts_backfill_state SET complete=0,last_rowid=99 WHERE table_name=?`, legacyPurgeMaintenanceState); err != nil {
		t.Fatal(err)
	}
	var merged mergeLog
	if result, err := s.System().runLegacyPurgeMaintenance(ctx, tenantPurgeOptions{afterMerge: merged.afterMerge}); err != nil || !result.Complete || !slices.Equal(merged.started, tenantPurgeSearchIndexes) {
		t.Fatalf("cleanup from an unknown position = %+v, %v (merges %+v)", result, err, merged)
	}

	// A closed writer fails the pass after the checkpoint was read, and a
	// closed database fails it and the report at once.
	if _, err := s.DB.Exec(`UPDATE fts_backfill_state SET complete=0,initialized=0,last_rowid=0 WHERE table_name=?`, legacyPurgeMaintenanceState); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if result, err := s.System().RunLegacyPurgeMaintenance(ctx); err == nil || !result.Pending || result.Started {
		t.Fatalf("cleanup with a closed writer = %+v, %v", result, err)
	}
	_ = s.Close()
	if _, err := s.System().RunLegacyPurgeMaintenance(ctx); err == nil {
		t.Fatal("cleanup of a closed database succeeded")
	}
	if _, err := legacyPurgeMaintenanceStatus(ctx, s.reader()); err == nil {
		t.Fatal("the cleanup of a closed database was reported")
	}
}
