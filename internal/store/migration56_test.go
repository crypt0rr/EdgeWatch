package store

import (
	"context"
	"slices"
	"testing"
)

// reopenAtSchema55 turns the store's database back into a schema 55 one and
// opens it again, as the first start of this release after an upgrade does.
func reopenAtSchema55(t *testing.T, s *Store) *Store {
	t.Helper()
	if _, err := s.DB.Exec(`PRAGMA user_version=55`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Open(s.Path)
	if err != nil {
		t.Fatalf("upgrade from schema 55: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	return upgraded
}

// completeLegacyCleanupAsBefore records the cleanup after deleted tenants as
// a release before schema 56 completed it, at its checkpoint phase, which
// was then its fourth.
func completeLegacyCleanupAsBefore(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.DB.Exec(`INSERT INTO fts_backfill_state(table_name,last_rowid,processed_rows,initialized,complete,updated_at) VALUES(?,4,4,1,1,'2026-09-29T10:00:00Z')`, legacyPurgeMaintenanceState); err != nil {
		t.Fatal(err)
	}
}

// purgePhaseOf returns the purge phase of a tenant.
func purgePhaseOf(t *testing.T, s *Store, id string) string {
	t.Helper()
	var phase string
	if err := s.DB.QueryRow(`SELECT purge_phase FROM tenants WHERE id=?`, id).Scan(&phase); err != nil {
		t.Fatal(err)
	}
	return phase
}

// In a database without incremental auto-vacuum that holds a deleted
// tenant, schema 56 records the cleanup after deleted tenants as pending at
// its free-pages phase, whether there was none or one that an earlier
// release completed, and leaves a pending one alone. A deletion that had
// reached its checkpoint phase goes back to the free-pages phase. A
// database with incremental auto-vacuum is left as it was, and so is the
// cleanup when the migration runs again after it has finished.
func TestMigration56RecordsTheOverwriteWhereFreePagesStay(t *testing.T) {
	t.Parallel()
	freePages := legacyPurgeMaintenancePosition(tenantPurgePhaseFreePages)
	last := legacyPurgeMaintenancePosition(tenantPurgePhaseCheckpoint)
	if freePages != 4 || last != 5 {
		t.Fatalf("the free-pages phase is at %d and the checkpoint at %d; schema 56 re-records cleanups that releases before it completed at 4", freePages, last)
	}
	insertOthers := func(t *testing.T, s *Store) {
		t.Helper()
		insertTenantInState(t, s, "checkpointing", TenantStateDeleting, tenantPurgePhaseCheckpoint)
		insertTenantInState(t, s, "compacting", TenantStateDeleting, tenantPurgePhaseCompact+"latest_host_search")
	}

	// With incremental auto-vacuum nothing changes.
	s := openTestStore(t)
	insertOthers(t, s)
	insertTenantInState(t, s, "deleted", TenantStateDeleted, tenantPurgePhaseComplete)
	completeLegacyCleanupAsBefore(t, s)
	before, _ := legacyPurgeMaintenanceRow(t, s)
	s = reopenAtSchema55(t, s)
	if after, ok := legacyPurgeMaintenanceRow(t, s); !ok || after != before {
		t.Fatalf("an upgrade with incremental auto-vacuum changed the cleanup from %+v to %+v", before, after)
	}
	if phase := purgePhaseOf(t, s, "checkpointing"); phase != tenantPurgePhaseCheckpoint {
		t.Fatalf("an upgrade with incremental auto-vacuum moved a deletion to %s", phase)
	}

	// Without it and without a deleted tenant, only the deletion at its
	// checkpoint moves.
	s = openTestStore(t)
	useAutoVacuum(t, s, "NONE")
	insertOthers(t, s)
	s = reopenAtSchema55(t, s)
	if row, ok := legacyPurgeMaintenanceRow(t, s); ok {
		t.Fatalf("an upgrade without a deleted tenant recorded the cleanup %+v", row)
	}
	for id, want := range map[string]string{"checkpointing": tenantPurgePhaseFreePages, "compacting": tenantPurgePhaseCompact + "latest_host_search"} {
		if phase := purgePhaseOf(t, s, id); phase != want {
			t.Errorf("tenant %s is in phase %s after the upgrade, want %s", id, phase, want)
		}
	}

	// With a deleted tenant, the cleanup is pending at the free-pages phase,
	// whether the database had none or one that an earlier release
	// completed.
	for name, prepare := range map[string]func(*testing.T, *Store){
		"no cleanup":        func(*testing.T, *Store) {},
		"completed cleanup": completeLegacyCleanupAsBefore,
	} {
		s = openTestStore(t)
		useAutoVacuum(t, s, "NONE")
		insertTenantInState(t, s, "deleted", TenantStateDeleted, tenantPurgePhaseComplete)
		prepare(t, s)
		s = reopenAtSchema55(t, s)
		row, ok := legacyPurgeMaintenanceRow(t, s)
		if !ok || row.Complete || row.Initialized || row.LastRowID != freePages || row.ProcessedRows != freePages-1 || row.UpdatedAt == "" || row.UpdatedAt == "2026-09-29T10:00:00Z" {
			t.Fatalf("%s: the cleanup after the upgrade = %+v, %v; want it pending at the free-pages phase", name, row, ok)
		}
	}

	// A cleanup that is still pending stays where it is.
	if _, err := s.DB.Exec(`UPDATE fts_backfill_state SET last_rowid=2,processed_rows=1,initialized=1,updated_at='2026-09-29T11:00:00Z' WHERE table_name=?`, legacyPurgeMaintenanceState); err != nil {
		t.Fatal(err)
	}
	before, _ = legacyPurgeMaintenanceRow(t, s)
	s = reopenAtSchema55(t, s)
	if after, _ := legacyPurgeMaintenanceRow(t, s); after != before {
		t.Fatalf("the upgrade moved a pending cleanup from %+v to %+v", before, after)
	}

	// Once this release has completed it, it stays complete.
	if _, err := completeLegacyPurgeMaintenance(context.Background(), s.DB); err != nil {
		t.Fatal(err)
	}
	before, _ = legacyPurgeMaintenanceRow(t, s)
	s = reopenAtSchema55(t, s)
	if after, _ := legacyPurgeMaintenanceRow(t, s); after != before || !after.Complete || after.LastRowID != last {
		t.Fatalf("repeating migration 56 changed the complete cleanup from %+v to %+v", before, after)
	}
}

// In a database without incremental auto-vacuum, the cleanup that schema 55
// records overwrites the free pages after compacting the indexes: pages
// that retention freed while the unit existed hold its rows, and after the
// cleanup no free page does.
func TestLegacyPurgeMaintenanceOverwritesFreePages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	useAutoVacuum(t, f.store, "NONE")
	seedTenantPurgeMarker(t, f)
	kept := tenantContent(t, f.store, DefaultTenantID)
	if _, err := f.store.DB.Exec(`DELETE FROM scan_hosts WHERE scan_id=?`, f.scanB); err != nil {
		t.Fatal(err)
	}
	requestSecondTenantDeletion(t, f)
	// A release before schema 55 erased the rows and made the tombstone
	// before any maintenance.
	if _, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, maintenanceBudget: spentBudget}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`UPDATE tenants SET state=?,purge_phase=? WHERE id=?`, TenantStateDeleted, tenantPurgePhaseComplete, secondTenantID); err != nil {
		t.Fatal(err)
	}
	if err := applyMigration(f.store.DB, 55, migration55Statements()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if copies, _ := freePageCopies(t, f.store.Path, []byte(tenantPurgeMarker)); copies == 0 {
		t.Fatal("no free page holds the unit's rows; the test shows nothing")
	}

	var merged mergeLog
	var steps freePagesLog
	result, err := f.store.System().runLegacyPurgeMaintenance(ctx, tenantPurgeOptions{afterMerge: merged.afterMerge, afterFreePages: steps.afterFreePages})
	if err != nil || result != (LegacyPurgeMaintenanceResult{Pending: true, Started: true, Phase: tenantPurgePhaseComplete, Complete: true}) {
		t.Fatalf("cleanup = %+v, %v; want it started and complete", result, err)
	}
	if !slices.Equal(merged.started, tenantPurgeSearchIndexes) || len(steps) < 3 || steps[len(steps)-1] != freePagesFinished {
		t.Fatalf("the cleanup merged %+v and overwrote free pages in steps %v", merged, steps)
	}
	last := legacyPurgeMaintenancePosition(tenantPurgePhaseCheckpoint)
	if row, ok := legacyPurgeMaintenanceRow(t, f.store); !ok || !row.Complete || row.LastRowID != last || row.ProcessedRows != last {
		t.Fatalf("the finished cleanup = %+v, %v", row, ok)
	}
	assertNothingOfTheMarkerLeft(t, f.store)
	assertNoFreePageCopies(t, f.store)
	assertNoFreePagesTable(t, f.store)
	assertLiveDataKept(t, f.store, kept)
}

// After an upgrade over a unit that a release before schema 56 deleted in a
// database without incremental auto-vacuum, the cleanup overwrites the free
// pages that still hold the unit's rows and truncates the log, without
// compacting the indexes again. edgewatch health reports it at its
// free-pages phase until it has finished.
func TestLegacyPurgeMaintenanceAfterSchema56OverwritesOnlyFreePages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	useAutoVacuum(t, f.store, "NONE")
	seedTenantPurgeMarker(t, f)
	requestSecondTenantDeletion(t, f)
	if results, err := f.store.System().PurgeDeletingTenants(ctx); err != nil || len(results) != 1 || !results[0].Complete {
		t.Fatalf("purge = %+v, %v", results, err)
	}
	// What that release left in the free pages, and the cleanup it
	// completed.
	freeMarkerPages(t, f.store, 300)
	completeLegacyCleanupAsBefore(t, f.store)
	kept := tenantContent(t, f.store, DefaultTenantID)
	s := reopenAtSchema55(t, f.store)
	if err := s.System().AcquireLease(ctx, "daemon"); err != nil {
		t.Fatal(err)
	}
	freePages := legacyPurgeMaintenancePosition(tenantPurgePhaseFreePages)
	last := legacyPurgeMaintenancePosition(tenantPurgePhaseCheckpoint)
	assertLegacyPurgeMaintenanceReported(t, s, &MaintenanceStatus{Phase: legacyPurgeMaintenancePhase + ":" + tenantPurgePhaseFreePages, Progress: freePages - 1, Total: last})

	var merged mergeLog
	var steps freePagesLog
	result, err := s.System().runLegacyPurgeMaintenance(ctx, tenantPurgeOptions{afterMerge: merged.afterMerge, afterFreePages: steps.afterFreePages})
	if err != nil || result != (LegacyPurgeMaintenanceResult{Pending: true, Started: true, Phase: tenantPurgePhaseComplete, Complete: true}) {
		t.Fatalf("cleanup = %+v, %v; want it started and complete", result, err)
	}
	if len(merged.started) != 0 || len(merged.continued) != 0 || len(steps) < 3 || steps[len(steps)-1] != freePagesFinished {
		t.Fatalf("the cleanup merged %+v and overwrote free pages in steps %v; want only the overwrite", merged, steps)
	}
	assertLegacyPurgeMaintenanceReported(t, s, nil)
	assertNothingOfTheMarkerLeft(t, s)
	assertNoFreePageCopies(t, s)
	assertNoFreePagesTable(t, s)
	assertLiveDataKept(t, s, kept)
}

// A deletion that a release before schema 56 left in its checkpoint phase,
// because a reader kept the log, had compacted the indexes but not
// overwritten the free pages. After the upgrade it overwrites them before
// its tombstone.
func TestMigration56SendsACheckpointingPurgeBackToTheOverwrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	useAutoVacuum(t, f.store, "NONE")
	seedTenantPurgeMarker(t, f)
	requestSecondTenantDeletion(t, f)
	shortenBusyTimeout(t, f.store)
	reader := openSnapshot(t, f.store)
	results, err := f.store.System().PurgeDeletingTenants(ctx)
	if err != nil || len(results) != 1 || !results[0].CheckpointBusy || results[0].Phase != tenantPurgePhaseCheckpoint {
		t.Fatalf("purge with a reader open = %+v, %v", results, err)
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	// The free pages that release did not overwrite.
	freeMarkerPages(t, f.store, 300)
	kept := tenantContent(t, f.store, DefaultTenantID)
	s := reopenAtSchema55(t, f.store)
	if phase := purgePhaseOf(t, s, secondTenantID); phase != tenantPurgePhaseFreePages {
		t.Fatalf("the deletion is in phase %s after the upgrade, want %s", phase, tenantPurgePhaseFreePages)
	}

	var steps freePagesLog
	results, err = s.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, afterFreePages: steps.afterFreePages})
	if err != nil || len(results) != 1 || !results[0].Complete || len(steps) < 3 || steps[len(steps)-1] != freePagesFinished {
		t.Fatalf("purge after the upgrade = %+v, %v with steps %v", results, err, steps)
	}
	assertNothingOfTheMarkerLeft(t, s)
	assertNoFreePageCopies(t, s)
	assertLiveDataKept(t, s, kept)
}
