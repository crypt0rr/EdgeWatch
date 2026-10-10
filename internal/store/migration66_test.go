package store

import (
	"context"
	"database/sql"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// schema66ScanIndexes are the scan history indexes that schema 66 adds, and
// schema65ScanIndexes, with their keys, the ones it replaces.
var (
	schema66ScanIndexes = map[string]string{
		scansJobHistoryIndex:    "job_id,finished_at DESC,id DESC,tenant_id,status",
		scansTenantHistoryIndex: "tenant_id,finished_at DESC,id DESC,job_id,status,job",
		scansIdentityIndex:      "id,tenant_id,job_id,status,finished_at,job",
		scansCycleOutcomeIndex:  "cycle_id,cycle_status,status,tenant_id",
	}
	schema65ScanIndexes = map[string]string{
		"scans_job_time":       "job,finished_at DESC",
		"scans_job_id_time":    "job_id,finished_at DESC,id DESC",
		"scans_cycle_id":       "cycle_id",
		"scans_tenant_id_time": "tenant_id,finished_at DESC,id DESC",
	}
)

// schema65LatestScanHostScanTenantCheck is the scan check of the latest-host
// guard triggers from schema 54 to schema 65, which read the tenant from the
// scan row.
const schema65LatestScanHostScanTenantCheck = `NEW.tenant_id IS NOT (SELECT scans.tenant_id FROM scans WHERE scans.id=NEW.scan_id)`

// schema66UndoStatements turn a current database back into the schema-65
// shape: the indexes that schema 66 replaced come back in place of its own,
// the latest-host guard triggers read the scan row again, and the legacy
// host index checkpoint is removed.
var schema66UndoStatements = func() []string {
	statements := []string{
		"DROP TRIGGER " + latestScanHostsTenantInsertTrigger,
		"DROP TRIGGER " + latestScanHostsTenantUpdateTrigger,
	}
	for _, trigger := range latestScanHostsTenantTriggerSQL {
		statements = append(statements, strings.ReplaceAll(trigger, "NOT "+latestScanHostScanTenantSQL, schema65LatestScanHostScanTenantCheck))
	}
	for _, index := range slices.Sorted(maps.Keys(schema66ScanIndexes)) {
		statements = append(statements, "DROP INDEX "+index)
	}
	for _, index := range slices.Sorted(maps.Keys(schema65ScanIndexes)) {
		statements = append(statements, "CREATE INDEX "+index+" ON scans("+schema65ScanIndexes[index]+")")
	}
	return append(statements, "DELETE FROM fts_backfill_state WHERE table_name='"+legacyScanHostIndexState+"'")
}()

// schema65FixtureStatements turn a current database into the schema-65
// shape.
var schema65FixtureStatements = append(slices.Clone(schema66UndoStatements), "PRAGMA user_version=65")

// pendingLegacyScanHostIndexSQL sets the legacy host index backfill's
// marker back to pending, as an upgrade from before schema 66 does. A test
// that removes a scan's host rows or checkpoint, to model a scan of a
// release before the host index, runs it too, because a saved scan never
// waits for the backfill.
const pendingLegacyScanHostIndexSQL = `UPDATE fts_backfill_state SET complete=0 WHERE table_name='` + legacyScanHostIndexState + `'`

// rewindToLegacyScans makes saved scans look like scans of a release before
// the host index: it removes their host rows and backfill checkpoints, and
// sets the backfill's marker back to pending.
func rewindToLegacyScans(t testing.TB, db *sql.DB, scanIDs ...string) {
	t.Helper()
	for _, id := range scanIDs {
		for _, statement := range []string{`DELETE FROM scan_hosts WHERE scan_id=?`, `DELETE FROM latest_scan_hosts WHERE scan_id=?`, `DELETE FROM legacy_scan_host_backfill WHERE scan_id=?`} {
			if _, err := db.Exec(statement, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.Exec(pendingLegacyScanHostIndexSQL); err != nil {
		t.Fatal(err)
	}
}

// legacyScanHostIndexMarker returns the complete flag of the legacy host
// index checkpoint, or -1 when the database has none.
func legacyScanHostIndexMarker(t *testing.T, db *sql.DB) int {
	t.Helper()
	marker := -1
	if err := db.QueryRow(`SELECT complete FROM fts_backfill_state WHERE table_name=?`, legacyScanHostIndexState).Scan(&marker); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	return marker
}

// Schema 66 replaces the scan history indexes and the latest-host guard
// triggers and records the legacy host index backfill, without changing a
// scan. The startup backfill then finds nothing left and marks itself
// complete, and a repeated upgrade does the same again.
func TestMigration66ReplacesScanHistoryIndexesAndKeepsScans(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("migration-66"))
	if err != nil {
		t.Fatal(err)
	}
	finished := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for index, scan := range []model.Scan{
		largeSnapshotScan("schema-65-large", record.ID, record.Job.Name, finished),
		fixtureScan("schema-65-hosts", record.ID, record.Job.Name, finished.Add(time.Minute), fixtureHosts(0, 3)),
		fixtureScan("schema-65-empty", record.ID, record.Job.Name, finished.Add(2*time.Minute), nil),
	} {
		scan.CycleID, scan.CycleStatus = "cycle-66", []string{"failed", "completed", "completed"}[index]
		if err := s.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	path := s.Path
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	execFixtureStatements(t, path, schema65FixtureStatements)

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for index, keys := range schema65ScanIndexes {
		if got := indexKeys(t, raw, index); got != keys {
			t.Fatalf("schema 65 fixture %s keys = %q, want %q", index, got, keys)
		}
	}
	const scanRows = `SELECT rowid,id,tenant_id,job_id,status,finished_at,cycle_id,cycle_status,length(snapshot_json),hex(changes_json) FROM scans ORDER BY rowid`
	var before strings.Builder
	if err := snapshotRows(raw, scanRows, &before); err != nil {
		t.Fatal(err)
	}

	for _, repeat := range []bool{false, true} {
		if repeat {
			if _, err := raw.Exec(`PRAGMA user_version=65`); err != nil {
				t.Fatal(err)
			}
		}
		upgraded, err := Open(path)
		if err != nil {
			t.Fatalf("upgrade from schema 65 (repeated %t): %v", repeat, err)
		}
		for index, keys := range schema66ScanIndexes {
			if got := indexKeys(t, upgraded.DB, index); got != keys {
				t.Fatalf("%s keys = %q, want %q", index, got, keys)
			}
		}
		for index := range schema65ScanIndexes {
			if got := countRows(t, upgraded.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, index); got != 0 {
				t.Fatalf("index %s is left after schema 66", index)
			}
		}
		for _, trigger := range schema54Triggers {
			var definition string
			if err := upgraded.DB.QueryRow(`SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?`, trigger).Scan(&definition); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(definition, latestScanHostScanTenantSQL) || strings.Contains(definition, schema65LatestScanHostScanTenantCheck) {
				t.Fatalf("trigger %s = %s, want the scan check through the tenant", trigger, definition)
			}
		}
		if got := legacyScanHostIndexMarker(t, upgraded.DB); got != 1 {
			t.Fatalf("legacy host index checkpoint after the startup backfill = %d, want complete", got)
		}
		var after strings.Builder
		if err := snapshotRows(upgraded.DB, scanRows, &after); err != nil {
			t.Fatal(err)
		}
		if after.String() != before.String() {
			t.Fatalf("schema 66 changed the scans:\n%s\nwant\n%s", after.String(), before.String())
		}
		var integrity string
		if err := upgraded.DB.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
			t.Fatalf("integrity_check = %q, %v", integrity, err)
		}
		assertForeignKeysClean(t, upgraded.DB)

		// The guard triggers still refuse a latest host in another tenant
		// than its scan, and accept the scan's own.
		if !repeat {
			insertSecondTenant(t, upgraded)
		}
		if _, err := upgraded.DB.Exec(`INSERT INTO latest_scan_hosts(tenant_id,address,scan_id,finished_at,host_json) VALUES(?,'192.0.2.250','schema-65-hosts','x','{}')`, secondTenantID); err == nil || !strings.Contains(err.Error(), "must be the tenant of the row's scan") {
			t.Fatalf("latest host in another tenant than its scan = %v, want the guard to refuse it", err)
		}
		if _, err := upgraded.DB.Exec(`UPDATE latest_scan_hosts SET scan_id='schema-65-missing' WHERE scan_id='schema-65-hosts'`); err == nil || !strings.Contains(err.Error(), "must be the tenant of the row's scan") {
			t.Fatalf("latest host moved to a missing scan = %v, want the guard to refuse it", err)
		}
		if _, err := upgraded.DB.Exec(`INSERT INTO latest_scan_hosts(tenant_id,address,scan_id,finished_at,host_json) VALUES(?,'192.0.2.250','schema-65-hosts','x','{}')`, DefaultTenantID); err != nil {
			t.Fatalf("latest host of its scan's tenant: %v", err)
		}
		if _, err := upgraded.DB.Exec(`DELETE FROM latest_scan_hosts WHERE address='192.0.2.250'`); err != nil {
			t.Fatal(err)
		}
		if err := upgraded.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
