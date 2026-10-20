package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// reconstructSchema75 removes what schema 76 added from the open store's
// database, so the migration can run again on it.
func reconstructSchema75(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, statement := range []string{
		`DROP TRIGGER IF EXISTS perimeter_seeds_tenant_immutable`,
		`DROP TABLE IF EXISTS perimeter_seeds`,
		`PRAGMA user_version=75`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("reconstruct schema 75 with %s: %v", statement, err)
		}
	}
}

// Schema 76 adds the perimeter table and its tenant guard in one step: a
// failed step leaves schema 75 as it was, the step applies to a schema 75
// database, and it applies again, as a test that lowers a current template
// runs it, without touching the stored ranges.
func TestMigration76AddsThePerimeterTable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	reconstructSchema75(t, s.DB)

	if err := runMigration(ctx, s.DB, 76, append(migration76Statements(), `CREATE INDEX perimeter_seeds_broken ON perimeter_seeds(missing_column)`), false); err == nil {
		t.Fatal("schema 76 migration with an invalid index succeeded")
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 75 {
		t.Fatalf("failed schema 76 migration advanced to schema %d", got)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE tbl_name='perimeter_seeds'`); got != 0 {
		t.Fatalf("failed schema 76 migration left %d schema objects of perimeter_seeds", got)
	}

	if err := applyMigration(ctx, s.DB, 76, migration76Statements()); err != nil {
		t.Fatalf("apply schema 76: %v", err)
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 76 {
		t.Fatalf("schema version = %d, want 76", got)
	}
	want := []string{
		"id TEXT notnull=0 default=<none> pk=1",
		"tenant_id TEXT notnull=1 default=<none> pk=0",
		"kind TEXT notnull=1 default=<none> pk=0",
		"value TEXT notnull=1 default=<none> pk=0",
		"label TEXT notnull=1 default='' pk=0",
		"source TEXT notnull=1 default='declared' pk=0",
		"adopted_from TEXT notnull=1 default='' pk=0",
		"created_at TEXT notnull=1 default=<none> pk=0",
		"created_by TEXT notnull=1 default='' pk=0",
	}
	if got := tableColumns(t, s.DB, "perimeter_seeds"); !reflect.DeepEqual(got, want) {
		t.Fatalf("perimeter_seeds columns = %q, want %q", got, want)
	}
	// The UNIQUE constraint's index is the table's only index; it serves the
	// lookups by tenant and by tenant and kind.
	if got := queryStrings(t, s.DB, `SELECT name FROM pragma_index_list('perimeter_seeds') WHERE origin<>'pk' ORDER BY name`); !reflect.DeepEqual(got, []string{"sqlite_autoindex_perimeter_seeds_2"}) {
		t.Fatalf("perimeter_seeds indexes = %q", got)
	}
	if got := indexKeys(t, s.DB, "sqlite_autoindex_perimeter_seeds_2"); got != "tenant_id,kind,value" {
		t.Fatalf("unique index keys = %q", got)
	}
	if plan := queryPlan(t, s.DB, `SELECT id FROM perimeter_seeds WHERE tenant_id=? AND kind IN ('prefix','authorized')`, DefaultTenantID); !strings.Contains(plan, "sqlite_autoindex_perimeter_seeds_2") {
		t.Fatalf("the unit's ranges are not read through the unique index: %s", plan)
	}

	if _, err := s.DB.ExecContext(ctx, `INSERT INTO perimeter_seeds(id,tenant_id,kind,value,created_at) VALUES('kept',?,'prefix','192.0.2.0/24','2026-10-20T00:00:00.000000000Z')`, DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	if err := reapplyMigration(t, s.DB, 76, migration76Statements()); err != nil {
		t.Fatalf("reapply schema 76: %v", err)
	}
	if got := queryStrings(t, s.DB, `SELECT id||':'||kind||':'||value FROM perimeter_seeds`); !reflect.DeepEqual(got, []string{"kept:prefix:192.0.2.0/24"}) {
		t.Fatalf("ranges after reapplying schema 76 = %q", got)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='perimeter_seeds_tenant_immutable'`); got != 1 {
		t.Fatalf("tenant guard triggers after reapplying schema 76 = %d, want 1", got)
	}
	// reapplyMigration left the marker at 76, whatever the current schema is.
	if err := runMigration(ctx, s.DB, 76, migration76Statements(), false); err == nil || err.Error() != "schema migration 76: the database is at schema 76, not 75; another process is migrating it" {
		t.Errorf("repeated schema 76 migration = %v, want moved-marker refusal", err)
	}
}

// The table refuses what the store never writes: a second row with the same
// tenant, kind and value, an unknown kind or source, an empty or over-long
// value, a tenant that does not exist, and a change of a row's tenant. The
// same value under another kind or in another tenant is allowed, and so are
// the kind asn and the source adopted, which later stages write.
func TestMigration76PerimeterTableConstraints(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	insertSecondTenant(t, s)
	stamp := sqliteTimestamp(time.Now())
	sequence := 0
	insert := func(tenant, kind, value, source string) error {
		sequence++
		_, err := s.DB.Exec(`INSERT INTO perimeter_seeds(id,tenant_id,kind,value,source,created_at) VALUES(?,?,?,?,?,?)`, fmt.Sprintf("seed-%d", sequence), tenant, kind, value, source, stamp)
		return err
	}
	for _, accepted := range []struct{ tenant, kind, value, source string }{
		{DefaultTenantID, PerimeterKindPrefix, "192.0.2.0/24", "declared"},
		{DefaultTenantID, PerimeterKindAuthorized, "192.0.2.0/24", "declared"},
		{secondTenantID, PerimeterKindPrefix, "192.0.2.0/24", "declared"},
		{DefaultTenantID, PerimeterKindASN, "AS64500", "declared"},
		{DefaultTenantID, PerimeterKindPrefix, "198.51.100.0/24", "adopted"},
		{DefaultTenantID, PerimeterKindPrefix, strings.Repeat("x", 64), "declared"},
	} {
		if err := insert(accepted.tenant, accepted.kind, accepted.value, accepted.source); err != nil {
			t.Errorf("insert %+v: %v", accepted, err)
		}
	}
	for _, refused := range []struct {
		name                        string
		tenant, kind, value, source string
		want                        string
	}{
		{"duplicate", DefaultTenantID, PerimeterKindPrefix, "192.0.2.0/24", "declared", "UNIQUE constraint failed"},
		{"unknown kind", DefaultTenantID, "owned", "203.0.113.0/24", "declared", "CHECK constraint failed"},
		{"unknown source", DefaultTenantID, PerimeterKindPrefix, "203.0.113.0/24", "imported", "CHECK constraint failed"},
		{"empty value", DefaultTenantID, PerimeterKindPrefix, "", "declared", "CHECK constraint failed"},
		{"over-long value", DefaultTenantID, PerimeterKindPrefix, strings.Repeat("x", 65), "declared", "CHECK constraint failed"},
		{"unknown tenant", "00000000-0000-0000-0000-00000000dead", PerimeterKindPrefix, "203.0.113.0/24", "declared", "FOREIGN KEY constraint failed"},
	} {
		if err := insert(refused.tenant, refused.kind, refused.value, refused.source); err == nil || !strings.Contains(err.Error(), refused.want) {
			t.Errorf("%s: insert error = %v, want %q", refused.name, err, refused.want)
		}
	}
	if _, err := s.DB.Exec(`UPDATE perimeter_seeds SET tenant_id=? WHERE id='seed-1'`, secondTenantID); err == nil || !strings.Contains(err.Error(), "perimeter_seeds.tenant_id cannot be changed") {
		t.Fatalf("moving a range to another tenant = %v, want the tenant guard", err)
	}
	if _, err := s.DB.Exec(`UPDATE perimeter_seeds SET label='edge' WHERE id='seed-1'`); err != nil {
		t.Fatalf("updating a label: %v", err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM perimeter_seeds WHERE tenant_id=?`, DefaultTenantID); got != 5 {
		t.Fatalf("default tenant ranges = %d, want 5", got)
	}
}

// A schema 75 backup restores as it is: Restore stages it without running
// the application migrations, so the restored file is still at schema 75
// and has no perimeter table. The next Open upgrades it to the current
// schema with an empty perimeter, which accepts declarations.
func TestMigration76UpgradesARestoredSchema75Backup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// The backup starts as a copy of the migrated template, lowered to
	// schema 75, so the test does not migrate from scratch.
	source := freshTestDatabasePath(t)
	destination := filepath.Join(t.TempDir(), "restored.db")
	s, err := Open(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateJob(ctx, testJob("edge")); err != nil {
		t.Fatal(err)
	}
	reconstructSchema75(t, s.DB)
	if _, err := s.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Restore(ctx, source, destination, RestoreOptions{}); err != nil {
		t.Fatalf("restore a schema 75 backup: %v", err)
	}
	raw, err := sql.Open("sqlite", destination)
	if err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, raw, `PRAGMA user_version`); got != 75 {
		t.Fatalf("restored schema = %d, want the backup's 75", got)
	}
	if got := countRows(t, raw, `SELECT COUNT(*) FROM sqlite_master WHERE name='perimeter_seeds'`); got != 0 {
		t.Fatal("the restore created the perimeter table without migrating")
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	restored, err := Open(destination)
	if err != nil {
		t.Fatalf("open the restored schema 75 database: %v", err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	if got := countRows(t, restored.DB, `PRAGMA user_version`); got != schemaVersion {
		t.Fatalf("schema after opening the restored database = %d, want %d", got, schemaVersion)
	}
	ts := defaultTenant(restored)
	if seeds, err := ts.ListPerimeterSeeds(ctx); err != nil || len(seeds) != 0 {
		t.Fatalf("perimeter after the upgrade = %+v, %v; want empty", seeds, err)
	}
	if records, err := ts.ListJobs(ctx, false); err != nil || len(records) != 1 || records[0].Job.Name != "edge" {
		t.Fatalf("jobs after the upgrade = %+v, %v", records, err)
	}
	if result, err := ts.DeclarePerimeterSeeds(ctx, []PerimeterEntry{{Kind: PerimeterKindPrefix, Value: "192.0.2.0/24"}}, AuditEntry{}); err != nil || result.Created != 1 {
		t.Fatalf("declare after the upgrade = %+v, %v", result, err)
	}
}
