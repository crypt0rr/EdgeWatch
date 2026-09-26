package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"modernc.org/sqlite"
)

// rebuildFixtureSchema models a parent table such as users or jobs: two child
// tables reference it with ON DELETE CASCADE, a view reads it, and it has its
// own index. The parent rowids are deliberately sparse so a rebuild that
// renumbers them is caught.
const rebuildFixtureSchema = `
CREATE TABLE parents (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL UNIQUE
);
CREATE INDEX parents_name_id ON parents(name, id);
CREATE TABLE parent_notes (
 id INTEGER PRIMARY KEY,
 parent_id TEXT NOT NULL,
 note TEXT NOT NULL,
 FOREIGN KEY(parent_id) REFERENCES parents(id) ON DELETE CASCADE
);
CREATE TABLE parent_tags (
 parent_id TEXT NOT NULL,
 tag TEXT NOT NULL,
 PRIMARY KEY(parent_id, tag),
 FOREIGN KEY(parent_id) REFERENCES parents(id) ON DELETE CASCADE
);
CREATE VIEW parent_names AS SELECT id, name FROM parents;
INSERT INTO parents(rowid, id, name) VALUES (7, 'p1', 'alpha'), (42, 'p2', 'beta'), (1000, 'p3', 'gamma');
INSERT INTO parent_notes(id, parent_id, note) VALUES (1, 'p1', 'first'), (2, 'p1', 'second'), (3, 'p2', 'third');
INSERT INTO parent_tags(parent_id, tag) VALUES ('p1', 'edge'), ('p2', 'core'), ('p3', 'edge'), ('p3', 'lab');
PRAGMA user_version = 6;
`

// parentsRebuild adds a column to parents with the full table rebuild,
// including the view that must be dropped before the rename.
var parentsRebuild = sqliteTableRebuild{
	table:          "parents",
	definition:     "id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1",
	columns:        []string{"id", "name"},
	dropDependents: []string{"DROP VIEW parent_names"},
	recreate: []string{
		"CREATE INDEX parents_name_id ON parents(name, id)",
		"CREATE VIEW parent_names AS SELECT id, name FROM parents",
	},
}

// pinnedConnectionMarker is a TEMP table, which exists only on the connection
// that created it. The fixture creates it on the pool's only connection, so
// finding it later identifies the connection the runner pinned.
const pinnedConnectionMarker = "pinned_connection_marker"

// openRebuildTestDB opens a temporary file database through the production
// connector, so every new connection starts with PRAGMA foreign_keys=ON. Like
// the daemon's writer pool it holds one connection until a check widens it.
func openRebuildTestDB(t *testing.T) *sql.DB {
	t.Helper()
	connector, err := sqlite.NewConnector(filepath.Join(t.TempDir(), "rebuild.db"))
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(sqlitePragmaConnector{Connector: connector})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(4)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(rebuildFixtureSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TEMP TABLE " + pinnedConnectionMarker + " (x)"); err != nil {
		t.Fatal(err)
	}
	return db
}

// rebuildFixtureRows lists every fixture row together with its rowid.
func rebuildFixtureRows(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT 'parents', rowid, id || ':' || name FROM parents
UNION ALL SELECT 'parent_notes', rowid, parent_id || ':' || note FROM parent_notes
UNION ALL SELECT 'parent_tags', rowid, parent_id || ':' || tag FROM parent_tags
ORDER BY 1, 2`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var table, value string
		var rowID int64
		if err := rows.Scan(&table, &rowID, &value); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s/%d/%s", table, rowID, value))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func rebuildTestCount(t *testing.T, db *sql.DB, query string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(query).Scan(&count); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return count
}

func rebuildTestUserVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	return rebuildTestCount(t, db, "PRAGMA user_version")
}

// rebuildTestForeignKeyCheck returns the rows of PRAGMA foreign_key_check.
func rebuildTestForeignKeyCheck(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query("PRAGMA foreign_key_check")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var table, parent string
		var rowID, foreignKey sql.NullInt64
		if err := rows.Scan(&table, &rowID, &parent, &foreignKey); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s/%d/%s", table, rowID.Int64, parent))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

// assertParentsUnchanged checks that a failed run left the fixture exactly as
// seeded: the old table shape, its view, every row and the schema marker.
func assertParentsUnchanged(t *testing.T, db *sql.DB, want []string) {
	t.Helper()
	if got := rebuildFixtureRows(t, db); !slices.Equal(got, want) {
		t.Fatalf("rows changed:\n got %v\nwant %v", got, want)
	}
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM pragma_table_info('parents') WHERE name='enabled'"); got != 0 {
		t.Fatal("rolled-back rebuild left the new parents column")
	}
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM parent_names"); got != 3 {
		t.Fatalf("parent_names view rows = %d, want 3", got)
	}
	if got := rebuildTestUserVersion(t, db); got != 6 {
		t.Fatalf("user_version = %d, want 6", got)
	}
}

// assertPoolEnforcesForeignKeys holds several pool connections at once and
// checks that each enforces foreign keys. wantPinned is how many of them carry
// the marker of the connection the runner pinned: 1 when the runner returned
// it to the pool, 0 when it closed it.
func assertPoolEnforcesForeignKeys(t *testing.T, db *sql.DB, wantPinned int) {
	t.Helper()
	const connections = 4
	ctx := context.Background()
	db.SetMaxOpenConns(connections)
	defer db.SetMaxOpenConns(1)
	held := make([]*sql.Conn, 0, connections)
	defer func() {
		for _, conn := range held {
			_ = conn.Close()
		}
	}()
	pinned := 0
	for range connections {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
		var enabled, marker int
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&enabled); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_temp_master WHERE name=?", pinnedConnectionMarker).Scan(&marker); err != nil {
			t.Fatal(err)
		}
		if enabled != 1 {
			t.Errorf("pooled connection %d (pinned: %t) has foreign_keys=%d", len(held), marker == 1, enabled)
		}
		pinned += marker
	}
	if pinned != wantPinned {
		t.Fatalf("pool holds %d pinned connection(s), want %d", pinned, wantPinned)
	}
}

// cancelMigrationForTest is called by the edgewatch_test_cancel_migration()
// SQL function, which lets a test cancel a migration at an exact statement.
var cancelMigrationForTest atomic.Pointer[context.CancelFunc]

var registerCancelMigrationFunction = sync.OnceValue(func() error {
	return sqlite.RegisterScalarFunction("edgewatch_test_cancel_migration", 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
		if cancel := cancelMigrationForTest.Load(); cancel != nil {
			(*cancel)()
		}
		return int64(1), nil
	})
})

func TestForeignKeysOffMigrationRebuildKeepsCascadeChildren(t *testing.T) {
	ctx := context.Background()
	db := openRebuildTestDB(t)
	before := rebuildFixtureRows(t, db)

	if err := runMigration(ctx, db, 7, parentsRebuild.statements(), true); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	// Every parent keeps its rowid and every child row survives.
	if got := rebuildFixtureRows(t, db); !slices.Equal(got, before) {
		t.Fatalf("rows changed:\n got %v\nwant %v", got, before)
	}
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM parent_notes"); got != 3 {
		t.Fatalf("parent_notes rows = %d, want 3", got)
	}
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM parent_tags"); got != 4 {
		t.Fatalf("parent_tags rows = %d, want 4", got)
	}
	if got := rebuildTestUserVersion(t, db); got != 7 {
		t.Fatalf("user_version = %d, want 7", got)
	}
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM parents WHERE enabled=1"); got != 3 {
		t.Fatalf("parents with the new column default = %d, want 3", got)
	}
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='parents_name_id' AND tbl_name='parents'"); got != 1 {
		t.Fatal("parents index was not recreated")
	}
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM parent_names"); got != 3 {
		t.Fatalf("parent_names view rows = %d, want 3", got)
	}
	if got := rebuildTestForeignKeyCheck(t, db); len(got) != 0 {
		t.Fatalf("foreign_key_check after rebuild = %v", got)
	}
	assertPoolEnforcesForeignKeys(t, db, 1)

	// The children still reference the rebuilt table, and the cascade still
	// fires on the connection the runner used.
	if _, err := db.Exec("DELETE FROM parents WHERE id='p1'"); err != nil {
		t.Fatal(err)
	}
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM parent_notes"); got != 1 {
		t.Fatalf("parent_notes rows after deleting p1 = %d, want 1", got)
	}
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM parent_tags"); got != 3 {
		t.Fatalf("parent_tags rows after deleting p1 = %d, want 3", got)
	}
}

// The plain runner shows the problem the foreign-keys-off runner solves: the
// same rebuild succeeds but DROP TABLE cascades into, and empties, the
// child tables.
func TestPlainMigrationRebuildDeletesCascadeChildren(t *testing.T) {
	ctx := context.Background()
	db := openRebuildTestDB(t)

	if err := runMigration(ctx, db, 7, parentsRebuild.statements(), false); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM parents"); got != 3 {
		t.Fatalf("parents rows = %d, want 3", got)
	}
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM parent_notes"); got != 0 {
		t.Fatalf("parent_notes rows = %d, want the cascade to have deleted all of them", got)
	}
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM parent_tags"); got != 0 {
		t.Fatalf("parent_tags rows = %d, want the cascade to have deleted all of them", got)
	}
}

func TestForeignKeysOffMigrationRollsBackNewViolation(t *testing.T) {
	ctx := context.Background()
	db := openRebuildTestDB(t)
	before := rebuildFixtureRows(t, db)

	// With enforcement off, deleting p2 during the rebuild orphans its note
	// and its tag instead of cascading.
	statements := append(parentsRebuild.statements(), "DELETE FROM parents WHERE id='p2'")
	err := runMigration(ctx, db, 7, statements, true)
	want := "schema migration 7 rolled back: it would add 2 foreign key violation(s): parent_notes row 3 references a missing parents row; parent_tags row 2 references a missing parents row"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}

	assertParentsUnchanged(t, db, before)
	if got := rebuildTestForeignKeyCheck(t, db); len(got) != 0 {
		t.Fatalf("foreign_key_check after rollback = %v", got)
	}
	assertPoolEnforcesForeignKeys(t, db, 1)
}

func TestForeignKeysOffMigrationToleratesExistingViolations(t *testing.T) {
	ctx := context.Background()
	db := openRebuildTestDB(t)
	// Old databases and recovery fixtures can already hold orphans.
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"PRAGMA foreign_keys=OFF",
		"INSERT INTO parent_notes(id, parent_id, note) VALUES (9, 'ghost', 'orphan')",
		"INSERT INTO parent_tags(parent_id, tag) VALUES ('ghost', 'stale')",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	existing := rebuildTestForeignKeyCheck(t, db)
	if want := []string{"parent_notes/9/parents", "parent_tags/5/parents"}; !slices.Equal(existing, want) {
		t.Fatalf("seeded violations = %v, want %v", existing, want)
	}
	before := rebuildFixtureRows(t, db)

	if err := runMigration(ctx, db, 7, parentsRebuild.statements(), true); err != nil {
		t.Fatalf("rebuild with existing violations: %v", err)
	}
	if got := rebuildFixtureRows(t, db); !slices.Equal(got, before) {
		t.Fatalf("rows changed:\n got %v\nwant %v", got, before)
	}
	if got := rebuildTestForeignKeyCheck(t, db); !slices.Equal(got, existing) {
		t.Fatalf("violations after rebuild = %v, want the existing %v", got, existing)
	}
	if got := rebuildTestUserVersion(t, db); got != 7 {
		t.Fatalf("user_version = %d, want 7", got)
	}

	// The old orphans do not hide a new one.
	err = runMigration(ctx, db, 8, []string{"DELETE FROM parents WHERE id='p3'"}, true)
	if err == nil || !strings.Contains(err.Error(), "it would add 2 foreign key violation(s): parent_tags row 3 references a missing parents row; parent_tags row 4") {
		t.Fatalf("new violation error = %v", err)
	}
	if got := rebuildTestUserVersion(t, db); got != 7 {
		t.Fatalf("user_version after refused migration = %d, want 7", got)
	}
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM parents WHERE id='p3'"); got != 1 {
		t.Fatal("refused migration deleted p3")
	}
	assertPoolEnforcesForeignKeys(t, db, 1)
}

func TestForeignKeysOffMigrationRollsBackFailedStatement(t *testing.T) {
	ctx := context.Background()
	db := openRebuildTestDB(t)
	before := rebuildFixtureRows(t, db)

	statements := append(parentsRebuild.statements(), "INSERT INTO missing_table VALUES (1)")
	err := runMigration(ctx, db, 7, statements, true)
	if err == nil || !strings.Contains(err.Error(), "schema migration 7: ") || !strings.Contains(err.Error(), "missing_table") {
		t.Fatalf("error = %v, want the failing statement", err)
	}
	assertParentsUnchanged(t, db, before)
	assertPoolEnforcesForeignKeys(t, db, 1)
}

// The runner must not start when it cannot confirm that enforcement is off.
// A pooled connection left inside a transaction ignores the PRAGMA.
func TestForeignKeysOffMigrationRefusesWhenForeignKeysStayOn(t *testing.T) {
	ctx := context.Background()
	db := openRebuildTestDB(t)
	before := rebuildFixtureRows(t, db)
	if _, err := db.Exec("BEGIN"); err != nil {
		t.Fatal(err)
	}

	err := runMigration(ctx, db, 7, parentsRebuild.statements(), true)
	want := "schema migration 7: turn off foreign keys: PRAGMA foreign_keys is 1 after setting it to 0"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if _, err := db.Exec("ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	assertParentsUnchanged(t, db, before)
	if got := rebuildTestCount(t, db, "SELECT COUNT(*) FROM parent_notes"); got != 3 {
		t.Fatalf("parent_notes rows = %d, want 3", got)
	}
	assertPoolEnforcesForeignKeys(t, db, 1)
}

func TestForeignKeysOffMigrationHandlesCancellation(t *testing.T) {
	if err := registerCancelMigrationFunction(); err != nil {
		t.Fatal(err)
	}
	rebuild := parentsRebuild.statements()
	dropIndex := slices.Index(rebuild, "DROP TABLE parents")
	if dropIndex < 0 {
		t.Fatalf("rebuild has no DROP TABLE parents: %v", rebuild)
	}
	for _, test := range []struct {
		name        string
		statements  []string
		cancelFirst bool
		wantError   string
	}{
		{
			name:        "before the run",
			statements:  rebuild,
			cancelFirst: true,
			wantError:   "schema migration 7: pin connection: context canceled",
		},
		{
			// Cancelled after the old table is gone: the rollback must restore it.
			name:       "after dropping the parent",
			statements: slices.Insert(slices.Clone(rebuild), dropIndex+1, "SELECT edgewatch_test_cancel_migration()"),
			wantError:  "schema migration 7: context canceled",
		},
		{
			name:       "after the last statement",
			statements: append(slices.Clone(rebuild), "SELECT edgewatch_test_cancel_migration()"),
			wantError:  "schema migration 7: check foreign keys after the rebuild: context canceled",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := openRebuildTestDB(t)
			before := rebuildFixtureRows(t, db)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancelFirst {
				cancel()
			}
			cancelMigrationForTest.Store(&cancel)
			defer cancelMigrationForTest.Store(nil)

			err := runMigration(ctx, db, 7, test.statements, true)
			if !errors.Is(err, context.Canceled) || err.Error() != test.wantError {
				t.Fatalf("error = %v, want %q wrapping context.Canceled", err, test.wantError)
			}
			assertParentsUnchanged(t, db, before)
			assertPoolEnforcesForeignKeys(t, db, 1)
		})
	}
}

// A connection whose enforcement cannot be confirmed must never return to
// the pool. Here it is inside a transaction, where SQLite ignores the PRAGMA.
func TestReleaseForeignKeysOffConnClosesConnectionItCannotRestore(t *testing.T) {
	ctx := context.Background()
	db := openRebuildTestDB(t)
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{"PRAGMA foreign_keys=OFF", "BEGIN"} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	err = releaseForeignKeysOffConn(ctx, conn, 51)
	want := "schema migration 51: turn foreign keys back on: PRAGMA foreign_keys is 0 after setting it to 1; the connection was closed"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if err := conn.PingContext(ctx); !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("released connection ping = %v, want sql.ErrConnDone", err)
	}
	assertPoolEnforcesForeignKeys(t, db, 0)
}

func TestIntroducedForeignKeyViolationsCountsRepeatedRows(t *testing.T) {
	row := func(table string, rowID int64, parent string) foreignKeyViolation {
		return foreignKeyViolation{table: table, rowID: sql.NullInt64{Int64: rowID, Valid: true}, parent: parent}
	}
	withoutRowID := foreignKeyViolation{table: "links", parent: "jobs"}
	before := map[foreignKeyViolation]int{row("tokens", 4, "users"): 1, withoutRowID: 1, row("gone", 1, "users"): 1}
	after := map[foreignKeyViolation]int{row("tokens", 4, "users"): 2, withoutRowID: 3, row("invites", 9, "users"): 1}

	got := introducedForeignKeyViolations(before, after)
	want := []foreignKeyViolation{row("invites", 9, "users"), withoutRowID, withoutRowID, row("tokens", 4, "users")}
	if !slices.Equal(got, want) {
		t.Fatalf("introduced = %v, want %v", got, want)
	}
	if got := introducedForeignKeyViolations(after, after); len(got) != 0 {
		t.Fatalf("unchanged violations reported as new: %v", got)
	}
}

func TestDescribeForeignKeyViolationsBoundsExamples(t *testing.T) {
	violations := []foreignKeyViolation{{table: "links", parent: "jobs"}}
	for rowID := range int64(6) {
		violations = append(violations, foreignKeyViolation{table: "tokens", rowID: sql.NullInt64{Int64: rowID + 1, Valid: true}, parent: "users"})
	}
	got := describeForeignKeyViolations(violations)
	want := "links row references a missing jobs row; tokens row 1 references a missing users row; tokens row 2 references a missing users row; tokens row 3 references a missing users row; tokens row 4 references a missing users row; and 2 more"
	if got != want {
		t.Fatalf("description = %q, want %q", got, want)
	}
}

func TestSQLiteTableRebuildStatements(t *testing.T) {
	got := parentsRebuild.statements()
	want := []string{
		"DROP VIEW parent_names",
		"CREATE TABLE parents_next (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1)",
		"INSERT INTO parents_next(rowid, id, name) SELECT rowid, id, name FROM parents",
		"DROP TABLE parents",
		"ALTER TABLE parents_next RENAME TO parents",
		"CREATE INDEX parents_name_id ON parents(name, id)",
		"CREATE VIEW parent_names AS SELECT id, name FROM parents",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("statements:\n got %q\nwant %q", got, want)
	}

	owned := sqliteTableRebuild{
		table:      "parents",
		definition: "id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, kind TEXT",
		columns:    []string{"id", "name"},
		fill:       []sqliteRebuildFill{{column: "owner", expression: "'default'"}, {column: "kind", expression: "CASE WHEN name='alpha' THEN NULL ELSE 'custom' END"}},
	}
	if got, want := owned.statements()[1], "INSERT INTO parents_next(rowid, id, name, owner, kind) SELECT rowid, id, name, 'default', CASE WHEN name='alpha' THEN NULL ELSE 'custom' END FROM parents"; got != want {
		t.Fatalf("fill copy = %q, want %q", got, want)
	}

	for _, test := range []struct {
		name    string
		rebuild sqliteTableRebuild
		want    string
	}{
		{"table name", sqliteTableRebuild{table: "users; DROP TABLE jobs", definition: "id TEXT", columns: []string{"id"}}, `invalid table name "users; DROP TABLE jobs"`},
		{"empty definition", sqliteTableRebuild{table: "users", definition: " ", columns: []string{"id"}}, "empty definition"},
		{"no columns", sqliteTableRebuild{table: "users", definition: "id TEXT"}, "no columns to copy"},
		{"rowid column", sqliteTableRebuild{table: "users", definition: "id TEXT", columns: []string{"id", "ROWID"}}, `invalid column name "ROWID"`},
		{"column name", sqliteTableRebuild{table: "users", definition: "id TEXT", columns: []string{"id, secret"}}, `invalid column name "id, secret"`},
		{"fill column name", sqliteTableRebuild{table: "users", definition: "id TEXT", columns: []string{"id"}, fill: []sqliteRebuildFill{{column: "tenant; DROP TABLE jobs", expression: "'x'"}}}, `invalid fill column "tenant; DROP TABLE jobs"`},
		{"fill of a copied column", sqliteTableRebuild{table: "users", definition: "id TEXT", columns: []string{"id"}, fill: []sqliteRebuildFill{{column: "ID", expression: "'x'"}}}, `invalid fill column "ID"`},
		{"fill of rowid", sqliteTableRebuild{table: "users", definition: "id TEXT", columns: []string{"id"}, fill: []sqliteRebuildFill{{column: "rowid", expression: "1"}}}, `invalid fill column "rowid"`},
		{"empty fill expression", sqliteTableRebuild{table: "users", definition: "id TEXT", columns: []string{"id"}, fill: []sqliteRebuildFill{{column: "tenant_id", expression: " "}}}, "empty fill expression for tenant_id"},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				recovered := recover()
				if message, _ := recovered.(string); !strings.Contains(message, test.want) {
					t.Fatalf("panic = %v, want %q", recovered, test.want)
				}
			}()
			test.rebuild.statements()
		})
	}
}
