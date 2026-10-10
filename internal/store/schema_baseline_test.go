package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"modernc.org/sqlite"
)

// schemaBaselineGolden holds what the retired migrations from schema 1 to
// schema 54, as v0.35.0 has them, left in a new database, in the form of
// baselineSchemaDump. It was written from those migrations before they were
// removed, and must never be regenerated from the baseline.
const schemaBaselineGolden = "testdata/schema54-migration-chain.golden"

// openNewSchemaTestDB opens an empty database file as a migrating open
// prepares one: with incremental auto-vacuum, WAL, the production
// connector's foreign keys, and the startup_state table that the migration
// creates before its first step.
func openNewSchemaTestDB(t *testing.T) *sql.DB {
	t.Helper()
	connector, err := sqlite.NewConnector(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(sqlitePragmaConnector{Connector: connector})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{"PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL"} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := ensureStartupStateContext(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

var baselineTestDigit = regexp.MustCompile(`\d`)

// baselineSchemaDump describes a database for the comparison with the
// migration chain: the pragmas, every sqlite_master entry with its SQL text
// in SQLite's form, whitespace aside, and every row of every table. The
// digits of each timestamp are masked, and its format is kept, so a row
// written in another timestamp format differs.
func baselineSchemaDump(t *testing.T, db *sql.DB) []string {
	t.Helper()
	var dump []string
	for _, pragma := range []string{"user_version", "auto_vacuum", "journal_mode", "foreign_keys"} {
		dump = append(dump, fmt.Sprintf("pragma %s=%s", pragma, templateTestPragma(t, db, pragma)))
	}
	for _, entry := range templateTestSchema(t, db) {
		dump = append(dump, "schema "+entry)
	}
	for _, table := range templateTestTables(t, db) {
		dump = append(dump, baselineTableDump(t, db, table)...)
	}
	return dump
}

// baselineTableDump returns the rows of table for baselineSchemaDump, sorted.
func baselineTableDump(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT * FROM "` + table + `"`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var tableRows []string
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		fields := make([]string, len(values))
		for i, value := range values {
			kind := fmt.Sprintf("%T", value)
			if raw, ok := value.([]byte); ok {
				value = string(raw)
			}
			masked := templateTestTimestamp.ReplaceAllStringFunc(fmt.Sprintf("%s:%v", kind, value), func(timestamp string) string {
				return baselineTestDigit.ReplaceAllString(timestamp, "0")
			})
			fields[i] = columns[i] + "=" + masked
		}
		tableRows = append(tableRows, "row "+table+" "+strings.Join(fields, ","))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(tableRows)
	return tableRows
}

// readSchemaBaselineGolden returns the lines of the golden file, without its
// comments.
func readSchemaBaselineGolden(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(schemaBaselineGolden)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

// The frozen baseline creates exactly what the retired migrations left in a
// new database at schema 54: the same tables, columns, indexes and
// triggers, with the same SQL text, and the same rows.
func TestBaselineSchemaMatchesMigrationChain(t *testing.T) {
	t.Parallel()
	db := openNewSchemaTestDB(t)
	if err := applyBaselineSchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	got := baselineSchemaDump(t, db)
	want := readSchemaBaselineGolden(t)
	if slices.Equal(got, want) {
		return
	}
	for _, line := range want {
		if !slices.Contains(got, line) {
			t.Errorf("baseline lacks %s", line)
		}
	}
	for _, line := range got {
		if !slices.Contains(want, line) {
			t.Errorf("baseline adds %s", line)
		}
	}
	t.Fatal("the baseline differs from the migration chain")
}

// The baseline is a step from schema 0 and runs only there.
func TestBaselineSchemaRefusesASchemaMarker(t *testing.T) {
	t.Parallel()
	db := openNewSchemaTestDB(t)
	if _, err := db.Exec(`PRAGMA user_version = 54`); err != nil {
		t.Fatal(err)
	}
	err := applyBaselineSchema(context.Background(), db)
	want := "baseline schema 54: the database is at schema 54, not 0; another process is migrating it"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if tables := templateTestTables(t, db); !slices.Equal(tables, []string{"startup_state"}) {
		t.Fatalf("tables after the refused baseline = %v", tables)
	}
}
