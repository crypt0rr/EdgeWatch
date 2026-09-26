package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

// A fresh database runs every migration, table rebuild and startup phase,
// which takes seconds under the race detector. openTestStore migrates one
// template database per test binary and gives each test its own copy of it.
// TestMigratedTemplateMatchesFreshMigration keeps the copy identical to a
// real migration.
var (
	migratedTemplateOnce  sync.Once
	migratedTemplateBytes []byte
	migratedTemplateErr   error
)

// migratedTemplate returns the contents of a database that Open has fully
// migrated. The database is built in a private directory that is removed
// before this returns, so no key file written beside it can reach a copy.
func migratedTemplate() ([]byte, error) {
	migratedTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "edgewatch-store-template-*")
		if err != nil {
			migratedTemplateErr = err
			return
		}
		defer os.RemoveAll(dir)
		migratedTemplateBytes, migratedTemplateErr = buildMigratedTemplate(filepath.Join(dir, "edgewatch.db"))
	})
	return migratedTemplateBytes, migratedTemplateErr
}

func buildMigratedTemplate(path string) ([]byte, error) {
	s, err := Open(path)
	if err != nil {
		return nil, fmt.Errorf("migrate template database: %w", err)
	}
	// Move every committed page into the main file, so the file alone is the
	// complete database.
	_, checkpointErr := s.DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	if err := errors.Join(checkpointErr, s.Close()); err != nil {
		return nil, fmt.Errorf("close template database: %w", err)
	}
	return os.ReadFile(path)
}

// freshTestDatabasePath writes a copy of the migrated template to a new
// temporary directory and returns its path.
func freshTestDatabasePath(t testing.TB) string {
	t.Helper()
	raw, err := migratedTemplate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMigratedTemplateMatchesFreshMigration(t *testing.T) {
	fresh, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	copied := openTestStore(t)

	// Keys are created lazily beside the database, so every copy starts
	// without them and gets its own.
	for _, name := range []string{"auth.key", "notification.key"} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(copied.FilePath()), name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("copy of the template has %s beside it: %v", name, err)
		}
	}

	for _, pragma := range []string{"user_version", "auto_vacuum", "journal_mode", "page_size", "foreign_keys"} {
		want := templateTestPragma(t, fresh.DB, pragma)
		if got := templateTestPragma(t, copied.DB, pragma); got != want {
			t.Errorf("PRAGMA %s = %q, fresh migration has %q", pragma, got, want)
		}
	}
	if got := templateTestPragma(t, copied.DB, "user_version"); got != fmt.Sprint(schemaVersion) {
		t.Fatalf("template user_version = %s, want %d", got, schemaVersion)
	}

	wantSchema := templateTestSchema(t, fresh.DB)
	if gotSchema := templateTestSchema(t, copied.DB); !slices.Equal(gotSchema, wantSchema) {
		t.Fatalf("template schema differs from a fresh migration:\ncopy:  %q\nfresh: %q", gotSchema, wantSchema)
	}

	// Every table must hold the same rows, such as the default tenant, the
	// built-in scanner profiles, the startup state and the backfill markers.
	// Timestamps record when the migration ran, so they are masked.
	for _, table := range templateTestTables(t, fresh.DB) {
		want := templateTestRows(t, fresh.DB, table)
		if got := templateTestRows(t, copied.DB, table); !slices.Equal(got, want) {
			t.Errorf("table %s differs from a fresh migration:\ncopy:  %q\nfresh: %q", table, got, want)
		}
	}
	for _, table := range []string{"tenants", "scanner_profiles", "startup_state"} {
		if len(templateTestRows(t, copied.DB, table)) == 0 {
			t.Errorf("template has no rows in %s", table)
		}
	}

	// Each copy is a separate database.
	other := openTestStore(t)
	if other.FilePath() == copied.FilePath() {
		t.Fatalf("two copies share %s", copied.FilePath())
	}
	if _, err := copied.DB.Exec(`CREATE TABLE template_copy_probe (id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(templateTestTables(t, other.DB), "template_copy_probe") {
		t.Fatal("a write to one copy reached another copy")
	}
}

func TestBuildMigratedTemplateReportsOpenFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildMigratedTemplate(filepath.Join(blocker, "edgewatch.db")); err == nil || !strings.Contains(err.Error(), "migrate template database") {
		t.Fatalf("buildMigratedTemplate() error = %v", err)
	}
}

func templateTestPragma(t *testing.T, db *sql.DB, pragma string) string {
	t.Helper()
	var value string
	if err := db.QueryRowContext(context.Background(), "PRAGMA "+pragma).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

var templateTestWhitespace = regexp.MustCompile(`\s+`)

func templateTestSchema(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_master ORDER BY type,name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var schema []string
	for rows.Next() {
		var kind, name, table, statement string
		if err := rows.Scan(&kind, &name, &table, &statement); err != nil {
			t.Fatal(err)
		}
		schema = append(schema, strings.Join([]string{kind, name, table, templateTestWhitespace.ReplaceAllString(strings.TrimSpace(statement), " ")}, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return schema
}

func templateTestTables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return tables
}

var templateTestTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?`)

// templateTestRows returns the rows of table in a stable order, with every
// timestamp replaced by a placeholder.
func templateTestRows(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT * FROM "`+strings.ReplaceAll(table, `"`, `""`)+`"`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var result []string
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
			if raw, ok := value.([]byte); ok {
				value = string(raw)
			}
			fields[i] = columns[i] + "=" + templateTestTimestamp.ReplaceAllString(fmt.Sprint(value), "<time>")
		}
		result = append(result, strings.Join(fields, ","))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(result)
	return result
}
