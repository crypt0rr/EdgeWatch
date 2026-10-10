package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// upgradeFloorRefusal is the refusal of a database at schema version.
func upgradeFloorRefusal(version int) string {
	return fmt.Sprintf("database schema version %d is older than schema 54, the oldest that this release upgrades; upgrade through v0.35.0 first", version)
}

// writeBelowFloorDatabase writes a copy of the migrated template whose schema
// marker is version, below the upgrade floor, with the startup state that an
// earlier release left: ready, with that release's owner and heartbeat.
func writeBelowFloorDatabase(t *testing.T, version int) string {
	t.Helper()
	path := freshTestDatabasePath(t)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(fmt.Sprintf(`UPDATE startup_state SET state='ready',owner='migration/1',phase='',started_at='2026-01-02T03:04:05Z',updated_at='2026-01-02T03:04:06Z' WHERE id=1; PRAGMA user_version=%d`, version)); err != nil {
		t.Fatal(err)
	}
	return path
}

// belowFloorState is what a refused open must leave unchanged: the schema
// marker, the startup state and the schema objects.
func belowFloorState(t *testing.T, path string) string {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var out strings.Builder
	fmt.Fprintf(&out, "user_version=%d\n", countRows(t, raw, `PRAGMA user_version`))
	for _, query := range []string{`SELECT * FROM startup_state`, `SELECT type,name FROM sqlite_master ORDER BY type,name`} {
		if err := snapshotRows(raw, query, &out); err != nil {
			t.Fatal(err)
		}
	}
	return out.String()
}

// A database older than schema 54, the schema of v0.20.0, is refused before
// anything writes: the daemon's open leaves the schema marker and the
// startup state as they are, and every other open names the release to
// upgrade through.
func TestOpenRefusesASchemaBelowTheUpgradeFloor(t *testing.T) {
	t.Parallel()
	for _, version := range []int{1, minimumUpgradeSchema - 1} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			t.Parallel()
			path := writeBelowFloorDatabase(t, version)
			before := belowFloorState(t, path)
			want := upgradeFloorRefusal(version)

			s, err := Open(path)
			if err == nil {
				s.Close()
				t.Fatal("a schema below the upgrade floor was migrated")
			}
			if !errors.Is(err, ErrSchemaBelowUpgradeFloor) || err.Error() != want {
				t.Fatalf("Open error = %v, want %q", err, want)
			}
			if after := belowFloorState(t, path); after != before {
				t.Fatalf("the refused open changed the database:\nbefore:\n%s\nafter:\n%s", before, after)
			}

			// The host commands get the same refusal, not the advice to let
			// the daemon upgrade the database.
			for name, open := range map[string]func(string) (*Store, error){
				"OpenExistingUpgraded":         OpenExistingUpgraded,
				"OpenReadOnlyExistingUpgraded": OpenReadOnlyExistingUpgraded,
			} {
				s, err := open(path)
				if err == nil {
					s.Close()
					t.Fatalf("%s opened a schema below the upgrade floor", name)
				}
				if !errors.Is(err, ErrSchemaBelowUpgradeFloor) || errors.Is(err, ErrSchemaUpgradePending) || err.Error() != want {
					t.Fatalf("%s error = %v, want %q", name, err, want)
				}
			}

			// edgewatch health reports the refusal instead of the startup
			// state of the earlier release, and verify reports it too.
			reader, err := OpenReadOnlyExisting(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if _, err := reader.System().HealthStatus(context.Background()); !errors.Is(err, ErrSchemaBelowUpgradeFloor) || err.Error() != want {
				t.Fatalf("HealthStatus error = %v, want %q", err, want)
			}
			verification, err := reader.Verify(context.Background())
			var verificationErr *VerificationError
			if !errors.As(err, &verificationErr) || !errors.Is(err, ErrSchemaBelowUpgradeFloor) || err.Error() != want || verification.SchemaSupported {
				t.Fatalf("Verify = %+v, %v; want %q", verification, err, want)
			}
			if after := belowFloorState(t, path); after != before {
				t.Fatalf("the refused opens changed the database:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

// A database without a schema marker but with tables, such as one of the
// releases before the web console, is refused too, and the refusal creates
// no table, not even startup_state.
func TestOpenRefusesTablesWithoutASchemaMarker(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE scans (id TEXT PRIMARY KEY, job TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL, status TEXT NOT NULL, config_hash TEXT NOT NULL, snapshot_json BLOB NOT NULL);
CREATE TABLE job_states (job TEXT PRIMARY KEY, state_json BLOB NOT NULL, updated_at TEXT NOT NULL)`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err == nil {
		s.Close()
		t.Fatal("a database with tables and no schema marker was migrated")
	}
	if want := upgradeFloorRefusal(0); !errors.Is(err, ErrSchemaBelowUpgradeFloor) || err.Error() != want {
		t.Fatalf("Open error = %v, want %q", err, want)
	}
	reader, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if tables := templateTestTables(t, reader.DB); !slices.Equal(tables, []string{"job_states", "scans"}) {
		t.Fatalf("tables after the refused open = %v", tables)
	}
}

// The first start of a new database creates startup_state before the
// baseline. When that start stops before the baseline commits, the next one
// still creates the database.
func TestOpenCreatesADatabaseThatHoldsOnlyStartupState(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(startupStateSchema); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if version := countRows(t, s.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("user_version = %d, want %d", version, schemaVersion)
	}
}

// A backup older than the upgrade floor is refused with the same message,
// and the destination is left unchanged.
func TestRestoreRefusesABackupBelowTheUpgradeFloor(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	destination := filepath.Join(dir, "destination.db")
	createRestoreFixture(t, destination, "destination")
	before, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	source := writeBelowFloorDatabase(t, minimumUpgradeSchema-1)
	want := upgradeFloorRefusal(minimumUpgradeSchema - 1)
	for name, restore := range map[string]func() error{
		"restore": func() error {
			_, err := Restore(context.Background(), source, destination, RestoreOptions{})
			return err
		},
		"dry run": func() error {
			_, err := DryRunRestore(context.Background(), source, destination, RestoreOptions{})
			return err
		},
	} {
		if err := restore(); !errors.Is(err, ErrSchemaBelowUpgradeFloor) || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s error = %v, want %q", name, err, want)
		}
	}
	after, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("the refused restore changed the destination")
	}
	// Schema 54 itself is still restored.
	if _, err := setRestoreFixtureVersion(t, source, minimumUpgradeSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), source, destination, RestoreOptions{}); err != nil {
		t.Fatalf("restore of a schema 54 backup: %v", err)
	}
}

// setRestoreFixtureVersion sets the schema marker of the closed database at
// path and returns the previous one.
func setRestoreFixtureVersion(t *testing.T, path string, version int) (int, error) {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		return 0, err
	}
	defer raw.Close()
	previous := countRows(t, raw, `PRAGMA user_version`)
	_, err = raw.Exec(fmt.Sprintf(`PRAGMA user_version=%d`, version))
	return previous, err
}
