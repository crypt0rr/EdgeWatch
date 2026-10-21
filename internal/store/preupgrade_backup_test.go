package store

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestPreMigrationBackupIsVerifiedBeforeUpgrade(t *testing.T) {
	requireLinuxDaemonStartup(t)
	path := newSchema75TestDatabase(t, false)
	backupDirectory := t.TempDir()

	opened, err := OpenDaemonWithLoggerContextAndBackupDirectory(context.Background(), path, nil, backupDirectory)
	if err != nil {
		t.Fatalf("open schema 75 database with configured pre-migration backups: %v", err)
	}
	if got := countRows(t, opened.DB, `PRAGMA user_version`); got != schemaVersion {
		t.Fatalf("schema after migration = %d, want %d", got, schemaVersion)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(backupDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !preUpgradeBackupName.MatchString(entries[0].Name()) {
		t.Fatalf("pre-migration backups = %v, want exactly one automatic backup", entries)
	}
	backupPath := filepath.Join(backupDirectory, entries[0].Name())
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("automatic backup mode = %04o, want 0600", got)
	}
	report, err := VerifyBackupFile(context.Background(), backupPath, BackupFileOptions{LiveDatabase: path})
	if err != nil {
		t.Fatalf("verify automatic pre-migration backup: %v (%+v)", err, report)
	}
	if !report.Valid || report.SchemaVersion != 75 || !report.EdgeWatchSchema {
		t.Fatalf("pre-migration backup verification = %+v, want a valid schema 75 backup", report)
	}
}

func TestPreMigrationBackupFailurePreventsMigrationWrites(t *testing.T) {
	requireLinuxDaemonStartup(t)
	for _, test := range []struct {
		name              string
		invalidForeignKey bool
		missingDirectory  bool
		wantError         string
	}{
		{name: "backup creation", missingDirectory: true, wantError: "create and verify automatic pre-migration backup"},
		{name: "backup verification", invalidForeignKey: true, wantError: "verify SQLite backup"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := newSchema75TestDatabase(t, test.invalidForeignKey)
			before := readPreMigrationState(t, path)
			backupDirectory := t.TempDir()
			if test.missingDirectory {
				backupDirectory = filepath.Join(backupDirectory, "missing")
			}

			opened, err := OpenDaemonWithLoggerContextAndBackupDirectory(context.Background(), path, nil, backupDirectory)
			if err == nil {
				if opened != nil {
					_ = opened.Close()
				}
				t.Fatal("daemon open succeeded despite the configured pre-migration backup failure")
			}
			if !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("daemon open error = %v, want it to include %q", err, test.wantError)
			}

			after := readPreMigrationState(t, path)
			if after.version != 75 {
				t.Errorf("schema after failed backup = %d, want 75", after.version)
			}
			if after.perimeterTable {
				t.Error("schema 76 perimeter table was created after the backup failed")
			}
			if !reflect.DeepEqual(after.schemaObjects, before.schemaObjects) {
				t.Error("schema objects changed after the backup failed")
			}
			if after.startup != before.startup {
				t.Errorf("startup state after failed backup = %+v, want unchanged %+v", after.startup, before.startup)
			}
			entries, readErr := os.ReadDir(backupDirectory)
			if !test.missingDirectory && (readErr != nil || len(entries) != 0) {
				t.Errorf("failed automatic backup left files %v (read error %v)", entries, readErr)
			}
		})
	}
}

func TestPreMigrationWithoutBackupDirectoryWarnsAndContinues(t *testing.T) {
	requireLinuxDaemonStartup(t)
	path := newSchema75TestDatabase(t, false)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	opened, err := OpenDaemonWithLoggerContextAndBackupDirectory(context.Background(), path, logger, "")
	if err != nil {
		t.Fatalf("open schema 75 database without a backup directory: %v", err)
	}
	defer opened.Close()
	if got := countRows(t, opened.DB, `PRAGMA user_version`); got != schemaVersion {
		t.Fatalf("schema after migration = %d, want %d", got, schemaVersion)
	}
	if !strings.Contains(logs.String(), "no configured backup directory; continuing without an automatic pre-migration backup") {
		t.Fatalf("migration log = %q, want a clear no-backup warning", logs.String())
	}
}

func TestPreMigrationBackupsRetainExactlyLatestThreeAndPreserveManualFiles(t *testing.T) {
	requireLinuxDaemonStartup(t)
	path := newSchema75TestDatabase(t, false)
	backupDirectory := t.TempDir()
	old := make([]string, 0, 4)
	for year := 2020; year <= 2023; year++ {
		name := fmt.Sprintf("edgewatch-preupgrade-s74-s76-%d0101T000000.000000000Z.db", year)
		old = append(old, name)
		if err := os.WriteFile(filepath.Join(backupDirectory, name), []byte("automatic backup fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manual := "manual-backup.db"
	scheduled := "edgewatch-scheduled-20260101T000000Z.db"
	malformedAutomatic := "edgewatch-preupgrade-manual.db"
	for _, name := range []string{manual, scheduled, malformedAutomatic} {
		if err := os.WriteFile(filepath.Join(backupDirectory, name), []byte("operator-owned"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	opened, err := OpenDaemonWithLoggerContextAndBackupDirectory(context.Background(), path, nil, backupDirectory)
	if err != nil {
		t.Fatalf("open schema 75 database with existing automatic backups: %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(backupDirectory)
	if err != nil {
		t.Fatal(err)
	}
	var automatic []string
	for _, entry := range entries {
		if preUpgradeBackupName.MatchString(entry.Name()) {
			automatic = append(automatic, entry.Name())
		}
	}
	if len(automatic) != preUpgradeBackupRetention {
		t.Fatalf("automatic pre-migration backups = %v, want exactly %d", automatic, preUpgradeBackupRetention)
	}
	for _, want := range []string{old[2], old[3], automatic[len(automatic)-1]} {
		// ReadDir sorts by name; the new timestamp sorts after the seeded files.
		if _, err := os.Stat(filepath.Join(backupDirectory, want)); err != nil {
			t.Errorf("expected retained automatic backup %q: %v", want, err)
		}
	}
	for _, removed := range old[:2] {
		if _, err := os.Stat(filepath.Join(backupDirectory, removed)); !os.IsNotExist(err) {
			t.Errorf("older automatic backup %q remains: %v", removed, err)
		}
	}
	for _, name := range []string{manual, scheduled, malformedAutomatic} {
		if _, err := os.Stat(filepath.Join(backupDirectory, name)); err != nil {
			t.Errorf("operator-owned file %q was removed: %v", name, err)
		}
	}
}

func newSchema75TestDatabase(t *testing.T, invalidForeignKey bool) string {
	t.Helper()
	path := freshTestDatabasePath(t)
	opened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	reconstructSchema75(t, opened.DB)
	if _, err := opened.DB.Exec(`UPDATE startup_state SET state='ready',owner='pre-migration-sentinel',phase='pre-migration-sentinel',started_at='before-start',updated_at='before-update',progress=7,total=9,last_error='before-error' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if invalidForeignKey {
		for _, statement := range []string{
			`PRAGMA foreign_keys=OFF`,
			`CREATE TABLE preupgrade_backup_parent (id INTEGER PRIMARY KEY)`,
			`CREATE TABLE preupgrade_backup_child (parent_id INTEGER REFERENCES preupgrade_backup_parent(id))`,
			`INSERT INTO preupgrade_backup_child(parent_id) VALUES(404)`,
			`PRAGMA foreign_keys=ON`,
		} {
			if _, err := opened.DB.Exec(statement); err != nil {
				t.Fatalf("prepare verification-failure fixture with %s: %v", statement, err)
			}
		}
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

type preMigrationStartupState struct {
	state, owner, phase, startedAt, updatedAt, lastError string
	progress, total                                      int
}

type preMigrationState struct {
	version        int
	perimeterTable bool
	schemaObjects  []string
	startup        preMigrationStartupState
}

func readPreMigrationState(t *testing.T, path string) preMigrationState {
	t.Helper()
	db, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	state := preMigrationState{}
	if err := db.DB.QueryRow(`PRAGMA user_version`).Scan(&state.version); err != nil {
		t.Fatal(err)
	}
	var perimeterTable int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='perimeter_seeds'`).Scan(&perimeterTable); err != nil {
		t.Fatal(err)
	}
	state.perimeterTable = perimeterTable != 0
	rows, err := db.DB.Query(`SELECT type||'/'||name||'/'||COALESCE(sql,'') FROM sqlite_master WHERE type IN ('table','index','trigger','view') AND name NOT LIKE 'sqlite_%' ORDER BY type,name`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var object string
		if err := rows.Scan(&object); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		state.schemaObjects = append(state.schemaObjects, object)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT state,owner,phase,started_at,updated_at,progress,total,last_error FROM startup_state WHERE id=1`).Scan(&state.startup.state, &state.startup.owner, &state.startup.phase, &state.startup.startedAt, &state.startup.updatedAt, &state.startup.progress, &state.startup.total, &state.startup.lastError); err != nil {
		t.Fatal(err)
	}
	return state
}

func requireLinuxDaemonStartup(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("daemon startup migration guards are implemented on Linux")
	}
}
