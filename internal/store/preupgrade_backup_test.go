package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
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

func TestPrunePreUpgradeBackupsPreservesMalformedAndNonOwnerFiles(t *testing.T) {
	directory := t.TempDir()
	invalidTimestamp := "edgewatch-preupgrade-s74-s76-20261301T000000.000000000Z.db"
	nonOwnerOnly := "edgewatch-preupgrade-s74-s76-20250101T000000.000000000Z.db"
	invalidSchema := "edgewatch-preupgrade-s99999999999999999999-s76-20240101T000000.000000000Z.db"
	operatorFiles := []string{invalidTimestamp, nonOwnerOnly, invalidSchema}
	for _, name := range operatorFiles {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("operator backup"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(directory, nonOwnerOnly), 0o644); err != nil {
		t.Fatal(err)
	}

	removed, err := prunePreUpgradeBackups(directory, schemaVersion-1, schemaVersion, 0)
	if err != nil {
		t.Fatalf("prune automatic pre-migration backups: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("removed backups = %v, want malformed and non-owner files preserved", removed)
	}
	for _, name := range operatorFiles {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Errorf("operator backup %q was removed: %v", name, err)
		}
	}
}

// For each source schema below the database's current schema, retention
// keeps the newest copy to the running schema: the copies taken at the
// earlier schemas of the upgrade in progress. Every other copy, including
// those at the current schema and those for another target, falls under the
// count of three, which keeps the newest by timestamp.
func TestPrunePreUpgradeBackupsKeepEachEarlierSchemaCopyOfTheUpgrade(t *testing.T) {
	for _, test := range []struct {
		name            string
		current, target int
		files, kept     []string
	}{
		{
			name:    "retries at one intermediate schema",
			current: 77,
			target:  78,
			files: []string{
				"edgewatch-preupgrade-s74-s76-20210101T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s78-20220101T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s78-20220201T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220301T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220401T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220501T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220601T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s75-s78-20220201T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220401T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220501T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220601T000000.000000000Z.db",
			},
		},
		{
			// January's attempt to reach 78 was rolled back. February's
			// upgrade went through a release at schema 76, so March's upgrade
			// to 78 started at 76 and failed at 77, followed by three
			// retries. The March copy is what the previous release opens; the
			// lowest source schema would pick January's stale copy instead.
			name:    "an earlier attempt and a step upgrade",
			current: 77,
			target:  78,
			files: []string{
				"edgewatch-preupgrade-s75-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s76-20260201T000000.000000000Z.db",
				"edgewatch-preupgrade-s76-s78-20260301T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260401T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260402T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260403T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s75-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s76-s78-20260301T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260401T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260402T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260403T000000.000000000Z.db",
			},
		},
		{
			// The first start committed the step to 76 and failed, and the
			// restart at 76 committed the step to 77 and failed again.
			name:    "steps committed by two starts",
			current: 77,
			target:  78,
			files: []string{
				"edgewatch-preupgrade-s74-s76-20250101T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s76-s78-20260102T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260103T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260104T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260105T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260106T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s75-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s76-s78-20260102T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260104T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260105T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260106T000000.000000000Z.db",
			},
		},
		{
			// After a rollback, a new attempt starts at the schema the
			// previous release used. Its new copy supersedes the old one.
			name:    "a new attempt from the previous release's schema",
			current: 75,
			target:  78,
			files: []string{
				"edgewatch-preupgrade-s75-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260102T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260103T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260104T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s78-20260110T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s75-s78-20260110T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260103T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260104T000000.000000000Z.db",
			},
		},
		{
			// Copies from a schema above the current one are not protected.
			name:    "a restart from a copy at an intermediate schema",
			current: 76,
			target:  78,
			files: []string{
				"edgewatch-preupgrade-s75-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s76-s78-20260102T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260103T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260104T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260105T000000.000000000Z.db",
				"edgewatch-preupgrade-s76-s78-20260106T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s75-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s76-s78-20260106T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260104T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260105T000000.000000000Z.db",
			},
		},
		{
			name:    "no copy for the target",
			current: 78,
			target:  79,
			files: []string{
				"edgewatch-preupgrade-s74-s76-20210101T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s78-20220101T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220301T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220401T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220501T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s77-s78-20220301T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220401T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220501T000000.000000000Z.db",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			for _, name := range test.files {
				if err := os.WriteFile(filepath.Join(directory, name), []byte("automatic backup fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var wantRemoved []string
			for _, name := range test.files {
				if !slices.Contains(test.kept, name) {
					wantRemoved = append(wantRemoved, name)
				}
			}
			slices.Sort(wantRemoved)
			wantKept := slices.Sorted(slices.Values(test.kept))

			removed, err := prunePreUpgradeBackups(directory, test.current, test.target, preUpgradeBackupRetention)
			if err != nil {
				t.Fatalf("prune automatic pre-migration backups: %v", err)
			}
			slices.Sort(removed)
			if !reflect.DeepEqual(removed, wantRemoved) {
				t.Errorf("removed = %q, want %q", removed, wantRemoved)
			}
			if got := automaticPreUpgradeBackups(t, directory); !reflect.DeepEqual(got, wantKept) {
				t.Errorf("kept = %q, want %q", got, wantKept)
			}

			// Retention is stable: a second pass removes nothing more.
			removed, err = prunePreUpgradeBackups(directory, test.current, test.target, preUpgradeBackupRetention)
			if err != nil || len(removed) != 0 {
				t.Errorf("second prune removed %q (error %v), want nothing", removed, err)
			}
		})
	}
}

// Each schema step commits on its own, so an upgrade that fails at a later
// step leaves the database at an intermediate schema, and Compose restarts
// the daemon at once. Every restart writes a copy of the schema it finds,
// which the previous release refuses to open. Here the first start commits
// the step to 76 and fails, and the restart at 76 commits the step to 77 and
// fails again. No retry at 77 may evict the copy taken at 75, where the
// upgrade started, or the one taken at 76, and repeated retries do not grow
// the directory past the retention bound.
func TestPreMigrationBackupRetriesKeepTheStartingSchemaCopy(t *testing.T) {
	ctx := context.Background()
	path := newSchema75TestDatabase(t, false)
	backupDirectory := t.TempDir()
	s, err := OpenExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	migrations := schemaMigrationStatements()
	earlier := make([]string, 0, 2)
	for _, version := range []int{75, 76} {
		if err := preparePreMigrationBackup(ctx, s.DB, s.Path, version, backupDirectory, logger); err != nil {
			t.Fatalf("back up schema %d before the start migrates it: %v", version, err)
		}
		automatic := automaticPreUpgradeBackups(t, backupDirectory)
		prefix := fmt.Sprintf("edgewatch-preupgrade-s%d-s%d-", version, schemaVersion)
		index := slices.IndexFunc(automatic, func(name string) bool { return strings.HasPrefix(name, prefix) })
		if index < 0 || len(automatic) != len(earlier)+1 {
			t.Fatalf("automatic backups after the start at %d = %q, want the earlier copies %q and one schema %d copy", version, automatic, earlier, version)
		}
		earlier = append(earlier, automatic[index])
		// The start commits the next step and fails after it.
		next := version + 1
		if err := runMigration(ctx, s.DB, next, migrations[next], foreignKeysOffMigrations[next]); err != nil {
			t.Fatalf("commit schema %d: %v", next, err)
		}
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 77 {
		t.Fatalf("schema after the failed starts = %d, want 77", got)
	}

	retries := 2 * preUpgradeBackupRetention
	for retry := 1; retry <= retries; retry++ {
		if err := preparePreMigrationBackup(ctx, s.DB, s.Path, 77, backupDirectory, logger); err != nil {
			t.Fatalf("back up schema 77 on retry %d: %v", retry, err)
		}
		automatic := automaticPreUpgradeBackups(t, backupDirectory)
		for _, name := range earlier {
			if !slices.Contains(automatic, name) {
				t.Fatalf("retry %d removed the earlier-schema copy %q; automatic backups = %q", retry, name, automatic)
			}
		}
		if want := len(earlier) + min(retry, preUpgradeBackupRetention); len(automatic) != want {
			t.Fatalf("automatic backups after retry %d = %q, want %d", retry, automatic, want)
		}
	}
	entries, err := os.ReadDir(backupDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(earlier) + preUpgradeBackupRetention; len(entries) != want {
		t.Errorf("backup directory holds %d entries after %d retries, want only the %d automatic copies", len(entries), retries, want)
	}

	// Each start logs the backup step before it copies the database, and the
	// start and completion records name the same file by its full path.
	var started, written []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n")) {
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		switch record["msg"] {
		case "pre-migration backup started":
			started = append(started, record)
		case "verified pre-migration backup written":
			written = append(written, record)
		}
	}
	if starts := len(earlier) + retries; len(started) != starts || len(written) != starts {
		t.Fatalf("pre-migration backup logs = %d started and %d written, want one of each per start (%d)", len(started), len(written), starts)
	}
	for i, record := range started {
		from := 77.0
		if i < len(earlier) {
			from = float64(75 + i)
		}
		backup, _ := record["backup"].(string)
		if record["from_schema"] != from || record["to_schema"] != float64(schemaVersion) || filepath.Dir(backup) != backupDirectory || !preUpgradeBackupName.MatchString(filepath.Base(backup)) {
			t.Errorf("start log %d = %v, want the path of a schema %v to %d copy in %s", i, record, from, schemaVersion, backupDirectory)
		}
		if written[i]["backup"] != backup {
			t.Errorf("completion log %d names %v, want the started backup %q", i, written[i]["backup"], backup)
		}
	}

	for i, name := range earlier {
		report, err := VerifyBackupFile(ctx, filepath.Join(backupDirectory, name), BackupFileOptions{LiveDatabase: path})
		if err != nil {
			t.Fatalf("verify the earlier-schema copy %q: %v (%+v)", name, err, report)
		}
		if want := 75 + i; !report.Valid || report.SchemaVersion != want || !report.EdgeWatchSchema {
			t.Fatalf("earlier-schema copy verification = %+v, want a valid schema %d backup", report, want)
		}
	}
}

// The first start of an upgrade has no earlier schema to protect, so its new
// copy and copies for an earlier upgrade all fall under the count of three.
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

	automatic := automaticPreUpgradeBackups(t, backupDirectory)
	if len(automatic) != preUpgradeBackupRetention {
		t.Fatalf("automatic pre-migration backups = %v, want exactly %d", automatic, preUpgradeBackupRetention)
	}
	// The names sort by source schema first, so the new schema 75 copy sorts
	// after the seeded schema 74 copies.
	newest := automatic[len(automatic)-1]
	if !strings.HasPrefix(newest, fmt.Sprintf("edgewatch-preupgrade-s75-s%d-", schemaVersion)) {
		t.Fatalf("newest automatic backup = %q, want the schema 75 copy", newest)
	}
	if want := append(slices.Clone(old[2:]), newest); !reflect.DeepEqual(automatic, want) {
		t.Errorf("retained automatic backups = %q, want %q", automatic, want)
	}
	for _, name := range old[:2] {
		if _, err := os.Stat(filepath.Join(backupDirectory, name)); !os.IsNotExist(err) {
			t.Errorf("older automatic backup %q remains: %v", name, err)
		}
	}
	for _, name := range []string{manual, scheduled, malformedAutomatic} {
		if _, err := os.Stat(filepath.Join(backupDirectory, name)); err != nil {
			t.Errorf("operator-owned file %q was removed: %v", name, err)
		}
	}
}

// automaticPreUpgradeBackups lists the names in directory that have the
// reserved automatic-backup form, sorted by name.
func automaticPreUpgradeBackups(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var automatic []string
	for _, entry := range entries {
		if preUpgradeBackupName.MatchString(entry.Name()) {
			automatic = append(automatic, entry.Name())
		}
	}
	return automatic
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
	defer rows.Close()
	for rows.Next() {
		var object string
		if err := rows.Scan(&object); err != nil {
			t.Fatal(err)
		}
		state.schemaObjects = append(state.schemaObjects, object)
	}
	if err := rows.Err(); err != nil {
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
