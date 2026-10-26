package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
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
	invalidTarget := "edgewatch-preupgrade-s76-s99999999999999999999-20240101T000000.000000000Z.db"
	operatorFiles := []string{invalidTimestamp, nonOwnerOnly, invalidSchema, invalidTarget}
	for _, name := range operatorFiles {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("operator backup"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(directory, nonOwnerOnly), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink and a directory that carry the reserved name are not
	// automatic backups either.
	symlink := "edgewatch-preupgrade-s74-s76-20230101T000000.000000000Z.db"
	if err := os.Symlink(invalidTimestamp, filepath.Join(directory, symlink)); err != nil {
		t.Fatal(err)
	}
	subdirectory := "edgewatch-preupgrade-s74-s76-20220101T000000.000000000Z.db"
	if err := os.Mkdir(filepath.Join(directory, subdirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	operatorFiles = append(operatorFiles, symlink, subdirectory)

	removed, err := prunePreUpgradeBackups(context.Background(), directory, schemaVersion-1, 0, "")
	if err != nil {
		t.Fatalf("prune automatic pre-migration backups: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("removed backups = %v, want malformed and non-owner files preserved", removed)
	}
	for _, name := range operatorFiles {
		if _, err := os.Lstat(filepath.Join(directory, name)); err != nil {
			t.Errorf("operator backup %q was removed: %v", name, err)
		}
	}
}

func TestPrunePreUpgradeBackupsDoesNotLetCorruptCopyReplaceValidPairCopy(t *testing.T) {
	directory := t.TempDir()
	fixtures := make(map[int][]byte)
	valid := "edgewatch-preupgrade-s75-s78-20260401T000000.000000000Z.db"
	mismatched := "edgewatch-preupgrade-s75-s78-20260430T000000.000000000Z.db"
	corrupt := "edgewatch-preupgrade-s75-s78-20260501T000000.000000000Z.db"
	writeValidPreUpgradeBackup(t, directory, valid, fixtures)
	writePreUpgradeBackupAtSchema(t, directory, mismatched, 76, fixtures)
	if err := os.WriteFile(filepath.Join(directory, corrupt), []byte("not a SQLite database"), 0o600); err != nil {
		t.Fatal(err)
	}

	// These three newer completed-upgrade copies fill the regular retention
	// set, which would otherwise evict valid outside the newest three.
	for _, name := range []string{
		"edgewatch-preupgrade-s77-s78-20260402T000000.000000000Z.db",
		"edgewatch-preupgrade-s77-s78-20260403T000000.000000000Z.db",
		"edgewatch-preupgrade-s77-s78-20260404T000000.000000000Z.db",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("not a SQLite database"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := prunePreUpgradeBackups(context.Background(), directory, 77, preUpgradeBackupRetention, "")
	if err != nil {
		t.Fatalf("prune automatic pre-migration backups: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, valid)); err != nil {
		t.Fatalf("valid older backup for the unfinished upgrade was removed; removed %q: %v", removed, err)
	}
}

func TestPrunePreUpgradeBackupsAbortsWhenVerificationCannotStageCopy(t *testing.T) {
	directory := t.TempDir()
	fixtures := make(map[int][]byte)
	olderPairCopy := "edgewatch-preupgrade-s75-s78-20250101T000000.000000000Z.db"
	writeValidPreUpgradeBackup(t, directory, olderPairCopy, fixtures)
	newer := []string{
		"edgewatch-preupgrade-s77-s78-20260101T000000.000000000Z.db",
		"edgewatch-preupgrade-s77-s78-20260102T000000.000000000Z.db",
		"edgewatch-preupgrade-s77-s78-20260103T000000.000000000Z.db",
	}
	for _, name := range newer {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("completed upgrade"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// This valid pair copy is older than the newest three and would otherwise
	// be removed. Verification cannot decide whether it is valid when staging
	// is unavailable, so pruning must stop before removing any candidate.
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	removed, err := prunePreUpgradeBackups(context.Background(), directory, 77, preUpgradeBackupRetention, "")
	if err == nil || !strings.Contains(err.Error(), "create backup verification directory") {
		t.Fatalf("prune with unavailable verification staging = %v, want a staging failure", err)
	}
	if len(removed) != 0 {
		t.Fatalf("removed backups = %v, want no pruning after verification failed", removed)
	}
	for _, name := range append(newer, olderPairCopy) {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Errorf("backup %q was removed after verification failed: %v", name, err)
		}
	}
}

func TestPrunePreUpgradeBackupsAbortsWhenSchemaProbeFails(t *testing.T) {
	directory := t.TempDir()
	fixtures := make(map[int][]byte)
	olderPairCopy := "edgewatch-preupgrade-s75-s78-20250101T000000.000000000Z.db"
	writeValidPreUpgradeBackup(t, directory, olderPairCopy, fixtures)
	olderPath := filepath.Join(directory, olderPairCopy)
	validReport, err := VerifyBackupFile(context.Background(), olderPath, BackupFileOptions{})
	if err != nil || !validReport.Valid || validReport.SchemaVersion != 75 {
		t.Fatalf("verify older rollback copy before inducing the probe failure = %+v, %v", validReport, err)
	}
	newer := []string{
		"edgewatch-preupgrade-s77-s78-20260101T000000.000000000Z.db",
		"edgewatch-preupgrade-s77-s78-20260102T000000.000000000Z.db",
		"edgewatch-preupgrade-s77-s78-20260103T000000.000000000Z.db",
	}
	for _, name := range newer {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("completed upgrade"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	probeErr := errors.New("temporary SQLite schema-probe I/O failure")
	probe := func(context.Context, edgeWatchSchemaQueryer) (bool, error) {
		return false, probeErr
	}
	removed, err := prunePreUpgradeBackupsWithSchemaProbe(context.Background(), directory, 77, preUpgradeBackupRetention, "", probe)
	if !errors.Is(err, probeErr) {
		t.Fatalf("prune after schema-probe failure = %v, want the operational probe error", err)
	}
	if len(removed) != 0 {
		t.Fatalf("removed backups = %v, want no pruning after schema-probe failure", removed)
	}
	for _, name := range append(newer, olderPairCopy) {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Errorf("backup %q was removed after schema-probe failure: %v", name, err)
		}
	}
}

func writeValidPreUpgradeBackup(t *testing.T, directory, name string, fixtures map[int][]byte) {
	t.Helper()
	match := preUpgradeBackupName.FindStringSubmatch(name)
	if match == nil {
		t.Fatalf("pre-upgrade backup fixture name %q does not match the automatic backup format", name)
	}
	sourceSchema, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("parse fixture source schema from %q: %v", name, err)
	}
	writePreUpgradeBackupAtSchema(t, directory, name, sourceSchema, fixtures)
}

func writePreUpgradeBackupAtSchema(t *testing.T, directory, name string, sourceSchema int, fixtures map[int][]byte) {
	t.Helper()
	contents, ok := fixtures[sourceSchema]
	if !ok {
		s, _ := openFreshFileStore(t)
		if _, err := s.DB.ExecContext(context.Background(), fmt.Sprintf("PRAGMA user_version = %d", sourceSchema)); err != nil {
			t.Fatalf("set fixture source schema %d: %v", sourceSchema, err)
		}
		backupPath, err := s.Backup(context.Background(), filepath.Join(t.TempDir(), "fixture.db"))
		if err != nil {
			t.Fatalf("write verified pre-upgrade backup fixture at schema %d: %v", sourceSchema, err)
		}
		contents, err = os.ReadFile(backupPath)
		if err != nil {
			t.Fatalf("read verified pre-upgrade backup fixture at schema %d: %v", sourceSchema, err)
		}
		fixtures[sourceSchema] = contents
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write verified pre-upgrade backup fixture %q: %v", name, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("set verified pre-upgrade backup fixture mode %q: %v", name, err)
	}
}

// Retention keeps the copy just written and, for each source schema below the
// database's current schema, the newest copy to a schema above the current
// one: the copies of upgrades that have not yet passed the database's schema,
// whichever release wrote them. Every other copy, including earlier copies at
// the current schema and those of finished upgrades, falls under keep, which
// keeps the newest by timestamp.
func TestPrunePreUpgradeBackupsKeepEachUnfinishedUpgradeCopy(t *testing.T) {
	fixtures := make(map[int][]byte)
	for _, test := range []struct {
		name          string
		current, keep int
		// written, when set, names the copy that the start just wrote.
		written     string
		files, kept []string
	}{
		{
			name:    "retries at one intermediate schema",
			current: 77,
			keep:    preUpgradeBackupRetention,
			written: "edgewatch-preupgrade-s77-s78-20220601T000000.000000000Z.db",
			files: []string{
				"edgewatch-preupgrade-s73-s75-20210101T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s78-20220101T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s78-20220201T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220301T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220401T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220501T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220601T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s75-s78-20220201T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220301T000000.000000000Z.db",
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
			// Without a copy just written, the count of three takes the
			// retries, and the February copy of a finished upgrade goes.
			name:    "an earlier attempt and a step upgrade",
			current: 77,
			keep:    preUpgradeBackupRetention,
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
			keep:    preUpgradeBackupRetention,
			written: "edgewatch-preupgrade-s77-s78-20260106T000000.000000000Z.db",
			files: []string{
				"edgewatch-preupgrade-s73-s75-20250101T000000.000000000Z.db",
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
				"edgewatch-preupgrade-s77-s78-20260103T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260104T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260105T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260106T000000.000000000Z.db",
			},
		},
		{
			// Release 0.43.0, with schema 78, started at 76, committed the
			// step to 77, and failed on that start and two restarts. Release
			// 0.43.1, with schema 79, then took over the upgrade and failed
			// three times at 77. The copy at 76 is still the one the previous
			// release opens, although its target is not the running schema.
			name:    "a release with another target takes over the upgrade",
			current: 77,
			keep:    preUpgradeBackupRetention,
			written: "edgewatch-preupgrade-s77-s79-20260302T000200.000000000Z.db",
			files: []string{
				"edgewatch-preupgrade-s76-s78-20260301T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260301T000100.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260301T000200.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260302T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260302T000100.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260302T000200.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s76-s78-20260301T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260301T000200.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260302T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260302T000100.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260302T000200.000000000Z.db",
			},
		},
		{
			// After a rollback, a new attempt starts at the schema the
			// previous release used. Its new copy supersedes the old one.
			// v0.43.0 (target 78) started at 76, committed 77 and failed, and
			// three restarts followed. v0.43.1 (target 79) then took over at
			// 77, committed 78 and failed at 79, and this start retries it at
			// 78. The copy at 76 is the one the previous release opens: its
			// upgrade has passed 78, but it reaches beyond 77, the schema that
			// the kept copy of the takeover started from.
			name:    "a takeover release passes the first release's target",
			current: 78,
			keep:    preUpgradeBackupRetention,
			written: "edgewatch-preupgrade-s78-s79-20260107T000000.000000000Z.db",
			files: []string{
				"edgewatch-preupgrade-s76-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260102T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260103T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260104T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260105T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20260106T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20260107T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s76-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260103T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260104T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260105T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20260106T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20260107T000000.000000000Z.db",
			},
		},
		{
			// The 79 release first tried from 76 and failed. A 78 release
			// then committed 76->77 and failed; a 79 release took over,
			// committed 77->78, and failed. The newest schema 76 copy at
			// limit 77 is the rollback point for the previous release, even
			// though a newer, different schema 76 copy is kept at limit 78.
			name:    "retention is per upgrade limit and source schema",
			current: 78,
			keep:    3,
			written: "edgewatch-preupgrade-s78-s79-20260109T000000.000000000Z.db",
			files: []string{
				"edgewatch-preupgrade-s76-s79-20251201T000000.000000000Z.db",
				"edgewatch-preupgrade-s76-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260105T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20260106T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20260107T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20260108T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20260109T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s76-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s76-s79-20251201T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260105T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20260106T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20260107T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20260108T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20260109T000000.000000000Z.db",
			},
		},
		{
			name:    "a new attempt from the previous release's schema",
			current: 75,
			keep:    preUpgradeBackupRetention,
			written: "edgewatch-preupgrade-s75-s78-20260110T000000.000000000Z.db",
			files: []string{
				"edgewatch-preupgrade-s75-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260102T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260103T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260104T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s78-20260110T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s75-s78-20260110T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260102T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260103T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260104T000000.000000000Z.db",
			},
		},
		{
			// Copies from a schema above the current one are not protected.
			name:    "a restart from a copy at an intermediate schema",
			current: 76,
			keep:    preUpgradeBackupRetention,
			written: "edgewatch-preupgrade-s76-s78-20260106T000000.000000000Z.db",
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
				"edgewatch-preupgrade-s77-s78-20260103T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260104T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260105T000000.000000000Z.db",
			},
		},
		{
			// No copy goes beyond the current schema 78, so every copy but
			// the new one falls under the count.
			name:    "copies of finished upgrades only",
			current: 78,
			keep:    preUpgradeBackupRetention,
			written: "edgewatch-preupgrade-s78-s79-20230101T000000.000000000Z.db",
			files: []string{
				"edgewatch-preupgrade-s73-s75-20210101T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s78-20220101T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220301T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220401T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220501T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20230101T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s77-s78-20220301T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220401T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20220501T000000.000000000Z.db",
				"edgewatch-preupgrade-s78-s79-20230101T000000.000000000Z.db",
			},
		},
		{
			// Without a count, only the newest copy beyond 77 from each
			// earlier schema, whatever its target, and the new copy remain.
			name:    "keep 0",
			current: 77,
			keep:    0,
			written: "edgewatch-preupgrade-s77-s79-20260105T000000.000000000Z.db",
			files: []string{
				"edgewatch-preupgrade-s73-s75-20250101T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s78-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s78-20260102T000000.000000000Z.db",
				"edgewatch-preupgrade-s76-s79-20260103T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260104T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260105T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s75-s78-20260102T000000.000000000Z.db",
				"edgewatch-preupgrade-s76-s79-20260103T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260105T000000.000000000Z.db",
			},
		},
		{
			// The host clock was behind when the start wrote its copy, so its
			// name sorts before the three copies of earlier retries and an
			// older one. The new copy stays, and the count still applies to
			// the others.
			name:    "a copy just written with an older timestamp",
			current: 77,
			keep:    preUpgradeBackupRetention,
			written: "edgewatch-preupgrade-s77-s78-20250101T000000.000000000Z.db",
			files: []string{
				"edgewatch-preupgrade-s76-s78-20260301T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20240601T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260401T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260402T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260403T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20250101T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s76-s78-20260301T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20250101T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260401T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260402T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s78-20260403T000000.000000000Z.db",
			},
		},
		{
			// Two copies of finished upgrades from different schemas carry
			// the same timestamp; the greater name counts as newer.
			name:    "equal timestamps",
			current: 77,
			keep:    1,
			written: "edgewatch-preupgrade-s77-s79-20260105T000000.000000000Z.db",
			files: []string{
				"edgewatch-preupgrade-s73-s75-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s75-s76-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260105T000000.000000000Z.db",
			},
			kept: []string{
				"edgewatch-preupgrade-s75-s76-20260101T000000.000000000Z.db",
				"edgewatch-preupgrade-s77-s79-20260105T000000.000000000Z.db",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			for _, name := range test.files {
				writeValidPreUpgradeBackup(t, directory, name, fixtures)
			}
			var wantRemoved []string
			for _, name := range test.files {
				if !slices.Contains(test.kept, name) {
					wantRemoved = append(wantRemoved, name)
				}
			}
			slices.Sort(wantRemoved)
			wantKept := slices.Sorted(slices.Values(test.kept))

			removed, err := prunePreUpgradeBackups(context.Background(), directory, test.current, test.keep, test.written)
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
			removed, err = prunePreUpgradeBackups(context.Background(), directory, test.current, test.keep, test.written)
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
// the directory past the retention bound: those two, the copy just written,
// and three more.
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
		if want := len(earlier) + min(retry, preUpgradeBackupRetention+1); len(automatic) != want {
			t.Fatalf("automatic backups after retry %d = %q, want %d", retry, automatic, want)
		}
	}
	entries, err := os.ReadDir(backupDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(earlier) + preUpgradeBackupRetention + 1; len(entries) != want {
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

// The first start of an upgrade has no earlier schema to protect, so beside
// its new copy, the copies of an earlier, finished upgrade fall under the
// count of three.
func TestPreMigrationBackupsRetainNewCopyAndLatestThreeOthersAndPreserveManualFiles(t *testing.T) {
	requireLinuxDaemonStartup(t)
	path := newSchema75TestDatabase(t, false)
	backupDirectory := t.TempDir()
	old := make([]string, 0, 4)
	for year := 2020; year <= 2023; year++ {
		name := fmt.Sprintf("edgewatch-preupgrade-s74-s75-%d0101T000000.000000000Z.db", year)
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
	if len(automatic) != preUpgradeBackupRetention+1 {
		t.Fatalf("automatic pre-migration backups = %v, want exactly %d", automatic, preUpgradeBackupRetention+1)
	}
	// The names sort by source schema first, so the new schema 75 copy sorts
	// after the seeded schema 74 copies.
	newest := automatic[len(automatic)-1]
	if !strings.HasPrefix(newest, fmt.Sprintf("edgewatch-preupgrade-s75-s%d-", schemaVersion)) {
		t.Fatalf("newest automatic backup = %q, want the schema 75 copy", newest)
	}
	if want := append(slices.Clone(old[1:]), newest); !reflect.DeepEqual(automatic, want) {
		t.Errorf("retained automatic backups = %q, want %q", automatic, want)
	}
	for _, name := range old[:1] {
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
