package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// openFreshFileStore opens a writable copy of the migrated template in a
// private directory and closes it when the test ends.
func openFreshFileStore(t *testing.T) (*Store, string) {
	t.Helper()
	database := freshTestDatabasePath(t)
	s, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, database
}

// entriesWithPrefix lists the names in dir that start with prefix.
func entriesWithPrefix(t *testing.T, dir, prefix string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			names = append(names, entry.Name())
		}
	}
	return names
}

// A backup reports the checks it passed: quick_check by default, the full
// integrity_check on request, the foreign-key check, and the schema.
func TestBackupWithOptionsReportsTheChecksItPassed(t *testing.T) {
	t.Parallel()
	s, _ := openFreshFileStore(t)
	dir := t.TempDir()
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		options BackupOptions
		check   string
	}{
		{name: "quick.db", check: QuickCheck},
		{name: "full.db", options: BackupOptions{FullIntegrityCheck: true}, check: IntegrityCheck},
	} {
		result, err := s.BackupWithOptions(ctx, filepath.Join(dir, tc.name), tc.options)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		info, err := os.Stat(result.Path)
		if err != nil {
			t.Fatal(err)
		}
		if result.Path != filepath.Join(dir, tc.name) || result.Bytes != info.Size() || result.SchemaVersion != schemaVersion || result.Check != tc.check || result.IntegrityCheck != "ok" || result.ForeignKeyViolations != 0 {
			t.Fatalf("%s: backup result = %+v (size %d)", tc.name, result, info.Size())
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: backup mode = %04o, want 0600", tc.name, info.Mode().Perm())
		}
	}
	if _, err := s.verify(ctx, "unknown_check"); err == nil || !strings.Contains(err.Error(), "unknown database check") {
		t.Fatalf("verify with an unknown check = %v", err)
	}
}

// A backup is checked before it is published: a database whose rows break a
// foreign key, which a restore would refuse, fails the backup, and nothing is
// left in the output directory.
func TestBackupOfADatabaseWithAForeignKeyViolationPublishesNothing(t *testing.T) {
	t.Parallel()
	s, _ := openFreshFileStore(t)
	ctx := context.Background()
	if _, err := s.DB.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES('orphan','{}','now')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	output := filepath.Join(dir, "backup.db")
	result, err := s.BackupWithOptions(ctx, output, BackupOptions{})
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.ForeignKeyViolations != 1 || !strings.Contains(err.Error(), "verify SQLite backup") {
		t.Fatalf("backup of a database with a foreign-key violation = %+v, %v", result, err)
	}
	if result.Path != "" || result.SchemaVersion != schemaVersion {
		t.Fatalf("failed backup result = %+v", result)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a failed backup left %d entries in the output directory, the first %q", len(entries), entries[0].Name())
	}
	if _, err := s.Backup(ctx, output); err == nil {
		t.Fatal("Backup published a database with a foreign-key violation")
	}
}

// The backup's private modes are set on its temporary file. Files next to
// the published path that share its SQLite sidecar names belong to someone
// else: the backup neither changes their mode nor fails because of them.
func TestBackupLeavesFilesWithItsSidecarNamesAlone(t *testing.T) {
	t.Parallel()
	s, _ := openFreshFileStore(t)
	ctx := context.Background()
	dir := t.TempDir()

	regular := filepath.Join(dir, "regular.db")
	if err := os.WriteFile(regular+"-wal", []byte("unrelated"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(regular+"-wal", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Backup(ctx, regular); err != nil {
		t.Fatalf("backup next to an unrelated -wal file: %v", err)
	}
	info, err := os.Stat(regular + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("the unrelated -wal file mode = %04o, want 0644", info.Mode().Perm())
	}

	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("target"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "linked.db")
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.Symlink(target, linked+suffix); err != nil {
			t.Fatal(err)
		}
	}
	path, err := s.Backup(ctx, linked)
	if err != nil {
		t.Fatalf("backup next to sidecar symbolic links: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the backup next to sidecar symbolic links was removed: %v", err)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("the symbolic link target = %v, %v; want it unchanged at 0644", info, err)
	}
}

// writeBackupFile writes a verified backup of a fresh database and returns
// its path.
func writeBackupFile(t *testing.T) string {
	t.Helper()
	s, _ := openFreshFileStore(t)
	path, err := s.Backup(context.Background(), filepath.Join(t.TempDir(), "backup.db"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// VerifyBackupFile checks a backup on a private copy: the source stays byte
// for byte as it was, no sidecar appears next to it, and the copy is gone
// afterwards.
func TestVerifyBackupFileChecksAPrivateCopy(t *testing.T) {
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	source := writeBackupFile(t)
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	inspected := ""
	report, err := VerifyBackupFile(context.Background(), source, BackupFileOptions{
		LiveDatabase: filepath.Join(t.TempDir(), "edgewatch.db"),
		InspectStaged: func(_ context.Context, path string) (RestoreKeyCheck, error) {
			inspected = path
			return RestoreKeyCheck{Destinations: 2, TOTPSecrets: 1}, nil
		},
	})
	if err != nil {
		t.Fatalf("verify a valid backup: %v (%+v)", err, report)
	}
	if !report.Valid || report.Error != "" || report.SourcePath != source || report.Bytes != int64(len(before)) || report.SchemaVersion != schemaVersion || !report.SchemaSupported || !report.EdgeWatchSchema || report.IntegrityCheck != "ok" || len(report.SourceSidecars) != 0 {
		t.Fatalf("verification report = %+v", report)
	}
	if report.KeyCheck == nil || *report.KeyCheck != (RestoreKeyCheck{Destinations: 2, TOTPSecrets: 1}) {
		t.Fatalf("key check = %+v", report.KeyCheck)
	}
	if !strings.HasPrefix(inspected, temp+string(filepath.Separator)) || inspected == source {
		t.Fatalf("the key check opened %q, want a copy below TMPDIR %q", inspected, temp)
	}
	after, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("verification changed the backup file")
	}
	if left := entriesWithPrefix(t, filepath.Dir(source), filepath.Base(source)+"-"); len(left) != 0 {
		t.Fatalf("verification left sidecars next to the backup: %v", left)
	}
	if left := entriesWithPrefix(t, temp, ".edgewatch-verify-"); len(left) != 0 {
		t.Fatalf("verification left its private copy: %v", left)
	}
}

// Every check that a restore runs on its source fails the verification, with
// the report filled in as far as the checks went.
func TestVerifyBackupFileReportsEveryFailedCheck(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	ctx := context.Background()
	valid := writeBackupFile(t)
	raw, err := os.ReadFile(valid)
	if err != nil {
		t.Fatal(err)
	}
	write := func(t *testing.T, content []byte) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "backup.db")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	mismatch := func(context.Context, string) (RestoreKeyCheck, error) {
		return RestoreKeyCheck{Destinations: 3, DestinationsLocked: 3, TOTPSecrets: 1, TOTPUnreadable: 1}, nil
	}
	for _, tc := range []struct {
		name    string
		source  func(t *testing.T) string
		options BackupFileOptions
		wantErr error
		want    string
		check   func(t *testing.T, report BackupFileVerification)
	}{
		{name: "missing", source: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing.db") }, wantErr: os.ErrNotExist},
		{name: "empty path", source: func(*testing.T) string { return " " }, want: "path is required"},
		{name: "not SQLite", source: func(t *testing.T) string { return write(t, []byte("not a database, but long enough")) }, want: "not a SQLite database"},
		{
			name: "symbolic link",
			source: func(t *testing.T) string {
				link := filepath.Join(t.TempDir(), "link.db")
				if err := os.Symlink(valid, link); err != nil {
					t.Fatal(err)
				}
				return link
			},
			want: "symbolic link",
		},
		{
			name:    "the configured database",
			source:  func(*testing.T) string { return valid },
			options: BackupFileOptions{LiveDatabase: valid},
			want:    "run verify without --from",
		},
		{
			name:    "an invalid configured database",
			source:  func(*testing.T) string { return valid },
			options: BackupFileOptions{LiveDatabase: "file:%zz"},
			want:    "configured database",
		},
		{
			name: "sidecars",
			source: func(t *testing.T) string {
				path := write(t, raw)
				if err := os.WriteFile(path+"-wal", []byte("wal"), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			wantErr: ErrRestoreSidecars,
			check: func(t *testing.T, report BackupFileVerification) {
				if len(report.SourceSidecars) != 1 || report.SourceSidecars[0].Kind != "wal" {
					t.Fatalf("source sidecars = %+v", report.SourceSidecars)
				}
			},
		},
		{
			name:   "truncated",
			source: func(t *testing.T) string { return write(t, raw[:len(raw)/2]) },
			check: func(t *testing.T, report BackupFileVerification) {
				if report.Bytes != int64(len(raw)/2) {
					t.Fatalf("bytes = %d, want %d", report.Bytes, len(raw)/2)
				}
			},
		},
		{
			name: "newer schema",
			source: func(t *testing.T) string {
				path := write(t, raw)
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`PRAGMA user_version = 999`); err != nil {
					db.Close()
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				return path
			},
			want: "unsupported schema version: 999",
			check: func(t *testing.T, report BackupFileVerification) {
				if report.SchemaVersion != 999 || report.SchemaSupported {
					t.Fatalf("schema = %d supported %t", report.SchemaVersion, report.SchemaSupported)
				}
			},
		},
		{
			name:    "key mismatch",
			source:  func(*testing.T) string { return valid },
			options: BackupFileOptions{InspectStaged: mismatch},
			wantErr: ErrRestoreKeyMismatch,
			check: func(t *testing.T, report BackupFileVerification) {
				if report.KeyCheck == nil || report.KeyCheck.DestinationsLocked != 3 || report.KeyCheck.TOTPUnreadable != 1 {
					t.Fatalf("key check = %+v", report.KeyCheck)
				}
			},
		},
		{
			name:   "failed key check",
			source: func(*testing.T) string { return valid },
			options: BackupFileOptions{InspectStaged: func(context.Context, string) (RestoreKeyCheck, error) {
				return RestoreKeyCheck{}, errors.New("key check failed")
			}},
			want: "check the configured keys against the backup: key check failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := VerifyBackupFile(ctx, tc.source(t), tc.options)
			if err == nil || report.Valid || report.Error != err.Error() {
				t.Fatalf("verification = %+v, %v; want a failure", report, err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if report.ForeignKeyViolations == nil || report.SourceSidecars == nil {
				t.Fatalf("report lists are null: %+v", report)
			}
			if tc.check != nil {
				tc.check(t, report)
			}
		})
	}

	// With the mismatch allowed, the counts are reported and the file passes.
	report, err := VerifyBackupFile(ctx, valid, BackupFileOptions{InspectStaged: mismatch, AllowKeyMismatch: true})
	if err != nil || !report.Valid || report.KeyCheck == nil || report.KeyCheck.DestinationsLocked != 3 {
		t.Fatalf("verification with the key mismatch allowed = %+v, %v", report, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := VerifyBackupFile(canceled, valid, BackupFileOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verification = %v", err)
	}
}

// Without a usable temporary directory, verification fails before it reads
// the source.
func TestVerifyBackupFileNeedsATemporaryDirectory(t *testing.T) {
	valid := writeBackupFile(t)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	if _, err := VerifyBackupFile(context.Background(), valid, BackupFileOptions{}); err == nil || !strings.Contains(err.Error(), "create backup verification directory") {
		t.Fatalf("verification without a temporary directory = %v", err)
	}
}

// The key check of a restore runs on the sanitized staged copy, and its
// counts appear in the dry run and in the restore. A copy whose secrets the
// keys cannot open is refused, by the dry run and the restore alike, and
// leaves the destination as it was, unless the mismatch is allowed.
func TestRestoreRefusesABackupThatTheKeysCannotOpen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	source := writeBackupFile(t)
	destination := freshTestDatabasePath(t)
	var inspected []string
	inspect := func(_ context.Context, path string) (RestoreKeyCheck, error) {
		inspected = append(inspected, path)
		// The copy is sanitized before the check: its sessions are gone and
		// its restore epoch is recorded.
		staged, err := OpenReadOnlyExistingContext(ctx, path)
		if err != nil {
			return RestoreKeyCheck{}, err
		}
		defer staged.Close()
		var epochs int
		if err := staged.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM restore_epochs`).Scan(&epochs); err != nil || epochs != 1 {
			return RestoreKeyCheck{}, errors.Join(err, errors.New("the staged copy was not sanitized"))
		}
		return RestoreKeyCheck{Destinations: 2, DestinationsLocked: 2}, nil
	}
	before, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	options := RestoreOptions{InspectStaged: inspect}
	report, err := DryRunRestore(ctx, source, destination, options)
	if !errors.Is(err, ErrRestoreKeyMismatch) || report.Safe || !strings.Contains(report.Refusal, "cannot open 2 of 2 web-managed destinations") {
		t.Fatalf("dry run with a key mismatch = %+v, %v", report, err)
	}
	if report.KeyCheck == nil || report.KeyCheck.DestinationsLocked != 2 {
		t.Fatalf("dry run key check = %+v", report.KeyCheck)
	}
	if _, err := Restore(ctx, source, destination, options); !errors.Is(err, ErrRestoreKeyMismatch) {
		t.Fatalf("restore with a key mismatch = %v", err)
	}
	if after, err := fileDigest(destination); err != nil || after != before {
		t.Fatalf("a refused restore changed the destination (%v)", err)
	}
	if len(inspected) != 2 || inspected[0] == destination || inspected[1] == destination {
		t.Fatalf("the key check opened %v, want two staged copies", inspected)
	}

	options.AllowKeyMismatch = true
	report, err = DryRunRestore(ctx, source, destination, options)
	if err != nil || !report.Safe || report.KeyCheck == nil || report.KeyCheck.DestinationsLocked != 2 {
		t.Fatalf("dry run with the mismatch allowed = %+v, %v", report, err)
	}
	result, err := Restore(ctx, source, destination, options)
	if err != nil || result.KeyCheck == nil || *result.KeyCheck != (RestoreKeyCheck{Destinations: 2, DestinationsLocked: 2}) {
		t.Fatalf("restore with the mismatch allowed = %+v, %v", result, err)
	}

	// A key check that fails refuses the restore too.
	failing := RestoreOptions{InspectStaged: func(context.Context, string) (RestoreKeyCheck, error) {
		return RestoreKeyCheck{}, errors.New("key file unreadable")
	}}
	if _, err := Restore(ctx, source, destination, failing); err == nil || !strings.Contains(err.Error(), "key file unreadable") {
		t.Fatalf("restore with a failing key check = %v", err)
	}
}

func TestRestoreKeyMismatchErrorNamesTheCounts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err  *RestoreKeyMismatchError
		want string
	}{
		{err: nil, want: ErrRestoreKeyMismatch.Error()},
		{err: &RestoreKeyMismatchError{}, want: ErrRestoreKeyMismatch.Error()},
		{err: &RestoreKeyMismatchError{Check: RestoreKeyCheck{TOTPSecrets: 2, TOTPUnreadable: 1}}, want: ErrRestoreKeyMismatch.Error() + ": the authentication key cannot open 1 of 2 TOTP seeds"},
		{err: &RestoreKeyMismatchError{Check: RestoreKeyCheck{Destinations: 1, DestinationsLocked: 1, TOTPSecrets: 1, TOTPUnreadable: 1}}, want: ErrRestoreKeyMismatch.Error() + ": the notification key cannot open 1 of 1 web-managed destinations; the authentication key cannot open 1 of 1 TOTP seeds"},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("error = %q, want %q", got, tc.want)
		}
		if !errors.Is(tc.err, ErrRestoreKeyMismatch) {
			t.Errorf("%v does not wrap ErrRestoreKeyMismatch", tc.err)
		}
	}
}

// The key check reads the sealed destinations and TOTP seeds of every owner
// with columns that every schema since they exist has, and finds none in a
// database from before them.
func TestKeyCheckReadersCoverEveryOwnerAndOlderSchemas(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, database := openFreshFileStore(t)
	if _, err := defaultTenant(s).CreateManagedNotification(ctx, "destination-a", "Ops", "generic", []byte("sealed"), []byte("nonce"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateManagedNotification(ctx, "destination-b", "Paused", "generic", []byte("sealed"), []byte("nonce"), false); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "hash", TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	sealed, err := s.System().SealedManagedNotifications(ctx)
	if err != nil || len(sealed) != 2 || sealed[0].ID != "destination-a" || string(sealed[0].Ciphertext) != "sealed" || string(sealed[0].Nonce) != "nonce" || !sealed[0].Enabled || sealed[1].Enabled {
		t.Fatalf("sealed destinations = %+v, %v", sealed, err)
	}
	if seeds, unreadable, err := s.System().TOTPKeyCheck(ctx); err != nil || seeds != 1 || unreadable != 0 {
		t.Fatalf("TOTP key check with the right key = %d, %d, %v", seeds, unreadable, err)
	}
	s.SetAuthKeyPath(filepath.Join(filepath.Dir(database), "missing.key"))
	if seeds, unreadable, err := s.System().TOTPKeyCheck(ctx); err != nil || seeds != 1 || unreadable != 1 {
		t.Fatalf("TOTP key check without the key = %d, %d, %v", seeds, unreadable, err)
	}
	if path := DefaultAuthKeyPath("file:" + database + "?mode=rw"); path != filepath.Join(filepath.Dir(database), "auth.key") {
		t.Fatalf("default authentication key = %q", path)
	}
	if path := DefaultAuthKeyPath(":memory:"); path != "" {
		t.Fatalf("default authentication key of an in-memory database = %q", path)
	}

	// A database of the first schemas keeps the administrator's seed in
	// admins, which the key check reads with the legacy owner; a plaintext
	// seed of v0.3 needs no key.
	legacy := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE admins(id INTEGER PRIMARY KEY, totp_secret TEXT NOT NULL DEFAULT ''); INSERT INTO admins(id,totp_secret) VALUES(1,'JBSWY3DPEHPK3PXP')`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	old, err := OpenReadOnlyExisting(legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if sealed, err := old.System().SealedManagedNotifications(ctx); err != nil || len(sealed) != 0 {
		t.Fatalf("sealed destinations of an old schema = %+v, %v", sealed, err)
	}
	if seeds, unreadable, err := old.System().TOTPKeyCheck(ctx); err != nil || seeds != 1 || unreadable != 0 {
		t.Fatalf("TOTP key check of an old schema = %d, %d, %v", seeds, unreadable, err)
	}

	// A database without either table has no seed.
	empty := filepath.Join(t.TempDir(), "empty.db")
	raw, err = sql.Open("sqlite", empty)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE unrelated(x)`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	none, err := OpenReadOnlyExisting(empty)
	if err != nil {
		t.Fatal(err)
	}
	defer none.Close()
	if seeds, unreadable, err := none.System().TOTPKeyCheck(ctx); err != nil || seeds != 0 || unreadable != 0 {
		t.Fatalf("TOTP key check without accounts = %d, %d, %v", seeds, unreadable, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.System().SealedManagedNotifications(canceled); err == nil {
		t.Fatal("a canceled read of the sealed destinations succeeded")
	}
	if _, _, err := s.System().TOTPKeyCheck(canceled); err == nil {
		t.Fatal("a canceled TOTP key check succeeded")
	}
}
