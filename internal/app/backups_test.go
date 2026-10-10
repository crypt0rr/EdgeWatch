package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// backupTestApp returns an app whose scheduled backups write to a new
// directory, keeping keep of them, with a clock the test moves.
func backupTestApp(t *testing.T, keep int, logs io.Writer) (*App, string, *time.Time) {
	t.Helper()
	a, _ := newLifecycleTestApp(t, schedulerFake{}, logs)
	dir := t.TempDir()
	a.Config.Backup = config.Backup{Directory: dir, Schedule: "0 3 * * *", Keep: keep}
	now := time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	a.clock = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	return a, dir, &now
}

func writeBackupTestFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("not ours"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func directoryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// The worker takes a backup at each scheduled time, keeps the newest of the
// backups that it wrote, and records the outcome where health and the
// console read it. It removes only regular, owner-only files with the exact
// name of a scheduled backup: the operator's own files stay, whatever they
// are called.
func TestScheduledBackupsRotateOnlyTheirOwnFiles(t *testing.T) {
	t.Parallel()
	a, dir, now := backupTestApp(t, 2, nil)
	target := filepath.Join(t.TempDir(), "target")
	writeBackupTestFile(t, target, 0o600)
	foreign := []string{
		"edgewatch-20200101T000000Z.db",
		"edgewatch-scheduled-20200101T000000Z.db.keep",
		"edgewatch-scheduled-20200101T000000Z.db-wal",
		"Edgewatch-scheduled-20200101T000000Z.db",
		"edgewatch-scheduled-2020010T000000Z.db",
		"edgewatch-scheduled-20200101T000002Z.db",
	}
	for _, name := range foreign[:5] {
		writeBackupTestFile(t, filepath.Join(dir, name), 0o600)
	}
	// A matching name with another mode, a link, or a directory is not one
	// of the backups either.
	writeBackupTestFile(t, filepath.Join(dir, foreign[5]), 0o644)
	if err := os.Symlink(target, filepath.Join(dir, "edgewatch-scheduled-20200101T000003Z.db")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "edgewatch-scheduled-20200101T000004Z.db"), 0o700); err != nil {
		t.Fatal(err)
	}
	foreign = append(foreign, "edgewatch-scheduled-20200101T000003Z.db", "edgewatch-scheduled-20200101T000004Z.db")
	// An older scheduled backup is rotated out like the new ones.
	writeBackupTestFile(t, filepath.Join(dir, "edgewatch-scheduled-20200101T000005Z.db"), 0o600)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Time
	a.backupWait = func(_ context.Context, next time.Time) bool {
		waits = append(waits, next)
		if len(waits) > 3 {
			cancel()
			return false
		}
		*now = next
		return true
	}
	select {
	case <-a.startBackupWorker(ctx):
	case <-time.After(time.Minute):
		t.Fatal("the backup worker did not stop")
	}
	if len(waits) != 4 || !waits[0].Equal(time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)) || !waits[2].Equal(time.Date(2026, 10, 4, 3, 0, 0, 0, time.UTC)) {
		t.Fatalf("scheduled times = %v", waits)
	}
	want := append(slices.Clone(foreign), "edgewatch-scheduled-20261003T030000Z.db", "edgewatch-scheduled-20261004T030000Z.db")
	slices.Sort(want)
	if got := directoryNames(t, dir); !slices.Equal(got, want) {
		t.Fatalf("backup directory = %v\nwant %v", got, want)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("link target = %v, %v", info, err)
	}
	reader, err := store.OpenReadOnlyExisting(filepath.Join(dir, "edgewatch-scheduled-20261004T030000Z.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Verify(context.Background()); err != nil {
		t.Fatalf("the scheduled backup does not verify: %v", err)
	}
	_ = reader.Close()

	*now = time.Date(2026, 10, 4, 4, 0, 0, 0, time.UTC)
	status := a.BackupStatus()
	if status == nil || status.Directory != dir || status.Schedule != "0 3 * * *" || status.Keep != 2 || status.LastBackup != "edgewatch-scheduled-20261004T030000Z.db" || !status.LastSuccessAt.Equal(waits[2]) || status.LastBackupBytes <= 0 || status.LastBackupSchemaVersion < 1 || status.ConsecutiveFailures != 0 || !status.NextRunAt.Equal(waits[3]) {
		t.Fatalf("backup status = %+v", status)
	}
	if status.LastSuccessAgeSeconds == nil || *status.LastSuccessAgeSeconds != 3600 {
		t.Fatalf("age of the newest backup = %v", status.LastSuccessAgeSeconds)
	}
	if warnings := status.Warnings(); len(warnings) != 0 {
		t.Fatalf("warnings after successful backups = %v", warnings)
	}
	// The status file holds no computed age, and nothing in the deployment
	// besides the status and the backups was written.
	raw, err := os.ReadFile(BackupStatusPath(a.Store.Path))
	if err != nil || strings.Contains(string(raw), "age") {
		t.Fatalf("status file = %s, %v", raw, err)
	}
	if info, err := os.Stat(BackupStatusPath(a.Store.Path)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("status file = %v, %v; want mode 0600", info, err)
	}
}

// A failed backup is recorded with its reason and counted, removes no older
// backup, and is reported as a warning until a backup succeeds again. A
// backup that the daemon's shutdown interrupts records nothing.
func TestScheduledBackupFailuresAreRecordedUntilABackupSucceeds(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	a, dir, now := backupTestApp(t, 1, &logs)
	settings := a.Config.Backup
	missing := settings
	missing.Directory = filepath.Join(dir, "missing")
	older := filepath.Join(dir, "edgewatch-scheduled-20200101T000000Z.db")
	writeBackupTestFile(t, older, 0o600)

	ctx := context.Background()
	status := a.runScheduledBackup(ctx, missing, BackupStatus{})
	*now = now.Add(time.Hour)
	status = a.runScheduledBackup(ctx, missing, status)
	if status.ConsecutiveFailures != 2 || !status.LastFailureAt.Equal(*now) || !strings.Contains(status.LastError, "output directory") || status.LastBackup != "" {
		t.Fatalf("status after two failures = %+v", status)
	}
	warnings := status.Warnings()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "failed 2 time(s)") || !strings.Contains(warnings[0], "no scheduled backup has succeeded yet") {
		t.Fatalf("warnings = %v", warnings)
	}
	if !strings.Contains(logs.String(), "scheduled backup failed") {
		t.Fatalf("the failure was not logged: %s", logs.String())
	}

	status = a.runScheduledBackup(ctx, settings, status)
	if status.ConsecutiveFailures != 0 || status.LastBackup == "" || status.LastError == "" || status.Warnings() != nil {
		t.Fatalf("status after a success = %+v", status)
	}
	if _, err := os.Stat(older); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the older scheduled backup was kept beyond keep: %v", err)
	}
	*now = now.Add(time.Hour)
	failed := a.runScheduledBackup(ctx, missing, status)
	if warnings := failed.Warnings(); len(warnings) != 1 || !strings.Contains(warnings[0], "the newest good backup is "+status.LastBackup) {
		t.Fatalf("warnings after a later failure = %v", warnings)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got := a.runScheduledBackup(canceled, settings, status); got != status {
		t.Fatalf("an interrupted backup changed the status to %+v", got)
	}
}

// Health and the console read the status that the daemon recorded, with the
// configured settings. They report the configuration alone before the first
// backup and when the status cannot be read, and nothing when scheduled
// backups are off.
func TestReadBackupStatusReportsTheRecordedOutcome(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	settings := config.Backup{Directory: "/backups", Schedule: "0 3 * * *", Keep: 7}
	cfg := &config.Config{Database: database, Backup: settings}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	path := BackupStatusPath(database)
	if path != filepath.Join(dir, "backup-status.json") || BackupStatusPath(":memory:") != "" {
		t.Fatalf("status paths = %q, %q", path, BackupStatusPath(":memory:"))
	}
	if status, err := ReadBackupStatus(&config.Config{Database: database}, now); status != nil || err != nil {
		t.Fatalf("status with backups off = %+v, %v", status, err)
	}
	if status, err := ReadBackupStatus(nil, now); status != nil || err != nil {
		t.Fatalf("status without a configuration = %+v, %v", status, err)
	}
	status, err := ReadBackupStatus(cfg, now)
	if err != nil || status == nil || status.Directory != "/backups" || status.Keep != 7 || !status.LastSuccessAt.IsZero() || status.LastSuccessAgeSeconds != nil {
		t.Fatalf("status before the first backup = %+v, %v", status, err)
	}

	recorded := BackupStatus{Directory: "/backups", Schedule: "old", Keep: 3, LastSuccessAt: now.Add(-2 * time.Hour), LastBackup: "edgewatch-scheduled-20261001T100000Z.db", ConsecutiveFailures: 1, LastFailureAt: now.Add(-time.Hour), LastError: "disk full"}
	if err := writeBackupStatusFile(path, recorded); err != nil {
		t.Fatal(err)
	}
	status, err = ReadBackupStatus(cfg, now)
	if err != nil || status.Schedule != "0 3 * * *" || status.Keep != 7 || status.LastBackup != recorded.LastBackup || status.LastSuccessAgeSeconds == nil || *status.LastSuccessAgeSeconds != 7200 || status.LastError != "disk full" {
		t.Fatalf("recorded status = %+v, %v", status, err)
	}
	if future := recorded.reported(now.Add(-3 * time.Hour)); *future.LastSuccessAgeSeconds != 0 {
		t.Fatalf("age of a backup from the future = %d", *future.LastSuccessAgeSeconds)
	}
	encoded, err := json.Marshal(status)
	if err != nil || !strings.Contains(string(encoded), `"last_success_age_seconds":7200`) || strings.Contains(string(encoded), "next_run_at") {
		t.Fatalf("encoded status = %s, %v", encoded, err)
	}

	// A status recorded for another directory describes backups that are
	// not in the configured one.
	moved := *cfg
	moved.Backup.Directory = "/elsewhere"
	if status, err := ReadBackupStatus(&moved, now); err != nil || status.Directory != "/elsewhere" || status.LastBackup != "" || status.ConsecutiveFailures != 0 {
		t.Fatalf("status of another directory = %+v, %v", status, err)
	}

	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T)
		want    string
	}{
		{name: "malformed", prepare: func(t *testing.T) { writeBackupTestFile(t, path, 0o600) }, want: "read scheduled backup status"},
		{name: "too large", prepare: func(t *testing.T) {
			if err := os.WriteFile(path, bytes.Repeat([]byte(" "), backupStatusMaxBytes+1), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "too large"},
		{name: "directory", prepare: func(t *testing.T) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}, want: "not a regular file"},
	} {
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
		tc.prepare(t)
		status, err := ReadBackupStatus(cfg, now)
		if err == nil || !strings.Contains(err.Error(), tc.want) || status == nil || status.Directory != "/backups" || status.LastBackup != "" {
			t.Fatalf("%s status = %+v, %v; want the configuration and %q", tc.name, status, err, tc.want)
		}
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Error(err)
		}
	})
	if os.Geteuid() != 0 {
		if _, err := readBackupStatusFile(filepath.Join(path, "status.json")); err == nil {
			t.Fatal("an unreadable status file was read")
		}
	}
}

// The status file is replaced with a private file. A symbolic link at its
// name is replaced, never followed, and a status file that cannot be written
// is logged.
func TestBackupStatusFileIsReplacedAtomically(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, backupStatusFile)
	target := filepath.Join(t.TempDir(), "target")
	writeBackupTestFile(t, target, 0o644)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writeBackupStatusFile(path, BackupStatus{Directory: "/backups", LastSuccessAgeSeconds: new(int64)}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("status file = %v, %v", info, err)
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "not ours" {
		t.Fatalf("the link target changed: %q, %v", raw, err)
	}
	if names := directoryNames(t, dir); !slices.Equal(names, []string{backupStatusFile}) {
		t.Fatalf("status directory = %v", names)
	}
	if err := writeBackupStatusFile("", BackupStatus{}); err != nil {
		t.Fatalf("status of an in-memory database: %v", err)
	}
	if err := writeBackupStatusFile(filepath.Join(dir, "missing", backupStatusFile), BackupStatus{}); err == nil {
		t.Fatal("a status file in a missing directory was written")
	}

	var logs bytes.Buffer
	a, _, _ := backupTestApp(t, 1, &logs)
	if err := os.Mkdir(BackupStatusPath(a.Store.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	a.recordBackupStatus(BackupStatus{})
	if !strings.Contains(logs.String(), "could not be recorded") {
		t.Fatalf("the failed status write was not logged: %s", logs.String())
	}
	if status := a.BackupStatus(); status == nil || !strings.Contains(logs.String(), "could not be read") {
		t.Fatalf("status = %+v; the failed status read was not logged: %s", status, logs.String())
	}
	if (*App)(nil).BackupStatus() != nil {
		t.Fatal("a nil app reported a backup status")
	}
}

// The worker does not start when scheduled backups are off or their
// schedule is invalid, and warns at start about a missing directory.
func TestBackupWorkerStartsOnlyWithAValidSchedule(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	a, dir, _ := backupTestApp(t, 1, &logs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, settings := range []config.Backup{{}, {Directory: dir, Schedule: "not a schedule", Keep: 1}} {
		a.Config.Backup = settings
		select {
		case <-a.startBackupWorker(ctx):
		default:
			t.Fatalf("the backup worker started with %+v", settings)
		}
	}
	if !strings.Contains(logs.String(), "invalid backup.schedule") {
		t.Fatalf("the invalid schedule was not logged: %s", logs.String())
	}
	if _, err := os.Stat(BackupStatusPath(a.Store.Path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a worker that did not start recorded a status: %v", err)
	}

	a.Config.Backup = config.Backup{Directory: filepath.Join(dir, "missing"), Schedule: "0 3 * * *", Keep: 1}
	a.Config.Timezone = "Europe/Amsterdam"
	writeBackupTestFile(t, BackupStatusPath(a.Store.Path), 0o600)
	var next time.Time
	a.backupWait = func(_ context.Context, at time.Time) bool { next = at; return false }
	<-a.startBackupWorker(ctx)
	if !strings.Contains(logs.String(), "the backup directory is not an existing directory") || !strings.Contains(logs.String(), "the recorded scheduled backup status is ignored") {
		t.Fatalf("the start warnings were not logged: %s", logs.String())
	}
	// 03:00 in Amsterdam is 01:00 UTC in October.
	if !next.Equal(time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("next backup = %v", next)
	}
}

// A schedule that never fires, such as February 30, has no next time. The
// worker stops with an error instead of taking backups back to back.
func TestBackupWorkerStopsWhenTheScheduleNeverFires(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	a, dir, _ := backupTestApp(t, 1, &logs)
	waits := 0
	a.backupWait = func(context.Context, time.Time) bool { waits++; return waits < 3 }
	for _, schedule := range []string{"0 3 30 2 *", "0 3 31 4 *"} {
		a.Config.Backup.Schedule = schedule
		select {
		case <-a.startBackupWorker(context.Background()):
		case <-time.After(time.Minute):
			t.Fatalf("the backup worker with %q did not stop", schedule)
		}
	}
	if waits != 0 {
		t.Fatalf("the worker waited %d times for a schedule that never fires", waits)
	}
	if names := directoryNames(t, dir); len(names) != 0 {
		t.Fatalf("the worker wrote %v for a schedule that never fires", names)
	}
	if strings.Count(logs.String(), "scheduled backups stopped: backup.schedule never fires") != 2 {
		t.Fatalf("the stop was not logged: %s", logs.String())
	}
}

func TestWaitUntilStopsWithTheDaemon(t *testing.T) {
	t.Parallel()
	if !waitUntil(context.Background(), time.Now().Add(-time.Second)) {
		t.Fatal("a past time was not reached")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitUntil(ctx, time.Now().Add(time.Hour)) {
		t.Fatal("the wait outlived the daemon")
	}
}

func TestBoundedBackupErrorIsOneShortLine(t *testing.T) {
	t.Parallel()
	if got := boundedBackupError(errors.New("disk\nfull  now")); got != "disk full now" {
		t.Fatalf("bounded error = %q", got)
	}
	long := boundedBackupError(errors.New(strings.Repeat("é", backupErrorMaxBytes)))
	if len(long) > backupErrorMaxBytes || !utf8.ValidString(long) || len(long) < backupErrorMaxBytes-1 {
		t.Fatalf("bounded long error has %d bytes, valid %t", len(long), utf8.ValidString(long))
	}
}

func TestPruneScheduledBackupsReportsAMissingDirectory(t *testing.T) {
	t.Parallel()
	if _, err := pruneScheduledBackups(filepath.Join(t.TempDir(), "missing"), 1); err == nil {
		t.Fatal("pruning a missing directory succeeded")
	}
	dir := t.TempDir()
	writeBackupTestFile(t, filepath.Join(dir, "edgewatch-scheduled-20200101T000000Z.db"), 0o600)
	if removed, err := pruneScheduledBackups(dir, 1); err != nil || removed != nil {
		t.Fatalf("pruning within keep = %v, %v", removed, err)
	}
}
