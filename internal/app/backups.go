package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

const (
	// scheduledBackupPrefix starts the name of every scheduled backup. The
	// name continues with the UTC time the backup started, in
	// scheduledBackupTimeLayout, and ends in .db.
	scheduledBackupPrefix     = "edgewatch-scheduled-"
	scheduledBackupTimeLayout = "20060102T150405Z"
	// backupStatusFile records the outcome of the scheduled backups beside
	// the database, so that edgewatch health can report it and a restarted
	// daemon keeps it. It is kept outside the backup directory, whose
	// failure it must be able to record.
	backupStatusFile = "backup-status.json"
	// backupStatusMaxBytes bounds the status file that health reads.
	backupStatusMaxBytes = 64 << 10
	// backupErrorMaxBytes bounds the recorded reason of a failed backup.
	backupErrorMaxBytes = 512
)

// scheduledBackupName matches the names of the scheduled backups exactly.
// Pruning removes only files whose names match it, so an operator's own
// files in the backup directory, including backups made with the backup
// command under other names, are never removed.
var scheduledBackupName = regexp.MustCompile(`^edgewatch-scheduled-[0-9]{8}T[0-9]{6}Z\.db$`)

// BackupStatus is the outcome of the daemon's scheduled backups. It is
// deployment-wide and names no business unit's data: the configured
// directory, schedule, and number kept, the newest good backup, and the
// latest failure with a bounded reason.
type BackupStatus struct {
	Directory string    `json:"directory"`
	Schedule  string    `json:"schedule"`
	Keep      int       `json:"keep"`
	NextRunAt time.Time `json:"next_run_at,omitzero"`
	// LastSuccessAt is when the newest good backup was taken, LastBackup its
	// file name in Directory, with its size and schema version.
	LastSuccessAt           time.Time `json:"last_success_at,omitzero"`
	LastBackup              string    `json:"last_backup,omitempty"`
	LastBackupBytes         int64     `json:"last_backup_bytes,omitempty"`
	LastBackupSchemaVersion int       `json:"last_backup_schema_version,omitempty"`
	// LastSuccessAgeSeconds is the age of the newest good backup when the
	// status was reported. It is not stored.
	LastSuccessAgeSeconds *int64 `json:"last_success_age_seconds,omitempty"`
	// LastFailureAt and LastError describe the latest failed backup.
	// ConsecutiveFailures counts the failures since the newest good backup;
	// it is zero once a backup succeeds again.
	LastFailureAt       time.Time `json:"last_failure_at,omitzero"`
	LastError           string    `json:"last_error,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
}

// Warnings lists the scheduled backup problems that edgewatch health
// reports without failing: the latest backup failed.
func (s *BackupStatus) Warnings() []string {
	if s == nil || s.ConsecutiveFailures == 0 {
		return nil
	}
	newest := "no scheduled backup has succeeded yet"
	if !s.LastSuccessAt.IsZero() {
		newest = "the newest good backup is " + s.LastBackup + " from " + s.LastSuccessAt.UTC().Format(time.RFC3339)
	}
	return []string{fmt.Sprintf("the scheduled backup failed %d time(s), last at %s: %s; %s", s.ConsecutiveFailures, s.LastFailureAt.UTC().Format(time.RFC3339), s.LastError, newest)}
}

// reported returns a copy of the status with the age of the newest good
// backup at now.
func (s BackupStatus) reported(now time.Time) *BackupStatus {
	s.LastSuccessAgeSeconds = nil
	if !s.LastSuccessAt.IsZero() {
		age := int64(now.Sub(s.LastSuccessAt) / time.Second)
		if age < 0 {
			age = 0
		}
		s.LastSuccessAgeSeconds = &age
	}
	return &s
}

// BackupStatusPath returns the status file of the scheduled backups of the
// database: backup-status.json beside the database file. An in-memory
// database has none.
func BackupStatusPath(database string) string {
	path, err := store.DatabaseFilePath(database)
	if err != nil || path == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(path), backupStatusFile)
}

// ReadBackupStatus returns the status of the scheduled backups that the
// daemon recorded for cfg, with the age of the newest good backup at now. It
// is nil when cfg turns scheduled backups off. Before the daemon recorded a
// status, it reports only the configuration. The status is still returned
// with the configuration when the file cannot be read.
func ReadBackupStatus(cfg *config.Config, now time.Time) (*BackupStatus, error) {
	if cfg == nil {
		return nil, nil
	}
	return readBackupStatus(cfg.Database, cfg.Backup, now)
}

// readBackupStatus is ReadBackupStatus for the database and the settings.
func readBackupStatus(database string, settings config.Backup, now time.Time) (*BackupStatus, error) {
	if !settings.Enabled() {
		return nil, nil
	}
	status, err := readBackupStatusFile(BackupStatusPath(database))
	status = withBackupSettings(status, settings)
	return status.reported(now), err
}

// withBackupSettings applies the configured settings to a recorded status.
// A status recorded for another directory describes backups that are not
// there, so it is dropped.
func withBackupSettings(status BackupStatus, settings config.Backup) BackupStatus {
	if status.Directory != settings.Directory {
		status = BackupStatus{}
	}
	status.Directory, status.Schedule, status.Keep = settings.Directory, settings.Schedule, settings.Keep
	return status
}

// readBackupStatusFile reads a recorded status. A missing file is an empty
// status.
func readBackupStatusFile(path string) (BackupStatus, error) {
	var status BackupStatus
	if path == "" {
		return status, nil
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return status, nil
	}
	if err != nil {
		return status, fmt.Errorf("read scheduled backup status: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return status, fmt.Errorf("read scheduled backup status: %w", err)
	}
	if !info.Mode().IsRegular() {
		return status, errors.New("read scheduled backup status: not a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, backupStatusMaxBytes+1))
	if err != nil {
		return status, fmt.Errorf("read scheduled backup status: %w", err)
	}
	if len(raw) > backupStatusMaxBytes {
		return status, errors.New("read scheduled backup status: the file is too large")
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		return BackupStatus{}, fmt.Errorf("read scheduled backup status: %w", err)
	}
	status.LastSuccessAgeSeconds = nil
	return status, nil
}

// writeBackupStatusFile replaces the status file atomically with a private
// file. The rename replaces whatever has the name, a symbolic link
// included, without following it.
func writeBackupStatusFile(path string, status BackupStatus) error {
	if path == "" {
		return nil
	}
	status.LastSuccessAgeSeconds = nil
	raw, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+backupStatusFile+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(append(raw, '\n')); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	keep = true
	return syncBackupDirectory(dir)
}

// syncBackupDirectory makes a rename or a removal in dir durable.
func syncBackupDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := handle.Sync()
	return errors.Join(syncErr, handle.Close())
}

// BackupStatus returns the status of the scheduled backups as the daemon
// recorded it, with the age of the newest good backup now, or nil when they
// are off. The console reads it as edgewatch health does.
func (a *App) BackupStatus() *BackupStatus {
	if a == nil || a.Config == nil || a.Store == nil {
		return nil
	}
	status, err := readBackupStatus(a.Store.Path, a.Config.Backup, a.nowUTC())
	if err != nil {
		a.backupLogger().Warn("the scheduled backup status could not be read", "error", err)
	}
	return status
}

// recordBackupStatus writes the status to the status file.
func (a *App) recordBackupStatus(status BackupStatus) {
	if err := writeBackupStatusFile(BackupStatusPath(a.Store.Path), status); err != nil {
		a.backupLogger().Warn("the scheduled backup status could not be recorded", "error", err)
	}
}

func (a *App) backupLogger() *slog.Logger {
	if a.Logger == nil {
		return slog.Default()
	}
	return a.Logger
}

// startBackupWorker takes the scheduled backups that config.yaml configures,
// until ctx ends. It does nothing when they are off.
func (a *App) startBackupWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	settings := a.Config.Backup
	if !settings.Enabled() {
		close(done)
		return done
	}
	logger := a.backupLogger()
	schedule, err := config.ParseBackupSchedule(settings.Schedule)
	if err != nil {
		// Configuration validation refuses such a schedule before the
		// daemon starts; a library caller could still pass one.
		logger.Error("scheduled backups are off: invalid backup.schedule", "error", err)
		close(done)
		return done
	}
	location := time.UTC
	if configured, err := a.Config.Location(); err == nil && configured != nil {
		location = configured
	}
	recorded, err := readBackupStatusFile(BackupStatusPath(a.Store.Path))
	if err != nil {
		logger.Warn("the recorded scheduled backup status is ignored", "error", err)
	}
	// The worker owns the status; the status file is how health and the
	// console read it.
	status := withBackupSettings(recorded, settings)
	if info, err := os.Stat(settings.Directory); err != nil || !info.IsDir() {
		logger.Warn("the backup directory is not an existing directory; scheduled backups fail until it is created", "directory", settings.Directory)
	}
	wait := a.backupWait
	if wait == nil {
		wait = waitUntil
	}
	go func() {
		defer close(done)
		defer a.recoverBackgroundPanic("scheduled-backup-worker")
		for {
			status.NextRunAt = schedule.Next(a.nowUTC().In(location)).UTC()
			a.recordBackupStatus(status)
			if !wait(ctx, status.NextRunAt) {
				return
			}
			status = a.runScheduledBackup(ctx, settings, status)
		}
	}()
	return done
}

// waitUntil waits for the time at, and reports false when ctx ends first.
func waitUntil(ctx context.Context, at time.Time) bool {
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// runScheduledBackup writes one scheduled backup through Store.Backup, which
// checks it before it publishes it, then removes the scheduled backups beyond
// the newest settings.Keep, and returns status with the outcome. A failed
// backup removes nothing, so the older good backups stay. A backup that the
// daemon's shutdown interrupts leaves status as it was.
func (a *App) runScheduledBackup(ctx context.Context, settings config.Backup, status BackupStatus) BackupStatus {
	logger := a.backupLogger()
	started := a.nowUTC()
	name := scheduledBackupPrefix + started.Format(scheduledBackupTimeLayout) + ".db"
	result, err := a.Store.BackupWithOptions(ctx, filepath.Join(settings.Directory, name), store.BackupOptions{})
	if err != nil {
		if ctx.Err() != nil {
			return status
		}
		status.LastFailureAt, status.LastError = a.nowUTC(), boundedBackupError(err)
		status.ConsecutiveFailures++
		logger.Error("scheduled backup failed", "backup", name, "error", status.LastError, "consecutive_failures", status.ConsecutiveFailures)
		return status
	}
	removed, pruneErr := pruneScheduledBackups(settings.Directory, settings.Keep)
	if pruneErr != nil {
		logger.Warn("old scheduled backups could not be removed", "error", pruneErr)
	}
	logger.Info("scheduled backup written", "backup", name, "bytes", result.Bytes, "schema_version", result.SchemaVersion, "check", result.Check, "removed", len(removed))
	status.LastSuccessAt, status.LastBackup = started, name
	status.LastBackupBytes, status.LastBackupSchemaVersion = result.Bytes, result.SchemaVersion
	status.ConsecutiveFailures = 0
	return status
}

// boundedBackupError is the reason of a failed backup, on one line and at
// most backupErrorMaxBytes long.
func boundedBackupError(err error) string {
	reason := strings.Join(strings.Fields(err.Error()), " ")
	if len(reason) <= backupErrorMaxBytes {
		return reason
	}
	reason = reason[:backupErrorMaxBytes]
	for !utf8.ValidString(reason) {
		reason = reason[:len(reason)-1]
	}
	return reason
}

// pruneScheduledBackups removes the scheduled backups in dir beyond the
// newest keep and returns the names it removed. It considers only regular
// files whose names match scheduledBackupName and that have the owner-only
// mode every backup is published with. The UTC timestamp in the name orders
// them.
func pruneScheduledBackups(dir string, keep int) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if !scheduledBackupName.MatchString(entry.Name()) {
			continue
		}
		info, err := os.Lstat(filepath.Join(dir, entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			continue
		}
		names = append(names, entry.Name())
	}
	if len(names) <= keep {
		return nil, nil
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	var removed []string
	for _, name := range names[keep:] {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed = append(removed, name)
	}
	return removed, syncBackupDirectory(dir)
}
