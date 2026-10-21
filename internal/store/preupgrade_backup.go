package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

const preUpgradeBackupRetention = 3

var preUpgradeBackupName = regexp.MustCompile(`^edgewatch-preupgrade-s([0-9]+)-s([0-9]+)-([0-9]{8}T[0-9]{6}\.[0-9]{9}Z)\.db$`)

// preparePreMigrationBackup publishes and verifies the current schema before
// the first migration write. Fresh databases have no prior EdgeWatch schema
// to preserve. A missing backup directory is an explicit warning-and-continue
// policy; a configured directory must produce a verified backup successfully.
func preparePreMigrationBackup(ctx context.Context, db *sql.DB, dsn string, version int, directory string, logger *slog.Logger) error {
	if version == 0 || version >= schemaVersion {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	if directory == "" {
		logger.Warn("database schema migration has no configured backup directory; continuing without an automatic pre-migration backup", "from_schema", version, "to_schema", schemaVersion, "remediation", "configure backup.directory to retain verified pre-migration backups")
		return nil
	}

	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	name := fmt.Sprintf("edgewatch-preupgrade-s%d-s%d-%s.db", version, schemaVersion, stamp)
	path := filepath.Join(directory, name)
	snapshot := &Store{DB: db, Path: dsn}
	result, err := snapshot.BackupWithOptions(ctx, path, BackupOptions{})
	if err != nil {
		return fmt.Errorf("create and verify automatic pre-migration backup: %w", err)
	}
	if result.SchemaVersion != version {
		return fmt.Errorf("automatic pre-migration backup has schema version %d, expected %d", result.SchemaVersion, version)
	}
	removed, err := prunePreUpgradeBackups(directory, preUpgradeBackupRetention)
	if err != nil {
		return fmt.Errorf("retain automatic pre-migration backups: %w", err)
	}
	logger.Info("verified pre-migration backup written", "backup", result.Path, "from_schema", version, "to_schema", schemaVersion, "bytes", result.Bytes, "check", result.Check, "removed", len(removed))
	return nil
}

type preUpgradeBackupFile struct {
	name string
	time time.Time
}

// prunePreUpgradeBackups removes only regular owner-only files with the
// reserved automatic-backup name. Manual and scheduled backups are untouched.
// Names include a UTC timestamp so the newest three can be retained across
// upgrades from different schema versions.
func prunePreUpgradeBackups(directory string, keep int) ([]string, error) {
	if keep < 0 {
		return nil, errors.New("pre-migration backup retention cannot be negative")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	files := make([]preUpgradeBackupFile, 0, len(entries))
	for _, entry := range entries {
		match := preUpgradeBackupName.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		info, err := os.Lstat(filepath.Join(directory, entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			continue
		}
		stamp, err := time.Parse("20060102T150405.000000000Z", match[3])
		if err != nil {
			continue
		}
		files = append(files, preUpgradeBackupFile{name: entry.Name(), time: stamp})
	}
	if len(files) <= keep {
		return nil, nil
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].time.Equal(files[j].time) {
			return files[i].name > files[j].name
		}
		return files[i].time.After(files[j].time)
	})
	removed := make([]string, 0, len(files)-keep)
	for _, file := range files[keep:] {
		path := filepath.Join(directory, file.name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed = append(removed, file.name)
	}
	if err := syncDirectory(directory); err != nil {
		return removed, err
	}
	return removed, nil
}
