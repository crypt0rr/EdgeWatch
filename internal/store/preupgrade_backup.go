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
	"strconv"
	"time"
)

// preUpgradeBackupRetention is the number of automatic pre-migration backups
// kept by the timestamp in their names. prunePreUpgradeBackups keeps the
// starting copy of the current upgrade in addition to them, so the directory
// holds at most one more automatic backup than this.
const preUpgradeBackupRetention = 3

var preUpgradeBackupName = regexp.MustCompile(`^edgewatch-preupgrade-s([0-9]+)-s([0-9]+)-([0-9]{8}T[0-9]{6}\.[0-9]{9}Z)\.db$`)

// preparePreMigrationBackup publishes and verifies the current schema before
// the first migration write. Fresh databases have no prior EdgeWatch schema
// to preserve. A missing backup directory is an explicit warning-and-continue
// policy; a configured directory must produce a verified backup successfully.
//
// Every start that needs a migration writes a new backup, including a start
// that retries an upgrade whose earlier steps committed: the operator may have
// run the previous release on a restored copy in between.
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
	// Copying and verifying a large database can take a while, and the
	// migration waits for it. Log the file name only; the completion record
	// below reports the full path.
	logger.Info("pre-migration backup started", "backup", name, "from_schema", version, "to_schema", schemaVersion)
	snapshot := &Store{DB: db, Path: dsn}
	result, err := snapshot.BackupWithOptions(ctx, path, BackupOptions{})
	if err != nil {
		return fmt.Errorf("create and verify automatic pre-migration backup: %w", err)
	}
	if result.SchemaVersion != version {
		return fmt.Errorf("automatic pre-migration backup has schema version %d, expected %d", result.SchemaVersion, version)
	}
	removed, err := prunePreUpgradeBackups(directory, schemaVersion, preUpgradeBackupRetention)
	if err != nil {
		return fmt.Errorf("retain automatic pre-migration backups: %w", err)
	}
	logger.Info("verified pre-migration backup written", "backup", result.Path, "from_schema", version, "to_schema", schemaVersion, "bytes", result.Bytes, "check", result.Check, "removed", len(removed))
	return nil
}

type preUpgradeBackupFile struct {
	name     string
	from, to int
	time     time.Time
}

// prunePreUpgradeBackups removes only regular owner-only files with the
// reserved automatic-backup name whose schemas and timestamp parse. Manual and
// scheduled backups are untouched.
//
// It always keeps the starting copy of the upgrade to target: of the copies
// whose target schema is target, the newest of those with the lowest source
// schema. Each schema step commits on its own, so an upgrade that fails part
// way leaves the database at an intermediate schema, and every retry writes a
// copy of that schema, which the previous release refuses to open; the
// starting copy is the one it can open. Beside it, the newest keep other
// copies by the UTC timestamp in their names are kept, whatever their
// schemas, so at most keep+1 remain. Copies for other target schemas fall
// under this count only.
func prunePreUpgradeBackups(directory string, target, keep int) ([]string, error) {
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
		from, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		to, err := strconv.Atoi(match[2])
		if err != nil {
			continue
		}
		stamp, err := time.Parse("20060102T150405.000000000Z", match[3])
		if err != nil {
			continue
		}
		files = append(files, preUpgradeBackupFile{name: entry.Name(), from: from, to: to, time: stamp})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].time.Equal(files[j].time) {
			return files[i].name > files[j].name
		}
		return files[i].time.After(files[j].time)
	})
	// Newest first, so the first copy with the lowest source schema for the
	// target is the newest of them.
	start := -1
	for i, file := range files {
		if file.to == target && (start < 0 || file.from < files[start].from) {
			start = i
		}
	}
	var removed []string
	kept := 0
	for i, file := range files {
		if i == start {
			continue
		}
		if kept < keep {
			kept++
			continue
		}
		path := filepath.Join(directory, file.name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed = append(removed, file.name)
	}
	if len(removed) == 0 {
		return nil, nil
	}
	if err := syncDirectory(directory); err != nil {
		return removed, err
	}
	return removed, nil
}
