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
// kept by the timestamp in their names. prunePreUpgradeBackups also keeps, in
// addition to them, the copy just written and the newest copy for each
// (upgrade limit, source schema) pair in the unfinished-upgrade chain. A
// source schema can therefore have more than one protected copy when the
// chain has different limits.
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
	// migration waits for it, so the start is logged too. Both records give
	// the backup's full path under the same key.
	logger.Info("pre-migration backup started", "backup", path, "from_schema", version, "to_schema", schemaVersion)
	snapshot := &Store{DB: db, Path: dsn}
	result, err := snapshot.BackupWithOptions(ctx, path, BackupOptions{})
	if err != nil {
		return fmt.Errorf("create and verify automatic pre-migration backup: %w", err)
	}
	if result.SchemaVersion != version {
		return fmt.Errorf("automatic pre-migration backup has schema version %d, expected %d", result.SchemaVersion, version)
	}
	removed, err := prunePreUpgradeBackups(directory, version, preUpgradeBackupRetention, name)
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
// scheduled backups are untouched. current is the stored schema of the
// database being upgraded, and written names the copy of it just written.
//
// Each schema step commits on its own, so an upgrade that fails part way
// leaves the database at an intermediate schema, and every retry writes a
// copy of that schema, which the previous release refuses to open. A copy
// from a schema below current to a schema above it belongs to an upgrade that
// has not yet passed the database's schema: this upgrade, whichever release
// started it, or an attempt that was rolled back. For each pair of an upgrade
// limit and an earlier source schema, the newest such copy is therefore kept.
// The limit starts at current and descends to each protected copy's source
// schema. The same source schema can be protected at different limits, so the
// copy at the schema the previous release used stays among them even after a
// release with a later target took over and passed the first release's target.
// The running release's
// target does not decide, because a release with another target can take over
// a failing upgrade, and neither the timestamps nor the lowest source schema
// single that copy out, because a rolled-back attempt can leave a copy at a
// lower schema than the one this upgrade started from. written is kept too,
// even when a clock that is behind gives it an older timestamp. Every other
// copy, including earlier copies at current and those of finished upgrades,
// falls under keep: the newest keep of them by the UTC timestamp in their
// names remain, and of two equal timestamps the greater name counts as newer.
// The directory thus holds at most keep automatic copies plus the copy just
// written plus one per qualifying (limit, source schema) pair in the
// descending chain, so retries at one schema never grow it.
func prunePreUpgradeBackups(directory string, current, keep int, written string) ([]string, error) {
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
	// Newest first, so the first match for each earlier source schema at a
	// given limit is the newest of them. A protected copy's own schema becomes
	// another limit. If a later-target release takes over and passes the first
	// release's target, that earlier copy is still considered at the takeover's
	// source schema when its target is above that schema.
	protected := make(map[string]bool)
	type limitSource struct{ limit, from int }
	seen := make(map[limitSource]bool)
	for limits := []int{current}; len(limits) > 0; limits = limits[1:] {
		limit := limits[0]
		for _, file := range files {
			pair := limitSource{limit: limit, from: file.from}
			if file.from < limit && file.to > limit && !seen[pair] {
				seen[pair] = true
				protected[file.name] = true
				limits = append(limits, file.from)
			}
		}
	}
	var removed []string
	kept := 0
	for _, file := range files {
		if file.name == written || protected[file.name] {
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
