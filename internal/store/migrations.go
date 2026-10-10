package store

import (
	"cmp"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/scanner"
)

// schemaVersion is deliberately independent from the configuration version.
// The former describes on-disk compatibility; the latter describes YAML.
const schemaVersion = 66

// foreignKeysOffMigrations lists the schema versions that must run through
// applyMigrationForeignKeysOff because they rebuild a table that other tables
// reference with ON DELETE CASCADE, such as users, jobs, scanner_profiles or
// managed_notifications. Add a version here in the same change that adds its
// rebuild statements; applyMigration refuses the rebuild otherwise. No
// version after the baseline rebuilds such a table yet: schema 52, which
// gave the four root tables their tenant, is part of the baseline.
var foreignKeysOffMigrations = map[int]bool{}

// conditionalMigrationStatements lists the schema versions with statements
// that depend on the current schema, such as a table rename that a repeated
// run must not apply a second time. The function reads the schema in the
// version's transaction and returns the statements to run after the fixed
// ones. These versions run through applyMigration.
var conditionalMigrationStatements = map[int]func(*sql.Tx) ([]string, error){
	// Schema 59's column may already be present in tests that reconstruct an
	// older migration from a newer template.
	59: migration59ConditionalStatements,
	// Schema 60's cadence column may already exist in a reconstructed test DB.
	60: migration60ConditionalStatements,
	// Schema 61 distinguishes inherited cadence defaults from saved cadence
	// preferences while migrating legacy every-scan defaults safely.
	61: migration61ConditionalStatements,
	// Schema 65's comparison column may already exist in a reconstructed
	// test DB.
	65: migration65ConditionalStatements,
	// Schema 66 replaces the latest-host guard triggers only where the
	// schema 54 copy has installed them.
	66: migration66ConditionalStatements,
}

// newerSchemaError is the refusal for a database that a newer release has
// upgraded. Migrations are forward-only, so an older binary must not write to
// a schema it does not know.
func newerSchemaError(version int) error {
	return fmt.Errorf("database schema version %d is newer than supported version %d", version, schemaVersion)
}

// ErrSchemaUpgradePending is the refusal of OpenExistingUpgraded and
// OpenReadOnlyExistingUpgraded for a database with an older schema. Only the
// daemon migrates, at its next start.
var ErrSchemaUpgradePending = errors.New("database schema upgrade pending")

// schemaUpgradePendingError names the schema version of a database that
// this release has not migrated yet.
type schemaUpgradePendingError struct {
	version int
}

func (e schemaUpgradePendingError) Error() string {
	return fmt.Sprintf("database schema version %d has not been upgraded to version %d yet", e.version, schemaVersion)
}

func (e schemaUpgradePendingError) Is(target error) bool {
	return target == ErrSchemaUpgradePending
}

// olderSchemaError is the refusal of an open that does not migrate for a
// database with an older schema: the daemon migrates it at its next start,
// unless the schema is older than this release upgrades.
func olderSchemaError(version int) error {
	if version < minimumUpgradeSchema {
		return schemaBelowUpgradeFloorError{version: version}
	}
	return schemaUpgradePendingError{version: version}
}

func migrate(db *sql.DB) error {
	return migrateContext(context.Background(), db)
}

func migrateContext(ctx context.Context, db *sql.DB) error {
	return migrateContextWithLogger(ctx, db, nil)
}

func migrateContextWithLogger(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	// Refuse a schema that this release does not migrate, newer than it or
	// older than minimumUpgradeSchema, before anything writes: the schema
	// marker and startup_state stay as they are.
	version, err := checkUpgradableSchemaContext(ctx, db)
	if err != nil {
		return err
	}
	if err := ensureStartupStateContext(ctx, db); err != nil {
		return err
	}
	from := version
	migrations := schemaMigrationStatements()
	// Mark the complete startup reconciliation as active, not only the DDL
	// steps. FTS and other resumable backfills can be the longest part of an
	// upgrade even when the schema marker is already current.
	if err := markMigrationStarted(ctx, db, version, schemaVersion); err != nil {
		return err
	}
	logger.Info("database migration started", "from_schema", version, "to_schema", schemaVersion)
	if version == 0 {
		// A new database starts from the frozen schema 54 baseline.
		if err := applyBaselineSchema(ctx, db); err != nil {
			markMigrationFailed(ctx, db, err)
			return err
		}
		version = minimumUpgradeSchema
		if err := updateMigrationStatus(ctx, db, "schema", int64(version), int64(schemaVersion)); err != nil {
			markMigrationFailed(ctx, db, err)
			return err
		}
		logger.Info("database migration step completed", "schema", version, "target_schema", schemaVersion)
	}
	for next := version + 1; next <= schemaVersion; next++ {
		statements, ok := migrations[next]
		if !ok {
			err := fmt.Errorf("missing migration for schema version %d", next)
			markMigrationFailed(ctx, db, err)
			return err
		}
		if err := runMigration(ctx, db, next, statements, foreignKeysOffMigrations[next]); err != nil {
			markMigrationFailed(ctx, db, err)
			return err
		}
		version = next
		if err := updateMigrationStatus(ctx, db, "schema", int64(version), int64(schemaVersion)); err != nil {
			markMigrationFailed(ctx, db, err)
			return err
		}
		logger.Info("database migration step completed", "schema", version, "target_schema", schemaVersion)
	}
	// Copy the latest host projection into its tenant-keyed table first. Until
	// the copy completes, the table has no search triggers and refuses other
	// writes, and the phases below that repair or index it wait for the copy.
	if err := updateMigrationStatus(ctx, db, latestScanHostsTenantPhase, 0, 0); err != nil {
		markMigrationFailed(ctx, db, err)
		return err
	}
	if err := rekeyLatestScanHostsByTenantContext(ctx, db, func(processed, total int64) {
		// The callback runs after each committed batch. Progress bookkeeping
		// is diagnostic only and never fails the migration.
		statusCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		_ = updateMigrationStatus(statusCtx, db, latestScanHostsTenantPhase, processed, total)
		cancel()
	}); err != nil {
		markMigrationFailed(ctx, db, err)
		return fmt.Errorf("key the latest host projection by tenant: %w", err)
	}
	if err := updateMigrationStatus(ctx, db, "timestamp-normalization", 0, 0); err != nil {
		markMigrationFailed(ctx, db, err)
		return err
	}
	if err := normalizePersistedTimestampsContextWithProgress(ctx, db, func(column timestampColumn, processed int64) {
		statusCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		_ = updateMigrationStatus(statusCtx, db, "timestamp-normalization:"+column.table+"."+column.column, processed, 0)
		cancel()
	}); err != nil {
		markMigrationFailed(ctx, db, err)
		return fmt.Errorf("normalize persisted timestamps: %w", err)
	}
	if err := repairScanHostsForeignKeyContext(ctx, db); err != nil {
		markMigrationFailed(ctx, db, err)
		return fmt.Errorf("repair scan host foreign key: %w", err)
	}
	if err := updateMigrationStatus(ctx, db, "scan-cycle-identities", int64(version), int64(schemaVersion)); err != nil {
		markMigrationFailed(ctx, db, err)
		return err
	}
	if err := backfillScanCycleUnitIdentitiesContextWithProgress(ctx, db, func(processed int64) {
		statusCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		_ = updateMigrationStatus(statusCtx, db, "scan-cycle-identities", processed, 0)
		cancel()
	}); err != nil {
		markMigrationFailed(ctx, db, err)
		return err
	}
	if err := updateMigrationStatus(ctx, db, "host-search", 0, 0); err != nil {
		markMigrationFailed(ctx, db, err)
		return err
	}
	if err := backfillHostSearchIndexesContextWithProgress(ctx, db, func(progress ftsBatchProgress) {
		// Progress bookkeeping is diagnostic only. Never make an otherwise
		// healthy migration fail because a status write was interrupted.
		statusCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		_ = updateMigrationStatus(statusCtx, db, "host-search:"+progress.table, int64(progress.processedRows), 0)
		cancel()
	}, logger); err != nil {
		markMigrationFailed(ctx, db, err)
		return err
	}
	if err := updateMigrationStatus(ctx, db, "legacy-host-index", 0, 0); err != nil {
		markMigrationFailed(ctx, db, err)
		return err
	}
	if err := backfillLegacyScanHostsContextWithLoggerAndProgress(ctx, db, logger, func(processed, total int64) {
		// Progress bookkeeping is diagnostic only. Never make an otherwise
		// healthy migration fail because a status write was interrupted. The
		// callback runs after each bounded transaction has committed, so the
		// persisted counter never claims work that can still be rolled back.
		statusCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		_ = updateMigrationStatus(statusCtx, db, "legacy-host-index", processed, total)
		cancel()
	}, defaultLegacyHostBackfillLimits); err != nil {
		markMigrationFailed(ctx, db, err)
		return err
	}
	if err := updateMigrationStatus(ctx, db, "scanner-profiles", 0, 0); err != nil {
		markMigrationFailed(ctx, db, err)
		return err
	}
	if err := ensureBuiltinScannerProfilesContext(ctx, db); err != nil {
		markMigrationFailed(ctx, db, err)
		return err
	}
	if err := markMigrationReady(ctx, db); err != nil {
		markMigrationFailed(ctx, db, err)
		return err
	}
	if from < schemaVersion {
		truncateWriteAheadLog(ctx, db)
	}
	logger.Info("database migration completed", "schema", version)
	return nil
}

// truncateWriteAheadLog checkpoints the write-ahead log and truncates it after
// an upgrade. SQLite reuses the log from its start after a checkpoint but
// keeps the file at the size of the largest transaction it held, so a large
// upgrade step would otherwise leave a log of that size beside the database
// while the daemon runs. It is best effort: a reader that holds an older
// snapshot keeps the log until the next checkpoint, and an error only means
// the file keeps its size.
func truncateWriteAheadLog(ctx context.Context, db *sql.DB) {
	var busy, logFrames, checkpointed int
	_ = db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed)
}

// schemaMigrationStatements returns the statements of each schema version
// after the baseline, keyed by the version they upgrade to. A new database
// starts from the schema 54 baseline, see applyBaselineSchema; the
// migrations from schema 1 to 54 are retired with the upgrade floor.
func schemaMigrationStatements() map[int][]string {
	return map[int][]string{
		// The cleanup after the tenants that earlier releases deleted is
		// recorded as pending, and the daemon's purge worker runs it. See
		// migration55.go.
		55: migration55Statements(),
		// The cleanup after deleted tenants is recorded as pending again, at
		// its overwrite of free pages, in a database without incremental
		// auto-vacuum. See migration56.go.
		56: migration56Statements(),
		// Tenants record whether they have a high-cost grant, and the
		// automatic ceiling of a tenant whose capacity no platform
		// administrator saved is no longer one. See migration57.go.
		57: migration57Statements(),
		// Rebuild bounded host-search documents so late service identifiers
		// remain searchable after the prioritized index format change. See
		// migration58.go.
		58: migration58Statements(),
		// Per-business-unit incident reminders default on for existing and new installations.
		59: {},
		// Units can bound persistent-incident reminders while preserving legacy every-scan defaults.
		60: {},
		// Inherited every-scan reminder cadence becomes hourly unless a prior
		// settings audit record indicates an administrator may have saved it.
		61: {},
		62: migration62Statements(),
		// Terminalize delivery rows that exhausted the former eight-attempt
		// policy before schema 31 could record terminal state.
		63: migration63Statements(),
		// Expired restore quarantine entries by retention timestamp without
		// rescanning the full quarantine table for each bounded delete batch.
		64: migration64Statements(),
		// Scans record their comparison outcome at finalization, so baseline
		// samples are no longer reported as failed or diffed against a later
		// baseline. See migration65.go.
		65: {},
		// The scan history indexes hold the tenant, job and cycle outcome
		// that history reads test, and the legacy host index backfill
		// records its completion. See migration66.go.
		66: migration66Statements(),
	}
}

// applyMigration applies one schema version in one transaction with foreign
// key enforcement on, as every version runs that is not listed in
// foreignKeysOffMigrations. It refuses a DROP TABLE of a table that another
// table references, see refuseReferencedTableDrop. Keeping this in a helper
// avoids accumulating deferred rollbacks while a database is upgraded
// through many versions.
func applyMigration(ctx context.Context, db *sql.DB, version int, statements []string) error {
	tx, err := beginSchemaStep(ctx, db, version-1, version)
	if err != nil {
		return fmt.Errorf("schema migration %d: %w", version, err)
	}
	defer func() { _ = tx.Rollback() }()
	run := func(statements []string) error {
		for _, statement := range statements {
			if err := refuseReferencedTableDrop(ctx, tx, version, statement); err != nil {
				return err
			}
			if err := execMigrationStatement(tx, statement); err != nil {
				return err
			}
		}
		return nil
	}
	if err := run(statements); err != nil {
		return err
	}
	if conditional := conditionalMigrationStatements[version]; conditional != nil {
		extra, err := conditional(tx)
		if err != nil {
			return err
		}
		if err := run(extra); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		return err
	}
	return tx.Commit()
}

// beginSchemaStep begins the transaction of the schema step from schema from
// to schema to. It takes the write lock with its first statement and then
// reads the schema marker, which must still be from: the step fails instead
// of running a second time, or over a newer schema, when another process has
// migrated the database since this one read its version. The migration
// guard keeps a second process out; this check holds where the guard is
// unavailable.
func beginSchemaStep(ctx context.Context, beginner txBeginner, from, to int) (*sql.Tx, error) {
	tx, err := beginWriteTx(ctx, beginner)
	if err != nil {
		return nil, err
	}
	var current int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if current != from {
		_ = tx.Rollback()
		return nil, fmt.Errorf("the database is at schema %d, not %d; another process is migrating it", current, from)
	}
	return tx, nil
}

// dropTablePattern finds the table that each DROP TABLE in a migration
// statement names.
var dropTablePattern = regexp.MustCompile(`(?i)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:main\s*\.\s*)?["\x60\[]?([A-Za-z_][A-Za-z0-9_]*)`)

// refuseReferencedTableDrop refuses a DROP TABLE, in a version that runs
// through applyMigration, of a table that another table references with a
// foreign key. With enforcement on, as on every pooled connection, DROP
// TABLE first deletes the table's rows, and the foreign key actions delete
// or change the rows that reference them: ON DELETE CASCADE empties the
// child tables without an error. Rebuild such a table with
// sqliteTableRebuild in a version listed in foreignKeysOffMigrations, whose
// runner turns enforcement off and checks foreign_key_check before it
// commits.
func refuseReferencedTableDrop(ctx context.Context, tx *sql.Tx, version int, statement string) error {
	for _, match := range dropTablePattern.FindAllStringSubmatch(statement, -1) {
		table := match[1]
		var referencing string
		err := tx.QueryRowContext(ctx, `SELECT m.name FROM sqlite_master AS m, pragma_foreign_key_list(m.name) AS f
WHERE m.type='table' AND m.name<>?1 COLLATE NOCASE AND f."table"=?1 COLLATE NOCASE
 AND EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 COLLATE NOCASE)
ORDER BY m.name LIMIT 1`, table).Scan(&referencing)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("schema migration %d drops table %s, which %s references with a foreign key: with foreign keys on, the drop would delete or change the referencing rows; list the version in foreignKeysOffMigrations", version, table, referencing)
	}
	return nil
}

// runMigration applies one schema version with the runner it needs: versions
// listed in foreignKeysOffMigrations run with foreign key enforcement off,
// and every other version uses the plain transactional runner.
func runMigration(ctx context.Context, db *sql.DB, version int, statements []string, foreignKeysOff bool) error {
	if foreignKeysOff {
		return applyMigrationForeignKeysOff(ctx, db, version, statements)
	}
	return applyMigration(ctx, db, version, statements)
}

// foreignKeysRestoreTimeout bounds re-enabling foreign keys on a pinned
// migration connection. The restore must still run when the migration context
// has been cancelled, so it uses its own deadline.
const foreignKeysRestoreTimeout = 5 * time.Second

// maxReportedForeignKeyViolations bounds the examples in a rebuild error.
const maxReportedForeignKeyViolations = 5

// applyMigrationForeignKeysOff applies one schema version with foreign key
// enforcement turned off. Use it, by listing the version in
// foreignKeysOffMigrations, for every version that rebuilds a table that
// other tables reference.
//
// applyMigration cannot run such a rebuild. Every pooled connection runs with
// PRAGMA foreign_keys=ON, and SQLite ignores PRAGMA foreign_keys while a
// transaction is open, so a statement in applyMigration cannot turn it off.
// With enforcement on, DROP TABLE performs an implicit DELETE that fires the
// ON DELETE CASCADE actions of the child tables, so rebuilding users, jobs,
// scanner_profiles or managed_notifications there would delete rows such as
// user_invites, totp_replay, the job history tables and
// scanner_profile_revisions.
//
// This runner pins one connection and turns enforcement off on it before the
// transaction starts. It records the existing PRAGMA foreign_key_check
// violations, because old databases and recovery fixtures may already hold
// orphaned rows. It then runs the statements through execMigrationStatement
// in one transaction and checks the foreign keys again. The migration fails
// and rolls back only when the statements added a violation. Last, the runner
// turns enforcement back on and reads it back. A connection on which that
// fails is closed instead of being returned to the pool.
//
// Write each rebuild in SQLite's documented order
// (https://www.sqlite.org/lang_altertable.html#otheralter), which
// sqliteTableRebuild generates:
//
//	DROP VIEW v; DROP TRIGGER t      -- views and other tables' triggers that reference X
//	CREATE TABLE X_next (...)        -- the new definition
//	INSERT INTO X_next(rowid, a, b) SELECT rowid, a, b FROM X
//	DROP TABLE X
//	ALTER TABLE X_next RENAME TO X
//	CREATE INDEX ...; CREATE TRIGGER ...  -- X's indexes and triggers went with the old table
//	CREATE VIEW v ...; CREATE TRIGGER t ...
//
// Do not rename X out of the way first (X to X_old, then X_next to X). SQLite
// rewrites the REFERENCES clauses of the child tables to follow a rename, so
// the children would point at X_old and lose their parent when it is dropped.
func applyMigrationForeignKeysOff(ctx context.Context, db *sql.DB, version int, statements []string) (err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("schema migration %d: pin connection: %w", version, err)
	}
	// Runs after the transaction below has been committed or rolled back.
	defer func() {
		err = errors.Join(err, releaseForeignKeysOffConn(ctx, conn, version))
	}()
	if err := setConnForeignKeys(ctx, conn, false); err != nil {
		return fmt.Errorf("schema migration %d: turn off foreign keys: %w", version, err)
	}
	// The transaction is deliberately not bound to ctx. database/sql rolls
	// back a context-bound transaction from another goroutine when ctx is
	// cancelled, and that rollback could still be pending when the deferred
	// release turns foreign keys back on, which SQLite ignores inside a
	// transaction. Cancellation is checked between statements instead, and
	// the deferred rollback runs synchronously.
	tx, err := beginSchemaStep(context.WithoutCancel(ctx), conn, version-1, version)
	if err != nil {
		return fmt.Errorf("schema migration %d: %w", version, err)
	}
	defer func() { _ = tx.Rollback() }()
	before, err := foreignKeyViolationCounts(ctx, tx)
	if err != nil {
		return fmt.Errorf("schema migration %d: check foreign keys before the rebuild: %w", version, err)
	}
	for _, statement := range statements {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("schema migration %d: %w", version, err)
		}
		if err := execMigrationStatement(tx, statement); err != nil {
			return fmt.Errorf("schema migration %d: %w", version, err)
		}
	}
	after, err := foreignKeyViolationCounts(ctx, tx)
	if err != nil {
		return fmt.Errorf("schema migration %d: check foreign keys after the rebuild: %w", version, err)
	}
	if introduced := introducedForeignKeyViolations(before, after); len(introduced) > 0 {
		return fmt.Errorf("schema migration %d rolled back: it would add %d foreign key violation(s): %s", version, len(introduced), describeForeignKeyViolations(introduced))
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		return fmt.Errorf("schema migration %d: %w", version, err)
	}
	return tx.Commit()
}

// releaseForeignKeysOffConn turns foreign key enforcement back on for a
// connection pinned by applyMigrationForeignKeysOff and returns it to the
// pool. When enforcement cannot be confirmed, it discards the connection
// instead: database/sql closes a connection whose Raw callback reports
// driver.ErrBadConn, and the connector turns enforcement on for any
// replacement it opens. Either way no pooled connection keeps running with
// foreign keys off.
func releaseForeignKeysOffConn(ctx context.Context, conn *sql.Conn, version int) error {
	restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), foreignKeysRestoreTimeout)
	defer cancel()
	restoreErr := setConnForeignKeys(restoreCtx, conn, true)
	if restoreErr == nil {
		return conn.Close()
	}
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
	return fmt.Errorf("schema migration %d: turn foreign keys back on: %w; the connection was closed", version, restoreErr)
}

// setConnForeignKeys sets foreign key enforcement on one connection and reads
// it back. SQLite silently ignores the PRAGMA inside a transaction, so only
// the read-back proves the setting took effect.
func setConnForeignKeys(ctx context.Context, conn *sql.Conn, enabled bool) error {
	statement, want := "PRAGMA foreign_keys=OFF", 0
	if enabled {
		statement, want = "PRAGMA foreign_keys=ON", 1
	}
	if _, err := conn.ExecContext(ctx, statement); err != nil {
		return err
	}
	var got int
	if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&got); err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("PRAGMA foreign_keys is %d after setting it to %d", got, want)
	}
	return nil
}

// foreignKeyViolation identifies one row reported by PRAGMA foreign_key_check.
// It leaves out the foreign key index on purpose: a rebuild may reorder a
// table's constraints, which renumbers them without orphaning another row.
// Counting each key still catches a second broken reference from the same row.
// rowID is NULL for a WITHOUT ROWID table.
type foreignKeyViolation struct {
	table  string
	rowID  sql.NullInt64
	parent string
}

type migrationQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// foreignKeyViolationCounts returns how often PRAGMA foreign_key_check reports
// each violation.
func foreignKeyViolationCounts(ctx context.Context, queryer migrationQueryer) (map[foreignKeyViolation]int, error) {
	rows, err := queryer.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	counts := make(map[foreignKeyViolation]int)
	for rows.Next() {
		var violation foreignKeyViolation
		var foreignKey sql.NullInt64
		if err := rows.Scan(&violation.table, &violation.rowID, &violation.parent, &foreignKey); err != nil {
			return nil, err
		}
		counts[violation]++
	}
	return counts, rows.Err()
}

// introducedForeignKeyViolations returns the violations in after that before
// did not already contain, in a stable order.
func introducedForeignKeyViolations(before, after map[foreignKeyViolation]int) []foreignKeyViolation {
	var introduced []foreignKeyViolation
	for violation, count := range after {
		for extra := count - before[violation]; extra > 0; extra-- {
			introduced = append(introduced, violation)
		}
	}
	slices.SortFunc(introduced, func(a, b foreignKeyViolation) int {
		return cmp.Or(
			cmp.Compare(a.table, b.table),
			cmp.Compare(a.parent, b.parent),
			cmp.Compare(a.rowID.Int64, b.rowID.Int64),
		)
	})
	return introduced
}

func describeForeignKeyViolations(violations []foreignKeyViolation) string {
	parts := make([]string, 0, min(len(violations), maxReportedForeignKeyViolations)+1)
	for _, violation := range violations[:min(len(violations), maxReportedForeignKeyViolations)] {
		row := "row"
		if violation.rowID.Valid {
			row = fmt.Sprintf("row %d", violation.rowID.Int64)
		}
		parts = append(parts, fmt.Sprintf("%s %s references a missing %s row", violation.table, row, violation.parent))
	}
	if hidden := len(violations) - maxReportedForeignKeyViolations; hidden > 0 {
		parts = append(parts, fmt.Sprintf("and %d more", hidden))
	}
	return strings.Join(parts, "; ")
}

// sqliteTableRebuild describes one table rebuild in SQLite's documented order
// (https://www.sqlite.org/lang_altertable.html#otheralter). A rebuild is the
// only way to change a column's type or constraints, or a table's foreign
// keys. Run its statements through applyMigrationForeignKeysOff: under
// applyMigration, DROP TABLE would cascade into the child tables.
//
// The copy keeps each row's rowid, so rowid-keyed search projections and
// violations that existed before the rebuild still line up afterwards. It
// cannot rebuild a WITHOUT ROWID table, and it does not carry an
// AUTOINCREMENT high-water mark over to the new table. The planned parent
// tables use neither.
type sqliteTableRebuild struct {
	// table is the table to rebuild, X in the pattern.
	table string
	// definition is the body of the new CREATE TABLE statement: the column
	// and constraint definitions between the parentheses. A foreign key that
	// references the table itself names X, not X_next.
	definition string
	// columns lists the columns copied from the old table. Each must exist in
	// both definitions. New columns take their DEFAULT unless fill sets them.
	columns []string
	// fill sets new columns from an SQL expression over the old row, for a
	// column that must not have a DEFAULT, such as the owner of a row. The
	// expression is part of the migration source, never user input.
	fill []sqliteRebuildFill
	// dropDependents drops the views, and the triggers on other tables, whose
	// SQL references X. ALTER TABLE ... RENAME re-parses the whole schema and
	// fails while any of them refers to the dropped table. Triggers on X itself
	// are dropped with it. The tenant guard triggers on scans, events and
	// public_dashboard_hosts read jobs, tenants and public_dashboards, and the
	// latest-host guard triggers read scans and tenants, so a rebuild of one
	// of those tables drops and recreates them; their SQL is in the baseline
	// and in latestScanHostsTenantTriggerSQL.
	dropDependents []string
	// recreate runs after the rename. It creates the indexes and triggers of X
	// and the views and triggers removed by dropDependents.
	recreate []string
}

// sqliteRebuildFill sets one new column of a rebuilt table.
type sqliteRebuildFill struct {
	// column is the new column. It must not exist in the old table.
	column string
	// expression computes the value from the old row, for example a string
	// literal or a CASE over the copied columns.
	expression string
}

// statements returns the rebuild in migration order. It panics on an invalid
// description: the fields are constants in the migration source, so every
// store test that migrates a database reports the mistake.
func (r sqliteTableRebuild) statements() []string {
	if !validMigrationIdentifier(r.table) {
		panic(fmt.Sprintf("table rebuild: invalid table name %q", r.table))
	}
	if strings.TrimSpace(r.definition) == "" {
		panic(fmt.Sprintf("table rebuild of %s: empty definition", r.table))
	}
	if len(r.columns) == 0 {
		panic(fmt.Sprintf("table rebuild of %s: no columns to copy", r.table))
	}
	for _, column := range r.columns {
		if !validMigrationIdentifier(column) || strings.EqualFold(column, "rowid") {
			panic(fmt.Sprintf("table rebuild of %s: invalid column name %q", r.table, column))
		}
	}
	targets := slices.Clone(r.columns)
	values := slices.Clone(r.columns)
	for _, fill := range r.fill {
		if !validMigrationIdentifier(fill.column) || strings.EqualFold(fill.column, "rowid") || slices.ContainsFunc(targets, func(column string) bool { return strings.EqualFold(column, fill.column) }) {
			panic(fmt.Sprintf("table rebuild of %s: invalid fill column %q", r.table, fill.column))
		}
		if strings.TrimSpace(fill.expression) == "" {
			panic(fmt.Sprintf("table rebuild of %s: empty fill expression for %s", r.table, fill.column))
		}
		targets = append(targets, fill.column)
		values = append(values, fill.expression)
	}
	next := r.table + "_next"
	statements := make([]string, 0, len(r.dropDependents)+4+len(r.recreate))
	statements = append(statements, r.dropDependents...)
	statements = append(statements,
		"CREATE TABLE "+next+" ("+r.definition+")",
		"INSERT INTO "+next+"(rowid, "+strings.Join(targets, ", ")+") SELECT rowid, "+strings.Join(values, ", ")+" FROM "+r.table,
		"DROP TABLE "+r.table,
		"ALTER TABLE "+next+" RENAME TO "+r.table,
	)
	return append(statements, r.recreate...)
}

// execMigrationStatement handles the only intentionally repeatable DDL in
// the migration set (ALTER TABLE ... ADD COLUMN) by inspecting SQLite's
// schema first. Suppressing arbitrary errors based on driver error text would
// hide real migration failures and is not stable across SQLite versions.
func execMigrationStatement(tx *sql.Tx, statement string) error {
	if table, column, ok := parseAddColumnStatement(statement); ok {
		exists, err := migrationColumnExists(tx, table, column)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
	}
	_, err := tx.Exec(statement)
	return err
}

func parseAddColumnStatement(statement string) (table, column string, ok bool) {
	fields := strings.Fields(statement)
	if len(fields) < 6 || !strings.EqualFold(fields[0], "ALTER") || !strings.EqualFold(fields[1], "TABLE") || !strings.EqualFold(fields[3], "ADD") || !strings.EqualFold(fields[4], "COLUMN") {
		return "", "", false
	}
	table = strings.Trim(fields[2], "`\"")
	column = strings.Trim(fields[5], "`\"")
	if !validMigrationIdentifier(table) || !validMigrationIdentifier(column) {
		return "", "", false
	}
	return table, column, true
}

func validMigrationIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func migrationColumnExists(tx *sql.Tx, table, column string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM pragma_table_info('" + table + "') WHERE name='" + column + "'"
	if err := tx.QueryRow(query).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// backfillScanCycleUnitIdentitiesContext upgrades rows created before schema
// 32 in bounded writer transactions. It intentionally runs after the schema
// marker is committed: if a process stops midway, the next open resumes from
// the remaining empty identities without replaying any scanner work.
func backfillScanCycleUnitIdentitiesContext(ctx context.Context, db *sql.DB) error {
	return backfillScanCycleUnitIdentitiesContextWithProgress(ctx, db, nil)
}

// backfillScanCycleUnitIdentitiesContextWithProgress keeps the legacy wrapper
// available for callers and tests while allowing startup to refresh its
// migration heartbeat after each committed bounded batch.
func backfillScanCycleUnitIdentitiesContextWithProgress(ctx context.Context, db *sql.DB, observer func(int64)) error {
	var processed int64
	for {
		// Each batch reads its checkpoint before it writes, so it takes the
		// write lock first.
		tx, err := beginWriteTx(ctx, db)
		if err != nil {
			return err
		}
		var complete int
		if err := tx.QueryRowContext(ctx, `SELECT complete FROM scan_cycle_identity_backfill WHERE id=1`).Scan(&complete); err != nil {
			_ = tx.Rollback()
			return err
		}
		if complete != 0 {
			return tx.Commit()
		}
		rows, err := tx.QueryContext(ctx, `SELECT rowid,work_unit_json FROM scan_cycle_units WHERE identity='' ORDER BY rowid LIMIT 256`)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		type row struct {
			rowID int64
			raw   []byte
		}
		batch, batchErr := func() ([]row, error) {
			defer rows.Close()
			batch := make([]row, 0, 256)
			for rows.Next() {
				var item row
				if err := rows.Scan(&item.rowID, &item.raw); err != nil {
					return nil, err
				}
				batch = append(batch, item)
			}
			if err := rows.Err(); err != nil {
				return nil, err
			}
			return batch, nil
		}()
		if batchErr != nil {
			_ = tx.Rollback()
			return batchErr
		}
		if len(batch) == 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE scan_cycle_identity_backfill SET complete=1,updated_at=? WHERE id=1`, sqliteTimestamp(time.Now())); err != nil {
				_ = tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			return nil
		}
		for _, item := range batch {
			var unit scanner.WorkUnit
			if err := json.Unmarshal(item.raw, &unit); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("backfill scan cycle unit identity: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE scan_cycle_units SET identity=? WHERE rowid=? AND identity=''`, scanCycleUnitIdentity(unit), item.rowID); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		processed += int64(len(batch))
		if observer != nil {
			observer(processed)
		}
	}
}
