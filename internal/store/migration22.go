package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// ftsBackfillBatchSize keeps upgrade work bounded. The progress marker is
// updated in the same transaction as each batch, so an interrupted startup can
// resume without duplicating rows or replaying the whole retained history.
const ftsBackfillBatchSize = 500

var scanHostSearchTriggerNames = []string{
	"scan_hosts_search_ai",
	"scan_hosts_search_au",
	"scan_hosts_search_ad",
	"latest_scan_hosts_search_ai",
	"latest_scan_hosts_search_au",
	"latest_scan_hosts_search_ad",
}

// repairScanHostsForeignKey repairs databases created by the migration-15
// recovery fallback before the fallback included the source-row cascade. SQLite
// cannot add a foreign key to an existing table, so only tables that are
// missing the exact scans(id) ON DELETE CASCADE constraint are rebuilt.
func repairScanHostsForeignKey(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	rollback := func() error {
		_ = tx.Rollback()
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var tableCount int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='scan_hosts'`).Scan(&tableCount); err != nil {
		return rollback()
	}
	if tableCount == 0 {
		if err = tx.Commit(); err != nil {
			return err
		}
		return nil
	}
	hasCascade, err := scanHostsHasCascadeTx(tx)
	if err != nil {
		return rollback()
	}
	if hasCascade {
		if err = tx.Commit(); err != nil {
			return err
		}
		return nil
	}

	columns, err := tableColumnsTx(tx, "scan_hosts")
	if err != nil {
		return rollback()
	}
	for _, required := range []string{"scan_id", "address", "host_json"} {
		if !columns[required] {
			err = fmt.Errorf("scan_hosts is missing required column %q", required)
			return rollback()
		}
	}
	if err = dropHostSearchTriggersTx(tx); err != nil {
		return rollback()
	}
	// A row without a source scan cannot be retained once the cascade is
	// repaired. Such rows are only possible in a partially recovered database;
	// remove them while the source table is being rebuilt rather than failing the
	// entire upgrade on the new constraint.
	if _, err = tx.Exec(`DELETE FROM scan_hosts WHERE NOT EXISTS (SELECT 1 FROM scans WHERE scans.id=scan_hosts.scan_id)`); err != nil {
		return rollback()
	}
	if _, err = tx.Exec(`DROP TABLE IF EXISTS scan_hosts_repair`); err != nil {
		return rollback()
	}
	if _, err = tx.Exec(scanHostsRepairTableSQL); err != nil {
		return rollback()
	}

	allColumns := []string{
		"scan_id", "address", "job", "address_family", "source_targets_json", "dns_names_json",
		"host_json", "data_quality", "open_ports", "open_filtered_ports", "tcp_present", "udp_present",
		"tcp_open_ports", "tcp_open_filtered_ports", "udp_open_ports", "udp_open_filtered_ports",
	}
	if columns["search_text"] {
		allColumns = append(allColumns[:7], append([]string{"search_text"}, allColumns[7:]...)...)
	}
	columnList := strings.Join(allColumns, ",")
	if _, err = tx.Exec(`INSERT INTO scan_hosts_repair(` + columnList + `) SELECT ` + columnList + ` FROM scan_hosts`); err != nil {
		return rollback()
	}
	if _, err = tx.Exec(`DROP TABLE scan_hosts`); err != nil {
		return rollback()
	}
	if _, err = tx.Exec(`ALTER TABLE scan_hosts_repair RENAME TO scan_hosts`); err != nil {
		return rollback()
	}
	for _, statement := range []string{
		"CREATE INDEX IF NOT EXISTS scan_hosts_address ON scan_hosts(address)",
		"CREATE INDEX IF NOT EXISTS scan_hosts_scan_address ON scan_hosts(scan_id, address)",
		"CREATE INDEX IF NOT EXISTS scan_hosts_job_address ON scan_hosts(job, address)",
		"CREATE INDEX IF NOT EXISTS scan_hosts_open ON scan_hosts(open_ports, open_filtered_ports)",
	} {
		if _, err = tx.Exec(statement); err != nil {
			return rollback()
		}
	}
	if err = ensureHostSearchSchemaTx(tx, true); err != nil {
		return rollback()
	}
	// Force the bounded rebuild to run after the source table was replaced. The
	// state table is created by migration 22, but this update is harmless when a
	// recovery fixture already carried it.
	if _, err = tx.Exec(`UPDATE fts_backfill_state SET last_rowid=0, processed_rows=0, initialized=0, complete=0, updated_at=?`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return rollback()
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

const scanHostsRepairTableSQL = `CREATE TABLE scan_hosts_repair (
 scan_id TEXT NOT NULL,
 address TEXT NOT NULL,
 job TEXT NOT NULL DEFAULT '',
 address_family TEXT NOT NULL DEFAULT '',
 source_targets_json BLOB NOT NULL DEFAULT '[]',
 dns_names_json BLOB NOT NULL DEFAULT '[]',
 host_json BLOB NOT NULL,
 search_text TEXT NOT NULL DEFAULT '',
 data_quality TEXT NOT NULL DEFAULT 'detailed',
 open_ports INTEGER NOT NULL DEFAULT 0,
 open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 tcp_present INTEGER NOT NULL DEFAULT 0,
 udp_present INTEGER NOT NULL DEFAULT 0,
 tcp_open_ports INTEGER NOT NULL DEFAULT 0,
 tcp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(scan_id, address),
 FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
)`

func scanHostsHasCascadeTx(tx *sql.Tx) (bool, error) {
	rows, err := tx.Query(`PRAGMA foreign_key_list(scan_hosts)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, seq int64
		var tableName, from, to, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &seq, &tableName, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			return false, err
		}
		if strings.EqualFold(tableName, "scans") && from == "scan_id" && to == "id" && strings.EqualFold(onDelete, "CASCADE") {
			return true, nil
		}
	}
	return false, rows.Err()
}

func tableColumnsTx(tx *sql.Tx, table string) (map[string]bool, error) {
	if table != "scan_hosts" && table != "latest_scan_hosts" {
		return nil, fmt.Errorf("unsupported table %q", table)
	}
	rows, err := tx.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int64
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	return columns, rows.Err()
}

func dropHostSearchTriggersTx(tx *sql.Tx) error {
	for _, name := range scanHostSearchTriggerNames {
		if _, err := tx.Exec(`DROP TRIGGER IF EXISTS ` + name); err != nil {
			return err
		}
	}
	return nil
}

// ensureHostSearchSchemaTx creates the bounded FTS projections and current
// search_text triggers. Recreating triggers is used only when repairing a
// source table or when a recovery fixture omitted them.
func ensureHostSearchSchemaTx(tx *sql.Tx, recreateTriggers bool) error {
	for _, statement := range []string{
		`CREATE VIRTUAL TABLE IF NOT EXISTS scan_host_search USING fts5(
 scan_id UNINDEXED,
 address UNINDEXED,
 content,
 tokenize='trigram'
);`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS latest_host_search USING fts5(
 address UNINDEXED,
 content,
 tokenize='trigram'
);`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	if recreateTriggers {
		if err := dropHostSearchTriggersTx(tx); err != nil {
			return err
		}
	}
	for _, statement := range currentHostSearchTriggerSQL {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

var currentHostSearchTriggerSQL = []string{
	`CREATE TRIGGER IF NOT EXISTS scan_hosts_search_ai AFTER INSERT ON scan_hosts BEGIN
 INSERT INTO scan_host_search(rowid,scan_id,address,content)
 VALUES(NEW.rowid,NEW.scan_id,NEW.address,lower(coalesce(NEW.search_text,'') || ' ' || coalesce(NEW.address,'') || ' ' || coalesce(NEW.job,'') || ' ' || coalesce(NEW.source_targets_json,'') || ' ' || coalesce(NEW.dns_names_json,'')));
END;`,
	`CREATE TRIGGER IF NOT EXISTS scan_hosts_search_au AFTER UPDATE ON scan_hosts BEGIN
 DELETE FROM scan_host_search WHERE rowid=OLD.rowid;
 INSERT INTO scan_host_search(rowid,scan_id,address,content)
 VALUES(NEW.rowid,NEW.scan_id,NEW.address,lower(coalesce(NEW.search_text,'') || ' ' || coalesce(NEW.address,'') || ' ' || coalesce(NEW.job,'') || ' ' || coalesce(NEW.source_targets_json,'') || ' ' || coalesce(NEW.dns_names_json,'')));
END;`,
	`CREATE TRIGGER IF NOT EXISTS scan_hosts_search_ad AFTER DELETE ON scan_hosts BEGIN
 DELETE FROM scan_host_search WHERE rowid=OLD.rowid;
END;`,
	`CREATE TRIGGER IF NOT EXISTS latest_scan_hosts_search_ai AFTER INSERT ON latest_scan_hosts BEGIN
 INSERT INTO latest_host_search(rowid,address,content)
 VALUES(NEW.rowid,NEW.address,lower(coalesce(NEW.search_text,'') || ' ' || coalesce(NEW.address,'') || ' ' || coalesce(NEW.job,'') || ' ' || coalesce(NEW.source_targets_json,'') || ' ' || coalesce(NEW.dns_names_json,'')));
END;`,
	`CREATE TRIGGER IF NOT EXISTS latest_scan_hosts_search_au AFTER UPDATE ON latest_scan_hosts BEGIN
 DELETE FROM latest_host_search WHERE rowid=OLD.rowid;
 INSERT INTO latest_host_search(rowid,address,content)
 VALUES(NEW.rowid,NEW.address,lower(coalesce(NEW.search_text,'') || ' ' || coalesce(NEW.address,'') || ' ' || coalesce(NEW.job,'') || ' ' || coalesce(NEW.source_targets_json,'') || ' ' || coalesce(NEW.dns_names_json,'')));
END;`,
	`CREATE TRIGGER IF NOT EXISTS latest_scan_hosts_search_ad AFTER DELETE ON latest_scan_hosts BEGIN
 DELETE FROM latest_host_search WHERE rowid=OLD.rowid;
END;`,
}

// backfillHostSearchIndexesContext rebuilds both FTS projections without
// making database-open work uncancellable. Each batch commits its checkpoint
// before returning, so a cancelled migration can be restarted without
// replaying already indexed rows.
func backfillHostSearchIndexesContext(ctx context.Context, db *sql.DB) error {
	return backfillHostSearchIndexesContextWithProgress(ctx, db, nil)
}

// backfillHostSearchIndexesContextWithProgress is the context-aware rebuild
// implementation. The observer is intentionally internal and is used by
// tests to cancel after a committed batch; production callers pass nil.
func backfillHostSearchIndexesContextWithProgress(ctx context.Context, db *sql.DB, observer func(ftsBatchProgress)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ensureHostSearchTriggersContext(ctx, db); err != nil {
		return err
	}
	if err := ensureFTSBackfillStateContext(ctx, db); err != nil {
		return err
	}
	if err := initializeFTSBackfillContext(ctx, db); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		scanProgress, err := backfillFTSTableBatchContext(ctx, db, "scan_hosts")
		if err != nil {
			return err
		}
		if observer != nil && scanProgress.batchRows > 0 {
			observer(scanProgress)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		latestProgress, err := backfillFTSTableBatchContext(ctx, db, "latest_scan_hosts")
		if err != nil {
			return err
		}
		if observer != nil && latestProgress.batchRows > 0 {
			observer(latestProgress)
		}
		if scanProgress.batchRows > 0 || scanProgress.complete {
			logFTSProgress(scanProgress)
		}
		if latestProgress.batchRows > 0 || latestProgress.complete {
			logFTSProgress(latestProgress)
		}
		if scanProgress.complete && latestProgress.complete {
			return nil
		}
	}
}

type ftsBatchProgress struct {
	table         string
	batchRows     int
	processedRows int
	lastRowID     int64
	complete      bool
}

func logFTSProgress(progress ftsBatchProgress) {
	// Migration logging is intentionally structured and cumulative. Operators
	// can distinguish a large, healthy rebuild from a migration that repeatedly
	// restarts at the same marker.
	slog.Default().Info("rebuilt host search index", "table", progress.table, "batch_rows", progress.batchRows, "processed_rows", progress.processedRows, "last_rowid", progress.lastRowID, "complete", progress.complete)
}

func ensureHostSearchTriggersContext(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(scanHostSearchTriggerNames)), ",")
	args := make([]any, len(scanHostSearchTriggerNames))
	for i, name := range scanHostSearchTriggerNames {
		args[i] = name
	}
	var triggerCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN (`+placeholders+`)`, args...).Scan(&triggerCount); err != nil {
		return err
	}
	if triggerCount < len(scanHostSearchTriggerNames) {
		if err := ensureHostSearchSchemaTx(tx, true); err != nil {
			return err
		}
		// A newly installed trigger set must see a complete rebuild. Ignore the
		// update only when this is the first startup before migration 22 creates
		// the progress table; ensureFTSBackfillState will create it immediately
		// afterwards.
		if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET last_rowid=0,processed_rows=0,initialized=0,complete=0,updated_at=?`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return err
		}
	}
	return tx.Commit()
}

func ensureFTSBackfillStateContext(ctx context.Context, db *sql.DB) error {
	// Keep schema creation separate from bookkeeping writes. A CREATE TABLE
	// IF NOT EXISTS inside a deferred transaction can be read-only when the
	// table already exists, leaving the first real write vulnerable to SQLite's
	// immediate deferred-transaction lock-upgrade failure. The autocommit DDL
	// and the write-first transaction both honor busy_timeout before any
	// checkpoint rows are touched.
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS fts_backfill_state (
 table_name TEXT PRIMARY KEY,
 last_rowid INTEGER NOT NULL DEFAULT 0,
 processed_rows INTEGER NOT NULL DEFAULT 0,
 initialized INTEGER NOT NULL DEFAULT 0,
 complete INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL
)`); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, tableName := range []string{"scan_hosts", "latest_scan_hosts"} {
		// This is intentionally the first statement in the transaction. Even
		// when the row already exists, INSERT OR IGNORE is a write attempt and
		// therefore waits for an active writer instead of upgrading a read
		// transaction after the busy handler has been bypassed.
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO fts_backfill_state(table_name,updated_at) VALUES(?,?)`, tableName, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func initializeFTSBackfillContext(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Acquire the write lock before reading the checkpoint. SQLite may reject
	// a deferred read-to-write upgrade immediately when another writer is
	// active, even with a busy timeout configured on the connection.
	if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET updated_at=updated_at WHERE table_name IN ('scan_hosts','latest_scan_hosts')`); err != nil {
		return err
	}
	var initialized int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MIN(initialized),0) FROM fts_backfill_state WHERE table_name IN ('scan_hosts','latest_scan_hosts')`).Scan(&initialized); err != nil {
		return err
	}
	if initialized == 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM scan_host_search`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM latest_host_search`); err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET last_rowid=0, processed_rows=0, initialized=1, complete=0, updated_at=? WHERE table_name IN ('scan_hosts','latest_scan_hosts')`, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type ftsHostRow struct {
	rowID int64
	job   string
	addr  string
	raw   []byte
}

func backfillFTSTableBatchContext(ctx context.Context, db *sql.DB, sourceTable string) (ftsBatchProgress, error) {
	progress := ftsBatchProgress{table: sourceTable}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return progress, err
	}
	defer func() { _ = tx.Rollback() }()
	// Checkpoint reads are followed by FTS/source-table writes below. Make the
	// lock acquisition explicit and write-first so a concurrent writer is
	// handled by SQLite's busy timeout rather than an immediate upgrade error.
	if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET updated_at=updated_at WHERE table_name=?`, sourceTable); err != nil {
		return progress, err
	}
	var lastRowID int64
	var complete, processedRows int
	if err := tx.QueryRowContext(ctx, `SELECT last_rowid,processed_rows,complete FROM fts_backfill_state WHERE table_name=?`, sourceTable).Scan(&lastRowID, &processedRows, &complete); err != nil {
		return progress, err
	}
	progress.lastRowID = lastRowID
	progress.processedRows = processedRows
	progress.complete = complete != 0
	if complete != 0 {
		if err := tx.Commit(); err != nil {
			return progress, err
		}
		return progress, nil
	}
	query := `SELECT rowid,job,address,host_json FROM ` + sourceTable + ` WHERE rowid>? ORDER BY rowid LIMIT ?`
	rows, err := tx.QueryContext(ctx, query, lastRowID, ftsBackfillBatchSize)
	if err != nil {
		return progress, err
	}
	defer func() { _ = rows.Close() }()
	var batch []ftsHostRow
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return progress, err
		}
		var row ftsHostRow
		if err := rows.Scan(&row.rowID, &row.job, &row.addr, &row.raw); err != nil {
			return progress, err
		}
		batch = append(batch, row)
	}
	if err := rows.Err(); err != nil {
		return progress, err
	}
	if len(batch) == 0 {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET complete=1,updated_at=? WHERE table_name=?`, now, sourceTable); err != nil {
			return progress, err
		}
		if err := tx.Commit(); err != nil {
			return progress, err
		}
		progress.complete = true
		return progress, nil
	}
	maxRowID := lastRowID
	for _, row := range batch {
		var host model.HostObservation
		if len(row.raw) > 0 {
			_ = json.Unmarshal(row.raw, &host)
		}
		host.Address = row.addr
		searchText := hostSearchContent(row.job, host)
		if _, err := tx.ExecContext(ctx, `UPDATE `+sourceTable+` SET search_text=? WHERE rowid=?`, searchText, row.rowID); err != nil {
			return progress, err
		}
		if row.rowID > maxRowID {
			maxRowID = row.rowID
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	processedRows += len(batch)
	if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET last_rowid=?,processed_rows=?,updated_at=? WHERE table_name=?`, maxRowID, processedRows, now, sourceTable); err != nil {
		return progress, err
	}
	if err := tx.Commit(); err != nil {
		return progress, err
	}
	progress.batchRows = len(batch)
	progress.lastRowID = maxRowID
	progress.processedRows = processedRows
	return progress, nil
}
