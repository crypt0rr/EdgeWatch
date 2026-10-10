package store

import (
	"context"
	"database/sql"
	"fmt"
)

// txBeginner is a *sql.DB or a pinned *sql.Conn.
type txBeginner interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

// beginWriteTx begins a transaction that holds SQLite's write lock from its
// first statement, for startup work that reads before it writes, such as a
// backfill that reads its checkpoint or a schema step that reads the schema
// marker. SQLite does not run the busy handler when a transaction that has
// already read asks for the write lock, so a deferred transaction that reads
// first fails at once with SQLITE_BUSY while another connection writes, for
// example a host command run beside the daemon. A first statement that
// writes waits up to busy_timeout instead.
//
// That statement is an UPDATE of startup_state that matches no row, so it
// changes nothing. The migration creates startup_state before any other
// work, so every database that a schema step or a startup backfill touches
// has it.
func beginWriteTx(ctx context.Context, beginner txBeginner) (*sql.Tx, error) {
	tx, err := beginner.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE startup_state SET rowid=rowid WHERE 0`); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("take the database write lock: %w", err)
	}
	return tx, nil
}
