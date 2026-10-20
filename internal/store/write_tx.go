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
// first statement, for a transaction that reads before it writes: startup
// work, such as a backfill that reads its checkpoint or a schema step that
// reads the schema marker, and a write that a host command or the scan it
// runs makes beside the daemon, such as a setup token, an account recovery,
// a baseline decision or a scan cycle transition, which checks the current
// state first. SQLite does not run the busy handler when a transaction that
// has already read asks for the write lock, so a deferred transaction that
// reads first fails at once with SQLITE_BUSY while another connection
// writes, as the daemon and a host command run beside it do. A first
// statement that writes waits up to busy_timeout instead.
//
// That statement is an UPDATE of startup_state that matches no row, so it
// changes nothing. The migration creates startup_state before any other
// work, and the stores of the host commands refuse a schema older than the
// upgrade floor, so every database that a schema step, a startup backfill
// or a host command writes has it.
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
