package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// execFixtureStatements runs statements against the closed database at path
// without migrating it.
func execFixtureStatements(t *testing.T, path string, statements []string) {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, statement := range statements {
		if _, err := raw.Exec(statement); err != nil {
			t.Fatalf("fixture statement %s: %v", statement, err)
		}
	}
}

func assertForeignKeysClean(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		var table, parent string
		var rowID, key sql.NullInt64
		if err := rows.Scan(&table, &rowID, &parent, &key); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("foreign key violation in %s row %v referencing %s", table, rowID, parent)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

// snapshotRows writes one line per row of query to out.
func snapshotRows(db *sql.DB, query string, out *strings.Builder) error {
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return err
	}
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return err
		}
		fmt.Fprintln(out, values...)
	}
	return rows.Err()
}

// The update routing lives on the default tenant's row. Without that row a
// routing write fails and changes nothing, instead of reporting success for
// a routing that is not stored.
func TestUpdateRoutingWritesRequireTheDefaultTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	destination, err := defaultTenant(s).CreateManagedNotification(ctx, "destination-routing", "Routing", "generic", []byte{1}, []byte{2}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SetApplicationUpdateDestinations(ctx, []string{destination.ID}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	// Since schema 52 the destination references the tenant.
	if _, err := s.DB.ExecContext(ctx, `PRAGMA foreign_keys=OFF; DELETE FROM public_dashboards; DELETE FROM tenants; PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SetApplicationUpdateDestinations(ctx, []string{"file:other"}, AuditEntry{Action: "notifications.update_routing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("routing write without the default tenant = %v, want ErrNotFound", err)
	}
	var audits int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='notifications.update_routing'`).Scan(&audits); err != nil || audits != 0 {
		t.Fatalf("failed routing write left %d audit rows: %v", audits, err)
	}
	if changed, err := defaultTenant(s).DeleteManagedNotificationWithAudit(ctx, destination.ID, destination.Revision, AuditEntry{Action: "notifications.deleted"}); err != nil || len(changed) != 0 {
		t.Fatalf("delete without the default tenant = %v, %v", changed, err)
	}
}
