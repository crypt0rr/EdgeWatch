package store

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// startupWriteLockHold is how long the second connection holds the write
// lock: long enough that a backfill which only read before it asked for the
// lock would have failed at once, and well within busy_timeout.
const startupWriteLockHold = time.Second

// holdWriteLock takes the write lock of the database at path on a second
// connection, as a host command beside the daemon does, and returns the
// function that commits that transaction.
func holdWriteLock(t *testing.T, path string) (release func()) {
	t.Helper()
	ctx := context.Background()
	other, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	conn, err := other.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	return func() {
		if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
			t.Error(err)
		}
		_ = conn.Close()
	}
}

// Each startup phase that reads before it writes takes the write lock first.
// While another connection, such as a host command, holds the lock for a
// second, the phase waits for it instead of failing at once with
// SQLITE_BUSY, which made the daemon's start fail.
func TestStartupPhasesWaitForAConcurrentWriter(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		// prepare gives the phase work that needs a write.
		prepare func(t *testing.T, s *Store)
		run     func(ctx context.Context, s *Store) error
		// check confirms that the phase did its work.
		check func(t *testing.T, s *Store)
	}{
		{
			name: "schema step",
			prepare: func(t *testing.T, s *Store) {
				execStoreStatements(t, s, `DROP INDEX restore_quarantined_retention`, `PRAGMA user_version=63`)
			},
			run: func(ctx context.Context, s *Store) error {
				return applyMigration(ctx, s.DB, 64, migration64Statements())
			},
			check: func(t *testing.T, s *Store) {
				if got := countRows(t, s.DB, `PRAGMA user_version`); got != 64 {
					t.Fatalf("user_version = %d, want 64", got)
				}
			},
		},
		{
			name: "scan cycle identities",
			prepare: func(t *testing.T, s *Store) {
				execStoreStatements(t, s, `UPDATE scan_cycle_identity_backfill SET complete=0`)
			},
			run: func(ctx context.Context, s *Store) error {
				return backfillScanCycleUnitIdentitiesContext(ctx, s.DB)
			},
			check: func(t *testing.T, s *Store) {
				if got := countRows(t, s.DB, `SELECT complete FROM scan_cycle_identity_backfill`); got != 1 {
					t.Fatal("the identity backfill did not complete")
				}
			},
		},
		{
			name: "timestamp normalization",
			prepare: func(t *testing.T, s *Store) {
				execStoreStatements(t, s,
					`INSERT INTO scans(id,job,started_at,finished_at,status,config_hash,snapshot_json) VALUES('timestamp-scan','edge','2026-09-09T00:00:00Z','2026-09-09T00:00:01Z','failed','hash','{}')`,
					`UPDATE timestamp_normalization_state SET complete=0`)
			},
			run: func(ctx context.Context, s *Store) error {
				return normalizePersistedTimestampsContext(ctx, s.DB)
			},
			check: func(t *testing.T, s *Store) {
				if got := queryStrings(t, s.DB, `SELECT started_at FROM scans WHERE id='timestamp-scan'`); len(got) != 1 || got[0] != sqliteTimestamp(time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)) {
					t.Fatalf("normalized started_at = %v", got)
				}
			},
		},
		{
			name: "legacy host index",
			prepare: func(t *testing.T, s *Store) {
				execStoreStatements(t, s,
					`INSERT INTO scans(id,job,started_at,finished_at,status,config_hash,snapshot_json) VALUES('legacy-scan','edge','2026-09-09T00:00:00.000000000Z','2026-09-09T00:00:01.000000000Z','success','hash','{"hosts":[{"address":"192.0.2.44"}]}')`,
					`UPDATE fts_backfill_state SET complete=0 WHERE table_name='`+legacyScanHostIndexState+`'`)
			},
			run: func(ctx context.Context, s *Store) error {
				return backfillLegacyScanHostsContext(ctx, s.DB)
			},
			check: func(t *testing.T, s *Store) {
				if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id='legacy-scan'`); got != 1 {
					t.Fatalf("indexed legacy hosts = %d, want 1", got)
				}
			},
		},
		{
			name: "scan host repair",
			prepare: func(t *testing.T, s *Store) {
				statements := make([]string, 0, len(scanHostSearchTriggerNames)+2)
				for _, trigger := range scanHostSearchTriggerNames {
					statements = append(statements, `DROP TRIGGER `+trigger)
				}
				execStoreStatements(t, s, append(statements, `DROP TABLE scan_hosts`, `CREATE TABLE scan_hosts (scan_id TEXT NOT NULL, address TEXT NOT NULL, job TEXT NOT NULL DEFAULT '', address_family TEXT NOT NULL DEFAULT '', source_targets_json BLOB NOT NULL DEFAULT '[]', dns_names_json BLOB NOT NULL DEFAULT '[]', host_json BLOB NOT NULL, search_text TEXT NOT NULL DEFAULT '', data_quality TEXT NOT NULL DEFAULT 'detailed', open_ports INTEGER NOT NULL DEFAULT 0, open_filtered_ports INTEGER NOT NULL DEFAULT 0, tcp_present INTEGER NOT NULL DEFAULT 0, udp_present INTEGER NOT NULL DEFAULT 0, tcp_open_ports INTEGER NOT NULL DEFAULT 0, tcp_open_filtered_ports INTEGER NOT NULL DEFAULT 0, udp_open_ports INTEGER NOT NULL DEFAULT 0, udp_open_filtered_ports INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(scan_id,address))`)...)
			},
			run: func(ctx context.Context, s *Store) error {
				return repairScanHostsForeignKeyContext(ctx, s.DB)
			},
			check: func(t *testing.T, s *Store) {
				if got := countRows(t, s.DB, `SELECT COUNT(*) FROM pragma_foreign_key_list('scan_hosts') WHERE "table"='scans' AND on_delete='CASCADE'`); got != 1 {
					t.Fatal("scan_hosts was not repaired")
				}
			},
		},
		{
			name: "host search triggers",
			prepare: func(t *testing.T, s *Store) {
				execStoreStatements(t, s, `DROP TRIGGER `+scanHostSearchTriggerNames[0])
			},
			run: func(ctx context.Context, s *Store) error {
				return ensureHostSearchTriggersContext(ctx, s.DB)
			},
			check: func(t *testing.T, s *Store) {
				if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?`, scanHostSearchTriggerNames[0]); got != 1 {
					t.Fatal("the search trigger was not installed")
				}
			},
		},
		{
			name: "built-in scanner profiles",
			prepare: func(t *testing.T, s *Store) {
				execStoreStatements(t, s, `DELETE FROM scanner_profiles WHERE built_in=1`)
			},
			run: func(ctx context.Context, s *Store) error {
				return ensureBuiltinScannerProfilesContext(ctx, s.DB)
			},
			check: func(t *testing.T, s *Store) {
				if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scanner_profiles WHERE built_in=1`); got != 2 {
					t.Fatalf("built-in profiles = %d, want 2", got)
				}
			},
		},
		{
			name: "administrator compatibility",
			prepare: func(t *testing.T, s *Store) {
				now := time.Now().UTC()
				if err := s.SaveAdmin(context.Background(), Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
					t.Fatal(err)
				}
				execStoreStatements(t, s, `UPDATE users SET totp_secret='JBSWY3DPEHPK3PXP',totp_enabled=1 WHERE id='`+LegacyAdminUserID+`'`)
			},
			run: func(ctx context.Context, s *Store) error {
				return s.MigrateAdminCompatibility(ctx)
			},
			check: func(t *testing.T, s *Store) {
				if got := queryStrings(t, s.DB, `SELECT substr(totp_secret,1,?) FROM users WHERE id=?`, len(authCiphertextV2), LegacyAdminUserID); len(got) != 1 || got[0] != authCiphertextV2 {
					t.Fatalf("administrator secret = %v, want the sealed form", got)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			s := openTestStore(t)
			test.prepare(t, s)
			release := holdWriteLock(t, s.FilePath())
			timer := time.AfterFunc(startupWriteLockHold, release)
			defer timer.Stop()
			started := time.Now()
			if err := test.run(context.Background(), s); err != nil {
				t.Fatalf("%s while another connection writes: %v", test.name, err)
			}
			if waited := time.Since(started); waited < startupWriteLockHold/2 {
				t.Fatalf("%s finished after %v without waiting for the writer", test.name, waited)
			}
			test.check(t, s)
		})
	}
}

// execStoreStatements runs fixture statements on the store's writer.
func execStoreStatements(t *testing.T, s *Store, statements ...string) {
	t.Helper()
	for _, statement := range statements {
		if _, err := s.DB.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}
