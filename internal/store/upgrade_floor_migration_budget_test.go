package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"modernc.org/sqlite"
)

const maxSchemaStepWALBytes = 16 << 20

func openFrozenSchema54Fixture(ctx context.Context, t *testing.T) (string, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "schema54.db")
	connector, err := sqlite.NewConnector(path)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(sqlitePragmaConnector{Connector: connector})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{"PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL"} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := ensureStartupStateContext(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := applyBaselineSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if got, want := baselineSchemaDumpContext(ctx, t, db), readSchemaBaselineGolden(t); !slices.Equal(got, want) {
		t.Fatal("schema 54 fixture does not match the frozen baseline")
	}
	return path, db
}

func insertUpgradeBudgetDeliveries(t *testing.T, db *sql.DB) (exhaustedPayload, pendingPayload, sentPayload []byte, exhaustedAt string) {
	t.Helper()
	cutoff, err := time.Parse(time.RFC3339Nano, legacyDeliveryRetryBudgetStart)
	if err != nil {
		t.Fatal(err)
	}
	exhaustedAt = cutoff.Add(-time.Second).Format(time.RFC3339Nano)
	exhaustedPayload = []byte(`{"type":"changes-detected","job_id":"legacy-exhausted","changes":[{"key":"old"}]}`)
	pendingPayload = []byte(`{"type":"changes-reminder","job_id":"pending-reminder","changes_truncated":true,"changes_count":17}`)
	sentPayload = []byte(`{"type":"changes-detected","job_id":"sent-history","changes":[{"key":"must-remain-byte-identical"}]}`)
	rows := []struct {
		destination string
		payload     []byte
		attempts    int
		nextAt      string
		sentAt      string
	}{
		{"floor-exhausted", exhaustedPayload, 8, exhaustedAt, ""},
		{"floor-pending", pendingPayload, 2, cutoff.Add(time.Hour).Format(time.RFC3339Nano), ""},
		{"floor-sent", sentPayload, 1, cutoff.Add(time.Hour).Format(time.RFC3339Nano), cutoff.Format(time.RFC3339Nano)},
	}
	for _, row := range rows {
		if _, err := db.Exec(`INSERT INTO outbox(destination,payload_json,attempts,next_at,sent_at,tenant_id) VALUES(?,?,?,?,?,?)`, row.destination, row.payload, row.attempts, row.nextAt, nullableRestoreTimestamp(row.sentAt), DefaultTenantID); err != nil {
			t.Fatalf("insert schema 54 delivery %s: %v", row.destination, err)
		}
	}
	return exhaustedPayload, pendingPayload, sentPayload, exhaustedAt
}

func insertUpgradeHistoryFixture(t *testing.T, db *sql.DB) {
	t.Helper()
	const (
		jobID = "floor-upgrade-job"
		stamp = "2024-01-02T03:04:05.000000000Z"
	)
	if _, err := db.Exec(`INSERT INTO jobs(id,tenant_id,name,definition_json,created_at,updated_at) VALUES(?,?,?,?,?,?)`, jobID, DefaultTenantID, "floor upgrade fixture", []byte(`{"name":"floor upgrade fixture"}`), stamp, stamp); err != nil {
		t.Fatalf("insert floor job: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO scans(id,job,started_at,finished_at,status,config_hash,snapshot_json,job_id,tenant_id) VALUES(?,?,?,?,?,?,?,?,?)`, "floor-indexed-scan", "floor upgrade fixture", stamp, stamp, "success", "floor-hash", []byte(`{"units":[]}`), jobID, DefaultTenantID); err != nil {
		t.Fatalf("insert indexed floor scan: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO scan_hosts(scan_id,address,job,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,tcp_present,tcp_open_ports) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "floor-indexed-scan", "192.0.2.201", "floor upgrade fixture", "IPv4", []byte(`["floorscansearchtoken"]`), []byte(`[]`), []byte(`{"address":"192.0.2.201","source_targets":["floorscansearchtoken"]}`), "legacy search text is rebuilt", 1, 1, 1); err != nil {
		t.Fatalf("insert indexed floor host: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO latest_scan_hosts_pre_tenant(address,scan_id,job_id,job,finished_at,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,tcp_present,tcp_open_ports) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, "192.0.2.201", "floor-indexed-scan", jobID, "floor upgrade fixture", stamp, "IPv4", []byte(`["floorlatestsearchtoken"]`), []byte(`[]`), []byte(`{"address":"192.0.2.201","source_targets":["floorlatestsearchtoken"]}`), "legacy latest search text is rebuilt", 1, 1, 1); err != nil {
		t.Fatalf("insert pre-tenant latest host: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO baseline_hosts(job_id,address,address_family,dns_names_json,host_json,search_text,open_ports,tcp_present,tcp_open_ports) VALUES(?,?,?,?,?,?,?,?,?)`, jobID, "192.0.2.201", "IPv4", []byte(`[]`), []byte(`{"address":"192.0.2.201","source_targets":["floorbaselinesearchtoken"]}`), "legacy baseline search text is rebuilt", 1, 1, 1); err != nil {
		t.Fatalf("insert floor baseline host: %v", err)
	}
	legacySnapshot := []byte(`{"units":[{"target":"floor-legacy.example","protocol":"tcp","addresses":["192.0.2.202"],"ports":[{"port":443,"state":"open","service":"https"}]}]}`)
	if _, err := db.Exec(`INSERT INTO scans(id,job,started_at,finished_at,status,config_hash,snapshot_json,job_id,tenant_id) VALUES(?,?,?,?,?,?,?,?,?)`, "floor-legacy-scan", "floor upgrade fixture", stamp, stamp, "success", "floor-legacy-hash", legacySnapshot, jobID, DefaultTenantID); err != nil {
		t.Fatalf("insert legacy floor scan: %v", err)
	}
}

func nullableRestoreTimestamp(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func walSize(path string) (int64, error) {
	info, err := os.Stat(path + "-wal")
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func truncateFixtureWAL(t *testing.T, db *sql.DB) {
	t.Helper()
	var busy, logFrames, checkpointed int
	if err := db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil {
		t.Fatalf("checkpoint fixture WAL: %v", err)
	}
	if busy != 0 {
		t.Fatalf("fixture WAL checkpoint busy=%d log=%d checkpointed=%d", busy, logFrames, checkpointed)
	}
}

func TestUpgradeFromFrozenSchema54BoundsEveryMigrationTransaction(t *testing.T) {
	ctx := context.Background()
	path, db := openFrozenSchema54Fixture(ctx, t)
	exhaustedPayload, pendingPayload, sentPayload, exhaustedAt := insertUpgradeBudgetDeliveries(t, db)
	insertUpgradeHistoryFixture(t, db)
	if version := countRows(t, db, `PRAGMA user_version`); version != minimumUpgradeSchema {
		t.Fatalf("fixture starts at schema %d, want %d", version, minimumUpgradeSchema)
	}
	if _, err := db.Exec(`PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}
	truncateFixtureWAL(t, db)
	migrations := schemaMigrationStatements()
	for version := minimumUpgradeSchema + 1; version <= schemaVersion; version++ {
		statements, ok := migrations[version]
		if !ok {
			t.Fatalf("schema %d migration is missing", version)
		}
		if err := runMigration(ctx, db, version, statements, foreignKeysOffMigrations[version]); err != nil {
			t.Fatalf("apply schema %d from floor fixture: %v", version, err)
		}
		if got := countRows(t, db, `PRAGMA user_version`); got != version {
			t.Fatalf("after migration %d marker is %d", version, got)
		}
		bytes, err := walSize(path)
		if err != nil {
			t.Fatalf("measure schema %d WAL: %v", version, err)
		}
		if bytes > maxSchemaStepWALBytes {
			t.Fatalf("schema %d used %d WAL bytes; per-step limit is %d", version, bytes, maxSchemaStepWALBytes)
		}
		t.Logf("schema %d WAL bytes=%d (per-step cap %d)", version, bytes, maxSchemaStepWALBytes)
		truncateFixtureWAL(t, db)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Opening an already migrated floor database still runs the production
	// startup reconciliation phases, including the bounded projection/index
	// backfills and consistency checks.
	upgraded, err := openWithOptionsContext(ctx, path, openOptions{create: true, migrate: true, configureWAL: true})
	if err != nil {
		t.Fatalf("complete startup reconciliation after floor migration: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("upgraded schema version = %d, want %d", version, schemaVersion)
	}
	var terminalAt string
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT terminal_at FROM outbox WHERE destination='floor-exhausted'`).Scan(&terminalAt); err != nil {
		t.Fatal(err)
	}
	if terminalAt != exhaustedAt {
		t.Fatalf("legacy exhausted delivery terminal_at = %q, want scheduled value %q", terminalAt, exhaustedAt)
	}
	for _, expected := range []struct {
		table string
		want  int
	}{
		{"scan_hosts", 1},
		{"latest_scan_hosts", 2}, // one rekeyed row plus one legacy snapshot projection
		{"baseline_hosts", 1},
	} {
		var count int
		if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+expected.table).Scan(&count); err != nil {
			t.Fatalf("count upgraded %s: %v", expected.table, err)
		}
		if count < expected.want {
			t.Errorf("upgraded %s rows = %d, want at least %d", expected.table, count, expected.want)
		}
	}
	var indexedLegacy int
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id='floor-legacy-scan' AND address='192.0.2.202' AND data_quality='legacy'`).Scan(&indexedLegacy); err != nil {
		t.Fatal(err)
	}
	if indexedLegacy != 1 {
		t.Fatalf("legacy snapshot projection rows = %d, want 1", indexedLegacy)
	}
	var rekeyedTenant, rekeyedJob string
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT tenant_id,job_id FROM latest_scan_hosts WHERE address='192.0.2.201' AND scan_id='floor-indexed-scan'`).Scan(&rekeyedTenant, &rekeyedJob); err != nil {
		t.Fatalf("read rekeyed latest-host relation: %v", err)
	}
	if rekeyedTenant != DefaultTenantID || rekeyedJob != "floor-upgrade-job" {
		t.Fatalf("rekeyed latest-host tenant/job = %q/%q, want %q/%q", rekeyedTenant, rekeyedJob, DefaultTenantID, "floor-upgrade-job")
	}
	var legacyCheckpoint string
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT status FROM legacy_scan_host_backfill WHERE scan_id='floor-legacy-scan'`).Scan(&legacyCheckpoint); err != nil || legacyCheckpoint != "complete" {
		t.Errorf("legacy scan backfill checkpoint = %q, err=%v", legacyCheckpoint, err)
	}
	for _, expected := range []struct {
		index string
		token string
	}{
		{"scan_host_search", "floorscansearchtoken"},
		{"latest_host_search", "floorlatestsearchtoken"},
		{"baseline_host_search", "floorbaselinesearchtoken"},
	} {
		var count int
		if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+expected.index+` WHERE `+expected.index+` MATCH ?`, hostSearchMatchQuery(expected.token)).Scan(&count); err != nil || count != 1 {
			t.Errorf("%s match count = %d, err=%v, want 1", expected.index, count, err)
		}
	}
	if page, err := defaultTenant(upgraded).ListScanHostsPage(ctx, "floor-indexed-scan", "floorscansearchtoken", "", nil, 10, 0); err != nil || page.Total != 1 {
		t.Errorf("tenant scan-host search = %#v, err=%v; want one indexed result", page, err)
	}
	if page, err := defaultTenant(upgraded).ListLatestScanHostsPage(ctx, "floorlatestsearchtoken", "", nil, 10, 0); err != nil || page.Total != 1 {
		t.Errorf("tenant latest-host search = %#v, err=%v; want one indexed result", page, err)
	}
	if page, err := defaultTenant(upgraded).ListBaselineHostsPage(ctx, "floor-upgrade-job", "floorbaselinesearchtoken", "", nil, 10, 0); err != nil || page.Total != 1 {
		t.Errorf("tenant baseline-host search = %#v, err=%v; want one indexed result", page, err)
	}
	for _, table := range []string{"scan_hosts", "latest_scan_hosts", "baseline_hosts"} {
		var complete int
		if err := upgraded.DB.QueryRowContext(ctx, `SELECT complete FROM fts_backfill_state WHERE table_name=?`, table).Scan(&complete); err != nil || complete != 1 {
			t.Errorf("%s search backfill complete=%d, err=%v", table, complete, err)
		}
	}
	var rekeyComplete, legacyIndexComplete int
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT complete FROM fts_backfill_state WHERE table_name=?`, latestScanHostsTenantRekeyState).Scan(&rekeyComplete); err != nil || rekeyComplete != 1 {
		t.Errorf("schema 54 latest-host rekey complete=%d, err=%v", rekeyComplete, err)
	}
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT complete FROM fts_backfill_state WHERE table_name=?`, legacyScanHostIndexState).Scan(&legacyIndexComplete); err != nil || legacyIndexComplete != 1 {
		t.Errorf("legacy scan index backfill complete=%d, err=%v", legacyIndexComplete, err)
	}
	for _, expected := range []struct {
		destination string
		payload     []byte
		eventType   string
		jobID       string
	}{
		{"floor-exhausted", exhaustedPayload, "changes-detected", "legacy-exhausted"},
		{"floor-pending", pendingPayload, "changes-reminder", "pending-reminder"},
		{"floor-sent", sentPayload, "", ""},
	} {
		var payload []byte
		var eventType, jobID string
		if err := upgraded.DB.QueryRowContext(ctx, `SELECT payload_json,event_type,event_job_id FROM outbox WHERE destination=?`, expected.destination).Scan(&payload, &eventType, &jobID); err != nil {
			t.Fatalf("read upgraded %s: %v", expected.destination, err)
		}
		if string(payload) != string(expected.payload) || eventType != expected.eventType || jobID != expected.jobID {
			t.Errorf("upgraded %s payload same=%t type=%q job=%q; want payload same and %q/%q", expected.destination, string(payload) == string(expected.payload), eventType, jobID, expected.eventType, expected.jobID)
		}
	}
	var integrity string
	if err := upgraded.DB.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity_check = %q, %v", integrity, err)
	}
	assertForeignKeysClean(t, upgraded.DB)
	if _, err := upgraded.DB.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint after startup reconciliation: %v", err)
	}
}

func TestRestoreAcceptedSchemaFloorsDoNotQuarantineOldBudgetExhaustedRows(t *testing.T) {
	ctx := context.Background()
	for _, sourceVersion := range []int{minimumUpgradeSchema, 62} {
		t.Run(fmt.Sprintf("schema-%d", sourceVersion), func(t *testing.T) {
			path, db := openFrozenSchema54Fixture(ctx, t)
			migrations := schemaMigrationStatements()
			for version := minimumUpgradeSchema + 1; version <= sourceVersion; version++ {
				if err := runMigration(ctx, db, version, migrations[version], foreignKeysOffMigrations[version]); err != nil {
					t.Fatalf("build schema %d from frozen baseline at step %d: %v", sourceVersion, version, err)
				}
			}
			if version := countRows(t, db, `PRAGMA user_version`); version != sourceVersion {
				t.Fatalf("legacy fixture schema version = %d, want %d", version, sourceVersion)
			}
			exhaustedPayload, pendingPayload, _, exhaustedAt := insertUpgradeBudgetDeliveries(t, db)
			// Include one already-terminal row so its existing state remains distinct
			// from the row migration 63 still needs to terminalize.
			if _, err := db.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,attempts,next_at,terminal_at,tenant_id) VALUES(?,?,?,?,?,?)`, "floor-already-terminal", []byte(`{"type":"changes-recovered","job_id":"already-terminal"}`), 15, exhaustedAt, exhaustedAt, DefaultTenantID); err != nil {
				t.Fatal(err)
			}
			truncateFixtureWAL(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			for _, policy := range []PendingDeliveryPolicy{PendingDeliveriesQuarantine, PendingDeliveriesDiscard, PendingDeliveriesPreserve} {
				t.Run(string(policy), func(t *testing.T) {
					destination := filepath.Join(t.TempDir(), "restored.db")
					createRestoreFixtureContext(ctx, t, destination, "destination")
					options := RestoreOptions{PendingDeliveries: policy}
					dryRun, err := DryRunRestore(ctx, path, destination, options)
					if err != nil {
						t.Fatalf("dry-run restore schema %d: %v", sourceVersion, err)
					}
					if dryRun.SourceSchemaVersion != sourceVersion || dryRun.PendingDeliveriesAffected != 1 || dryRun.PendingDeliveriesPolicy != policy {
						t.Fatalf("dry-run restore result = %#v; want schema %d and one genuinely pending delivery", dryRun, sourceVersion)
					}
					result, err := Restore(ctx, path, destination, options)
					if err != nil {
						t.Fatalf("restore schema %d: %v", sourceVersion, err)
					}
					if result.PendingDeliveriesAffected != 1 || result.PendingDeliveriesPolicy != policy {
						t.Fatalf("restore result = %#v; want one genuinely pending delivery", result)
					}
					staged, err := OpenReadOnlyExistingContext(ctx, destination)
					if err != nil {
						t.Fatal(err)
					}
					var retainedPayload []byte
					if err := staged.DB.QueryRowContext(ctx, `SELECT payload_json FROM outbox WHERE destination='floor-exhausted'`).Scan(&retainedPayload); err != nil {
						staged.Close()
						t.Fatalf("read old-budget exhausted row before startup: %v", err)
					}
					if string(retainedPayload) != string(exhaustedPayload) {
						staged.Close()
						t.Fatal("restore changed the exhausted historical payload")
					}
					var exhaustedQuarantineCount int
					if err := staged.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE restore_epoch=? AND destination='floor-exhausted'`, result.RestoreEpoch).Scan(&exhaustedQuarantineCount); err != nil {
						staged.Close()
						t.Fatal(err)
					}
					if exhaustedQuarantineCount != 0 {
						staged.Close()
						t.Fatalf("old-budget exhausted row was quarantined %d times", exhaustedQuarantineCount)
					}
					wantQuarantine := 0
					var pendingQuarantineCount int
					if policy == PendingDeliveriesQuarantine {
						if err := staged.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE restore_epoch=? AND destination='floor-pending' AND payload_json=?`, result.RestoreEpoch, pendingPayload).Scan(&pendingQuarantineCount); err != nil {
							staged.Close()
							t.Fatal(err)
						}
						wantQuarantine = 1
					}
					if pendingQuarantineCount != wantQuarantine {
						staged.Close()
						t.Fatalf("policy %s pending row quarantine count = %d, want %d", policy, pendingQuarantineCount, wantQuarantine)
					}
					if err := staged.Close(); err != nil {
						t.Fatal(err)
					}

					upgraded, err := openWithOptionsContext(ctx, destination, openOptions{create: true, migrate: true, configureWAL: true})
					if err != nil {
						t.Fatalf("upgrade restored schema %d: %v", sourceVersion, err)
					}
					t.Cleanup(func() { _ = upgraded.Close() })
					var terminalAt string
					if err := upgraded.DB.QueryRowContext(ctx, `SELECT terminal_at FROM outbox WHERE destination='floor-exhausted'`).Scan(&terminalAt); err != nil {
						t.Fatal(err)
					}
					if terminalAt != exhaustedAt {
						t.Fatalf("restored legacy row terminal_at = %q, want %q", terminalAt, exhaustedAt)
					}
					var pendingCount, terminalCount int
					if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination='floor-pending' AND sent_at IS NULL AND terminal_at=''`).Scan(&pendingCount); err != nil {
						t.Fatal(err)
					}
					if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination IN ('floor-exhausted','floor-already-terminal') AND sent_at IS NULL AND terminal_at<>''`).Scan(&terminalCount); err != nil {
						t.Fatal(err)
					}
					if (policy == PendingDeliveriesPreserve && pendingCount != 1) || (policy != PendingDeliveriesPreserve && pendingCount != 0) || terminalCount != 2 {
						t.Fatalf("policy %s post-upgrade pending=%d terminal=%d", policy, pendingCount, terminalCount)
					}
				})
			}
		})
	}
}

func createRestoreFixtureContext(ctx context.Context, t *testing.T, path, value string) {
	t.Helper()
	s, err := openWithOptionsContext(ctx, path, openOptions{create: true, migrate: true, configureWAL: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE restore_fixture (value TEXT NOT NULL); INSERT INTO restore_fixture(value) VALUES (?)`, value); err != nil {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("create restore fixture: %v (close: %v)", err, closeErr)
		}
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
