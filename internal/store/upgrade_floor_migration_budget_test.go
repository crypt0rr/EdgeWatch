package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"modernc.org/sqlite"
)

const maxSchemaStepWALBytes = 16 << 20

const (
	upgradeBudgetBulkRows       = 5_000
	upgradeBudgetBulkPayloadLen = 4_096
	upgradeBudgetProjectionRows = 251
	upgradeBudgetCycleUnitRows  = 257
)

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

func insertUpgradeBudgetDeliveries(t *testing.T, db *sql.DB, exhaustedDestination string) (exhaustedPayload, pendingPayload, sentPayload []byte, exhaustedAt string) {
	t.Helper()
	cutoff, err := time.Parse(time.RFC3339Nano, legacyDeliveryRetryBudgetStart)
	if err != nil {
		t.Fatal(err)
	}
	exhaustedAt = cutoff.Add(-time.Second).Format(time.RFC3339Nano)
	if exhaustedDestination == "" {
		exhaustedDestination = "floor-exhausted"
	}
	legacyEvent := model.Event{Type: "changes-detected", JobID: "legacy-exhausted", Job: "legacy-exhausted", Message: "legacy exhausted delivery", TenantID: DefaultTenantID, CreatedAt: cutoff.Add(-time.Second)}
	_, exhaustedPayload, err = model.MarshalBoundedEvent(legacyEvent, model.EventPayloadLimit)
	if err != nil {
		t.Fatalf("marshal exhausted delivery fixture: %v", err)
	}
	pendingPayload = []byte(`{"type":"changes-reminder","job_id":"pending-reminder","changes_truncated":true,"changes_count":17}`)
	sentPayload = []byte(`{"type":"changes-detected","job_id":"sent-history","changes":[{"key":"must-remain-byte-identical"}]}`)
	rows := []struct {
		destination string
		payload     []byte
		attempts    int
		nextAt      string
		sentAt      string
	}{
		{exhaustedDestination, exhaustedPayload, 8, exhaustedAt, ""},
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

func managedNotificationColumnNames(t *testing.T, ctx context.Context, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(managed_notifications)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return columns
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

// insertUpgradeBudgetRepresentativeRows gives the floor-to-current test
// enough retained data to make an all-row rewrite visible in a single WAL
// transaction. The outbox and event payloads deliberately span several
// thousand pages; the other rows exercise the indexes and resumable startup
// projections that were empty in the original floor fixture.
func insertUpgradeBudgetRepresentativeRows(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	const stamp = "2024-01-02T03:04:05Z"

	if _, err := db.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,state,is_default,high_cost_ceiling,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		"floor-capacity-tenant", "Floor capacity", "floor-capacity", TenantStateActive, 0, 4096, stamp, stamp); err != nil {
		t.Fatalf("insert capacity tenant: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,state,is_default,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
		"floor-deleted-tenant", "Floor deleted", "floor-deleted", TenantStateDeleted, 0, stamp, stamp); err != nil {
		t.Fatalf("insert deleted tenant: %v", err)
	}
	for _, action := range []string{auditActionTenantCapacityChanged, "notifications.incident_reminders_changed"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO security_audit(action,detail,created_at,tenant_id,category) VALUES(?,?,?,?,?)`, action, "floor upgrade fixture", stamp, "floor-capacity-tenant", auditCategoryPlatform); err != nil {
			t.Fatalf("insert audit evidence %s: %v", action, err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO restore_quarantined_deliveries(restore_epoch,destination,payload_json,attempts,next_at,last_error,quarantined_at,tenant_id) VALUES(?,?,?,?,?,?,?,?)`,
		"floor-restore-epoch", "floor-quarantined", []byte(`{"job_id":"floor-upgrade-job"}`), 1, stamp, "", stamp, DefaultTenantID); err != nil {
		t.Fatalf("insert quarantined delivery: %v", err)
	}

	// This exact payload size makes an update of each row rewrite more than
	// the per-step WAL cap while keeping the fixture bounded at about 40 MiB
	// across the two large source tables.
	const payloadPrefix = `{"type":"changes-detected","job_id":"floor-upgrade-job","padding":"`
	const payloadSuffix = `"}`
	if len(payloadPrefix)+len(payloadSuffix) >= upgradeBudgetBulkPayloadLen {
		t.Fatal("bulk payload envelope exceeds its fixture budget")
	}
	bulkPayload := []byte(payloadPrefix + strings.Repeat("x", upgradeBudgetBulkPayloadLen-len(payloadPrefix)-len(payloadSuffix)) + payloadSuffix)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	jobInsert, err := tx.PrepareContext(ctx, `INSERT INTO jobs(id,tenant_id,name,definition_json,created_at,updated_at) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer jobInsert.Close()
	for i := 0; i < upgradeBudgetProjectionRows; i++ {
		jobID := fmt.Sprintf("floor-projection-%03d", i)
		if _, err := jobInsert.ExecContext(ctx, jobID, DefaultTenantID, jobID, []byte(`{}`), stamp, stamp); err != nil {
			t.Fatalf("insert projection job %s: %v", jobID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit projection jobs: %v", err)
	}

	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	metaInsert, err := tx.PrepareContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,1,'','',0,0,0,0,0,0,?)`)
	if err != nil {
		t.Fatal(err)
	}
	runtimeInsert, err := tx.PrepareContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`)
	if err != nil {
		_ = metaInsert.Close()
		t.Fatal(err)
	}
	incidentInsert, err := tx.PrepareContext(ctx, `INSERT INTO runtime_incidents(job_id,key,incident_json) VALUES(?,?,?)`)
	if err != nil {
		_ = metaInsert.Close()
		_ = runtimeInsert.Close()
		t.Fatal(err)
	}
	for i := 0; i < upgradeBudgetProjectionRows; i++ {
		jobID := fmt.Sprintf("floor-projection-%03d", i)
		key := fmt.Sprintf("floor-budget-skip-%03d|32768", i)
		state := []byte(fmt.Sprintf(`{"budget_skip_alert_key":%q}`, key))
		if _, err := metaInsert.ExecContext(ctx, jobID, stamp); err != nil {
			t.Fatalf("insert runtime metadata %s: %v", jobID, err)
		}
		if _, err := runtimeInsert.ExecContext(ctx, jobID, state, stamp); err != nil {
			t.Fatalf("insert runtime source %s: %v", jobID, err)
		}
		incidentKey := fmt.Sprintf("floor-incident-%03d", i)
		incident := fmt.Sprintf(`{"change":{"key":%q,"kind":"port","severity":"critical","target":"floor.example","protocol":"tcp","port":443,"old":"closed","new":"open"},"opened_at":%q,"last_seen_at":%q,"recovery_count":0,"scan_id":"floor-indexed-scan"}`, incidentKey, stamp, stamp)
		if _, err := incidentInsert.ExecContext(ctx, jobID, incidentKey, []byte(incident)); err != nil {
			t.Fatalf("insert runtime incident %s: %v", incidentKey, err)
		}
	}
	for _, stmt := range []*sql.Stmt{metaInsert, runtimeInsert, incidentInsert} {
		if err := stmt.Close(); err != nil {
			t.Fatalf("close upgrade fixture statement: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit runtime and incident fixtures: %v", err)
	}

	// A large event table makes the schema-72 index transaction's budget
	// observable if a future change adds a payload-rewriting UPDATE there.
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	eventInsert, err := tx.PrepareContext(ctx, `INSERT INTO events(type,job,scan_id,payload_json,created_at,job_id,tenant_id) VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	for i := 0; i < upgradeBudgetBulkRows; i++ {
		if _, err := eventInsert.ExecContext(ctx, "changes-detected", "floor upgrade fixture", "floor-indexed-scan", bulkPayload, stamp, "floor-upgrade-job", DefaultTenantID); err != nil {
			_ = eventInsert.Close()
			_ = tx.Rollback()
			t.Fatalf("insert bulk event %d: %v", i, err)
		}
	}
	if err := eventInsert.Close(); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit bulk events: %v", err)
	}

	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	outboxInsert, err := tx.PrepareContext(ctx, `INSERT INTO outbox(destination,payload_json,attempts,next_at,sent_at,tenant_id) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	for i := 0; i < upgradeBudgetBulkRows; i++ {
		sentAt := any(nil)
		if i%2 == 0 {
			sentAt = stamp
		}
		if _, err := outboxInsert.ExecContext(ctx, fmt.Sprintf("floor-bulk-%05d", i), bulkPayload, 1, stamp, sentAt, DefaultTenantID); err != nil {
			_ = outboxInsert.Close()
			_ = tx.Rollback()
			t.Fatalf("insert bulk outbox row %d: %v", i, err)
		}
	}
	if err := outboxInsert.Close(); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit bulk outbox rows: %v", err)
	}

	// Force the floor fixture's real restartable phases to process data across
	// more than one bounded batch instead of inheriting an already-complete
	// checkpoint from the baseline.
	if _, err := db.ExecContext(ctx, `UPDATE scan_cycle_identity_backfill SET complete=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,total_units,total_probes,started_at,updated_at,expires_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"floor-budget-cycle", "floor-upgrade-job", "floor upgrade fixture", 1, "floor-config", "floor-execution", []byte(`{}`), "completed", upgradeBudgetCycleUnitRows, 0, stamp, stamp, stamp, stamp); err != nil {
		t.Fatalf("insert cycle fixture: %v", err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	unitInsert, err := tx.PrepareContext(ctx, `INSERT INTO scan_cycle_units(cycle_id,sequence,work_unit_json,status,started_at,finished_at) VALUES(?,?,?,'completed',?,?)`)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	for i := 0; i < upgradeBudgetCycleUnitRows; i++ {
		if _, err := unitInsert.ExecContext(ctx, "floor-budget-cycle", i, []byte(`{}`), stamp, stamp); err != nil {
			_ = unitInsert.Close()
			_ = tx.Rollback()
			t.Fatalf("insert scan cycle unit %d: %v", i, err)
		}
	}
	if err := unitInsert.Close(); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit scan cycle units: %v", err)
	}
}

func insertUpgradeChangeWindowRows(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	const stamp = "2024-01-02T03:04:05Z"
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO change_windows(id,job_id,start_at,end_at,timezone,reason,actor_label,created_at,status,closed_at,review_state) VALUES(?, 'floor-upgrade-job', ?, ?, 'UTC', 'upgrade fixture', 'Operator', ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	for _, kind := range []string{"active", "scheduled", "due", "reviewed"} {
		for i := 0; i < 100; i++ {
			id := fmt.Sprintf("floor-window-%s-%03d", kind, i)
			start, end, status, closedAt, review := stamp, "2027-01-02T03:04:05Z", "active", "", "none"
			switch kind {
			case "scheduled":
				start, end, status = "2027-01-02T03:04:05Z", "2027-01-03T03:04:05Z", "scheduled"
			case "due":
				status, closedAt, review = "closed", stamp, "due"
			case "reviewed":
				status, closedAt, review = "closed", stamp, "reviewed"
			}
			if _, err := stmt.ExecContext(ctx, id, start, end, stamp, status, closedAt, review); err != nil {
				_ = stmt.Close()
				_ = tx.Rollback()
				t.Fatalf("insert %s window %d: %v", kind, i, err)
			}
		}
	}
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit change-window fixtures: %v", err)
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
	exhaustedPayload, pendingPayload, sentPayload, exhaustedAt := insertUpgradeBudgetDeliveries(t, db, "")
	insertUpgradeHistoryFixture(t, db)
	insertUpgradeBudgetRepresentativeRows(t, db)
	if version := countRows(t, db, `PRAGMA user_version`); version != minimumUpgradeSchema {
		t.Fatalf("fixture starts at schema %d, want %d", version, minimumUpgradeSchema)
	}
	if _, err := db.Exec(`PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}
	truncateFixtureWAL(t, db)
	fixtureInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat representative schema-54 fixture: %v", err)
	}
	t.Logf("schema-54 fixture database=%d bytes; bulk outbox=%d rows x %d-byte payload; events=%d rows; projection jobs/incidents=%d; cycle units=%d; per-step WAL cap=%d", fixtureInfo.Size(), upgradeBudgetBulkRows, upgradeBudgetBulkPayloadLen, upgradeBudgetBulkRows, upgradeBudgetProjectionRows, upgradeBudgetCycleUnitRows, maxSchemaStepWALBytes)
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
		if version == 69 {
			// This table is introduced by schema 69, so seed it after that
			// transaction and before schema 73 builds its retained-window indexes.
			insertUpgradeChangeWindowRows(t, db)
			truncateFixtureWAL(t, db)
		}
	}
	// The schema loop above measures each DDL transaction independently. Mark
	// the fixture as an interrupted startup after the schema reaches 74 so the
	// production reopen path resumes the schema-74 runtime projection as well
	// as the other restartable startup backfills.
	if _, err := db.ExecContext(ctx, `UPDATE startup_state SET state='migrating',owner='migration/floor-fixture',phase='probe-budget-alert-projection',started_at=?,updated_at=?,progress=0,total=0,last_error='' WHERE id=1`, sqliteTimestamp(time.Now().UTC()), sqliteTimestamp(time.Now().UTC())); err != nil {
		t.Fatalf("mark floor fixture startup reconciliation pending: %v", err)
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
	var startupState, startupPhase string
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT state,phase FROM startup_state WHERE id=1`).Scan(&startupState, &startupPhase); err != nil || startupState != "ready" || startupPhase != "" {
		t.Errorf("startup state = %q/%q, err=%v; want ready with no pending phase", startupState, startupPhase, err)
	}
	var timestampComplete int
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT complete FROM timestamp_normalization_state WHERE id=1`).Scan(&timestampComplete); err != nil || timestampComplete != 1 {
		t.Errorf("timestamp normalization checkpoint complete=%d, err=%v; want 1", timestampComplete, err)
	}
	var normalizedEventAt string
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT created_at FROM events WHERE job_id='floor-upgrade-job' ORDER BY id LIMIT 1`).Scan(&normalizedEventAt); err != nil || normalizedEventAt != "2024-01-02T03:04:05.000000000Z" {
		t.Errorf("normalized event timestamp=%q, err=%v", normalizedEventAt, err)
	}
	var identityComplete, identifiedUnits int
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT complete FROM scan_cycle_identity_backfill WHERE id=1`).Scan(&identityComplete); err != nil || identityComplete != 1 {
		t.Errorf("scan-cycle identity checkpoint complete=%d, err=%v; want 1", identityComplete, err)
	}
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_cycle_units WHERE cycle_id='floor-budget-cycle' AND identity<>''`).Scan(&identifiedUnits); err != nil || identifiedUnits != upgradeBudgetCycleUnitRows {
		t.Errorf("backfilled scan-cycle unit identities=%d, err=%v; want %d", identifiedUnits, err, upgradeBudgetCycleUnitRows)
	}
	var projectionRows, missingBudgetKeys, projectedIncidents int
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN budget_skip_alert_key IS NULL THEN 1 ELSE 0 END),0) FROM job_runtime_meta WHERE job_id LIKE 'floor-projection-%'`).Scan(&projectionRows, &missingBudgetKeys); err != nil || projectionRows != upgradeBudgetProjectionRows || missingBudgetKeys != 0 {
		t.Errorf("schema-74 runtime projection rows=%d missing keys=%d, err=%v; want %d rows and no missing keys", projectionRows, missingBudgetKeys, err, upgradeBudgetProjectionRows)
	}
	var projectedBudgetKey string
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COALESCE(budget_skip_alert_key,'') FROM job_runtime_meta WHERE job_id='floor-projection-000'`).Scan(&projectedBudgetKey); err != nil || projectedBudgetKey != "floor-budget-skip-000|32768" {
		t.Errorf("schema-74 budget key=%q, err=%v", projectedBudgetKey, err)
	}
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM runtime_incidents WHERE job_id LIKE 'floor-projection-%' AND occurrence_token<>'' AND severity='critical' AND kind='port' AND opened_at_sort<>'' AND last_seen_at_sort<>''`).Scan(&projectedIncidents); err != nil || projectedIncidents != upgradeBudgetProjectionRows {
		t.Errorf("incident inbox projection rows=%d, err=%v; want %d", projectedIncidents, err, upgradeBudgetProjectionRows)
	}
	var legacyPurgeComplete int
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT complete FROM fts_backfill_state WHERE table_name=?`, legacyPurgeMaintenanceState).Scan(&legacyPurgeComplete); err != nil || legacyPurgeComplete != 0 {
		t.Errorf("deleted-tenant maintenance checkpoint complete=%d, err=%v; want pending work recorded", legacyPurgeComplete, err)
	}
	var capacityGranted, capacityCeiling, remindersExplicit int
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT high_cost_granted,high_cost_ceiling,incident_reminder_cadence_explicit FROM tenants WHERE id='floor-capacity-tenant'`).Scan(&capacityGranted, &capacityCeiling, &remindersExplicit); err != nil || capacityGranted != 1 || capacityCeiling != 4096 || remindersExplicit != 1 {
		t.Errorf("capacity tenant migration state=%d/%d reminder-explicit=%d, err=%v", capacityGranted, capacityCeiling, remindersExplicit, err)
	}
	if got := countRows(t, upgraded.DB, `SELECT COUNT(*) FROM outbox WHERE destination LIKE 'floor-bulk-%'`); got != upgradeBudgetBulkRows {
		t.Errorf("bulk outbox rows=%d, want %d", got, upgradeBudgetBulkRows)
	}
	if got := countRows(t, upgraded.DB, `SELECT COUNT(*) FROM events WHERE job_id='floor-upgrade-job'`); got != upgradeBudgetBulkRows {
		t.Errorf("bulk event rows=%d, want %d", got, upgradeBudgetBulkRows)
	}
	if got := countRows(t, upgraded.DB, `SELECT COUNT(*) FROM change_windows WHERE id LIKE 'floor-window-%'`); got != 400 {
		t.Errorf("change-window fixture rows=%d, want 400", got)
	}
	for _, index := range []string{eventsTenantHistoryIndex, eventsTenantJobHistoryIndex, eventsTenantJobIDHistoryIndex, changeWindowsOpenLatestIndex, changeWindowsOpenScheduledIndex, changeWindowsDueReviewIndex, changeWindowsClosedHistoryIndex, budgetSkipAlertPendingIndex} {
		if got := countRows(t, upgraded.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='`+index+`'`); got != 1 {
			t.Errorf("migration index %s present count=%d, want 1", index, got)
		}
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
			columnsBeforeCreate := managedNotificationColumnNames(t, ctx, db)
			wantColumns := []string{"id", "tenant_id", "name", "provider", "ciphertext", "nonce", "enabled", "revision", "created_at", "updated_at", "credential_revision"}
			if !slices.Equal(columnsBeforeCreate, wantColumns) {
				t.Fatalf("schema %d managed_notifications columns before destination creation = %v, want %v", sourceVersion, columnsBeforeCreate, wantColumns)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			legacyStore, err := OpenExistingContext(ctx, path)
			if err != nil {
				t.Fatalf("open schema %d fixture for managed destination: %v", sourceVersion, err)
			}
			managedDestination, err := defaultTenant(legacyStore).CreateManagedNotification(ctx, "floor-managed-exhausted", "Floor exhausted", "generic", []byte("sealed"), []byte("nonce"), true)
			if err != nil {
				legacyStore.Close()
				t.Fatalf("create managed destination in schema %d fixture: %v", sourceVersion, err)
			}
			if version := countRows(t, legacyStore.DB, `PRAGMA user_version`); version != sourceVersion {
				legacyStore.Close()
				t.Fatalf("managed destination creation upgraded the source from schema %d to %d", sourceVersion, version)
			}
			columnsAfterCreate := managedNotificationColumnNames(t, ctx, legacyStore.DB)
			if !slices.Equal(columnsAfterCreate, columnsBeforeCreate) {
				legacyStore.Close()
				t.Fatalf("managed destination creation changed schema %d managed_notifications columns from %v to %v", sourceVersion, columnsBeforeCreate, columnsAfterCreate)
			}
			exhaustedDestination := managedNotificationKey(managedDestination.ID, managedDestination.CredentialRevision)
			exhaustedPayload, pendingPayload, _, exhaustedAt := insertUpgradeBudgetDeliveries(t, legacyStore.DB, exhaustedDestination)
			// Include one already-terminal row so its existing state remains distinct
			// from the row migration 63 still needs to terminalize.
			if _, err := legacyStore.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,attempts,next_at,terminal_at,tenant_id) VALUES(?,?,?,?,?,?)`, "floor-already-terminal", []byte(`{"type":"changes-recovered","job_id":"already-terminal"}`), 15, exhaustedAt, exhaustedAt, DefaultTenantID); err != nil {
				legacyStore.Close()
				t.Fatal(err)
			}
			truncateFixtureWAL(t, legacyStore.DB)
			if err := legacyStore.Close(); err != nil {
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
					if err := staged.DB.QueryRowContext(ctx, `SELECT payload_json FROM outbox WHERE destination=?`, exhaustedDestination).Scan(&retainedPayload); err != nil {
						staged.Close()
						t.Fatalf("read old-budget exhausted row before startup: %v", err)
					}
					if string(retainedPayload) != string(exhaustedPayload) {
						staged.Close()
						t.Fatal("restore changed the exhausted historical payload")
					}
					var exhaustedQuarantineCount int
					if err := staged.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE restore_epoch=? AND destination=?`, result.RestoreEpoch, exhaustedDestination).Scan(&exhaustedQuarantineCount); err != nil {
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
					if err := upgraded.DB.QueryRowContext(ctx, `SELECT terminal_at FROM outbox WHERE destination=?`, exhaustedDestination).Scan(&terminalAt); err != nil {
						t.Fatal(err)
					}
					if terminalAt != exhaustedAt {
						t.Fatalf("restored legacy row terminal_at = %q, want %q", terminalAt, exhaustedAt)
					}
					var pendingCount, terminalCount int
					if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination='floor-pending' AND sent_at IS NULL AND terminal_at=''`).Scan(&pendingCount); err != nil {
						t.Fatal(err)
					}
					if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination IN (?,'floor-already-terminal') AND sent_at IS NULL AND terminal_at<>''`, exhaustedDestination).Scan(&terminalCount); err != nil {
						t.Fatal(err)
					}
					if (policy == PendingDeliveriesPreserve && pendingCount != 1) || (policy != PendingDeliveriesPreserve && pendingCount != 0) || terminalCount != 2 {
						t.Fatalf("policy %s post-upgrade pending=%d terminal=%d", policy, pendingCount, terminalCount)
					}
					listed, err := defaultTenant(upgraded).ListTerminalDeliveries(ctx, managedDestination.ID, 0, 10)
					if err != nil || len(listed) != 1 {
						t.Fatalf("policy %s restored legacy terminal deliveries = %+v, err=%v; want the managed exhausted row", policy, listed, err)
					}
					if listed[0].EventType != "changes-detected" || listed[0].Job != "legacy-exhausted" || listed[0].Attempts != 8 || listed[0].TerminalAt.Format(time.RFC3339Nano) != exhaustedAt || listed[0].EventAt.IsZero() {
						t.Fatalf("policy %s restored legacy terminal delivery = %+v; want its legacy event, attempts, and terminal time", policy, listed[0])
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
