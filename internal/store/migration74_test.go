package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMigration74BackfillsBudgetSkipProjectionInRestartableBatches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `DROP INDEX IF EXISTS `+budgetSkipAlertPendingIndex); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `ALTER TABLE job_runtime_meta DROP COLUMN budget_skip_alert_key`); err != nil {
		t.Fatalf("reconstruct schema 73 metadata: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `PRAGMA user_version=73`); err != nil {
		t.Fatal(err)
	}

	// The index name collision fails after the migration's conditional ALTER
	// TABLE has run, proving both DDL changes roll back in the real migration
	// transaction.
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE `+budgetSkipAlertPendingIndex+` (sentinel TEXT)`); err != nil {
		t.Fatal(err)
	}
	statements := migration74Statements()
	if err := applyMigration(ctx, s.DB, 74, statements); err == nil {
		t.Fatal("schema 74 migration succeeded with a conflicting pending-index name")
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 73 {
		t.Fatalf("failed schema 74 migration advanced to %d", got)
	}
	if hasBudgetSkipProjection(t, s.DB) {
		t.Fatal("failed schema 74 migration left its new column")
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, budgetSkipAlertPendingIndex); got != 0 {
		t.Fatalf("failed schema 74 migration left %d pending indexes", got)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, budgetSkipAlertPendingIndex); got != 1 {
		t.Fatalf("failed schema 74 migration changed its conflicting table: %d rows", got)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TABLE `+budgetSkipAlertPendingIndex); err != nil {
		t.Fatal(err)
	}
	if err := applyMigration(ctx, s.DB, 74, statements); err != nil {
		t.Fatalf("apply schema 74: %v", err)
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 74 {
		t.Fatalf("schema version = %d, want 74", got)
	}
	plan := queryPlan(t, s.DB, `SELECT job_id FROM job_runtime_meta WHERE budget_skip_alert_key IS NULL ORDER BY job_id LIMIT ?`, 2)
	if !strings.Contains(plan, budgetSkipAlertPendingIndex) {
		t.Fatalf("bounded backfill query does not use its pending index: %s", plan)
	}

	stamp := sqliteTimestamp(time.Now().UTC())
	fixtures := []struct {
		id, runtimeJSON, want string
	}{
		{"budget-b-malformed", `{"budget_skip_alert_key":`, ""},
		{"budget-c-wrong-type", `{"budget_skip_alert_key":7}`, ""},
		{"budget-d-oversized", `{"budget_skip_alert_key":"` + strings.Repeat("x", 129) + `"}`, ""},
		{"budget-e-no-key", `{"baseline":null}`, ""},
		{"budget-z-valid", `{"budget_skip_alert_key":"` + strings.Repeat("a", 64) + `|65536"}`, strings.Repeat("a", 64) + "|65536"},
	}
	for _, fixture := range fixtures {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,tenant_id,name,definition_json,created_at,updated_at) VALUES(?,?,?,?,?,?)`, fixture.id, DefaultTenantID, fixture.id, `{}`, stamp, stamp); err != nil {
			t.Fatalf("insert job %s: %v", fixture.id, err)
		}
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, fixture.id, fixture.runtimeJSON, stamp); err != nil {
			t.Fatalf("insert runtime %s: %v", fixture.id, err)
		}
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,1,'','',0,0,0,0,0,0,?)`, fixture.id, stamp); err != nil {
			t.Fatalf("insert runtime metadata %s: %v", fixture.id, err)
		}
	}
	// A metadata row without a runtime row must also finish the projection as
	// an empty value rather than remaining in every future startup batch.
	const noRuntimeID = "budget-a-no-runtime"
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,tenant_id,name,definition_json,created_at,updated_at) VALUES(?,?,?,?,?,?)`, noRuntimeID, DefaultTenantID, noRuntimeID, `{}`, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,1,'','',0,0,0,0,0,0,?)`, noRuntimeID, stamp); err != nil {
		t.Fatal(err)
	}

	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER reject_budget_skip_batch BEFORE UPDATE OF budget_skip_alert_key ON job_runtime_meta WHEN NEW.job_id='budget-b-malformed' BEGIN SELECT RAISE(ABORT,'injected batch failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := backfillBudgetSkipAlertKeyProjectionWithBatchSize(ctx, s.DB, 2, nil); err == nil {
		t.Fatal("backfill succeeded despite the injected second-row update failure")
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM job_runtime_meta WHERE budget_skip_alert_key IS NOT NULL`); got != 0 {
		t.Fatalf("failed batch committed %d projection rows, want transaction rollback", got)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER reject_budget_skip_batch`); err != nil {
		t.Fatal(err)
	}

	canceledCtx, cancel := context.WithCancel(ctx)
	err := backfillBudgetSkipAlertKeyProjectionWithBatchSize(canceledCtx, s.DB, 2, func(processed int64) {
		if processed == 2 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled backfill error = %v, want context.Canceled", err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM job_runtime_meta WHERE budget_skip_alert_key IS NOT NULL`); got != 2 {
		t.Fatalf("canceled backfill committed %d rows, want only its first batch", got)
	}
	if err := backfillBudgetSkipAlertKeyProjectionWithBatchSize(ctx, s.DB, 2, nil); err != nil {
		t.Fatalf("resume backfill: %v", err)
	}
	for _, fixture := range fixtures {
		var got string
		if err := s.DB.QueryRowContext(ctx, `SELECT budget_skip_alert_key FROM job_runtime_meta WHERE job_id=?`, fixture.id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != fixture.want {
			t.Errorf("projection for %s = %q, want %q", fixture.id, got, fixture.want)
		}
	}
	var noRuntime string
	if err := s.DB.QueryRowContext(ctx, `SELECT budget_skip_alert_key FROM job_runtime_meta WHERE job_id=?`, noRuntimeID).Scan(&noRuntime); err != nil {
		t.Fatal(err)
	}
	if noRuntime != "" {
		t.Fatalf("metadata without runtime projected %q, want empty", noRuntime)
	}
}

func hasBudgetSkipProjection(t *testing.T, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) bool {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `PRAGMA table_info(job_runtime_meta)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if name == "budget_skip_alert_key" {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return false
}
