package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

func TestTenantOutboxQueriesAvoidAllRowsPurgeIndex(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	seedRetainedOutboxHistory(t, s.DB)

	closeWindowTransitions := []struct {
		name      string
		kind      outboxTransitionName
		where     string
		whereArgs []any
		changes   []outboxColumnChange
	}{
		{
			name:      "assign pending window",
			kind:      outboxAssignWindow,
			where:     outboxAssignWindowWhere,
			whereArgs: []any{"job", DefaultTenantID, "job", "start", DefaultTenantID},
			changes:   []outboxColumnChange{outboxChange("change_window_id", outboxSet, "?", "window")},
		},
		{
			name:      "cancel pending window",
			kind:      outboxCancelPending,
			where:     outboxCancelPendingWindowWhere,
			whereArgs: []any{"window", DefaultTenantID},
			changes:   []outboxColumnChange{outboxChange("change_window_id", outboxConditional, `''`)},
		},
		{
			name:      "close pending window row",
			kind:      outboxClosePending,
			where:     outboxClosePendingWindowWhere,
			whereArgs: []any{"window", DefaultTenantID},
			changes: []outboxColumnChange{
				outboxChange("coalesced_at", outboxSet, "?", "stamp"),
				outboxChange("last_error", outboxReset, "''"),
				outboxChange("claim_token", outboxReset, "''"),
				outboxChange("claim_until", outboxReset, "''"),
			},
		},
		{
			name:      "close in-flight window row",
			kind:      outboxCloseInFlight,
			where:     outboxCloseInFlightWindowWhere,
			whereArgs: []any{"window", DefaultTenantID},
			changes:   []outboxColumnChange{outboxChange("coalesce_after_attempt", outboxSet, "1")},
		},
		{
			name:      "close orphaned window row",
			kind:      outboxCloseOrphan,
			where:     outboxCloseOrphanWindowWhere,
			whereArgs: []any{"window", DefaultTenantID},
			changes: []outboxColumnChange{
				outboxChange("coalesced_at", outboxSet, "?", "stamp"),
				outboxChange("attempt_started_at", outboxReset, "''"),
				outboxChange("coalesce_after_attempt", outboxReset, "0"),
				outboxChange("last_error", outboxReset, "''"),
			},
		},
	}
	for _, test := range closeWindowTransitions {
		statement, args, err := buildOutboxTransitionStatement(test.kind, test.where, test.whereArgs, test.changes...)
		if err != nil {
			t.Fatalf("build %s: %v", test.name, err)
		}
		wantIndex := "outbox_change_window_pending"
		if test.kind == outboxAssignWindow {
			wantIndex = "outbox_job_change_pending"
		}
		requireOutboxPlan(t, s.DB, test.name, statement, args, wantIndex, "outbox_tenant_purge")
	}

	requireOutboxPlan(t, s.DB, "capture pending window rows", capturePendingWindowRowsQuery,
		[]any{"window", DefaultTenantID, int64(0), changeWindowBatchSize}, "outbox_change_window_pending", "outbox_tenant_purge")

	for _, phase := range []string{jobPurgePhaseWindowOutboxJob, jobPurgePhaseWindowOutboxLinks} {
		var step *jobHistoryPurgeStep
		for index := range jobHistoryPurgeSteps {
			if jobHistoryPurgeSteps[index].phase == phase {
				step = &jobHistoryPurgeSteps[index]
				break
			}
		}
		if step == nil {
			t.Fatalf("missing job purge step %q", phase)
		}
		wantIndex := "outbox_job_change_pending"
		if phase == jobPurgePhaseWindowOutboxLinks {
			wantIndex = "outbox_change_window_pending"
		}
		query := `SELECT EXISTS(` + step.rowids + `)`
		requireOutboxPlan(t, s.DB, phase, query, []any{DefaultTenantID, "job"}, wantIndex, "outbox_tenant_purge")
	}

	requireOutboxPlanAny(t, s.DB, "terminal delivery list", tenantTerminalDeliveriesQuery,
		[]any{"destination", DefaultTenantID, DefaultTenantID, int64(0), int64(0), MaxTerminalDeliveriesPage}, []string{"outbox_sent_at", "outbox_terminal_due"}, "outbox_tenant_purge")
	requireOutboxPlanAny(t, s.DB, "terminal delivery redeliver selector", tenantRedeliverableTerminalIDsQuery,
		[]any{"destination", DefaultTenantID, DefaultTenantID}, []string{"outbox_sent_at", "outbox_terminal_due"}, "outbox_tenant_purge")
	requireOutboxPlanAny(t, s.DB, "failed delivery count", tenantFailedDeliveriesQuery,
		[]any{deliveryMaxAttempts, DefaultTenantID}, []string{"outbox_sent_at", "outbox_terminal_due"}, "outbox_tenant_purge")
	requireOutboxPlan(t, s.DB, "tenant telemetry pending", tenantOutboxPendingCountQuery,
		[]any{DefaultTenantID}, "outbox_sent_at", "outbox_tenant_purge")
	requireOutboxPlanAny(t, s.DB, "tenant telemetry retrying", tenantOutboxRetryingCountQuery,
		[]any{deliveryMaxAttempts, DefaultTenantID}, []string{"outbox_sent_at", "outbox_terminal_due"}, "outbox_tenant_purge")
	requireOutboxPlanAny(t, s.DB, "tenant telemetry failed", tenantOutboxFailedCountQuery,
		[]any{deliveryMaxAttempts, DefaultTenantID}, []string{"outbox_sent_at", "outbox_terminal_due"}, "outbox_tenant_purge")
}

func seedRetainedOutboxHistory(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	stamp := "2026-10-16T00:00:00Z"
	const retainedSentRows = 1000
	if _, err := db.ExecContext(ctx, `WITH RECURSIVE rows(n) AS (
		VALUES(1) UNION ALL SELECT n+1 FROM rows WHERE n<?
	) INSERT INTO outbox(destination,payload_json,next_at,sent_at,tenant_id)
	SELECT printf('retained-sent-%04d',n),zeroblob(4096),?,?,? FROM rows`, retainedSentRows, stamp, stamp, DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	const unsentRows = 8
	if _, err := db.ExecContext(ctx, `WITH RECURSIVE rows(n) AS (
		VALUES(1) UNION ALL SELECT n+1 FROM rows WHERE n<?
	) INSERT INTO outbox(destination,payload_json,next_at,tenant_id,terminal_at,attempts)
	SELECT printf('retained-terminal-%04d',n),zeroblob(4096),?,?,?,? FROM rows`, unsentRows, stamp, DefaultTenantID, stamp, deliveryMaxAttempts); err != nil {
		t.Fatal(err)
	}
	var sent, terminal int
	if err := db.QueryRowContext(ctx, `SELECT SUM(sent_at IS NOT NULL),SUM(terminal_at<>'') FROM outbox WHERE tenant_id=?`, DefaultTenantID).Scan(&sent, &terminal); err != nil {
		t.Fatal(err)
	}
	if sent != retainedSentRows || terminal != unsentRows {
		t.Fatalf("seeded outbox history = sent:%d terminal:%d; want sent:%d terminal:%d", sent, terminal, retainedSentRows, unsentRows)
	}
}

func TestTenantPurgeStillUsesCoveringOutboxIndex(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	var tenantPurgeStep string
	for _, step := range tenantPurgeSteps {
		if step.table == "outbox" {
			tenantPurgeStep = step.rowids

			break
		}
	}
	if tenantPurgeStep == "" {
		t.Fatal("missing tenant outbox purge step")
	}
	requireOutboxPlan(t, s.DB, "tenant purge batch", tenantPurgeStep+` LIMIT ?2`, []any{DefaultTenantID, 10}, "outbox_tenant_purge", "")
	requireOutboxPlan(t, s.DB, "tenant purge remaining check", `SELECT EXISTS(SELECT 1 FROM outbox WHERE tenant_id=?)`,
		[]any{DefaultTenantID}, "outbox_tenant_purge", "")
}

func requireOutboxPlan(t *testing.T, db *sql.DB, name, statement string, args []any, wantIndex, forbiddenIndex string) {
	t.Helper()
	plan := strings.Join(explainPlan(t, db, statement, args...), " | ")
	t.Logf("%s plan: %s", name, plan)
	if !strings.Contains(plan, wantIndex) {
		t.Errorf("%s plan = %s; want %s", name, plan, wantIndex)
	}
	if forbiddenIndex != "" && strings.Contains(plan, forbiddenIndex) {
		t.Errorf("%s plan = %s; must not use %s", name, plan, forbiddenIndex)
	}
}

func requireOutboxPlanAny(t *testing.T, db *sql.DB, name, statement string, args []any, wantIndexes []string, forbiddenIndex string) {
	t.Helper()
	plan := strings.Join(explainPlan(t, db, statement, args...), " | ")
	t.Logf("%s plan: %s", name, plan)
	for _, wantIndex := range wantIndexes {
		if strings.Contains(plan, wantIndex) {
			if forbiddenIndex != "" && strings.Contains(plan, forbiddenIndex) {
				t.Errorf("%s plan = %s; must not use %s", name, plan, forbiddenIndex)
			}
			return
		}
	}
	t.Errorf("%s plan = %s; want one of %v", name, plan, wantIndexes)
}
