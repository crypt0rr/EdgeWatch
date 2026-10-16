package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

const expiryDestinationSavedTable = "managed_notifications_expiry_saved"

func breakExpiryDestinationRead(t *testing.T, ctx context.Context, db *store.Store) {
	t.Helper()
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications RENAME TO `+expiryDestinationSavedTable); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `CREATE VIEW managed_notifications(id,tenant_id,name,provider,ciphertext,nonce,enabled,revision,credential_revision,created_at,updated_at) AS SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM missing_managed_notifications_expiry_fixture`); err != nil {
		t.Fatal(err)
	}
}

func restoreExpiryDestinationRead(t *testing.T, ctx context.Context, db *store.Store) {
	t.Helper()
	if _, err := db.DB.ExecContext(ctx, `DROP VIEW managed_notifications`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE `+expiryDestinationSavedTable+` RENAME TO managed_notifications`); err != nil {
		t.Fatal(err)
	}
}

func newExpiryDestinationFailureFixture(t *testing.T, logs *strings.Builder) (*App, *store.Store, *store.TenantStore, store.JobRecord, store.ChangeWindow, time.Time) {
	t.Helper()
	ctx := context.Background()
	a, db := newLifecycleTestApp(t, schedulerFake{}, logs)
	ts := defaultTenant(db)
	managed, err := a.Notifier.Tenant(ts).CreateManagedWithAudit(ctx, "Expiry destination recovery", "generic://localhost/expiry?disabletls=yes&template=json", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	definition := lifecycleJob("expiry-destination-recovery")
	definition.NotificationDestinations = []string{managed.ID}
	job, err := ts.CreateJob(ctx, definition)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	end := now.Add(2 * time.Hour)
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, end, true, "planned maintenance", "expiry-test", "Expiry Test")
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{Type: "changes-detected", JobID: job.ID, Job: job.Job.Name, ScanID: "expiry-destination-scan", Message: "one change", CreatedAt: now, Changes: []model.Change{{Key: "expiry-destination-change", Kind: "port", Target: "192.0.2.1", Port: 443}}}
	if err := db.System().QueueEvent(ctx, "expiry-destination-event", event); err != nil {
		t.Fatal(err)
	}
	return a, db, ts, job, window, end
}

func TestExpireChangeWindowsRetriesDestinationReadThroughGrace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var logs strings.Builder
	a, db, ts, job, window, end := newExpiryDestinationFailureFixture(t, &logs)
	breakExpiryDestinationRead(t, ctx, db)

	for _, now := range []time.Time{end, end.Add(store.ChangeWindowSummaryDestinationGrace).Add(-time.Nanosecond)} {
		a.clock = func() time.Time { return now }
		a.expireChangeWindows(ctx, db.System(), false)
		open, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
		if err != nil {
			t.Fatal(err)
		}
		if open.ClosedAt != nil || open.Summary != nil {
			t.Fatalf("destination read failure at %s closed the window: %+v", now, open)
		}
		var coalesced int
		if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE change_window_id=? AND coalesced_at<>''`, window.ID).Scan(&coalesced); err != nil || coalesced != 0 {
			t.Fatalf("destination read failure at %s coalesced %d held rows, err %v", now, coalesced, err)
		}
	}
	if strings.Contains(logs.String(), "missing_managed_notifications_expiry_fixture") {
		t.Fatalf("destination lookup details escaped into logs: %q", logs.String())
	}

	restoreExpiryDestinationRead(t, ctx, db)
	a.clock = func() time.Time { return end.Add(store.ChangeWindowSummaryDestinationGrace).Add(-time.Second) }
	a.expireChangeWindows(ctx, db.System(), false)
	closed, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.ClosedAt == nil || closed.ReviewState != "due" || closed.Summary == nil || closed.Summary.SuppressedEventCount != 1 || closed.Summary.SummaryNotificationStatus != "" {
		t.Fatalf("restored destinations before the bound did not close normally: %+v", closed)
	}
	if countRowsForExpiryTest(t, db, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND event_job_id=?`, job.ID) != 1 {
		t.Fatal("restored destination lookup did not queue exactly one summary")
	}
	if countRowsForExpiryTest(t, db, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID) != 1 {
		t.Fatal("restored destination lookup did not persist exactly one review event")
	}
	a.expireChangeWindows(ctx, db.System(), false)
	if countRowsForExpiryTest(t, db, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND event_job_id=?`, job.ID) != 1 {
		t.Fatal("repeated expiry duplicated the summary notification")
	}
}

func TestExpireChangeWindowsAtDestinationGraceRecordsUndeliveredSummaryAndReleasesAlerts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var logs strings.Builder
	a, db, ts, job, window, _ := newExpiryDestinationFailureFixture(t, &logs)
	endedAt := time.Now().UTC().Add(-time.Second).Truncate(time.Second)
	if _, err := db.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, endedAt.Format(time.RFC3339Nano), window.ID); err != nil {
		t.Fatal(err)
	}
	var alertID int64
	if err := db.DB.QueryRowContext(ctx, `SELECT id FROM outbox WHERE event_job_id=? AND event_type='changes-detected'`, job.ID).Scan(&alertID); err != nil {
		t.Fatal(err)
	}
	breakExpiryDestinationRead(t, ctx, db)
	terminalAt := endedAt.Add(store.ChangeWindowSummaryDestinationGrace)
	a.clock = func() time.Time { return terminalAt }
	a.expireChangeWindows(ctx, db.System(), false)
	closed, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.ClosedAt == nil || closed.ReviewState != "due" || closed.Summary == nil || closed.Summary.SummaryNotificationStatus != "not_queued_destinations_unavailable" {
		t.Fatalf("terminal destination failure was not recorded in the review: %+v", closed)
	}
	var eventPayload []byte
	if err := db.DB.QueryRowContext(ctx, `SELECT payload_json FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID).Scan(&eventPayload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(eventPayload), "summary notification was not queued") || !strings.Contains(string(eventPayload), "individual alerts remain retryable") {
		t.Fatalf("durable review event omits the undelivered summary outcome: %s", eventPayload)
	}
	var link, coalesced, claim, started string
	if err := db.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at,claim_token,attempt_started_at FROM outbox WHERE id=?`, alertID).Scan(&link, &coalesced, &claim, &started); err != nil {
		t.Fatal(err)
	}
	if link != "" || coalesced != "" || claim != "" || started != "" {
		t.Fatalf("eligible alert after fallback link=%q coalesced=%q claim=%q started=%q", link, coalesced, claim, started)
	}
	if countRowsForExpiryTest(t, db, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND event_job_id=?`, job.ID) != 0 {
		t.Fatal("summary notification was queued without loaded destinations")
	}
	if countRowsForExpiryTest(t, db, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID) != 1 {
		t.Fatal("terminal fallback did not retain one durable summary/review event")
	}
	if !drainWake(a) {
		t.Fatal("released individual alert did not wake delivery")
	}

	// A second failed destination lookup cannot repeat the close or the release.
	a.expireChangeWindows(ctx, db.System(), false)
	if countRowsForExpiryTest(t, db, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID) != 1 {
		t.Fatal("repeated terminal expiry duplicated the durable review")
	}
	if countRowsForExpiryTest(t, db, `SELECT COUNT(*) FROM outbox WHERE id=? AND coalesced_at=''`, alertID) != 1 {
		t.Fatal("repeated terminal expiry removed the individually retryable alert")
	}
	if strings.Contains(logs.String(), "missing_managed_notifications_expiry_fixture") {
		t.Fatalf("destination lookup details escaped into logs: %q", logs.String())
	}
}

func countRowsForExpiryTest(t *testing.T, db *store.Store, query string, args ...any) int {
	t.Helper()
	var count int
	if err := db.DB.QueryRowContext(context.Background(), query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
