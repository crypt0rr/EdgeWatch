package notify

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestClaimBeforeWindowStartIsStoppedAtFinalProviderGateWithoutBudget(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ts := db.Tenant(store.DefaultTenantScope())
	job, err := ts.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "final-window-gate", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	const destination = "generic://localhost/final-window-gate?disabletls=yes&template=json"
	notifier, err := New(db, []string{destination})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(time.Hour)
	window, err := ts.CreateChangeWindow(ctx, job.ID, start, start.Add(time.Hour), false, "scheduled maintenance", "actor", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{
		Type: "changes-detected", JobID: job.ID, Job: job.Job.Name, ScanID: "final-gate-scan",
		Message: "observed change", CreatedAt: time.Now().UTC(),
		Changes: []model.Change{{Key: "final-gate-change", Kind: "port", Target: "192.0.2.10", Protocol: "tcp", Port: 443}},
	}
	if err := notifier.Queue(ctx, []model.Event{event}); err != nil {
		t.Fatal(err)
	}
	claimed, err := db.System().ClaimDueDeliveries(ctx, 8, "window-boundary-claim")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before window start = %d deliveries, %v", len(claimed), err)
	}

	// Move the scheduled boundary close to the already-issued claim so the
	// test exercises the final transaction deterministically without a long
	// sleep. Claim-time filtering happened while this boundary was still far
	// in the future; provider handoff happens only after it becomes active.
	boundary := time.Now().UTC().Add(150 * time.Millisecond)
	fixedBoundary := boundary.Format("2006-01-02T15:04:05.000000000Z07:00")
	if _, err := db.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=? WHERE id=?`, fixedBoundary, window.ID); err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(boundary) + 25*time.Millisecond; delay > 0 {
		timer := time.NewTimer(delay)
		<-timer.C
	}

	var providerCalls atomic.Int32
	previousSend := notificationProviderSend
	notificationProviderSend = func(context.Context, string, string) error {
		providerCalls.Add(1)
		return nil
	}
	t.Cleanup(func() { notificationProviderSend = previousSend })
	if err := notifier.deliverOne(ctx, claimed[0], notifier.destinationSnapshot()); err != nil {
		t.Fatalf("final-window-gated delivery = %v", err)
	}
	if providerCalls.Load() != 0 {
		t.Fatalf("provider was invoked %d times after the window began", providerCalls.Load())
	}
	var attempts, deferrals int
	var lastError, terminalAt, claim, attemptStarted, coalescedAt string
	if err := db.DB.QueryRowContext(ctx, `SELECT attempts,deferrals,last_error,terminal_at,claim_token,attempt_started_at,coalesced_at FROM outbox WHERE id=?`, claimed[0].ID).Scan(&attempts, &deferrals, &lastError, &terminalAt, &claim, &attemptStarted, &coalescedAt); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || deferrals != 0 || lastError != "" || terminalAt != "" || claim != "" || attemptStarted != "" || coalescedAt != "" {
		t.Fatalf("held outbox row has attempts=%d deferrals=%d error=%q terminal=%q claim=%q started=%q coalesced=%q", attempts, deferrals, lastError, terminalAt, claim, attemptStarted, coalescedAt)
	}
	var failedHealth int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_delivery_health WHERE last_failure_at<>'' OR terminal_failures>0 OR last_error_code<>''`).Scan(&failedHealth); err != nil {
		t.Fatal(err)
	}
	if failedHealth != 0 {
		t.Fatalf("final gate recorded %d failed destination health entries", failedHealth)
	}
}

func TestIndeterminateSendAfterWindowCloseCoalescesThroughNotifierWithoutHealthPenalty(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ts := db.Tenant(store.DefaultTenantScope())
	job, err := ts.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "late-window-indeterminate", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	const destination = "generic://localhost/late-window-indeterminate?disabletls=yes&template=json"
	notifier, err := New(db, []string{destination})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(time.Hour)
	window, err := ts.CreateChangeWindow(ctx, job.ID, start, start.Add(time.Hour), false, "maintenance", "actor", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{
		Type: "changes-detected", JobID: job.ID, Job: job.Job.Name, ScanID: "late-window-scan",
		Message: "observed change", CreatedAt: time.Now().UTC(),
		Changes: []model.Change{{Key: "late-window-change", Kind: "port", Target: "192.0.2.10", Protocol: "tcp", Port: 443}},
	}
	if err := notifier.Queue(ctx, []model.Event{event}); err != nil {
		t.Fatal(err)
	}
	claimed, err := db.System().ClaimDueDeliveries(ctx, 8, "late-window-claim")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before window start = %d deliveries, %v", len(claimed), err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	previousSend := notificationProviderSend
	notificationProviderSend = func(context.Context, string, string) error {
		close(entered)
		<-release
		return nil
	}
	defer func() {
		notificationProviderSend = previousSend
		close(release)
	}()
	providerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- notifier.deliverOne(providerCtx, claimed[0], notifier.destinationSnapshot()) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("provider handoff did not begin")
	}
	cancel()
	var marker string
	if err := db.DB.QueryRowContext(ctx, `SELECT attempt_started_at FROM outbox WHERE id=?`, claimed[0].ID).Scan(&marker); err != nil || marker == "" {
		t.Fatalf("provider invocation marker = %q, err %v", marker, err)
	}
	// Advance the persisted window after the provider has started, then close
	// it while the provider ignores cancellation and is still inside grace.
	markerAt, err := time.Parse(time.RFC3339Nano, marker)
	if err != nil {
		t.Fatalf("parse provider marker %q: %v", marker, err)
	}
	windowStart := markerAt.Add(5 * time.Second)
	windowEnd := windowStart.Add(time.Second)
	closeAt := windowEnd.Add(time.Second)
	sqliteStamp := func(value time.Time) string { return value.UTC().Format("2006-01-02T15:04:05.000000000Z07:00") }
	if _, err := db.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id=?`, sqliteStamp(windowStart), sqliteStamp(windowEnd), window.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE outbox SET claim_until=? WHERE id=?`, closeAt.Add(time.Minute).Format(time.RFC3339Nano), claimed[0].ID); err != nil {
		t.Fatal(err)
	}
	if summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return closeAt }, []string{destination}); err != nil || !changed || summary.InFlightEventCount != 1 {
		t.Fatalf("close while provider is blocked = %+v, changed %v, err %v", summary, changed, err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotificationSendIndeterminate) {
			t.Fatalf("deliverOne result = %v, want indeterminate send", err)
		}
	case <-time.After(notificationSendCancellationGrace + 3*time.Second):
		t.Fatal("canceled delivery did not exit after its cancellation grace")
	}
	var attempts, deferrals int
	var claim, started, coalesced string
	if err := db.DB.QueryRowContext(ctx, `SELECT attempts,deferrals,claim_token,attempt_started_at,coalesced_at FROM outbox WHERE id=?`, claimed[0].ID).Scan(&attempts, &deferrals, &claim, &started, &coalesced); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || deferrals != 0 || claim != "" || started != "" || coalesced == "" {
		t.Fatalf("late indeterminate outbox row = attempts %d deferrals %d claim %q marker %q coalesced %q", attempts, deferrals, claim, started, coalesced)
	}
	var failures int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_delivery_health WHERE last_failure_at<>'' OR terminal_failures>0 OR last_error_code<>''`).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if failures != 0 {
		t.Fatalf("late indeterminate delivery recorded %d destination health failures", failures)
	}
}
