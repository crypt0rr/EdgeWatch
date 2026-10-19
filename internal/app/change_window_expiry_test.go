package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestExpireChangeWindowsClosesReviewAndWakesDeliveryOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	ts := defaultTenant(db)
	managed, err := a.Notifier.Tenant(ts).CreateManagedWithAudit(ctx, "Expiry summaries", "generic://localhost/expiry?disabletls=yes&template=json", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	jobDefinition := lifecycleJob("expiry-review-wakeup")
	jobDefinition.NotificationDestinations = []string{managed.ID}
	job, err := ts.CreateJob(ctx, jobDefinition)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	end := now.Add(2 * time.Hour)
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, end, true, "planned maintenance", "expiry-test", "Expiry Test")
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{
		Type: "changes-detected", JobID: job.ID, Job: job.Job.Name, ScanID: "expiry-scan",
		Message: "one change", CreatedAt: now, Changes: []model.Change{{Key: "new:expiry-key", Kind: "port", Target: "192.0.2.1", Port: 443}},
	}
	if err := db.System().QueueEvent(ctx, "expiry-destination", event); err != nil {
		t.Fatal(err)
	}
	closeAt := end.Add(time.Second)
	a.clock = func() time.Time { return closeAt }
	live := make(chan model.Event, 2)
	a.SetEventHandler(func(event model.Event) { live <- event })
	drainWake(a)
	a.expireChangeWindows(ctx, db.System(), false)

	select {
	case event := <-live:
		if event.Type != "change-window.updated" || event.JobID != job.ID || event.TenantID != store.DefaultTenantID {
			t.Fatalf("live closure event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("expiry did not emit the tenant-scoped window update")
	}
	closed, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Status != "expired" || closed.EndReason != "expired" || closed.ReviewState != "due" || closed.Summary == nil || closed.Summary.SuppressedEventCount != 1 {
		t.Fatalf("expired review state = %+v", closed)
	}
	if !drainWake(a) {
		t.Fatal("expiry did not wake delivery for the closing summary")
	}
	var summaries int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID).Scan(&summaries); err != nil {
		t.Fatal(err)
	}
	if summaries != 1 {
		t.Fatalf("durable close summaries = %d; want one", summaries)
	}
	var queued int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND event_job_id=?`, job.ID).Scan(&queued); err != nil || queued != 1 {
		t.Fatalf("summary outbox rows = %d, %v; want one selected-destination notification", queued, err)
	}

	a.expireChangeWindows(ctx, db.System(), false)
	if drainWake(a) {
		t.Fatal("a repeated expiry pass woke delivery again")
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID).Scan(&summaries); err != nil || summaries != 1 {
		t.Fatalf("summaries after repeated expiry = %d, %v; want one", summaries, err)
	}
	select {
	case event := <-live:
		t.Fatalf("repeated expiry emitted another event: %+v", event)
	default:
	}
}

func TestExpireChangeWindowsWithoutEvidenceDoesNotWakeDelivery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	ts := defaultTenant(db)
	job, err := ts.CreateJob(ctx, lifecycleJob("expiry-no-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().UTC().Add(2 * time.Hour)
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, end, true, "routine window", "expiry-test", "Expiry Test")
	if err != nil {
		t.Fatal(err)
	}
	a.clock = func() time.Time { return end.Add(time.Second) }
	drainWake(a)
	a.expireChangeWindows(ctx, db.System(), true)
	closed, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Status != "expired" || closed.ReviewState != "none" || closed.Summary != nil {
		t.Fatalf("evidence-free expiry = %+v", closed)
	}
	if drainWake(a) {
		t.Fatal("expiry with no change evidence woke delivery")
	}
}

func TestConcurrentWindowExpiryAndDeliveryDoNotSendHeldAlertIndividually(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	ts := defaultTenant(db)
	type received struct {
		mu     sync.Mutex
		bodies [][]byte
	}
	var got received
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.mu.Lock()
		got.bodies = append(got.bodies, body)
		got.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	managed, err := a.Notifier.Tenant(ts).CreateManagedWithAudit(ctx, "Concurrent expiry", "generic://"+parsed.Host+"/expiry?disabletls=yes&template=json", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	definition := lifecycleJob("concurrent-window-expiry")
	definition.NotificationDestinations = []string{managed.ID}
	job, err := ts.CreateJob(ctx, definition)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	window, err := ts.CreateChangeWindow(ctx, job.ID, now.Add(-time.Hour), now.Add(time.Hour), true, "planned maintenance", "expiry-test", "Expiry Test")
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{Type: "changes-detected", JobID: job.ID, Job: job.Job.Name, ScanID: "concurrent-expiry-scan", Message: "held change", CreatedAt: now, Changes: []model.Change{{Key: "concurrent-held-change", Kind: "port", Target: "192.0.2.91", Port: 443}}}
	if err := db.System().QueueEvent(ctx, "concurrent-expiry-alert", event); err != nil {
		t.Fatal(err)
	}
	end := now.Add(-time.Second)
	if _, err := db.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, end.Format(time.RFC3339Nano), window.ID); err != nil {
		t.Fatal(err)
	}
	a.clock = func() time.Time { return now }
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		a.expireChangeWindows(ctx, db.System(), false)
		results <- nil
	}()
	go func() {
		<-start
		results <- a.Notifier.Drain(ctx)
	}()
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent expiry/delivery pass: %v", err)
		}
	}
	if err := a.Notifier.Drain(ctx); err != nil {
		t.Fatalf("drain closing summary: %v", err)
	}
	closed, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || closed.ClosedAt == nil || closed.Summary == nil || closed.Summary.SuppressedEventCount != 1 {
		t.Fatalf("closed window = %+v, %v; want one suppressed alert", closed, err)
	}
	if got := countRowsForExpiryTest(t, db, `SELECT COUNT(*) FROM outbox WHERE event_job_id=? AND event_type='changes-detected' AND change_window_id=? AND sent_at IS NOT NULL`, job.ID, window.ID); got != 0 {
		t.Fatalf("individually sent held alerts = %d; want zero", got)
	}
	got.mu.Lock()
	bodies := append([][]byte(nil), got.bodies...)
	got.mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("provider calls = %d; want only the closing summary", len(bodies))
	}
	if !strings.Contains(string(bodies[0]), "Planned change window closed") || strings.Contains(string(bodies[0]), "held change") {
		t.Fatalf("provider payload = %q; want only the closing summary", bodies[0])
	}
}

func TestExpireChangeWindowsHandlesNilAndLookupFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var nilApp *App
	nilApp.expireChangeWindows(ctx, nil, true)

	var logs strings.Builder
	a, db := newLifecycleTestApp(t, schedulerFake{}, &logs)
	a.expireChangeWindows(ctx, nil, false)
	if _, err := db.DB.ExecContext(ctx, `DROP TABLE change_windows`); err != nil {
		t.Fatal(err)
	}
	a.expireChangeWindows(ctx, db.System(), true)
	if !strings.Contains(logs.String(), "planned change window expiry lookup failed") || !strings.Contains(logs.String(), "startup=true") {
		t.Fatalf("lookup failure was not logged with startup context: %q", logs.String())
	}
}
