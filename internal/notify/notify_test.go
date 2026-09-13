package notify

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestQueueAndDeliverGenericWebhook(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	destination := "generic://" + parsed.Host + "/edgewatch?disabletls=yes&template=json"
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	notifier, err := New(db, []string{destination})
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{Type: "changes-detected", Job: "public", ScanID: "scan-1", Message: "one change", CreatedAt: time.Now(), Changes: []model.Change{{Target: "example.com", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}}}
	if err := notifier.Queue(context.Background(), []model.Event{event}); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("received %d webhook calls", calls.Load())
	}
	due, err := db.DueDeliveries(context.Background(), 10)
	if err != nil || len(due) != 0 {
		t.Fatalf("delivery remains due: %#v %v", due, err)
	}
}

func TestDrainProcessesMultipleBoundedBatches(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	destination := "generic://" + parsed.Host + "/edgewatch?disabletls=yes&template=json"
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	notifier, err := New(db, []string{destination})
	if err != nil {
		t.Fatal(err)
	}
	events := make([]model.Event, 40)
	for i := range events {
		events[i] = model.Event{Type: "batch", Job: "job", ScanID: fmt.Sprintf("scan-%d", i), Message: fmt.Sprintf("event-%d", i), CreatedAt: time.Now().UTC()}
	}
	if err := notifier.Queue(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != int32(len(events)) {
		t.Fatalf("webhook calls = %d, want %d", calls.Load(), len(events))
	}
	due, err := db.DueDeliveries(context.Background(), 100)
	if err != nil || len(due) != 0 {
		t.Fatalf("deliveries remain after bounded multi-batch drain: %#v %v", due, err)
	}
}

func TestQueueDestinationsForJobUsesStableSelection(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	deployment := "generic://localhost/deployment?disabletls=yes&template=json"
	notifier, err := New(db, []string{deployment})
	if err != nil {
		t.Fatal(err)
	}
	managed, err := notifier.CreateManaged(ctx, "Operations", "generic://localhost/managed?disabletls=yes&template=json", true)
	if err != nil {
		t.Fatal(err)
	}
	all, err := notifier.QueueDestinationsForJob(ctx, config.Job{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("legacy selection returned %d destinations, want 2", len(all))
	}
	selected, err := notifier.QueueDestinationsForJob(ctx, config.Job{NotificationDestinations: []string{managed.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0] != managedKey(managed.ID, managed.Revision) {
		t.Fatalf("managed selection = %#v, want current managed revision", selected)
	}
	selected, err = notifier.QueueDestinationsForJob(ctx, config.Job{NotificationDestinations: []string{"file:" + hashURL(deployment)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0] != hashURL(deployment) {
		t.Fatalf("deployment selection = %#v, want hashed file key", selected)
	}
	none, err := notifier.QueueDestinationsForJob(ctx, config.Job{NotificationDestinations: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("explicit empty selection returned %#v", none)
	}
	if err := notifier.ValidateDestinationSelection(ctx, []string{managed.ID, "file:" + hashURL(deployment)}); err != nil {
		t.Fatalf("valid selection rejected: %v", err)
	}
	if err := notifier.ValidateDestinationSelection(ctx, []string{"managed:missing"}); err == nil {
		t.Fatal("unknown destination selection accepted")
	}
}

func TestCreateManagedDoesNotOptInExistingLegacyJobs(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	deployment := "generic://localhost/deployment?disabletls=yes&template=json"
	legacyJob := config.NormalizeJob(config.Job{
		Name:     "legacy-job",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"127.0.0.1"},
		TCP:      &config.Protocol{Ports: "1", Mode: "connect"},
		Timeout:  config.Duration(time.Minute),
		Timing:   "balanced",
	})
	createdJob, err := db.CreateJob(ctx, legacyJob)
	if err != nil {
		t.Fatal(err)
	}
	if createdJob.Job.NotificationDestinations != nil {
		t.Fatalf("fixture unexpectedly has a saved selection: %#v", createdJob.Job.NotificationDestinations)
	}

	notifier, err := New(db, []string{deployment})
	if err != nil {
		t.Fatal(err)
	}
	created, err := notifier.CreateManaged(ctx, "Operations", "generic://localhost/managed?disabletls=yes&template=json", true)
	if err != nil {
		t.Fatal(err)
	}

	stored, err := db.GetJob(ctx, createdJob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != createdJob.Revision+1 {
		t.Fatalf("legacy job revision = %d, want %d", stored.Revision, createdJob.Revision+1)
	}
	if stored.Job.NotificationDestinations == nil || len(stored.Job.NotificationDestinations) != 1 {
		t.Fatalf("legacy job selection = %#v, want the pre-existing deployment destination", stored.Job.NotificationDestinations)
	}
	if stored.Job.NotificationDestinations[0] != "file:"+hashURL(deployment) {
		t.Fatalf("legacy job selection = %#v, want file destination", stored.Job.NotificationDestinations)
	}
	if stored.Job.NotificationDestinations[0] == created.ID {
		t.Fatalf("new managed destination was added to legacy job selection: %#v", stored.Job.NotificationDestinations)
	}
	keys, err := notifier.QueueDestinationsForJob(ctx, stored.Job)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != hashURL(deployment) {
		t.Fatalf("legacy job queued destinations = %#v, want only the pre-existing deployment destination", keys)
	}
}

func TestQueueDestinationsForJobTracksManagedRevision(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	notifier, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := notifier.CreateManaged(ctx, "Operations", "generic://localhost/first?disabletls=yes&template=json", true)
	if err != nil {
		t.Fatal(err)
	}
	updatedURL := "generic://localhost/second?disabletls=yes&template=json"
	if _, err := notifier.UpdateManaged(ctx, created.ID, created.Revision, created.Name, &updatedURL, nil); err != nil {
		t.Fatal(err)
	}
	keys, err := notifier.QueueDestinationsForJob(ctx, config.Job{NotificationDestinations: []string{created.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != managedKey(created.ID, created.Revision+1) {
		t.Fatalf("revision-aware selection = %#v", keys)
	}
}

func TestConcurrentDrainsDoNotDuplicateDelivery(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		once.Do(func() { close(entered) })
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	destination := "generic://" + parsed.Host + "/edgewatch?disabletls=yes&template=json"
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	notifier, err := New(db, []string{destination})
	if err != nil {
		t.Fatal(err)
	}
	if err := notifier.Queue(context.Background(), []model.Event{{Type: "concurrent", Job: "job", CreatedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() { firstDone <- notifier.Drain(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first drain did not reach webhook")
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- notifier.Drain(context.Background()) }()
	select {
	case err := <-secondDone:
		t.Fatalf("second drain completed while first delivery was in flight: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("webhook calls = %d, want one", calls.Load())
	}
}

func TestLockedManagedDeliveryIsDeferredWithoutAttempts(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyPath := filepath.Join(dir, "notification.key")
	creator, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := creator.CreateManaged(ctx, "Locked", "generic://localhost/locked?disabletls=yes&template=json", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueueEvent(ctx, managedKey(created.ID, created.Revision), model.Event{Type: "locked", Job: "job", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	locked, err := NewWithKeyFile(db, nil, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := locked.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	var attempts int
	if err := db.DB.QueryRowContext(ctx, `SELECT attempts FROM outbox WHERE destination=?`, managedKey(created.ID, created.Revision)).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("locked delivery attempts = %d, want 0", attempts)
	}
}

func TestLockedDestinationDoesNotStarveHealthyDelivery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyPath := filepath.Join(dir, "notification.key")
	creator, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := creator.CreateManaged(ctx, "Locked", "generic://localhost/locked?disabletls=yes&template=json", true)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	healthy := "generic://" + parsed.Host + "/healthy?disabletls=yes&template=json"
	managedDestination := managedKey(created.ID, created.Revision)
	for i := 0; i < 10; i++ {
		if err := db.QueueEvent(ctx, managedDestination, model.Event{Type: "locked", Job: "job", ScanID: fmt.Sprintf("locked-%d", i), CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.QueueEvent(ctx, hashURL(healthy), model.Event{Type: "healthy", Job: "job", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	locked, err := NewWithKeyFile(db, []string{healthy}, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := locked.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("healthy destination calls = %d, want 1", calls.Load())
	}
	var pendingLocked, liveClaims int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=? AND attempts=0`, managedDestination).Scan(&pendingLocked); err != nil {
		t.Fatal(err)
	}
	if pendingLocked != 10 {
		t.Fatalf("locked rows changed during healthy drain: %d", pendingLocked)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE claim_token<>''`).Scan(&liveClaims); err != nil {
		t.Fatal(err)
	}
	if liveClaims != 0 {
		t.Fatalf("locked rows retained live claims: %d", liveClaims)
	}
}

func TestCanceledBatchReleasesUnsentClaims(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	notifier, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < notificationBatchSize; i++ {
		if err := db.QueueEvent(ctx, "destination", model.Event{Type: "cancel", Job: "job", ScanID: fmt.Sprintf("scan-%d", i), CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	deliveries, err := db.ClaimDueDeliveries(ctx, notificationBatchSize, "owner")
	if err != nil || len(deliveries) != notificationBatchSize {
		t.Fatalf("claimed deliveries = %d, error = %v", len(deliveries), err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_ = notifier.deliverBatch(canceled, deliveries, nil)
	var liveClaims, attempts, deferrals int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE claim_token<>''`).Scan(&liveClaims); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COALESCE(SUM(attempts),0) FROM outbox`).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COALESCE(SUM(deferrals),0) FROM outbox`).Scan(&deferrals); err != nil {
		t.Fatal(err)
	}
	if liveClaims != 0 || attempts != 0 || deferrals != 0 {
		t.Fatalf("canceled batch left claims/budgets: claims=%d attempts=%d deferrals=%d", liveClaims, attempts, deferrals)
	}
}

func TestCanceledDeliveryReleasesClaimWithoutBudget(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	notifier, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueueEvent(ctx, "destination", model.Event{Type: "cancel-one", Job: "job", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	due, err := db.ClaimDueDeliveries(ctx, 1, "owner")
	if err != nil || len(due) != 1 {
		t.Fatalf("claimed delivery = %#v, error = %v", due, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := notifier.deliverOne(canceled, due[0], nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled delivery error = %v, want context cancellation", err)
	}
	var attempts, deferrals, claims int
	if err := db.DB.QueryRowContext(ctx, `SELECT attempts,deferrals,CASE WHEN claim_token<>'' THEN 1 ELSE 0 END FROM outbox WHERE id=?`, due[0].ID).Scan(&attempts, &deferrals, &claims); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || deferrals != 0 || claims != 0 {
		t.Fatalf("canceled delivery consumed state: attempts=%d deferrals=%d claims=%d", attempts, deferrals, claims)
	}
}

func TestInvalidURLDoesNotLeakSecret(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = New(db, []string{"unknown://super-secret@example.invalid/path"})
	if err == nil {
		t.Fatal("invalid URL accepted")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("secret leaked in error: %v", err)
	}
}

func TestSafeSendRedactsProviderErrors(t *testing.T) {
	rawURL := "unknown://secret-token@example.invalid/path"
	err := safeSend(rawURL, "test")
	if err == nil {
		t.Fatal("invalid destination unexpectedly sent")
	}
	if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), rawURL) {
		t.Fatalf("provider error leaked destination: %v", err)
	}
	if !strings.Contains(err.Error(), hashURL(rawURL)[:12]) {
		t.Fatalf("redacted error omitted destination fingerprint: %v", err)
	}
}

func TestSafeSendContextWaitsForInFlightSendAfterCancellation(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	destination := "generic://" + parsed.Host + "/edgewatch?disabletls=yes&template=json"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- safeSendContext(ctx, destination, "test") }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("notification send did not reach the provider")
	}
	cancel()
	// A canceled caller must not immediately requeue an in-flight request: the
	// provider may already have accepted it. Let the handler finish and verify
	// the definitive result is observed.
	close(release)
	select {
	case err := <-done:
		if errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled in-flight send returned context cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight notification send did not settle")
	}
}

func TestManagedNotificationCRUDEncryptsAndCancelsOldDeliveries(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyPath := filepath.Join(dir, "notification.key")
	notifier, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstURL := "generic://localhost/first?disabletls=yes&template=json"
	secondURL := "generic://localhost/second?disabletls=yes&template=json"
	created, err := notifier.CreateManaged(ctx, "Operations", firstURL, true)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Revision != 1 || created.Locked || created.ReadOnly || created.Source != "web" {
		t.Fatalf("unexpected managed destination: %#v", created)
	}
	viewJSON, _ := json.Marshal(created)
	if strings.Contains(string(viewJSON), firstURL) || strings.Contains(string(viewJSON), `"url"`) {
		t.Fatalf("destination view exposed a URL: %s", viewJSON)
	}
	record, err := db.GetManagedNotification(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(record.Ciphertext), firstURL) {
		t.Fatal("notification URL was stored in plaintext")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions = %o, want 600", info.Mode().Perm())
	}
	if err := db.QueueEvent(ctx, managedKey(created.ID, created.Revision), model.Event{Type: "test", Job: "ops", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	updated, err := notifier.UpdateManaged(ctx, created.ID, created.Revision, "Operations", &secondURL, boolPtr(true))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.Provider != "generic" || updated.Locked {
		t.Fatalf("unexpected updated destination: %#v", updated)
	}
	if _, err := notifier.UpdateManaged(ctx, created.ID, created.Revision, "stale", nil, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale update error = %v, want conflict", err)
	}
	var pending int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE destination LIKE ?`, "managed:"+created.ID+":%").Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("pending deliveries for old revision = %d", pending)
	}
	restarted, err := NewWithKeyFile(db, nil, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if views := restarted.Destinations(); len(views) != 1 || views[0].Locked || views[0].Provider != "generic" {
		t.Fatalf("managed destination did not survive reload: %#v", views)
	}
	if err := restarted.DeleteManaged(ctx, created.ID, updated.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetManagedNotification(ctx, created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted destination lookup = %v", err)
	}
}

func TestManagedNotificationLocksWhenKeyIsUnavailable(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyPath := filepath.Join(t.TempDir(), "notification.key")
	if _, err := createKey(keyPath); err != nil {
		t.Fatal(err)
	}
	creator, err := NewWithKeyFile(db, nil, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	created, err := creator.CreateManaged(ctx, "Locked", "generic://localhost/locked?disabletls=yes&template=json", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	fileURL := "generic://localhost/deployment?disabletls=yes&template=json"
	locked, err := NewWithKeyFile(db, []string{fileURL}, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	views := locked.Destinations()
	if len(views) != 2 {
		t.Fatalf("unexpected destination count: %#v", views)
	}
	var managedView DestinationView
	for _, view := range views {
		if view.Source == "web" {
			managedView = view
		}
	}
	if managedView.ID == "" || !managedView.Locked || managedView.ErrorCode != "key_unavailable" {
		t.Fatalf("unexpected locked view: %#v", views)
	}
	if locked.ActiveCount() != 1 {
		t.Fatalf("active destination count = %d, want deployment destination only", locked.ActiveCount())
	}
	if err := locked.Queue(ctx, []model.Event{{Type: "test", Job: "ops", CreatedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	var queued int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE destination=?`, hashURL(fileURL)).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Fatalf("deployment notification was not queued while managed key was locked: %d", queued)
	}
	var managedQueued int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE destination=?`, managedKey(created.ID, created.Revision)).Scan(&managedQueued); err != nil {
		t.Fatal(err)
	}
	if managedQueued != 1 {
		t.Fatalf("managed notification was dropped while key was locked: %d", managedQueued)
	}
	if err := locked.TestDestination(created.ID); !errors.Is(err, ErrManagedNotificationLocked) {
		t.Fatalf("locked test error = %v", err)
	}
	if _, err := locked.UpdateManaged(ctx, created.ID, created.Revision, "Locked renamed", nil, boolPtr(true)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("enabling without key error = %v", err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing key was silently regenerated: %v", err)
	}
	if updated, err := locked.UpdateManaged(ctx, created.ID, created.Revision, "Locked renamed", nil, boolPtr(false)); err != nil || !updated.Locked {
		t.Fatalf("disabling locked destination: %#v %v", updated, err)
	}
}

func boolPtr(value bool) *bool { return &value }

func TestManagedNotificationWrongKeyIsReportedAsDecryptFailure(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyPath := filepath.Join(t.TempDir(), "notification.key")
	if _, err := createKey(keyPath); err != nil {
		t.Fatal(err)
	}
	creator, err := NewWithKeyFile(db, nil, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := creator.CreateManaged(ctx, "Wrong key", "generic://localhost/wrong?disabletls=yes&template=json", true); err != nil {
		t.Fatal(err)
	}
	wrong := make([]byte, notificationKeySize)
	if _, err := rand.Read(wrong); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, wrong, 0o600); err != nil {
		t.Fatal(err)
	}
	locked, err := NewWithKeyFile(db, nil, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	status := locked.Status()
	if status["key_state"] != "decrypt_failed" || status["locked"] != 1 {
		t.Fatalf("wrong key status = %#v", status)
	}
}

func TestExplicitKeyPathIsNotGenerated(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyPath := filepath.Join(t.TempDir(), "external-notification.key")
	notifier, err := NewWithKeyFile(db, nil, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := notifier.CreateManaged(ctx, "External", "generic://localhost/external?disabletls=yes&template=json", true); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("missing external key error = %v, want ErrKeyUnavailable", err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("external key path was generated: %v", err)
	}
}

func TestNotificationKeyRejectsUnsafePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notification.key")
	if err := os.WriteFile(path, make([]byte, notificationKeySize), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKey(path); !errors.Is(err, ErrKeyPermissions) {
		t.Fatalf("unsafe key error = %v", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKey(path); !errors.Is(err, ErrKeyPermissions) {
		t.Fatalf("executable key error = %v", err)
	}
}
