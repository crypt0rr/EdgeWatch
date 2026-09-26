package notify

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// countingWebhook starts a local generic webhook that counts the requests it
// receives. It never forwards anything outside the test process.
func countingWebhook(t *testing.T, path string) (string, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return "generic://" + parsed.Host + "/" + path + "?disabletls=yes&template=json", &calls
}

func TestStoreBackedNotificationTestSendsOncePerDeploymentDestination(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw, calls := countingWebhook(t, "deployment")
	notifier, err := New(db, []string{raw})
	if err != nil {
		t.Fatal(err)
	}
	summary, err := notifier.TestSummaryContext(ctx)
	if err != nil {
		t.Fatalf("notification test: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("deployment destination received %d test messages, want 1", got)
	}
	if summary != (TestSummary{Tested: 1}) {
		t.Fatalf("test summary = %#v, want one tested destination", summary)
	}

	// The legacy digest alias must keep routing outbox rows created before
	// opaque deployment IDs, even though it no longer adds a test send.
	if err := db.QueueEvent(ctx, hashURL(raw), model.Event{Type: "legacy", Job: "job", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Drain(ctx); err != nil {
		t.Fatalf("drain legacy digest row: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("legacy digest outbox row was not delivered: calls=%d", got)
	}
}

func TestNotificationTestKeepsManagedDestinationSharingDeploymentURL(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw, calls := countingWebhook(t, "shared")
	notifier, err := New(db, []string{raw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := notifier.CreateManaged(ctx, "Shared", raw, true); err != nil {
		t.Fatal(err)
	}
	summary, err := notifier.TestSummaryContext(ctx)
	if err != nil {
		t.Fatalf("notification test: %v", err)
	}
	// A managed destination deliberately configured with the deployment URL
	// is a separate destination and is tested separately.
	if got := calls.Load(); got != 2 || summary.Tested != 2 {
		t.Fatalf("shared-URL test = %d messages, summary %#v; want 2 of each", got, summary)
	}
}

// lockManagedDestination creates an enabled managed destination and then
// replaces or removes its key, as an operator restoring the wrong key would.
func lockManagedDestination(t *testing.T, db *store.Store, keyPath string, removeKey bool) DestinationView {
	t.Helper()
	creator, err := newWithKeyFile(db, nil, keyPath, true)
	if err != nil {
		t.Fatal(err)
	}
	created, err := creator.CreateManaged(context.Background(), "Ops", "generic://127.0.0.1:9/ops?disabletls=yes&template=json", true)
	if err != nil {
		t.Fatal(err)
	}
	if removeKey {
		if err := os.Remove(keyPath); err != nil {
			t.Fatal(err)
		}
		return created
	}
	wrong := make([]byte, notificationKeySize)
	if _, err := rand.Read(wrong); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, wrong, 0o600); err != nil {
		t.Fatal(err)
	}
	return created
}

func TestNotificationTestFailsForLockedManagedDestination(t *testing.T) {
	for _, tc := range []struct {
		name      string
		removeKey bool
		code      string
	}{
		{name: "wrong key", code: "decrypt_failed"},
		{name: "missing key", removeKey: true, code: "key_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			db, err := store.Open(filepath.Join(dir, "edgewatch.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			keyPath := filepath.Join(dir, "notification.key")
			created := lockManagedDestination(t, db, keyPath, tc.removeKey)

			notifier, err := New(db, nil)
			if err != nil {
				t.Fatal(err)
			}
			summary, err := notifier.TestSummaryContext(ctx)
			if !errors.Is(err, ErrManagedNotificationLocked) {
				t.Fatalf("locked destination test error = %v, want ErrManagedNotificationLocked", err)
			}
			if !strings.Contains(err.Error(), created.ID) || !strings.Contains(err.Error(), tc.code) {
				t.Fatalf("locked destination error %q does not name the destination and lock reason", err)
			}
			if strings.Contains(err.Error(), "generic://") || strings.Contains(err.Error(), "127.0.0.1") {
				t.Fatalf("locked destination error leaked the destination URL: %v", err)
			}
			if summary != (TestSummary{Locked: 1}) {
				t.Fatalf("locked test summary = %#v, want one locked destination", summary)
			}
			if err := notifier.Test(); !errors.Is(err, ErrManagedNotificationLocked) {
				t.Fatalf("Test() error = %v, want ErrManagedNotificationLocked", err)
			}
		})
	}
}

func TestNotificationTestFailsWhenWorkingDeploymentAndLockedManagedDestinationMix(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	lockManagedDestination(t, db, filepath.Join(dir, "notification.key"), false)
	raw, calls := countingWebhook(t, "deployment")
	notifier, err := New(db, []string{raw})
	if err != nil {
		t.Fatal(err)
	}
	summary, err := notifier.TestSummaryContext(ctx)
	if !errors.Is(err, ErrManagedNotificationLocked) {
		t.Fatalf("mixed test error = %v, want ErrManagedNotificationLocked", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("working deployment destination received %d test messages, want 1", got)
	}
	if summary != (TestSummary{Tested: 1, Locked: 1}) {
		t.Fatalf("mixed test summary = %#v", summary)
	}
}

func TestCanceledNotificationTestCountsEveryDestinationAsFailed(t *testing.T) {
	var urls []string
	var counters []*atomic.Int32
	for i := 0; i < notificationWorkers+2; i++ {
		raw, calls := countingWebhook(t, "canceled-"+string(rune('a'+i)))
		urls = append(urls, raw)
		counters = append(counters, calls)
	}
	notifier, err := New(nil, urls)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	summary, err := notifier.TestSummaryContext(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled test error = %v, want context.Canceled", err)
	}
	if summary != (TestSummary{Tested: len(urls), Failed: len(urls)}) {
		t.Fatalf("canceled test summary = %#v, want every destination failed", summary)
	}
	for i, calls := range counters {
		if calls.Load() != 0 {
			t.Fatalf("destination %d was contacted after cancellation", i)
		}
	}
}

func TestNotificationTestIgnoresPausedLockedManagedDestination(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyPath := filepath.Join(dir, "notification.key")
	created := lockManagedDestination(t, db, keyPath, true)
	notifier, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Pausing a locked destination is allowed without the key. A paused
	// destination is not part of the global test, locked or not.
	if _, err := notifier.UpdateManaged(ctx, created.ID, created.Revision, created.Name, nil, boolPtr(false)); err != nil {
		t.Fatal(err)
	}
	summary, err := notifier.TestSummaryContext(ctx)
	if err != nil {
		t.Fatalf("paused locked destination failed the global test: %v", err)
	}
	if summary != (TestSummary{}) {
		t.Fatalf("paused locked test summary = %#v, want nothing tested", summary)
	}
}
