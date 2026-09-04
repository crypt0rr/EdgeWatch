package notify

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
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
