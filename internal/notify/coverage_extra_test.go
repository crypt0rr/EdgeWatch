package notify

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestNotificationValidationAndSecretCryptoBranches(t *testing.T) {
	if providerForURL("GENERIC://localhost/path") != "generic" {
		t.Fatal("provider scheme was not normalized")
	}
	if providerForURL("://malformed") != "" {
		t.Fatal("malformed provider URL returned a scheme")
	}
	for _, raw := range []string{"", "localhost/path", "://malformed"} {
		if _, err := validateManagedURL(raw); err == nil {
			t.Fatalf("invalid managed URL %q was accepted", raw)
		}
	}
	if err := validateName(""); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("empty notification name error = %v", err)
	}
	if err := validateName(strings.Repeat("x", 101)); err == nil || !strings.Contains(err.Error(), "100") {
		t.Fatalf("long notification name error = %v", err)
	}
	if err := validateName("  Operations  "); err != nil {
		t.Fatal(err)
	}
	if keyErrorCode(ErrKeyUnavailable) != "key_unavailable" || keyErrorCode(ErrKeyPermissions) != "key_permissions" || keyErrorCode(ErrKeyInvalid) != "key_invalid" {
		t.Fatal("key error codes were not mapped")
	}

	if DefaultKeyPath("") != "" || DefaultKeyPath(":memory:") != "" || DefaultKeyPath("/var/lib/edgewatch/edgewatch.db") != "/var/lib/edgewatch/notification.key" {
		t.Fatalf("default key path handling is incorrect")
	}
	if _, err := loadKey(""); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("empty key path error = %v", err)
	}
	if _, err := loadKey(filepath.Join(t.TempDir(), "missing.key")); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("missing key error = %v", err)
	}
	if err := ValidateKeyFile(filepath.Join(t.TempDir(), "missing.key")); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("missing configured key error = %v", err)
	}
	dir := t.TempDir()
	if _, err := loadKey(dir); !errors.Is(err, ErrKeyPermissions) {
		t.Fatalf("directory key error = %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "key")
	if _, err := createKey(""); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("empty create-key error = %v", err)
	}
	key, err := createKey(keyPath)
	if err != nil || len(key) != notificationKeySize {
		t.Fatalf("create key = %d bytes, %v", len(key), err)
	}
	if _, err := createKey(keyPath); !errors.Is(err, os.ErrExist) {
		t.Fatalf("duplicate create-key error = %v", err)
	}
	loaded, err := loadKey(keyPath)
	if err != nil || string(loaded) != string(key) {
		t.Fatalf("raw key load = %x, %v", loaded, err)
	}
	if err := ValidateKeyFile(keyPath); err != nil {
		t.Fatalf("valid configured key rejected: %v", err)
	}
	hexPath := filepath.Join(t.TempDir(), "hex-key")
	if err := os.WriteFile(hexPath, []byte(strings.ToUpper(hex.EncodeToString(key))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	decoded, err := loadKey(hexPath)
	if err != nil || string(decoded) != string(key) {
		t.Fatalf("hex key load = %x, %v", decoded, err)
	}
	badHexPath := filepath.Join(t.TempDir(), "bad-hex-key")
	if err := os.WriteFile(badHexPath, []byte(strings.Repeat("g", notificationKeySize*2)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKey(badHexPath); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("invalid hex key error = %v", err)
	}
	shortPath := filepath.Join(t.TempDir(), "short-key")
	if err := os.WriteFile(shortPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKey(shortPath); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("short key error = %v", err)
	}

	if _, _, err := sealURL([]byte("short"), "id", "url"); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("invalid seal key error = %v", err)
	}
	nonce, ciphertext, err := sealURL(key, "id", "secret://value")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := openURL(key, "id", nonce, ciphertext)
	if err != nil || plain != "secret://value" {
		t.Fatalf("crypto round trip = %q, %v", plain, err)
	}
	if _, err := openURL([]byte("short"), "id", nonce, ciphertext); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("invalid open key error = %v", err)
	}
	if _, err := openURL(key, "id", []byte("short"), ciphertext); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("invalid nonce error = %v", err)
	}
	if _, err := openURL(key, "other-id", nonce, ciphertext); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("associated-data mismatch error = %v", err)
	}
	if _, err := newAEAD([]byte("short")); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("invalid AEAD key error = %v", err)
	}
}

func TestNotifierLockedAndErrorBranches(t *testing.T) {
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
	if _, err := notifier.CreateManaged(ctx, "", "generic://localhost/path?disabletls=yes", true); err == nil {
		t.Fatal("empty notification name was accepted")
	}
	if _, err := notifier.CreateManaged(ctx, "bad", "not-a-shoutrrr-url", true); err == nil {
		t.Fatal("invalid notification URL was accepted")
	}
	if got := notifier.view("missing"); got.ID != "" {
		t.Fatalf("missing view = %#v", got)
	}
	if _, err := notifier.Destination(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing destination error = %v", err)
	}
	if err := notifier.ValidateDestinationSelection(ctx, []string{"file:"}); !errors.Is(err, ErrInvalidDestinationSelection) {
		t.Fatalf("empty file selection error = %v", err)
	}

	created, err := notifier.CreateManaged(ctx, "Locked", "generic://localhost/locked?disabletls=yes&template=json", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := notifier.UpdateManaged(ctx, "missing", 1, "name", nil, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing notification update error = %v", err)
	}
	if _, err := notifier.UpdateManaged(ctx, created.ID, created.Revision, "", nil, nil); err == nil {
		t.Fatal("empty notification update name was accepted")
	}
	if _, err := notifier.UpdateManaged(ctx, created.ID, created.Revision, "Locked", stringPtr("not-a-url"), nil); err == nil {
		t.Fatal("invalid notification update URL was accepted")
	}

	// Keep a valid key on disk but corrupt the ciphertext. Reload marks the
	// destination locked, allowing metadata edits while refusing re-enable.
	if _, err := db.DB.ExecContext(ctx, "UPDATE managed_notifications SET ciphertext=? WHERE id=?", []byte("corrupt"), created.ID); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := notifier.UpdateManaged(ctx, created.ID, created.Revision, "Locked", nil, boolPtr(true)); !errors.Is(err, ErrManagedNotificationLocked) {
		t.Fatalf("locked re-enable error = %v", err)
	}
	if err := notifier.TestDestinationContext(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing destination test error = %v", err)
	}
	if err := notifier.TestDestinationContext(ctx, created.ID); !errors.Is(err, ErrManagedNotificationLocked) {
		t.Fatalf("locked destination test error = %v", err)
	}

	if err := notifier.TestContext(nil); err != nil {
		t.Fatalf("nil notification test context = %v", err)
	}
	if err := notifier.Drain(nil); err != nil {
		t.Fatalf("nil drain context = %v", err)
	}
	if _, err := notifier.QueueDestinationsForSelection(ctx, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNotifierDeliveryFailureAndCancellationBranches(t *testing.T) {
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
	if err := db.QueueEvent(ctx, "removed-destination", model.Event{Type: "test", Job: "job", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Drain(ctx); err == nil {
		t.Fatal("missing destination delivery unexpectedly succeeded")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := sendContext(canceled, "generic://localhost/noop", "test"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled send error = %v", err)
	}
	if err := sendContext(nil, "unknown://secret@example.invalid", "test"); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("nil-context send error = %v", err)
	}
	locked := &sync.Mutex{}
	locked.Lock()
	lockCtx, lockCancel := context.WithCancel(ctx)
	lockCancel()
	if err := lockContext(lockCtx, locked); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled notification lock error = %v", err)
	}
	locked.Unlock()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider failure", http.StatusInternalServerError)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	failingURL := "generic://" + parsed.Host + "/edgewatch?disabletls=yes&template=json"
	failing, err := New(db, []string{failingURL})
	if err != nil {
		t.Fatal(err)
	}
	if err := failing.TestContext(ctx); err == nil {
		t.Fatal("failing notification provider unexpectedly succeeded")
	}
}

func stringPtr(value string) *string { return &value }
