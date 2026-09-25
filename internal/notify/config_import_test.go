package notify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func openImportStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	db, err := store.Open(filepath.Join(dir, "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, dir
}

func managedCount(t *testing.T, db *store.Store) int {
	t.Helper()
	records, err := db.ListManagedNotifications(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(records)
}

func deploymentViews(views []DestinationView) (deployment, web []DestinationView) {
	for _, view := range views {
		if view.Source == "deployment" {
			deployment = append(deployment, view)
		} else {
			web = append(web, view)
		}
	}
	return deployment, web
}

func writeTestKey(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	key := make([]byte, notificationKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// The first import creates the default key next to the database, as the
// first destination created in the console does, and stores each distinct
// URL once, encrypted and named after its console label.
func TestImportConfiguredURLsCreatesMissingDefaultKey(t *testing.T) {
	ctx := context.Background()
	db, dir := openImportStore(t)
	first := "generic://127.0.0.1:9/first?disabletls=yes&template=json"
	second := "generic://127.0.0.1:9/second?disabletls=yes&template=json"
	keyPath := filepath.Join(dir, "notification.key")
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("key exists before the import: %v", err)
	}

	result, err := ImportConfiguredURLs(ctx, db, []string{first, second, first}, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Configured != 2 || len(result.Imported) != 2 || result.AlreadyImported != 0 || result.ImportedURLs() != 2 {
		t.Fatalf("import result = %#v, want two distinct URLs imported", result)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("notification key was not created beside the database: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("notification key mode = %v, want 0600", info.Mode().Perm())
	}
	records, err := db.ListManagedNotifications(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if strings.Contains(string(record.Ciphertext), "127.0.0.1") || record.Provider != "generic" || !record.Enabled {
			t.Fatalf("imported record %#v is not an enabled, encrypted generic destination", record.ID)
		}
	}

	notifier, err := New(db, []string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	deployment, web := deploymentViews(notifier.DestinationsContext(ctx))
	if len(deployment) != 0 || len(web) != 2 || web[0].Name != "Deployment destination" || web[1].Name != "Deployment destination 2" {
		t.Fatalf("destinations after import = deployment %#v, web %#v", deployment, web)
	}
	urls := map[string]bool{}
	for _, view := range web {
		entry := notifier.managed[view.ID]
		if entry.locked || view.ReadOnly {
			t.Fatalf("imported destination %s is locked or read-only", view.ID)
		}
		urls[entry.url] = true
	}
	if !urls[first] || !urls[second] {
		t.Fatalf("imported destinations do not decrypt to the configured URLs")
	}
	if status := notifier.StatusContext(ctx); status["deployment"] != 0 || status["managed"] != 2 || status["active"] != 2 {
		t.Fatalf("notifier status after import = %#v", status)
	}
}

// An explicitly configured key is used as-is; no default key is generated.
func TestImportConfiguredURLsUsesConfiguredKeyFile(t *testing.T) {
	ctx := context.Background()
	db, dir := openImportStore(t)
	keyFile := filepath.Join(t.TempDir(), "operator.key")
	writeTestKey(t, keyFile, 0o600)
	raw := "generic://127.0.0.1:9/explicit?disabletls=yes"
	if _, err := ImportConfiguredURLs(ctx, db, []string{raw}, keyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notification.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a default key was generated although a key file is configured: %v", err)
	}
	notifier, err := NewWithKeyFile(db, []string{raw}, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	_, web := deploymentViews(notifier.DestinationsContext(ctx))
	if len(web) != 1 || web[0].Locked || notifier.managed[web[0].ID].url != raw {
		t.Fatalf("imported destination with configured key = %#v", web)
	}
}

// A failed import imports nothing, returns a bounded reason without the URL,
// and leaves the URL a deployment destination that keeps delivering.
func TestImportConfiguredURLsFailureImportsNothing(t *testing.T) {
	raw := "generic://127.0.0.1:9/secret-token-value?disabletls=yes"
	for _, test := range []struct {
		name  string
		code  string
		setup func(t *testing.T, db *store.Store, dir string)
	}{
		{name: "missing key for existing destinations", code: "key_unavailable", setup: func(t *testing.T, db *store.Store, dir string) {
			createExistingDestination(t, db)
			if err := os.Remove(filepath.Join(dir, "notification.key")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unsafe key permissions", code: "key_permissions", setup: func(t *testing.T, db *store.Store, dir string) {
			writeTestKey(t, filepath.Join(dir, "notification.key"), 0o644)
		}},
		{name: "replaced key", code: "decrypt_failed", setup: func(t *testing.T, db *store.Store, dir string) {
			createExistingDestination(t, db)
			writeTestKey(t, filepath.Join(dir, "notification.key"), 0o600)
		}},
		{name: "database error", code: "database_error", setup: func(t *testing.T, db *store.Store, dir string) {
			if _, err := db.DB.Exec(`CREATE TRIGGER reject_import BEFORE INSERT ON managed_notifications BEGIN SELECT RAISE(ABORT,'database unavailable'); END`); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			db, dir := openImportStore(t)
			test.setup(t, db, dir)
			before := managedCount(t, db)
			result, err := ImportConfiguredURLs(ctx, db, []string{raw}, "")
			var importErr *ConfigImportError
			if !errors.As(err, &importErr) || importErr.Code != test.code {
				t.Fatalf("import error = %v, want code %s", err, test.code)
			}
			if strings.Contains(err.Error(), "secret-token-value") || strings.Contains(err.Error(), hashURL(raw)) {
				t.Fatalf("import error exposes the URL: %v", err)
			}
			if len(result.Imported) != 0 || result.ImportedURLs() != 0 || result.Configured != 1 {
				t.Fatalf("failed import result = %#v", result)
			}
			if got := managedCount(t, db); got != before {
				t.Fatalf("managed destinations after a failed import = %d, want %d", got, before)
			}
			imported, err := db.ImportedDeploymentNotifications(ctx, []string{hashURL(raw)})
			if err != nil || len(imported) != 0 {
				t.Fatalf("failed import recorded the URL: %v, %v", imported, err)
			}
			notifier, err := New(db, []string{raw})
			if err != nil {
				t.Fatal(err)
			}
			if deployment, _ := deploymentViews(notifier.DestinationsContext(ctx)); len(deployment) != 1 {
				t.Fatalf("configured URL is no longer a deployment destination after a failed import: %#v", deployment)
			}
		})
	}
}

func createExistingDestination(t *testing.T, db *store.Store) {
	t.Helper()
	notifier, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := notifier.CreateManaged(context.Background(), "Existing", "generic://127.0.0.1:9/existing?disabletls=yes", true); err != nil {
		t.Fatal(err)
	}
}

// Alerts queued for the deployment destination before the import, including
// rows still addressed through the legacy digest alias, are delivered by the
// imported destination.
func TestImportConfiguredURLsDeliversQueuedAlerts(t *testing.T) {
	ctx := context.Background()
	db, _ := openImportStore(t)
	raw, calls := countingWebhook(t, "queued")
	before, err := New(db, []string{raw})
	if err != nil {
		t.Fatal(err)
	}
	if err := before.Queue(ctx, []model.Event{{Type: "scan_failed", Job: "queued-opaque", CreatedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	if err := db.QueueEvent(ctx, hashURL(raw), model.Event{Type: "scan_failed", Job: "queued-legacy", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	result, err := ImportConfiguredURLs(ctx, db, []string{raw}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 1 || result.MovedDeliveries != 2 {
		t.Fatalf("import result = %#v, want both queued alerts moved", result)
	}
	after, err := New(db, []string{raw})
	if err != nil {
		t.Fatal(err)
	}
	if err := after.Drain(ctx); err != nil {
		t.Fatalf("drain after import: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("queued alerts delivered after import = %d, want 2", got)
	}
	health, err := db.ListDeliveryHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if item := health["managed:"+result.Imported[0].ID]; item.LastSuccessAt.IsZero() || item.Pending != 0 {
		t.Fatalf("imported destination health = %#v", item)
	}
}

// A restart imports nothing and needs no key; a destination deleted after its
// import is not recreated; a new or changed URL becomes an extra destination.
func TestImportConfiguredURLsIsIdempotentAndImportsNewURLs(t *testing.T) {
	ctx := context.Background()
	db, dir := openImportStore(t)
	original := "generic://127.0.0.1:9/original?disabletls=yes"
	changed := "generic://127.0.0.1:9/rotated?disabletls=yes"
	first, err := ImportConfiguredURLs(ctx, db, []string{original}, "")
	if err != nil || len(first.Imported) != 1 {
		t.Fatalf("first import = %#v, %v", first, err)
	}
	keyPath := filepath.Join(dir, "notification.key")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	again, err := ImportConfiguredURLs(ctx, db, []string{original}, "")
	if err != nil || len(again.Imported) != 0 || again.AlreadyImported != 1 {
		t.Fatalf("second import = %#v, %v; want nothing imported without touching the key", again, err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a second start created a key: %v", err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteManagedNotification(ctx, first.Imported[0].ID, 1); err != nil {
		t.Fatal(err)
	}
	afterDelete, err := ImportConfiguredURLs(ctx, db, []string{original}, "")
	if err != nil || len(afterDelete.Imported) != 0 || afterDelete.AlreadyImported != 1 {
		t.Fatalf("import after delete = %#v, %v; want the deleted destination left deleted", afterDelete, err)
	}
	if got := managedCount(t, db); got != 0 {
		t.Fatalf("deleted imported destination was recreated: %d destinations", got)
	}
	withChange, err := ImportConfiguredURLs(ctx, db, []string{original, changed}, "")
	if err != nil || len(withChange.Imported) != 1 || withChange.AlreadyImported != 1 || withChange.ImportedURLs() != 2 {
		t.Fatalf("import with a changed URL = %#v, %v", withChange, err)
	}
	notifier, err := New(db, []string{original, changed})
	if err != nil {
		t.Fatal(err)
	}
	deployment, web := deploymentViews(notifier.DestinationsContext(ctx))
	if len(deployment) != 0 || len(web) != 1 || notifier.managed[web[0].ID].url != changed {
		t.Fatalf("destinations after a changed URL = deployment %#v, web %#v", deployment, web)
	}
}

func TestImportConfiguredURLsRejectsInvalidURLWithoutLeakingIt(t *testing.T) {
	db, _ := openImportStore(t)
	_, err := ImportConfiguredURLs(context.Background(), db, []string{"unknown-service://secret-token@example.invalid/path"}, "")
	var importErr *ConfigImportError
	if err == nil || errors.As(err, &importErr) {
		t.Fatalf("invalid URL error = %v, want a configuration error", err)
	}
	if strings.Contains(err.Error(), "secret-token") || !strings.Contains(err.Error(), "invalid Shoutrrr destination") {
		t.Fatalf("invalid URL error = %q", err)
	}
	if got := managedCount(t, db); got != 0 {
		t.Fatalf("invalid configuration imported %d destinations", got)
	}
}

func TestImportConfiguredURLsWithoutURLsDoesNothing(t *testing.T) {
	db, dir := openImportStore(t)
	result, err := ImportConfiguredURLs(context.Background(), db, nil, "")
	if err != nil || result.Configured != 0 || result.ImportedURLs() != 0 {
		t.Fatalf("empty import = %#v, %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notification.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an empty import created a key: %v", err)
	}
	if _, err := ImportConfiguredURLs(context.Background(), nil, []string{"generic://127.0.0.1:9/x"}, ""); err == nil {
		t.Fatal("import without a store succeeded")
	}
}

// The console learns from the notifier status that config.yaml still lists
// imported URLs, or that their import failed.
func TestNotifierStatusReportsConfigImport(t *testing.T) {
	ctx := context.Background()
	db, _ := openImportStore(t)
	notifier, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := notifier.StatusContext(ctx)["config_import"]; ok {
		t.Fatal("status reports a config import before any daemon start")
	}
	for _, test := range []struct {
		state store.NotificationConfigImport
		want  any
	}{
		{store.NotificationConfigImport{Status: store.NotificationConfigImportNone}, nil},
		{store.NotificationConfigImport{Status: store.NotificationConfigImportImported, ConfiguredURLs: 1, ImportedURLs: 1}, "imported"},
		{store.NotificationConfigImport{Status: store.NotificationConfigImportFailed, ConfiguredURLs: 1, ErrorCode: "key_unavailable"}, "failed"},
	} {
		if err := db.RecordNotificationConfigImport(ctx, test.state); err != nil {
			t.Fatal(err)
		}
		if got := notifier.StatusContext(ctx)["config_import"]; got != test.want {
			t.Fatalf("config_import for %#v = %v, want %v", test.state, got, test.want)
		}
	}
}

func TestConfigImportErrorUnwraps(t *testing.T) {
	err := configImportError(configImportKeyUnavailable, ErrKeyUnavailable)
	if !errors.Is(err, ErrKeyUnavailable) || !strings.Contains(err.Error(), "key_unavailable") {
		t.Fatalf("config import error = %v", err)
	}
	for want, keyErr := range map[string]error{
		"key_unavailable": ErrKeyUnavailable,
		"key_permissions": ErrKeyPermissions,
		"key_invalid":     ErrKeyInvalid,
		"key_unreadable":  errors.New("read notification key: permission denied"),
	} {
		if got := configImportKeyCode(keyErr); got != want {
			t.Fatalf("key code for %v = %s, want %s", keyErr, got, want)
		}
	}
}
