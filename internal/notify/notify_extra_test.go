package notify

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestAuditedNotificationWrappersAndReadViews(t *testing.T) {
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
	url := "generic://localhost/ops?disabletls=yes&template=json"
	created, err := notifier.CreateManagedWithAudit(ctx, "Operations", url, true, store.AuditEntry{Action: "notifications.created", Detail: "created"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Provider != "generic" || created.Source != "web" || created.Revision != 1 || created.ReadOnly || created.Locked {
		t.Fatalf("created view = %#v", created)
	}
	encoded, err := json.Marshal(created)
	if err != nil || strings.Contains(string(encoded), url) || strings.Contains(string(encoded), `"url"`) {
		t.Fatalf("notification URL leaked in view: %s (%v)", encoded, err)
	}
	view, err := notifier.Destination(ctx, created.ID)
	if err != nil || view.ID != created.ID || view.Name != "Operations" {
		t.Fatalf("destination view = %#v, %v", view, err)
	}
	if _, err := notifier.Destination(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing destination error = %v", err)
	}
	if err := notifier.ValidateDestinationSelection(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := notifier.ValidateDestinationSelection(ctx, []string{created.ID, created.ID}); err != nil {
		t.Fatalf("duplicate valid selection rejected: %v", err)
	}
	if err := notifier.ValidateDestinationSelection(ctx, []string{""}); !errors.Is(err, ErrInvalidDestinationSelection) {
		t.Fatalf("empty selection error = %v", err)
	}
	if status := notifier.Status(); status["managed"] != 1 || status["active"] != 1 || status["key_state"] != "ready" {
		t.Fatalf("notification status = %#v", status)
	}
	if count := notifier.ActiveCount(); count != 1 {
		t.Fatalf("active destination count = %d", count)
	}

	disabled := false
	updated, err := notifier.UpdateManagedWithAudit(ctx, created.ID, created.Revision, "Ops renamed", nil, &disabled, store.AuditEntry{Action: "notifications.updated", Detail: "updated"})
	if err != nil || updated.Revision != 2 || updated.Enabled {
		t.Fatalf("updated view = %#v, %v", updated, err)
	}
	if err := notifier.TestContext(ctx); err != nil {
		t.Fatalf("test with only disabled destination: %v", err)
	}
	if err := notifier.DeleteManagedWithAudit(ctx, created.ID, updated.Revision, store.AuditEntry{Action: "notifications.deleted", Detail: "deleted"}); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Test(); err != nil {
		t.Fatalf("empty notification test: %v", err)
	}
	var audits int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action LIKE 'notifications.%'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 3 {
		t.Fatalf("notification audit count = %d, want 3", audits)
	}
}

func TestQueueDestinationsResolvesLegacyAndJobSelections(t *testing.T) {
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
	created, err := notifier.CreateManaged(ctx, "Ops", "generic://localhost/ops?disabletls=yes", true)
	if err != nil {
		t.Fatal(err)
	}
	all, err := notifier.QueueDestinations(ctx)
	if err != nil || len(all) != 1 || all[0] == "" {
		t.Fatalf("all destination keys = %#v, %v", all, err)
	}
	selected, err := notifier.QueueDestinationsForJob(ctx, config.Job{NotificationDestinations: []string{created.ID}})
	if err != nil || len(selected) != 1 || selected[0] != all[0] {
		t.Fatalf("selected destination keys = %#v, %v", selected, err)
	}
	silent, err := notifier.QueueDestinationsForSelection(ctx, []string{})
	if err != nil || len(silent) != 0 {
		t.Fatalf("silent destination keys = %#v, %v", silent, err)
	}
}
