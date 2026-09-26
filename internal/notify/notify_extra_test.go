package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestManagedDeliverySurvivesMetadataEditAndPause(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	rawURL := fmt.Sprintf("generic://%s/alerts?disabletls=yes&template=json", parsed.Host)
	notifier, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := notifier.CreateManaged(ctx, "Operations", rawURL, true)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := managedKey(created.ID, created.Revision)
	if err := db.QueueEvent(ctx, oldKey, model.Event{Type: "rename", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	renamed, err := notifier.UpdateManaged(ctx, created.ID, created.Revision, "Operations renamed", nil, boolPtr(true))
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Revision != created.Revision+1 {
		t.Fatalf("metadata revision = %d, want %d", renamed.Revision, created.Revision+1)
	}
	if err := notifier.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("metadata-edited delivery calls = %d, want 1", calls.Load())
	}

	if err := db.QueueEvent(ctx, managedKey(renamed.ID, renamed.Revision), model.Event{Type: "pause", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	paused, err := notifier.UpdateManaged(ctx, renamed.ID, renamed.Revision, renamed.Name, nil, boolPtr(false))
	if err != nil || paused.Enabled {
		t.Fatalf("pause result = %#v, %v", paused, err)
	}
	if err := notifier.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("paused delivery was attempted: calls=%d", calls.Load())
	}
	var attempts, terminal int
	if err := db.DB.QueryRowContext(ctx, `SELECT attempts,CASE WHEN terminal_at='' THEN 0 ELSE 1 END FROM outbox WHERE sent_at IS NULL`).Scan(&attempts, &terminal); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || terminal != 0 {
		t.Fatalf("paused outbox state = attempts %d terminal %d", attempts, terminal)
	}
	if health, err := db.ListDeliveryHealth(ctx); err != nil {
		t.Fatal(err)
	} else if health["managed:"+created.ID].Pending != 0 {
		t.Fatalf("paused delivery counted as pending: %#v", health["managed:"+created.ID])
	}
	resumed, err := notifier.UpdateManaged(ctx, paused.ID, paused.Revision, paused.Name, nil, boolPtr(true))
	if err != nil || !resumed.Enabled {
		t.Fatalf("resume result = %#v, %v", resumed, err)
	}
	if err := notifier.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("resumed delivery calls = %d, want 2", calls.Load())
	}
}

func TestAuditedNotificationWrappersAndReadViews(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
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
	if changedJobs, err := notifier.DeleteManagedWithAudit(ctx, created.ID, updated.Revision, store.AuditEntry{Action: "notifications.deleted", Detail: "deleted"}); err != nil || len(changedJobs) != 0 {
		t.Fatalf("delete without routed jobs = %#v, %v", changedJobs, err)
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
	db, err := store.Open(storetest.FreshPath(t))
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

func TestDeleteManagedRejectsStaleRevisionWithoutChangingRouting(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
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
	job := config.NormalizeJob(config.Job{Name: "routed", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced", NotificationDestinations: []string{created.ID}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if err := notifier.DeleteManaged(ctx, created.ID, created.Revision+1); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale delete error = %v, want conflict", err)
	}
	if changed, err := notifier.DeleteManagedWithAudit(ctx, created.ID, created.Revision+1, store.AuditEntry{Action: "notifications.deleted"}); !errors.Is(err, store.ErrConflict) || changed != nil {
		t.Fatalf("stale audited delete = %#v, %v; want conflict", changed, err)
	}
	stored, err := db.GetJob(ctx, record.ID)
	if err != nil || stored.Revision != record.Revision || strings.Join(stored.Job.NotificationDestinations, ",") != created.ID {
		t.Fatalf("job routing after rejected deletes = %#v, %v", stored, err)
	}
	changed, err := notifier.DeleteManagedWithAudit(ctx, created.ID, created.Revision, store.AuditEntry{Action: "notifications.deleted"})
	if err != nil || strings.Join(changed, ",") != record.ID {
		t.Fatalf("audited delete changed jobs %#v, %v; want %s", changed, err, record.ID)
	}
	if views := notifier.Destinations(); len(views) != 0 {
		t.Fatalf("destinations after delete = %#v", views)
	}
}

func TestCanonicalSelectionReportsMissingDestinations(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	deploymentURL := "generic://localhost/deployment?token=current&disabletls=yes&template=json"
	notifier, err := New(db, []string{deploymentURL})
	if err != nil {
		t.Fatal(err)
	}
	deployment := notifier.LegacySelection()[0]
	paused, err := notifier.CreateManaged(ctx, "Paused", "generic://localhost/paused?disabletls=yes", false)
	if err != nil {
		t.Fatal(err)
	}
	legacyDigest := "file:" + hashURL(deploymentURL)
	canonical, missing := notifier.CanonicalSelection([]string{legacyDigest, paused.ID, " file:rotated ", "deleted", "", deployment})
	wantCanonical := []string{deployment, paused.ID, "deleted", "file:rotated"}
	sort.Strings(wantCanonical)
	if strings.Join(canonical, ",") != strings.Join(wantCanonical, ",") {
		t.Fatalf("canonical selection = %#v, want %#v", canonical, wantCanonical)
	}
	if strings.Join(missing, ",") != "deleted,file:rotated" {
		t.Fatalf("missing selectors = %#v", missing)
	}
	if canonical, missing := notifier.CanonicalSelection(nil); canonical != nil || missing != nil {
		t.Fatalf("legacy nil selection = %#v, %#v", canonical, missing)
	}
	if canonical, missing := notifier.CanonicalSelection([]string{}); canonical == nil || len(canonical) != 0 || missing != nil {
		t.Fatalf("explicit empty selection = %#v, %#v", canonical, missing)
	}
}
