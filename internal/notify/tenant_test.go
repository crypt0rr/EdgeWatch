package notify

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// otherTenantID is a second tenant that the tests create in SQL, because no
// product API creates one yet.
const otherTenantID = "00000000-0000-0000-0000-000000000200"

// twoTenantNotifier returns a notifier over a database with a second tenant,
// and the stores of the default tenant and the second one.
func twoTenantNotifier(t *testing.T) (*Notifier, *store.Store, *store.TenantStore, *store.TenantStore) {
	t.Helper()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	t.Cleanup(func() { _ = db.Close() })
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, otherTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	scope, err := db.TenantScopeByID(ctx, otherTenantID)
	if err != nil {
		t.Fatal(err)
	}
	notifier, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	return notifier, db, db.Tenant(store.DefaultTenantScope()), db.Tenant(scope)
}

// Each tenant lists, reads, changes, tests, selects, and routes alerts to its
// own destinations only. Another tenant's destination is not found, exactly
// as an unknown one, and nothing about it changes. No error or view names a
// URL.
func TestTenantNotifierKeepsEachTenantToItsDestinations(t *testing.T) {
	ctx := context.Background()
	notifier, db, own, other := twoTenantNotifier(t)
	secrets := map[string]string{"own": "generic://127.0.0.1:9/own-secret?disabletls=yes&template=json", "other": "generic://127.0.0.1:9/other-secret?disabletls=yes&template=json"}
	audit := store.AuditEntry{Action: "notifications.created"}
	ownOps, err := notifier.Tenant(own).CreateManagedWithAudit(ctx, "Operations", secrets["own"], true, audit)
	if err != nil {
		t.Fatal(err)
	}
	// The same name is free in the other tenant.
	otherOps, err := notifier.Tenant(other).CreateManagedWithAudit(ctx, "Operations", secrets["other"], true, audit)
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	record := func(values ...any) {
		for _, value := range values {
			raw, _ := json.Marshal(value)
			texts = append(texts, string(raw))
			if err, ok := value.(error); ok && err != nil {
				texts = append(texts, err.Error())
			}
		}
	}

	for ts, want := range map[*store.TenantStore]string{own: ownOps.ID, other: otherOps.ID} {
		tenant := notifier.Tenant(ts)
		views, err := tenant.Destinations(ctx)
		if err != nil || len(views) != 1 || views[0].ID != want {
			t.Fatalf("destinations = %+v, %v; want only %s", views, err, want)
		}
		status, err := tenant.Status(ctx)
		if err != nil || status["managed"] != 1 || status["active"] != 1 {
			t.Fatalf("status = %v, %v", status, err)
		}
		legacy, err := tenant.LegacySelection(ctx)
		if err != nil || !reflect.DeepEqual(legacy, []string{want}) {
			t.Fatalf("legacy selection = %v, %v; want %s", legacy, err, want)
		}
		// A job with the legacy nil selection alerts every enabled
		// destination of its own tenant only.
		keys, err := tenant.QueueDestinationsForJob(ctx, config.Job{Name: "edge"})
		if err != nil || !reflect.DeepEqual(keys, []string{managedKey(want, 1)}) {
			t.Fatalf("nil selection keys = %v, %v; want only %s", keys, err, want)
		}
		record(views, status)
	}

	const unknown = "00000000-0000-0000-0000-00000000dead"
	tenant := notifier.Tenant(other)
	for _, id := range []string{ownOps.ID, unknown} {
		view, err := tenant.Destination(ctx, id)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("read %s: %+v, %v", id, view, err)
		}
		// Nothing is sent: a send to the unreachable URL would fail with a
		// delivery error instead.
		if err := tenant.TestDestination(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("test %s: %v", id, err)
		}
		renamed := secrets["other"]
		if _, err := tenant.UpdateManagedWithAudit(ctx, id, 1, "stolen", &renamed, boolPtr(true), store.AuditEntry{Action: "notifications.updated"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("update %s: %v", id, err)
		}
		if _, err := tenant.DeleteManagedWithAudit(ctx, id, 1, store.AuditEntry{Action: "notifications.deleted"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("delete %s: %v", id, err)
		}
		if keys, err := tenant.QueueDestinationsForSelection(ctx, []string{id}); err != nil || len(keys) != 0 {
			t.Errorf("selection of %s resolved to %v, %v", id, keys, err)
		}
		if _, missing, err := tenant.CanonicalSelection(ctx, []string{id}); err != nil || !reflect.DeepEqual(missing, []string{id}) {
			t.Errorf("selection of %s: missing = %v, %v", id, missing, err)
		}
		record(view, err)
	}
	// Selecting another tenant's destination is refused with the error of an
	// unknown one.
	foreign := tenant.ValidateDestinationSelection(ctx, []string{ownOps.ID})
	missing := tenant.ValidateDestinationSelection(ctx, []string{unknown})
	if !errors.Is(foreign, ErrInvalidDestinationSelection) || strings.ReplaceAll(foreign.Error(), ownOps.ID, "ID") != strings.ReplaceAll(missing.Error(), unknown, "ID") {
		t.Errorf("selecting another tenant's destination = %v; an unknown one = %v", foreign, missing)
	}
	if err := tenant.ValidateDestinationSelection(ctx, []string{otherOps.ID}); err != nil {
		t.Errorf("selecting the tenant's own destination: %v", err)
	}
	record(foreign, missing)

	stored, err := own.GetManagedNotification(ctx, ownOps.ID)
	if err != nil || stored.Name != "Operations" || stored.Revision != 1 {
		t.Fatalf("the first tenant's destination changed: %+v, %v", stored, err)
	}
	if opened, err := notifier.Tenant(own).Destination(ctx, ownOps.ID); err != nil || opened.Locked {
		t.Fatalf("the first tenant's destination = %+v, %v", opened, err)
	}

	// The notifier methods without a tenant serve the default tenant, and the
	// delivery worker holds the destinations of both.
	if keys, err := notifier.QueueDestinationsForJob(ctx, config.Job{Name: "edge"}); err != nil || !reflect.DeepEqual(keys, []string{managedKey(ownOps.ID, 1)}) {
		t.Fatalf("default tenant nil selection = %v, %v", keys, err)
	}
	if views := notifier.Destinations(); len(views) != 1 || views[0].ID != ownOps.ID {
		t.Fatalf("default tenant destinations = %+v", views)
	}
	if err := notifier.ValidateDestinationSelection(ctx, []string{otherOps.ID}); !errors.Is(err, ErrInvalidDestinationSelection) {
		t.Fatalf("the default tenant selected the other tenant's destination: %v", err)
	}
	snapshot := notifier.destinationSnapshot()
	if snapshot[managedKey(ownOps.ID, 1)] != secrets["own"] || snapshot[managedKey(otherOps.ID, 1)] != secrets["other"] {
		t.Fatal("the delivery worker does not hold both tenants' destinations")
	}

	// Queued for a job of the other tenant, the default tenant's nil
	// selection creates no delivery to the default tenant's destination.
	otherJob, err := other.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "edge", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}))
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{Type: "changes-detected", JobID: otherJob.ID, Job: "edge", Message: "other tenant alert", CreatedAt: time.Now().UTC()}
	defaultKeys, err := notifier.QueueDestinationsForJob(ctx, otherJob.Job)
	if err != nil {
		t.Fatal(err)
	}
	tenantKeys, err := notifier.Tenant(other).QueueDestinationsForJob(ctx, otherJob.Job)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range append(defaultKeys, tenantKeys...) {
		if err := db.System().QueueEvent(ctx, key, event); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.DB.QueryContext(ctx, `SELECT destination FROM outbox WHERE CAST(payload_json AS TEXT) LIKE '%other tenant alert%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var queued []string
	for rows.Next() {
		var destination string
		if err := rows.Scan(&destination); err != nil {
			t.Fatal(err)
		}
		queued = append(queued, destination)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(queued, []string{managedKey(otherOps.ID, 1)}) {
		t.Fatalf("the other tenant's alert was queued to %v, want only its own destination", queued)
	}

	for _, text := range texts {
		if strings.Contains(text, "own-secret") || strings.Contains(text, "other-secret") {
			t.Fatalf("a view or error names a URL: %s", text)
		}
	}
}

// A tenant store without a valid tenant fails every read and changes
// nothing.
func TestTenantNotifierRefusesAStoreWithoutATenant(t *testing.T) {
	ctx := context.Background()
	notifier, db, _, _ := twoTenantNotifier(t)
	tenant := notifier.Tenant(db.Tenant(store.TenantScope{}))
	if _, err := tenant.Destinations(ctx); !errors.Is(err, store.ErrNoTenantScope) {
		t.Fatalf("destinations: %v", err)
	}
	if _, err := tenant.Status(ctx); !errors.Is(err, store.ErrNoTenantScope) {
		t.Fatalf("status: %v", err)
	}
	if _, err := tenant.CreateManagedWithAudit(ctx, "Operations", "generic://127.0.0.1:9/x?disabletls=yes", true, store.AuditEntry{}); !errors.Is(err, store.ErrNoTenantScope) {
		t.Fatalf("create: %v", err)
	}
	if err := tenant.ValidateDestinationSelection(ctx, nil); err != nil {
		t.Fatalf("a nil selection needs no destinations: %v", err)
	}
	for name, err := range map[string]error{
		"validate": tenant.ValidateDestinationSelection(ctx, []string{"x"}),
		"test":     tenant.TestDestination(ctx, "x"),
	} {
		if !errors.Is(err, store.ErrNoTenantScope) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, call := range map[string]func() error{
		"legacy":    func() error { _, err := tenant.LegacySelection(ctx); return err },
		"canonical": func() error { _, _, err := tenant.CanonicalSelection(ctx, []string{"x"}); return err },
		"queue":     func() error { _, err := tenant.QueueDestinationsForJob(ctx, config.Job{}); return err },
		"summary":   func() error { _, err := tenant.TestSummary(ctx); return err },
		"get":       func() error { _, err := tenant.Destination(ctx, "x"); return err },
	} {
		if err := call(); !errors.Is(err, store.ErrNoTenantScope) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
