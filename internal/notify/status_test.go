package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The notification status was a map before it became Status. The legacy
// functions below are the map-based ones as they were, kept to prove that
// Status writes the same bytes. When the status changes on purpose, change
// them with it.

func (set destinationSet) legacyStatus() map[string]any {
	locked, activeManaged := 0, 0
	for _, entry := range set.managed {
		if entry.locked {
			locked++
		}
		if entry.record.Enabled && !entry.locked {
			activeManaged++
		}
	}
	keyState := "not_required"
	if len(set.managed) > 0 {
		keyState = "ready"
		if set.keyErr != nil {
			keyState = keyErrorCode(set.keyErr)
		} else if locked > 0 {
			keyState = "decrypt_failed"
		}
	}
	return map[string]any{"deployment": len(set.fileURLs), "managed": len(set.managed), "active": len(set.fileURLs) + activeManaged, "locked": locked, "key_state": keyState}
}

func (n *Notifier) legacyCompleteStatus(ctx context.Context, set destinationSet, ts *store.TenantStore) map[string]any {
	status := set.legacyStatus()
	if n.Store == nil {
		return status
	}
	if set.deployment {
		// Tell the console when config.yaml still lists URLs that were
		// imported, or when their import failed and they are still delivered
		// from config.yaml.
		if state, err := n.Store.System().NotificationConfigImportState(ctx); err == nil {
			switch {
			case state.Status == store.NotificationConfigImportFailed:
				status["config_import"] = store.NotificationConfigImportFailed
			case state.ImportedURLs > 0:
				status["config_import"] = store.NotificationConfigImportImported
			}
		}
	}
	if health, err := ts.ListDeliveryHealth(ctx); err == nil {
		legacyAddDeliveryTotals(status, health)
	}
	return status
}

func legacyAddDeliveryTotals(status map[string]any, health map[string]store.DeliveryHealth) {
	pending, retrying, deferrals, terminal := 0, 0, 0, 0
	for _, item := range health {
		pending += item.Pending
		retrying += item.Retrying
		deferrals += item.Deferrals
		terminal += item.TerminalFailures
	}
	status["delivery_pending"] = pending
	status["delivery_retrying"] = retrying
	status["delivery_deferrals"] = deferrals
	status["delivery_terminal_failures"] = terminal
}

func (pn *PlatformNotifier) legacyDestinations(ctx context.Context) ([]DestinationView, map[string]any, error) {
	set, err := pn.destinations(ctx)
	if err != nil {
		return nil, nil, err
	}
	status := set.legacyStatus()
	var health map[string]store.DeliveryHealth
	if current, err := pn.ps.ListDeliveryHealth(ctx); err == nil {
		health = current
		legacyAddDeliveryTotals(status, health)
	}
	return finishViews(set.views(), health), status, nil
}

// sameStatus checks that the status encodes as the legacy map did.
func sameStatus(t *testing.T, situation string, current Status, legacy map[string]any) {
	t.Helper()
	got, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s: status = %s, want the legacy %s", situation, got, want)
	}
}

// Status writes the bytes of the legacy map for every combination of
// destinations, key state, config.yaml import, and delivery totals, for a
// unit and for the platform.
func TestStatusWritesTheLegacyBytes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	notifier, db, own, _ := twoTenantNotifier(t)
	enabled := store.ManagedNotification{ID: "enabled", Enabled: true}
	paused := store.ManagedNotification{ID: "paused"}
	sets := map[string]destinationSet{
		"no destinations":         {},
		"deployment destinations": {fileURLs: map[string]string{"first": "generic://localhost/first", "second": "generic://localhost/second"}, deployment: true},
		"managed destinations":    {managed: map[string]managedDestination{"enabled": {record: enabled}, "paused": {record: paused}, "locked": {record: enabled, locked: true}}},
		"a key error":             {managed: map[string]managedDestination{"locked": {record: enabled, locked: true}}, keyErr: ErrKeyUnavailable, deployment: true},
	}
	compareSets := func(situation string, ts *store.TenantStore) {
		t.Helper()
		for name, set := range sets {
			sameStatus(t, situation+", "+name+", without a store", (&Notifier{}).completeStatus(ctx, set, ts), (&Notifier{}).legacyCompleteStatus(ctx, set, ts))
			sameStatus(t, situation+", "+name, notifier.completeStatus(ctx, set, ts), notifier.legacyCompleteStatus(ctx, set, ts))
		}
	}
	compareSets("no deliveries", own)
	// Without a tenant, the delivery totals cannot be read and are left out.
	unscoped := db.Tenant(store.TenantScope{})
	if totals := deliveryTotals(notifier.completeStatus(ctx, destinationSet{}, unscoped)); totals != [4]int{-1, -1, -1, -1} {
		t.Fatalf("delivery totals without a tenant = %v, want them left out", totals)
	}
	compareSets("unreadable deliveries", unscoped)

	created, err := notifier.Tenant(own).CreateManagedWithAudit(ctx, "Status hook", "generic://localhost/status-hook?disabletls=yes", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	failTerminally(t, db, created, model.Event{Type: "scan_failed", Job: "status", CreatedAt: time.Now().UTC()})
	if err := db.System().QueueEvent(ctx, managedKey(created.ID, created.Revision), model.Event{Type: "scan_failed", Job: "status", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for _, state := range []store.NotificationConfigImport{
		{Status: store.NotificationConfigImportNone},
		{Status: store.NotificationConfigImportImported, ConfiguredURLs: 1, ImportedURLs: 1},
		{Status: store.NotificationConfigImportFailed, ConfiguredURLs: 1, ErrorCode: "key_unavailable"},
	} {
		if err := db.System().RecordNotificationConfigImport(ctx, state); err != nil {
			t.Fatal(err)
		}
		compareSets("config import "+state.Status, own)
		current, err := notifier.Tenant(own).Status(ctx)
		if err != nil || deliveryTotals(current) != [4]int{1, 0, 0, 1} {
			t.Fatalf("the default unit's status = %+v, %v; want a pending alert and a terminal failure", current, err)
		}
		set, err := notifier.Tenant(own).destinations(ctx)
		if err != nil {
			t.Fatal(err)
		}
		sameStatus(t, "the default unit after config import "+state.Status, current, notifier.legacyCompleteStatus(ctx, set, own))
	}

	audit := addPlatformAdmin(t, db)
	platform := notifier.Platform(db.Platform())
	if _, err := platform.CreateManagedWithAudit(ctx, "Platform hook", "generic://localhost/platform-hook?disabletls=yes", true, audit); err != nil {
		t.Fatal(err)
	}
	_, current, err := platform.Destinations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, legacy, err := platform.legacyDestinations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sameStatus(t, "the platform", current, legacy)
}
