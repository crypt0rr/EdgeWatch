package notify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

const (
	rotationOldURL = "generic://localhost/old-recipient?disabletls=yes&template=json"
	rotationNewURL = "generic://localhost/new-recipient?disabletls=yes&template=json"
)

// passWithWaitingClaims runs one delivery pass while the provider holds
// every send to a URL that contains marker. The pass claims its whole batch
// at once, so once every worker holds such a send, the rest of the batch is
// claimed and waiting for a worker. change runs at that moment; the held
// sends then finish, and the URLs of every send of the pass are returned.
func passWithWaitingClaims(t *testing.T, notifier *Notifier, marker string, change func()) []string {
	t.Helper()
	started, release := make(chan struct{}, notificationBatchSize), make(chan struct{})
	var mu sync.Mutex
	var sent []string
	previous := notificationProviderSend
	notificationProviderSend = func(_ context.Context, raw, _ string) error {
		if strings.Contains(raw, marker) {
			started <- struct{}{}
			<-release
		}
		mu.Lock()
		sent = append(sent, raw)
		mu.Unlock()
		return nil
	}
	defer func() { notificationProviderSend = previous }()
	done := make(chan error, 1)
	go func() { done <- notifier.Drain(context.Background()) }()
	for i := 0; i < notificationWorkers; i++ {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			close(release)
			t.Fatalf("only %d workers started a send", i)
		}
	}
	change()
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("delivery pass: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), sent...)
}

// recordSends makes the provider accept every send and returns the URLs it
// was given.
func recordSends(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var sent []string
	previous := notificationProviderSend
	notificationProviderSend = func(_ context.Context, raw, _ string) error {
		mu.Lock()
		sent = append(sent, raw)
		mu.Unlock()
		return nil
	}
	t.Cleanup(func() { notificationProviderSend = previous })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), sent...)
	}
}

// A delivery that a pass claimed before a destination's URL was replaced,
// and that reaches a worker only afterwards, is never sent to the new URL:
// the alert was queued for the old credentials. This holds for a unit's
// destination and for a platform destination.
func TestClaimedDeliveryIsNeverSentToTheReplacementURL(t *testing.T) {
	for _, owner := range []struct {
		name string
		// create creates the destination with rotationOldURL and returns a
		// function that replaces its URL with rotationNewURL.
		create func(t *testing.T, notifier *Notifier, db *store.Store) (DestinationView, func())
		event  func(i int) model.Event
	}{
		{
			name: "unit",
			create: func(t *testing.T, notifier *Notifier, _ *store.Store) (DestinationView, func()) {
				ctx := context.Background()
				created, err := defaultNotifier(notifier).createManaged(ctx, "Webhook", rotationOldURL, true, nil)
				if err != nil {
					t.Fatal(err)
				}
				return created, func() {
					newURL := rotationNewURL
					if _, err := defaultNotifier(notifier).updateManaged(ctx, created.ID, created.Revision, "Webhook", &newURL, nil, nil); err != nil {
						t.Error(err)
					}
				}
			},
			event: func(i int) model.Event {
				return model.Event{Type: "port-opened", Job: fmt.Sprintf("queued-before-rotation-%d", i), TenantID: store.DefaultTenantID, CreatedAt: time.Now().UTC()}
			},
		},
		{
			name: "platform",
			create: func(t *testing.T, notifier *Notifier, db *store.Store) (DestinationView, func()) {
				ctx := context.Background()
				audit := addPlatformAdmin(t, db)
				platform := notifier.Platform(db.Platform())
				created, err := platform.CreateManagedWithAudit(ctx, "Webhook", rotationOldURL, true, audit)
				if err != nil {
					t.Fatal(err)
				}
				return created, func() {
					newURL := rotationNewURL
					if _, err := platform.UpdateManagedWithAudit(ctx, created.ID, created.Revision, "Webhook", &newURL, nil, audit); err != nil {
						t.Error(err)
					}
				}
			},
			event: func(i int) model.Event {
				return model.Event{Type: "application-update-available", LatestVersion: fmt.Sprintf("9.9.%d", i), CreatedAt: time.Now().UTC()}
			},
		},
	} {
		t.Run(owner.name, func(t *testing.T) {
			ctx := context.Background()
			notifier, db, _, _ := twoTenantNotifier(t)
			created, replace := owner.create(t, notifier, db)
			queued := notificationWorkers + 1
			for i := 1; i <= queued; i++ {
				if err := db.System().QueueEvent(ctx, managedKey(created.ID, created.Revision), owner.event(i)); err != nil {
					t.Fatal(err)
				}
			}
			sent := passWithWaitingClaims(t, notifier, "old-recipient", replace)
			for _, raw := range sent {
				if strings.Contains(raw, "new-recipient") {
					t.Errorf("an alert queued before the URL replacement was sent to the new URL: %s", raw)
				}
			}
			if len(sent) != notificationWorkers {
				t.Errorf("the pass sent %d alerts, want only the %d that workers held before the replacement", len(sent), notificationWorkers)
			}
			var pending int
			if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL`).Scan(&pending); err != nil || pending != 0 {
				t.Fatalf("unsent deliveries after the replacement = %d, %v; want every queued alert discarded", pending, err)
			}
		})
	}
}

// A claimed delivery whose destination has had its credentials replaced
// since the alert was queued is not sent, even while the delivery is still
// in the outbox under its claim. The replacement credentials never receive
// it; the claim is closed as for a deleted destination.
func TestClaimedDeliveryRefusesReplacedCredentials(t *testing.T) {
	ctx := context.Background()
	notifier, db, _, _ := twoTenantNotifier(t)
	created, err := defaultNotifier(notifier).createManaged(ctx, "Webhook", rotationOldURL, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.System().QueueEvent(ctx, managedKey(created.ID, created.Revision), model.Event{Type: "port-opened", Job: "edge", TenantID: store.DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	due, err := db.System().ClaimDueDeliveries(ctx, 1, "owner")
	if err != nil || len(due) != 1 {
		t.Fatalf("claimed deliveries = %+v, %v", due, err)
	}
	// Replace the credentials in place, as a URL replacement does, but keep
	// the claimed delivery, so that only the credential revision tells it
	// apart from a delivery of the new URL.
	key, err := notifier.ensureKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := sealURL(key, created.ID, rotationNewURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE managed_notifications SET ciphertext=?,nonce=?,revision=revision+1,credential_revision=revision+1 WHERE id=?`, ciphertext, nonce, created.ID); err != nil {
		t.Fatal(err)
	}
	sends := recordSends(t)
	_ = notifier.deliverOne(ctx, due[0], nil)
	if sent := sends(); len(sent) != 0 {
		t.Fatalf("a delivery queued for the replaced credentials was sent: %v", sent)
	}
	var sentAt, claim string
	if err := db.DB.QueryRowContext(ctx, `SELECT COALESCE(sent_at,''),claim_token FROM outbox WHERE id=?`, due[0].ID).Scan(&sentAt, &claim); err != nil {
		t.Fatal(err)
	}
	if sentAt != "" || claim != "" {
		t.Fatalf("the refused delivery has sent_at %q and claim %q; want it unsent with its claim closed", sentAt, claim)
	}
}

// A claimed delivery of a unit that is disabled before a worker takes it is
// not sent. It stays held, with its retry and deferral budgets untouched,
// until the unit is enabled again, and is then delivered.
func TestClaimedDeliveryOfADisabledUnitIsHeld(t *testing.T) {
	ctx := context.Background()
	notifier, db, _, other := twoTenantNotifier(t)
	audit := addPlatformAdmin(t, db)
	created, err := notifier.Tenant(other).CreateManagedWithAudit(ctx, "B hook", "generic://localhost/unit-b?disabletls=yes&template=json", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	queued := notificationWorkers + 1
	for i := 1; i <= queued; i++ {
		event := model.Event{Type: "application-update-available", LatestVersion: fmt.Sprintf("9.9.%d", i), TenantID: otherTenantID, CreatedAt: time.Now().UTC()}
		if err := db.System().QueueEvent(ctx, managedKey(created.ID, created.Revision), event); err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := db.Platform().GetTenant(ctx, otherTenantID)
	if err != nil {
		t.Fatal(err)
	}
	sent := passWithWaitingClaims(t, notifier, "unit-b", func() {
		if tenant, err = db.Platform().DisableTenant(ctx, otherTenantID, tenant.Revision, audit); err != nil {
			t.Error(err)
		}
	})
	if len(sent) != notificationWorkers {
		t.Fatalf("the pass sent %d alerts, want only the %d that workers held before the unit was disabled", len(sent), notificationWorkers)
	}
	held := func() (count, claimed, attempts, deferrals int) {
		t.Helper()
		if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(claim_token<>''),0),COALESCE(SUM(attempts),0),COALESCE(SUM(deferrals),0) FROM outbox WHERE sent_at IS NULL AND terminal_at=''`).Scan(&count, &claimed, &attempts, &deferrals); err != nil {
			t.Fatal(err)
		}
		return count, claimed, attempts, deferrals
	}
	if count, claimed, attempts, deferrals := held(); count != 1 || claimed != 0 || attempts != 0 || deferrals != 0 {
		t.Fatalf("held deliveries = %d (claimed %d, attempts %d, deferrals %d); want one, unclaimed, with its budgets untouched", count, claimed, attempts, deferrals)
	}

	sends := recordSends(t)
	if err := notifier.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sends(); len(got) != 0 {
		t.Fatalf("a disabled unit's held alert was sent: %v", got)
	}
	if _, err := db.Platform().EnableTenant(ctx, otherTenantID, tenant.Revision, audit); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sends(); len(got) != 1 || !strings.Contains(got[0], "unit-b") {
		t.Fatalf("sends after the unit was enabled = %v, want the held alert", got)
	}
	if count, _, _, _ := held(); count != 0 {
		t.Fatalf("%d deliveries still held after the unit was enabled", count)
	}
}

// outboxBudget returns the budgets and state of one outbox row.
func outboxBudget(t *testing.T, db *store.Store, id int64) (attempts, deferrals int, lastError, terminalAt, claim string) {
	t.Helper()
	if err := db.DB.QueryRowContext(context.Background(), `SELECT attempts,deferrals,last_error,terminal_at,claim_token FROM outbox WHERE id=?`, id).Scan(&attempts, &deferrals, &lastError, &terminalAt, &claim); err != nil {
		t.Fatal(err)
	}
	return attempts, deferrals, lastError, terminalAt, claim
}

// A delivery that a pass claimed before its destination was paused, and
// that reaches a worker only afterwards, is not sent. Its claim is returned
// without using a retry or deferral budget and without a delivery failure,
// so the pause is not reported as a lock, and the alert is held until the
// destination is enabled again. This holds however often it happens, for a
// unit's destination and for a platform destination.
func TestClaimedDeliveryOfAPausedDestinationIsHeldWithoutABudget(t *testing.T) {
	for _, owner := range []struct {
		name string
		// create creates the destination and returns a function that
		// pauses or enables it, and one that returns its view.
		create func(t *testing.T, notifier *Notifier, db *store.Store) (DestinationView, func(enabled bool), func() DestinationView)
		event  model.Event
	}{
		{
			name: "unit",
			create: func(t *testing.T, notifier *Notifier, _ *store.Store) (DestinationView, func(bool), func() DestinationView) {
				ctx := context.Background()
				created, err := defaultNotifier(notifier).createManaged(ctx, "Webhook", rotationOldURL, true, nil)
				if err != nil {
					t.Fatal(err)
				}
				current := created
				setEnabled := func(enabled bool) {
					t.Helper()
					if current, err = defaultNotifier(notifier).updateManaged(ctx, created.ID, current.Revision, "Webhook", nil, &enabled, nil); err != nil {
						t.Fatal(err)
					}
				}
				view := func() DestinationView {
					t.Helper()
					view, err := defaultNotifier(notifier).Destination(ctx, created.ID)
					if err != nil {
						t.Fatal(err)
					}
					return view
				}
				return created, setEnabled, view
			},
			event: model.Event{Type: "port-opened", Job: "noisy", TenantID: store.DefaultTenantID},
		},
		{
			name: "platform",
			create: func(t *testing.T, notifier *Notifier, db *store.Store) (DestinationView, func(bool), func() DestinationView) {
				ctx := context.Background()
				audit := addPlatformAdmin(t, db)
				platform := notifier.Platform(db.Platform())
				created, err := platform.CreateManagedWithAudit(ctx, "Webhook", rotationOldURL, true, audit)
				if err != nil {
					t.Fatal(err)
				}
				current := created
				setEnabled := func(enabled bool) {
					t.Helper()
					if current, err = platform.UpdateManagedWithAudit(ctx, created.ID, current.Revision, "Webhook", nil, &enabled, audit); err != nil {
						t.Fatal(err)
					}
				}
				view := func() DestinationView {
					t.Helper()
					views, _, err := platform.Destinations(ctx)
					if err != nil || len(views) != 1 {
						t.Fatalf("platform destinations = %+v, %v", views, err)
					}
					return views[0]
				}
				return created, setEnabled, view
			},
			event: model.Event{Type: "application-update-available", LatestVersion: "9.9.9"},
		},
	} {
		t.Run(owner.name, func(t *testing.T) {
			ctx := context.Background()
			notifier, db, _, _ := twoTenantNotifier(t)
			sent := recordSends(t)
			created, setEnabled, view := owner.create(t, notifier, db)
			event := owner.event
			event.CreatedAt = time.Now().UTC()
			if err := db.System().QueueEvent(ctx, managedKey(created.ID, created.Revision), event); err != nil {
				t.Fatal(err)
			}
			// More pauses while the alert is claimed than the deferral limit
			// allows deferrals.
			for round := 1; round <= 9; round++ {
				// The pass claims its batch while the destination is enabled,
				// and the destination is paused before a worker reaches the
				// delivery.
				claimed, err := db.System().ClaimDueDeliveriesExcluding(ctx, notificationBatchSize, fmt.Sprintf("pass-%d", round), notifier.pausedDestinationKeys())
				if err != nil || len(claimed) != 1 {
					t.Fatalf("round %d: claimed deliveries = %+v, %v", round, claimed, err)
				}
				setEnabled(false)
				if err := notifier.deliverOne(ctx, claimed[0], notifier.destinationSnapshot()); err != nil {
					t.Fatalf("round %d: delivery = %v", round, err)
				}
				if got := sent(); len(got) != 0 {
					t.Fatalf("round %d: a paused destination's alert was sent: %v", round, got)
				}
				attempts, deferrals, lastError, terminalAt, claim := outboxBudget(t, db, claimed[0].ID)
				if attempts != 0 || deferrals != 0 || lastError != "" || terminalAt != "" || claim != "" {
					t.Fatalf("round %d: the held alert has attempts %d, deferrals %d, last error %q, terminal at %q, claim %q; want it unclaimed with its budgets untouched", round, attempts, deferrals, lastError, terminalAt, claim)
				}
				paused := view()
				if paused.Enabled || paused.LastFailureAt != "" || paused.LastErrorCode != "" || paused.Deferrals != 0 || paused.TerminalFailures != 0 {
					t.Fatalf("round %d: paused destination = %+v; want no delivery failure", round, paused)
				}
				// While it is paused, a delivery pass leaves the alert alone.
				if err := notifier.Drain(ctx); err != nil {
					t.Fatal(err)
				}
				if got := sent(); len(got) != 0 {
					t.Fatalf("round %d: a pass sent a paused destination's alert: %v", round, got)
				}
				setEnabled(true)
			}
			if err := notifier.Drain(ctx); err != nil {
				t.Fatal(err)
			}
			if got := sent(); len(got) != 1 || got[0] != rotationOldURL {
				t.Fatalf("sends after the destination was enabled = %v, want the held alert once", got)
			}
			if resumed := view(); resumed.LastFailureAt != "" || resumed.LastErrorCode != "" || resumed.Pending != 0 || resumed.LastSuccessAt == "" {
				t.Fatalf("resumed destination = %+v; want one success and no failure", resumed)
			}
		})
	}
}

// A delivery that a pass claimed before its enabled destination became
// locked, because the key no longer opens it, is still deferred as a lock:
// each time it uses a deferral and records a destination_locked failure, and
// at the deferral limit it ends as a terminal failure.
func TestClaimedDeliveryOfALockedDestinationIsDeferred(t *testing.T) {
	ctx := context.Background()
	notifier, db, _, _ := twoTenantNotifier(t)
	sent := recordSends(t)
	created, err := defaultNotifier(notifier).createManaged(ctx, "Webhook", rotationOldURL, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.System().QueueEvent(ctx, managedKey(created.ID, created.Revision), model.Event{Type: "port-opened", Job: "locked", TenantID: store.DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := db.DB.QueryRowContext(ctx, `SELECT ciphertext FROM managed_notifications WHERE id=?`, created.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	for round := 1; round <= 8; round++ {
		if _, err := db.DB.ExecContext(ctx, `UPDATE outbox SET next_at=?`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.ExecContext(ctx, `UPDATE managed_notifications SET ciphertext=? WHERE id=?`, ciphertext, created.ID); err != nil {
			t.Fatal(err)
		}
		if err := notifier.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		claimed, err := db.System().ClaimDueDeliveriesExcluding(ctx, notificationBatchSize, fmt.Sprintf("pass-%d", round), notifier.pausedDestinationKeys())
		if err != nil || len(claimed) != 1 {
			t.Fatalf("round %d: claimed deliveries = %+v, %v", round, claimed, err)
		}
		// The key no longer opens the destination when a worker reaches it.
		if _, err := db.DB.ExecContext(ctx, `UPDATE managed_notifications SET ciphertext=x'00' WHERE id=?`, created.ID); err != nil {
			t.Fatal(err)
		}
		if err := notifier.deliverOne(ctx, claimed[0], notifier.destinationSnapshot()); err != nil {
			t.Fatalf("round %d: delivery = %v", round, err)
		}
		attempts, deferrals, lastError, terminalAt, _ := outboxBudget(t, db, claimed[0].ID)
		if attempts != 0 || deferrals != round || lastError != "destination_locked" || (terminalAt != "") != (round == 8) {
			t.Fatalf("round %d: the locked alert has attempts %d, deferrals %d, last error %q, terminal at %q", round, attempts, deferrals, lastError, terminalAt)
		}
	}
	if got := sent(); len(got) != 0 {
		t.Fatalf("a locked destination's alert was sent: %v", got)
	}
	locked := defaultDestinations(t, notifier)[0]
	if !locked.Locked || locked.LastErrorCode != "destination_locked" || locked.TerminalFailures != 1 {
		t.Fatalf("locked destination = %+v; want its lock failures", locked)
	}
}
