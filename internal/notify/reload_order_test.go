package notify

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// hookContext runs hook each time the database or the notifier asks whether
// the context is done, so a test can act between two steps of a delivery.
type hookContext struct {
	context.Context
	hook func()
}

func (c hookContext) Done() <-chan struct{} { c.hook(); return c.Context.Done() }
func (c hookContext) Err() error            { c.hook(); return c.Context.Err() }

// cachedDestination returns the notifier's cached record of a destination.
func cachedDestination(n *Notifier, id string) (managedDestination, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	entry, ok := n.managed[id]
	return entry, ok
}

// An alert raised after a destination's URL was replaced is never sent to
// the replaced URL, even when a reload that read the destinations before
// the replacement puts them in the cache after the delivery's refresh. The
// delivery sees that its selector is newer than the cache and reloads again.
func TestAlertAfterAReplacementIsNeverSentToTheReplacedURL(t *testing.T) {
	ctx := context.Background()
	notifier, db, _, _ := twoTenantNotifier(t)
	sent := recordSends(t)
	created, err := defaultNotifier(notifier).createManaged(ctx, "Webhook", rotationOldURL, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Number and read a full snapshot before the replacement...
	earlyReload := notifier.reloads.Add(1)
	stale, err := db.System().ListManagedNotifications(ctx)
	if err != nil {
		t.Fatal(err)
	}
	newURL := rotationNewURL
	replaced, err := defaultNotifier(notifier).updateManaged(ctx, created.ID, created.Revision, "Webhook", &newURL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// ...and an alert raised after the replacement is queued and claimed.
	if err := db.System().QueueEvent(ctx, managedKey(created.ID, replaced.Revision), model.Event{Type: "port-opened", Job: "after-replacement", TenantID: store.DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	claimed, err := db.System().ClaimDueDeliveriesExcluding(ctx, notificationBatchSize, "claim", nil)
	if err != nil || len(claimed) != 1 || claimed[0].Destination != managedKey(created.ID, replaced.Revision) {
		t.Fatalf("claimed deliveries = %+v, %v", claimed, err)
	}
	// Seed the pre-replacement cache. The delivery must refresh because the
	// queued selector is newer than this destination revision.
	oldEntries, oldKeyErr := notifier.openManaged(stale)
	notifier.mu.Lock()
	notifier.managed, notifier.keyErr = oldEntries, oldKeyErr
	notifier.mu.Unlock()
	// The early full reload finishes last: after the delivery refresh has put
	// the current destination in the cache, it tries to install the
	// pre-replacement snapshot. Generation ordering must reject it.
	var fired atomic.Bool
	var staleInstallAccepted atomic.Bool
	hook := func() {
		entry, installed := cachedDestination(notifier, created.ID)
		if !installed || entry.record.CredentialRevision != replaced.Revision || fired.Swap(true) {
			return
		}
		managed, keyErr := notifier.openManaged(stale)
		staleInstallAccepted.Store(notifier.install(earlyReload, managed, keyErr))
	}
	if err := notifier.deliverOne(hookContext{Context: ctx, hook: hook}, claimed[0], notifier.destinationSnapshot()); err != nil {
		t.Fatalf("delivery = %v", err)
	}
	if !fired.Load() {
		t.Fatal("the early reload never finished during the delivery")
	}
	if staleInstallAccepted.Load() {
		t.Fatal("the stale pre-replacement snapshot replaced the current cache")
	}
	if got := sent(); len(got) != 1 || got[0] != rotationNewURL {
		t.Fatalf("the alert raised after the replacement was sent to %v; want only the new URL", got)
	}
	if entry, _ := cachedDestination(notifier, created.ID); entry.record.CredentialRevision != replaced.Revision {
		t.Fatalf("cached credential revision = %d, want %d", entry.record.CredentialRevision, replaced.Revision)
	}
}

func TestDrainRefreshesManagedDestinationsOnceForABatch(t *testing.T) {
	ctx := context.Background()
	notifier, db, _, _ := twoTenantNotifier(t)
	sent := recordSends(t)
	created, err := defaultNotifier(notifier).createManaged(ctx, "Webhook", rotationOldURL, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := db.System().QueueEvent(ctx, managedKey(created.ID, created.Revision), model.Event{Type: "port-opened", Job: "batch", ScanID: fmt.Sprintf("scan-%d", i), TenantID: store.DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	before := notifier.reloads.Load()
	if err := notifier.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := notifier.reloads.Load() - before; got != 1 {
		t.Fatalf("destination reloads for one delivery batch = %d, want one", got)
	}
	if got := sent(); len(got) != 3 {
		t.Fatalf("sent %d notifications, want all 3", len(got))
	}
}

// A reload whose read started before another reload's does not replace that
// reload's snapshot, so the cache never goes back to destinations older
// than those it already holds.
func TestReloadNeverInstallsAnOlderSnapshot(t *testing.T) {
	ctx := context.Background()
	notifier, db, _, _ := twoTenantNotifier(t)
	created, err := defaultNotifier(notifier).createManaged(ctx, "Webhook", rotationOldURL, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	// An early reload is numbered and reads the destinations before the
	// URL is replaced; the replacement then reloads them.
	early := notifier.reloads.Add(1)
	stale, err := db.System().ListManagedNotifications(ctx)
	if err != nil {
		t.Fatal(err)
	}
	newURL := rotationNewURL
	replaced, err := defaultNotifier(notifier).updateManaged(ctx, created.ID, created.Revision, "Webhook", &newURL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	managed, keyErr := notifier.openManaged(stale)
	if notifier.install(early, managed, keyErr) {
		t.Fatal("the early reload replaced the snapshot of a later one")
	}
	entry, ok := cachedDestination(notifier, created.ID)
	if !ok || entry.record.CredentialRevision != replaced.Revision || entry.url != rotationNewURL {
		t.Fatalf("cached destination = revision %d, credential revision %d, URL %q; want the replacement", entry.record.Revision, entry.record.CredentialRevision, entry.url)
	}
	// What the notifier reads from the cache follows the replacement.
	if keys := notifier.defaultSet().queue(nil); len(keys) != 1 || keys[0] != managedKey(created.ID, replaced.Revision) {
		t.Fatalf("queue keys = %v, want the replacement's revision", keys)
	}
	if view := notifier.view(created.ID); view.Revision != replaced.Revision {
		t.Fatalf("view revision = %d, want %d", view.Revision, replaced.Revision)
	}
	// A later reload still installs.
	if err := notifier.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	notifier.mu.RLock()
	installed := notifier.installed
	notifier.mu.RUnlock()
	if installed != notifier.reloads.Load() {
		t.Fatalf("installed reload = %d, want the latest, %d", installed, notifier.reloads.Load())
	}
}

// Reloads that run concurrently with URL replacements never leave the cache
// older than a replacement that has returned.
func TestConcurrentReloadsKeepTheCacheAtTheLatestReplacement(t *testing.T) {
	ctx := context.Background()
	notifier, _, _, _ := twoTenantNotifier(t)
	current, err := defaultNotifier(notifier).createManaged(ctx, "Webhook", rotationOldURL, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := notifier.Reload(ctx); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	defer func() {
		close(stop)
		wg.Wait()
	}()
	for round := 0; round < 60; round++ {
		replacement := fmt.Sprintf("generic://localhost/round-%d?disabletls=yes&template=json", round)
		next, err := defaultNotifier(notifier).updateManaged(ctx, current.ID, current.Revision, "Webhook", &replacement, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(3 * time.Millisecond); time.Now().Before(deadline); {
			entry, ok := cachedDestination(notifier, current.ID)
			if !ok || entry.record.CredentialRevision < next.Revision || (entry.record.CredentialRevision == next.Revision && entry.url != replacement) {
				t.Fatalf("round %d: the cache holds credential revision %d (%q) after the replacement to revision %d returned", round, entry.record.CredentialRevision, entry.url, next.Revision)
			}
		}
		current = next
	}
}

// A delivery whose revision is newer than the destination that the notifier
// reads, even after it reads the destinations again, is not sent with the
// cached URL. Its claim is returned without using a retry or deferral
// budget, so a later pass resolves it again.
func TestDeliveryNewerThanItsDestinationIsNotSent(t *testing.T) {
	ctx := context.Background()
	notifier, db, _, _ := twoTenantNotifier(t)
	sent := recordSends(t)
	created, err := defaultNotifier(notifier).createManaged(ctx, "Webhook", rotationOldURL, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.System().QueueEvent(ctx, managedKey(created.ID, created.Revision), model.Event{Type: "port-opened", Job: "newer", TenantID: store.DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	newer := managedKey(created.ID, created.Revision+1)
	if _, err := db.DB.ExecContext(ctx, `UPDATE outbox SET destination=?`, newer); err != nil {
		t.Fatal(err)
	}
	claimed, err := db.System().ClaimDueDeliveriesExcluding(ctx, notificationBatchSize, "claim", nil)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claimed deliveries = %+v, %v", claimed, err)
	}
	if err := notifier.deliverOne(ctx, claimed[0], notifier.destinationSnapshot()); err != nil {
		t.Fatalf("delivery = %v", err)
	}
	if got := sent(); len(got) != 0 {
		t.Fatalf("a delivery newer than its destination was sent to %v", got)
	}
	var attempts, deferrals int
	var claim, lastError string
	if err := db.DB.QueryRowContext(ctx, `SELECT attempts,deferrals,claim_token,last_error FROM outbox WHERE id=?`, claimed[0].ID).Scan(&attempts, &deferrals, &claim, &lastError); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || deferrals != 0 || claim != "" || lastError != "" {
		t.Fatalf("the delivery has attempts %d, deferrals %d, claim %q, last error %q; want it returned without a budget", attempts, deferrals, claim, lastError)
	}
}
