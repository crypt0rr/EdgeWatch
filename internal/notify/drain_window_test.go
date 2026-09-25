package notify

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// A delivery pass window bounds dispatch, not in-flight sends. This test goes
// through the isolated provider process (runNotificationProcess), because the
// in-process test path ignores the send context and would hide a send killed
// by the pass deadline.
func TestDrainWithinLetsInFlightSendsFinishAfterDispatchWindow(t *testing.T) {
	originalIsTestBinary := notificationIsTestBinary
	originalExecutable := notificationExecutable
	originalCommand := notificationCommandContext
	t.Cleanup(func() {
		notificationIsTestBinary = originalIsTestBinary
		notificationExecutable = originalExecutable
		notificationCommandContext = originalCommand
	})
	notificationIsTestBinary = func() bool { return false }
	notificationExecutable = func() (string, error) { return "/usr/local/bin/edgewatch", nil }

	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The provider child below never contacts this address.
	notifier, err := New(db, []string{"generic://127.0.0.1:9/hook?disabletls=yes"})
	if err != nil {
		t.Fatal(err)
	}
	events := make([]model.Event, notificationBatchSize)
	for i := range events {
		events[i] = model.Event{Type: "window", Job: "job", ScanID: fmt.Sprintf("scan-%d", i), CreatedAt: time.Now().UTC()}
	}
	if err := notifier.Queue(ctx, events); err != nil {
		t.Fatal(err)
	}

	const window = time.Second
	deadline := time.Now().Add(window)
	var started atomic.Int32
	notificationCommandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		started.Add(1)
		// Hold every dispatched send until the pass window has closed, so each
		// one is still in flight when the pass deadline fires. The provider
		// itself is healthy: it finishes well within its own timeout.
		time.Sleep(time.Until(deadline) + 100*time.Millisecond)
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exec sleep 0.2")
	}
	if err := notifier.DrainWithin(ctx, window); err != nil {
		t.Fatalf("bounded delivery pass: %v", err)
	}

	inFlight := int(started.Load())
	if inFlight == 0 || inFlight > notificationWorkers {
		t.Fatalf("sends started before the window closed = %d, want 1..%d", inFlight, notificationWorkers)
	}
	var sent, unsent, charged, claimed int
	if err := db.DB.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(CASE WHEN sent_at IS NOT NULL THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN sent_at IS NULL THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN deferrals>0 OR attempts>0 OR last_error<>'' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN claim_token<>'' THEN 1 ELSE 0 END),0)
		FROM outbox`).Scan(&sent, &unsent, &charged, &claimed); err != nil {
		t.Fatal(err)
	}
	if sent != inFlight {
		t.Fatalf("sent rows = %d, want the %d sends that were in flight when the window closed", sent, inFlight)
	}
	if unsent != len(events)-inFlight {
		t.Fatalf("unsent rows = %d, want %d", unsent, len(events)-inFlight)
	}
	if charged != 0 || claimed != 0 {
		t.Fatalf("pass window charged a budget or kept a claim: charged=%d claimed=%d", charged, claimed)
	}
	health, err := db.ListDeliveryHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for identity, item := range health {
		if item.Deferrals != 0 || item.TerminalFailures != 0 || item.LastErrorCode != "" {
			t.Fatalf("healthy provider reported as failing for %s: %#v", identity, item)
		}
	}
}
