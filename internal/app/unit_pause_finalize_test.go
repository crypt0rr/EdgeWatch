package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// unitAlerts counts the events and the queued alerts of a unit.
func unitAlerts(t *testing.T, db *store.Store, tenantID string) [2]int {
	t.Helper()
	var events, outbox int
	if err := db.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM events WHERE tenant_id=?1),(SELECT COUNT(*) FROM outbox WHERE tenant_id=?1)`, tenantID).Scan(&events, &outbox); err != nil {
		t.Fatal(err)
	}
	return [2]int{events, outbox}
}

// requireScanCanceledByPause fails unless the run of the paused unit's job
// reported store.ErrTenantNotActive, returned no events, and recorded its
// scan as canceled in the unit's history, and unless the unit's runtime
// state, events and alerts are as they were.
func requireScanCanceledByPause(t *testing.T, f twoTenants, scan model.Scan, events []model.Event, err error, alertsBefore [2]int) {
	t.Helper()
	ctx := context.Background()
	if !errors.Is(err, store.ErrTenantNotActive) || events != nil {
		t.Fatalf("the run = %v, %v; want %v and no events", events, err, store.ErrTenantNotActive)
	}
	if scan.ID == "" || scan.Status != "canceled" || scan.Error != store.ScanCanceledByPauseMessage {
		t.Fatalf("the scan = %+v; want it canceled by the pause", scan)
	}
	b := f.db.Tenant(f.b)
	if scans, err := b.ListJobScans(ctx, f.jobB.ID, 10); err != nil || len(scans) != 1 || scans[0].ID != scan.ID || scans[0].Status != "canceled" {
		t.Fatalf("tenant B's scans = %+v, %v; want the canceled scan", scans, err)
	}
	if state, err := b.RuntimeState(ctx, f.jobB.ID); err != nil || state.Baseline != nil || state.BaselineScanID != "" || state.CandidateCount != 0 {
		t.Fatalf("the scan changed tenant B's runtime state: %+v, %v", state, err)
	}
	if got := unitAlerts(t, f.db, secondTenantID); got != alertsBefore {
		t.Fatalf("tenant B's events and queued alerts = %v, want %v", got, alertsBefore)
	}
}

// A host `edgewatch scan` runs in a process of its own, which DisableUnit in
// the daemon cannot cancel. When it finishes after the disable, its scan is
// recorded as canceled, the paused unit's baseline and alerts stay as they
// were, and the run reports store.ErrTenantNotActive. The default unit's
// host scan runs as before while the unit is paused, and so does the
// unit's next one once the unit is enabled again.
func TestHostScanFinishingAfterDisableUnitChangesNothing(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	// A second application on its own connection to the database stands in
	// for the host command's process, and f.app for the daemon.
	cliDB, err := store.OpenExisting(f.db.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cliDB.Close() })
	cli, err := New(routingTestConfig(f.db.Path), cliDB, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	sc := gatedScanner{started: make(chan string, 1), finish: make(chan struct{})}
	cli.Scanner = sc
	alertsBefore := unitAlerts(t, f.db, secondTenantID)

	type outcome struct {
		scan   model.Scan
		events []model.Event
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		scan, events, err := cli.RunJobRecord(ctx, f.jobB)
		done <- outcome{scan, events, err}
	}()
	select {
	case <-sc.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the host scan did not start")
	}
	disabled, err := f.app.DisableUnit(ctx, secondTenantID, tenantRecord(t, f.db, secondTenantID).Revision, store.AuditEntry{ActorKind: store.AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	sc.finish <- struct{}{}
	var got outcome
	select {
	case got = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the host scan did not finish")
	}
	requireScanCanceledByPause(t, f, got.scan, got.events, got.err, alertsBefore)

	cli.Scanner = schedulerFake{}
	if scan, _, err := cli.RunJobRecord(ctx, f.jobA); err != nil || scan.Status != "success" {
		t.Fatalf("the default unit's host scan while tenant B is paused = %+v, %v", scan, err)
	}
	if state, err := f.db.Tenant(f.a).RuntimeState(ctx, f.jobA.ID); err != nil || state.Baseline == nil {
		t.Fatalf("the default unit's host scan did not set its baseline: %+v, %v", state, err)
	}

	if _, err := f.app.EnableUnit(ctx, secondTenantID, disabled.Revision, store.AuditEntry{ActorKind: store.AuditActorHost}); err != nil {
		t.Fatal(err)
	}
	next, events, err := cli.RunJobRecord(ctx, f.jobB)
	if err != nil || next.Status != "success" || !hasEventType(events, "baseline-complete") {
		t.Fatalf("tenant B's host scan after it was enabled = %+v, %v, %v", next, events, err)
	}
	if state, err := f.db.Tenant(f.b).RuntimeState(ctx, f.jobB.ID); err != nil || state.BaselineScanID != next.ID {
		t.Fatalf("tenant B's runtime state after it was enabled = %+v, %v; want the next scan as the baseline", state, err)
	}
	if after := unitAlerts(t, f.db, secondTenantID); after[1] <= alertsBefore[1] {
		t.Fatalf("tenant B's queued alerts after it was enabled = %d, want more than %d", after[1], alertsBefore[1])
	}
}

// disablingScanner disables the unit of the job it scans once it has its
// result, as a disable that commits after the scanner returned and before
// the result is saved does.
type disablingScanner struct{ disable func() }

func (disablingScanner) Version(context.Context) string { return "disabling" }
func (s disablingScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	s.disable()
	return model.Snapshot{}, nil
}

// The daemon's pause cancels the scan context of its running scans, but a
// scan whose scanner has already returned saves its result on a context
// without that cancellation. When the disable commits in that window, the
// scan is recorded as canceled and changes neither the paused unit's
// baseline nor its alerts.
func TestDaemonScanFinishingDuringDisableUnitChangesNothing(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	alertsBefore := unitAlerts(t, f.db, secondTenantID)
	revision := tenantRecord(t, f.db, secondTenantID).Revision
	f.app.Scanner = disablingScanner{disable: func() {
		if _, err := f.app.DisableUnit(ctx, secondTenantID, revision, store.AuditEntry{ActorKind: store.AuditActorHost}); err != nil {
			t.Error(err)
		}
	}}
	scan, events, err := f.app.RunJobRecord(ctx, f.jobB)
	if errors.Is(err, context.Canceled) {
		t.Fatalf("the run = %v; the scanner returned its result before the pause cancelled it", err)
	}
	requireScanCanceledByPause(t, f, scan, events, err, alertsBefore)
}
