package app

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestDaemonRetentionMaintenanceKeepsHeartbeatAndScheduleResponsive(t *testing.T) {
	a, db := newLifecycleTestApp(t, schedulerFake{}, io.Discard)
	a.ReleaseChecker = nil
	a.heartbeatInterval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	pruneStarted := make(chan struct{})
	a.pruneHistory = func(ctx context.Context, _ time.Time) (store.PruneStats, error) {
		close(pruneStarted)
		<-ctx.Done()
		return store.PruneStats{}, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- a.Daemon(ctx) }()
	finished := false
	defer func() {
		cancel()
		if finished {
			return
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("daemon returned during cleanup: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("daemon did not stop during cleanup")
		}
	}()

	select {
	case <-pruneStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("startup retention pass did not start")
	}
	lease, err := db.System().DaemonLeaseStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lastHeartbeat := lease.Heartbeat
	heartbeatAdvances := 0
	heartbeatDeadline := time.Now().Add(500 * time.Millisecond)
	for heartbeatAdvances < 3 && time.Now().Before(heartbeatDeadline) {
		lease, err = db.System().DaemonLeaseStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if lease.Heartbeat.After(lastHeartbeat) {
			heartbeatAdvances++
			lastHeartbeat = lease.Heartbeat
		}
		time.Sleep(5 * time.Millisecond)
	}

	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("maintenance-schedule-refresh"))
	if err != nil {
		t.Fatal(err)
	}
	a.RefreshSchedules()
	scheduled := false
	scheduleDeadline := time.Now().Add(500 * time.Millisecond)
	for !scheduled && time.Now().Before(scheduleDeadline) {
		a.scheduleMu.Lock()
		_, scheduled = a.entries[record.ID]
		a.scheduleMu.Unlock()
		if !scheduled {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if heartbeatAdvances < 3 {
		t.Errorf("daemon heartbeat advanced %d times while retention was blocked; want at least 3", heartbeatAdvances)
	}
	if !scheduled {
		t.Error("schedule refresh did not reconcile a new job while retention was blocked")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemon returned unexpected error after cancellation: %v", err)
		}
		finished = true
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not cancel blocked retention and stop within 2 seconds")
	}
}
