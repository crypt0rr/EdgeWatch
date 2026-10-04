package app

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type persistenceContentionScanner struct {
	store       *store.Store
	secondStore bool
	lockFor     time.Duration
	locked      chan struct{}
}

type immediateSnapshotScanner struct{}

func (immediateSnapshotScanner) Version(context.Context) string { return "immediate-test" }

func (immediateSnapshotScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	return model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "443"}},
		Units:  []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}},
	}, nil
}

func (s *persistenceContentionScanner) Version(context.Context) string { return "contention-test" }

func (s *persistenceContentionScanner) Scan(ctx context.Context, job config.Job) (model.Snapshot, error) {
	writer := s.store
	if s.secondStore {
		var err error
		writer, err = store.OpenExistingContext(ctx, s.store.Path)
		if err != nil {
			return model.Snapshot{}, err
		}
	}
	tx, err := writer.DB.BeginTx(ctx, nil)
	if err != nil {
		if s.secondStore {
			_ = writer.Close()
		}
		return model.Snapshot{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET revision=revision WHERE name=?`, job.Name); err != nil {
		_ = tx.Rollback()
		if s.secondStore {
			_ = writer.Close()
		}
		return model.Snapshot{}, err
	}
	close(s.locked)
	go func() {
		timer := time.NewTimer(s.lockFor)
		defer timer.Stop()
		<-timer.C
		_ = tx.Commit()
		if s.secondStore {
			_ = writer.Close()
		}
	}()
	return model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "443"}},
		Units:  []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}},
	}, nil
}

func TestRunJobPersistsFinishedScanAfterWriterWait(t *testing.T) {
	for _, secondStore := range []bool{false, true} {
		name := "in-process writer queue"
		if secondStore {
			name = "second-store SQLite writer lock"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			lockFor := 450 * time.Millisecond
			if secondStore {
				// Exceed SQLite's configured 5-second busy timeout to prove that
				// managed finalization retries writer acquisition independently
				// of its much shorter work budget.
				lockFor = 5500 * time.Millisecond
			}
			probe := &persistenceContentionScanner{
				secondStore: secondStore,
				lockFor:     lockFor,
				locked:      make(chan struct{}),
			}
			a, db := newLifecycleTestApp(t, probe, io.Discard)
			probe.store = db
			const workBudget = 200 * time.Millisecond
			a.persistenceBudget = func(int) time.Duration { return workBudget }
			record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("persist-after-writer-wait"))
			if err != nil {
				t.Fatal(err)
			}

			var eventsMu sync.Mutex
			var liveEvents []model.Event
			a.SetEventHandler(func(event model.Event) {
				eventsMu.Lock()
				defer eventsMu.Unlock()
				liveEvents = append(liveEvents, event)
			})

			scan, _, runErr := a.RunJobRecord(ctx, record)
			if runErr != nil || scan.Status != "success" {
				t.Fatalf("scan after writer wait = %#v, err=%v", scan, runErr)
			}
			select {
			case <-probe.locked:
			default:
				t.Fatal("scanner did not acquire the contention lock")
			}
			scans, err := defaultTenant(db).ListJobScans(ctx, record.ID, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(scans) != 1 || scans[0].ID != scan.ID || scans[0].Status != "success" {
				t.Fatalf("persisted scan history = %#v, want one successful result", scans)
			}
			active, err := defaultTenant(db).JobActive(ctx, record.ID)
			if err != nil || active {
				t.Fatalf("job remains active after scan return: active=%t err=%v", active, err)
			}
			eventsMu.Lock()
			defer eventsMu.Unlock()
			var completedSuccess bool
			for _, event := range liveEvents {
				if event.Type == "scan.completed" && strings.Contains(event.Message, "Scan success") {
					completedSuccess = true
				}
			}
			if !completedSuccess {
				t.Fatalf("successful persisted scan had no successful completion event: %#v", liveEvents)
			}
		})
	}
}

func TestRunJobDowngradesUnfinalizableScanAndPersistsFailure(t *testing.T) {
	ctx := t.Context()
	a, db := newLifecycleTestApp(t, immediateSnapshotScanner{}, io.Discard)
	// Force the first finalization transaction to expire before it can save.
	// The fallback receives a bounded minimum budget and records a small,
	// actionable failed-scan row instead of advertising success.
	a.persistenceBudget = func(int) time.Duration { return time.Nanosecond }
	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("persist-finalization-failure"))
	if err != nil {
		t.Fatal(err)
	}
	var eventsMu sync.Mutex
	var liveEvents []model.Event
	a.SetEventHandler(func(event model.Event) {
		eventsMu.Lock()
		defer eventsMu.Unlock()
		liveEvents = append(liveEvents, event)
	})

	scan, events, runErr := a.RunJobRecord(ctx, record)
	if runErr == nil || scan.Status != "failed" || !strings.Contains(scan.Error, "could not be finalized") {
		t.Fatalf("failed finalization result = %#v, events=%#v, err=%v", scan, events, runErr)
	}
	scans, err := defaultTenant(db).ListJobScans(ctx, record.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 || scans[0].Status != "failed" || scans[0].ID != scan.ID {
		t.Fatalf("persisted failure history = %#v, want one failed result", scans)
	}
	var failureEvent bool
	for _, event := range events {
		if event.Type == "scan-failure" {
			failureEvent = true
		}
	}
	if !failureEvent {
		t.Fatalf("fallback did not return a scan-failure event: %#v", events)
	}
	active, err := defaultTenant(db).JobActive(ctx, record.ID)
	if err != nil || active {
		t.Fatalf("job remains active after failed finalization: active=%t err=%v", active, err)
	}
	eventsMu.Lock()
	defer eventsMu.Unlock()
	for _, event := range liveEvents {
		if event.Type == "scan.completed" && strings.Contains(event.Message, "Scan success") {
			t.Fatalf("unfinalized success was broadcast: %#v", liveEvents)
		}
	}
}

var _ Scanner = (*persistenceContentionScanner)(nil)
