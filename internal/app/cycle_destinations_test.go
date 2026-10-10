package app

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

// completingCycleScanner plans a two-unit resumable cycle and completes it
// in one attempt. It counts its plans and unit scans.
type completingCycleScanner struct {
	mu    sync.Mutex
	plans int
	units int
}

func (s *completingCycleScanner) Version(context.Context) string { return "completing-cycle" }
func (s *completingCycleScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	return model.Snapshot{}, errors.New("ordinary scan path is not expected")
}
func (s *completingCycleScanner) Plan(ctx context.Context, job config.Job) (scanner.WorkPlan, error) {
	s.mu.Lock()
	s.plans++
	s.mu.Unlock()
	return (&lifecycleScanner{}).Plan(ctx, job)
}
func (s *completingCycleScanner) ScanWorkUnit(_ context.Context, _ config.Job, unit scanner.WorkUnit, _ scanner.ProgressReporter) (model.Snapshot, error) {
	s.mu.Lock()
	s.units++
	s.mu.Unlock()
	port, err := strconv.Atoi(unit.Ports)
	if err != nil {
		return model.Snapshot{}, err
	}
	return model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Addresses: unit.Addresses, Ports: []model.PortState{{Port: port, State: "open"}}}}}, nil
}

func (s *completingCycleScanner) counts() (plans, units int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plans, s.units
}

// A completed resumable cycle is compared only when a scan promotes it. When
// its notification destinations cannot be read, the cycle must stay
// unpromoted, so the next trigger promotes and compares the same cycle
// instead of discarding its result and planning a new one.
func TestCompletedCycleWaitsForNotificationDestinations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	probe := &completingCycleScanner{}
	a, db := newLifecycleTestApp(t, probe, nil)
	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("cycle-destinations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-2"}}, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}}
		state.BaselineScanID = "seed"
		state.BaselineConfigHash = record.Job.SecurityHash()
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	var eventsMu sync.Mutex
	var live []model.Event
	a.SetEventHandler(func(event model.Event) {
		eventsMu.Lock()
		defer eventsMu.Unlock()
		live = append(live, event)
	})

	// The destination read fails once.
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications RENAME TO managed_notifications_unavailable`); err != nil {
		t.Fatal(err)
	}
	deferred, events, deferErr := a.runJobRecord(ctx, record, false)
	if deferErr == nil || len(events) != 0 || deferred.CycleID == "" || deferred.CycleStatus != "completed" {
		t.Fatalf("run without destinations = %#v, events %#v, err %v", deferred, events, deferErr)
	}
	eventsMu.Lock()
	assertBalancedScanLifecycle(t, live, record.ID)
	if message := eventByType(live, "scan.completed").Message; !strings.Contains(message, "notification destinations were unavailable") {
		t.Fatalf("lifecycle message = %q", message)
	}
	live = nil
	eventsMu.Unlock()
	if scans, err := defaultTenant(db).ListJobScans(ctx, record.ID, 10); err != nil || len(scans) != 0 {
		t.Fatalf("scans after the destination failure = %#v, %v; want the cycle unpromoted", scans, err)
	}
	cycle, err := defaultTenant(db).GetScanCycle(ctx, deferred.CycleID)
	if err != nil || cycle.Status != "completed" {
		t.Fatalf("cycle after the destination failure = %#v, %v", cycle, err)
	}
	if state, err := defaultTenant(db).RuntimeState(ctx, record.ID); err != nil || len(state.Incidents) != 0 {
		t.Fatalf("runtime after the destination failure = %#v, %v", state, err)
	}
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications_unavailable RENAME TO managed_notifications`); err != nil {
		t.Fatal(err)
	}

	promoted, events, promoteErr := a.runJobRecord(ctx, record, false)
	if promoteErr != nil || promoted.CycleID != deferred.CycleID || promoted.Status != "success" || promoted.Comparison != model.ScanComparisonCompared {
		t.Fatalf("next run = %#v, err %v; want the completed cycle promoted and compared", promoted, promoteErr)
	}
	if !hasEventType(events, "changes-detected") {
		t.Fatalf("promoted cycle was not compared with the baseline: %#v", events)
	}
	if plans, units := probe.counts(); plans != 1 || units != 2 {
		t.Fatalf("scanner planned %d cycles and scanned %d units; want the one cycle reused", plans, units)
	}
	var compared int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE cycle_id=? AND comparison=?`, deferred.CycleID, model.ScanComparisonCompared).Scan(&compared); err != nil || compared != 1 {
		t.Fatalf("compared scans of the cycle = %d, %v; want 1", compared, err)
	}
	if latest, err := defaultTenant(db).GetLatestScanCycle(ctx, record.ID); err != nil || latest.ID != deferred.CycleID {
		t.Fatalf("latest cycle = %#v, %v; want no new cycle", latest, err)
	}
	if state, err := defaultTenant(db).RuntimeState(ctx, record.ID); err != nil || len(state.Incidents) != 1 {
		t.Fatalf("runtime after promotion = %#v, %v", state, err)
	}
}

// A scan outside a completed cycle keeps the earlier behavior: its result is
// saved as not compared.
func TestCompletedCycleResult(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		scan model.Scan
		want bool
	}{
		{scan: model.Scan{Resumable: true, CycleID: "cycle", CycleStatus: "completed", Status: "success"}, want: true},
		{scan: model.Scan{Resumable: true, CycleID: "cycle", CycleStatus: "completed", Status: "incomplete"}, want: true},
		{scan: model.Scan{Resumable: true, CycleID: "cycle", CycleStatus: "paused", Status: "timed_out"}},
		{scan: model.Scan{Resumable: true, CycleID: "cycle", CycleStatus: "completed", Status: "failed"}},
		{scan: model.Scan{Status: "success"}},
	} {
		if got := completedCycleResult(test.scan); got != test.want {
			t.Errorf("completedCycleResult(%#v) = %t, want %t", test.scan, got, test.want)
		}
	}
}

var _ scanner.ResumableScanner = (*completingCycleScanner)(nil)
