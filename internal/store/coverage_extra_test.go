package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

func TestScanCycleDefaultsAndMalformedPayloads(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if cycle.ID == "" || cycle.StartedAt.IsZero() || cycle.UpdatedAt.IsZero() || cycle.ExpiresAt.IsZero() || cycle.Status != "paused" || cycle.TotalUnits != 1 || cycle.TotalProbes != 1 {
		t.Fatalf("cycle defaults = %#v", cycle)
	}
	if _, err := s.CreateScanCycle(ctx, ScanCycleRecord{ID: cycle.ID, JobID: job.ID, Job: job.Job.Name, Plan: plan}); err == nil {
		t.Fatal("duplicate cycle ID was accepted")
	}
	if _, err := s.GetScanCycle(ctx, "missing"); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing cycle error = %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET plan_json=? WHERE id=?`, []byte("not-json"), cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetScanCycle(ctx, cycle.ID); err == nil {
		t.Fatal("malformed cycle plan was accepted")
	}
}

func TestScanCycleStateAndUnitErrorBranches(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, "missing"); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing start error = %v", err)
	}
	if _, err := s.NextScanCycleUnit(ctx, cycle.ID); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("paused next unit error = %v", err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, 0); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("paused claim error = %v", err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, 99); !errors.Is(err, ErrNoPendingUnit) {
		t.Fatalf("unknown sequence claim error = %v", err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, 0); !errors.Is(err, ErrNoPendingUnit) {
		t.Fatalf("already-running claim error = %v", err)
	}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, 0, model.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, 0, model.Snapshot{}); err != nil {
		t.Fatalf("idempotent completion failed: %v", err)
	}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, 99, model.Snapshot{}); err == nil {
		t.Fatal("missing unit completion succeeded")
	}
	if _, err := s.NextScanCycleUnit(ctx, cycle.ID); !errors.Is(err, ErrNoPendingUnit) {
		t.Fatalf("completed-only next unit error = %v", err)
	}
}

func TestScanCycleMalformedUnitAndTerminalBranches(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET work_unit_json=? WHERE cycle_id=? AND sequence=0`, []byte("bad-unit"), cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NextScanCycleUnit(ctx, cycle.ID); err == nil {
		t.Fatal("malformed work unit was accepted")
	}
	// Restore the work unit and claim it, then make the transaction-level decode
	// fail in CompleteScanCycleUnit as well.
	raw, _ := json.Marshal(plan.Units[0])
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET work_unit_json=? WHERE cycle_id=? AND sequence=0`, raw, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET work_unit_json=? WHERE cycle_id=? AND sequence=0`, []byte("bad-unit"), cycle.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, 0, model.Snapshot{}); err == nil {
		t.Fatal("malformed completion unit was accepted")
	}

	otherJob, err := s.CreateJob(ctx, testJob("cycle-terminal"))
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: otherJob.ID, Job: otherJob.Job.Name, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='discarded' WHERE id=?`, terminal.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, terminal.ID); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("terminal restart error = %v", err)
	}
	if err := s.DiscardScanCycle(ctx, terminal.ID); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("terminal discard error = %v", err)
	}
	if _, err := s.CompleteScanCycle(ctx, terminal.ID); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("terminal complete error = %v", err)
	}
}

func TestScanCyclePauseStallAndRetryStatuses(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PauseScanCycle(ctx, cycle.ID, false, "idle"); err != nil {
		t.Fatal(err)
	}
	if paused, err := s.PauseScanCycle(ctx, cycle.ID, true, "  "+strings.Repeat("x", 600)); err != nil || paused.NoProgressAttempts != 1 || len([]rune(paused.LastError)) != 501 {
		t.Fatalf("pause state = %#v, %v", paused, err)
	}
	if stalled, err := s.MarkScanCycleStalled(ctx, cycle.ID, "stalled"); err != nil || stalled.Status != "stalled" {
		t.Fatalf("stalled state = %#v, %v", stalled, err)
	}
	if err := s.RetryScanCycleUnit(ctx, cycle.ID, 0, "retry"); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("retry paused error = %v", err)
	}
	if err := s.SplitScanCycleUnit(ctx, cycle.ID, 0, scanner.WorkUnit{}, scanner.WorkUnit{}, "split"); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("split paused error = %v", err)
	}
	if _, err := s.ExpireScanCycles(ctx, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseAndDeliveryHelpersCoverBoundaries(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, testJob("lease-boundary"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireJobLeaseForRevision(ctx, "missing", "owner", 1, time.Now().Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing revision lease error = %v", err)
	}
	if err := s.AcquireJobLeaseForRevision(ctx, job.ID, "owner", job.Revision, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireJobLeaseForRevision(ctx, job.ID, "other", job.Revision, time.Now().Add(time.Minute)); !errors.Is(err, ErrJobBusy) {
		t.Fatalf("busy revision lease error = %v", err)
	}
	if err := s.ReleaseJobLease(ctx, job.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireJobLeaseForRevision(ctx, job.ID, "other", job.Revision, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseJobLease(ctx, job.ID, "other"); err != nil {
		t.Fatal(err)
	}
	if min(1, 2) != 1 || min(2, 1) != 1 || truncate("short", 10) != "short" || truncate("012345", 3) != "012" {
		t.Fatal("boundary helpers returned unexpected values")
	}
}

func TestIncidentChangeApplicationBranches(t *testing.T) {
	if err := applyAcceptedChange(nil, model.Change{Kind: "port"}); !errors.Is(err, ErrBaselineNotReady) {
		t.Fatalf("nil baseline error = %v", err)
	}
	snapshot := &model.Snapshot{Units: []model.Unit{{Target: "target", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open", Service: "ssh"}}}}}
	for _, change := range []model.Change{
		{Kind: "unknown", Target: "target", Protocol: "tcp", Port: 22},
		{Kind: "port", Target: "", Protocol: "tcp", Port: 22, New: "open"},
		{Kind: "port", Target: "target", Protocol: "tcp", Port: 0, New: "open"},
		{Kind: "port", Target: "target", Protocol: "tcp", Port: 22, New: ""},
		{Kind: "service", Target: "target", Protocol: "tcp", Port: 22, New: ""},
		{Kind: "service", Target: "missing", Protocol: "tcp", Port: 22, New: "svc"},
		{Kind: "service", Target: "target", Protocol: "tcp", Port: 443, New: "svc"},
		{Kind: "dns-added", Target: "", New: "1.2.3.4"},
	} {
		if err := applyAcceptedChange(snapshot, change); err == nil {
			t.Errorf("invalid change %#v was accepted", change)
		}
	}
	if err := acceptPortChange(snapshot, model.Change{Kind: "port", Target: "target", Protocol: "tcp", Port: 22, New: "not-open"}); err != nil {
		t.Fatal(err)
	}
	if err := acceptPortChange(snapshot, model.Change{Kind: "port", Target: "new-target", Protocol: "udp", Port: 53, New: "open"}); err != nil {
		t.Fatal(err)
	}
	if err := acceptPortChange(snapshot, model.Change{Kind: "port", Target: "target", Protocol: "tcp", Port: 80, New: "open"}); err != nil {
		t.Fatal(err)
	}
	// Service updates require a baseline port and support both accepting a new
	// fingerprint and acknowledging that it disappeared.
	snapshot.Units = append(snapshot.Units, model.Unit{Target: "svc-target", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: "old"}}})
	if err := acceptServiceChange(snapshot, model.Change{Kind: "service", Target: "svc-target", Protocol: "tcp", Port: 443, New: "nginx"}); err != nil {
		t.Fatal(err)
	}
	if err := acceptServiceChange(snapshot, model.Change{Kind: "service", Target: "svc-target", Protocol: "tcp", Port: 443, New: "not-open"}); err != nil {
		t.Fatal(err)
	}

	dns := &model.Snapshot{}
	if err := acceptDNSChange(dns, model.Change{Kind: "dns-added", Target: "name", New: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if err := acceptDNSChange(dns, model.Change{Kind: "dns-added", Target: "name", New: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if err := acceptDNSChange(dns, model.Change{Kind: "dns-removed", Target: "name", Old: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if len(dns.DNS) != 0 {
		t.Fatalf("DNS entry remained after removal: %#v", dns.DNS)
	}
}
