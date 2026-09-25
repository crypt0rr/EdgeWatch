package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

func TestScanCycleUnitIdentityBackfillIsBoundedAndDeterministic(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	defer s.Close()
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{
		JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	unit := plan.Units[0]
	raw, err := json.Marshal(unit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET work_unit_json=?,identity='' WHERE cycle_id=? AND sequence=?`, raw, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_identity_backfill SET complete=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := backfillScanCycleUnitIdentitiesContext(ctx, s.DB); err != nil {
		t.Fatal(err)
	}
	if err := backfillScanCycleUnitIdentitiesContext(ctx, s.DB); err != nil {
		t.Fatalf("completed identity backfill: %v", err)
	}
	var got string
	if err := s.DB.QueryRowContext(ctx, `SELECT identity FROM scan_cycle_units WHERE cycle_id=? AND sequence=?`, cycle.ID, unit.Sequence).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if want := scanCycleUnitIdentity(unit); got != want {
		t.Fatalf("backfilled identity = %q, want %q", got, want)
	}
}

func TestScanCycleExpiryAndDiscardRespectLiveJobLease(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	defer s.Close()
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{
		JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(),
		Plan: plan, ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET expires_at=? WHERE id=?`, sqliteTimestamp(time.Now().UTC().Add(-time.Minute)), cycle.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireJobLease(ctx, job.ID, "cycle-owner", time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if expired, err := s.ExpireScanCycles(ctx, time.Now().UTC()); err != nil || expired != 0 {
		t.Fatalf("live cycle expiry = %d, %v", expired, err)
	}
	if err := s.DiscardScanCycle(ctx, cycle.ID); !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("live cycle discard error = %v, want ErrJobScanActive", err)
	}
	if err := s.ReleaseJobLease(ctx, job.ID, "cycle-owner"); err != nil {
		t.Fatal(err)
	}
	if expired, err := s.ExpireScanCycles(ctx, time.Now().UTC()); err != nil || expired != 1 {
		t.Fatalf("expired cycle cleanup = %d, %v", expired, err)
	}
	updated, err := s.GetScanCycle(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "expired" {
		t.Fatalf("cycle status = %q, want expired", updated.Status)
	}
}
func TestDiscardRunningScanCycleAtomicallyClearsProgress(t *testing.T) {
	cases := []struct {
		name           string
		completedUnits int
	}{
		{"partial", 1},
		{"all", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, s, job, plan := cycleFixture(t)
			defer s.Close()
			second := plan.Units[0]
			second.Sequence, second.Ports = 1, "2"
			plan.Units = append(plan.Units, second)
			cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{
				JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
				ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
				t.Fatal(err)
			}
			for sequence := 0; sequence < tc.completedUnits; sequence++ {
				if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, sequence); err != nil {
					t.Fatal(err)
				}
				if err := s.CompleteScanCycleUnit(ctx, cycle.ID, sequence, model.Snapshot{}); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.DiscardScanCycle(ctx, cycle.ID); err != nil {
				t.Fatal(err)
			}
			got, err := s.GetScanCycle(ctx, cycle.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != "discarded" || got.FinishedAt.IsZero() {
				t.Fatalf("discarded cycle state = status %q finished_at %v", got.Status, got.FinishedAt)
			}
			if got.CompletedUnits != 0 || got.TotalUnits != 0 || got.CompletedProbes != 0 || got.TotalProbes != 0 {
				t.Fatalf("discarded cycle retained progress: completed=%d/%d probes=%d/%d", got.CompletedUnits, got.TotalUnits, got.CompletedProbes, got.TotalProbes)
			}
			var units int
			if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_cycle_units WHERE cycle_id=?`, cycle.ID).Scan(&units); err != nil {
				t.Fatal(err)
			}
			if units != 0 {
				t.Fatalf("discarded cycle retained %d work units", units)
			}
		})
	}
}

func TestDiscardScanCycleRollsBackWhenTransitionOrCleanupFails(t *testing.T) {
	cases := []struct {
		name        string
		trigger     string
		wantErr     error
		wantMessage string
	}{
		{name: "update error", trigger: `CREATE TRIGGER reject_discard BEFORE UPDATE OF status ON scan_cycles WHEN NEW.status='discarded' BEGIN SELECT RAISE(ABORT, 'update unavailable'); END`, wantMessage: "update unavailable"},
		{name: "ignored update", trigger: `CREATE TRIGGER ignore_discard BEFORE UPDATE OF status ON scan_cycles WHEN NEW.status='discarded' BEGIN SELECT RAISE(IGNORE); END`, wantErr: ErrCycleNotResumable},
		{name: "delete error", trigger: `CREATE TRIGGER reject_cycle_unit_delete BEFORE DELETE ON scan_cycle_units BEGIN SELECT RAISE(ABORT, 'delete unavailable'); END`, wantMessage: "delete unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, s, job, plan := cycleFixture(t)
			defer s.Close()
			cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), Plan: plan})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, 0); err != nil {
				t.Fatal(err)
			}
			if err := s.CompleteScanCycleUnit(ctx, cycle.ID, 0, model.Snapshot{}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.ExecContext(ctx, tc.trigger); err != nil {
				t.Fatal(err)
			}
			discardErr := s.DiscardScanCycle(ctx, cycle.ID)
			if tc.wantErr != nil {
				if !errors.Is(discardErr, tc.wantErr) {
					t.Fatalf("discard error = %v, want %v", discardErr, tc.wantErr)
				}
			} else if discardErr == nil || !strings.Contains(discardErr.Error(), tc.wantMessage) {
				t.Fatalf("discard error = %v, want message %q", discardErr, tc.wantMessage)
			}
			got, err := s.GetScanCycle(ctx, cycle.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != "running" || got.CompletedUnits != 1 || got.TotalUnits != 1 || got.CompletedProbes != 1 || got.TotalProbes != 1 {
				t.Fatalf("failed discard mutated cycle: %#v", got)
			}
			var units int
			if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_cycle_units WHERE cycle_id=?`, cycle.ID).Scan(&units); err != nil {
				t.Fatal(err)
			}
			if units != len(plan.Units) {
				t.Fatalf("failed discard removed work: got %d units, want %d", units, len(plan.Units))
			}
		})
	}
}

func TestScanCyclePhaseAndProbeMetadataUsesIndexedColumns(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	defer s.Close()
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	var phase string
	var probes int64
	if err := s.DB.QueryRowContext(ctx, `SELECT phase,probes FROM scan_cycle_units WHERE cycle_id=? AND sequence=0`, cycle.ID).Scan(&phase, &probes); err != nil {
		t.Fatal(err)
	}
	if phase != plan.Units[0].Phase || probes != plan.Units[0].Probes {
		t.Fatalf("indexed unit metadata = phase %q probes %d, want %q/%d", phase, probes, plan.Units[0].Phase, plan.Units[0].Probes)
	}
	var indexCount int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_index_list('scan_cycle_units') WHERE name='scan_cycle_units_cycle_phase_status'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if indexCount != 1 {
		t.Fatal("cycle phase/status index is missing")
	}
	// The aggregate query must remain usable from the scalar columns even if a
	// legacy detail blob is unavailable; recovery paths decode that blob only
	// when they actually need the unit payload.
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET work_unit_json=? WHERE cycle_id=? AND sequence=0`, []byte("not-json"), cycle.ID); err != nil {
		t.Fatal(err)
	}
	discovery, nmap, err := s.ScanCycleProbeTotals(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if phase == "discovery" {
		if discovery != probes || nmap != 0 {
			t.Fatalf("probe totals = discovery %d nmap %d, want %d/0", discovery, nmap, probes)
		}
	} else if nmap != probes || discovery != 0 {
		t.Fatalf("probe totals = discovery %d nmap %d, want 0/%d", discovery, nmap, probes)
	}
}

func TestScanCycleHasScanRequiresPromotedFinalRecord(t *testing.T) {
	cases := []struct {
		name, status, cycleStatus string
	}{
		{name: "failed", status: "failed", cycleStatus: "paused"},
		{name: "canceled", status: "canceled", cycleStatus: "paused"},
		{name: "timed-out", status: "timed_out", cycleStatus: "paused"},
		{name: "expired", status: "timed_out", cycleStatus: "expired"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx, s, job, plan := cycleFixture(t)
			defer s.Close()
			cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			if err := s.SaveScan(ctx, model.Scan{ID: "attempt-" + test.name, JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now, FinishedAt: now, Status: test.status, CycleID: cycle.ID, CycleStatus: test.cycleStatus, ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}); err != nil {
				t.Fatal(err)
			}
			if hasScan, err := s.ScanCycleHasScan(ctx, cycle.ID); err != nil || hasScan {
				t.Fatalf("attempt row proved promotion = %v, %v", hasScan, err)
			}
			if err := s.SaveScan(ctx, model.Scan{ID: "promoted-" + test.name, JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", CycleID: cycle.ID, CycleStatus: "completed", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}); err != nil {
				t.Fatal(err)
			}
			if hasScan, err := s.ScanCycleHasScan(ctx, cycle.ID); err != nil || !hasScan {
				t.Fatalf("promoted row did not prove promotion = %v, %v", hasScan, err)
			}
		})
	}
}

func TestScanCycleAuxiliaryLifecycleAndFragments(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{
		JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetActiveScanCycle(ctx, "missing-job"); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing active cycle error = %v", err)
	}
	if _, err := s.GetLatestScanCycle(ctx, "missing-job"); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing latest cycle error = %v", err)
	}
	if _, err := s.GetScanCycle(ctx, "missing-cycle"); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing cycle error = %v", err)
	}
	if notified, err := s.ScanCycleExpiryNotified(ctx, cycle.ID); err != nil || notified {
		t.Fatalf("initial expiry notification = %v, %v", notified, err)
	}
	if hasScan, err := s.ScanCycleHasScan(ctx, cycle.ID); err != nil || hasScan {
		t.Fatalf("initial cycle scan state = %v, %v", hasScan, err)
	}

	summaries, err := s.ListScanCycleUnitSummaries(ctx, cycle.ID)
	if err != nil || len(summaries) != 1 {
		t.Fatalf("initial unit summaries = %#v, %v", summaries, err)
	}
	if summaries[0].Status != "pending" || summaries[0].Addresses != 1 || summaries[0].Probes != 1 {
		t.Fatalf("initial unit summary = %#v", summaries[0])
	}

	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if active, err := s.GetActiveScanCycle(ctx, job.ID); err != nil || active.ID != cycle.ID || active.Status != "running" {
		t.Fatalf("active cycle = %#v, %v", active, err)
	}
	if latest, err := s.GetLatestScanCycle(ctx, job.ID); err != nil || latest.ID != cycle.ID {
		t.Fatalf("latest cycle = %#v, %v", latest, err)
	}

	unit, err := s.NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp"}}}); err != nil {
		t.Fatal(err)
	}
	if fragmentsPlan, fragments, err := s.LoadScanCycleFragments(ctx, cycle.ID); err != nil || len(fragmentsPlan.Units) != 1 || len(fragments) != 1 {
		t.Fatalf("cycle fragments = %#v, %#v, %v", fragmentsPlan, fragments, err)
	}
	if _, err := s.CompleteScanCycle(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetActiveScanCycle(ctx, job.ID); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("completed cycle remained active: %v", err)
	}
	if _, err := s.NextScanCycleUnit(ctx, cycle.ID); !errors.Is(err, ErrNoPendingUnit) {
		t.Fatalf("completed cycle next unit error = %v", err)
	}

	now := time.Now().UTC()
	if err := s.SaveScan(ctx, model.Scan{ID: "cycle-timeout", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now, FinishedAt: now, Status: "timed_out", CycleID: cycle.ID, CycleStatus: "expired", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}); err != nil {
		t.Fatal(err)
	}
	if hasScan, err := s.ScanCycleHasScan(ctx, cycle.ID); err != nil || hasScan {
		t.Fatalf("attempt scan incorrectly proved promotion = %v, %v", hasScan, err)
	}
	if notified, err := s.ScanCycleExpiryNotified(ctx, cycle.ID); err != nil || !notified {
		t.Fatalf("expiry notification after timeout = %v, %v", notified, err)
	}
	if err := s.SaveScan(ctx, model.Scan{ID: "cycle-final", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now, FinishedAt: now, Status: "incomplete", CycleID: cycle.ID, CycleStatus: "completed", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}); err != nil {
		t.Fatal(err)
	}
	if hasScan, err := s.ScanCycleHasScan(ctx, cycle.ID); err != nil || !hasScan {
		t.Fatalf("promoted cycle scan state = %v, %v", hasScan, err)
	}
}

func TestReconcileNaabuDiscoveryAddsDeterministicEnrichmentAndUDP(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	jobValue := config.NormalizeJob(config.Job{Name: "naabu-cycle", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"edge.example"}, MaxExpandedHosts: 1, TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{AddressBatchSize: 1}}, UDP: &config.Protocol{Ports: "53"}})
	job, err := s.CreateJob(ctx, jobValue)
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{Job: job.Job, Targets: []scanner.ResolvedTarget{{Name: "edge.example", ConfiguredTarget: "edge.example", Addresses: []string{"192.0.2.1"}, Aggregate: true, Hostname: true}}, DNS: map[string][]string{"edge.example": {"192.0.2.1"}}, Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "1-65535"}, {Target: "edge.example", Protocol: "udp", Ports: "53"}}, Units: []scanner.WorkUnit{{Sequence: 0, Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Family: 4, Targets: []scanner.ResolvedTarget{{Name: "edge.example", ConfiguredTarget: "edge.example", Addresses: []string{"192.0.2.1"}, Aggregate: true, Hostname: true}}, Addresses: []string{"192.0.2.1"}, Ports: "1-65535", PortCount: 65535, Probes: 65535}}, TotalUnits: 1, TotalProbes: 65535}
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	fragment := model.Snapshot{Hosts: []model.HostObservation{{Address: "192.0.2.1", Protocols: []model.ProtocolObservation{{Protocol: "tcp", DiscoveryEngine: "naabu", DiscoveredPorts: []model.PortObservation{{Port: 22, State: "open", Verification: "discovered"}, {Port: 443, State: "open", Verification: "discovered"}}}}}}}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, fragment); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileScanCycleEnrichment(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	updated, err := s.GetScanCycle(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.TotalUnits != 3 || updated.TotalProbes <= 65535 {
		t.Fatalf("dynamic phase expansion = units %d probes %d", updated.TotalUnits, updated.TotalProbes)
	}
	discoveryProbes, nmapProbes, err := s.ScanCycleProbeTotals(ctx, cycle.ID)
	if err != nil || discoveryProbes != 65535 || nmapProbes <= 0 {
		t.Fatalf("probe categories = discovery %d nmap %d error %v", discoveryProbes, nmapProbes, err)
	}
	summaries, err := s.ListScanCycleUnitSummaries(ctx, cycle.ID)
	if err != nil || len(summaries) != 3 {
		t.Fatalf("expanded summaries = %#v, %v", summaries, err)
	}
	if summaries[1].Phase != "enrichment" || summaries[1].Engine != config.EngineNmap || summaries[1].Ports != "22,443" || summaries[2].Phase != "udp" {
		t.Fatalf("expanded phase order = %#v", summaries)
	}
	if err := s.ReconcileScanCycleEnrichment(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	again, err := s.ListScanCycleUnitSummaries(ctx, cycle.ID)
	if err != nil || len(again) != 3 {
		t.Fatalf("reconciliation duplicated units: %#v, %v", again, err)
	}
}

func TestReconcileNaabuDiscoveryIncludesBaselineExpectedPorts(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	jobValue := config.NormalizeJob(config.Job{
		Name: "naabu-baseline-union", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{AddressBatchSize: 1}},
	})
	job, err := s.CreateJob(ctx, jobValue)
	if err != nil {
		t.Fatal(err)
	}
	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}},
		Units:  []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: []model.PortState{{Port: 443, State: "open"}}}},
	}
	if _, err := s.UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &baseline
		state.BaselineScanID = "baseline"
		state.BaselineConfigHash = job.Job.SecurityHash()
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	target := scanner.ResolvedTarget{Name: "192.0.2.1", ConfiguredTarget: "192.0.2.1", Addresses: []string{"192.0.2.1"}}
	plan := scanner.WorkPlan{
		Job: job.Job, Targets: []scanner.ResolvedTarget{target},
		Scopes:     []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}},
		Units:      []scanner.WorkUnit{{Sequence: 0, Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Family: 4, Targets: []scanner.ResolvedTarget{target}, Addresses: []string{"192.0.2.1"}, Ports: "1-65535", PortCount: 65535, Probes: 65535}},
		TotalUnits: 1, TotalProbes: 65535,
	}
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	// Naabu sees only 22 in this run. The active baseline still expects 443,
	// so resumable reconciliation must create one Nmap unit for both ports.
	fragment := model.Snapshot{Hosts: []model.HostObservation{{Address: "192.0.2.1", Protocols: []model.ProtocolObservation{{Protocol: "tcp", DiscoveryEngine: "naabu", DiscoveredPorts: []model.PortObservation{{Port: 22, State: "open", Verification: "discovered"}}}}}}}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, fragment); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileScanCycleEnrichment(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	summaries, err := s.ListScanCycleUnitSummaries(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 2 || summaries[1].Phase != "enrichment" || summaries[1].Ports != "22,443" {
		t.Fatalf("baseline union enrichment = %#v", summaries)
	}
}

// Naabu reports positive ports only, so a single miss must not close a port
// the job still tracks. Open incidents, pending changes and suppressed
// changes that expect a TCP port open are confirmed by Nmap, like baseline
// ports. Changes name logical targets, so a DNS target maps to every
// address its plan resolved to.
func TestReconcileNaabuDiscoveryIncludesTrackedChangePorts(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	jobValue := config.NormalizeJob(config.Job{
		Name: "naabu-tracked-changes", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.1", "edge.example"}, MaxExpandedHosts: 3,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{AddressBatchSize: 16}},
		UDP: &config.Protocol{Ports: "53"},
	})
	job, err := s.CreateJob(ctx, jobValue)
	if err != nil {
		t.Fatal(err)
	}
	change := func(kind, target, protocol string, port int, old, current string) model.Change {
		return model.Change{Key: kind + "|" + target + "|" + protocol + "|" + fmt.Sprint(port), Kind: kind, Target: target, Protocol: protocol, Port: port, Old: old, New: current}
	}
	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}, {Target: "edge.example", Protocol: "tcp", Ports: "1-65535"}},
		Units:  []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: []model.PortState{{Port: 443, State: "open"}}}},
	}
	if _, err := s.UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &baseline
		state.BaselineScanID = "baseline"
		state.BaselineConfigHash = job.Job.SecurityHash()
		addition := change("port", "192.0.2.1", "tcp", 8080, "not-open", "open")
		service := change("service", "192.0.2.1", "tcp", 8081, "not-open", "http")
		removal := change("port", "192.0.2.1", "tcp", 25, "open", "not-open")
		udp := change("port", "192.0.2.1", "udp", 53, "not-open", "open|filtered")
		serviceRemoval := change("service", "192.0.2.1", "tcp", 587, "smtp", "not-open")
		dnsChange := model.Change{Key: "dns|edge.example|192.0.2.9", Kind: "dns-added", Target: "edge.example", New: "192.0.2.9"}
		unplanned := change("port", "gone.example", "tcp", 7000, "not-open", "open")
		invalidPort := change("port", "192.0.2.1", "tcp", 0, "not-open", "open")
		state.Incidents = map[string]model.Incident{}
		for _, tracked := range []model.Change{addition, service, removal, udp, serviceRemoval, dnsChange, unplanned, invalidPort} {
			state.Incidents[tracked.Key] = model.Incident{Change: tracked}
		}
		pending := change("port", "192.0.2.1", "tcp", 8443, "not-open", "open|filtered")
		state.Pending = map[string]model.Pending{pending.Key: {Change: pending, Count: 1}}
		suppressed := change("port", "edge.example", "tcp", 9443, "not-open", "open")
		state.Suppressed = map[string]int{suppressed.Key: 1}
		state.SuppressedChanges = map[string]model.Change{suppressed.Key: suppressed}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	direct := scanner.ResolvedTarget{Name: "192.0.2.1", ConfiguredTarget: "192.0.2.1", Addresses: []string{"192.0.2.1"}}
	dns := scanner.ResolvedTarget{Name: "edge.example", ConfiguredTarget: "edge.example", Addresses: []string{"192.0.2.7", "192.0.2.8"}, Aggregate: true, Hostname: true}
	targets := []scanner.ResolvedTarget{direct, dns}
	addresses := []string{"192.0.2.1", "192.0.2.7", "192.0.2.8"}
	plan := scanner.WorkPlan{
		Job: job.Job, Targets: targets, DNS: map[string][]string{"edge.example": dns.Addresses},
		Scopes:     baseline.Scopes,
		Units:      []scanner.WorkUnit{{Sequence: 0, Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Family: 4, Targets: targets, Addresses: addresses, Ports: "1-65535", PortCount: 65535, Probes: 3 * 65535}},
		TotalUnits: 1, TotalProbes: 3 * 65535,
	}
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	// Naabu misses every tracked port in this run; it only reports 22.
	discovered := func(address string, ports ...int) model.HostObservation {
		protocol := model.ProtocolObservation{Protocol: "tcp", DiscoveryEngine: "naabu"}
		for _, port := range ports {
			protocol.DiscoveredPorts = append(protocol.DiscoveredPorts, model.PortObservation{Port: port, State: "open", Verification: "discovered"})
		}
		return model.HostObservation{Address: address, Protocols: []model.ProtocolObservation{protocol}}
	}
	fragment := model.Snapshot{Hosts: []model.HostObservation{discovered("192.0.2.1", 22), discovered("192.0.2.7", 22), discovered("192.0.2.8")}}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, fragment); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileScanCycleEnrichment(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT work_unit_json FROM scan_cycle_units WHERE cycle_id=? AND phase='enrichment' ORDER BY sequence`, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	enrichment := map[string]string{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var unit scanner.WorkUnit
		if err := json.Unmarshal(raw, &unit); err != nil {
			t.Fatal(err)
		}
		for _, address := range unit.Addresses {
			enrichment[address] = unit.Ports
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		// Discovered 22, baseline 443, incidents 8080 and 8081 (a service
		// change implies an open port), pending 8443. Removals (port 25 and
		// the service on 587), the UDP and DNS incidents, a target outside
		// the plan and an invalid port add no TCP confirmation.
		"192.0.2.1": "22,443,8080-8081,8443",
		// The suppressed change on edge.example covers both DNS addresses.
		"192.0.2.7": "22,9443",
		"192.0.2.8": "9443",
	}
	if len(enrichment) != len(want) {
		t.Fatalf("enrichment units = %#v, want %#v", enrichment, want)
	}
	for address, ports := range want {
		if enrichment[address] != ports {
			t.Fatalf("enrichment ports for %s = %q, want %q (all %#v)", address, enrichment[address], ports, enrichment)
		}
	}
}

func TestReconcileNaabuDiscoveryChunksLargePortSets(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	jobValue := config.NormalizeJob(config.Job{
		Name: "naabu-large", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", ServiceDetection: true, Naabu: &config.NaabuOptions{AddressBatchSize: 1}},
	})
	job, err := s.CreateJob(ctx, jobValue)
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{
		Job:     job.Job,
		Targets: []scanner.ResolvedTarget{{Name: "192.0.2.1", ConfiguredTarget: "192.0.2.1", Addresses: []string{"192.0.2.1"}}},
		Scopes:  []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535", ServiceDetection: true}},
		Units: []scanner.WorkUnit{{
			Sequence: 0, Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Family: 4,
			Targets:   []scanner.ResolvedTarget{{Name: "192.0.2.1", ConfiguredTarget: "192.0.2.1", Addresses: []string{"192.0.2.1"}}},
			Addresses: []string{"192.0.2.1"}, Ports: "1-65535", PortCount: 65535, Probes: 65535,
		}},
		TotalUnits: 1, TotalProbes: 65535,
	}
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{
		JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	discovered := make([]model.PortObservation, 5000)
	for i := range discovered {
		discovered[i] = model.PortObservation{Port: i + 1, State: "open", Verification: "discovered"}
	}
	fragment := model.Snapshot{Hosts: []model.HostObservation{{
		Address: "192.0.2.1",
		Protocols: []model.ProtocolObservation{{
			Protocol: "tcp", DiscoveryEngine: "naabu", DiscoveredPorts: discovered,
		}},
	}}}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, fragment); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileScanCycleEnrichment(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	summaries, err := s.ListScanCycleUnitSummaries(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 3 {
		t.Fatalf("large discovery produced %d units, want discovery plus two bounded enrichments: %#v", len(summaries), summaries)
	}
	for _, summary := range summaries[1:] {
		if summary.Phase != "enrichment" || summary.Engine != config.EngineNmap || summary.PortCount > scanner.MaxWorkUnitPorts || summary.Probes > scanner.MaxWorkUnitProbes {
			t.Fatalf("enrichment unit exceeded checkpoint bounds: %#v", summary)
		}
	}
	if summaries[1].Ports != "1-4096" || summaries[2].Ports != "4097-5000" {
		t.Fatalf("large port set was not split deterministically: %#v", summaries)
	}
}

func TestReconcileNaabuDiscoveryIsIncremental(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	jobValue := config.NormalizeJob(config.Job{
		Name: "naabu-incremental", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.1", "192.0.2.2"}, MaxExpandedHosts: 2,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{AddressBatchSize: 1}},
	})
	job, err := s.CreateJob(ctx, jobValue)
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{
		Job: job.Job,
		Targets: []scanner.ResolvedTarget{
			{Name: "192.0.2.1", ConfiguredTarget: "192.0.2.1", Addresses: []string{"192.0.2.1"}},
			{Name: "192.0.2.2", ConfiguredTarget: "192.0.2.2", Addresses: []string{"192.0.2.2"}},
		},
		Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}, {Target: "192.0.2.2", Protocol: "tcp", Ports: "1-65535"}},
		Units: []scanner.WorkUnit{
			{Sequence: 0, Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Family: 4, Targets: []scanner.ResolvedTarget{{Name: "192.0.2.1", ConfiguredTarget: "192.0.2.1", Addresses: []string{"192.0.2.1"}}}, Addresses: []string{"192.0.2.1"}, Ports: "1-65535", PortCount: 65535, Probes: 65535},
			{Sequence: 1, Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Family: 4, Targets: []scanner.ResolvedTarget{{Name: "192.0.2.2", ConfiguredTarget: "192.0.2.2", Addresses: []string{"192.0.2.2"}}}, Addresses: []string{"192.0.2.2"}, Ports: "1-65535", PortCount: 65535, Probes: 65535},
		},
		TotalUnits: 2, TotalProbes: 131070,
	}
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	var planBefore []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT plan_json FROM scan_cycles WHERE id=?`, cycle.ID).Scan(&planBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	completeDiscovery := func(port, sequence int, address string) {
		t.Helper()
		unit, err := s.NextScanCycleUnit(ctx, cycle.ID)
		if err != nil || unit.Sequence != sequence {
			t.Fatalf("next discovery unit = %#v, %v", unit, err)
		}
		if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, sequence); err != nil {
			t.Fatal(err)
		}
		fragment := model.Snapshot{Hosts: []model.HostObservation{{Address: address, Protocols: []model.ProtocolObservation{{Protocol: "tcp", DiscoveryEngine: "naabu", DiscoveredPorts: []model.PortObservation{{Port: port, State: "open", Verification: "discovered"}}}}}}}
		if err := s.CompleteScanCycleUnit(ctx, cycle.ID, sequence, fragment); err != nil {
			t.Fatal(err)
		}
		if err := s.ReconcileScanCycleEnrichment(ctx, cycle.ID); err != nil {
			t.Fatal(err)
		}
	}
	completeDiscovery(22, 0, "192.0.2.1")
	var checkpoints int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_cycle_discovery_checkpoints WHERE cycle_id=?`, cycle.ID).Scan(&checkpoints); err != nil {
		t.Fatal(err)
	}
	if checkpoints != 1 {
		t.Fatalf("checkpoint count after first batch = %d, want 1", checkpoints)
	}
	var planAfter []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT plan_json FROM scan_cycles WHERE id=?`, cycle.ID).Scan(&planAfter); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(planBefore, planAfter) {
		t.Fatal("incremental reconciliation rewrote the persisted plan blob")
	}
	summaries, err := s.ListScanCycleUnitSummaries(ctx, cycle.ID)
	if err != nil || len(summaries) != 3 {
		t.Fatalf("first incremental reconciliation = %#v, %v", summaries, err)
	}
	completeDiscovery(443, 1, "192.0.2.2")
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_cycle_discovery_checkpoints WHERE cycle_id=?`, cycle.ID).Scan(&checkpoints); err != nil {
		t.Fatal(err)
	}
	if checkpoints != 2 {
		t.Fatalf("checkpoint count after second batch = %d, want 2", checkpoints)
	}
	summaries, err = s.ListScanCycleUnitSummaries(ctx, cycle.ID)
	if err != nil || len(summaries) != 4 {
		t.Fatalf("second incremental reconciliation = %#v, %v", summaries, err)
	}
	if summaries[2].Ports != "22" || summaries[3].Ports != "443" {
		t.Fatalf("incremental enrichment scopes = %#v", summaries)
	}
	if err := s.ReconcileScanCycleEnrichment(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	again, err := s.ListScanCycleUnitSummaries(ctx, cycle.ID)
	if err != nil || len(again) != 4 {
		t.Fatalf("reconciliation duplicated units: %#v, %v", again, err)
	}
}

func TestReconcileNaabuDiscoveryRepairsSplitPlanCounters(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	jobValue := config.NormalizeJob(config.Job{
		Name: "naabu-split", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.1", "192.0.2.2"}, MaxExpandedHosts: 2,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{AddressBatchSize: 1}},
	})
	job, err := s.CreateJob(ctx, jobValue)
	if err != nil {
		t.Fatal(err)
	}
	targets := []scanner.ResolvedTarget{
		{Name: "192.0.2.1", ConfiguredTarget: "192.0.2.1", Addresses: []string{"192.0.2.1"}},
		{Name: "192.0.2.2", ConfiguredTarget: "192.0.2.2", Addresses: []string{"192.0.2.2"}},
	}
	plan := scanner.WorkPlan{
		Job: job.Job, Targets: targets,
		Scopes:     []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}, {Target: "192.0.2.2", Protocol: "tcp", Ports: "1-65535"}},
		Units:      []scanner.WorkUnit{{Sequence: 0, Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Family: 4, Targets: targets[:1], Addresses: []string{"192.0.2.1"}, Ports: "1-65535", PortCount: 65535, Probes: 65535}},
		TotalUnits: 1, TotalProbes: 65535,
	}
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	first := unit.Unit
	first.Addresses = []string{"192.0.2.1"}
	first.Targets = targets[:1]
	second := unit.Unit
	second.Addresses = []string{"192.0.2.2"}
	second.Targets = targets[1:]
	if err := s.SplitScanCycleUnit(ctx, cycle.ID, unit.Sequence, first, second, "split for test"); err != nil {
		t.Fatal(err)
	}

	complete := func(sequence int, address string, port int) {
		t.Helper()
		if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, sequence); err != nil {
			t.Fatal(err)
		}
		fragment := model.Snapshot{Hosts: []model.HostObservation{{Address: address, Protocols: []model.ProtocolObservation{{Protocol: "tcp", DiscoveryEngine: "naabu", DiscoveredPorts: []model.PortObservation{{Port: port, State: "open", Verification: "discovered"}}}}}}}
		if err := s.CompleteScanCycleUnit(ctx, cycle.ID, sequence, fragment); err != nil {
			t.Fatal(err)
		}
		if err := s.ReconcileScanCycleEnrichment(ctx, cycle.ID); err != nil {
			t.Fatal(err)
		}
	}

	// The split leaves plan_json with one unit while the durable table has two.
	// Reconciliation must preserve the durable counters before adding enrichment.
	complete(0, "192.0.2.1", 22)
	updated, err := s.GetScanCycle(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.TotalUnits != 3 || updated.Plan.TotalUnits != 3 || updated.TotalProbes != 65535*2+1 {
		t.Fatalf("split counters after first discovery = total=%d plan=%d probes=%d", updated.TotalUnits, updated.Plan.TotalUnits, updated.TotalProbes)
	}
	complete(1, "192.0.2.2", 443)
	updated, err = s.GetScanCycle(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.TotalUnits != 4 || updated.Plan.TotalUnits != 4 || updated.TotalProbes != 65535*2+2 {
		t.Fatalf("split counters after second discovery = total=%d plan=%d probes=%d", updated.TotalUnits, updated.Plan.TotalUnits, updated.TotalProbes)
	}
	complete(2, "192.0.2.1", 22)
	complete(3, "192.0.2.2", 443)
	if _, err := s.CompleteScanCycle(ctx, cycle.ID); err != nil {
		t.Fatalf("completed split cycle = %v", err)
	}
}

func TestScanCycleRetrySplitStallAndDiscard(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	longError := strings.Repeat("x", 600)
	if err := s.RetryScanCycleUnit(ctx, cycle.ID, unit.Sequence, longError); err != nil {
		t.Fatal(err)
	}
	pending, err := s.NextScanCycleUnit(ctx, cycle.ID)
	if err != nil || pending.LastError != strings.Repeat("x", 500)+"…" {
		t.Fatalf("retried unit = %#v, %v", pending, err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, pending.Sequence); err != nil {
		t.Fatal(err)
	}
	first := pending.Unit
	first.Ports = "1"
	first.PortCount = 1
	second := pending.Unit
	second.Ports = "2"
	second.PortCount = 1
	if err := s.SplitScanCycleUnit(ctx, cycle.ID, pending.Sequence, first, second, "split after timeout"); err != nil {
		t.Fatal(err)
	}
	updated, err := s.GetScanCycle(ctx, cycle.ID)
	if err != nil || updated.TotalUnits != 2 || updated.LastError != "split after timeout" {
		t.Fatalf("split cycle = %#v, %v", updated, err)
	}
	summaries, err := s.ListScanCycleUnitSummaries(ctx, cycle.ID)
	if err != nil || len(summaries) != 2 || summaries[1].Sequence != 1 {
		t.Fatalf("split summaries = %#v, %v", summaries, err)
	}

	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, 0, model.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, 1, model.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteScanCycle(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RetryScanCycleUnit(ctx, cycle.ID, 0, "late retry"); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("late retry error = %v", err)
	}

	secondCycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, secondCycle.ID); err != nil {
		t.Fatal(err)
	}
	if stalled, err := s.MarkScanCycleStalled(ctx, secondCycle.ID, "no progress"); err != nil || stalled.Status != "stalled" {
		t.Fatalf("stalled cycle = %#v, %v", stalled, err)
	}
	if resumed, err := s.StartScanCycleAttempt(ctx, secondCycle.ID); err != nil || resumed.Status != "running" || resumed.AttemptCount != 2 {
		t.Fatalf("resumed stalled cycle = %#v, %v", resumed, err)
	}
	if paused, err := s.PauseScanCycle(ctx, secondCycle.ID, true, "paused again"); err != nil || paused.Status != "paused" || paused.NoProgressAttempts != 1 {
		t.Fatalf("paused cycle = %#v, %v", paused, err)
	}
	if err := s.DiscardScanCycle(ctx, secondCycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetActiveScanCycle(ctx, job.ID); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("discarded cycle remained active: %v", err)
	}
	if err := s.DiscardScanCycle(ctx, secondCycle.ID); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("discarded cycle second discard error = %v", err)
	}
}

func TestScanCycleValidationAndMissingOperations(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	if _, err := s.CreateScanCycle(ctx, ScanCycleRecord{Plan: plan}); err == nil {
		t.Fatal("cycle without job was accepted")
	}
	if _, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name}); err == nil {
		t.Fatal("cycle without units was accepted")
	}
	if _, err := s.NextScanCycleUnit(ctx, "missing"); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing next unit error = %v", err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, "missing", 0); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing claim error = %v", err)
	}
	if err := s.RetryScanCycleUnit(ctx, "missing", 0, "error"); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing retry error = %v", err)
	}
	if err := s.SplitScanCycleUnit(ctx, "missing", 0, scanner.WorkUnit{}, scanner.WorkUnit{}, "error"); err == nil {
		t.Fatal("missing split unexpectedly succeeded")
	}
	if err := s.DiscardScanCycle(ctx, "missing"); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing discard error = %v", err)
	}
	if _, err := s.MarkScanCycleStalled(ctx, "missing", "error"); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing stalled lookup error = %v", err)
	}
	if _, err := s.PauseScanCycle(ctx, "missing", false, "error"); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing pause lookup error = %v", err)
	}
	if _, err := s.CompleteScanCycle(ctx, "missing"); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing completion error = %v", err)
	}
	if _, _, err := s.LoadScanCycleFragments(ctx, "missing"); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("missing fragments error = %v", err)
	}
	if trimCycleError(strings.Repeat("z", 600)) != strings.Repeat("z", 500)+"…" {
		t.Fatal("long cycle error was not trimmed deterministically")
	}
}
