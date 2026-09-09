package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

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
	if hasScan, err := s.ScanCycleHasScan(ctx, cycle.ID); err != nil || !hasScan {
		t.Fatalf("cycle scan state after save = %v, %v", hasScan, err)
	}
	if notified, err := s.ScanCycleExpiryNotified(ctx, cycle.ID); err != nil || !notified {
		t.Fatalf("expiry notification after timeout = %v, %v", notified, err)
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
	// Reconciliation must repair the plan and totals before adding enrichment.
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
