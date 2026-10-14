package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

// BenchmarkProcessSuccessDenseFingerprintLearning reproduces the scale in
// issue #1407: a /16-sized scope list and 20,000 live hosts with three
// fingerprinted service ports each. Each iteration starts with a baseline
// missing those fingerprints and one matching prior candidate sample, so it
// measures the complete scan comparison that learns the stable fingerprints.
func BenchmarkProcessSuccessDenseFingerprintLearning(b *testing.B) {
	const (
		scopeCount = 1 << 16
		hostCount  = 20_000
		portCount  = 3
	)

	job := config.Job{
		Name:     "fingerprint-index-benchmark",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.0.0/16"},
		TCP:      &config.Protocol{Ports: "1-3", ServiceDetection: true},
		Baseline: config.Baseline{Samples: 2},
		Change:   config.Change{Confirmations: 1},
	}
	hash := job.SecurityHash()
	baseline := model.Snapshot{
		Scopes: make([]model.Scope, 0, scopeCount),
		Units:  make([]model.Unit, 0, hostCount),
	}
	current := model.Snapshot{
		Scopes: make([]model.Scope, 0, scopeCount),
		Units:  make([]model.Unit, 0, hostCount),
	}
	for i := 0; i < scopeCount; i++ {
		target := fmt.Sprintf("192.0.%d.%d", i/256, i%256)
		scope := model.Scope{Target: target, Protocol: "tcp", Ports: "1-3", ServiceDetection: true}
		baseline.Scopes = append(baseline.Scopes, scope)
		current.Scopes = append(current.Scopes, scope)
		if i >= hostCount {
			continue
		}
		portsBefore := make([]model.PortState, portCount)
		portsNow := make([]model.PortState, portCount)
		for offset := 0; offset < portCount; offset++ {
			port := offset + 1
			portsBefore[offset] = model.PortState{Port: port, State: "open"}
			portsNow[offset] = model.PortState{Port: port, State: "open", Service: fmt.Sprintf("service-%d", port)}
		}
		baseline.Units = append(baseline.Units, model.Unit{Target: target, Protocol: "tcp", Ports: portsBefore})
		current.Units = append(current.Units, model.Unit{Target: target, Protocol: "tcp", Ports: portsNow})
	}
	candidates := make(map[string]model.ValueCount, hostCount*portCount)
	for _, unit := range current.Units {
		for _, port := range unit.Ports {
			key := fingerprintKey(unit.Target, unit.Protocol, port.Port)
			candidates[key] = model.ValueCount{Value: port.Service, Count: 1}
		}
	}
	finishedAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	scanTemplate := model.Scan{
		ID: "fingerprint-index-benchmark", Job: job.Name, Status: "success",
		ConfigHash: hash, FinishedAt: finishedAt, Snapshot: current,
	}

	b.ReportAllocs()
	b.ReportMetric(scopeCount, "scopes/op")
	b.ReportMetric(hostCount*portCount, "service-ports/op")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		state := model.JobState{
			Baseline:              ptrSnapshot(cloneSnapshot(baseline)),
			BaselineConfigHash:    hash,
			FingerprintCandidates: make(map[string]model.ValueCount, len(candidates)),
			Incidents:             make(map[string]model.Incident),
			Pending:               make(map[string]model.Pending),
			Suppressed:            make(map[string]int),
			SuppressedChanges:     make(map[string]model.Change),
		}
		for key, candidate := range candidates {
			state.FingerprintCandidates[key] = candidate
		}
		scan := scanTemplate
		b.StartTimer()
		if _, _, err := processSuccessWithChanges(&state, job, scan); err != nil {
			b.Fatal(err)
		}
	}
}

func ptrSnapshot(snapshot model.Snapshot) *model.Snapshot {
	return &snapshot
}
