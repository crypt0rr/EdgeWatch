package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
)

func TestNmapVersionAndScanWorkUnit(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s' '"+sampleXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	if version := n.Version(context.Background()); version == "unknown" || !strings.Contains(version, "<?xml") {
		t.Fatalf("unexpected fake nmap version output = %q", version)
	}

	job := config.NormalizeJob(config.Job{Name: "unit", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "22", Mode: "syn"}, Timing: "balanced"})
	unit := WorkUnit{Sequence: 2, Protocol: "tcp", Family: 4, Targets: []ResolvedTarget{{Name: "192.0.2.1", ConfiguredTarget: "192.0.2.1", Addresses: []string{"192.0.2.1"}}}, Addresses: []string{"192.0.2.1"}, Ports: "22", PortCount: 1, Probes: 1}
	var updates []Progress
	snapshot, err := n.ScanWorkUnit(context.Background(), job, unit, func(progress Progress) { updates = append(updates, progress) })
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Units) != 1 || len(snapshot.Hosts) != 1 || snapshot.Hosts[0].Address != "192.0.2.1" {
		t.Fatalf("work unit snapshot = %#v", snapshot)
	}
	if len(updates) < 3 || updates[0].CurrentUnit != 3 || updates[len(updates)-1].ProcessProgressPercent != 100 {
		t.Fatalf("work unit progress = %#v", updates)
	}
	if _, err := n.ScanWorkUnit(context.Background(), config.Job{}, unit, nil); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("disabled protocol error = %v", err)
	}

	// Older Naabu revisions stored the confirmation template in nmap_args and
	// left enrichment_args empty. ScanWorkUnit must keep those revisions
	// executable rather than attempting an empty command template.
	enrichmentJob := config.NormalizeJob(config.Job{
		Name:    "legacy-enrichment",
		Targets: []string{"192.0.2.1"},
		TCP:     &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "22", Mode: "connect"},
	})
	enrichmentUnit := unit
	enrichmentUnit.Phase = "enrichment"
	if _, err := n.ScanWorkUnit(context.Background(), enrichmentJob, enrichmentUnit, nil); err != nil {
		t.Fatalf("legacy enrichment fallback failed: %v", err)
	}
}

func TestScanWorkUnitReappliesTargetExclusions(t *testing.T) {
	n := New("missing-nmap")
	if err := n.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	unit := WorkUnit{Protocol: "tcp", Addresses: []string{"127.0.0.1"}, Ports: "1", PortCount: 1, Probes: 1}
	if _, err := n.ScanWorkUnit(context.Background(), config.Job{}, unit, nil); err == nil || !strings.Contains(err.Error(), "excluded by deployment policy") {
		t.Fatalf("excluded persisted work unit accepted: %v", err)
	}
	if err := n.SetTargetExclusions([]string{"192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	unit.Addresses = []string{"192.0.2.1"}
	if _, err := n.ScanWorkUnit(context.Background(), config.Job{}, unit, nil); err == nil || !strings.Contains(err.Error(), "192.0.2.0/24") {
		t.Fatalf("CIDR-excluded persisted work unit accepted: %v", err)
	}
}
