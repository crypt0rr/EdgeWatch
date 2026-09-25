package scanner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

// allOpenNaabuFixture returns a fake Naabu that reports every TCP port open
// on each address and, like Naabu v2.6.1, prints every result twice: once when
// found and again when the scan ends. The records carry the fields Naabu emits
// with EdgeWatch's arguments, so the raw output is far larger than the
// distinct results (more than 16 MiB for two IPv4 addresses or one long IPv6
// address).
func allOpenNaabuFixture(t *testing.T, addresses ...string) string {
	t.Helper()
	script := `awk 'BEGIN {
  n = split("` + strings.Join(addresses, " ") + `", addresses, " ")
  for (copy = 0; copy < 2; copy++)
    for (port = 1; port <= 65535; port++)
      for (i = 1; i <= n; i++)
        printf "{\"host\":\"%s\",\"ip\":\"%s\",\"timestamp\":\"2026-09-25T10:00:00.123456789Z\",\"port\":%d,\"protocol\":\"tcp\",\"tls\":false}\n", addresses[i], addresses[i], port
}'
`
	return writeNaabuFixture(t, script)
}

func naabuDiscoveryUnit(addresses ...string) WorkUnit {
	targets := make([]ResolvedTarget, 0, len(addresses))
	for _, address := range addresses {
		targets = append(targets, ResolvedTarget{Name: address, ConfiguredTarget: address, Addresses: []string{address}})
	}
	family := 4
	if strings.Contains(addresses[0], ":") {
		family = 6
	}
	return WorkUnit{Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Family: family, Targets: targets, Addresses: append([]string(nil), addresses...), Ports: "1-65535", PortCount: 65535, Probes: int64(len(addresses)) * 65535}
}

func naabuDiscoveryJob(assumeAlive bool, scanType string, addresses ...string) config.Job {
	return config.NormalizeJob(config.Job{
		Name: "naabu-discovery", Targets: addresses, MaxExpandedHosts: len(addresses), AssumeAlive: boolPtr(assumeAlive),
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Mode: "connect", Naabu: &config.NaabuOptions{ScanType: scanType}},
	})
}

func discoveredPortCounts(snapshot model.Snapshot) map[string]int {
	counts := map[string]int{}
	for _, host := range snapshot.Hosts {
		for _, protocol := range host.Protocols {
			if protocol.DiscoveryEngine == "naabu" {
				counts[host.Address] += len(protocol.DiscoveredPorts)
			}
		}
	}
	return counts
}

func hostsByAddress(snapshot model.Snapshot) map[string]model.HostObservation {
	hosts := make(map[string]model.HostObservation, len(snapshot.Hosts))
	for _, host := range snapshot.Hosts {
		hosts[host.Address] = host
	}
	return hosts
}

func naabuProtocol(t *testing.T, host model.HostObservation) model.ProtocolObservation {
	t.Helper()
	for _, protocol := range host.Protocols {
		if protocol.Protocol == "tcp" && protocol.DiscoveryEngine == "naabu" {
			return protocol
		}
	}
	t.Fatalf("host %s has no Naabu TCP evidence: %#v", host.Address, host.Protocols)
	return model.ProtocolObservation{}
}

func allowNaabuSYNForTest(t *testing.T) {
	t.Helper()
	previous := naabuRawPrivileges
	naabuRawPrivileges = func() bool { return true }
	t.Cleanup(func() { naabuRawPrivileges = previous })
}

// Two addresses that accept every TCP port produce more than 16 MiB of raw
// JSONL because Naabu repeats each result. The distinct results are bounded,
// so the discovery checkpoint must complete instead of failing the unit on
// every retry and stalling the cycle.
func TestNaabuDiscoveryDeduplicatesAllOpenAddressesBeyondRawOutputSize(t *testing.T) {
	addresses := []string{"192.0.2.3", "192.0.2.4"}
	n := NewWithNaabu(filepath.Join(t.TempDir(), "missing-nmap"), allOpenNaabuFixture(t, addresses...))
	snapshot, err := n.ScanWorkUnit(context.Background(), naabuDiscoveryJob(true, "connect", addresses...), naabuDiscoveryUnit(addresses...), nil)
	if err != nil {
		t.Fatalf("all-open discovery failed: %v", err)
	}
	counts := discoveredPortCounts(snapshot)
	for _, address := range addresses {
		if counts[address] != 65535 {
			t.Fatalf("discovered ports for %s = %d, want 65535 (all counts %v)", address, counts[address], counts)
		}
	}
	for _, host := range snapshot.Hosts {
		if host.Status != "up" {
			t.Fatalf("all-open host %s status = %q/%q", host.Address, host.Status, host.StatusReason)
		}
	}
}

// A single all-open IPv6 address cannot be split further. Its duplicated
// output alone exceeds 16 MiB, yet it has only 65535 distinct results.
func TestNaabuDiscoveryCompletesSingleAllOpenIPv6Address(t *testing.T) {
	address := "2001:db8:1234:5678:9abc:def0:1234:5678"
	n := NewWithNaabu(filepath.Join(t.TempDir(), "missing-nmap"), allOpenNaabuFixture(t, address))
	snapshot, err := n.ScanWorkUnit(context.Background(), naabuDiscoveryJob(true, "connect", address), naabuDiscoveryUnit(address), nil)
	if err != nil {
		t.Fatalf("all-open IPv6 discovery failed: %v", err)
	}
	if counts := discoveredPortCounts(snapshot); counts[address] != 65535 {
		t.Fatalf("discovered IPv6 ports = %v, want 65535", counts)
	}
}

// When a batch reports more distinct results than one checkpoint may hold,
// the addresses with the most results are recorded as incomplete with an
// explicit reason, and the rest of the batch completes normally.
func TestNaabuDiscoveryMarksAddressesBeyondResultLimitIncomplete(t *testing.T) {
	previous := maxNaabuUniqueResults
	maxNaabuUniqueResults = 10
	t.Cleanup(func() { maxNaabuUniqueResults = previous })
	record := func(address string, ports ...string) string {
		var lines strings.Builder
		for _, port := range ports {
			lines.WriteString(`{"ip":"` + address + `","port":` + port + `,"protocol":"tcp"}` + "\n")
		}
		return lines.String()
	}
	output := record("192.0.2.1", "1", "2", "3", "4", "5", "6", "7", "8") +
		record("192.0.2.2", "1", "2", "3", "4", "5", "6") +
		record("192.0.2.3", "22", "80", "443", "8443")
	// Repeat everything, as Naabu does at the end of a scan.
	path := filepath.Join(t.TempDir(), "results.jsonl")
	if err := os.WriteFile(path, []byte(output+output), 0o600); err != nil {
		t.Fatal(err)
	}
	addresses := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	n := NewWithNaabu(filepath.Join(t.TempDir(), "missing-nmap"), writeNaabuFixture(t, "cat "+path+"\n"))
	snapshot, err := n.ScanWorkUnit(context.Background(), naabuDiscoveryJob(true, "connect", addresses...), naabuDiscoveryUnit(addresses...), nil)
	if err != nil {
		t.Fatalf("discovery beyond the result limit failed the unit: %v", err)
	}
	hosts := hostsByAddress(snapshot)
	truncated := hosts["192.0.2.1"]
	protocol := naabuProtocol(t, truncated)
	if truncated.Status != "unknown" || truncated.StatusReason != naabuResultLimitReason || protocol.Status != "unknown" || protocol.StatusReason != naabuResultLimitReason || len(protocol.DiscoveredPorts) != 0 {
		t.Fatalf("address beyond the result limit = %q/%q, protocol %#v", truncated.Status, truncated.StatusReason, protocol)
	}
	if !isIncompleteProtocolStatus(protocol.Status, protocol.StatusReason) {
		t.Fatal("address beyond the result limit is not incomplete coverage")
	}
	counts := discoveredPortCounts(snapshot)
	if counts["192.0.2.2"] != 6 || counts["192.0.2.3"] != 4 || hosts["192.0.2.2"].Status != "up" || hosts["192.0.2.3"].Status != "up" {
		t.Fatalf("addresses within the result limit = %v, hosts %#v", counts, hosts)
	}
}

// With host discovery (SYN and assume_alive=false) Naabu prints nothing for an
// address that did not answer discovery. That address was not probed, so it
// must stay incomplete, as a down host does with the Nmap engine. Without host
// discovery every port was probed and a silent address is complete (#718).
func TestNaabuSilentAddressesAreCompleteOnlyWithoutHostDiscovery(t *testing.T) {
	allowNaabuSYNForTest(t)
	for _, test := range []struct {
		name        string
		assumeAlive bool
		flag        string
		reason      string
	}{
		{name: "host discovery", assumeAlive: false, flag: "-with-host-discovery", reason: "no-response"},
		{name: "assume alive", assumeAlive: true, flag: "-skip-host-discovery", reason: naabuFullRangeCompleteReason},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			argsPath := filepath.Join(dir, "args")
			naabuPath := writeNaabuFixture(t, "printf '%s\\n' \"$@\" > "+argsPath+"\nprintf '%s\\n' '{\"ip\":\"192.0.2.1\",\"port\":22,\"protocol\":\"tcp\"}'\n")
			nmapPath := filepath.Join(dir, "nmap")
			if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s' '"+sampleXML+"'\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			n := NewWithNaabu(nmapPath, naabuPath)
			addresses := []string{"192.0.2.1", "192.0.2.50"}
			job := naabuDiscoveryJob(test.assumeAlive, "syn", addresses...)
			unit := naabuDiscoveryUnit(addresses...)

			checkpoint, err := n.ScanWorkUnit(context.Background(), job, unit, nil)
			if err != nil {
				t.Fatalf("SYN discovery = %v", err)
			}
			args, err := os.ReadFile(argsPath)
			if err != nil || !slices.Contains(strings.Split(strings.TrimSpace(string(args)), "\n"), test.flag) {
				t.Fatalf("Naabu arguments = %q (%v), want %s", args, err, test.flag)
			}
			// The resumable path merges the discovery checkpoint into the cycle
			// result; the direct pipeline builds the same observation itself.
			merged := MergeWorkSnapshots(WorkPlan{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}, {Target: "192.0.2.50", Protocol: "tcp", Ports: "1-65535"}}}, []model.Snapshot{checkpoint})
			direct, err := n.scanNaabuPipelineResolved(context.Background(), job, importResolvedTargets(unit.Targets), nil)
			if err != nil {
				t.Fatalf("direct SYN pipeline = %v", err)
			}
			for name, snapshot := range map[string]model.Snapshot{"checkpoint": merged, "direct": direct} {
				hosts := hostsByAddress(snapshot)
				if hosts["192.0.2.1"].Status != "up" {
					t.Fatalf("%s responsive host = %#v", name, hosts["192.0.2.1"])
				}
				silent := hosts["192.0.2.50"]
				protocol := naabuProtocol(t, silent)
				if silent.Status != "unknown" || silent.StatusReason != test.reason || protocol.Status != "unknown" || protocol.StatusReason != test.reason {
					t.Fatalf("%s silent host = %q/%q, protocol %q/%q, want unknown/%s", name, silent.Status, silent.StatusReason, protocol.Status, protocol.StatusReason, test.reason)
				}
				if incomplete := isIncompleteProtocolStatus(protocol.Status, protocol.StatusReason); incomplete != !test.assumeAlive {
					t.Fatalf("%s silent host incomplete = %t, want %t", name, incomplete, !test.assumeAlive)
				}
			}
		})
	}
}
