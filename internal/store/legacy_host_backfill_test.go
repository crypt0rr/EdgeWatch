package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestLegacyHostBackfillBuildsIndexedHostsOnce(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy-hosts.db")
	initial, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC().Add(-time.Hour)
	scan := model.Scan{
		ID:         "legacy-host-scan",
		Job:        "legacy-job",
		StartedAt:  when,
		FinishedAt: when,
		Status:     "success",
		Snapshot: model.Snapshot{
			Scopes: []model.Scope{{Target: "legacy.example", Protocol: "tcp", Ports: "80,443", ServiceDetection: true}},
			Units: []model.Unit{{
				Target:    "legacy.example",
				Protocol:  "tcp",
				Addresses: []string{"192.0.2.10", "2001:db8::10"},
				Ports: []model.PortState{
					{Port: 80, State: "open", Service: "http", Evidence: []string{"192.0.2.10"}},
					{Port: 443, State: "open", Service: "https", Evidence: []string{"2001:db8::10"}},
				},
			}},
		},
	}
	if err := initial.SaveScan(ctx, scan); err != nil {
		initial.Close()
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}

	// Rewind the marker to the release immediately before the backfill. This
	// models an upgraded legacy database without any scan_hosts projection.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DELETE FROM scan_hosts; DELETE FROM latest_scan_hosts; DELETE FROM legacy_scan_host_backfill; PRAGMA user_version=38`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	var sourceCount, latestCount, checkpointCount, legacyCount int
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id=?`, scan.ID).Scan(&sourceCount); err != nil {
		t.Fatal(err)
	}
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM latest_scan_hosts WHERE scan_id=?`, scan.ID).Scan(&latestCount); err != nil {
		t.Fatal(err)
	}
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM legacy_scan_host_backfill WHERE scan_id=?`, scan.ID).Scan(&checkpointCount); err != nil {
		t.Fatal(err)
	}
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id=? AND data_quality='legacy'`, scan.ID).Scan(&legacyCount); err != nil {
		t.Fatal(err)
	}
	if sourceCount != 2 || latestCount != 2 || checkpointCount != 1 || legacyCount != 2 {
		t.Fatalf("legacy host projection counts source=%d latest=%d checkpoint=%d quality=%d", sourceCount, latestCount, checkpointCount, legacyCount)
	}
	legacyExists, err := upgraded.LegacySuccessfulScanExists(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if legacyExists {
		t.Fatal("completed legacy backfill still reported unindexed history")
	}

	rows, err := upgraded.DB.QueryContext(ctx, `SELECT address,host_json FROM scan_hosts WHERE scan_id=? ORDER BY address`, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var address string
		var rawHost []byte
		if err := rows.Scan(&address, &rawHost); err != nil {
			t.Fatal(err)
		}
		var host model.HostObservation
		if err := json.Unmarshal(rawHost, &host); err != nil {
			t.Fatal(err)
		}
		if host.Address != address || len(host.SourceTargets) != 1 || host.SourceTargets[0] != "legacy.example" || len(host.DNSNames) != 1 || host.DNSNames[0] != "legacy.example" {
			t.Fatalf("legacy host %s relationships = %#v", address, host)
		}
		if len(host.Protocols) != 1 || host.Protocols[0].ScannedPortCount != 2 || len(host.Protocols[0].Ports) != 1 {
			t.Fatalf("legacy host %s protocol = %#v", address, host.Protocols)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyHostObservationsNormalizeAndMergeLegacyUnits(t *testing.T) {
	// Already-indexed host evidence still goes through the same deterministic
	// normalization path when a partially upgraded database is backfilled.
	detailed := legacyHostObservations(model.Snapshot{Hosts: []model.HostObservation{{
		Address:       " 192.0.2.20 ",
		SourceTargets: []string{"z-target", "a-target"},
	}}})
	if len(detailed) != 1 || detailed[0].Address != "192.0.2.20" || detailed[0].SourceTargets[0] != "a-target" {
		t.Fatalf("normalized detailed host = %#v", detailed)
	}

	legacy := model.Snapshot{Units: []model.Unit{
		{
			Target:    "198.51.100.10",
			Protocol:  "TCP",
			Addresses: []string{"198.51.100.10", "not-an-ip"},
			Ports: []model.PortState{
				{Port: 443, State: "open", Service: "https"},
				{Port: 8443, State: "open"},
				{Port: 9000, State: "closed"},
			},
		},
		{
			Target:    "198.51.100.10",
			Protocol:  "tcp",
			Addresses: []string{"198.51.100.10"},
			Ports:     []model.PortState{{Port: 22, State: "filtered", Service: "ssh"}},
		},
		{
			Target:    "example.test",
			Protocol:  "udp",
			Addresses: []string{"2001:db8::10"},
			Ports:     []model.PortState{{Port: 53, State: "open", Service: "domain"}},
		},
		{
			Target:    "198.51.100.0/24",
			Protocol:  "tcp",
			Addresses: []string{"198.51.100.11"},
			Ports:     []model.PortState{{Port: 80, State: "open"}},
		},
	}}
	hosts := legacyHostObservations(legacy)
	if len(hosts) != 3 {
		t.Fatalf("legacy host count = %d, want 3 (%#v)", len(hosts), hosts)
	}
	var ipv4, ipv6 *model.HostObservation
	for i := range hosts {
		switch hosts[i].Address {
		case "198.51.100.10":
			ipv4 = &hosts[i]
		case "2001:db8::10":
			ipv6 = &hosts[i]
		}
	}
	if ipv4 == nil || len(ipv4.Protocols) != 1 || ipv4.Protocols[0].Protocol != "tcp" {
		t.Fatalf("merged IPv4 protocols = %#v", ipv4)
	}
	if len(ipv4.Protocols[0].Ports) != 4 || ipv4.Protocols[0].ScannedPortCount != 3 {
		t.Fatalf("merged IPv4 coverage = %#v", ipv4.Protocols[0])
	}
	if len(ipv4.Protocols[0].StateSummaries) < 2 || ipv4.Protocols[0].Ports[0].Service == nil {
		t.Fatalf("merged IPv4 evidence = %#v", ipv4.Protocols[0])
	}
	if ipv6 == nil || ipv6.AddressFamily != "IPv6" || len(ipv6.DNSNames) != 1 || ipv6.DNSNames[0] != "example.test" {
		t.Fatalf("IPv6 DNS relationship = %#v", ipv6)
	}

	// Exercise the small compatibility helpers directly, including their empty
	// and already-present branches, which are otherwise rare in real snapshots.
	if legacyServiceObservation(" ") != nil || legacyServiceObservation("http").Method != "legacy" {
		t.Fatal("legacy service conversion did not preserve empty/non-empty semantics")
	}
	var summary model.ProtocolObservation
	legacyAddStateSummary(&summary, "open")
	legacyAddStateSummary(&summary, "open")
	if len(summary.StateSummaries) != 1 || summary.StateSummaries[0].Count != 2 {
		t.Fatalf("state summary = %#v", summary.StateSummaries)
	}
	protocols := []model.ProtocolObservation{{Protocol: "udp", ScannedPorts: "53"}}
	legacyMergeProtocol(&protocols, model.ProtocolObservation{Protocol: "udp", Ports: []model.PortObservation{{Port: 53}}})
	legacyMergeProtocol(&protocols, model.ProtocolObservation{Protocol: "tcp"})
	if len(protocols) != 2 || protocols[0].ScannedPortCount != 0 || protocols[1].Protocol != "tcp" {
		t.Fatalf("protocol merge/append = %#v", protocols)
	}
	// Empty address lists fall back to the logical target. Invalid targets are
	// then discarded rather than becoming synthetic host rows.
	if got := legacyHostObservations(model.Snapshot{Units: []model.Unit{{Target: "not-an-ip", Protocol: "tcp"}}}); len(got) != 0 {
		t.Fatalf("invalid target produced legacy hosts: %#v", got)
	}
	if got := legacyUniqueStrings([]string{" ", "host", "host", "other"}); len(got) != 2 {
		t.Fatalf("legacy string normalization = %#v", got)
	}
	if got := legacyAddressFamily("not-an-ip"); got != "" {
		t.Fatalf("invalid address family = %q", got)
	}

	mergedSummaries := []model.StateSummary{{State: "open", Count: 1, Reasons: []model.StateReason{{Reason: "syn-ack", Count: 1}}}}
	legacyMergeStateSummaries(&mergedSummaries, []model.StateSummary{
		{State: "open", Count: 2, Reasons: []model.StateReason{{Reason: "syn-ack", Count: 3}, {Reason: "reset", Count: 4}}},
		{State: "closed", Count: 5},
	})
	if len(mergedSummaries) != 2 || mergedSummaries[0].Count != 3 || len(mergedSummaries[0].Reasons) != 2 || mergedSummaries[0].Reasons[0].Count != 4 {
		t.Fatalf("merged state summaries = %#v", mergedSummaries)
	}
	if mergedSummaries[1].State != "closed" || mergedSummaries[1].Count != 5 {
		t.Fatalf("appended state summary = %#v", mergedSummaries)
	}

	deduped := model.ProtocolObservation{Ports: []model.PortObservation{
		{Port: 1, State: "closed"},
		{Port: 1, State: "open", Service: &model.ServiceObservation{Name: "http"}},
		{Port: 2, State: "open"},
	}}
	legacyDedupeProtocol(&deduped)
	if len(deduped.Ports) != 2 || deduped.Ports[0].State != "open" || deduped.Ports[0].Service == nil {
		t.Fatalf("deduped ports = %#v", deduped.Ports)
	}
}

func TestIndexLegacyScanRejectsOversizedSnapshot(t *testing.T) {
	err := indexLegacyScanTx(context.Background(), nil, legacyHostBackfillScan{snapshot: make([]byte, maxLegacyHostBackfillSnapshotBytes+1)})
	var dataErr *legacyHostBackfillDataError
	if !errors.As(err, &dataErr) || !strings.Contains(dataErr.Error(), "conversion limit") {
		t.Fatalf("oversized snapshot error = %v", err)
	}
}

func TestLegacyHostStatusMerge(t *testing.T) {
	tests := []struct {
		name, currentStatus, currentReason, additionStatus, additionReason string
		wantStatus, wantReason                                             string
	}{
		{name: "incomplete addition wins", currentStatus: "up", currentReason: "arp", additionStatus: "down", additionReason: "no-response", wantStatus: "unreachable", wantReason: "no-response"},
		{name: "incomplete current is sticky", currentStatus: "down", currentReason: "nmap-host-down", additionStatus: "up", additionReason: "arp-response", wantStatus: "unreachable", wantReason: "nmap-host-down"},
		{name: "two incomplete reasons normalize", currentStatus: "timeout", currentReason: "timeout", additionStatus: "down", additionReason: "no-response", wantStatus: "unreachable", wantReason: "no-response"},
		{name: "unknown adopts known status", currentStatus: "unknown", additionStatus: "up", additionReason: "host-response", wantStatus: "up", wantReason: "host-response"},
		{name: "known status retains deterministic reason", currentStatus: "up", currentReason: "z-reason", additionStatus: "up", additionReason: "a-reason", wantStatus: "up", wantReason: "a-reason"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, reason := legacyMergeHostStatus(test.currentStatus, test.currentReason, test.additionStatus, test.additionReason)
			if status != test.wantStatus || reason != test.wantReason {
				t.Fatalf("merged status/reason = %q/%q, want %q/%q", status, reason, test.wantStatus, test.wantReason)
			}
		})
	}
	if legacyIncompleteHostStatus(" ") || !legacyIncompleteHostStatus("timed-out") {
		t.Fatal("incomplete host status classification is incorrect")
	}
	if got := legacyChooseStatusReason("same", "same"); got != "same" {
		t.Fatalf("identical status reason = %q", got)
	}
	if got := legacyChooseStatusReason("present", ""); got != "present" {
		t.Fatalf("empty incoming status reason = %q", got)
	}
}

func TestLegacyHostBackfillNilLogger(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "nil-logger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := backfillLegacyScanHostsContextWithLogger(context.Background(), store.DB, nil); err != nil {
		t.Fatalf("backfill with default logger failed: %v", err)
	}
}

func TestLegacyHostBackfillStorageFailureIsFatal(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "storage-error.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	when := time.Now().UTC().Add(-time.Hour)
	scan := model.Scan{ID: "legacy-storage-error", Job: "legacy-job", StartedAt: when, FinishedAt: when, Status: "success"}
	if err := store.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	snapshot, err := json.Marshal(model.Snapshot{Hosts: []model.HostObservation{{Address: "192.0.2.10", Status: "up"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.ExecContext(ctx, `UPDATE scans SET snapshot_json=? WHERE id=?`, snapshot, scan.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.ExecContext(ctx, `DELETE FROM scan_hosts; DELETE FROM latest_scan_hosts; DELETE FROM legacy_scan_host_backfill`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.ExecContext(ctx, `CREATE TRIGGER fail_legacy_host_projection BEFORE INSERT ON scan_hosts BEGIN SELECT RAISE(ABORT, 'injected projection failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := backfillLegacyScanHostsContext(ctx, store.DB); err == nil {
		t.Fatal("projection storage failure was treated as malformed legacy data")
	}
	var checkpoints int
	if err := store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM legacy_scan_host_backfill WHERE scan_id=?`, scan.ID).Scan(&checkpoints); err != nil {
		t.Fatal(err)
	}
	if checkpoints != 0 {
		t.Fatalf("failed scan has %d backfill checkpoints, want none", checkpoints)
	}
}

func TestLegacyHostBackfillFailureBoundaries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(t.TempDir(), "canceled.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := backfillLegacyScanHostsContext(ctx, s.DB); err == nil {
		t.Fatal("canceled legacy backfill unexpectedly succeeded")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	closed, err := Open(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := backfillLegacyScanHostsContext(context.Background(), closed.DB); err == nil {
		t.Fatal("backfill on closed database unexpectedly succeeded")
	}

	broken, err := Open(filepath.Join(t.TempDir(), "broken.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer broken.Close()
	if _, err := broken.DB.ExecContext(context.Background(), `DROP TABLE legacy_scan_host_backfill`); err != nil {
		t.Fatal(err)
	}
	if err := backfillLegacyScanHostsContext(context.Background(), broken.DB); err == nil {
		t.Fatal("backfill with missing checkpoint table unexpectedly succeeded")
	}
}

func TestLegacyHostBackfillDeduplicatesCanonicalAddresses(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy-duplicate-hosts.db")
	initial, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC().Add(-time.Hour)
	scan := model.Scan{ID: "legacy-duplicate-host-scan", Job: "legacy-job", StartedAt: when, FinishedAt: when, Status: "success"}
	if err := initial.SaveScan(ctx, scan); err != nil {
		initial.Close()
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot := model.Snapshot{Hosts: []model.HostObservation{
		{
			Address:       "2001:0db8:0:0:0:0:0:1",
			SourceTargets: []string{"one.example"},
			DNSNames:      []string{"one.example"},
			Protocols: []model.ProtocolObservation{{
				Protocol: "TCP",
				Ports:    []model.PortObservation{{Port: 443, State: "open", Service: &model.ServiceObservation{Name: "https"}}},
			}},
		},
		{
			Address:       "2001:db8::1",
			SourceTargets: []string{"two.example"},
			DNSNames:      []string{"two.example"},
			Protocols: []model.ProtocolObservation{{
				Protocol: "udp",
				Ports:    []model.PortObservation{{Port: 53, State: "open", Service: &model.ServiceObservation{Name: "domain"}}},
			}},
		},
	}}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE scans SET snapshot_json=? WHERE id=?`, snapshotJSON, scan.ID); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DELETE FROM scan_hosts; DELETE FROM latest_scan_hosts; DELETE FROM legacy_scan_host_backfill; PRAGMA user_version=38`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	var count int
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id=?`, scan.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("canonical IPv6 host row count = %d, want 1", count)
	}
	var address string
	var hostJSON []byte
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT address,host_json FROM scan_hosts WHERE scan_id=?`, scan.ID).Scan(&address, &hostJSON); err != nil {
		t.Fatal(err)
	}
	var host model.HostObservation
	if err := json.Unmarshal(hostJSON, &host); err != nil {
		t.Fatal(err)
	}
	if address != "2001:db8::1" || host.Address != address || len(host.Protocols) != 2 {
		t.Fatalf("canonical merged host = address %q, %#v", address, host)
	}
	if len(host.SourceTargets) != 2 || len(host.DNSNames) != 2 {
		t.Fatalf("merged target relationships = targets %#v DNS %#v", host.SourceTargets, host.DNSNames)
	}
	portsByProtocol := map[string]int{}
	for _, protocol := range host.Protocols {
		portsByProtocol[protocol.Protocol] = len(protocol.Ports)
	}
	if portsByProtocol["tcp"] != 1 || portsByProtocol["udp"] != 1 {
		t.Fatalf("merged protocol evidence = %#v", host.Protocols)
	}
}

func TestLegacyHostBackfillSkipsMalformedScanAndContinues(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy-malformed-hosts.db")
	initial, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	bad := model.Scan{ID: "bad-legacy-scan", Job: "legacy-job", StartedAt: base, FinishedAt: base, Status: "success"}
	good := model.Scan{ID: "good-legacy-scan", Job: "legacy-job", StartedAt: base.Add(time.Minute), FinishedAt: base.Add(time.Minute), Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "192.0.2.42", Status: "up"}}}}
	for _, scan := range []model.Scan{bad, good} {
		if err := initial.SaveScan(ctx, scan); err != nil {
			initial.Close()
			t.Fatal(err)
		}
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE scans SET snapshot_json='{' WHERE id=?`, bad.ID); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DELETE FROM scan_hosts; DELETE FROM latest_scan_hosts; DELETE FROM legacy_scan_host_backfill; PRAGMA user_version=38`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	upgraded, err := OpenWithLogger(path, logger)
	if err != nil {
		t.Fatalf("migration failed with one malformed legacy scan: %v", err)
	}
	defer upgraded.Close()
	var badHosts, goodHosts, badCheckpoints int
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id=?`, bad.ID).Scan(&badHosts); err != nil {
		t.Fatal(err)
	}
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id=?`, good.ID).Scan(&goodHosts); err != nil {
		t.Fatal(err)
	}
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM legacy_scan_host_backfill WHERE scan_id=?`, bad.ID).Scan(&badCheckpoints); err != nil {
		t.Fatal(err)
	}
	if badHosts != 0 || goodHosts != 1 || badCheckpoints != 1 {
		t.Fatalf("backfill results malformed hosts=%d valid hosts=%d malformed checkpoints=%d", badHosts, goodHosts, badCheckpoints)
	}
	legacyExists, err := upgraded.LegacySuccessfulScanExists(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if legacyExists {
		t.Fatal("skipped malformed scan prevented legacy backfill from completing")
	}
	if output := logs.String(); !strings.Contains(output, "legacy scan host indexing skipped") || !strings.Contains(output, "scan_id="+bad.ID) || !strings.Contains(output, "snapshot JSON is malformed") {
		t.Fatalf("malformed scan was not logged with bounded context: %q", output)
	}
}
