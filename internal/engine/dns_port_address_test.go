package engine

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

const (
	dualStackTarget = "edge.example"
	dualStackV4     = "192.0.2.10"
	dualStackV6     = "2001:db8::10"
)

func portAddressChangeKey(port int, address string) string {
	return fmt.Sprintf("port-address|%s|tcp|%d|%s", dualStackTarget, port, address)
}

// dualStackSnapshot is the complete result the scanner records for a DNS
// target whose IPv4 and IPv6 addresses are both up: one logical unit whose
// ports name the addresses exposing them, and per-address host evidence.
func dualStackSnapshot(exposure map[int][]string) model.Snapshot {
	addresses := []string{dualStackV4, dualStackV6}
	unit := model.Unit{Target: dualStackTarget, Protocol: "tcp", Addresses: addresses}
	observed := map[string][]model.PortObservation{}
	for port, on := range exposure {
		unit.Ports = append(unit.Ports, model.PortState{Port: port, State: "open", Evidence: append([]string(nil), on...)})
		for _, address := range on {
			observed[address] = append(observed[address], model.PortObservation{Port: port, State: "open", Verification: "confirmed"})
		}
	}
	snapshot := model.Snapshot{
		Scopes: []model.Scope{{Target: dualStackTarget, Protocol: "tcp", Ports: "22,443"}},
		DNS:    map[string][]string{dualStackTarget: addresses},
		Units:  []model.Unit{unit},
	}
	for _, address := range addresses {
		snapshot.Hosts = append(snapshot.Hosts, model.HostObservation{
			Address: address, SourceTargets: []string{dualStackTarget}, DNSNames: []string{dualStackTarget}, Status: "up",
			Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up", ScannedPorts: "22,443", ScannedPortCount: 2, Ports: observed[address]}},
		})
	}
	snapshot.Normalize()
	return snapshot
}

func dualStackState(baseline model.Snapshot, job config.Job) model.JobState {
	baseline = cloneSnapshot(baseline)
	completeHostDiscoveryStates(&baseline)
	return model.JobState{
		Baseline: &baseline, BaselineScanID: "baseline", BaselineConfigHash: job.SecurityHash(),
		Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{},
		Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{},
		FingerprintCandidates: map[string]model.ValueCount{},
	}
}

func dualStackJob(mode string) config.Job {
	return config.NormalizeJob(config.Job{
		Name: "dual-stack", Targets: []string{dualStackTarget}, DNSComparisonMode: mode, MaxExpandedHosts: 4,
		TCP:      &config.Protocol{Ports: "22,443", Mode: "connect"},
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	})
}

func dualStackScan(id string, job config.Job, snapshot model.Snapshot) model.Scan {
	return model.Scan{ID: id, Job: job.Name, Status: "success", ConfigHash: job.SecurityHash(), Snapshot: snapshot, FinishedAt: time.Now().UTC()}
}

func changeKeys(changes []model.Change) []string {
	keys := make([]string, 0, len(changes))
	for _, change := range changes {
		keys = append(keys, change.Key)
	}
	return keys
}

func TestDiffReportsPortChangesOnOneAddressOfDNSTarget(t *testing.T) {
	baseline := dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4, dualStackV6}})
	current := dualStackSnapshot(map[int][]string{22: {dualStackV4, dualStackV6}, 443: {dualStackV6}})
	changes := diffForJob(baseline, current, false, dualStackJob(config.DNSComparisonAddressSensitive))
	want := []model.Change{
		{Key: portAddressChangeKey(22, dualStackV6), Kind: "port-address", Severity: "critical", Target: dualStackTarget, Protocol: "tcp", Port: 22, Address: dualStackV6, Old: "not-open", New: "open"},
		{Key: portAddressChangeKey(443, dualStackV4), Kind: "port-address", Severity: "info", Target: dualStackTarget, Protocol: "tcp", Port: 443, Address: dualStackV4, Old: "open", New: "not-open"},
	}
	if !slices.Equal(changes, want) {
		t.Fatalf("per-address changes = %#v, want %#v", changes, want)
	}
	if !slices.Equal(Diff(baseline, current, false), want) {
		t.Fatalf("default Diff = %#v, want %#v", Diff(baseline, current, false), want)
	}
	if got := model.ChangeSummary(want[0]); got != "edge.example tcp/22 on 2001:db8::10: not-open -> open" {
		t.Fatalf("summary = %q", got)
	}
	if got := model.ChangeSummary(want[1]); got != "edge.example tcp/443 on 192.0.2.10: open -> not-open" {
		t.Fatalf("summary = %q", got)
	}

	// An unchanged per-address surface, IP literal targets, and an aggregate
	// job report nothing.
	if changes := Diff(baseline, baseline, false); len(changes) != 0 {
		t.Fatalf("unchanged snapshot changes = %#v", changes)
	}
	if changes := diffForJob(baseline, current, false, dualStackJob(config.DNSComparisonAggregate)); len(changes) != 0 {
		t.Fatalf("aggregate mode reported per-address changes: %#v", changes)
	}
}

func TestPortAddressChangeOpensAndRecoversIncident(t *testing.T) {
	job := dualStackJob(config.DNSComparisonAddressSensitive)
	baseline := dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4, dualStackV6}})
	state := dualStackState(baseline, job)
	opened := dualStackSnapshot(map[int][]string{22: {dualStackV4, dualStackV6}, 443: {dualStackV4, dualStackV6}})
	events, changes, err := processSuccessWithChanges(&state, job, dualStackScan("opened", job, opened))
	key := portAddressChangeKey(22, dualStackV6)
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" || !slices.Equal(changeKeys(changes), []string{key}) {
		t.Fatalf("opened on IPv6: events %#v changes %#v err %v", events, changes, err)
	}
	if !strings.Contains(FormatEvent(events[0]), "🔴 EdgeWatch: 1 baseline change confirmed") || !strings.Contains(FormatEvent(events[0]), "- [critical] edge.example tcp/22 on 2001:db8::10: not-open -> open") {
		t.Fatalf("notification = %q", FormatEvent(events[0]))
	}
	if _, ok := state.Incidents[key]; !ok {
		t.Fatalf("incidents = %#v", state.Incidents)
	}
	if got := state.Baseline.Units[0].Ports[0].Evidence; !slices.Equal(got, []string{dualStackV4}) {
		t.Fatalf("an incident changed the baseline evidence: %#v", got)
	}

	events, changes, err = processSuccessWithChanges(&state, job, dualStackScan("closed-again", job, baseline))
	if err != nil || len(changes) != 0 || len(events) != 1 || events[0].Type != "changes-recovered" || events[0].Changes[0].Key != key || events[0].Changes[0].New != "not-open" {
		t.Fatalf("closed again on IPv6: events %#v changes %#v err %v", events, changes, err)
	}
	if len(state.Incidents) != 0 {
		t.Fatalf("incidents after recovery = %#v", state.Incidents)
	}
}

func TestPortAddressFindingIsRetiredWhenItCannotBeCompared(t *testing.T) {
	job := dualStackJob(config.DNSComparisonAddressSensitive)
	baseline := dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4, dualStackV6}})
	closedOn := portAddressChangeKey(443, dualStackV6)
	openedOn := portAddressChangeKey(22, dualStackV6)
	seed := func() model.JobState {
		state := dualStackState(baseline, job)
		state.Incidents[closedOn] = model.Incident{Change: model.Change{Key: closedOn, Kind: "port-address", Severity: "info", Target: dualStackTarget, Protocol: "tcp", Port: 443, Address: dualStackV6, Old: "open", New: "not-open"}}
		state.Incidents[openedOn] = model.Incident{Change: model.Change{Key: openedOn, Kind: "port-address", Severity: "critical", Target: dualStackTarget, Protocol: "tcp", Port: 22, Address: dualStackV6, Old: "not-open", New: "open"}}
		return state
	}

	// When the logical port closes, the port change is the transition; the
	// closure on one address must not be announced as a recovery to open.
	state := seed()
	gone := dualStackSnapshot(map[int][]string{22: {dualStackV4, dualStackV6}})
	events, changes, err := processSuccessWithChanges(&state, job, dualStackScan("port-gone", job, gone))
	if err != nil || !slices.Equal(changeKeys(changes), []string{openedOn, "port|edge.example|tcp|443"}) {
		t.Fatalf("logical closure: changes %#v err %v", changes, err)
	}
	for _, event := range events {
		if event.Type == "changes-recovered" {
			t.Fatalf("retired finding was reported as a recovery: %#v", event)
		}
	}
	if _, ok := state.Incidents[closedOn]; ok {
		t.Fatalf("per-address finding of a closed port stayed open: %#v", state.Incidents)
	}

	// An address whose host discovery completed down reports its host state
	// only.
	state = seed()
	down := dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4}})
	down.Hosts[1] = model.HostObservation{Address: dualStackV6, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}}
	events, changes, err = processSuccessWithChanges(&state, job, dualStackScan("ipv6-down", job, down))
	if err != nil || !slices.Equal(changeKeys(changes), []string{"host|" + dualStackV6}) {
		t.Fatalf("down address: events %#v changes %#v err %v", events, changes, err)
	}
	if len(events) != 1 || events[0].Type != "changes-detected" || len(state.Incidents) != 1 {
		t.Fatalf("down address events %#v incidents %#v", events, state.Incidents)
	}

	// An address that left the DNS answer is reported as dns-removed only.
	state = seed()
	moved := dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4}})
	moved.DNS[dualStackTarget] = []string{dualStackV4}
	moved.Units[0].Addresses = []string{dualStackV4}
	moved.Hosts = moved.Hosts[:1]
	events, changes, err = processSuccessWithChanges(&state, job, dualStackScan("ipv6-left-answer", job, moved))
	if err != nil || !slices.Equal(changeKeys(changes), []string{"dns|edge.example|" + dualStackV6}) || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("address left the answer: events %#v changes %#v err %v", events, changes, err)
	}
	if _, ok := state.Incidents[closedOn]; ok {
		t.Fatalf("finding of an address outside the answer stayed open: %#v", state.Incidents)
	}
}

func TestAggregateDNSComparisonIgnoresPortAddresses(t *testing.T) {
	job := dualStackJob(config.DNSComparisonAggregate)
	baseline := dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4, dualStackV6}})
	current := dualStackSnapshot(map[int][]string{22: {dualStackV4, dualStackV6}, 443: {dualStackV6}})
	state := dualStackState(baseline, job)
	stale := portAddressChangeKey(22, dualStackV6)
	state.Pending[stale] = model.Pending{Change: model.Change{Key: stale, Kind: "port-address", Target: dualStackTarget, Protocol: "tcp", Port: 22, Address: dualStackV6, Old: "not-open", New: "open"}, Count: 1}
	events, changes, err := processSuccessWithChanges(&state, job, dualStackScan("aggregate", job, current))
	if err != nil || len(events) != 0 || len(changes) != 0 || len(state.Pending) != 0 {
		t.Fatalf("aggregate mode: events %#v changes %#v pending %#v err %v", events, changes, state.Pending, err)
	}
	if got := state.Baseline.Units[0].Ports[0].Evidence; !slices.Equal(got, []string{dualStackV4}) {
		t.Fatalf("aggregate mode changed the baseline evidence: %#v", got)
	}
	if snapshotHashForDNSMode(baseline, config.DNSComparisonAggregate) != snapshotHashForDNSMode(current, config.DNSComparisonAggregate) {
		t.Fatal("aggregate convergence identity depends on port evidence")
	}
}

func TestPortWithoutAddressEvidenceIsLearnedWithoutAChange(t *testing.T) {
	job := dualStackJob(config.DNSComparisonAddressSensitive)
	legacy := dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4, dualStackV6}})
	for index := range legacy.Units[0].Ports {
		legacy.Units[0].Ports[index].Evidence = nil
	}
	current := dualStackSnapshot(map[int][]string{22: {dualStackV4, dualStackV6}, 443: {dualStackV6}})
	if changes := Diff(legacy, current, false); len(changes) != 0 {
		t.Fatalf("baseline without evidence reported changes: %#v", changes)
	}
	withoutEvidence := current
	withoutEvidence.Units = []model.Unit{{Target: dualStackTarget, Protocol: "tcp", Addresses: current.Units[0].Addresses, Ports: []model.PortState{{Port: 22, State: "open"}, {Port: 443, State: "open"}}}}
	if changes := Diff(dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4, dualStackV6}}), withoutEvidence, false); len(changes) != 0 {
		t.Fatalf("snapshot without evidence reported changes: %#v", changes)
	}

	state := dualStackState(legacy, job)
	events, changes, err := processSuccessWithChanges(&state, job, dualStackScan("learn", job, current))
	if err != nil || len(events) != 0 || len(changes) != 0 {
		t.Fatalf("first scan against a baseline without evidence: events %#v changes %#v err %v", events, changes, err)
	}
	if got := state.Baseline.Units[0].Ports; !slices.Equal(got[0].Evidence, []string{dualStackV4, dualStackV6}) || !slices.Equal(got[1].Evidence, []string{dualStackV6}) {
		t.Fatalf("learned evidence = %#v", got)
	}
	// The learned addresses are compared from now on.
	_, changes, err = processSuccessWithChanges(&state, job, dualStackScan("compare", job, dualStackSnapshot(map[int][]string{22: {dualStackV4, dualStackV6}, 443: {dualStackV4, dualStackV6}})))
	if err != nil || !slices.Equal(changeKeys(changes), []string{portAddressChangeKey(443, dualStackV4)}) {
		t.Fatalf("changes after learning = %#v, %v", changes, err)
	}

	// A down address leaves the evidence unknown until a later scan.
	state = dualStackState(legacy, job)
	down := dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4}})
	down.Hosts[1] = model.HostObservation{Address: dualStackV6, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}}
	if _, _, err := processSuccessWithChanges(&state, job, dualStackScan("down", job, down)); err != nil {
		t.Fatal(err)
	}
	for _, port := range state.Baseline.Units[0].Ports {
		if len(port.Evidence) != 0 {
			t.Fatalf("evidence learned while an address was down: %#v", state.Baseline.Units[0].Ports)
		}
	}
}

func TestIncompleteDNSScanReportsPortAddressAdditionsAndDefersRemovals(t *testing.T) {
	job := dualStackJob(config.DNSComparisonAddressSensitive)
	baseline := dualStackSnapshot(map[int][]string{22: {dualStackV6}, 443: {dualStackV4, dualStackV6}})
	state := dualStackState(baseline, job)
	deferred := portAddressChangeKey(443, dualStackV6)
	state.Incidents[deferred] = model.Incident{Change: model.Change{Key: deferred, Kind: "port-address", Severity: "info", Target: dualStackTarget, Protocol: "tcp", Port: 443, Address: dualStackV6, Old: "open", New: "not-open"}}
	partial := dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4}})
	partial.Hosts[1] = model.HostObservation{Address: dualStackV6, Status: "down", StatusReason: "no-response"}
	events, changes, err := processSuccessWithChanges(&state, job, dualStackScan("partial", job, partial))
	added := portAddressChangeKey(22, dualStackV4)
	if err != nil || !slices.Equal(changeKeys(changes), []string{added}) {
		t.Fatalf("incomplete scan changes = %#v, %v", changes, err)
	}
	if len(events) != 2 || events[0].Type != "changes-detected" || events[1].Type != "scan-incomplete" {
		t.Fatalf("incomplete scan events = %#v", events)
	}
	if _, ok := state.Incidents[added]; !ok {
		t.Fatalf("addition on a complete address did not open an incident: %#v", state.Incidents)
	}
	if _, ok := state.Incidents[deferred]; !ok || len(state.Incidents) != 2 {
		t.Fatalf("incomplete coverage changed a protected finding: %#v", state.Incidents)
	}
	if _, reported := state.Incidents[portAddressChangeKey(22, dualStackV6)]; reported {
		t.Fatal("closure on an incomplete address was reported")
	}
}

// A scan that is incomplete only for another target compares edge.example
// fully, but it must not take a missing per-address comparison as a recovery
// or retire the finding; the next complete scan does that.
func TestIncompleteScanKeepsUncomparedPortAddressFinding(t *testing.T) {
	job := dualStackJob(config.DNSComparisonAddressSensitive)
	const other = "198.51.100.7"
	withOther := func(snapshot model.Snapshot, reachable bool) model.Snapshot {
		snapshot.Scopes = append(snapshot.Scopes, model.Scope{Target: other, Protocol: "tcp", Ports: "22,443"})
		host := model.HostObservation{Address: other, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}}
		if !reachable {
			host = model.HostObservation{Address: other, Status: "down", StatusReason: "no-response"}
		}
		snapshot.Hosts = append(snapshot.Hosts, host)
		snapshot.Normalize()
		return snapshot
	}
	state := dualStackState(withOther(dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4, dualStackV6}}), true), job)
	key := portAddressChangeKey(443, dualStackV6)
	state.Incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "port-address", Severity: "info", Target: dualStackTarget, Protocol: "tcp", Port: 443, Address: dualStackV6, Old: "open", New: "not-open"}}

	gone := dualStackSnapshot(map[int][]string{22: {dualStackV4}})
	_, changes, err := processSuccessWithChanges(&state, job, dualStackScan("other-incomplete", job, withOther(gone, false)))
	if err != nil || !slices.Equal(changeKeys(changes), []string{"port|edge.example|tcp|443"}) {
		t.Fatalf("incomplete scan changes = %#v, %v", changes, err)
	}
	if incident, ok := state.Incidents[key]; !ok || incident.RecoveryCount != 0 {
		t.Fatalf("incomplete scan advanced an uncompared finding: %#v", state.Incidents)
	}
	if _, _, err := processSuccessWithChanges(&state, job, dualStackScan("complete", job, withOther(gone, true))); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Incidents[key]; ok {
		t.Fatalf("complete scan kept an uncompared finding: %#v", state.Incidents)
	}
}

func TestAddressSensitiveBaselineConvergesOnStablePortAddresses(t *testing.T) {
	first := dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4, dualStackV6}})
	moved := dualStackSnapshot(map[int][]string{22: {dualStackV6}, 443: {dualStackV4, dualStackV6}})

	state := model.JobState{FingerprintCandidates: map[string]model.ValueCount{}}
	advanceCandidateWithDNSMode(&state, scan("first", first), 2, false, config.DNSComparisonAddressSensitive)
	advanceCandidateWithDNSMode(&state, scan("moved", moved), 2, false, config.DNSComparisonAddressSensitive)
	if state.Baseline != nil || state.CandidateCount != 1 {
		t.Fatalf("samples with different port addresses converged: candidate %d baseline %#v", state.CandidateCount, state.Baseline)
	}
	events := advanceCandidateWithDNSMode(&state, scan("repeat", moved), 2, false, config.DNSComparisonAddressSensitive)
	if len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("identical samples did not converge: %#v", events)
	}
	if got := state.Baseline.Units[0].Ports[0].Evidence; !slices.Equal(got, []string{dualStackV6}) {
		t.Fatalf("converged baseline evidence = %#v", got)
	}

	aggregate := model.JobState{FingerprintCandidates: map[string]model.ValueCount{}}
	advanceCandidateWithDNSMode(&aggregate, scan("first", first), 2, false, config.DNSComparisonAggregate)
	if events := advanceCandidateWithDNSMode(&aggregate, scan("moved", moved), 2, false, config.DNSComparisonAggregate); len(events) != 1 {
		t.Fatalf("aggregate samples did not converge across port addresses: %#v", events)
	}
}

func TestAcceptAndSuppressPortAddressIncidents(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	job := dualStackJob(config.DNSComparisonAddressSensitive)
	job.Schedule, job.Timezone = "0 * * * *", "UTC"
	record, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Store: db}
	finalize := func(id string, snapshot model.Snapshot) ([]model.Event, model.Scan) {
		t.Helper()
		result := model.Scan{ID: id, JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: snapshot, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC()}
		events, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &result, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Reminders of the incidents that stay open are not under test here.
		return slices.DeleteFunc(events, func(event model.Event) bool { return event.Type == "changes-reminder" }), result
	}
	if events, _ := finalize("baseline", dualStackSnapshot(map[int][]string{22: {dualStackV4}, 443: {dualStackV4, dualStackV6}})); len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline events = %#v", events)
	}
	drifted := dualStackSnapshot(map[int][]string{22: {dualStackV4, dualStackV6}, 443: {dualStackV6}})
	if events, result := finalize("drifted", drifted); len(events) != 1 || len(result.Changes) != 2 {
		t.Fatalf("drifted scan events %#v changes %#v", events, result.Changes)
	}
	opened, closed := portAddressChangeKey(22, dualStackV6), portAddressChangeKey(443, dualStackV4)
	audit := func(key string) store.AuditEntry {
		return store.AuditEntry{Action: "incident.accepted", Detail: record.ID + ":" + key}
	}

	// A suppressed per-address incident stays hidden for one scan and is
	// reported again while the address still differs.
	if _, err := defaultTenant(db).SuppressIncidentWithAudit(ctx, record.ID, record.Job.Name, closed, store.AuditEntry{Action: "incident.suppressed", Detail: closed}); err != nil {
		t.Fatal(err)
	}
	if events, _ := finalize("suppressed", drifted); len(events) != 0 {
		t.Fatalf("suppressed scan events = %#v", events)
	}
	if events, _ := finalize("reopened", drifted); len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != closed {
		t.Fatalf("reopened events = %#v", events)
	}

	for _, key := range []string{opened, closed} {
		events, err := defaultTenant(db).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, key, audit(key))
		if err != nil || len(events) != 1 || events[0].Type != "incident-accepted" || events[0].Changes[0].Key != key {
			t.Fatalf("accept %s = %#v, %v", key, events, err)
		}
	}
	state, err := defaultTenant(db).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 0 {
		t.Fatalf("incidents after acceptance = %#v", state.Incidents)
	}
	ports := state.Baseline.Units[0].Ports
	if !slices.Equal(ports[0].Evidence, []string{dualStackV4, dualStackV6}) || !slices.Equal(ports[1].Evidence, []string{dualStackV6}) {
		t.Fatalf("accepted baseline evidence = %#v", ports)
	}
	if events, result := finalize("identical", drifted); len(events) != 0 || len(result.Changes) != 0 {
		t.Fatalf("identical scan after acceptance: events %#v changes %#v", events, result.Changes)
	}
}

// fakeDualStackNmap answers for the invocation's address family, reporting
// the open TCP ports listed in a per-family file next to the script and, when
// a per-family product file exists, a probed service on each of them.
const fakeDualStackNmap = `#!/bin/sh
family=ipv4
for arg in "$@"; do
  case "$arg" in
    --version|-V) echo "Nmap version 7.95"; exit 0 ;;
    -6) family=ipv6 ;;
  esac
done
address='192.0.2.10'; files="${0%/*}/v4"
if [ "$family" = ipv6 ]; then
  address='2001:db8::10'; files="${0%/*}/v6"
fi
ports=''; product=''
read -r ports < "${files}ports"
if [ -f "${files}product" ]; then
  read -r product < "${files}product"
fi
printf '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="%s" addrtype="%s"/><ports>' "$address" "$family"
for port in $ports; do
  if [ -n "$product" ]; then
    printf '<port protocol="tcp" portid="%s"><state state="open"/><service name="https" product="%s" version="1" method="probed"/></port>' "$port" "$product"
  else
    printf '<port protocol="tcp" portid="%s"><state state="open"/></port>' "$port"
  fi
done
printf '</ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
`

type fakeDualStackResolver struct{}

func (fakeDualStackResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP(dualStackV6), net.ParseIP(dualStackV4)}, nil
}

// fakeDualStackScanner scans edge.example with fakeDualStackNmap. The
// returned function sets the open ports, and optionally the service product,
// that later scans observe on the v4 or v6 address.
func fakeDualStackScanner(t *testing.T) (*scanner.Nmap, func(family, ports, product string)) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "nmap")
	if err := os.WriteFile(path, []byte(fakeDualStackNmap), 0o700); err != nil {
		t.Fatal(err)
	}
	n := scanner.New(path)
	n.Resolver = fakeDualStackResolver{}
	return n, func(family, ports, product string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, family+"ports"), []byte(ports+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if product != "" {
			if err := os.WriteFile(filepath.Join(dir, family+"product"), []byte(product+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// The scanner merges a DNS target's ports across its addresses on both the
// direct and the resumable path. Each must still report a port that opens or
// closes on one address while another address exposes it.
func TestScannedDNSTargetReportsPortChangesOnOneAddress(t *testing.T) {
	ctx := context.Background()
	n, observe := fakeDualStackScanner(t)
	expose := func(v4, v6 string) {
		t.Helper()
		observe("v4", v4, "")
		observe("v6", v6, "")
	}
	job := dualStackJob("")
	scanners := map[string]func() model.Snapshot{
		"direct": func() model.Snapshot {
			t.Helper()
			snapshot, err := n.Scan(ctx, job)
			if err != nil {
				t.Fatal(err)
			}
			return snapshot
		},
		"resumable": func() model.Snapshot {
			t.Helper()
			plan, err := n.Plan(ctx, job)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Units) != 2 {
				t.Fatalf("plan units = %#v, want one unit per address family", plan.Units)
			}
			fragments := make([]model.Snapshot, 0, len(plan.Units))
			for _, unit := range plan.Units {
				fragment, err := n.ScanWorkUnit(ctx, job, unit, nil)
				if err != nil {
					t.Fatal(err)
				}
				fragments = append(fragments, fragment)
			}
			return scanner.MergeWorkSnapshots(plan, fragments)
		},
	}
	observed := map[string][]string{}
	for _, name := range []string{"direct", "resumable"} {
		t.Run(name, func(t *testing.T) {
			run := scanners[name]
			state := model.JobState{Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{}, FingerprintCandidates: map[string]model.ValueCount{}}
			expose("22 443", "443")
			if events, _, err := processSuccessWithChanges(&state, job, dualStackScan("baseline", job, run())); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
				t.Fatalf("baseline: %#v, %v", events, err)
			}

			expose("22 443", "22 443")
			events, changes, err := processSuccessWithChanges(&state, job, dualStackScan("ipv6-opens-22", job, run()))
			if err != nil || len(events) != 1 || events[0].Type != "changes-detected" || !slices.Equal(changeKeys(changes), []string{portAddressChangeKey(22, dualStackV6)}) {
				t.Fatalf("22 opens on IPv6: events %#v changes %#v err %v", events, changes, err)
			}
			if change := changes[0]; change.Address != dualStackV6 || change.Old != "not-open" || change.New != "open" || change.Severity != "critical" {
				t.Fatalf("22 opens on IPv6 change = %#v", change)
			}

			expose("22", "22 443")
			events, changes, err = processSuccessWithChanges(&state, job, dualStackScan("ipv4-closes-443", job, run()))
			closed := portAddressChangeKey(443, dualStackV4)
			if err != nil || len(events) != 1 || len(events[0].Changes) != 1 || events[0].Changes[0].Key != closed {
				t.Fatalf("443 closes on IPv4: events %#v err %v", events, err)
			}
			if !slices.Equal(changeKeys(changes), []string{portAddressChangeKey(22, dualStackV6), closed}) || len(state.Incidents) != 2 {
				t.Fatalf("443 closes on IPv4: changes %#v incidents %#v", changes, state.Incidents)
			}
			observed[name] = changeKeys(changes)
		})
	}
	if !slices.Equal(observed["direct"], observed["resumable"]) {
		t.Fatalf("direct changes %v differ from resumable changes %v", observed["direct"], observed["resumable"])
	}
}

// Accepting a per-address change must leave the baseline matching what the
// scanner reports next, including the service fingerprint it merges across
// the target's addresses.
func TestAcceptedPortAddressChangesMatchTheNextScan(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	n, observe := fakeDualStackScanner(t)
	job := dualStackJob("")
	job.Schedule, job.Timezone = "0 * * * *", "UTC"
	job.TCP.ServiceDetection = true
	job = config.NormalizeJob(job)
	record, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Store: db}
	scans := 0
	finalize := func() ([]model.Event, []model.Change) {
		t.Helper()
		snapshot, err := n.Scan(ctx, record.Job)
		if err != nil {
			t.Fatal(err)
		}
		scans++
		result := model.Scan{ID: fmt.Sprintf("scan-%d", scans), JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: snapshot, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC()}
		events, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &result, nil)
		if err != nil {
			t.Fatal(err)
		}
		return slices.DeleteFunc(events, func(event model.Event) bool { return event.Type == "changes-reminder" }), result.Changes
	}
	accept := func(key string) []model.Change {
		t.Helper()
		events, err := defaultTenant(db).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, key, store.AuditEntry{Action: "incident.accepted", Detail: key})
		if err != nil || len(events) != 1 {
			t.Fatalf("accept %s = %#v, %v", key, events, err)
		}
		return events[0].Changes
	}

	observe("v4", "22 443", "nginx")
	observe("v6", "443", "Caddy")
	if events, _ := finalize(); len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline events = %#v", events)
	}

	// 443 closes on IPv6. Its merged fingerprint loses Caddy, so the scan
	// also reports a service change, which accepting the closure resolves.
	observe("v6", "", "")
	_, changes := finalize()
	closed, service443 := portAddressChangeKey(443, dualStackV6), "service|edge.example|tcp|443"
	if !slices.Equal(changeKeys(changes), []string{closed, service443}) {
		t.Fatalf("443 closes on IPv6: changes %#v", changes)
	}
	if accepted := accept(closed); !slices.Equal(changeKeys(accepted), []string{closed, service443}) {
		t.Fatalf("accepting the closure = %#v", accepted)
	}
	if events, changes := finalize(); len(events) != 0 || len(changes) != 0 {
		t.Fatalf("identical scan after accepting the closure: events %#v changes %#v", events, changes)
	}

	// 22 opens on IPv6 with another fingerprint. The new exposure and the
	// changed fingerprint are separate decisions.
	observe("v6", "22", "")
	_, changes = finalize()
	opened, service22 := portAddressChangeKey(22, dualStackV6), "service|edge.example|tcp|22"
	if !slices.Equal(changeKeys(changes), []string{opened, service22}) {
		t.Fatalf("22 opens on IPv6: changes %#v", changes)
	}
	if accepted := accept(opened); !slices.Equal(changeKeys(accepted), []string{opened}) {
		t.Fatalf("accepting the opening = %#v", accepted)
	}
	if events, changes := finalize(); len(events) != 0 || !slices.Equal(changeKeys(changes), []string{service22}) {
		t.Fatalf("identical scan after accepting the opening: events %#v changes %#v", events, changes)
	}
	accept(service22)
	if events, changes := finalize(); len(events) != 0 || len(changes) != 0 {
		t.Fatalf("identical scan after accepting the service: events %#v changes %#v", events, changes)
	}
	state, err := defaultTenant(db).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ports := state.Baseline.Units[0].Ports; !slices.Equal(ports[0].Evidence, []string{dualStackV4, dualStackV6}) || !slices.Equal(ports[1].Evidence, []string{dualStackV4}) {
		t.Fatalf("accepted baseline evidence = %#v", ports)
	}
}
