package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// defaultTenant returns the store of the default tenant, which owns every
// job that a test creates without naming a tenant.
func defaultTenant(s *store.Store) *store.TenantStore {
	return s.Tenant(store.DefaultTenantScope())
}

func snapshot(state string) model.Snapshot {
	s := model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}}}
	if state != "" {
		s.Units = []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: state}}}}
	}
	s.Normalize()
	return s
}

func TestEquivalentPortCanonicalizationDoesNotInvalidateExistingBaseline(t *testing.T) {
	legacy := config.NormalizeStoredJob(config.Job{
		Name: "legacy-ports", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Ports: "443, 22", Mode: "connect"},
	})
	baseline := model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{
		{Port: 22, State: "open"}, {Port: 443, State: "open"},
	}}}}
	state := model.JobState{
		Baseline: &baseline, BaselineScanID: "legacy-baseline", BaselineConfigHash: legacy.LegacySecurityHash(),
		Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{},
		Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{},
		FingerprintCandidates: map[string]model.ValueCount{},
	}
	scan := model.Scan{
		Job: legacy.Name, Status: "success", ConfigHash: legacy.SecurityHash(),
		FinishedAt: time.Now().UTC(), Snapshot: baseline,
	}
	events, changes, err := processSuccessWithChanges(&state, legacy, scan)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 || len(events) != 0 {
		t.Fatalf("canonicalization created changes or events: changes=%#v events=%#v", changes, events)
	}
	if state.BaselineConfigHash != scan.ConfigHash || state.BaselineScanID != "legacy-baseline" || state.Baseline == nil {
		t.Fatalf("legacy baseline was not preserved and rehashed safely: %#v", state)
	}
}

func TestManagedScanMigratesLegacyPortHashWithoutResettingBaseline(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	created, err := defaultTenant(db).CreateJob(ctx, config.Job{
		Name: "legacy-managed", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Ports: "1-2", Mode: "connect"},
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyDefinition := created.Job
	legacyDefinition.TCP.Ports = "2, 1"
	legacyHash := config.NormalizeStoredJob(legacyDefinition).LegacySecurityHash()
	definition, err := json.Marshal(legacyDefinition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=?`, definition, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE job_revisions SET definition_json=?,security_hash=? WHERE job_id=? AND revision=?`, definition, legacyHash, created.ID, created.Revision); err != nil {
		t.Fatal(err)
	}
	baseline := snapshotWithOpenPorts(1, 2)
	if _, err := db.System().UpdateRuntime(ctx, created.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &baseline
		state.BaselineScanID = "legacy-baseline"
		state.BaselineConfigHash = legacyHash
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	current, err := defaultTenant(db).GetJob(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	scan := model.Scan{
		ID: "canonical-scan", JobID: created.ID, Job: current.Job.Name, JobRevision: current.Revision,
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "success",
		ConfigHash: current.Job.SecurityHash(), Snapshot: baseline,
	}
	e := Engine{Store: db}
	if events, err := e.FinalizeManagedScan(ctx, created.ID, current.Job, &scan, nil); err != nil || len(events) != 0 {
		t.Fatalf("finalize = events %#v, err %v", events, err)
	}
	state, err := defaultTenant(db).RuntimeState(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || state.BaselineScanID != "legacy-baseline" || state.BaselineConfigHash != scan.ConfigHash {
		t.Fatalf("scan invalidated legacy baseline instead of safely migrating its hash: %#v", state)
	}
	if len(scan.Changes) != 0 {
		t.Fatalf("representation-only port change created scan changes: %#v", scan.Changes)
	}
}

func TestLegacyNotificationMaterializationKeepsNewPortIncidentOpen(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	created, err := defaultTenant(db).CreateJob(ctx, config.Job{
		Name: "legacy-notification-managed", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP:      &config.Protocol{Ports: "1-2", Mode: "connect"},
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyDefinition := created.Job
	legacyDefinition.TCP.Ports = "2, 1"
	legacyDefinition.NotificationDestinations = nil
	legacyHash := config.NormalizeStoredJob(legacyDefinition).LegacySecurityHash()
	definition, err := json.Marshal(legacyDefinition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=?`, definition, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE job_revisions SET definition_json=?,security_hash=? WHERE job_id=? AND revision=?`, definition, legacyHash, created.ID, created.Revision); err != nil {
		t.Fatal(err)
	}
	baseline := snapshotWithOpenPorts(1)
	if _, err := db.System().UpdateRuntime(ctx, created.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &baseline
		state.BaselineScanID = "legacy-baseline"
		state.BaselineConfigHash = legacyHash
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	// Freezing the legacy nil selection only changes routing. It must not turn
	// the next scan of the same effective scope into a scope change.
	if count, err := defaultTenant(db).MaterializeLegacyNotificationSelections(ctx, []string{}); err != nil || count != 1 {
		t.Fatalf("materialized job count = %d, %v", count, err)
	}
	current, err := defaultTenant(db).GetJob(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	e := Engine{Store: db}
	for i := 1; i <= 2; i++ {
		scan := model.Scan{
			ID: fmt.Sprintf("materialized-scan-%d", i), JobID: created.ID, Job: current.Job.Name, JobRevision: current.Revision,
			StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "success",
			ConfigHash: current.Job.SecurityHash(), Snapshot: snapshotWithOpenPorts(1, 2),
		}
		events, err := e.FinalizeManagedScan(ctx, created.ID, current.Job, &scan, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if event.Type == "baseline-updated" || event.Type == "changes-recovered" {
				t.Fatalf("scan %d after materialization emitted %s: %#v", i, event.Type, events)
			}
		}
	}
	state, err := defaultTenant(db).RuntimeState(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || state.BaselineScanID != "legacy-baseline" || state.BaselineConfigHash != current.Job.SecurityHash() {
		t.Fatalf("materialization moved the baseline instead of preserving it: %#v", state)
	}
	if len(state.Incidents) != 1 {
		t.Fatalf("newly opened port incident = %#v, want one open incident", state.Incidents)
	}
	for _, incident := range state.Incidents {
		if incident.Change.Port != 2 || incident.Change.New != "open" {
			t.Fatalf("open incident = %#v, want tcp/2 opened", incident)
		}
	}
}

func snapshotWithOpenPorts(ports ...int) model.Snapshot {
	s := model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}}}
	unit := model.Unit{Target: "192.0.2.1", Protocol: "tcp"}
	for _, port := range ports {
		unit.Ports = append(unit.Ports, model.PortState{Port: port, State: "open"})
	}
	s.Units = []model.Unit{unit}
	s.Normalize()
	return s
}
func scan(id string, s model.Snapshot) model.Scan {
	return model.Scan{ID: id, Job: "test", Status: "success", ConfigHash: "hash", Snapshot: s, FinishedAt: time.Now().UTC()}
}

func TestBaselineChangeAndRecoveryConfirmations(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 2}}
	if events, err := e.Success(ctx, job, scan("1", snapshot(""))); err != nil || len(events) != 0 {
		t.Fatalf("first baseline: %v %v", events, err)
	}
	if events, err := e.Success(ctx, job, scan("2", snapshot(""))); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline completion: %v %v", events, err)
	}
	if events, _ := e.Success(ctx, job, scan("3", snapshot("open"))); len(events) != 0 {
		t.Fatalf("early change event %v", events)
	}
	events, _ := e.Success(ctx, job, scan("4", snapshot("open")))
	if len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("change event %v", events)
	}
	if events, _ := e.Success(ctx, job, scan("5", snapshot(""))); len(events) != 0 {
		t.Fatalf("early recovery %v", events)
	}
	events, _ = e.Success(ctx, job, scan("6", snapshot("")))
	if len(events) != 1 || events[0].Type != "changes-recovered" {
		t.Fatalf("recovery %v", events)
	}
}

func TestTotalLossScanRequiresConfirmationBeforeOpeningIncidents(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "total-loss", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	ports := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	if events, err := e.Success(ctx, job, scan("baseline", snapshotWithOpenPorts(ports...))); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline setup: %#v, %v", events, err)
	}

	firstEmpty := scan("empty-1", snapshot(""))
	events, err := e.Success(ctx, job, firstEmpty)
	if err != nil || len(events) != 1 || events[0].Type != "scan-anomaly" {
		t.Fatalf("first total-loss scan: %#v, %v", events, err)
	}
	if !strings.Contains(FormatEvent(events[0]), "awaiting confirmation") {
		t.Fatalf("anomaly notification: %q", FormatEvent(events[0]))
	}
	state, err := defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 0 || state.TotalLossCandidateCount != 1 || state.Baseline == nil || len(state.Baseline.Units[0].Ports) != len(ports) {
		t.Fatalf("first total-loss state: %#v", state)
	}

	// A second identical complete result confirms the loss and hands control
	// back to the normal diff engine. The finding is never suppressed forever;
	// it is merely protected from a single anomalous pass.
	events, err = e.Success(ctx, job, scan("empty-2", snapshot("")))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("confirmed total-loss scan: %#v, %v", events, err)
	}
	state, err = defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != len(ports) || state.TotalLossCandidateCount != totalLossConfirmationScans || state.TotalLossCandidateHash == "" {
		t.Fatalf("confirmed total-loss state: %#v", state)
	}

	// The confirmation covers the whole outage: later zero-positive scans are
	// compared normally instead of being held back as new anomalies.
	for i := 3; i <= 5; i++ {
		events, err = e.Success(ctx, job, scan(fmt.Sprintf("empty-%d", i), snapshot("")))
		if err != nil || len(events) != 0 {
			t.Fatalf("sustained total-loss scan %d: %#v, %v", i, events, err)
		}
	}
	state, err = defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != len(ports) || state.TotalLossCandidateCount != totalLossConfirmationScans {
		t.Fatalf("sustained total-loss state: %#v", state)
	}

	// A positive result ends the outage, so the next sudden all-closed scan
	// again needs its own matching confirmation.
	events, err = e.Success(ctx, job, scan("restored", snapshotWithOpenPorts(ports...)))
	if err != nil || len(events) != 1 || events[0].Type != "changes-recovered" {
		t.Fatalf("restored scan: %#v, %v", events, err)
	}
	state, err = defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 0 || state.TotalLossCandidateCount != 0 || state.TotalLossCandidateHash != "" {
		t.Fatalf("restored state: %#v", state)
	}
	events, err = e.Success(ctx, job, scan("empty-again", snapshot("")))
	if err != nil || len(events) != 1 || events[0].Type != "scan-anomaly" {
		t.Fatalf("new total-loss scan after recovery: %#v, %v", events, err)
	}
}

func TestTotalLossHostTransitionDoesNotAdvancePortIncidentState(t *testing.T) {
	const upAddress = "192.0.2.31"
	const downAddress = "192.0.2.32"
	const incidentKey = "port|192.0.2.31|tcp|8080"
	const pendingKey = "port|192.0.2.31|tcp|80"
	const suppressedKey = "port|192.0.2.31|tcp|25"
	job := config.Job{Name: "guard-host-transition", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: upAddress, Protocol: "tcp", Ports: "22,443,8080"}, {Target: downAddress, Protocol: "tcp", Ports: "22,443,8080"}},
		Units: []model.Unit{
			{Target: upAddress, Protocol: "tcp", Addresses: []string{upAddress}, Ports: []model.PortState{{Port: 443, State: "open"}}},
			{Target: downAddress, Protocol: "tcp", Addresses: []string{downAddress}, Ports: []model.PortState{{Port: 22, State: "open"}}},
		},
		HostStates: []model.HostState{{Address: upAddress, State: "up"}, {Address: downAddress, State: "up"}},
	}
	state := model.JobState{
		Baseline: &baseline, BaselineScanID: "baseline", BaselineConfigHash: "hash",
		Incidents:             map[string]model.Incident{incidentKey: {Change: model.Change{Key: incidentKey, Kind: "port", Target: upAddress, Protocol: "tcp", Port: 8080, Old: "not-open", New: "open"}}},
		Pending:               map[string]model.Pending{pendingKey: {Change: model.Change{Key: pendingKey, Kind: "port", Target: upAddress, Protocol: "tcp", Port: 80, Old: "not-open", New: "open"}, Count: 1}},
		Suppressed:            map[string]int{suppressedKey: 1},
		SuppressedChanges:     map[string]model.Change{suppressedKey: {Key: suppressedKey, Kind: "port", Target: upAddress, Protocol: "tcp", Port: 25, Old: "not-open", New: "open"}},
		FingerprintCandidates: map[string]model.ValueCount{},
	}
	zeroWithHostDown := model.Snapshot{
		Scopes: []model.Scope{{Target: upAddress, Protocol: "tcp", Ports: "22,443,8080"}, {Target: downAddress, Protocol: "tcp", Ports: "22,443,8080"}},
		Units:  []model.Unit{{Target: upAddress, Protocol: "tcp", Addresses: []string{upAddress}}},
		Hosts: []model.HostObservation{
			{Address: upAddress, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}},
			{Address: downAddress, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}},
		},
	}
	events, changes, err := processSuccessWithChanges(&state, job, scan("zero-with-host-down-1", zeroWithHostDown))
	if err != nil || len(events) != 2 || events[0].Type != "scan-anomaly" || events[1].Type != "changes-detected" || len(changes) != 1 || changes[0].Key != "host|"+downAddress {
		t.Fatalf("first zero scan with host transition: events=%#v changes=%#v err=%v", events, changes, err)
	}
	if _, ok := state.Incidents[incidentKey]; !ok {
		t.Fatalf("existing port incident recovered during guarded scan: %#v", state.Incidents)
	}
	if pending, ok := state.Pending[pendingKey]; !ok || pending.Count != 1 {
		t.Fatalf("pending port change advanced during guarded scan: %#v", state.Pending)
	}
	if state.Suppressed[suppressedKey] != 1 {
		t.Fatalf("port suppression advanced during guarded scan: %#v", state.Suppressed)
	}

	events, changes, err = processSuccessWithChanges(&state, job, scan("zero-with-host-down-2", zeroWithHostDown))
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]bool{}
	for _, event := range events {
		types[event.Type] = true
	}
	if types["scan-anomaly"] || !types["changes-detected"] || !types["changes-recovered"] {
		t.Fatalf("confirmed zero scan did not return to normal comparison: events=%#v changes=%#v", events, changes)
	}
	if _, ok := state.Incidents[incidentKey]; ok {
		t.Fatalf("existing port incident was not recovered after confirmation: %#v", state.Incidents)
	}
	if _, ok := state.Pending[pendingKey]; ok {
		t.Fatalf("pending port change was not evaluated after confirmation: %#v", state.Pending)
	}
	if state.Suppressed[suppressedKey] != 0 {
		t.Fatalf("port suppression did not resume after confirmation: %#v", state.Suppressed)
	}
}

func TestTotalLossConfirmsOncePerOutage(t *testing.T) {
	dnsBaseline := func() model.Snapshot {
		s := model.Snapshot{
			Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "1-65535"}},
			Units:  []model.Unit{{Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.10"}, Ports: []model.PortState{{Port: 22, State: "open"}, {Port: 443, State: "open"}}}},
			DNS:    map[string][]string{"edge.example": {"192.0.2.10"}},
		}
		s.Normalize()
		return s
	}
	dnsEmpty := func(address string) model.Snapshot {
		s := model.Snapshot{
			Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "1-65535"}},
			Units:  []model.Unit{{Target: "edge.example", Protocol: "tcp", Addresses: []string{address}}},
			DNS:    map[string][]string{"edge.example": {address}},
		}
		s.Normalize()
		return s
	}
	for _, tc := range []struct {
		name          string
		confirmations int
		baseline      model.Snapshot
		empty         func(scan int) model.Snapshot
		openAt        int
	}{
		{name: "confirmations-1", confirmations: 1, baseline: snapshotWithOpenPorts(22, 443), empty: func(int) model.Snapshot { return snapshot("") }, openAt: 2},
		{name: "confirmations-2", confirmations: 2, baseline: snapshotWithOpenPorts(22, 443), empty: func(int) model.Snapshot { return snapshot("") }, openAt: 3},
		{name: "dns-rotating", confirmations: 1, baseline: dnsBaseline(), empty: func(i int) model.Snapshot { return dnsEmpty(fmt.Sprintf("192.0.2.%d", 10+i)) }, openAt: 2},
		{name: "dns-alternating", confirmations: 1, baseline: dnsBaseline(), empty: func(i int) model.Snapshot { return dnsEmpty(fmt.Sprintf("192.0.2.%d", 11+i%2)) }, openAt: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := tc.baseline
			state := model.JobState{Baseline: &base, BaselineScanID: "baseline", BaselineConfigHash: "hash", Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{}, FingerprintCandidates: map[string]model.ValueCount{}}
			job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: tc.confirmations}}
			var timeline []string
			for i := 1; i <= 6; i++ {
				events, _, err := processSuccessWithChanges(&state, job, scan(fmt.Sprintf("empty-%d", i), tc.empty(i)))
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range events {
					entry := fmt.Sprintf("scan%d:%s", i, event.Type)
					for _, change := range event.Changes {
						if change.Kind == "port" {
							entry += "[" + change.Key + "]"
						}
					}
					timeline = append(timeline, entry)
					switch {
					case event.Type == "scan-anomaly" && i != 1:
						t.Fatalf("total loss was held back again after the first scan: %v", timeline)
					case event.Type == "changes-recovered" && strings.Contains(entry, "port|"):
						t.Fatalf("sustained total loss recovered a port: %v", timeline)
					case event.Type == "changes-detected" && strings.Contains(entry, "port|") && i != tc.openAt:
						t.Fatalf("port incidents opened on scan %d, want scan %d: %v", i, tc.openAt, timeline)
					}
				}
				if i == 1 && (len(events) != 1 || events[0].Type != "scan-anomaly") {
					t.Fatalf("first empty scan was not held for confirmation: %v", timeline)
				}
			}
			portIncidents := 0
			for key := range state.Incidents {
				if strings.HasPrefix(key, "port|") {
					portIncidents++
				}
			}
			if portIncidents != 2 {
				t.Fatalf("port incidents = %d, want 2: %v", portIncidents, timeline)
			}
		})
	}
}

func TestConfirmedTotalLossResetsOnlyForNewEvidence(t *testing.T) {
	base := snapshotWithOpenPorts(22, 443)
	state := model.JobState{Baseline: &base, BaselineScanID: "baseline", BaselineConfigHash: "hash", Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{}, FingerprintCandidates: map[string]model.ValueCount{}}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	eventTypes := func(events []model.Event) []string {
		types := make([]string, 0, len(events))
		for _, event := range events {
			types = append(types, event.Type)
		}
		return types
	}
	process := func(id string, snapshot model.Snapshot) []string {
		t.Helper()
		events, _, err := processSuccessWithChanges(&state, job, scan(id, snapshot))
		if err != nil {
			t.Fatal(err)
		}
		return eventTypes(events)
	}
	if got := process("empty-1", snapshot("")); fmt.Sprint(got) != "[scan-anomaly]" {
		t.Fatalf("first empty scan = %v", got)
	}
	if got := process("empty-2", snapshot("")); fmt.Sprint(got) != "[changes-detected]" {
		t.Fatalf("confirming empty scan = %v", got)
	}

	// Failed and incomplete scans provide no positive evidence, so they neither
	// end a confirmed outage nor make the next complete empty scan an anomaly.
	failed := scan("failed", model.Snapshot{})
	failed.Status = "failed"
	if events, err := processFailure(&state, job.Name, failed); err != nil || fmt.Sprint(eventTypes(events)) != "[scan-failure]" {
		t.Fatalf("failed scan = %#v, %v", events, err)
	}
	if got := process("empty-3", snapshot("")); len(got) != 0 {
		t.Fatalf("empty scan after a failure = %v", got)
	}
	partial := snapshot("")
	partial.Hosts = []model.HostObservation{{Address: "192.0.2.1", Status: "down", StatusReason: "nmap-omitted"}}
	if got := process("partial", partial); fmt.Sprint(got) != "[scan-incomplete]" {
		t.Fatalf("incomplete empty scan = %v", got)
	}
	if got := process("empty-4", snapshot("")); len(got) != 0 {
		t.Fatalf("empty scan after an incomplete scan = %v", got)
	}
	if len(state.Incidents) != 2 || state.TotalLossCandidateCount != totalLossConfirmationScans {
		t.Fatalf("confirmed outage state = %#v", state)
	}

	// A replaced baseline is new expected state; its first all-closed scan
	// needs its own confirmation.
	replaced := snapshotWithOpenPorts(22, 443, 8443)
	state.Baseline = &replaced
	state.BaselineScanID = "approved"
	state.Incidents = map[string]model.Incident{}
	if got := process("empty-5", snapshot("")); fmt.Sprint(got) != "[scan-anomaly]" {
		t.Fatalf("empty scan after baseline replacement = %v", got)
	}
	if got := process("empty-6", snapshot("")); fmt.Sprint(got) != "[changes-detected]" {
		t.Fatalf("confirming empty scan after baseline replacement = %v", got)
	}

	// An unconfirmed candidate still requires consecutive complete evidence.
	state.Incidents = map[string]model.Incident{}
	clearTotalLossCandidate(&state)
	if got := process("empty-7", snapshot("")); fmt.Sprint(got) != "[scan-anomaly]" {
		t.Fatalf("new empty scan = %v", got)
	}
	if _, err := processFailure(&state, job.Name, failed); err != nil {
		t.Fatal(err)
	}
	if state.TotalLossCandidateCount != 0 || state.TotalLossCandidateHash != "" {
		t.Fatalf("failed scan kept an unconfirmed total-loss candidate: %#v", state)
	}
	if got := process("empty-8", snapshot("")); fmt.Sprint(got) != "[scan-anomaly]" {
		t.Fatalf("empty scan after an interrupted confirmation = %v", got)
	}
}

func TestGradualPortReductionBypassesTotalLossGuard(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "gradual-loss", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	if _, err := e.Success(ctx, job, scan("baseline", snapshotWithOpenPorts(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12))); err != nil {
		t.Fatal(err)
	}
	events, err := e.Success(ctx, job, scan("reduction", snapshotWithOpenPorts(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("gradual reduction: %#v, %v", events, err)
	}
	state, err := defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 2 {
		t.Fatalf("gradual reduction incidents: %d (%#v)", len(state.Incidents), state.Incidents)
	}
}

func TestSuppressedIncidentReopensAfterOneSuccessfulScan(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "suppressed", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 2}}
	if _, err := e.Success(ctx, job, scan("baseline", snapshot(""))); err != nil {
		t.Fatal(err)
	}
	if events, err := e.Success(ctx, job, scan("candidate-1", snapshot("open"))); err != nil || len(events) != 0 {
		t.Fatalf("first changed scan: %#v, %v", events, err)
	}
	if events, err := e.Success(ctx, job, scan("incident", snapshot("open"))); err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("incident scan: %#v, %v", events, err)
	}
	key := "port|192.0.2.1|tcp|443"
	if _, err := db.System().UpdateState(ctx, job.Name, func(state *model.JobState) ([]model.Event, error) {
		incident, ok := state.Incidents[key]
		if !ok {
			return nil, fmt.Errorf("incident %s not found", key)
		}
		state.Suppressed[key] = 1
		state.SuppressedChanges[key] = incident.Change
		delete(state.Incidents, key)
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if events, err := e.Success(ctx, job, scan("suppressed-scan", snapshot("open"))); err != nil || len(events) != 0 {
		t.Fatalf("suppressed scan: %#v, %v", events, err)
	}
	state, err := defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 0 || state.Suppressed[key] != 0 {
		t.Fatalf("suppression window after scan = %#v", state)
	}
	events, err := e.Success(ctx, job, scan("reopened", snapshot("open")))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("reopened scan: %#v, %v", events, err)
	}
	state, err = defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 1 || state.Suppressed[key] != 0 {
		t.Fatalf("reopened state = %#v", state)
	}
}

func TestUDPUncertaintyIsWarning(t *testing.T) {
	changes := Diff(snapshot(""), model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}}, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 53, State: "open|filtered"}}}}}, false)
	if len(changes) != 1 || changes[0].Severity != "warning" {
		t.Fatalf("changes %#v", changes)
	}
}

func TestFormatEventUsesOutcomeIndicators(t *testing.T) {
	recovered := FormatEvent(model.Event{Type: "changes-recovered", Message: "one change recovered", Job: "test"})
	if !strings.HasPrefix(recovered, "🟢 EdgeWatch: ") {
		t.Fatalf("recovery notification = %q", recovered)
	}
	cycleRecovered := FormatEvent(model.Event{Type: "scan-recovered", Message: "scan cycle recovered", Job: "test"})
	if !strings.HasPrefix(cycleRecovered, "🟢 EdgeWatch: ") {
		t.Fatalf("resumable recovery notification = %q", cycleRecovered)
	}

	critical := FormatEvent(model.Event{Type: "changes-detected", Message: "one change", Job: "test", Changes: []model.Change{{Severity: "critical"}}})
	if !strings.HasPrefix(critical, "🔴 EdgeWatch: ") {
		t.Fatalf("critical notification = %q", critical)
	}

	warning := FormatEvent(model.Event{Type: "changes-detected", Message: "one change", Job: "test", Changes: []model.Change{{Severity: "warning"}}})
	if strings.HasPrefix(warning, "🔴 ") || strings.HasPrefix(warning, "🟢 ") {
		t.Fatalf("warning notification has an outcome indicator = %q", warning)
	}
	anomaly := FormatEvent(model.Event{Type: "scan-anomaly", Message: "awaiting confirmation", Job: "test"})
	if !strings.HasPrefix(anomaly, "⚠️ EdgeWatch: ") {
		t.Fatalf("anomaly notification = %q", anomaly)
	}
	incomplete := FormatEvent(model.Event{Type: "scan-incomplete", Message: "Scan incomplete: scan coverage did not complete for 192.0.2.9", Job: "test"})
	if !strings.HasPrefix(incomplete, "⚠️ EdgeWatch: ") || !strings.Contains(incomplete, "192.0.2.9") {
		t.Fatalf("incomplete notification = %q", incomplete)
	}
}

func TestFormatEventUsesApplicationUpdateMessages(t *testing.T) {
	available := FormatEvent(model.Event{Type: "application-update-available", CurrentVersion: "v1.1.0", LatestVersion: "v1.2.0", ReleaseURL: "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.2.0"})
	if !strings.Contains(available, "⬆️ EdgeWatch update available") || !strings.Contains(available, "Current version: v1.1.0") || !strings.Contains(available, "New version: v1.2.0") || strings.Contains(available, "Job:") {
		t.Fatalf("available update notification = %q", available)
	}
	updated := FormatEvent(model.Event{Type: "application-updated", PreviousVersion: "v1.1.0", CurrentVersion: "v1.2.0", ReleaseURL: "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.2.0"})
	if !strings.Contains(updated, "🟢 EdgeWatch updated") || !strings.Contains(updated, "Previous version: v1.1.0") || strings.Contains(updated, "Job:") {
		t.Fatalf("updated notification = %q", updated)
	}
}

func TestFormatEventKeepsTrustedTextAndNeutralizesUntrustedScanValues(t *testing.T) {
	event := model.Event{
		Type:    "changes-detected",
		Message: "1 baseline change confirmed",
		Job:     "edge_[prod]",
		Changes: []model.Change{{Severity: "critical", Kind: "service", Target: "host-1", Protocol: "tcp", Port: 443, Old: "old", New: "[x](javascript:alert(1))"}},
	}
	got := FormatEvent(event)
	for _, unsafe := range []string{"[x](javascript:alert(1))", "\u202E", "\u202C"} {
		if strings.Contains(got, unsafe) {
			t.Fatalf("notification retained unsafe text %q: %q", unsafe, got)
		}
	}
	if !strings.Contains(got, "1 baseline change confirmed") || !strings.Contains(got, "Job: edge_[prod]") || !strings.Contains(got, "［x］（javascript:alert（1））") || !strings.Contains(got, "old ->") {
		t.Fatalf("notification did not preserve a readable neutralized form: %q", got)
	}
	long := FormatEvent(model.Event{Message: strings.Repeat("x", maxNotificationFieldRunes+20)})
	if len([]rune(long)) > len("EdgeWatch: ")+maxNotificationFieldRunes {
		t.Fatalf("notification field was not bounded: %d runes", len([]rune(long)))
	}
}

func TestIncompleteFailuresDoNotChangeBaseline(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(storetest.FreshPath(t))
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	e.Success(ctx, job, scan("1", snapshot("open")))
	failed := scan("2", snapshot(""))
	failed.Status = "failed"
	failed.Error = "timeout"
	for i := 0; i < 3; i++ {
		e.Failure(ctx, "test", failed)
	}
	state, _ := defaultTenant(db).State(ctx, "test")
	if state.Baseline == nil || len(state.Baseline.Units) == 0 {
		t.Fatal("failure modified baseline")
	}
	if len(state.Incidents) != 0 {
		t.Fatal("failure created incident")
	}
}

func TestUnreachableHostObservationDoesNotChangeBaseline(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "partial", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := model.Snapshot{
		Scopes: []model.Scope{
			{Target: "192.0.2.1", Protocol: "tcp", Ports: "443"},
			{Target: "192.0.2.2", Protocol: "tcp", Ports: "443"},
		},
		Units: []model.Unit{
			{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}},
			{Target: "192.0.2.2", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}},
		},
	}
	if events, err := e.Success(ctx, job, scan("baseline", baseline)); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline setup: %#v, %v", events, err)
	}
	partial := model.Snapshot{
		Scopes: baseline.Scopes,
		Units:  []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}, {Port: 80, State: "open"}}}},
		Hosts:  []model.HostObservation{{Address: "192.0.2.2", Status: "unreachable", StatusReason: "nmap-omitted"}},
	}
	if events, err := e.Success(ctx, job, scan("partial", partial)); err != nil || len(events) != 2 || events[0].Type != "changes-detected" || events[1].Type != "scan-incomplete" {
		t.Fatalf("partial scan did not compare reachable evidence and report incomplete coverage: %#v, %v", events, err)
	}
	state, err := defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || len(state.Baseline.Units) != 2 || len(state.Incidents) != 1 {
		t.Fatalf("partial scan changed baseline or incidents: %#v", state)
	}
	if _, ok := state.Incidents["port|192.0.2.2|tcp|443"]; ok {
		t.Fatal("unreachable host removal created an incident before it was observed")
	}
	complete := model.Snapshot{
		Scopes: baseline.Scopes,
		Units: []model.Unit{
			{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}, {Port: 80, State: "open"}}},
			{Target: "192.0.2.2", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "closed"}}},
		},
	}
	events, err := e.Success(ctx, job, scan("complete", complete))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 || events[0].Changes[0].Target != "192.0.2.2" {
		t.Fatalf("complete scan did not report deferred unreachable-host removal: %#v, %v", events, err)
	}
}

func TestUnknownNoResponseEvidenceCannotLearnOrRemoveBaselinePorts(t *testing.T) {
	job := config.Job{Name: "no-response", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	current := model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.30", Protocol: "tcp", Ports: "443"}},
		Units:  []model.Unit{{Target: "192.0.2.30", Protocol: "tcp", Addresses: []string{"192.0.2.30"}}},
		Hosts: []model.HostObservation{{
			Address: "192.0.2.30", Status: "unknown", StatusReason: "no-response",
			Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unknown", StatusReason: "no-response", ScannedPorts: "1-65535"}},
		}},
	}

	learningState := model.JobState{}
	learningScan := scan("no-response-learning", current)
	if !MarkIncompleteScan(&learningScan) {
		t.Fatal("unknown/no-response scan was not marked incomplete")
	}
	events, changes, err := processSuccessWithChanges(&learningState, job, learningScan)
	if err != nil || len(changes) != 0 || learningState.Baseline != nil || learningState.CandidateAttempts != 0 || learningState.IncompleteCandidateAttempts != 1 {
		t.Fatalf("incomplete no-response scan advanced baseline learning: events=%#v changes=%#v state=%#v err=%v", events, changes, learningState, err)
	}

	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.30", Protocol: "tcp", Ports: "443"}},
		Units:  []model.Unit{{Target: "192.0.2.30", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}},
	}
	state := model.JobState{Baseline: &baseline, BaselineConfigHash: "hash", Incidents: map[string]model.Incident{}, Pending: map[string]model.Pending{}}
	removalScan := scan("no-response-removal", current)
	removalScan.ConfigHash = "hash"
	if !MarkIncompleteScan(&removalScan) {
		t.Fatal("unknown/no-response removal scan was not marked incomplete")
	}
	events, changes, err = processSuccessWithChanges(&state, job, removalScan)
	if err != nil || len(changes) != 0 || len(events) != 1 || events[0].Type != "scan-incomplete" {
		t.Fatalf("incomplete no-response scan confirmed removals: events=%#v changes=%#v err=%v", events, changes, err)
	}
	if state.Baseline == nil || len(state.Baseline.Units) != 1 || len(state.Baseline.Units[0].Ports) != 1 || len(state.Incidents) != 0 {
		t.Fatalf("incomplete no-response scan changed expected state: %#v", state)
	}
}

func TestCompletedNmapHostDiscoveryDownDoesNotMarkScanIncomplete(t *testing.T) {
	address := "192.0.2.44"
	scanResult := scan("explicit-down", model.Snapshot{
		Scopes: []model.Scope{{Target: address, Protocol: "tcp", Ports: "22,443"}, {Target: address, Protocol: "udp", Ports: "53"}},
		Hosts: []model.HostObservation{{
			Address: address, Status: "unreachable", StatusReason: "no-response",
			Protocols: []model.ProtocolObservation{
				{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"},
				{Protocol: "udp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"},
			},
		}},
	})
	if MarkIncompleteScan(&scanResult) {
		t.Fatalf("completed Nmap host-discovery result was marked incomplete: %s", scanResult.Error)
	}
	if scanResult.Status != "success" {
		t.Fatalf("explicit host-down scan status = %q, want success", scanResult.Status)
	}
	if len(scanResult.Snapshot.HostStates) != 1 || scanResult.Snapshot.HostStates[0] != (model.HostState{Address: address, State: "down"}) {
		t.Fatalf("explicit host-discovery state = %#v, want down for %s", scanResult.Snapshot.HostStates, address)
	}

	for _, test := range []struct {
		name           string
		status, reason string
	}{
		{name: "unmarked down is ambiguous", status: "unreachable", reason: "no-response"},
		{name: "timeout remains incomplete", status: "unreachable", reason: "nmap-host-timeout"},
		{name: "omitted host remains incomplete", status: "unreachable", reason: "nmap-omitted"},
	} {
		t.Run(test.name, func(t *testing.T) {
			partial := scan(test.name, model.Snapshot{
				Scopes: []model.Scope{{Target: address, Protocol: "tcp", Ports: "22,443"}},
				Hosts: []model.HostObservation{{
					Address: address, Status: test.status, StatusReason: test.reason,
					Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: test.status, StatusReason: test.reason}},
				}},
			})
			if !MarkIncompleteScan(&partial) || partial.Status != "incomplete" {
				t.Fatalf("ambiguous host result was treated as complete: %#v", partial)
			}
		})
	}
}

func TestNaabuOpenAddressReportedDownByNmapEnrichmentRemainsIncomplete(t *testing.T) {
	const address = "192.0.2.51"
	job := config.Job{Name: "naabu-enrichment-down", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := model.Snapshot{
		Scopes:     []model.Scope{{Target: address, Protocol: "tcp", Ports: "22,8443"}},
		Units:      []model.Unit{{Target: address, Protocol: "tcp", Addresses: []string{address}, Ports: []model.PortState{{Port: 22, State: "open"}, {Port: 8443, State: "open"}}}},
		HostStates: []model.HostState{{Address: address, State: "up"}},
	}
	state := model.JobState{Baseline: &baseline, BaselineScanID: "baseline", BaselineConfigHash: "hash", Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{}, FingerprintCandidates: map[string]model.ValueCount{}}
	current := model.Snapshot{
		Scopes: []model.Scope{{Target: address, Protocol: "tcp", Ports: "1-65535"}},
		DNS:    map[string][]string{},
		Hosts: []model.HostObservation{{
			Address: address, Status: "unreachable", StatusReason: "no-response",
			Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down", DiscoveryEngine: "naabu", ScannedPorts: "1-65535"}},
		}},
	}
	scanResult := scan("naabu-open-nmap-down", current)
	if !MarkIncompleteScan(&scanResult) || scanResult.Status != "incomplete" || !strings.Contains(scanResult.Error, address) {
		t.Fatalf("contradictory Naabu/Nmap result was not marked incomplete: %#v", scanResult)
	}
	if len(scanResult.Snapshot.HostStates) != 0 {
		t.Fatalf("Nmap enrichment changed Naabu reachability state: %#v", scanResult.Snapshot.HostStates)
	}
	events, changes, err := processSuccessWithChanges(&state, job, scanResult)
	if err != nil || len(changes) != 0 || len(events) != 1 || events[0].Type != "scan-incomplete" {
		t.Fatalf("contradictory discovery comparison = events %#v changes %#v err %v", events, changes, err)
	}
	if state.Baseline == nil || len(state.Baseline.Units) != 1 || len(state.Baseline.Units[0].Ports) != 2 || len(state.Incidents) != 0 {
		t.Fatalf("contradictory evidence changed expected ports or incidents: %#v", state)
	}
}

func TestMixedHostDiscoveryRangeLearnsAndReportsHostDownWithoutPortClosures(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	assumeAlive := false
	job := config.Job{Name: "mixed-discovery", AssumeAlive: &assumeAlive, Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	upAddress, downAddress := "192.0.2.41", "192.0.2.42"
	scope := []model.Scope{{Target: upAddress, Protocol: "tcp", Ports: "22,443"}, {Target: downAddress, Protocol: "tcp", Ports: "22,443"}}
	first := model.Snapshot{
		Scopes: scope,
		Units:  []model.Unit{{Target: upAddress, Protocol: "tcp", Addresses: []string{upAddress}, Ports: []model.PortState{{Port: 22, State: "open"}}}},
		Hosts: []model.HostObservation{
			{Address: upAddress, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}},
			{Address: downAddress, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}},
		},
	}
	if events, err := e.Success(ctx, job, scan("mixed-learning", first)); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("mixed up/down range failed to establish baseline: events=%#v err=%v", events, err)
	}
	state, err := defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || state.CandidateAttempts != 0 || len(state.Baseline.HostStates) != 2 {
		t.Fatalf("mixed range baseline = %#v; candidate attempts=%d", state.Baseline, state.CandidateAttempts)
	}
	if state.Baseline.HostStates[0] != (model.HostState{Address: upAddress, State: "up"}) || state.Baseline.HostStates[1] != (model.HostState{Address: downAddress, State: "down"}) {
		t.Fatalf("mixed range host states = %#v", state.Baseline.HostStates)
	}

	// Establish a second job whose expected surface includes both hosts, then
	// make one host explicitly down. Its old ports must be protected from
	// closure incidents while a distinct host-state incident is confirmed.
	job.Name = "host-goes-down"
	baseline := model.Snapshot{
		Scopes: scope,
		Units: []model.Unit{
			{Target: upAddress, Protocol: "tcp", Addresses: []string{upAddress}, Ports: []model.PortState{{Port: 22, State: "open", Evidence: []string{upAddress}}}},
			{Target: downAddress, Protocol: "tcp", Addresses: []string{downAddress}, Ports: []model.PortState{{Port: 443, State: "open", Evidence: []string{downAddress}}}},
		},
		Hosts: []model.HostObservation{
			{Address: upAddress, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}},
			{Address: downAddress, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}},
		},
	}
	if events, err := e.Success(ctx, job, scan("up-baseline", baseline)); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("up baseline setup: %#v, %v", events, err)
	}
	current := model.Snapshot{
		Scopes: scope,
		Units:  []model.Unit{{Target: upAddress, Protocol: "tcp", Addresses: []string{upAddress}, Ports: []model.PortState{{Port: 22, State: "open", Evidence: []string{upAddress}}}}},
		Hosts: []model.HostObservation{
			{Address: upAddress, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}},
			{Address: downAddress, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}},
		},
	}
	events, err := e.Success(ctx, job, scan("host-down", current))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 {
		t.Fatalf("host-down transition events = %#v, %v", events, err)
	}
	change := events[0].Changes[0]
	if change.Kind != "host" || change.Target != downAddress || change.Old != "up" || change.New != "down" {
		t.Fatalf("host-down change = %#v", change)
	}
	state, err = defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := state.Incidents["port|"+downAddress+"|tcp|443"]; exists {
		t.Fatal("missing host coverage was incorrectly reported as a closed port")
	}
	if _, exists := state.Incidents["host|"+downAddress]; !exists {
		t.Fatalf("host-down incident missing: %#v", state.Incidents)
	}
}

func TestSingleHostDownBypassesTotalLossPortClosureGuard(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	assumeAlive := false
	job := config.Job{Name: "single-host-down", AssumeAlive: &assumeAlive, Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	address := "192.0.2.43"
	scope := []model.Scope{{Target: address, Protocol: "tcp", Ports: "443"}}
	baseline := model.Snapshot{Scopes: scope, Units: []model.Unit{{Target: address, Protocol: "tcp", Addresses: []string{address}, Ports: []model.PortState{{Port: 443, State: "open"}}}}, Hosts: []model.HostObservation{{Address: address, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}}}}
	if events, err := e.Success(ctx, job, scan("single-up", baseline)); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("single-host baseline setup: %#v, %v", events, err)
	}
	down := model.Snapshot{Scopes: scope, Hosts: []model.HostObservation{{Address: address, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}}}}
	events, err := e.Success(ctx, job, scan("single-down", down))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 || events[0].Changes[0].Kind != "host" {
		t.Fatalf("explicit single-host down was hidden by total-loss guard: %#v, %v", events, err)
	}
}

func TestAcceptDNSHostDownDoesNotRewriteSurvivingServiceFingerprint(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	job := config.NormalizeJob(config.Job{
		Name: "accept-dns-host-down", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"edge.example"}, DNSComparisonMode: config.DNSComparisonAggregate,
		TCP:      &config.Protocol{Ports: "22", Mode: "connect", ServiceDetection: true},
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	})
	record, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	const downAddress = "192.0.2.21"
	const liveAddress = "192.0.2.22"
	const fingerprint = "ssh | OpenSSH | 9.6 |"
	key := "host|" + downAddress
	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "22", ServiceDetection: true}},
		DNS:    map[string][]string{"edge.example": {downAddress, liveAddress}},
		Units: []model.Unit{{Target: "edge.example", Protocol: "tcp", Addresses: []string{downAddress, liveAddress}, Ports: []model.PortState{{
			Port: 22, State: "open", Service: fingerprint, Evidence: []string{downAddress, liveAddress},
		}}}},
		HostStates: []model.HostState{{Address: downAddress, State: "up"}, {Address: liveAddress, State: "up"}},
		Hosts: []model.HostObservation{
			{Address: downAddress, SourceTargets: []string{"edge.example"}, Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 22, State: "open", Service: &model.ServiceObservation{Name: "ssh", Product: "Removed", Version: "8.0", Method: "probed"}}}}}},
			{Address: liveAddress, SourceTargets: []string{"edge.example"}, Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 22, State: "open", Service: &model.ServiceObservation{Name: "ssh", Product: "OpenSSH", Version: "9.6", Method: "probed"}}}}}},
		},
	}
	if _, err := db.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &baseline
		state.BaselineScanID = "baseline"
		state.BaselineConfigHash = record.Job.SecurityHash()
		state.Incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "host", Target: downAddress, Old: "up", New: "down", Severity: "warning"}, ScanID: "host-down"}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(db).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, key, store.AuditEntry{Action: "incident.accepted", Detail: key}); err != nil {
		t.Fatal(err)
	}
	state, err := defaultTenant(db).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := baselineService(*state.Baseline, "edge.example", "tcp", 22); got != fingerprint {
		t.Fatalf("accepted host-down baseline fingerprint = %q, want %q", got, fingerprint)
	}

	current := baseline
	current.HostStates = []model.HostState{{Address: downAddress, State: "down"}, {Address: liveAddress, State: "up"}}
	current.Hosts = []model.HostObservation{
		{Address: downAddress, SourceTargets: []string{"edge.example"}, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}},
		{Address: liveAddress, SourceTargets: []string{"edge.example"}, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up", Ports: []model.PortObservation{{Port: 22, State: "open", Service: &model.ServiceObservation{Name: "ssh", Product: "OpenSSH", Version: "9.6", Method: "probed"}}}}}},
	}
	current.Units[0].Ports[0].Evidence = []string{liveAddress}
	scanResult := model.Scan{ID: "unchanged-after-accept", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: current, FinishedAt: time.Now().UTC()}
	events, err := (&Engine{Store: db}).FinalizeManagedScan(ctx, record.ID, record.Job, &scanResult, nil)
	if err != nil || len(events) != 0 {
		t.Fatalf("unchanged evidence after host-down acceptance = %#v, %v", events, err)
	}
}

func TestDNSHostDownDoesNotHideClosureOnLiveSibling(t *testing.T) {
	addresses := []string{"192.0.2.10", "192.0.2.11"}
	scope := []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "443"}}
	baseline := model.Snapshot{
		Scopes: scope,
		DNS:    map[string][]string{"edge.example": addresses},
		Units: []model.Unit{{Target: "edge.example", Protocol: "tcp", Addresses: addresses, Ports: []model.PortState{{
			Port: 443, State: "open", Evidence: addresses,
		}}}},
		HostStates: []model.HostState{{Address: addresses[0], State: "up"}, {Address: addresses[1], State: "up"}},
	}
	current := model.Snapshot{
		Scopes: scope,
		DNS:    map[string][]string{"edge.example": addresses},
		Units:  []model.Unit{{Target: "edge.example", Protocol: "tcp", Addresses: addresses}},
		Hosts: []model.HostObservation{
			{Address: addresses[0], Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}},
			{Address: addresses[1], Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}},
		},
		HostStates: []model.HostState{{Address: addresses[0], State: "down"}, {Address: addresses[1], State: "up"}},
	}
	changes := Diff(baseline, current, false)
	var portClosure, hostDown bool
	for _, change := range changes {
		if change.Key == "port|edge.example|tcp|443" && change.New == "not-open" {
			portClosure = true
		}
		if change.Key == "host|"+addresses[0] && change.New == "down" {
			hostDown = true
		}
	}
	if !portClosure || !hostDown {
		t.Fatalf("DNS sibling changes = %#v; want live-sibling closure and down-host transition", changes)
	}
}

func TestHostDiscoveryDownIsScopedToItsProtocol(t *testing.T) {
	address := "192.0.2.12"
	scopes := []model.Scope{
		{Target: address, Protocol: "tcp", Ports: "22"},
		{Target: address, Protocol: "udp", Ports: "53"},
	}
	baseline := model.Snapshot{
		Scopes: scopes,
		Units: []model.Unit{
			{Target: address, Protocol: "tcp", Addresses: []string{address}, Ports: []model.PortState{{Port: 22, State: "open"}}},
			{Target: address, Protocol: "udp", Addresses: []string{address}, Ports: []model.PortState{{Port: 53, State: "open"}}},
		},
		HostStates: []model.HostState{{Address: address, State: "up"}},
	}
	current := model.Snapshot{
		Scopes: scopes,
		Units:  []model.Unit{{Target: address, Protocol: "tcp", Addresses: []string{address}, Ports: []model.PortState{{Port: 22, State: "open"}}}},
		Hosts: []model.HostObservation{{Address: address, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{
			{Protocol: "tcp", Status: "up", StatusReason: "syn-ack", DiscoveryState: "up"},
			{Protocol: "udp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"},
		}}},
		HostStates: []model.HostState{{Address: address, State: "up"}},
	}
	completed := scan("protocol-discovery", current)
	if MarkIncompleteScan(&completed) {
		t.Fatalf("a completed per-protocol up/down result was marked incomplete: %s", completed.Error)
	}
	if changes := Diff(baseline, current, false); len(changes) != 0 {
		t.Fatalf("one protocol's host-discovery result changed another protocol's baseline: %#v", changes)
	}
}

func TestHostStateChangesRespectCIDRIntersectionScope(t *testing.T) {
	old := model.Snapshot{
		Scopes:     []model.Scope{{Target: "192.0.2.0/30", Protocol: "tcp", Ports: "1-65535"}},
		HostStates: []model.HostState{{Address: "192.0.2.2", State: "up"}},
	}
	current := model.Snapshot{
		Scopes:     []model.Scope{{Target: "192.0.2.0/30", Protocol: "tcp", Ports: "1-65535"}},
		HostStates: []model.HostState{{Address: "192.0.2.2", State: "down"}},
	}

	changes := Diff(old, current, true)
	if len(changes) != 1 || changes[0].Kind != "host" || changes[0].Target != "192.0.2.2" {
		t.Fatalf("CIDR-scoped host transition was filtered out: %#v", changes)
	}
}

func TestCompletedNaabuNoDiscoveryCanEstablishBaseline(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "completed-empty-naabu", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	address := "192.0.2.31"
	current := model.Snapshot{
		Scopes: []model.Scope{{Target: address, Protocol: "tcp", Ports: "1-65535"}},
		Units:  []model.Unit{{Target: address, Protocol: "tcp", Addresses: []string{address}}},
		Hosts: []model.HostObservation{{
			Address: address, Status: "unknown", StatusReason: "scan-complete",
			Protocols: []model.ProtocolObservation{{
				Protocol: "tcp", Status: "unknown", StatusReason: "scan-complete",
				ScannedPorts: "1-65535", ScannedPortCount: 65535,
			}},
		}},
	}
	completed := scan("completed-empty-naabu", current)
	if MarkIncompleteScan(&completed) {
		t.Fatal("completed full-range Naabu discovery was marked incomplete")
	}
	events, err := e.Success(ctx, job, completed)
	if err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("completed empty Naabu scan did not establish baseline: events=%#v err=%v", events, err)
	}
	state, err := defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || len(state.Baseline.Units) != 1 || len(state.Baseline.Units[0].Ports) != 0 {
		t.Fatalf("completed empty Naabu scan baseline = %#v", state.Baseline)
	}
}

func TestIncompleteProtocolDoesNotSuppressCompleteProtocolChanges(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "protocol-partial", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := model.Snapshot{
		Scopes: []model.Scope{
			{Target: "192.0.2.20", Protocol: "tcp", Ports: "80,443"},
			{Target: "192.0.2.20", Protocol: "udp", Ports: "53"},
		},
		Units: []model.Unit{
			{Target: "192.0.2.20", Protocol: "tcp", Addresses: []string{"192.0.2.20"}, Ports: []model.PortState{{Port: 80, State: "open"}, {Port: 443, State: "open"}}},
			{Target: "192.0.2.20", Protocol: "udp", Addresses: []string{"192.0.2.20"}, Ports: []model.PortState{{Port: 53, State: "open"}}},
		},
	}
	if events, err := e.Success(ctx, job, scan("protocol-baseline", baseline)); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline setup: %#v, %v", events, err)
	}

	partial := model.Snapshot{
		Scopes: baseline.Scopes,
		Units: []model.Unit{{
			Target: "192.0.2.20", Protocol: "tcp", Addresses: []string{"192.0.2.20"},
			Ports: []model.PortState{{Port: 80, State: "open"}},
		}},
		Hosts: []model.HostObservation{{
			Address: "192.0.2.20", Status: "up", StatusReason: "syn-ack",
			Protocols: []model.ProtocolObservation{
				{Protocol: "tcp", Status: "up", StatusReason: "syn-ack", ScannedPorts: "80,443"},
				{Protocol: "udp", Status: "unreachable", StatusReason: "nmap-host-timeout", ScannedPorts: "53"},
			},
		}},
	}
	partialScan := scan("protocol-partial", partial)
	if !MarkIncompleteScan(&partialScan) || partialScan.Status != "incomplete" {
		t.Fatalf("partial scan was not marked incomplete: %#v", partialScan)
	}
	events, err := e.Success(ctx, job, partialScan)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Type != "changes-detected" || events[1].Type != "scan-incomplete" {
		t.Fatalf("partial scan events = %#v", events)
	}
	if len(events[0].Changes) != 1 || events[0].Changes[0].Key != "port|192.0.2.20|tcp|443" {
		t.Fatalf("partial scan changes = %#v, want only complete TCP removal", events[0].Changes)
	}
	state, err := defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Incidents["port|192.0.2.20|tcp|443"]; !ok {
		t.Fatalf("complete TCP change did not open incident: %#v", state.Incidents)
	}
	if _, ok := state.Incidents["port|192.0.2.20|udp|53"]; ok {
		t.Fatal("incomplete UDP removal created an incident")
	}
	if state.Baseline == nil || len(state.Baseline.Units) != 2 || len(state.Baseline.Units[0].Ports) != 2 || len(state.Baseline.Units[1].Ports) != 1 {
		t.Fatalf("incomplete protocol evidence changed the baseline: %#v", state.Baseline)
	}
}

func TestIncompleteDNSScanKeepsHealthySiblingAdditions(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "dns-siblings", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "80,443", ServiceDetection: true}},
		DNS:    map[string][]string{"edge.example": {"192.0.2.1", "192.0.2.2"}},
		Units: []model.Unit{{
			Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"},
			Ports: []model.PortState{{Port: 443, State: "open", Evidence: []string{"192.0.2.1", "192.0.2.2"}}},
		}},
	}
	baseline.Normalize()
	if events, err := e.Success(ctx, job, scan("dns-baseline", baseline)); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline setup: %#v, %v", events, err)
	}

	partial := model.Snapshot{
		Scopes: baseline.Scopes,
		DNS:    baseline.DNS,
		Units: []model.Unit{{
			Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"},
			Ports: []model.PortState{{Port: 80, State: "open", Service: "http", Evidence: []string{"192.0.2.1"}}},
		}},
		Hosts: []model.HostObservation{{Address: "192.0.2.2", Status: "down", StatusReason: "no-response"}},
	}
	partial.Normalize()
	events, err := e.Success(ctx, job, scan("dns-partial", partial))
	if err != nil || len(events) != 2 || events[0].Type != "changes-detected" || events[1].Type != "scan-incomplete" {
		t.Fatalf("partial DNS scan events: %#v, err=%v", events, err)
	}
	if len(events[0].Changes) != 1 || events[0].Changes[0].Key != "port|edge.example|tcp|80" {
		t.Fatalf("partial DNS changes = %#v, want only healthy port addition", events[0].Changes)
	}
	state, err := defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Incidents["port|edge.example|tcp|80"]; !ok {
		t.Fatalf("healthy sibling addition did not open an incident: %#v", state.Incidents)
	}
	if _, ok := state.Incidents["port|edge.example|tcp|443"]; ok {
		t.Fatal("removal protected by incomplete DNS sibling was reported")
	}
	if _, ok := state.Incidents["service|edge.example|tcp|80"]; ok {
		t.Fatal("service change with merged/incomplete evidence was reported")
	}
	if state.Baseline == nil || state.Baseline.Units[0].Ports[0].Port != 443 {
		t.Fatalf("partial DNS scan advanced baseline: %#v", state.Baseline)
	}
}

func TestUnresolvedDNSKeepsOtherTargetsActiveAndProtectsMissingTarget(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "mixed-resolution", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := model.Snapshot{
		Scopes: []model.Scope{
			{Target: "edge.example", Protocol: "tcp", Ports: "443"},
			{Target: "192.0.2.9", Protocol: "tcp", Ports: "22,80"},
		},
		DNS: map[string][]string{"edge.example": {"192.0.2.1"}},
		Units: []model.Unit{
			{Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: []model.PortState{{Port: 443, State: "open", Evidence: []string{"192.0.2.1"}}}},
			{Target: "192.0.2.9", Protocol: "tcp", Addresses: []string{"192.0.2.9"}, Ports: []model.PortState{{Port: 22, State: "open"}, {Port: 80, State: "open"}}},
		},
	}
	if events, err := e.Success(ctx, job, scan("resolution-baseline", baseline)); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline setup: %#v, %v", events, err)
	}

	partial := model.Snapshot{
		Scopes:         baseline.Scopes,
		TargetFailures: []model.TargetCoverageFailure{{Target: "edge.example", Reason: "lookup-failed"}},
		Units:          []model.Unit{{Target: "192.0.2.9", Protocol: "tcp", Addresses: []string{"192.0.2.9"}, Ports: []model.PortState{{Port: 80, State: "open"}, {Port: 443, State: "open"}}}},
		Hosts:          []model.HostObservation{{Address: "192.0.2.9", Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}}},
	}
	partialScan := scan("resolution-partial", partial)
	if !MarkIncompleteScan(&partialScan) || partialScan.Status != "incomplete" || !strings.Contains(partialScan.Error, "edge.example") {
		t.Fatalf("unresolved DNS target was not retained as incomplete evidence: %#v", partialScan)
	}
	events, err := e.Success(ctx, job, partialScan)
	if err != nil || len(events) != 2 || events[0].Type != "changes-detected" || events[1].Type != "scan-incomplete" {
		t.Fatalf("mixed partial scan events: %#v, %v", events, err)
	}
	if len(events[0].Changes) != 2 {
		t.Fatalf("resolvable target changes = %#v, want its port removal and addition", events[0].Changes)
	}
	state, err := defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Incidents["port|edge.example|tcp|443"]; ok {
		t.Fatal("unresolved DNS target created a false port-closure incident")
	}
	if _, ok := state.Incidents["port|192.0.2.9|tcp|22"]; !ok {
		t.Fatal("fully scanned target's port closure was suppressed by another target's DNS failure")
	}
	if _, ok := state.Incidents["port|192.0.2.9|tcp|443"]; !ok {
		t.Fatal("fully scanned target's port addition was not reported")
	}
	if state.Baseline == nil {
		t.Fatal("incomplete scan removed the baseline")
	}
	var unresolvedBaselineRetained bool
	for _, unit := range state.Baseline.Units {
		if unit.Target == "edge.example" && len(unit.Ports) == 1 && unit.Ports[0].Port == 443 {
			unresolvedBaselineRetained = true
		}
	}
	if !unresolvedBaselineRetained {
		t.Fatalf("incomplete scan changed the unresolved target baseline: %#v", state.Baseline)
	}

	recovered := model.Snapshot{
		Scopes: baseline.Scopes,
		DNS:    map[string][]string{"edge.example": {"192.0.2.1"}},
		Units: []model.Unit{
			{Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.1"}},
			{Target: "192.0.2.9", Protocol: "tcp", Addresses: []string{"192.0.2.9"}, Ports: []model.PortState{{Port: 80, State: "open"}, {Port: 443, State: "open"}}},
		},
		Hosts: []model.HostObservation{
			{Address: "192.0.2.1", Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}},
			{Address: "192.0.2.9", Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}},
		},
	}
	recoveredScan := scan("resolution-recovered", recovered)
	if MarkIncompleteScan(&recoveredScan) {
		t.Fatalf("resolved DNS scan remained incomplete: %s", recoveredScan.Error)
	}
	events, err = e.Success(ctx, job, recoveredScan)
	if err != nil {
		t.Fatal(err)
	}
	state, err = defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Incidents["port|edge.example|tcp|443"]; !ok {
		t.Fatal("a later complete scan did not compare the recovered DNS target")
	}
	for _, event := range events {
		if event.Type == "scan-incomplete" {
			t.Fatalf("recovered scan still emitted incomplete event: %#v", events)
		}
	}
}

func TestIncompleteDNSScanPreservesPendingHealthyAdditionUntilCompleteConfirmation(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "dns-pending", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 2}}

	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "80,443"}},
		DNS:    map[string][]string{"edge.example": {"192.0.2.1", "192.0.2.2"}},
		Units: []model.Unit{{
			Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"},
			Ports: []model.PortState{{Port: 443, State: "open", Evidence: []string{"192.0.2.1", "192.0.2.2"}}},
		}},
	}
	baseline.Normalize()
	if events, err := e.Success(ctx, job, scan("dns-pending-baseline", baseline)); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline setup: %#v, %v", events, err)
	}

	// The first complete scan observes a new port only on the healthy address.
	// With two confirmations it must remain pending rather than opening an
	// incident immediately.
	first := baseline
	first.Units = []model.Unit{{
		Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"},
		Ports: []model.PortState{
			{Port: 80, State: "open", Evidence: []string{"192.0.2.1"}},
			{Port: 443, State: "open", Evidence: []string{"192.0.2.1", "192.0.2.2"}},
		},
	}}
	first.Normalize()
	if events, err := e.Success(ctx, job, scan("dns-pending-first", first)); err != nil {
		t.Fatalf("first complete scan: %v", err)
	} else if len(events) != 0 {
		t.Fatalf("first confirmation emitted events before the threshold: %#v", events)
	}
	state, err := defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := state.Pending["port|edge.example|tcp|80"]
	if !ok || pending.Count != 1 {
		t.Fatalf("pending healthy addition = %#v, want one confirmation", state.Pending)
	}

	// The sibling address is now incomplete and the pending port is absent from
	// the partial evidence. The pending addition must survive this scan, while
	// the baseline port remains protected from a false removal.
	partial := model.Snapshot{
		Scopes: baseline.Scopes,
		DNS:    baseline.DNS,
		Units: []model.Unit{{
			Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"},
			Ports: []model.PortState{{Port: 443, State: "open", Evidence: []string{"192.0.2.1"}}},
		}},
		Hosts: []model.HostObservation{{Address: "192.0.2.2", Status: "down", StatusReason: "no-response"}},
	}
	partial.Normalize()
	if events, err := e.Success(ctx, job, scan("dns-pending-partial", partial)); err != nil || len(events) != 1 || events[0].Type != "scan-incomplete" {
		t.Fatalf("partial DNS scan: %#v, %v", events, err)
	}
	state, err = defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if pending, ok = state.Pending["port|edge.example|tcp|80"]; !ok || pending.Count != 1 {
		t.Fatalf("partial scan changed pending addition = %#v, want one confirmation", state.Pending)
	}
	if _, ok := state.Incidents["port|edge.example|tcp|443"]; ok {
		t.Fatal("partial sibling loss opened a removal incident")
	}

	// A later complete observation of the same healthy addition supplies the
	// second confirmation and opens exactly one incident.
	final := first
	final.Units = append([]model.Unit(nil), first.Units...)
	final.Normalize()
	events, err := e.Success(ctx, job, scan("dns-pending-final", final))
	if err != nil {
		t.Fatalf("final complete scan: %v", err)
	}
	if len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != "port|edge.example|tcp|80" {
		t.Fatalf("final confirmation events = %#v, want one port change", events)
	}
	state, err = defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Pending["port|edge.example|tcp|80"]; ok {
		t.Fatal("confirmed addition remained pending")
	}
	if _, ok := state.Incidents["port|edge.example|tcp|80"]; !ok {
		t.Fatal("confirmed healthy addition did not open an incident")
	}
}

func TestEveryUnsuccessfulScanEmitsAnOutcomeEvent(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "outcomes", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}

	failed := scan("failed", snapshot(""))
	failed.Status = "failed"
	failed.Error = "nmap failed: permission denied"
	events, err := e.Failure(ctx, job.Name, failed)
	if err != nil || len(events) != 1 || events[0].Type != "scan-failure" {
		t.Fatalf("failed scan event = %#v, err=%v", events, err)
	}
	if events[0].Message != "Scan failed: nmap failed: permission denied" {
		t.Fatalf("failed scan message = %q", events[0].Message)
	}

	canceled := scan("canceled", snapshot(""))
	canceled.Status = "canceled"
	canceled.Error = "scan canceled"
	events, err = e.Failure(ctx, job.Name, canceled)
	if err != nil || len(events) != 1 || events[0].Type != "scan-canceled" {
		t.Fatalf("canceled scan event = %#v, err=%v", events, err)
	}
	if events[0].Message != "Scan canceled: scan canceled" {
		t.Fatalf("canceled scan message = %q", events[0].Message)
	}

	timedOut := scan("timed-out", snapshot(""))
	timedOut.Status = "timed_out"
	timedOut.Error = "scan exceeded its timeout"
	events, err = e.Failure(ctx, job.Name, timedOut)
	if err != nil || len(events) != 1 || events[0].Type != "scan-failure" {
		t.Fatalf("timed-out scan event = %#v, err=%v", events, err)
	}
	if events[0].Message != "Scan timed out: scan exceeded its timeout" {
		t.Fatalf("timed-out scan message = %q", events[0].Message)
	}

	state, err := defaultTenant(db).State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if state.ConsecutiveFailures != 2 {
		t.Fatalf("unexpected failure count after canceled and timed-out scans: %d", state.ConsecutiveFailures)
	}
}

func TestFinalizeManagedScanRecordsInitialBaselineScanMetadata(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	record, err := defaultTenant(db).CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "managed", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Ports: "443", Mode: "connect"}, Timing: "balanced", Timeout: config.Duration(time.Minute),
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	}))
	if err != nil {
		t.Fatal(err)
	}
	e := Engine{Store: db}
	current := scan("managed-baseline", snapshot("open"))
	current.Snapshot.Hosts = []model.HostObservation{{Address: "192.0.2.1", Status: "up"}}
	current.Snapshot.Normalize()
	current.JobID, current.JobRevision, current.Job = record.ID, record.Revision, record.Job.Name
	current.ConfigHash = record.Job.SecurityHash()
	if _, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &current, nil); err != nil {
		t.Fatal(err)
	}
	stored, err := defaultTenant(db).GetScan(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.BaselineScanID != current.ID || stored.BaselineConfigHash != current.ConfigHash {
		t.Fatalf("initial baseline metadata = %#v, want scan=%s hash=%s", stored, current.ID, current.ConfigHash)
	}
	if stored.Comparison != model.ScanComparisonBaselineEstablished {
		t.Fatalf("initial baseline comparison = %q, want %q", stored.Comparison, model.ScanComparisonBaselineEstablished)
	}
	if exists, err := defaultTenant(db).BaselineHostProjectionExists(ctx, record.ID); err != nil || !exists {
		t.Fatalf("automatic baseline did not maintain host projection: exists=%v err=%v", exists, err)
	}
}

func TestFinalizeManagedScanMarksIncompleteAndKeepsReachableChanges(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	job := config.NormalizeJob(config.Job{
		Name: "partial-managed", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1", "192.0.2.2"},
		TCP: &config.Protocol{Ports: "80,443", Mode: "connect"}, Timing: "balanced", Timeout: config.Duration(time.Minute),
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	})
	record, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	baseSnapshot := model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "80,443"}, {Target: "192.0.2.2", Protocol: "tcp", Ports: "80,443"}},
		Units: []model.Unit{
			{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}},
			{Target: "192.0.2.2", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}},
		},
	}
	e := Engine{Store: db}
	baseline := scan("partial-managed-baseline", baseSnapshot)
	baseline.JobID, baseline.JobRevision, baseline.Job, baseline.ConfigHash = record.ID, record.Revision, record.Job.Name, record.Job.SecurityHash()
	if _, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &baseline, nil); err != nil {
		t.Fatal(err)
	}
	current := scan("partial-managed-current", model.Snapshot{
		Scopes: baseSnapshot.Scopes,
		Units:  []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}, {Port: 80, State: "open"}}}},
		Hosts:  []model.HostObservation{{Address: "192.0.2.2", Status: "down", StatusReason: "no-response"}},
	})
	current.JobID, current.JobRevision, current.Job, current.ConfigHash = record.ID, record.Revision, record.Job.Name, record.Job.SecurityHash()
	events, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &current, nil)
	if err != nil || len(events) != 2 || events[0].Type != "changes-detected" || events[1].Type != "scan-incomplete" {
		t.Fatalf("partial managed finalization = %#v, err=%v", events, err)
	}
	stored, err := defaultTenant(db).GetScan(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "incomplete" || !strings.Contains(stored.Error, "192.0.2.2") {
		t.Fatalf("stored partial status = %#v", stored)
	}
	if len(stored.Changes) != 1 || stored.Changes[0].Target != "192.0.2.1" || stored.Changes[0].Port != 80 {
		t.Fatalf("stored reachable changes = %#v", stored.Changes)
	}
	state, err := defaultTenant(db).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || len(state.Baseline.Units) != 2 || state.Baseline.Units[0].Ports[0].State != "open" {
		t.Fatalf("partial scan advanced baseline: %#v", state.Baseline)
	}
}

func TestFinalizeManagedScanPersistsTheChangeSetAppliedByEngine(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	record, err := defaultTenant(db).CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "fingerprint-consistency", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Ports: "443", Mode: "connect", ServiceDetection: true}, Timing: "balanced", Timeout: config.Duration(time.Minute),
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	}))
	if err != nil {
		t.Fatal(err)
	}
	withService := func(service string) model.Snapshot {
		var hostService *model.ServiceObservation
		if service != "" {
			hostService = &model.ServiceObservation{Product: service, Method: "probed"}
		}
		snapshot := model.Snapshot{
			Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "443", ServiceDetection: true}},
			Units:  []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: service}}}},
			Hosts: []model.HostObservation{{
				Address: "192.0.2.1", Status: "up",
				Protocols: []model.ProtocolObservation{{
					Protocol: "tcp", ScannedPorts: "443", ScannedPortCount: 1, ServiceDetection: true,
					Ports: []model.PortObservation{{Port: 443, State: "open", Service: hostService}},
				}},
			}},
		}
		snapshot.Normalize()
		return snapshot
	}
	e := Engine{Store: db}
	baseline := model.Scan{ID: "fingerprint-baseline", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: withService("")}
	if _, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &baseline, nil); err != nil {
		t.Fatal(err)
	}
	current := model.Scan{ID: "fingerprint-learned", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: withService("nginx")}
	events, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &current, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("fingerprint learning emitted a change event: %#v", events)
	}
	stored, err := defaultTenant(db).GetScan(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Changes) != 0 {
		t.Fatalf("persisted changes = %#v, want the same empty set acted on by the engine", stored.Changes)
	}
	exists, err := defaultTenant(db).BaselineHostProjectionExists(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("engine baseline mutation did not maintain the baseline host projection")
	}
	projected, err := defaultTenant(db).GetBaselineHost(ctx, record.ID, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if projected.Host.Address != "192.0.2.1" {
		t.Fatalf("baseline projection host = %#v", projected.Host)
	}
}

func TestFingerprintStabilizesWithoutBlockingPortBaseline(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 1}}
	withService := func(service string) model.Snapshot {
		return model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "443", ServiceDetection: true}}, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: service}}}}}
	}
	if events, _ := e.Success(ctx, job, scan("1", withService("service A"))); len(events) != 0 {
		t.Fatalf("unexpected event %#v", events)
	}
	events, err := e.Success(ctx, job, scan("2", withService("service B")))
	if err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("fingerprint blocked baseline: %#v %v", events, err)
	}
	state, _ := defaultTenant(db).State(ctx, "test")
	if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 443); got != "" {
		t.Fatalf("unstable service entered baseline: %q", got)
	}
	if events, _ = e.Success(ctx, job, scan("3", withService("service B"))); len(events) != 0 {
		t.Fatalf("fingerprint learning generated alert: %#v", events)
	}
	state, _ = defaultTenant(db).State(ctx, "test")
	if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 443); got != "service B" {
		t.Fatalf("stable service not learned: %q", got)
	}
}

func TestNewPortServiceFingerprintDoesNotAlternate(t *testing.T) {
	scopes := []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535", ServiceDetection: true}}
	base := model.Snapshot{Scopes: scopes, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open", Service: "ssh"}}}}}
	current := model.Snapshot{Scopes: scopes, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open", Service: "ssh"}, {Port: 8080, State: "open", Service: "http"}}}}}
	state := model.JobState{Baseline: &base, BaselineConfigHash: "hash", Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{}, FingerprintCandidates: map[string]model.ValueCount{}}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 1}}
	portKey := "port|192.0.2.1|tcp|8080"
	serviceKey := fingerprintKey("192.0.2.1", "tcp", 8080)
	history := make([][]model.Event, 0, 6)
	var transitions []string
	for i := 1; i <= 6; i++ {
		events, _, err := processSuccessWithChanges(&state, job, scan(fmt.Sprintf("scan-%d", i), current))
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, events)
		for _, event := range events {
			for _, change := range event.Changes {
				transitions = append(transitions, fmt.Sprintf("scan%d:%s[%s]", i, event.Type, change.Key))
			}
		}
	}
	for _, transition := range transitions {
		if strings.Contains(transition, "changes-recovered") {
			t.Fatalf("unchanged new-port fingerprint alternated between detected and recovered: %v", transitions)
		}
	}
	for i, events := range history {
		if i == 0 {
			if len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 2 || events[0].Changes[0].Key != portKey || events[0].Changes[1].Key != serviceKey {
				t.Fatalf("new port and service were not reported together: %v", transitions)
			}
		} else if len(events) != 0 {
			t.Fatalf("scan %d emitted events for an unchanged observation: %v", i+1, transitions)
		}
	}
	if _, ok := state.Incidents[serviceKey]; !ok {
		t.Fatalf("service incident is not open after identical scans: %#v", state.Incidents)
	}
	if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 8080); got != "" {
		t.Fatalf("new-port fingerprint entered the baseline without an operator decision: %q", got)
	}
	if _, ok := state.FingerprintCandidates[serviceKey]; ok {
		t.Fatalf("new-port fingerprint was tracked as a learning candidate: %#v", state.FingerprintCandidates)
	}
}

func TestNewPortServiceIncidentsAcceptInEitherOrder(t *testing.T) {
	for _, order := range []string{"port-then-service", "service-while-port-open"} {
		t.Run(order, func(t *testing.T) {
			ctx := context.Background()
			db, err := store.Open(storetest.FreshPath(t))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			record, err := defaultTenant(db).CreateJob(ctx, config.NormalizeJob(config.Job{
				Name: "new-port-" + order, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
				TCP: &config.Protocol{Ports: "22,8080", Mode: "connect", ServiceDetection: true}, Timing: "balanced", Timeout: config.Duration(time.Minute),
				Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 1},
			}))
			if err != nil {
				t.Fatal(err)
			}
			e := Engine{Store: db}
			observe := func(ports ...model.PortState) model.Snapshot {
				snapshot := model.Snapshot{
					Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "22,8080", ServiceDetection: true}},
					Units:  []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: ports}},
				}
				snapshot.Normalize()
				return snapshot
			}
			sequence := 0
			run := func(snapshot model.Snapshot) []model.Event {
				t.Helper()
				sequence++
				current := model.Scan{ID: fmt.Sprintf("%s-%d", order, sequence), JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: snapshot, FinishedAt: time.Now().UTC()}
				events, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &current, nil)
				if err != nil {
					t.Fatal(err)
				}
				return events
			}
			accept := func(key string) []model.Event {
				t.Helper()
				events, err := defaultTenant(db).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, key, store.AuditEntry{Action: "incident.accepted", Detail: record.ID + ":" + key})
				if err != nil {
					t.Fatalf("accept %s: %v", key, err)
				}
				return events
			}
			ssh := model.PortState{Port: 22, State: "open", Service: "ssh"}
			http := model.PortState{Port: 8080, State: "open", Service: "http"}
			portKey := "port|192.0.2.1|tcp|8080"
			serviceKey := "service|192.0.2.1|tcp|8080"

			run(observe(ssh))
			if events := run(observe(ssh)); len(events) != 1 || events[0].Type != "baseline-complete" {
				t.Fatalf("baseline setup: %#v", events)
			}
			if events := run(observe(ssh, http)); len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 2 {
				t.Fatalf("new port with service: %#v", events)
			}

			switch order {
			case "port-then-service":
				if events := accept(portKey); len(events) != 1 || len(events[0].Changes) != 1 || events[0].Changes[0].Key != portKey {
					t.Fatalf("port acceptance also approved its fingerprint: %#v", events)
				}
				// A scan between the two decisions must keep the reported service
				// incident open rather than relearning it and emitting a false
				// recovery for a fingerprint that never changed.
				if events := run(observe(ssh, http)); len(events) != 1 || events[0].Type != "changes-reminder" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != serviceKey {
					t.Fatalf("scan between acceptances emitted events: %#v", events)
				}
				state, err := defaultTenant(db).RuntimeState(ctx, record.ID)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := state.Incidents[serviceKey]; !ok {
					t.Fatalf("service incident closed before the operator accepted it: %#v", state.Incidents)
				}
				if events := accept(serviceKey); len(events) != 1 || len(events[0].Changes) != 1 || events[0].Changes[0].Key != serviceKey {
					t.Fatalf("service acceptance: %#v", events)
				}
			case "service-while-port-open":
				events := accept(serviceKey)
				if len(events) != 1 || len(events[0].Changes) != 2 || events[0].Changes[0].Key != portKey || events[0].Changes[1].Key != serviceKey {
					t.Fatalf("service acceptance did not include its new port: %#v", events)
				}
			}

			for i := 0; i < 3; i++ {
				if events := run(observe(ssh, http)); len(events) != 0 {
					t.Fatalf("accepted observation emitted events: %#v", events)
				}
			}
			state, err := defaultTenant(db).RuntimeState(ctx, record.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(state.Incidents) != 0 || len(state.Pending) != 0 {
				t.Fatalf("accepted observation left runtime findings: incidents=%#v pending=%#v", state.Incidents, state.Pending)
			}
			if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 8080); got != "http" {
				t.Fatalf("accepted service = %q, want http", got)
			}
			if positivePortCount(*state.Baseline) != 2 {
				t.Fatalf("accepted baseline = %#v", state.Baseline)
			}
		})
	}
}

func TestClosedFingerprintedPortProducesSingleIncidentAndAction(t *testing.T) {
	for _, action := range []string{"accept", "suppress"} {
		t.Run(action, func(t *testing.T) {
			ctx := context.Background()
			db, err := store.Open(storetest.FreshPath(t))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			tenant := defaultTenant(db)
			record, err := tenant.CreateJob(ctx, config.NormalizeJob(config.Job{
				Name: "closed-fingerprinted-port-" + action, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
				TCP: &config.Protocol{Ports: "22,443", Mode: "connect", ServiceDetection: true}, Timeout: config.Duration(time.Minute),
				Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 1},
			}))
			if err != nil {
				t.Fatal(err)
			}
			engine := Engine{Store: db}
			sequence := 0
			ssh := model.PortState{Port: 22, State: "open", Service: "ssh"}
			https := model.PortState{Port: 443, State: "open", Service: "https"}
			observe := func(ports ...model.PortState) model.Snapshot {
				snapshot := model.Snapshot{
					Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "22,443", ServiceDetection: true}},
					Units:  []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: ports}},
				}
				snapshot.Normalize()
				return snapshot
			}
			run := func(snapshot model.Snapshot) []model.Event {
				t.Helper()
				sequence++
				scan := model.Scan{
					ID: fmt.Sprintf("%s-%d", action, sequence), JobID: record.ID, JobRevision: record.Revision,
					Job: record.Job.Name, Status: "success", ConfigHash: record.Job.SecurityHash(),
					Snapshot: snapshot, FinishedAt: time.Now().UTC(),
				}
				events, err := engine.FinalizeManagedScan(ctx, record.ID, record.Job, &scan, nil)
				if err != nil {
					t.Fatal(err)
				}
				return events
			}
			portKey := "port|192.0.2.1|tcp|443"
			serviceKey := "service|192.0.2.1|tcp|443"
			for i := 0; i < 2; i++ {
				events := run(observe(ssh, https))
				if i == 0 && len(events) != 0 {
					t.Fatalf("first baseline sample emitted events: %#v", events)
				}
				if i == 1 && (len(events) != 1 || events[0].Type != "baseline-complete") {
					t.Fatalf("baseline completion = %#v", events)
				}
			}
			if events := run(observe(ssh)); len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != portKey {
				t.Fatalf("closing a fingerprinted port should open only one port incident, got %#v (service key %s)", events, serviceKey)
			}
			state, err := tenant.RuntimeState(ctx, record.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(state.Incidents) != 1 {
				t.Fatalf("closing one port opened %d incidents: %#v", len(state.Incidents), state.Incidents)
			}
			if _, ok := state.Incidents[portKey]; !ok {
				t.Fatalf("port incident missing: %#v", state.Incidents)
			}
			if _, ok := state.Incidents[serviceKey]; ok {
				t.Fatalf("closed port also opened a service incident: %#v", state.Incidents)
			}

			audit := store.AuditEntry{Action: "incident.action", Detail: "closed fingerprinted port"}
			switch action {
			case "accept":
				events, err := tenant.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, portKey, audit)
				if err != nil {
					t.Fatal(err)
				}
				if len(events) != 1 || events[0].Type != "incident-accepted" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != portKey {
					t.Fatalf("accepting the port closure affected unrelated evidence: %#v", events)
				}
				state, err = tenant.RuntimeState(ctx, record.ID)
				if err != nil {
					t.Fatal(err)
				}
				if len(state.Incidents) != 0 || baselineService(*state.Baseline, "192.0.2.1", "tcp", 443) != "" {
					t.Fatalf("accepted port closure left stale incident or service baseline: %#v", state)
				}
				if events := run(observe(ssh)); len(events) != 0 {
					t.Fatalf("accepted closed-port observation re-alerted: %#v", events)
				}
			case "suppress":
				events, err := tenant.SuppressIncidentWithAudit(ctx, record.ID, record.Job.Name, portKey, audit)
				if err != nil {
					t.Fatal(err)
				}
				if len(events) != 1 || events[0].Type != "incident-suppressed" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != portKey {
					t.Fatalf("suppressing the port closure affected unrelated evidence: %#v", events)
				}
				if events := run(observe(ssh)); len(events) != 0 {
					t.Fatalf("one-scan suppression did not hide the next scan: %#v", events)
				}
				events = run(observe(ssh))
				if len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != portKey {
					t.Fatalf("suppressed port closure did not reopen by itself: %#v", events)
				}
				state, err = tenant.RuntimeState(ctx, record.ID)
				if err != nil {
					t.Fatal(err)
				}
				if len(state.Incidents) != 1 {
					t.Fatalf("suppressed closure reopened unrelated incidents: %#v", state.Incidents)
				}
			}
		})
	}
}

func TestClosingPortRetiresOpenServiceIncidentWithoutRecovery(t *testing.T) {
	scopes := []model.Scope{{Target: "192.0.2.9", Protocol: "tcp", Ports: "22,443", ServiceDetection: true}}
	baseline := model.Snapshot{
		Scopes: scopes,
		Units: []model.Unit{{Target: "192.0.2.9", Protocol: "tcp", Ports: []model.PortState{
			{Port: 22, State: "open", Service: "ssh | OpenSSH"},
			{Port: 443, State: "open", Service: "https | nginx"},
		}}},
	}
	changed := model.Snapshot{
		Scopes: scopes,
		Units: []model.Unit{{Target: "192.0.2.9", Protocol: "tcp", Ports: []model.PortState{
			{Port: 22, State: "open", Service: "ssh | OpenSSH"},
			{Port: 443, State: "open", Service: "https | apache"},
		}}},
	}
	closed := model.Snapshot{
		Scopes: scopes,
		Units: []model.Unit{{Target: "192.0.2.9", Protocol: "tcp", Ports: []model.PortState{
			{Port: 22, State: "open", Service: "ssh | OpenSSH"},
		}}},
	}
	baseline.Normalize()
	changed.Normalize()
	closed.Normalize()
	state := model.JobState{
		Baseline: &baseline, BaselineConfigHash: "hash",
		Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{},
		Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{},
		FingerprintCandidates: map[string]model.ValueCount{},
	}
	job := config.Job{Name: "closing-port", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	serviceKey := "service|192.0.2.9|tcp|443"
	portKey := "port|192.0.2.9|tcp|443"

	events, _, err := processSuccessWithChanges(&state, job, scan("service-change", changed))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != serviceKey {
		t.Fatalf("service change = %#v, %v", events, err)
	}
	if _, ok := state.Incidents[serviceKey]; !ok {
		t.Fatalf("service incident was not opened: %#v", state.Incidents)
	}
	partialClosed := closed
	partialClosed.TargetFailures = []model.TargetCoverageFailure{{Target: "192.0.2.9", Reason: "test timeout"}}
	events, _, err = processSuccessWithChanges(&state, job, scan("partial-close", partialClosed))
	if err != nil || len(events) != 1 || events[0].Type != "scan-incomplete" {
		t.Fatalf("incomplete scan should defer service retirement, events=%#v err=%v", events, err)
	}
	if _, ok := state.Incidents[serviceKey]; !ok {
		t.Fatalf("incomplete scan retired a service incident without complete evidence: %#v", state.Incidents)
	}

	events, changes, err := processSuccessWithChanges(&state, job, scan("port-closed", closed))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != portKey {
		t.Fatalf("closing the port should report only its closure, events=%#v changes=%#v err=%v", events, changes, err)
	}
	if _, ok := state.Incidents[serviceKey]; ok {
		t.Fatalf("closed-port service incident was not retired: %#v", state.Incidents)
	}

	// Reopening the port with the original fingerprint matches the baseline;
	// the retired apache finding must not be reported as a service recovery.
	events, _, err = processSuccessWithChanges(&state, job, scan("port-reopened", baseline))
	if err != nil || len(events) != 1 || events[0].Type != "changes-recovered" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != portKey {
		t.Fatalf("reopening the closed port should recover only its port incident, events=%#v err=%v", events, err)
	}
}

func TestOpenServiceIncidentRecoversWhenBaselineFingerprintReturns(t *testing.T) {
	scopes := []model.Scope{{Target: "192.0.2.9", Protocol: "tcp", Ports: "443", ServiceDetection: true}}
	baseline := model.Snapshot{Scopes: scopes, Units: []model.Unit{{Target: "192.0.2.9", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: "https | nginx"}}}}}
	changed := model.Snapshot{Scopes: scopes, Units: []model.Unit{{Target: "192.0.2.9", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: "https | apache"}}}}}
	baseline.Normalize()
	changed.Normalize()
	state := model.JobState{
		Baseline: &baseline, BaselineConfigHash: "hash",
		Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{},
		Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{},
		FingerprintCandidates: map[string]model.ValueCount{},
	}
	job := config.Job{Name: "service-return", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	key := "service|192.0.2.9|tcp|443"

	if events, _, err := processSuccessWithChanges(&state, job, scan("service-change", changed)); err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("service change = %#v, %v", events, err)
	}
	events, _, err := processSuccessWithChanges(&state, job, scan("service-return", baseline))
	if err != nil || len(events) != 1 || events[0].Type != "changes-recovered" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != key {
		t.Fatalf("return to baseline fingerprint should recover the service incident: %#v, %v", events, err)
	}
}

func TestClosedPortRetiresPendingAndSuppressedServiceFindings(t *testing.T) {
	serviceKey := "service|192.0.2.9|tcp|443"
	orphanSuppressionKey := "service|192.0.2.9|tcp|444"
	serviceChange := model.Change{Key: serviceKey, Kind: "service", Target: "192.0.2.9", Protocol: "tcp", Port: 443, Old: "https | nginx", New: "https | apache"}
	state := model.JobState{
		Pending:           map[string]model.Pending{serviceKey: {Change: serviceChange, Count: 1}},
		Incidents:         map[string]model.Incident{serviceKey: {Change: serviceChange}},
		Suppressed:        map[string]int{serviceKey: 1, orphanSuppressionKey: 1},
		SuppressedChanges: map[string]model.Change{serviceKey: serviceChange},
	}
	closed := model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.9", Protocol: "tcp", Ports: "443", ServiceDetection: true}},
		Units:  []model.Unit{{Target: "192.0.2.9", Protocol: "tcp"}},
	}
	positive := model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.9", Protocol: "tcp", Ports: "443", ServiceDetection: true}},
		Units:  []model.Unit{{Target: "192.0.2.9", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open|filtered"}}}},
	}
	closed.Normalize()
	positive.Normalize()

	retireClosedPortServiceChanges(&state, positive)
	if _, ok := state.Incidents[serviceKey]; !ok {
		t.Fatal("open|filtered port incorrectly retired its service incident")
	}

	retireClosedPortServiceChanges(&state, closed)
	if _, ok := state.Pending[serviceKey]; ok {
		t.Fatalf("closed-port service confirmation remained pending: %#v", state.Pending)
	}
	if _, ok := state.Incidents[serviceKey]; ok {
		t.Fatalf("closed-port service incident remained open: %#v", state.Incidents)
	}
	if _, ok := state.Suppressed[serviceKey]; ok {
		t.Fatalf("closed-port service suppression remained: %#v", state.Suppressed)
	}
	if _, ok := state.SuppressedChanges[serviceKey]; ok {
		t.Fatalf("closed-port suppressed service change remained: %#v", state.SuppressedChanges)
	}
	if _, ok := state.Suppressed[orphanSuppressionKey]; ok {
		t.Fatalf("orphaned closed-port service suppression remained: %#v", state.Suppressed)
	}
}

// Accepting a new port alone leaves its service for a separate decision.
// Suppressing the service incident, or one scan that recovers it because
// service detection returned no fingerprint, must not let fingerprint
// learning write that service into the baseline: it was reported, not
// unstable while the baseline was established.
func TestAcceptedPortServiceIsNotLearnedAfterSuppressionOrRecovery(t *testing.T) {
	for _, path := range []string{"suppress", "recover"} {
		for _, samples := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s-samples-%d", path, samples), func(t *testing.T) {
				ctx := context.Background()
				db, err := store.Open(storetest.FreshPath(t))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				tenant := defaultTenant(db)
				record, err := tenant.CreateJob(ctx, config.NormalizeJob(config.Job{
					Name: fmt.Sprintf("accepted-port-%s-%d", path, samples), Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
					TCP: &config.Protocol{Ports: "22,8080", Mode: "connect", ServiceDetection: true}, Timeout: config.Duration(time.Minute),
					Baseline: config.Baseline{Samples: samples}, Change: config.Change{Confirmations: 1},
				}))
				if err != nil {
					t.Fatal(err)
				}
				// This test exercises fingerprint acceptance, not reminder cadence.
				// Keep its reminder behavior explicit so scans can run back-to-back.
				everyScan := store.IncidentReminderCadenceEveryScan
				if _, err := tenant.SetIncidentReminderSettings(ctx, nil, &everyScan, store.AuditEntry{}); err != nil {
					t.Fatal(err)
				}
				e := Engine{Store: db}
				sequence := 0
				run := func(ports ...model.PortState) []string {
					t.Helper()
					sequence++
					snapshot := model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "22,8080", ServiceDetection: true}}, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: ports}}}
					snapshot.Normalize()
					current := model.Scan{ID: fmt.Sprint("scan-", sequence), JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: snapshot, FinishedAt: time.Now().UTC()}
					events, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &current, nil)
					if err != nil {
						t.Fatal(err)
					}
					var changes []string
					for _, event := range events {
						if len(event.Changes) == 0 {
							changes = append(changes, event.Type)
						}
						for _, change := range event.Changes {
							changes = append(changes, event.Type+" "+change.Key+" "+change.Old+"->"+change.New)
						}
					}
					return changes
				}
				baseline8080 := func() string {
					t.Helper()
					state, err := tenant.RuntimeState(ctx, record.ID)
					if err != nil {
						t.Fatal(err)
					}
					return baselineService(*state.Baseline, "192.0.2.1", "tcp", 8080)
				}
				expect := func(label string, got []string, want ...string) {
					t.Helper()
					if strings.Join(got, "\n") != strings.Join(want, "\n") {
						t.Fatalf("%s: changes = %q, want %q", label, got, want)
					}
				}
				audit := store.AuditEntry{Action: "incident.action", Detail: "accepted port"}
				ssh := model.PortState{Port: 22, State: "open", Service: "ssh | OpenSSH | 8.0"}
				http := model.PortState{Port: 8080, State: "open", Service: "http"}
				serviceKey := "service|192.0.2.1|tcp|8080"
				reported := "changes-detected " + serviceKey + " not-open->http"

				for i := 1; i < samples; i++ {
					expect("baseline sample", run(ssh))
				}
				expect("baseline", run(ssh), "baseline-complete")
				expect("new port", run(ssh, http), "changes-detected port|192.0.2.1|tcp|8080 not-open->open", reported)
				if _, err := tenant.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, "port|192.0.2.1|tcp|8080", audit); err != nil {
					t.Fatal(err)
				}
				switch path {
				case "suppress":
					if _, err := tenant.SuppressIncidentWithAudit(ctx, record.ID, record.Job.Name, serviceKey, audit); err != nil {
						t.Fatal(err)
					}
					expect("suppressed scan", run(ssh, http))
				case "recover":
					expect("scan without fingerprint", run(ssh, model.PortState{Port: 8080, State: "open"}), "changes-recovered "+serviceKey+" http->not-open")
				}
				if got := baseline8080(); got != "" {
					t.Fatalf("service of the accepted port entered the baseline without a decision: %q", got)
				}
				expect("fingerprint reported again", run(ssh, http), reported)
				for i := 0; i < 2; i++ {
					expect("unchanged observation", run(ssh, http), "changes-reminder "+serviceKey+" not-open->http")
				}
				if got := baseline8080(); got != "" {
					t.Fatalf("service of the accepted port entered the baseline without a decision: %q", got)
				}
				if _, err := tenant.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, serviceKey, audit); err != nil {
					t.Fatal(err)
				}
				if got := baseline8080(); got != "http" {
					t.Fatalf("accepted service = %q, want http", got)
				}
				expect("accepted service", run(ssh, http))
			})
		}
	}
}

// Suppressing a service change on a port whose baseline has a fingerprint
// defers it for one scan and then reports it again.
func TestSuppressedServiceChangeOnFingerprintedPortReopens(t *testing.T) {
	scopes := []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "22", ServiceDetection: true}}
	base := model.Snapshot{Scopes: scopes, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open", Service: "ssh | OpenSSH | 8.0"}}}}}
	current := model.Snapshot{Scopes: scopes, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open", Service: "ssh | OpenSSH | 9.0"}}}}}
	state := model.JobState{Baseline: &base, BaselineConfigHash: "hash", Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{}, FingerprintCandidates: map[string]model.ValueCount{}}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	key := fingerprintKey("192.0.2.1", "tcp", 22)
	events, _, err := processSuccessWithChanges(&state, job, scan("scan-1", current))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("service change = %#v, %v", events, err)
	}
	// Suppress 1 scan, as the incident action does.
	state.Suppressed[key] = 1
	state.SuppressedChanges[key] = state.Incidents[key].Change
	delete(state.Incidents, key)
	if events, _, err = processSuccessWithChanges(&state, job, scan("scan-2", current)); err != nil || len(events) != 0 {
		t.Fatalf("suppressed scan = %#v, %v", events, err)
	}
	events, _, err = processSuccessWithChanges(&state, job, scan("scan-3", current))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != key {
		t.Fatalf("change was not reported again after the suppression: %#v, %v", events, err)
	}
	if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 22); got != "ssh | OpenSSH | 8.0" {
		t.Fatalf("baseline service = %q", got)
	}
}

// A new baseline records what the scans observed, so no service decision on
// the previous baseline survives it, whether it replaces that baseline or is
// merged into it for a changed scope.
func TestEstablishedBaselineEndsServiceDecisions(t *testing.T) {
	scopes := []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "8080", ServiceDetection: true}}
	key := fingerprintKey("192.0.2.1", "tcp", 8080)
	observed := model.Snapshot{Scopes: scopes, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 8080, State: "open", Service: "http"}}}}}
	for _, merge := range []bool{false, true} {
		old := model.Snapshot{Scopes: scopes, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 8080, State: "open"}}}}}
		state := model.JobState{Baseline: &old, FingerprintCandidates: map[string]model.ValueCount{}, ServiceDecisionRequired: map[string]bool{key: true}}
		events := advanceCandidate(&state, scan("established", observed), 1, merge)
		if len(events) != 1 || state.ServiceDecisionRequired != nil {
			t.Fatalf("merge=%t: new baseline kept service decisions: events=%#v decisions=%#v", merge, events, state.ServiceDecisionRequired)
		}
		if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 8080); got != "http" {
			t.Fatalf("merge=%t: established service = %q, want http", merge, got)
		}
	}
}

// A runtime state written before accepted ports were recorded has no record
// of the port that was accepted alone. A suppressed service change on such a
// port still stays under normal comparison instead of being learned.
func TestSuppressedServiceChangeIsNotLearnedWithoutAcceptedPortRecord(t *testing.T) {
	scopes := []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "8080", ServiceDetection: true}}
	base := model.Snapshot{Scopes: scopes, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 8080, State: "open"}}}}}
	current := model.Snapshot{Scopes: scopes, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 8080, State: "open", Service: "http"}}}}}
	key := fingerprintKey("192.0.2.1", "tcp", 8080)
	change := model.Change{Key: key, Kind: "service", Severity: "warning", Target: "192.0.2.1", Protocol: "tcp", Port: 8080, Old: "not-open", New: "http"}
	state := model.JobState{Baseline: &base, BaselineConfigHash: "hash", Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{key: 1}, SuppressedChanges: map[string]model.Change{key: change}, FingerprintCandidates: map[string]model.ValueCount{}}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	if events, _, err := processSuccessWithChanges(&state, job, scan("scan-1", current)); err != nil || len(events) != 0 {
		t.Fatalf("suppressed scan = %#v, %v", events, err)
	}
	if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 8080); got != "" {
		t.Fatalf("suppressed service was learned into the baseline: %q", got)
	}
	events, _, err := processSuccessWithChanges(&state, job, scan("scan-2", current))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != key {
		t.Fatalf("change was not reported again after the suppression: %#v, %v", events, err)
	}
}

// learningSnapshot observes 192.0.2.1:443 with the given service. When
// complete, 192.0.2.2:443 answers with a fixed fingerprint; otherwise that
// address times out, which makes the scan incomplete while the 192.0.2.1
// target keeps complete coverage.
func learningSnapshot(service string, complete bool) model.Snapshot {
	snapshot := model.Snapshot{
		Scopes: []model.Scope{
			{Target: "192.0.2.1", Protocol: "tcp", Ports: "443", ServiceDetection: true},
			{Target: "192.0.2.2", Protocol: "tcp", Ports: "443", ServiceDetection: true},
		},
		Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: []model.PortState{{Port: 443, State: "open", Service: service, Evidence: []string{"192.0.2.1"}}}}},
	}
	if complete {
		snapshot.Units = append(snapshot.Units, model.Unit{Target: "192.0.2.2", Protocol: "tcp", Addresses: []string{"192.0.2.2"}, Ports: []model.PortState{{Port: 443, State: "open", Service: "http | nginx | 1.25 |", Evidence: []string{"192.0.2.2"}}}})
	} else {
		snapshot.Hosts = []model.HostObservation{{Address: "192.0.2.2", Status: "unreachable", StatusReason: "nmap-host-timeout"}}
	}
	snapshot.Normalize()
	return snapshot
}

// eventLines describes events and their changes for comparison in tests.
func eventLines(events []model.Event, skip ...string) []string {
	var lines []string
	for _, event := range events {
		if slices.Contains(skip, event.Type) {
			continue
		}
		lines = append(lines, event.Type)
		for _, change := range event.Changes {
			lines = append(lines, "  "+change.Key+" "+change.Old+" -> "+change.New)
		}
	}
	return lines
}

// A baseline port without a fingerprint learns it from complete scans
// without an alert (#529). An incomplete scan leaves that learning to the next
// complete scan, so it must not report the fingerprint either: the service
// incident it opened would stop the fingerprint from ever being learned.
func TestIncompleteScanDoesNotReportLearnableFingerprint(t *testing.T) {
	const (
		fingerprint = "http | nginx | 1.25 |"
		key         = "service|192.0.2.1|tcp|443"
	)
	for _, managed := range []bool{false, true} {
		for _, tc := range []struct{ samples, confirmations int }{{1, 1}, {2, 1}, {1, 2}, {2, 2}} {
			t.Run(fmt.Sprintf("managed-%t-samples-%d-confirmations-%d", managed, tc.samples, tc.confirmations), func(t *testing.T) {
				ctx := context.Background()
				db, err := store.Open(storetest.FreshPath(t))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				tenant := defaultTenant(db)
				e := Engine{Store: db}
				job := config.Job{Name: "test", Baseline: config.Baseline{Samples: tc.samples}, Change: config.Change{Confirmations: tc.confirmations}}
				var record store.JobRecord
				if managed {
					record, err = tenant.CreateJob(ctx, config.NormalizeJob(config.Job{
						Name: "learning", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1", "192.0.2.2"},
						TCP: &config.Protocol{Ports: "443", Mode: "connect", ServiceDetection: true}, Timeout: config.Duration(time.Minute),
						Baseline: job.Baseline, Change: job.Change,
					}))
					if err != nil {
						t.Fatal(err)
					}
				}
				sequence := 0
				var last model.Scan
				run := func(snapshot model.Snapshot) []string {
					t.Helper()
					sequence++
					last = scan(fmt.Sprint("scan-", sequence), snapshot)
					var events []model.Event
					var err error
					if managed {
						last.JobID, last.JobRevision, last.Job, last.ConfigHash = record.ID, record.Revision, record.Job.Name, record.Job.SecurityHash()
						events, err = e.FinalizeManagedScan(ctx, record.ID, record.Job, &last, nil)
					} else {
						events, err = e.Success(ctx, job, last)
					}
					if err != nil {
						t.Fatal(err)
					}
					return eventLines(events)
				}
				runtime := func() model.JobState {
					t.Helper()
					var state model.JobState
					var err error
					if managed {
						state, err = tenant.RuntimeState(ctx, record.ID)
					} else {
						state, err = tenant.State(ctx, job.Name)
					}
					if err != nil {
						t.Fatal(err)
					}
					return state
				}
				expect := func(label string, got []string, want ...string) {
					t.Helper()
					if strings.Join(got, "\n") != strings.Join(want, "\n") {
						t.Fatalf("%s: events = %q, want %q", label, got, want)
					}
				}

				for i := 1; i < tc.samples; i++ {
					expect("baseline sample", run(learningSnapshot("", true)))
				}
				expect("baseline", run(learningSnapshot("", true)), "baseline-complete")
				candidates := fmt.Sprint(runtime().FingerprintCandidates)

				// As many incomplete scans as a change needs to be confirmed.
				for i := 1; i <= tc.confirmations; i++ {
					expect(fmt.Sprint("incomplete scan ", i), run(learningSnapshot(fingerprint, false)), "scan-incomplete")
					state := runtime()
					if _, open := state.Incidents[key]; open {
						t.Fatalf("incomplete scan %d opened a service incident for a learnable fingerprint: %#v", i, state.Incidents)
					}
					if pending, ok := state.Pending[key]; ok {
						t.Fatalf("incomplete scan %d left a pending service change: %#v", i, pending)
					}
					if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 443); got != "" {
						t.Fatalf("incomplete scan %d learned the fingerprint: %q", i, got)
					}
					if got := fmt.Sprint(state.FingerprintCandidates); got != candidates {
						t.Fatalf("incomplete scan %d changed fingerprint candidates: %s, want %s", i, got, candidates)
					}
					if managed {
						stored, err := tenant.GetScan(ctx, last.ID)
						if err != nil {
							t.Fatal(err)
						}
						if stored.Status != "incomplete" || len(stored.Changes) != 0 {
							t.Fatalf("stored incomplete scan = status %q changes %#v, want no changes", stored.Status, stored.Changes)
						}
					}
				}

				// Complete scans then learn the fingerprint without an event.
				for i := 1; i <= tc.samples; i++ {
					if got := baselineService(*runtime().Baseline, "192.0.2.1", "tcp", 443); got != "" {
						t.Fatalf("fingerprint learned after %d of %d complete scans: %q", i-1, tc.samples, got)
					}
					expect(fmt.Sprint("complete scan ", i), run(learningSnapshot(fingerprint, true)))
				}
				state := runtime()
				if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 443); got != fingerprint {
					t.Fatalf("complete scans did not learn the fingerprint: %q", got)
				}
				if len(state.Incidents) != 0 || len(state.Pending) != 0 {
					t.Fatalf("learning left findings: incidents=%#v pending=%#v", state.Incidents, state.Pending)
				}
				expect("learned fingerprint", run(learningSnapshot(fingerprint, true)))
			})
		}
	}
}

// Deferring learnable fingerprints must not hide a service change that a
// complete scan reports. An incomplete scan still reports it when the port's
// own target completed, exactly as a complete scan does.
func TestIncompleteScanReportsServiceChangesExcludedFromLearning(t *testing.T) {
	const (
		fingerprint = "http | nginx | 1.25 |"
		key         = "service|192.0.2.1|tcp|443"
	)
	withoutPort := learningSnapshot("", true)
	withoutPort.Units = withoutPort.Units[1:]
	reported := model.Change{Key: key, Kind: "service", Severity: "warning", Target: "192.0.2.1", Protocol: "tcp", Port: 443, Old: "not-open", New: fingerprint}
	for _, tc := range []struct {
		name     string
		baseline model.Snapshot
		prepare  func(*model.JobState)
		want     []string
		open     bool
	}{
		{name: "fingerprinted port", baseline: learningSnapshot("http | nginx | 1.24 |", true), want: []string{"changes-detected", "  " + key + " http | nginx | 1.24 | -> " + fingerprint}, open: true},
		{name: "new port", baseline: withoutPort, want: []string{"changes-detected", "  port|192.0.2.1|tcp|443 not-open -> open", "  " + key + " not-open -> " + fingerprint}, open: true},
		{name: "service decision required", baseline: learningSnapshot("", true), prepare: func(state *model.JobState) {
			state.ServiceDecisionRequired = map[string]bool{key: true}
		}, want: []string{"changes-detected", "  " + key + " not-open -> " + fingerprint}, open: true},
		{name: "open service incident", baseline: learningSnapshot("", true), prepare: func(state *model.JobState) {
			state.Incidents[key] = model.Incident{Change: reported, ScanID: "earlier"}
		}, open: true},
		{name: "suppressed service change", baseline: learningSnapshot("", true), prepare: func(state *model.JobState) {
			state.Suppressed[key] = 1
			state.SuppressedChanges[key] = reported
		}},
	} {
		for _, complete := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s-complete-%t", tc.name, complete), func(t *testing.T) {
				baseline := cloneSnapshot(tc.baseline)
				state := model.JobState{Baseline: &baseline, BaselineConfigHash: "hash", Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{}, FingerprintCandidates: map[string]model.ValueCount{}}
				if tc.prepare != nil {
					tc.prepare(&state)
				}
				job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
				events, _, err := processSuccessWithChanges(&state, job, scan("scan", learningSnapshot(fingerprint, complete)))
				if err != nil {
					t.Fatal(err)
				}
				if got := eventLines(events, "scan-incomplete"); strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
					t.Fatalf("events = %q, want %q", got, tc.want)
				}
				if _, open := state.Incidents[key]; open != tc.open {
					t.Fatalf("service incident open = %t, want %t: %#v", open, tc.open, state.Incidents)
				}
				if got, want := baselineService(*state.Baseline, "192.0.2.1", "tcp", 443), baselineService(tc.baseline, "192.0.2.1", "tcp", 443); got != want {
					t.Fatalf("baseline service = %q, want %q", got, want)
				}
			})
		}
	}
}
