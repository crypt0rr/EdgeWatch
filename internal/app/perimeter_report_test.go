package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/addrspace"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// perimeterFixture is an application on a fresh database with the default
// deployment budgets, no target exclusions, and a clock the test sets.
type perimeterFixture struct {
	app  *App
	db   *store.Store
	ts   *store.TenantStore
	logs *bytes.Buffer
}

func newPerimeterFixture(t *testing.T) perimeterFixture {
	t.Helper()
	db := storetest.OpenFresh(t)
	logs := &bytes.Buffer{}
	a := &App{Store: db, Config: &config.Config{}, Logger: slog.New(slog.NewTextHandler(logs, nil))}
	return perimeterFixture{app: a, db: db, ts: defaultTenant(db), logs: logs}
}

// setClock makes now the application's current time.
func (f perimeterFixture) setClock(now time.Time) {
	f.app.clock = func() time.Time { return now }
}

// secondUnit adds the unit secondTenantID and returns its store.
func (f perimeterFixture) secondUnit(t *testing.T) *store.TenantStore {
	t.Helper()
	ctx := context.Background()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := f.db.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Second','second',?,?)`, secondTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	scope, err := f.db.TenantScopeByID(ctx, secondTenantID)
	if err != nil {
		t.Fatal(err)
	}
	return f.db.Tenant(scope)
}

// perimeterJob is an hourly job that scans TCP ports 22 and 443 of targets
// with Nmap.
func perimeterJob(name string, targets ...string) config.Job {
	return config.Job{
		Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: targets, MaxExpandedHosts: 256,
		TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "22,443", Mode: "connect"},
		Timeout: config.Duration(time.Minute),
	}
}

func createPerimeterJob(t *testing.T, ts *store.TenantStore, job config.Job, enabled bool) store.JobRecord {
	t.Helper()
	record, err := ts.CreateJobWithEnabled(context.Background(), job, enabled)
	if err != nil {
		t.Fatalf("create %s: %v", job.Name, err)
	}
	return record
}

// declarePerimeter declares values under kind and returns the IDs of the
// unit's ranges by value.
func declarePerimeter(t *testing.T, ts *store.TenantStore, kind string, values ...string) map[string]string {
	t.Helper()
	ctx := context.Background()
	entries := make([]store.PerimeterEntry, 0, len(values))
	for _, value := range values {
		entries = append(entries, store.PerimeterEntry{Kind: kind, Value: value})
	}
	if _, err := ts.DeclarePerimeterSeeds(ctx, entries, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	seeds, err := ts.ListPerimeterSeeds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, seed := range seeds {
		ids[seed.Value] = seed.ID
	}
	return ids
}

// editStoredJob changes the stored definition of a job, as an older binary
// or a later rule could have left it.
func editStoredJob(t *testing.T, db *store.Store, jobID string, edit func(definition map[string]any)) {
	t.Helper()
	ctx := context.Background()
	var raw []byte
	if err := db.DB.QueryRowContext(ctx, `SELECT definition_json FROM jobs WHERE id=?`, jobID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	definition := map[string]any{}
	if err := json.Unmarshal(raw, &definition); err != nil {
		t.Fatal(err)
	}
	edit(definition)
	edited, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=?`, string(edited), jobID); err != nil {
		t.Fatal(err)
	}
}

func (f perimeterFixture) report(t *testing.T, ts *store.TenantStore) PerimeterReport {
	t.Helper()
	report, err := f.app.PerimeterReport(context.Background(), ts)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func (f perimeterFixture) detail(t *testing.T, ts *store.TenantStore, id string) PerimeterRangeDetail {
	t.Helper()
	detail, err := f.app.PerimeterRangeDetail(context.Background(), ts, id)
	if err != nil {
		t.Fatal(err)
	}
	return detail
}

func perimeterMonitorNamed(t *testing.T, monitors []PerimeterMonitorRef, name string) PerimeterMonitorRef {
	t.Helper()
	for _, monitor := range monitors {
		if monitor.Name == name {
			return monitor
		}
	}
	t.Fatalf("no monitor %s in %+v", name, monitors)
	return PerimeterMonitorRef{}
}

func perimeterRangeValued(t *testing.T, ranges []PerimeterRange, value string) PerimeterRange {
	t.Helper()
	for _, r := range ranges {
		if r.Value == value {
			return r
		}
	}
	t.Fatalf("no range %s in %+v", value, ranges)
	return PerimeterRange{}
}

// suggestionsOf returns the suggestions of one mode.
func suggestionsOf(detail PerimeterRangeDetail, mode string) []PerimeterSuggestion {
	var out []PerimeterSuggestion
	for _, suggestion := range detail.Suggestions {
		if suggestion.Mode == mode {
			out = append(out, suggestion)
		}
	}
	return out
}

// coalescedSuggestionsOf returns the bounded alternative of one mode.
func coalescedSuggestionsOf(detail PerimeterRangeDetail, mode string) []PerimeterSuggestion {
	var out []PerimeterSuggestion
	for _, suggestion := range detail.CoalescedSuggestions {
		if suggestion.Mode == mode {
			out = append(out, suggestion)
		}
	}
	return out
}

// The presets are the console's own defaults, so a suggested monitor scans
// what a monitor created in the console scans.
func TestPerimeterPresetsMatchTheConsoleDefaults(t *testing.T) {
	t.Parallel()
	want := []struct {
		mode     string
		bucket   int
		cap      uint64
		protocol PerimeterProtocol
		json     string
	}{
		// defaultTCP() in src/job-form.ts.
		{"full_tcp", perimeterFullTCP, 0, PerimeterProtocol{Protocol: "tcp", Engine: "naabu_nmap", Ports: "1-65535", Mode: "connect", ServiceDetection: false, ProfileID: "00000000-0000-0000-0000-000000000014"},
			`{"protocol":"tcp","engine":"naabu_nmap","ports":"1-65535","mode":"connect","service_detection":false,"profile_id":"00000000-0000-0000-0000-000000000014"}`},
		// defaultSelectedTCP() in src/pages/MonitorSetup.tsx.
		{"selected_tcp", perimeterAnyTCP, 4096, PerimeterProtocol{Protocol: "tcp", Engine: "nmap", Ports: "22,443", Mode: "connect", ServiceDetection: false},
			`{"protocol":"tcp","engine":"nmap","ports":"22,443","mode":"connect","service_detection":false}`},
		{"udp", perimeterUDP, 1024, PerimeterProtocol{Protocol: "udp", Engine: "nmap", Ports: "53,123,161,500,1194,4500", ServiceDetection: true},
			`{"protocol":"udp","engine":"nmap","ports":"53,123,161,500,1194,4500","service_detection":true}`},
	}
	if len(perimeterPresets) != len(want) {
		t.Fatalf("presets = %+v", perimeterPresets)
	}
	for index, preset := range perimeterPresets {
		if preset.mode != want[index].mode || preset.bucket != want[index].bucket || preset.cap != want[index].cap || preset.protocol != want[index].protocol {
			t.Errorf("preset %d = %+v, want %+v", index, preset, want[index])
		}
		raw, err := json.Marshal(preset.protocol)
		if err != nil || string(raw) != want[index].json {
			t.Errorf("preset %s encodes as %s, %v; want %s", preset.mode, raw, err, want[index].json)
		}
	}
	if store.BuiltinNaabuProfileID != want[0].protocol.ProfileID {
		t.Fatalf("the built-in Naabu profile is %s", store.BuiltinNaabuProfileID)
	}
}

// A unit without declared ranges gets an empty overview, with empty lists
// rather than null, and the limits it would apply.
func TestPerimeterReportOfAnEmptyUnit(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	f.setClock(now)
	createPerimeterJob(t, f.ts, perimeterJob("edge", "198.51.100.0/28"), true)
	report := f.report(t, f.ts)
	if !report.GeneratedAt.Equal(now) {
		t.Fatalf("generated at %v, want %v", report.GeneratedAt, now)
	}
	want := PerimeterLimits{MaxJobHosts: 65_536, MaxProbeCount: 5_000_000, MaxNaabuProbeCount: 20_000_000, MaxRanges: 1024, MaxEntriesPerRequest: 256}
	if report.Limits != want {
		t.Fatalf("limits = %+v, want %+v", report.Limits, want)
	}
	if report.Totals != (PerimeterTotals{}) || report.OutsideTruncated {
		t.Fatalf("totals of an empty unit = %+v", report.Totals)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, list := range []string{`"ranges":[]`, `"monitors":[]`, `"outside":[]`} {
		if !strings.Contains(string(raw), list) {
			t.Errorf("the empty overview %s lacks %s", raw, list)
		}
	}
}

// Every state, in the order a scheduled run meets its checks, with every
// failing check among the reasons. Only covering monitors count as coverage.
func TestPerimeterReportClassifiesEveryMonitorState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24")
	full := func(job config.Job) config.Job {
		job.TCP.Ports = "1-65535"
		return job
	}
	limited := func(job config.Job, hosts int) config.Job {
		job.MaxExpandedHosts = hosts
		return job
	}
	highCost := full(perimeterJob("high-cost", "198.51.100.0/25"))
	highCost.AllowHighCost = true
	tests := []struct {
		job     config.Job
		enabled bool
		want    []string
	}{
		{perimeterJob("covering", "198.51.100.0/28"), true, nil},
		// The console stores a monitor saved with its schedule off as
		// disabled.
		{perimeterJob("schedule-off", "198.51.100.16/28"), false, []string{"paused"}},
		{perimeterJob("invalid", "198.51.100.32/28"), true, []string{"invalid_config"}},
		// 128 addresses at 65,535 ports exceed the 5,000,000 Nmap probes.
		{full(perimeterJob("over-budget", "198.51.100.128/25")), true, []string{"over_budget"}},
		// The same work within the high-cost ceiling scans.
		{highCost, true, nil},
		{limited(perimeterJob("over-expansion", "198.51.100.0/24"), 128), true, []string{"over_expansion"}},
		// The scanner counts overlapping targets again: 192 addresses.
		{limited(perimeterJob("overlapping", "198.51.100.0/25", "198.51.100.0/26"), 150), true, []string{"over_expansion"}},
		// scanner.max_job_hosts caps the job's own limit.
		{limited(perimeterJob("ceiling", "198.51.100.0/24"), 1000), true, []string{"over_expansion"}},
		{perimeterJob("excluded", "203.0.113.0/28"), true, []string{"excluded_target"}},
		{limited(full(perimeterJob("everything", "192.0.2.0/24")), 64), false, []string{"paused", "over_budget", "over_expansion", "excluded_target"}},
		// An invalid job has no estimate, so neither the budget nor the
		// expansion is checked, but its targets are.
		{perimeterJob("paused-invalid", "203.0.113.0/30"), false, []string{"paused", "invalid_config", "excluded_target"}},
	}
	records := map[string]store.JobRecord{}
	for _, test := range tests {
		records[test.job.Name] = createPerimeterJob(t, f.ts, test.job, test.enabled)
	}
	for _, name := range []string{"invalid", "paused-invalid"} {
		editStoredJob(t, f.db, records[name].ID, func(definition map[string]any) {
			definition["TCP"].(map[string]any)["Ports"] = "22-x"
		})
	}
	// The store refuses to save a job with an excluded target, so the
	// exclusions change after the jobs were saved.
	f.app.Config.Scanner.TargetExclusions = []string{"203.0.113.2", "192.0.2.200"}
	f.app.Config.Scanner.MaxJobHosts = ptrTo(200)

	report := f.report(t, f.ts)
	if len(report.Monitors) != len(tests) {
		t.Fatalf("monitors = %d, want %d", len(report.Monitors), len(tests))
	}
	for _, test := range tests {
		monitor := perimeterMonitorNamed(t, report.Monitors, test.job.Name)
		wantState := "covering"
		if len(test.want) > 0 {
			wantState = test.want[0]
		}
		wantReasons := test.want
		if wantReasons == nil {
			wantReasons = []string{}
		}
		if monitor.State != wantState || !reflect.DeepEqual(monitor.Reasons, wantReasons) || monitor.JobID != records[test.job.Name].ID {
			t.Errorf("%s = %s %v (%s), want %s %v", test.job.Name, monitor.State, monitor.Reasons, monitor.JobID, wantState, wantReasons)
		}
	}
	if report.Totals.CannotScanMonitors != 9 || report.Totals.UnprovenMonitors != 2 {
		t.Fatalf("totals = %+v, want 9 monitors that cannot scan and 2 without successful coverage", report.Totals)
	}
	// Only the two covering monitors cover: 198.51.100.0/25 at full TCP.
	edge := perimeterRangeValued(t, report.Ranges, "198.51.100.0/24")
	if want := (PerimeterCoverage{FullTCP: 128, AnyTCP: 128}); edge.Coverage != want {
		t.Fatalf("coverage = %+v, want %+v", edge.Coverage, want)
	}
	if len(edge.MonitorIDs) != 8 {
		t.Fatalf("monitors touching %s = %v", edge.Value, edge.MonitorIDs)
	}
	logged := f.logs.String()
	if !strings.Contains(logged, "category=invalid_config") || !strings.Contains(logged, "job_id="+records["invalid"].ID) {
		t.Fatalf("an invalid job was not logged: %s", logged)
	}

	// The report never changes a job.
	jobs, err := f.ts.ListJobs(ctx, false)
	if err != nil || len(jobs) != len(tests) {
		t.Fatalf("jobs after the report = %d, %v", len(jobs), err)
	}
	for _, job := range jobs {
		if job.Revision != records[job.Job.Name].Revision || job.Enabled != records[job.Job.Name].Enabled {
			t.Fatalf("the report changed %s", job.Job.Name)
		}
	}
}

// The unit's own budget decides the states, a high-cost monitor counts when
// it fits the unit's ceiling, and the limits show the budget that decided.
func TestPerimeterReportAppliesTheUnitsBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	b := f.secondUnit(t)
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET max_probe_count=100,max_naabu_probe_count=655350,high_cost_ceiling=1000 WHERE id=?`, secondTenantID); err != nil {
		t.Fatal(err)
	}
	wide := func(name string, allowHighCost bool, target string) config.Job {
		job := perimeterJob(name, target)
		job.AllowHighCost = allowHighCost
		job.MaxExpandedHosts = 1024
		return job
	}
	for _, ts := range []*store.TenantStore{f.ts, b} {
		declarePerimeter(t, ts, store.PerimeterKindPrefix, "198.51.100.0/22")
		// 64 addresses at two ports: 128 probes.
		createPerimeterJob(t, ts, wide("wide", false, "198.51.100.0/26"), true)
		createPerimeterJob(t, ts, wide("approved", true, "198.51.100.64/26"), true)
		// 1,024 addresses: 2,048 probes, above B's ceiling.
		createPerimeterJob(t, ts, wide("above-ceiling", true, "198.51.100.0/22"), true)
	}
	states := func(report PerimeterReport) map[string]string {
		got := map[string]string{}
		for _, monitor := range report.Monitors {
			got[monitor.Name] = monitor.State
		}
		return got
	}
	if got := states(f.report(t, f.ts)); !reflect.DeepEqual(got, map[string]string{"wide": "covering", "approved": "covering", "above-ceiling": "covering"}) {
		t.Fatalf("default unit states = %v", got)
	}
	reportB := f.report(t, b)
	if got := states(reportB); !reflect.DeepEqual(got, map[string]string{"wide": "over_budget", "approved": "covering", "above-ceiling": "over_budget"}) {
		t.Fatalf("lowered unit states = %v", got)
	}
	if reportB.Limits.MaxProbeCount != 100 || reportB.Limits.MaxNaabuProbeCount != 655350 {
		t.Fatalf("lowered unit limits = %+v", reportB.Limits)
	}
	if reportB.Totals.CoveredAnyTCP != 64 || reportB.Totals.CannotScanMonitors != 2 {
		t.Fatalf("lowered unit totals = %+v", reportB.Totals)
	}
}

// A covering monitor is stale exactly when the job-silent watchdog would
// call it overdue, measured from its creation, its eligibility or its latest
// success, whichever is latest.
func TestPerimeterReportFlagsStaleMonitorsByTheSilenceRule(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "198.51.100.0/24")
	records := map[string]store.JobRecord{}
	var created time.Time
	for index, name := range []string{"hourly", "weekly", "recent-success", "resumed", "retained-success", "never", "paused"} {
		job := perimeterJob(name, fmt.Sprintf("198.51.100.%d", index+1))
		if name == "weekly" {
			job.Schedule = "0 3 * * 1"
		}
		record := createPerimeterJob(t, f.ts, job, name != "paused")
		records[name] = record
		if record.CreatedAt.After(created) {
			created = record.CreatedAt
		}
	}
	editStoredJob(t, f.db, records["never"].ID, func(definition map[string]any) { definition["Schedule"] = "0 0 30 2 *" })
	success := created.Add(150 * time.Minute)
	if err := f.db.System().SaveScan(ctx, model.Scan{
		ID: "recent-success-scan", JobID: records["recent-success"].ID, JobRevision: 1, Job: "recent-success",
		StartedAt: success.Add(-time.Minute), FinishedAt: success, Status: "success", ConfigHash: records["recent-success"].Job.SecurityHash(),
	}); err != nil {
		t.Fatal(err)
	}
	later := created.Add(165 * time.Minute).Format(time.RFC3339Nano)
	for _, update := range []struct{ column, job string }{{"eligible_at", "resumed"}, {"last_success_at", "retained-success"}} {
		outcome, err := f.db.DB.ExecContext(ctx, `UPDATE job_silence_state SET `+update.column+`=? WHERE job_id=?`, later, records[update.job].ID)
		if err != nil {
			t.Fatal(err)
		}
		if changed, _ := outcome.RowsAffected(); changed != 1 {
			t.Fatalf("no silence state for %s", update.job)
		}
	}
	stale := func(at time.Duration) map[string]string {
		t.Helper()
		f.setClock(created.Add(at))
		got := map[string]string{}
		report := f.report(t, f.ts)
		for _, monitor := range report.Monitors {
			if monitor.Stale {
				got[monitor.Name] = monitor.StaleReason
			}
		}
		// Stale monitors are unproven, and monitors without a successful scan
		// can also be unproven before their silence threshold makes them stale.
		unproven := 0
		for _, monitor := range report.Monitors {
			unprovenState := (perimeterMonitor{ref: monitor}).unproven()
			if unprovenState {
				unproven++
			}
			if monitor.Stale && !unprovenState {
				t.Errorf("stale monitor %s has proven coverage", monitor.Name)
			}
		}
		if report.Totals.UnprovenMonitors != unproven {
			t.Fatalf("unproven monitors = %d, want %d", report.Totals.UnprovenMonitors, unproven)
		}
		return got
	}
	// A new monitor is unproven before its first successful scan, but is not
	// stale before its first scheduled run is overdue.
	if got := stale(10 * time.Minute); !reflect.DeepEqual(got, map[string]string{"never": "schedule never fires"}) {
		t.Fatalf("stale monitors after 10 minutes = %v", got)
	}
	// Three hours on, an hourly monitor without a scan is overdue, while a
	// recent success, eligibility or retained success keeps one current,
	// and a weekly monitor is still within its window. A paused monitor is
	// never flagged.
	if got := stale(3 * time.Hour); !reflect.DeepEqual(got, map[string]string{"hourly": "overdue", "never": "schedule never fires"}) {
		t.Fatalf("stale monitors after 3 hours = %v", got)
	}
	if got := stale(15 * 24 * time.Hour); len(got) != 6 || got["weekly"] != "overdue" {
		t.Fatalf("stale monitors after 15 days = %v", got)
	}
	f.setClock(created.Add(3 * time.Hour))
	report := f.report(t, f.ts)
	if monitor := perimeterMonitorNamed(t, report.Monitors, "recent-success"); monitor.LastSuccessAt == nil || !monitor.LastSuccessAt.Equal(success) {
		t.Fatalf("last success = %v, want %v", monitor.LastSuccessAt, success)
	}
	if monitor := perimeterMonitorNamed(t, report.Monitors, "hourly"); monitor.LastSuccessAt != nil {
		t.Fatalf("a monitor without a scan has a last success %v", monitor.LastSuccessAt)
	}
}

// The stalled-cycle, host-discovery and latest-attempt flags, and which of
// them leave coverage unproven.
func TestPerimeterReportFlagsCoverageThatIsNotProven(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "198.51.100.0/24")
	records := map[string]store.JobRecord{}
	for index, name := range []string{"healthy", "stalled", "discovery", "failed", "incomplete", "recovered", "paused-stalled", "timed-out"} {
		job := perimeterJob(name, fmt.Sprintf("198.51.100.%d", index+1))
		if name == "discovery" {
			job.AssumeAlive = ptrTo(false)
		}
		records[name] = createPerimeterJob(t, f.ts, job, name != "paused-stalled")
	}
	for _, name := range []string{"stalled", "paused-stalled"} {
		record := records[name]
		plan := scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{record.Job.Targets[0]}, Ports: "22", PortCount: 1, Probes: 1}}}
		cycle, err := f.db.System().CreateScanCycle(ctx, store.ScanCycleRecord{
			JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
			ConfigHash: record.Job.SecurityHash(), ExecutionHash: record.Job.ExecutionHash(), Plan: plan,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='stalled' WHERE id=?`, cycle.ID); err != nil {
			t.Fatal(err)
		}
	}
	finished := time.Now().UTC()
	for index, scan := range []struct{ job, status string }{
		{"failed", "failed"}, {"incomplete", "success"}, {"incomplete", "incomplete"}, {"recovered", "failed"}, {"recovered", "success"},
		{"timed-out", "timed_out"},
	} {
		at := finished.Add(time.Duration(index) * time.Second)
		if err := f.db.System().SaveScan(ctx, model.Scan{
			ID: fmt.Sprintf("scan-%d", index), JobID: records[scan.job].ID, JobRevision: 1, Job: scan.job,
			StartedAt: at.Add(-time.Second), FinishedAt: at, Status: scan.status, ConfigHash: records[scan.job].Job.SecurityHash(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	f.setClock(finished.Add(5 * time.Minute))
	report := f.report(t, f.ts)
	type flags struct {
		state          string
		stalled        bool
		discovery      bool
		attempt        string
		hasLastSuccess bool
		unproven       bool
	}
	want := map[string]flags{
		"healthy":    {"covering", false, false, "", false, true},
		"stalled":    {"covering", true, false, "", false, true},
		"discovery":  {"covering", false, true, "", false, true},
		"failed":     {"covering", false, false, "failed", false, true},
		"incomplete": {"covering", false, false, "incomplete", true, true},
		"recovered":  {"covering", false, false, "success", true, false},
		"timed-out":  {"covering", false, false, "timed_out", false, true},
		// The flags belong to covering monitors only.
		"paused-stalled": {"paused", false, false, "", false, false},
	}
	for name, wanted := range want {
		monitor := perimeterMonitorNamed(t, report.Monitors, name)
		got := flags{monitor.State, monitor.StalledCycle, monitor.HostDiscovery, monitor.LastAttemptStatus, monitor.LastSuccessAt != nil, (perimeterMonitor{ref: monitor}).unproven()}
		if got != wanted || monitor.Stale {
			t.Errorf("%s = %+v (stale %v), want %+v", name, got, monitor.Stale, wanted)
		}
	}
	// Covering monitors stay unproven until a successful scan establishes the
	// current scope, and later stalled/failed attempts keep that proof invalid.
	if report.Totals.UnprovenMonitors != 6 || report.Totals.CannotScanMonitors != 1 {
		t.Fatalf("totals = %+v", report.Totals)
	}
	if got := perimeterRangeValued(t, report.Ranges, "198.51.100.0/24").Coverage; got != (PerimeterCoverage{AnyTCP: 7}) {
		t.Fatalf("unproven monitors still cover: %+v", got)
	}
}

func TestPerimeterReportOnlyShowsRecentCheckpointAsInProgress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "198.51.100.0/24")
	record := createPerimeterJob(t, f.ts, perimeterJob("progressing", "198.51.100.10"), true)
	successAt := record.CreatedAt
	if err := f.db.System().SaveScan(ctx, model.Scan{
		ID: "progressing-success", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: successAt, FinishedAt: successAt, Status: "success", ConfigHash: record.Job.SecurityHash(),
	}); err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{Units: []scanner.WorkUnit{
		{Sequence: 0, Protocol: "tcp", Addresses: []string{"198.51.100.10"}, Ports: "22", PortCount: 1, Probes: 1},
		{Sequence: 1, Protocol: "tcp", Addresses: []string{"198.51.100.10"}, Ports: "443", PortCount: 1, Probes: 1},
	}}
	cycleStartedAt := time.Now().UTC()
	cycle, err := f.db.System().CreateScanCycle(ctx, store.ScanCycleRecord{
		JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
		ConfigHash: record.Job.SecurityHash(), ExecutionHash: record.Job.ExecutionHash(), Plan: plan,
		StartedAt: cycleStartedAt, UpdatedAt: cycleStartedAt, ExpiresAt: cycleStartedAt.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := f.db.System().NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.System().ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := f.db.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.System().PauseScanCycle(ctx, cycle.ID, false, "first unit completed"); err != nil {
		t.Fatal(err)
	}
	timeoutAt := time.Now().UTC()
	if err := f.db.System().SaveScan(ctx, model.Scan{
		ID: "progressing-timeout", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: cycleStartedAt, FinishedAt: timeoutAt, Status: "timed_out", ConfigHash: record.Job.SecurityHash(),
		CycleID: cycle.ID, CycleStatus: "paused", Resumable: true, CompletedUnits: 1, TotalUnits: 2,
	}); err != nil {
		t.Fatal(err)
	}
	f.setClock(time.Now().UTC())
	report := f.report(t, f.ts)
	monitor := perimeterMonitorNamed(t, report.Monitors, "progressing")
	if monitor.LastAttemptStatus != "timed_out" || monitor.LastSuccessAt == nil || monitor.ScopeChanged || !monitor.CycleInProgress || monitor.CycleCompletedUnits != 1 || monitor.CycleTotalUnits != 2 || report.Totals.UnprovenMonitors != 0 {
		t.Fatalf("progressing monitor = %+v; want in-progress cycle and proven recent coverage", monitor)
	}
	if report.Totals.UnprovenMonitors != 0 || perimeterRangeValued(t, report.Ranges, "198.51.100.0/24").Coverage.AnyTCP != 1 {
		t.Fatalf("progressing cycle coverage report = %+v; coverage should remain proven", report.Totals)
	}

	// A later timed-out attempt that completes no new unit must not make the
	// old checkpoint look recent just because the cycle is started and paused.
	checkpointAt := timeoutAt.Add(-72 * time.Hour)
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET finished_at=? WHERE cycle_id=? AND status='completed'`, checkpointAt.Format(time.RFC3339Nano), cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	paused, err := f.db.System().PauseScanCycle(ctx, cycle.ID, true, "timed out before the next checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	if paused.NoProgressAttempts != 1 {
		t.Fatalf("no-progress attempts = %d, want 1", paused.NoProgressAttempts)
	}
	noProgressAt := time.Now().UTC()
	if err := f.db.System().SaveScan(ctx, model.Scan{
		ID: "progressing-no-progress-timeout", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: noProgressAt.Add(-time.Minute), FinishedAt: noProgressAt, Status: "timed_out", ConfigHash: record.Job.SecurityHash(),
		CycleID: cycle.ID, CycleStatus: "paused", Resumable: true, CompletedUnits: 1, TotalUnits: 2,
	}); err != nil {
		t.Fatal(err)
	}
	f.setClock(noProgressAt)
	report = f.report(t, f.ts)
	monitor = perimeterMonitorNamed(t, report.Monitors, "progressing")
	if monitor.LastAttemptStatus != "timed_out" || monitor.CycleInProgress || report.Totals.UnprovenMonitors != 1 {
		t.Fatalf("no-progress timeout monitor = %+v; want no in-progress status and unproven coverage", monitor)
	}
}

func createRecentPerimeterProgress(t *testing.T, f perimeterFixture, record store.JobRecord, id string) {
	t.Helper()
	ctx := context.Background()
	startedAt := time.Now().UTC()
	plan := scanner.WorkPlan{Units: []scanner.WorkUnit{
		{Sequence: 0, Protocol: "tcp", Addresses: []string{record.Job.Targets[0]}, Ports: "22", PortCount: 1, Probes: 1},
		{Sequence: 1, Protocol: "tcp", Addresses: []string{record.Job.Targets[0]}, Ports: "443", PortCount: 1, Probes: 1},
	}}
	cycle, err := f.db.System().CreateScanCycle(ctx, store.ScanCycleRecord{
		JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
		ConfigHash: record.Job.SecurityHash(), ExecutionHash: record.Job.ExecutionHash(), Plan: plan,
		StartedAt: startedAt, UpdatedAt: startedAt, ExpiresAt: startedAt.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := f.db.System().NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.System().ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := f.db.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.System().PauseScanCycle(ctx, cycle.ID, false, "first unit completed"); err != nil {
		t.Fatal(err)
	}
	finishedAt := time.Now().UTC()
	if err := f.db.System().SaveScan(ctx, model.Scan{
		ID: id + "-timeout", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: startedAt, FinishedAt: finishedAt, Status: "timed_out", ConfigHash: record.Job.SecurityHash(),
		CycleID: cycle.ID, CycleStatus: "paused", Resumable: true, CompletedUnits: 1, TotalUnits: 2,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPerimeterFirstProgressDoesNotProveCoverage(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "198.51.100.0/24")
	record := createPerimeterJob(t, f.ts, perimeterJob("first-progress", "198.51.100.10"), true)
	createRecentPerimeterProgress(t, f, record, "first-progress")
	f.setClock(time.Now().UTC())

	report := f.report(t, f.ts)
	monitor := perimeterMonitorNamed(t, report.Monitors, "first-progress")
	if monitor.LastSuccessAt != nil || monitor.Stale || monitor.ScopeChanged || !monitor.CycleInProgress || monitor.CycleCompletedUnits != 1 || monitor.CycleTotalUnits != 2 {
		t.Fatalf("first-ever partial cycle = %+v; want recent progress, no success and no stale/scope flag", monitor)
	}
	if report.Totals.UnprovenMonitors != 1 {
		t.Fatalf("first-ever partial cycle has %d unproven monitors, want 1", report.Totals.UnprovenMonitors)
	}
}

func TestPerimeterCoverageProofTracksSecurityScopeHash(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "198.51.100.0/24")
	record := createPerimeterJob(t, f.ts, perimeterJob("scope-proof", "198.51.100.10"), true)
	now := time.Now().UTC()
	if err := f.db.System().SaveScan(ctx, model.Scan{
		ID: "scope-proof-before", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: now.Add(-2 * time.Minute), FinishedAt: now.Add(-time.Minute), Status: "success", ConfigHash: record.Job.SecurityHash(),
	}); err != nil {
		t.Fatal(err)
	}
	f.setClock(now)

	nameAndSchedule := record.Job
	nameAndSchedule.Name = "scope-proof-renamed"
	nameAndSchedule.Schedule = "15 * * * *"
	updated, _, err := f.ts.UpdateJob(ctx, record.ID, record.Revision, nameAndSchedule, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	report := f.report(t, f.ts)
	monitor := perimeterMonitorNamed(t, report.Monitors, nameAndSchedule.Name)
	if monitor.ScopeChanged || report.Totals.UnprovenMonitors != 0 {
		t.Fatalf("name/schedule-only change invalidated coverage proof: %+v", monitor)
	}

	changedScope := updated.Job
	changedScope.Targets = []string{"198.51.100.11"}
	changed, _, err := f.ts.UpdateJob(ctx, updated.ID, updated.Revision, changedScope, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	report = f.report(t, f.ts)
	monitor = perimeterMonitorNamed(t, report.Monitors, changedScope.Name)
	if !monitor.ScopeChanged || report.Totals.UnprovenMonitors != 1 {
		t.Fatalf("target change remained proven: %+v", monitor)
	}

	successAt := now.Add(time.Minute)
	if err := f.db.System().SaveScan(ctx, model.Scan{
		ID: "scope-proof-after", JobID: changed.ID, JobRevision: changed.Revision, Job: changed.Job.Name,
		StartedAt: successAt.Add(-time.Minute), FinishedAt: successAt, Status: "success", ConfigHash: changed.Job.SecurityHash(),
	}); err != nil {
		t.Fatal(err)
	}
	f.setClock(successAt.Add(time.Minute))
	report = f.report(t, f.ts)
	monitor = perimeterMonitorNamed(t, report.Monitors, changed.Job.Name)
	if monitor.ScopeChanged || report.Totals.UnprovenMonitors != 0 {
		t.Fatalf("successful current-scope scan did not restore proof: %+v", monitor)
	}

	changedExpansionLimit := changed.Job
	changedExpansionLimit.MaxExpandedHosts = 128
	expansionRecord, _, err := f.ts.UpdateJob(ctx, changed.ID, changed.Revision, changedExpansionLimit, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	report = f.report(t, f.ts)
	monitor = perimeterMonitorNamed(t, report.Monitors, changedExpansionLimit.Name)
	if !monitor.ScopeChanged || report.Totals.UnprovenMonitors != 1 {
		t.Fatalf("max-expanded-hosts-only change remained proven: %+v", monitor)
	}

	expansionSuccessAt := successAt.Add(2 * time.Minute)
	if err := f.db.System().SaveScan(ctx, model.Scan{
		ID: "scope-proof-expansion-after", JobID: expansionRecord.ID, JobRevision: expansionRecord.Revision, Job: expansionRecord.Job.Name,
		StartedAt: expansionSuccessAt.Add(-time.Minute), FinishedAt: expansionSuccessAt, Status: "success", ConfigHash: expansionRecord.Job.SecurityHash(),
	}); err != nil {
		t.Fatal(err)
	}
	f.setClock(expansionSuccessAt.Add(time.Minute))
	report = f.report(t, f.ts)
	monitor = perimeterMonitorNamed(t, report.Monitors, expansionRecord.Job.Name)
	if monitor.ScopeChanged || report.Totals.UnprovenMonitors != 0 {
		t.Fatalf("successful scan after host-expansion change did not restore proof: %+v", monitor)
	}

	changedProtocol := expansionRecord.Job
	updatedProtocol := *changedProtocol.TCP
	updatedProtocol.Ports = "80,443"
	changedProtocol.TCP = &updatedProtocol
	protocolRecord, _, err := f.ts.UpdateJob(ctx, expansionRecord.ID, expansionRecord.Revision, changedProtocol, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	report = f.report(t, f.ts)
	monitor = perimeterMonitorNamed(t, report.Monitors, changedProtocol.Name)
	if !monitor.ScopeChanged || report.Totals.UnprovenMonitors != 1 {
		t.Fatalf("protocol change remained proven: %+v", monitor)
	}

	protocolSuccessAt := expansionSuccessAt.Add(2 * time.Minute)
	if err := f.db.System().SaveScan(ctx, model.Scan{
		ID: "scope-proof-protocol-after", JobID: protocolRecord.ID, JobRevision: protocolRecord.Revision, Job: protocolRecord.Job.Name,
		StartedAt: protocolSuccessAt.Add(-time.Minute), FinishedAt: protocolSuccessAt, Status: "success", ConfigHash: protocolRecord.Job.SecurityHash(),
	}); err != nil {
		t.Fatal(err)
	}
	f.setClock(protocolSuccessAt.Add(time.Minute))
	report = f.report(t, f.ts)
	monitor = perimeterMonitorNamed(t, report.Monitors, protocolRecord.Job.Name)
	if monitor.ScopeChanged || report.Totals.UnprovenMonitors != 0 {
		t.Fatalf("successful current-protocol scan did not restore proof: %+v", monitor)
	}
}

func TestPerimeterProgressDoesNotProveChangedScope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "198.51.100.0/24")
	record := createPerimeterJob(t, f.ts, perimeterJob("changed-scope-progress", "198.51.100.10"), true)
	successAt := record.CreatedAt
	if err := f.db.System().SaveScan(ctx, model.Scan{
		ID: "changed-scope-success", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: successAt, FinishedAt: successAt, Status: "success", ConfigHash: record.Job.SecurityHash(),
	}); err != nil {
		t.Fatal(err)
	}

	changedScope := record.Job
	changedScope.Targets = []string{"198.51.100.11"}
	updated, _, err := f.ts.UpdateJob(ctx, record.ID, record.Revision, changedScope, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	createRecentPerimeterProgress(t, f, updated, "changed-scope-progress")
	f.setClock(time.Now().UTC())

	report := f.report(t, f.ts)
	monitor := perimeterMonitorNamed(t, report.Monitors, "changed-scope-progress")
	if monitor.LastSuccessAt == nil || !monitor.ScopeChanged || !monitor.CycleInProgress || monitor.CycleCompletedUnits != 1 || monitor.CycleTotalUnits != 2 || report.Totals.UnprovenMonitors != 1 {
		t.Fatalf("changed-scope progress = %+v; unproven monitors = %d, want progress visible but coverage unproven", monitor, report.Totals.UnprovenMonitors)
	}
}

func TestPerimeterScopeEditsDiscardPriorScopeProgress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "198.51.100.0/24")
	record := createPerimeterJob(t, f.ts, perimeterJob("discard-old-scope-progress", "198.51.100.10"), true)
	successAt := record.CreatedAt
	if err := f.db.System().SaveScan(ctx, model.Scan{
		ID: "discard-old-scope-success", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: successAt, FinishedAt: successAt, Status: "success", ConfigHash: record.Job.SecurityHash(),
	}); err != nil {
		t.Fatal(err)
	}
	createRecentPerimeterProgress(t, f, record, "discard-before-target-edit")
	f.setClock(time.Now().UTC())
	if report := f.report(t, f.ts); !perimeterMonitorNamed(t, report.Monitors, record.Job.Name).CycleInProgress {
		t.Fatal("the prior-scope fixture did not start with visible progress")
	}

	changedTargets := record.Job
	changedTargets.Targets = []string{"198.51.100.11"}
	updated, _, err := f.ts.UpdateJob(ctx, record.ID, record.Revision, changedTargets, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	report := f.report(t, f.ts)
	monitor := perimeterMonitorNamed(t, report.Monitors, updated.Job.Name)
	if monitor.CycleInProgress || !monitor.ScopeChanged || report.Totals.UnprovenMonitors != 1 {
		t.Fatalf("target edit retained prior-scope progress: %+v; totals %+v", monitor, report.Totals)
	}

	// A new cycle in the changed target scope may report progress, but a later
	// protocol edit must discard that cycle in the same revision transaction.
	createRecentPerimeterProgress(t, f, updated, "discard-before-protocol-edit")
	changedProtocol := updated.Job
	protocol := *changedProtocol.TCP
	protocol.Ports = "80,443"
	changedProtocol.TCP = &protocol
	protocolUpdated, _, err := f.ts.UpdateJob(ctx, updated.ID, updated.Revision, changedProtocol, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	report = f.report(t, f.ts)
	monitor = perimeterMonitorNamed(t, report.Monitors, protocolUpdated.Job.Name)
	if monitor.CycleInProgress || !monitor.ScopeChanged || report.Totals.UnprovenMonitors != 1 {
		t.Fatalf("protocol edit retained prior-scope progress: %+v; totals %+v", monitor, report.Totals)
	}
}

// Each covering monitor fills the buckets of its protocols: Naabu and Nmap
// over every port fill full TCP, every TCP scan fills any TCP, and a UDP
// scan fills UDP.
func TestPerimeterReportSplitsCoverageIntoProtocolBuckets(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "198.51.100.0/24")
	naabu := perimeterJob("naabu", "198.51.100.0/26")
	naabu.TCP = &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Mode: "connect", Naabu: &config.NaabuOptions{ScanType: "connect"}}
	nmapFull := perimeterJob("nmap-full", "198.51.100.64/28")
	nmapFull.TCP.Ports = "1-1000,1001-65535"
	selected := perimeterJob("selected", "198.51.100.128/25")
	udp := perimeterJob("udp", "198.51.100.0/24")
	udp.TCP, udp.UDP = nil, &config.Protocol{Ports: "53"}
	for _, job := range []config.Job{naabu, nmapFull, selected, udp} {
		createPerimeterJob(t, f.ts, job, true)
	}
	report := f.report(t, f.ts)
	for name, want := range map[string][]string{
		"naabu": {"full_tcp", "any_tcp"}, "nmap-full": {"full_tcp", "any_tcp"}, "selected": {"any_tcp"}, "udp": {"udp"},
	} {
		if monitor := perimeterMonitorNamed(t, report.Monitors, name); monitor.State != "covering" || !reflect.DeepEqual(monitor.Protocols, want) {
			t.Errorf("%s = %s %v, want covering %v", name, monitor.State, monitor.Protocols, want)
		}
	}
	want := PerimeterCoverage{FullTCP: 64 + 16, AnyTCP: 64 + 16 + 128, UDP: 256}
	if got := report.Ranges[0].Coverage; got != want {
		t.Fatalf("coverage = %+v, want %+v", got, want)
	}
	if got := report.Totals; got.CoveredFullTCP != want.FullTCP || got.CoveredAnyTCP != want.AnyTCP || got.CoveredUDP != want.UDP || got.DeclaredIPv4 != 256 {
		t.Fatalf("totals = %+v", got)
	}
}

// Excluded addresses leave every count's denominator, overlapping ranges
// count once in the totals, and a fully excluded range has nothing to cover
// or suggest.
func TestPerimeterReportSubtractsExclusionsAndCountsOverlapsOnce(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "203.0.113.0/24", "10.0.0.0/16")
	ids := declarePerimeter(t, f.ts, store.PerimeterKindAuthorized, "10.0.1.0/24", "192.0.2.0/30")
	createPerimeterJob(t, f.ts, perimeterJob("partner", "10.0.1.0/24"), true)
	createPerimeterJob(t, f.ts, perimeterJob("edge", "203.0.113.128/25"), true)
	f.app.Config.Scanner.TargetExclusions = []string{"203.0.113.0/30", "192.0.2.0/29"}
	report := f.report(t, f.ts)
	for _, want := range []struct {
		value               string
		addresses, excluded uint64
		anyTCP              uint64
	}{
		{"203.0.113.0/24", 256, 4, 128},
		{"10.0.0.0/16", 65536, 0, 256},
		{"10.0.1.0/24", 256, 0, 256},
		{"192.0.2.0/30", 4, 4, 0},
	} {
		got := perimeterRangeValued(t, report.Ranges, want.value)
		if got.Addresses != want.addresses || got.Excluded != want.excluded || got.Coverage.AnyTCP != want.anyTCP || got.Family != 4 {
			t.Errorf("%s = %+v, want %+v", want.value, got, want)
		}
	}
	if got := report.Totals; got.DeclaredIPv4 != 65536+256+4 || got.ExcludedIPv4 != 8 || got.CoveredAnyTCP != 384 || got.Ranges != 4 || got.IPv6Ranges != 0 {
		t.Fatalf("totals = %+v", got)
	}
	excluded := f.detail(t, f.ts, ids["192.0.2.0/30"])
	if excluded.Uncovered.FullTCP.Total != 0 || excluded.Uncovered.AnyTCP.Total != 0 || excluded.Uncovered.UDP.Total != 0 ||
		len(excluded.Suggestions) != 0 || excluded.MonitorsNeeded != (PerimeterModeCounts{}) {
		t.Fatalf("a fully excluded range = %+v", excluded)
	}
	edge := f.detail(t, f.ts, ids["203.0.113.0/24"])
	if want := []string{"203.0.113.4/30", "203.0.113.8/29", "203.0.113.16/28", "203.0.113.32/27", "203.0.113.64/26"}; !reflect.DeepEqual(edge.Uncovered.AnyTCP.CIDRs, want) {
		t.Fatalf("uncovered = %v, want %v", edge.Uncovered.AnyTCP.CIDRs, want)
	}
	if want := []string{"203.0.113.4/30", "203.0.113.8/29", "203.0.113.16/28", "203.0.113.32/27", "203.0.113.64/26", "203.0.113.128/25"}; !reflect.DeepEqual(edge.Uncovered.FullTCP.CIDRs, want) {
		t.Fatalf("uncovered full TCP = %v, want %v", edge.Uncovered.FullTCP.CIDRs, want)
	}
	assertNoExcludedSuggestion(t, edge, f.app.Config.Scanner.TargetExclusions)
}

// assertNoExcludedSuggestion fails when either suggestion plan holds an
// excluded address.
func assertNoExcludedSuggestion(t *testing.T, detail PerimeterRangeDetail, exclusions []string) {
	t.Helper()
	excluded, _ := addrspace.TargetRanges(exclusions)
	for _, suggestions := range [][]PerimeterSuggestion{detail.Suggestions, detail.CoalescedSuggestions} {
		for _, suggestion := range suggestions {
			targets, _ := addrspace.TargetRanges(suggestion.Targets)
			if overlap := addrspace.Intersect(targets, excluded); len(overlap) > 0 {
				t.Fatalf("suggestion %v holds excluded addresses %v", suggestion.Targets, overlap)
			}
		}
	}
}

// An IPv6 range shows monitored counts per bucket, saturating, and neither
// IPv4 counts nor suggestions.
func TestPerimeterReportCountsIPv6Ranges(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	ids := declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "2001:db8::/32")
	createPerimeterJob(t, f.ts, perimeterJob("selected", "2001:db8::/120"), true)
	naabu := perimeterJob("naabu", "2001:db8:1::/124")
	naabu.TCP = &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Mode: "connect", Naabu: &config.NaabuOptions{ScanType: "connect"}}
	createPerimeterJob(t, f.ts, naabu, true)
	// A /64 outside the perimeter holds 2^64 addresses.
	createPerimeterJob(t, f.ts, perimeterJob("sweep", "2001:db9::/64"), true)
	report := f.report(t, f.ts)
	got := report.Ranges[0]
	if got.Family != 6 || got.Addresses != 0 || got.Excluded != 0 || got.Coverage != (PerimeterCoverage{}) {
		t.Fatalf("IPv6 range = %+v", got)
	}
	if want := (PerimeterCoverage{FullTCP: 16, AnyTCP: 256 + 16}); got.IPv6Monitored != want {
		t.Fatalf("IPv6 monitored = %+v, want %+v", got.IPv6Monitored, want)
	}
	if report.Totals.Ranges != 1 || report.Totals.IPv6Ranges != 1 || report.Totals.DeclaredIPv4 != 0 || report.Totals.CoveredAnyTCP != 0 {
		t.Fatalf("totals = %+v", report.Totals)
	}
	if len(report.Outside) != 1 || report.Outside[0].Target != "2001:db9::/64" || report.Outside[0].OutsideAddresses != 9007199254740991 || report.Outside[0].Partial {
		t.Fatalf("outside = %+v", report.Outside)
	}
	if sweep := perimeterMonitorNamed(t, report.Monitors, "sweep"); sweep.State != "over_budget" {
		t.Fatalf("the /64 monitor = %+v", sweep)
	}
	detail := f.detail(t, f.ts, ids["2001:db8::/32"])
	if len(detail.Suggestions) != 0 || detail.MonitorsNeeded != (PerimeterModeCounts{}) || detail.SuggestionsTruncated != (PerimeterModeFlags{}) {
		t.Fatalf("IPv6 suggestions = %+v", detail)
	}
	if detail.AddressesPerMonitor != (PerimeterModeCounts{FullTCP: 305, SelectedTCP: 4096, UDP: 1024}) {
		t.Fatalf("addresses per monitor = %+v", detail.AddressesPerMonitor)
	}
	if len(detail.Monitors) != 2 || detail.Uncovered.AnyTCP.Total == 0 || detail.Uncovered.AnyTCP.CIDRs[0] != "2001:db8::100/120" {
		t.Fatalf("IPv6 detail = %+v", detail)
	}
}

// Every address count saturates at 2^53 - 1, JavaScript's
// Number.MAX_SAFE_INTEGER, so the console reads each one exactly: an IPv6
// target with 2^53 addresses outside the perimeter is reported at the cap,
// one with 2^52 exactly, and the JSON numbers are exact integers.
func TestPerimeterReportCapsAddressCountsAtTheSafeInteger(t *testing.T) {
	t.Parallel()
	const maxSafeInteger = 9007199254740991
	if perimeterCountLimit != maxSafeInteger {
		t.Fatalf("perimeterCountLimit = %d, want %d", uint64(perimeterCountLimit), uint64(maxSafeInteger))
	}
	for _, count := range []struct {
		prefixes []string
		want     uint64
	}{
		{[]string{"2001:db8::/76"}, 1 << 52},
		{[]string{"2001:db8::/75"}, maxSafeInteger},
		{[]string{"2001:db8::/76", "2001:db9::/77"}, 1<<52 + 1<<51},
		{[]string{"2001:db8::/76", "2001:db9::/76"}, maxSafeInteger},
		{[]string{"2001:db8::/32"}, maxSafeInteger},
		{[]string{"0.0.0.0/0"}, 1 << 32},
	} {
		ranges := make([]addrspace.Range, 0, len(count.prefixes))
		for _, value := range count.prefixes {
			ranges = append(ranges, addrspace.FromPrefix(netip.MustParsePrefix(value)))
		}
		if got := perimeterCount(ranges); got != count.want {
			t.Errorf("count of %v = %d, want %d", count.prefixes, got, count.want)
		}
	}

	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "2001:db8::/32")
	createPerimeterJob(t, f.ts, perimeterJob("over", "2001:db9::/75"), true)
	createPerimeterJob(t, f.ts, perimeterJob("under", "2001:dba::/76"), true)
	// Part of this target lies inside the perimeter, and 2^96 addresses
	// outside it.
	createPerimeterJob(t, f.ts, perimeterJob("partial", "2001:db8::/31"), true)
	report := f.report(t, f.ts)
	got := map[string]uint64{}
	for _, outside := range report.Outside {
		got[outside.Target] = outside.OutsideAddresses
	}
	want := map[string]uint64{"2001:db9::/75": maxSafeInteger, "2001:dba::/76": 1 << 52, "2001:db8::/31": maxSafeInteger}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outside addresses = %v, want %v", got, want)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, number := range []string{`"outside_addresses":9007199254740991`, `"outside_addresses":4503599627370496`} {
		if !strings.Contains(string(raw), number) {
			t.Errorf("report JSON lacks %s: %s", number, raw)
		}
	}
	// Every number in the report decodes to a float64 that holds it exactly.
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	var check func(path string, value any)
	check = func(path string, value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, item := range value {
				check(path+"."+key, item)
			}
		case []any:
			for index, item := range value {
				check(fmt.Sprintf("%s[%d]", path, index), item)
			}
		case float64:
			if value > maxSafeInteger {
				t.Errorf("%s = %v, above Number.MAX_SAFE_INTEGER", path, value)
			}
		}
	}
	check("report", decoded)
}

// A DNS name is counted on its monitor and never covers an address; a
// monitor with only DNS names touches no range.
func TestPerimeterReportNeverCountsDNSTargetsAsCoverage(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "198.51.100.0/24")
	createPerimeterJob(t, f.ts, perimeterJob("mixed", "edge.example.com", "198.51.100.7"), true)
	createPerimeterJob(t, f.ts, perimeterJob("names", "www.example.com", "mail.example.com"), true)
	report := f.report(t, f.ts)
	if len(report.Monitors) != 1 {
		t.Fatalf("monitors = %+v, want only the one with an address", report.Monitors)
	}
	if mixed := report.Monitors[0]; mixed.Name != "mixed" || mixed.DNSTargets != 1 || mixed.State != "covering" {
		t.Fatalf("mixed monitor = %+v", mixed)
	}
	if got := report.Ranges[0].Coverage; got != (PerimeterCoverage{AnyTCP: 1}) {
		t.Fatalf("coverage = %+v", got)
	}
	if len(report.Outside) != 0 {
		t.Fatalf("a DNS name is listed outside: %+v", report.Outside)
	}
}

// Every IP and CIDR target of every unarchived monitor outside the declared
// ranges is listed, partial or full, up to 200, with the total before the
// cut.
func TestPerimeterReportListsTargetsOutsideThePerimeter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	mixed := perimeterJob("mixed", "198.51.100.0/25", "198.51.100.0/23", "192.0.2.9", "203.0.113.5")
	mixed.MaxExpandedHosts = 1000
	mixedJob := createPerimeterJob(t, f.ts, mixed, true)
	pausedJob := createPerimeterJob(t, f.ts, perimeterJob("paused-outside", "192.0.2.0/28"), false)
	archived := createPerimeterJob(t, f.ts, perimeterJob("archived", "192.0.2.64/28"), true)
	if err := f.ts.SetJobArchived(ctx, archived.ID, true); err != nil {
		t.Fatal(err)
	}
	// Without declared ranges, nothing is outside.
	if report := f.report(t, f.ts); len(report.Outside) != 0 || len(report.Monitors) != 0 || report.Totals.OutsideTargets != 0 {
		t.Fatalf("report without ranges = %+v", report)
	}
	declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "198.51.100.0/24")
	declarePerimeter(t, f.ts, store.PerimeterKindAuthorized, "203.0.113.0/24")
	report := f.report(t, f.ts)
	want := []PerimeterOutsideTarget{
		{JobID: mixedJob.ID, JobName: "mixed", State: "covering", Target: "198.51.100.0/23", Partial: true, OutsideAddresses: 256},
		{JobID: mixedJob.ID, JobName: "mixed", State: "covering", Target: "192.0.2.9", Partial: false, OutsideAddresses: 1},
		{JobID: pausedJob.ID, JobName: "paused-outside", State: "paused", Target: "192.0.2.0/28", Partial: false, OutsideAddresses: 16},
	}
	if !reflect.DeepEqual(report.Outside, want) || report.OutsideTruncated || report.Totals.OutsideTargets != 3 {
		t.Fatalf("outside = %+v (truncated %v, total %d), want %+v", report.Outside, report.OutsideTruncated, report.Totals.OutsideTargets, want)
	}
	// A monitor only outside the perimeter is listed, but does not count
	// among the monitors that cannot scan it.
	if len(report.Monitors) != 2 || report.Totals.CannotScanMonitors != 0 {
		t.Fatalf("monitors = %+v, totals %+v", report.Monitors, report.Totals)
	}

	many := make([]string, 0, 210)
	for host := 1; host <= 210; host++ {
		many = append(many, fmt.Sprintf("10.9.0.%d", host))
	}
	createPerimeterJob(t, f.ts, perimeterJob("many", many...), true)
	report = f.report(t, f.ts)
	if len(report.Outside) != 200 || !report.OutsideTruncated || report.Totals.OutsideTargets != 213 {
		t.Fatalf("outside = %d rows (truncated %v, total %d), want 200 of 213", len(report.Outside), report.OutsideTruncated, report.Totals.OutsideTargets)
	}
	if report.Outside[0].JobName != "many" || report.Outside[0].Target != "10.9.0.1" || report.Outside[199].Target != "10.9.0.200" {
		t.Fatalf("first and last rows = %+v, %+v", report.Outside[0], report.Outside[199])
	}
}

// The addresses one suggested monitor holds follow the unit's budget, the
// mode's cap and scanner.max_job_hosts, and a mode whose budget does not fit
// one address suggests nothing.
func TestPerimeterRangeDetailSizesSuggestionsToTheBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	b := f.secondUnit(t)
	idA := declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "10.20.0.0/20")["10.20.0.0/20"]
	idB := declarePerimeter(t, b, store.PerimeterKindPrefix, "10.20.0.0/20")["10.20.0.0/20"]

	detail := f.detail(t, f.ts, idA)
	if want := (PerimeterModeCounts{FullTCP: 305, SelectedTCP: 4096, UDP: 1024}); detail.AddressesPerMonitor != want {
		t.Fatalf("addresses per monitor = %+v, want %+v", detail.AddressesPerMonitor, want)
	}
	// A /20 at 305 addresses per monitor needs 16 monitors of one /24 each.
	if want := (PerimeterModeCounts{FullTCP: 16, SelectedTCP: 1, UDP: 4}); detail.MonitorsNeeded != want || detail.SuggestionsTruncated != (PerimeterModeFlags{}) || detail.BudgetTooLow != (PerimeterModeFlags{}) {
		t.Fatalf("detail = %+v", detail)
	}
	full := suggestionsOf(detail, "full_tcp")
	if len(full) != 16 || len(detail.Suggestions) != 21 {
		t.Fatalf("suggestions = %+v", detail.Suggestions)
	}
	for index, suggestion := range full {
		minimumSeconds := int64(256*65535) / int64(config.BuiltinNaabuProfile().Naabu.Rate)
		if int64(256*65535)%int64(config.BuiltinNaabuProfile().Naabu.Rate) != 0 {
			minimumSeconds++
		}
		if want := []string{fmt.Sprintf("10.20.%d.0/24", index)}; !reflect.DeepEqual(suggestion.Targets, want) || suggestion.Addresses != 256 || suggestion.EstimatedProbes != 256*65535 || suggestion.MinimumDurationSeconds != minimumSeconds || suggestion.Protocol != perimeterPresets[0].protocol {
			t.Fatalf("full TCP suggestion %d = %+v", index, suggestion)
		}
	}
	if selected := suggestionsOf(detail, "selected_tcp"); len(selected) != 1 || !reflect.DeepEqual(selected[0].Targets, []string{"10.20.0.0/20"}) || selected[0].Addresses != 4096 || selected[0].EstimatedProbes != 4096*2 {
		t.Fatalf("selected TCP suggestions = %+v", selected)
	}
	if selected := suggestionsOf(detail, "selected_tcp"); selected[0].MinimumDurationSeconds != 0 {
		t.Fatalf("selected TCP suggestion has a Full TCP duration estimate: %+v", selected[0])
	}
	if udp := suggestionsOf(detail, "udp"); len(udp) != 4 || !reflect.DeepEqual(udp[3].Targets, []string{"10.20.12.0/22"}) || udp[3].EstimatedProbes != 1024*6*2 || udp[3].Protocol.Protocol != "udp" {
		t.Fatalf("UDP suggestions = %+v", udp)
	}

	// A lowered budget is followed.
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET max_probe_count=24,max_naabu_probe_count=655350 WHERE id=?`, secondTenantID); err != nil {
		t.Fatal(err)
	}
	lowered := f.detail(t, b, idB)
	if want := (PerimeterModeCounts{FullTCP: 10, SelectedTCP: 12, UDP: 2}); lowered.AddressesPerMonitor != want {
		t.Fatalf("lowered addresses per monitor = %+v, want %+v", lowered.AddressesPerMonitor, want)
	}
	if want := (PerimeterModeCounts{FullTCP: 512, SelectedTCP: 512, UDP: 2048}); lowered.MonitorsNeeded != want || lowered.SuggestionsTruncated != (PerimeterModeFlags{FullTCP: true, SelectedTCP: true, UDP: true}) || len(lowered.Suggestions) != 3*64 {
		t.Fatalf("lowered detail = needed %+v, truncated %+v, %d suggestions", lowered.MonitorsNeeded, lowered.SuggestionsTruncated, len(lowered.Suggestions))
	}
	if first := lowered.Suggestions[0]; !reflect.DeepEqual(first.Targets, []string{"10.20.0.0/29"}) || first.Addresses != 8 {
		t.Fatalf("first lowered suggestion = %+v", first)
	}

	// One address does not fit the budget.
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET max_probe_count=1,max_naabu_probe_count=1000 WHERE id=?`, secondTenantID); err != nil {
		t.Fatal(err)
	}
	tooLow := f.detail(t, b, idB)
	if tooLow.BudgetTooLow != (PerimeterModeFlags{FullTCP: true, SelectedTCP: true, UDP: true}) || tooLow.AddressesPerMonitor != (PerimeterModeCounts{}) ||
		tooLow.MonitorsNeeded != (PerimeterModeCounts{}) || len(tooLow.Suggestions) != 0 || tooLow.Suggestions == nil {
		t.Fatalf("detail with a budget too low = %+v", tooLow)
	}

	// Each mode is flagged on its own. Eleven Nmap probes fit five
	// addresses of two selected TCP probes and no address of twelve UDP
	// probes, while the Naabu budget still fits 305 full TCP addresses.
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET max_probe_count=11,max_naabu_probe_count=20000000 WHERE id=?`, secondTenantID); err != nil {
		t.Fatal(err)
	}
	udpTooLow := f.detail(t, b, idB)
	if want := (PerimeterModeCounts{FullTCP: 305, SelectedTCP: 5, UDP: 0}); udpTooLow.AddressesPerMonitor != want {
		t.Fatalf("addresses per monitor with a UDP budget too low = %+v, want %+v", udpTooLow.AddressesPerMonitor, want)
	}
	if want := (PerimeterModeFlags{UDP: true}); udpTooLow.BudgetTooLow != want {
		t.Fatalf("budget too low = %+v, want %+v", udpTooLow.BudgetTooLow, want)
	}
	if len(suggestionsOf(udpTooLow, "udp")) != 0 || len(suggestionsOf(udpTooLow, "full_tcp")) == 0 || len(suggestionsOf(udpTooLow, "selected_tcp")) == 0 {
		t.Fatalf("suggestions with a UDP budget too low = %+v", udpTooLow.Suggestions)
	}
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET max_probe_count=11,max_naabu_probe_count=1000 WHERE id=?`, secondTenantID); err != nil {
		t.Fatal(err)
	}
	if got := f.detail(t, b, idB); got.BudgetTooLow != (PerimeterModeFlags{FullTCP: true, UDP: true}) || got.AddressesPerMonitor != (PerimeterModeCounts{SelectedTCP: 5}) {
		t.Fatalf("detail with the full TCP and UDP budgets too low = budget too low %+v, addresses per monitor %+v", got.BudgetTooLow, got.AddressesPerMonitor)
	}

	// scanner.max_job_hosts caps every mode.
	f.app.Config.Scanner.MaxJobHosts = ptrTo(100)
	if capped := f.detail(t, f.ts, idA); capped.AddressesPerMonitor != (PerimeterModeCounts{FullTCP: 100, SelectedTCP: 100, UDP: 100}) {
		t.Fatalf("addresses per monitor under max_job_hosts = %+v", capped.AddressesPerMonitor)
	}
}

// Packing is deterministic, never suggests an excluded address, and keeps
// at most 64 suggestions per mode with the number of monitors needed.
func TestPerimeterRangeDetailPacksSuggestions(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	ids := declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "10.30.0.0/22", "10.50.0.0/16")
	// The exclusions leave a /24, a /27 and a /28 of the /22.
	f.app.Config.Scanner.TargetExclusions = []string{
		"10.30.1.32/27", "10.30.1.64/26", "10.30.1.128/25",
		"10.30.2.16/28", "10.30.2.32/27", "10.30.2.64/26", "10.30.2.128/25", "10.30.3.0/24",
	}
	detail := f.detail(t, f.ts, ids["10.30.0.0/22"])
	if detail.Range.Excluded != 1024-304 {
		t.Fatalf("excluded = %d", detail.Range.Excluded)
	}
	want := []string{"10.30.0.0/24", "10.30.1.0/27", "10.30.2.0/28"}
	for _, mode := range []string{"full_tcp", "selected_tcp", "udp"} {
		suggestions := suggestionsOf(detail, mode)
		if len(suggestions) != 1 || !reflect.DeepEqual(suggestions[0].Targets, want) || suggestions[0].Addresses != 304 {
			t.Fatalf("%s suggestions = %+v, want one monitor of %v", mode, suggestions, want)
		}
	}
	if !reflect.DeepEqual(detail.Uncovered.FullTCP, PerimeterBlocks{CIDRs: want, Total: 3}) {
		t.Fatalf("uncovered = %+v", detail.Uncovered.FullTCP)
	}
	assertNoExcludedSuggestion(t, detail, f.app.Config.Scanner.TargetExclusions)
	if again := f.detail(t, f.ts, ids["10.30.0.0/22"]); !reflect.DeepEqual(again, detail) {
		t.Fatalf("a second detail differs:\n%+v\n%+v", again, detail)
	}

	wide := f.detail(t, f.ts, ids["10.50.0.0/16"])
	if want := (PerimeterModeCounts{FullTCP: 256, SelectedTCP: 16, UDP: 64}); wide.MonitorsNeeded != want {
		t.Fatalf("monitors needed = %+v, want %+v", wide.MonitorsNeeded, want)
	}
	if want := (PerimeterModeFlags{FullTCP: true}); wide.SuggestionsTruncated != want {
		t.Fatalf("truncated = %+v, want %+v", wide.SuggestionsTruncated, want)
	}
	if full := suggestionsOf(wide, "full_tcp"); len(full) != 64 || full[63].Targets[0] != "10.50.63.0/24" || len(wide.Suggestions) != 64+16+64 {
		t.Fatalf("suggestions = %d, last full TCP %+v", len(wide.Suggestions), full[len(full)-1])
	}
}

func TestPerimeterRangeDetailCoalescesFragmentedGapsWithinBounds(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	const rangeValue = "10.60.0.0/24"
	id := declarePerimeter(t, f.ts, store.PerimeterKindPrefix, rangeValue)[rangeValue]
	targets := make([]string, 0, 10)
	for host := 4; host <= 220; host += 24 {
		targets = append(targets, fmt.Sprintf("10.60.0.%d", host))
	}
	createPerimeterJob(t, f.ts, perimeterJob("scattered", targets...), true)

	detail := f.detail(t, f.ts, id)
	gaps := suggestionsOf(detail, "selected_tcp")
	if len(gaps) != 1 || len(gaps[0].Targets) <= 16 {
		t.Fatalf("gaps-only suggestions = %+v, want one fragmented monitor", gaps)
	}
	coalesced := coalescedSuggestionsOf(detail, "selected_tcp")
	if len(coalesced) != 1 || detail.CoalescedMonitorsNeeded.SelectedTCP != 1 || detail.CoalescedSuggestionsTruncated.SelectedTCP {
		t.Fatalf("coalesced suggestions = %+v, needed %+v, truncated %+v", coalesced, detail.CoalescedMonitorsNeeded, detail.CoalescedSuggestionsTruncated)
	}
	if want := []string{rangeValue}; !reflect.DeepEqual(coalesced[0].Targets, want) || coalesced[0].Addresses != 256 || coalesced[0].AlreadyCoveredAddresses != len(targets) || coalesced[0].EstimatedProbes != 512 {
		t.Fatalf("coalesced suggestion = %+v, want /24 with %d covered addresses", coalesced[0], len(targets))
	}
	for _, suggestion := range detail.CoalescedSuggestions {
		if len(suggestion.Targets) > perimeterMaxCoalescedTargets || suggestion.Addresses > detail.AddressesPerMonitor.SelectedTCP {
			t.Errorf("coalesced suggestion exceeds target or address budget: %+v", suggestion)
		}
		for _, target := range suggestion.Targets {
			prefix, err := netip.ParsePrefix(target)
			if err != nil || !prefix.Addr().Is4() || prefix.Bits() < perimeterMaxCoalescedPrefixBits {
				t.Errorf("coalesced target %q is broader than /%d or invalid: %v", target, perimeterMaxCoalescedPrefixBits, err)
			}
		}
	}
	if len(coalesced) > perimeterMaxCoalescedSuggestions {
		t.Fatalf("coalesced suggestions = %d, want at most %d", len(coalesced), perimeterMaxCoalescedSuggestions)
	}
}

// A coalesced alternative appears only when it needs fewer targets or fewer
// monitors than the gaps-only plan. One /24 instead of one /25 or one address
// only rescans covered addresses, so the mode then has none and a count of 0.
func TestPerimeterRangeDetailOffersCoalescedPlanOnlyWhenItReducesTargets(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	ids := declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "10.80.0.0/24", "10.81.0.0/24", "10.82.0.0/24")
	createPerimeterJob(t, f.ts, perimeterJob("lower-half", "10.80.0.0/25"), true)
	// Every address of 10.81.0.0/24 but the last one.
	createPerimeterJob(t, f.ts, perimeterJob("all-but-one", "10.81.0.0/25", "10.81.0.128/26", "10.81.0.192/27", "10.81.0.224/28", "10.81.0.240/29", "10.81.0.248/30", "10.81.0.252/31", "10.81.0.254"), true)
	createPerimeterJob(t, f.ts, perimeterJob("lowest-quarter", "10.82.0.0/26"), true)

	tests := []struct {
		value          string
		gapsOnly       []string
		coalesced      []string
		alreadyCovered int
	}{
		{value: "10.80.0.0/24", gapsOnly: []string{"10.80.0.128/25"}},
		{value: "10.81.0.0/24", gapsOnly: []string{"10.81.0.255"}},
		// Two gaps-only targets become one: a real reduction.
		{value: "10.82.0.0/24", gapsOnly: []string{"10.82.0.64/26", "10.82.0.128/25"}, coalesced: []string{"10.82.0.0/24"}, alreadyCovered: 64},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			detail := f.detail(t, f.ts, ids[test.value])
			gaps := suggestionsOf(detail, "selected_tcp")
			if len(gaps) != 1 || !reflect.DeepEqual(gaps[0].Targets, test.gapsOnly) || detail.MonitorsNeeded.SelectedTCP != 1 {
				t.Fatalf("gaps-only suggestions = %+v, want one monitor on %v", gaps, test.gapsOnly)
			}
			// The job covers no full-TCP or UDP address, so only selected TCP
			// could have an alternative.
			if test.coalesced == nil {
				if len(detail.CoalescedSuggestions) != 0 || detail.CoalescedMonitorsNeeded != (PerimeterModeCounts{}) || detail.CoalescedSuggestionsTruncated != (PerimeterModeFlags{}) {
					t.Fatalf("coalesced alternative that reduces nothing = %+v, needed %+v, truncated %+v", detail.CoalescedSuggestions, detail.CoalescedMonitorsNeeded, detail.CoalescedSuggestionsTruncated)
				}
				return
			}
			coalesced := coalescedSuggestionsOf(detail, "selected_tcp")
			if len(coalesced) != 1 || len(detail.CoalescedSuggestions) != 1 || detail.CoalescedMonitorsNeeded != (PerimeterModeCounts{SelectedTCP: 1}) || detail.CoalescedSuggestionsTruncated != (PerimeterModeFlags{}) {
				t.Fatalf("coalesced suggestions = %+v, needed %+v, truncated %+v", detail.CoalescedSuggestions, detail.CoalescedMonitorsNeeded, detail.CoalescedSuggestionsTruncated)
			}
			if !reflect.DeepEqual(coalesced[0].Targets, test.coalesced) || coalesced[0].AlreadyCoveredAddresses != test.alreadyCovered {
				t.Fatalf("coalesced suggestion = %+v, want %v repeating %d covered addresses", coalesced[0], test.coalesced, test.alreadyCovered)
			}
		})
	}
}

func TestPerimeterRangeDetailCoalescedSuggestionsRespectExclusionsAndBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	const rangeValue = "10.61.0.0/27"
	id := declarePerimeter(t, f.ts, store.PerimeterKindPrefix, rangeValue)[rangeValue]
	record := createPerimeterJob(t, f.ts, perimeterJob("one-covered-host", "10.61.0.1"), true)
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET max_probe_count=32 WHERE id=(SELECT tenant_id FROM jobs WHERE id=?)`, record.ID); err != nil {
		t.Fatal(err)
	}
	// This exclusion is introduced after the existing job, as can happen
	// when deployment configuration changes.
	f.app.Config.Scanner.TargetExclusions = []string{"10.61.0.16/28"}

	detail := f.detail(t, f.ts, id)
	coalesced := coalescedSuggestionsOf(detail, "selected_tcp")
	if len(coalesced) != 1 || detail.AddressesPerMonitor.SelectedTCP != 16 || coalesced[0].Addresses != 16 || coalesced[0].AlreadyCoveredAddresses != 1 || coalesced[0].EstimatedProbes != 32 {
		t.Fatalf("bounded coalesced suggestion = %+v, addresses per monitor %+v", coalesced, detail.AddressesPerMonitor)
	}
	if !reflect.DeepEqual(coalesced[0].Targets, []string{"10.61.0.0/28"}) {
		t.Fatalf("coalesced targets = %v, want the scannable /28", coalesced[0].Targets)
	}
	assertNoExcludedSuggestion(t, detail, f.app.Config.Scanner.TargetExclusions)
}

func TestPerimeterRangeDetailWithholdsOversizedCoalescedPlans(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	const rangeValue = "10.62.0.0/15"
	id := declarePerimeter(t, f.ts, store.PerimeterKindPrefix, rangeValue)[rangeValue]
	// Put the one covered host at the end of the range. The coalesced plan
	// passes its 16-monitor cap before it reaches this address.
	createPerimeterJob(t, f.ts, perimeterJob("one-covered-host", "10.63.255.254"), true)

	detail := f.detail(t, f.ts, id)
	if detail.CoalescedMonitorsNeeded.SelectedTCP != perimeterMaxCoalescedSuggestions+1 || !detail.CoalescedSuggestionsTruncated.SelectedTCP || len(coalescedSuggestionsOf(detail, "selected_tcp")) != 0 {
		t.Fatalf("oversized coalesced plan = needed %+v, truncated %+v, suggestions %+v", detail.CoalescedMonitorsNeeded, detail.CoalescedSuggestionsTruncated, detail.CoalescedSuggestions)
	}
}

func TestPerimeterRangeDetailSkipsBroadUncoveredCoalescedWalk(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	f.app.Config.Scanner.MaxJobHosts = ptrTo(1)
	const rangeValue = "10.0.0.0/8"
	id := declarePerimeter(t, f.ts, store.PerimeterKindPrefix, rangeValue)[rangeValue]

	detail := f.detail(t, f.ts, id)
	if detail.AddressesPerMonitor != (PerimeterModeCounts{FullTCP: 1, SelectedTCP: 1, UDP: 1}) {
		t.Fatalf("addresses per monitor = %+v, want one per mode", detail.AddressesPerMonitor)
	}
	if detail.SuggestionsTruncated != (PerimeterModeFlags{FullTCP: true, SelectedTCP: true, UDP: true}) || len(detail.Suggestions) != 3*perimeterMaxSuggestions {
		t.Fatalf("ordinary suggestions = %d, truncated %+v, want the existing 64-suggestion cap per mode", len(detail.Suggestions), detail.SuggestionsTruncated)
	}
	if len(detail.CoalescedSuggestions) != 0 || detail.CoalescedMonitorsNeeded != (PerimeterModeCounts{}) || detail.CoalescedSuggestionsTruncated != (PerimeterModeFlags{}) {
		t.Fatalf("uncovered range has coalesced alternatives: suggestions %+v, needed %+v, truncated %+v", detail.CoalescedSuggestions, detail.CoalescedMonitorsNeeded, detail.CoalescedSuggestionsTruncated)
	}
}

func TestPerimeterRangeDetailStopsAtCoalescedCapBeforeBroadRangeEnd(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	f.app.Config.Scanner.MaxJobHosts = ptrTo(2)
	const rangeValue = "10.0.0.0/8"
	id := declarePerimeter(t, f.ts, store.PerimeterKindPrefix, rangeValue)[rangeValue]
	// This covered address is at the last address of the range. The selected
	// TCP plan can coalesce with its preceding /32, but only after the first
	// sixteen suggestions have already been exceeded.
	createPerimeterJob(t, f.ts, perimeterJob("last-host", "10.255.255.255"), true)

	detail := f.detail(t, f.ts, id)
	wantNeeded := PerimeterModeCounts{SelectedTCP: perimeterMaxCoalescedSuggestions + 1}
	wantTruncated := PerimeterModeFlags{SelectedTCP: true}
	if detail.CoalescedMonitorsNeeded != wantNeeded || detail.CoalescedSuggestionsTruncated != wantTruncated || len(coalescedSuggestionsOf(detail, "selected_tcp")) != 0 {
		t.Fatalf("coalesced cap result = needed %+v, truncated %+v, suggestions %+v; want %+v and %+v with no partial plan", detail.CoalescedMonitorsNeeded, detail.CoalescedSuggestionsTruncated, detail.CoalescedSuggestions, wantNeeded, wantTruncated)
	}
}

func TestPerimeterCoalescingPreflightRespectsBudgetAndScannableBoundaries(t *testing.T) {
	t.Parallel()
	rangeOf := func(value string) addrspace.Range {
		return addrspace.FromPrefix(netip.MustParsePrefix(value))
	}
	tests := []struct {
		name           string
		base, gaps     []addrspace.Range
		minPrefixBits  int
		wantCoalescing bool
	}{
		{
			name:           "no covered addresses",
			base:           []addrspace.Range{rangeOf("10.1.0.0/8")},
			gaps:           []addrspace.Range{rangeOf("10.1.0.0/8")},
			minPrefixBits:  24,
			wantCoalescing: false,
		},
		{
			name:           "one host budget cannot bridge coverage",
			base:           []addrspace.Range{rangeOf("10.1.0.0/31")},
			gaps:           []addrspace.Range{rangeOf("10.1.0.0/32")},
			minPrefixBits:  32,
			wantCoalescing: false,
		},
		{
			name:           "neighboring coverage fits budget",
			base:           []addrspace.Range{rangeOf("10.1.0.0/31")},
			gaps:           []addrspace.Range{rangeOf("10.1.0.0/32")},
			minPrefixBits:  31,
			wantCoalescing: true,
		},
		{
			name:           "exclusion boundary prevents a bridge",
			base:           []addrspace.Range{rangeOf("10.1.0.0/32"), rangeOf("10.1.0.2/32")},
			gaps:           []addrspace.Range{rangeOf("10.1.0.0/32")},
			minPrefixBits:  31,
			wantCoalescing: false,
		},
		{
			name:           "IPv6 does not produce IPv4 suggestions",
			base:           []addrspace.Range{rangeOf("2001:db8::/126")},
			gaps:           []addrspace.Range{rangeOf("2001:db8::/127")},
			minPrefixBits:  24,
			wantCoalescing: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := perimeterCoalescingCanIncludeCovered(test.base, test.gaps, test.minPrefixBits); got != test.wantCoalescing {
				t.Fatalf("coalescing preflight = %v, want %v", got, test.wantCoalescing)
			}
		})
	}
}

// The uncovered blocks of a bucket stop at 256 CIDRs, with their total.
func TestPerimeterRangeDetailCapsUncoveredBlocks(t *testing.T) {
	t.Parallel()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	ids := declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "10.40.0.0/22")
	even := make([]string, 0, 256)
	for host := 0; host < 512; host += 2 {
		even = append(even, netip.AddrFrom4([4]byte{10, 40, byte(host / 256), byte(host % 256)}).String())
	}
	createPerimeterJob(t, f.ts, perimeterJob("even", even...), true)
	detail := f.detail(t, f.ts, ids["10.40.0.0/22"])
	if detail.Range.Coverage.AnyTCP != 256 || len(detail.Monitors) != 1 {
		t.Fatalf("range = %+v", detail.Range)
	}
	anyTCP := detail.Uncovered.AnyTCP
	if len(anyTCP.CIDRs) != 256 || !anyTCP.Truncated || anyTCP.Total != 257 || anyTCP.CIDRs[0] != "10.40.0.1/32" || anyTCP.CIDRs[255] != "10.40.1.255/32" {
		t.Fatalf("uncovered any TCP = %d CIDRs (truncated %v, total %d)", len(anyTCP.CIDRs), anyTCP.Truncated, anyTCP.Total)
	}
	if !reflect.DeepEqual(detail.Uncovered.FullTCP, PerimeterBlocks{CIDRs: []string{"10.40.0.0/22"}, Total: 1}) {
		t.Fatalf("uncovered full TCP = %+v", detail.Uncovered.FullTCP)
	}
	selected := suggestionsOf(detail, "selected_tcp")
	if len(selected) != 1 || selected[0].Addresses != 768 || len(selected[0].Targets) != 257 || selected[0].Targets[0] != "10.40.0.1" || !slices.Contains(selected[0].Targets, "10.40.2.0/23") {
		t.Fatalf("selected TCP suggestions = %+v", selected)
	}
}

// A budget that cannot be read stops the request, without a partial report.
func TestPerimeterReportStopsWithoutTheProbeBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	b := f.secondUnit(t)
	id := declarePerimeter(t, b, store.PerimeterKindPrefix, "198.51.100.0/24")["198.51.100.0/24"]
	createPerimeterJob(t, b, perimeterJob("edge", "198.51.100.0/28"), true)
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, store.TenantStateDeleted, secondTenantID); err != nil {
		t.Fatal(err)
	}
	report, err := f.app.PerimeterReport(ctx, b)
	if !errors.Is(err, ErrProbeBudgetUnavailable) || !reflect.DeepEqual(report, PerimeterReport{}) {
		t.Fatalf("report = %+v, %v; want ErrProbeBudgetUnavailable and no report", report, err)
	}
	detail, err := f.app.PerimeterRangeDetail(ctx, b, id)
	if !errors.Is(err, ErrProbeBudgetUnavailable) || !reflect.DeepEqual(detail, PerimeterRangeDetail{}) {
		t.Fatalf("detail = %+v, %v; want ErrProbeBudgetUnavailable and no detail", detail, err)
	}
}

// Another unit's range, an unknown ID and a row the report does not cover
// are all store.ErrNotFound itself, and neither unit sees the other's data.
func TestPerimeterRangeDetailOfAnotherUnitIsNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPerimeterFixture(t)
	f.setClock(time.Now().UTC().Add(time.Minute))
	b := f.secondUnit(t)
	idA := declarePerimeter(t, f.ts, store.PerimeterKindPrefix, "198.51.100.0/24")["198.51.100.0/24"]
	createPerimeterJob(t, f.ts, perimeterJob("alpha", "198.51.100.0/28", "192.0.2.1"), true)
	declarePerimeter(t, b, store.PerimeterKindPrefix, "203.0.113.0/24")
	createPerimeterJob(t, b, perimeterJob("bravo", "203.0.113.0/28"), true)
	// A later stage stores ASN rows, which this report does not cover.
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := f.db.DB.ExecContext(ctx, `INSERT INTO perimeter_seeds(id,tenant_id,kind,value,created_at) VALUES('asn-row',?,'asn','AS64496',?)`, store.DefaultTenantScope().ID(), stamp); err != nil {
		t.Fatal(err)
	}
	for label, id := range map[string]string{"another unit's range": idA, "unknown ID": "missing", "ASN row": "asn-row"} {
		ts := b
		if label == "ASN row" {
			ts = f.ts
		}
		detail, err := f.app.PerimeterRangeDetail(ctx, ts, id)
		if err != store.ErrNotFound || !reflect.DeepEqual(detail, PerimeterRangeDetail{}) {
			t.Errorf("%s = %+v, %v; want store.ErrNotFound", label, detail, err)
		}
	}
	reportA, reportB := f.report(t, f.ts), f.report(t, b)
	if len(reportA.Ranges) != 1 || reportA.Ranges[0].ID != idA || len(reportA.Monitors) != 1 || reportA.Monitors[0].Name != "alpha" {
		t.Fatalf("unit A's report = %+v", reportA)
	}
	if len(reportB.Ranges) != 1 || reportB.Ranges[0].Value != "203.0.113.0/24" || len(reportB.Monitors) != 1 || reportB.Monitors[0].Name != "bravo" || len(reportB.Outside) != 0 {
		t.Fatalf("unit B's report = %+v", reportB)
	}
	raw, err := json.Marshal(reportB)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"alpha", idA, "198.51.100.", "192.0.2.1"} {
		if strings.Contains(string(raw), marker) {
			t.Fatalf("unit B's report holds %q of unit A: %s", marker, raw)
		}
	}
}
