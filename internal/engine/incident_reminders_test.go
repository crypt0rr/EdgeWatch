package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestIncidentReminderOnEverySuccessfulRepeat(t *testing.T) {
	job := config.Job{Name: "reminders", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := snapshotWithOpenPorts(80, 443, 587)
	state := model.JobState{Baseline: &baseline, Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{}}
	observed := snapshotWithOpenPorts(80)
	run := func(id string, enabled bool) []model.Event {
		t.Helper()
		events, _, err := processSuccessWithChangesAndReminders(&state, job, model.Scan{ID: id, Job: job.Name, Status: "success", FinishedAt: time.Now().UTC(), Snapshot: observed}, enabled)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	if events := run("first", true); len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("first scan: %#v", events)
	}
	for _, id := range []string{"second", "third"} {
		events := run(id, true)
		if len(events) != 1 || events[0].Type != "changes-reminder" || events[0].ScanID != id || len(events[0].Changes) != 2 || events[0].Changes[0].Port != 443 || events[0].Changes[1].Port != 587 {
			t.Fatalf("repeat scan %s: %#v", id, events)
		}
	}
	if events := run("disabled", false); len(events) != 0 {
		t.Fatalf("disabled reminders: %#v", events)
	}
	if events := run("enabled-again", true); len(events) != 1 || events[0].Type != "changes-reminder" {
		t.Fatalf("re-enabled reminders: %#v", events)
	}
	incomplete := model.Scan{ID: "incomplete", Job: job.Name, Status: "incomplete", FinishedAt: time.Now().UTC(), Snapshot: observed}
	if events, _, err := processSuccessWithChangesAndReminders(&state, job, incomplete, true); err != nil || hasEventType(events, "changes-reminder") {
		t.Fatalf("incomplete scan sent reminder: %#v, %v", events, err)
	}
}

func hasEventType(events []model.Event, kind string) bool {
	for _, event := range events {
		if event.Type == kind {
			return true
		}
	}
	return false
}

func TestCriticalReminderFormatIdentifiesPersistentChange(t *testing.T) {
	message := FormatEvent(model.Event{Type: "changes-reminder", Job: "edge", ScanID: "scan-repeat", Message: "Reminder: 1 baseline change remains open", Changes: []model.Change{{Target: "192.0.2.1", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}}})
	if !strings.HasPrefix(message, "🔴 EdgeWatch: Reminder:") || !strings.Contains(message, "Scan: scan-repeat") || !strings.Contains(message, "tcp/443") {
		t.Fatalf("reminder notification=%q", message)
	}
}

func TestIncidentReminderCadenceEnforcesIntervalsAndBoundaries(t *testing.T) {
	job := config.Job{Name: "cadence", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := snapshotWithOpenPorts(80, 443)
	state := model.JobState{Baseline: &baseline, Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{}}
	settings := store.IncidentReminderSettings{Enabled: true, Cadence: store.IncidentReminderCadenceDaily}
	observed := snapshotWithOpenPorts(80)
	start := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	run := func(id string, at time.Time) []model.Event {
		t.Helper()
		events, _, err := processSuccessWithReminderSettings(&state, job, model.Scan{ID: id, Job: job.Name, Status: "success", FinishedAt: at, Snapshot: observed}, settings)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	if events := run("incident", start); len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("initial incident: %#v", events)
	}
	firstReminder := start.Add(5 * time.Minute)
	if events := run("first-reminder", firstReminder); len(events) != 1 || events[0].Type != "changes-reminder" {
		t.Fatalf("first reminder: %#v", events)
	}
	if state.LastIncidentReminderAt == nil || !state.LastIncidentReminderAt.Equal(firstReminder) {
		t.Fatalf("last reminder time=%v, want %v", state.LastIncidentReminderAt, firstReminder)
	}
	if events := run("too-soon", firstReminder.Add(23*time.Hour+59*time.Minute)); hasEventType(events, "changes-reminder") {
		t.Fatalf("daily cadence sent early reminder: %#v", events)
	}
	if events := run("boundary", firstReminder.Add(24*time.Hour)); len(events) != 1 || events[0].Type != "changes-reminder" {
		t.Fatalf("reminder at exact daily boundary: %#v", events)
	}
}

func TestIncidentReminderDueSupportsEveryCadenceAndFallsBack(t *testing.T) {
	last := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		cadence    string
		elapsed    time.Duration
		noPrevious bool
		want       bool
	}{
		{name: "first reminder", cadence: store.IncidentReminderCadenceDaily, noPrevious: true, want: true},
		{name: "every scan", cadence: store.IncidentReminderCadenceEveryScan, elapsed: time.Minute, want: true},
		{name: "hourly before boundary", cadence: store.IncidentReminderCadenceHourly, elapsed: time.Hour - time.Second, want: false},
		{name: "hourly at boundary", cadence: store.IncidentReminderCadenceHourly, elapsed: time.Hour, want: true},
		{name: "six hours before boundary", cadence: store.IncidentReminderCadenceSixHours, elapsed: 6*time.Hour - time.Second, want: false},
		{name: "six hours at boundary", cadence: store.IncidentReminderCadenceSixHours, elapsed: 6 * time.Hour, want: true},
		{name: "unknown persisted cadence falls back", cadence: "future_value", elapsed: time.Minute, want: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var previous *time.Time
			if !test.noPrevious {
				previous = &last
			}
			if got := incidentReminderDue(previous, test.cadence, last.Add(test.elapsed)); got != test.want {
				t.Fatalf("incidentReminderDue(%v, %q)=%t, want %t", test.elapsed, test.cadence, got, test.want)
			}
		})
	}
}

func TestManagedIncidentRemindersFollowSavedSetting(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	job := config.NormalizeJob(config.Job{Name: "managed-reminders", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1-65535", Mode: "connect"}, Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}})
	record, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	engine := Engine{Store: db}
	start := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	run := func(id string, at time.Time, ports ...int) []model.Event {
		t.Helper()
		scan := model.Scan{ID: id, JobID: record.ID, Job: job.Name, JobRevision: record.Revision, StartedAt: at, FinishedAt: at, Status: "success", ConfigHash: job.SecurityHash(), Snapshot: snapshotWithOpenPorts(ports...)}
		events, err := engine.FinalizeManagedScan(ctx, record.ID, job, &scan, []string{"file:test-reminders"})
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	if events := run("baseline", start, 80, 443); len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline events: %#v", events)
	}
	if events := run("opened", start.Add(time.Minute), 80); len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("opened events: %#v", events)
	}
	if events := run("first-reminder", start.Add(2*time.Minute), 80); len(events) != 1 || events[0].Type != "changes-reminder" {
		t.Fatalf("first follow-up reminder events: %#v", events)
	}
	if events := run("too-soon", start.Add(3*time.Minute), 80); hasEventType(events, "changes-reminder") {
		t.Fatalf("default hourly cadence sent another early reminder: %#v", events)
	}
	if events := run("reminded", start.Add(time.Hour+2*time.Minute), 80); len(events) != 1 || events[0].Type != "changes-reminder" {
		t.Fatalf("reminder events: %#v", events)
	}
	if err := defaultTenant(db).SetIncidentRemindersEnabled(ctx, false, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if events := run("disabled", start.Add(time.Hour+3*time.Minute), 80); len(events) != 0 {
		t.Fatalf("disabled events: %#v", events)
	}
	if err := defaultTenant(db).SetIncidentRemindersEnabled(ctx, true, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if events := run("enabled-again", start.Add(2*time.Hour+2*time.Minute), 80); len(events) != 1 || events[0].Type != "changes-reminder" {
		t.Fatalf("re-enabled events: %#v", events)
	}
	var reminders int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE job_id=? AND type='changes-reminder'`, record.ID).Scan(&reminders); err != nil || reminders != 3 {
		t.Fatalf("persisted reminders=%d, %v; want 3", reminders, err)
	}
	var queued int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE tenant_id=? AND destination='file:test-reminders' AND json_extract(payload_json,'$.type')='changes-reminder'`, store.DefaultTenantID).Scan(&queued); err != nil || queued != 3 {
		t.Fatalf("queued reminders=%d, %v; want 3", queued, err)
	}
}

func TestManagedReminderCadencePersistsAcrossRestartAndIsPerJob(t *testing.T) {
	ctx := context.Background()
	path := storetest.FreshPath(t)
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
	})
	job := config.NormalizeJob(config.Job{Name: "managed-cadence-a", Schedule: "*/5 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1-65535", Mode: "connect"}, Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}})
	recordA, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	jobB := job
	jobB.Name = "managed-cadence-b"
	recordB, err := defaultTenant(db).CreateJob(ctx, jobB)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	cadence := store.IncidentReminderCadenceDaily
	if _, err := defaultTenant(db).SetIncidentReminderSettings(ctx, nil, &cadence, store.AuditEntry{}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	engine := Engine{Store: db}
	base := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	run := func(jobID string, currentJob config.Job, id string, at time.Time, ports ...int) []model.Event {
		t.Helper()
		scan := model.Scan{ID: id, JobID: jobID, Job: currentJob.Name, StartedAt: at, FinishedAt: at, Status: "success", ConfigHash: currentJob.SecurityHash(), Snapshot: snapshotWithOpenPorts(ports...)}
		events, err := engine.FinalizeManagedScan(ctx, jobID, currentJob, &scan, nil)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	if got := run(recordA.ID, job, "a-base", base, 80, 443); !hasEventType(got, "baseline-complete") {
		t.Fatalf("job A baseline events=%#v", got)
	}
	if got := run(recordA.ID, job, "a-open", base.Add(time.Minute), 80); !hasEventType(got, "changes-detected") {
		t.Fatalf("job A incident events=%#v", got)
	}
	if got := run(recordA.ID, job, "a-reminder", base.Add(2*time.Minute), 80); !hasEventType(got, "changes-reminder") {
		t.Fatalf("job A first reminder events=%#v", got)
	}
	if got := run(recordB.ID, jobB, "b-base", base.Add(2*time.Minute), 80, 443); !hasEventType(got, "baseline-complete") {
		t.Fatalf("job B baseline events=%#v", got)
	}
	if got := run(recordB.ID, jobB, "b-open", base.Add(3*time.Minute), 80); !hasEventType(got, "changes-detected") {
		t.Fatalf("job B incident events=%#v", got)
	}
	if got := run(recordB.ID, jobB, "b-reminder", base.Add(4*time.Minute), 80); !hasEventType(got, "changes-reminder") {
		t.Fatalf("job B reminder was suppressed by job A: %#v", got)
	}
	if got := run(recordA.ID, job, "a-before-restart", base.Add(3*time.Minute), 80); hasEventType(got, "changes-reminder") {
		t.Fatalf("job A sent a second reminder before cadence: %#v", got)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	engine.Store = db
	if got := run(recordA.ID, job, "a-after-restart-early", base.Add(23*time.Hour+2*time.Minute), 80); hasEventType(got, "changes-reminder") {
		t.Fatalf("restart reset reminder cadence: %#v", got)
	}
	if got := run(recordA.ID, job, "a-after-restart-due", base.Add(24*time.Hour+2*time.Minute), 80); !hasEventType(got, "changes-reminder") {
		t.Fatalf("restart lost due reminder: %#v", got)
	}
}

func TestReminderExcludesSuppressedAndNewIncidents(t *testing.T) {
	job := config.Job{Name: "reminders", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := snapshotWithOpenPorts(25, 80, 443)
	state := model.JobState{Baseline: &baseline, Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{}}
	makeScan := func(id string, ports ...int) model.Scan {
		return model.Scan{ID: id, Job: job.Name, Status: "success", FinishedAt: time.Now().UTC(), Snapshot: snapshotWithOpenPorts(ports...)}
	}
	first := makeScan("first", 25, 80)
	if _, _, err := processSuccessWithChangesAndReminders(&state, job, first, true); err != nil {
		t.Fatal(err)
	}
	second := makeScan("second", 25)
	events, _, err := processSuccessWithChangesAndReminders(&state, job, second, true)
	if err != nil || len(events) != 2 || events[0].Type != "changes-detected" || events[1].Type != "changes-reminder" || events[1].Changes[0].Port != 443 {
		t.Fatalf("mixed new and old incidents: %#v, %v", events, err)
	}
	for key, incident := range state.Incidents {
		if incident.Change.Port == 443 {
			state.Suppressed[key] = 1
			delete(state.Incidents, key)
		}
	}
	third := makeScan("third", 25)
	events, _, err = processSuccessWithChangesAndReminders(&state, job, third, true)
	if err != nil || len(events) != 1 || events[0].Type != "changes-reminder" || events[0].Changes[0].Port != 80 {
		t.Fatalf("suppressed incident reminder: %#v, %v", events, err)
	}
}
