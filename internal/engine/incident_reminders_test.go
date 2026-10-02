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
	message := FormatEvent(model.Event{Type: "changes-reminder", Job: "edge", ScanID: "scan-repeat", Message: "Reminder: 1 baseline change(s) remain open", Changes: []model.Change{{Target: "192.0.2.1", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}}})
	if !strings.HasPrefix(message, "🔴 EdgeWatch: Reminder:") || !strings.Contains(message, "Scan: scan-repeat") || !strings.Contains(message, "tcp/443") {
		t.Fatalf("reminder notification=%q", message)
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
	run := func(id string, ports ...int) []model.Event {
		t.Helper()
		at := time.Now().UTC()
		scan := model.Scan{ID: id, JobID: record.ID, Job: job.Name, JobRevision: record.Revision, StartedAt: at, FinishedAt: at, Status: "success", ConfigHash: job.SecurityHash(), Snapshot: snapshotWithOpenPorts(ports...)}
		events, err := engine.FinalizeManagedScan(ctx, record.ID, job, &scan, []string{"file:test-reminders"})
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	if events := run("baseline", 80, 443); len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline events: %#v", events)
	}
	if events := run("opened", 80); len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("opened events: %#v", events)
	}
	if events := run("reminded", 80); len(events) != 1 || events[0].Type != "changes-reminder" {
		t.Fatalf("reminder events: %#v", events)
	}
	if err := defaultTenant(db).SetIncidentRemindersEnabled(ctx, false, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if events := run("disabled", 80); len(events) != 0 {
		t.Fatalf("disabled events: %#v", events)
	}
	if err := defaultTenant(db).SetIncidentRemindersEnabled(ctx, true, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if events := run("enabled-again", 80); len(events) != 1 || events[0].Type != "changes-reminder" {
		t.Fatalf("re-enabled events: %#v", events)
	}
	var reminders int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE job_id=? AND type='changes-reminder'`, record.ID).Scan(&reminders); err != nil || reminders != 2 {
		t.Fatalf("persisted reminders=%d, %v", reminders, err)
	}
	var queued int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE tenant_id=? AND destination='file:test-reminders' AND json_extract(payload_json,'$.type')='changes-reminder'`, store.DefaultTenantID).Scan(&queued); err != nil || queued != 2 {
		t.Fatalf("queued reminders=%d, %v", queued, err)
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
