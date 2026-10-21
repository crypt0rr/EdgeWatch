package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func monitoringTestJob() store.JobRecord {
	return store.JobRecord{
		ID:      "monitoring-job",
		Enabled: true,
		Job: config.Job{
			Name:     "monitoring-job",
			Schedule: "30 2 * * *",
			Timezone: "Europe/Amsterdam",
		},
	}
}

func monitoringAttempt(status string) *store.JobScanStatusSummary {
	stamp := time.Date(2026, 10, 11, 8, 30, 0, 0, time.UTC)
	return &store.JobScanStatusSummary{ID: "scan-summary-id", Status: status, StartedAt: stamp, FinishedAt: stamp.Add(time.Minute)}
}

func monitoringView(record store.JobRecord, attempt *store.JobScanStatusSummary, historyAvailable bool, appActivity string, appActivityAvailable bool, cycleStatus string, cycleAvailable bool) jobMonitoringSummaryView {
	return jobMonitoringSummary(record, store.JobExecutionSummary{LatestAttempt: attempt}, "", historyAvailable, appActivity, appActivityAvailable, cycleStatus, cycleAvailable, false, time.Date(2026, 10, 11, 8, 0, 0, 0, time.UTC))
}

func TestJobMonitoringSummaryStatusPrecedenceAndAvailability(t *testing.T) {
	t.Parallel()
	record := monitoringTestJob()
	failed := monitoringAttempt("failed")
	tests := []struct {
		name             string
		record           store.JobRecord
		attempt          *store.JobScanStatusSummary
		historyAvailable bool
		appActivity      string
		appAvailable     bool
		cycleStatus      string
		cycleAvailable   bool
		availability     string
		activity         *string
		scheduleState    string
		attention        string
	}{
		{name: "no scans yet", record: record, historyAvailable: true, appAvailable: true, cycleAvailable: true, availability: "available", activity: stringPointer("none"), scheduleState: "scheduled", attention: "none"},
		{name: "history query unavailable", record: record, historyAvailable: false, appAvailable: true, cycleAvailable: true, availability: "unavailable", activity: stringPointer("none"), scheduleState: "scheduled", attention: "none"},
		{name: "failed attempt", record: record, attempt: failed, historyAvailable: true, appAvailable: true, cycleAvailable: true, availability: "available", activity: stringPointer("none"), scheduleState: "scheduled", attention: "failed"},
		{name: "queued work supersedes failed attempt", record: record, attempt: failed, historyAvailable: true, appActivity: "queued", appAvailable: true, cycleAvailable: true, availability: "available", activity: stringPointer("queued"), scheduleState: "scheduled", attention: "none"},
		{name: "running work supersedes failed attempt", record: record, attempt: failed, historyAvailable: true, appActivity: "running", appAvailable: true, cycleAvailable: true, availability: "available", activity: stringPointer("running"), scheduleState: "scheduled", attention: "none"},
		{name: "paused resumable cycle retains failure", record: record, attempt: failed, historyAvailable: true, appAvailable: true, cycleStatus: "paused", cycleAvailable: true, availability: "available", activity: stringPointer("resumable"), scheduleState: "scheduled", attention: "failed"},
		{name: "stalled cycle remains actionable", record: record, attempt: failed, historyAvailable: true, appAvailable: true, cycleStatus: "stalled", cycleAvailable: true, availability: "available", activity: stringPointer("stalled"), scheduleState: "scheduled", attention: "stalled_cycle"},
		{name: "queued manual retry preserves stalled attention", record: record, attempt: failed, historyAvailable: true, appActivity: "queued", appAvailable: true, cycleStatus: "stalled", cycleAvailable: true, availability: "available", activity: stringPointer("queued"), scheduleState: "scheduled", attention: "stalled_cycle"},
		{name: "running manual retry preserves stalled attention", record: record, attempt: failed, historyAvailable: true, appActivity: "running", appAvailable: true, cycleStatus: "stalled", cycleAvailable: true, availability: "available", activity: stringPointer("running"), scheduleState: "scheduled", attention: "stalled_cycle"},
		{name: "cycle lookup failure preserves known failure", record: record, attempt: failed, historyAvailable: true, appAvailable: true, cycleAvailable: false, availability: "unavailable", activity: nil, scheduleState: "scheduled", attention: "failed"},
		{name: "cycle lookup failure keeps known queued state", record: record, attempt: failed, historyAvailable: true, appActivity: "queued", appAvailable: true, cycleAvailable: false, availability: "unavailable", activity: stringPointer("queued"), scheduleState: "scheduled", attention: "none"},
		{name: "activity lookup failure preserves known failure", record: record, attempt: failed, historyAvailable: true, appAvailable: false, cycleAvailable: false, availability: "unavailable", activity: nil, scheduleState: "scheduled", attention: "failed"},
		{name: "timed out is failure", record: record, attempt: monitoringAttempt("timed_out"), historyAvailable: true, appAvailable: true, cycleAvailable: true, availability: "available", activity: stringPointer("none"), scheduleState: "scheduled", attention: "failed"},
		{name: "incomplete attempt", record: record, attempt: monitoringAttempt("incomplete"), historyAvailable: true, appAvailable: true, cycleAvailable: true, availability: "available", activity: stringPointer("none"), scheduleState: "scheduled", attention: "incomplete"},
		{name: "canceled attempt is neutral", record: record, attempt: monitoringAttempt("canceled"), historyAvailable: true, appAvailable: true, cycleAvailable: true, availability: "available", activity: stringPointer("none"), scheduleState: "scheduled", attention: "none"},
		{name: "later success clears earlier failure", record: record, attempt: monitoringAttempt("success"), historyAvailable: true, appAvailable: true, cycleAvailable: true, availability: "available", activity: stringPointer("none"), scheduleState: "scheduled", attention: "none"},
		{name: "manual schedule keeps failure", record: manualMonitoringRecord(record), attempt: failed, historyAvailable: true, appAvailable: true, cycleAvailable: true, availability: "available", activity: stringPointer("none"), scheduleState: "manual", attention: "failed"},
		{name: "paused schedule keeps failure", record: pausedMonitoringRecord(record), attempt: failed, historyAvailable: true, appAvailable: true, cycleAvailable: true, availability: "available", activity: stringPointer("none"), scheduleState: "paused", attention: "failed"},
		{name: "archived schedule keeps failure", record: archivedMonitoringRecord(record), attempt: failed, historyAvailable: true, appAvailable: true, cycleAvailable: true, availability: "available", activity: stringPointer("none"), scheduleState: "archived", attention: "failed"},
		{name: "invalid schedule is distinguishable", record: invalidScheduleMonitoringRecord(record), historyAvailable: true, appAvailable: true, cycleAvailable: true, availability: "available", activity: stringPointer("none"), scheduleState: "unavailable", attention: "none"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			view := monitoringView(test.record, test.attempt, test.historyAvailable, test.appActivity, test.appAvailable, test.cycleStatus, test.cycleAvailable)
			if view.Availability != test.availability || view.Activity == nil && test.activity != nil || view.Activity != nil && (test.activity == nil || *view.Activity != *test.activity) || view.ScheduleState != test.scheduleState || view.AttentionReason != test.attention {
				t.Fatalf("monitoring summary = %+v; want availability=%q activity=%v schedule=%q attention=%q", view, test.availability, test.activity, test.scheduleState, test.attention)
			}
			if test.scheduleState != "scheduled" && view.NextRunAt != nil {
				t.Fatalf("unscheduled job next run = %s", view.NextRunAt)
			}
			if test.name == "no scans yet" && !view.HistoryAvailable || test.name == "history query unavailable" && view.HistoryAvailable {
				t.Fatalf("history availability = %v for %s", view.HistoryAvailable, test.name)
			}
			if test.name == "no scans yet" && (view.LatestAttempt != nil || view.LatestSuccessfulScan != nil) {
				t.Fatalf("no-scan job has scan history: %+v", view)
			}
		})
	}
}

func TestJobMonitoringScheduledBudgetSkipPrecedence(t *testing.T) {
	t.Parallel()
	record := monitoringTestJob()
	failed := store.JobExecutionSummary{LatestAttempt: monitoringAttempt("failed")}
	now := time.Date(2026, 10, 11, 8, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name           string
		activity       string
		activityLoaded bool
		cycle          string
		cycleLoaded    bool
		want           string
	}{
		{name: "saved budget skip remains visible over an older failure", activity: "none", activityLoaded: true, cycleLoaded: true, want: "probe_budget_skipped"},
		{name: "active queued work suppresses older budget skip", activity: "queued", activityLoaded: true, cycleLoaded: true, want: "none"},
		{name: "active running work suppresses older budget skip", activity: "running", activityLoaded: true, cycleLoaded: true, want: "none"},
		{name: "stalled cycle has higher precedence", activity: "none", activityLoaded: true, cycle: "stalled", cycleLoaded: true, want: "stalled_cycle"},
		{name: "known budget skip survives unavailable activity", want: "probe_budget_skipped"},
	} {
		t.Run(test.name, func(t *testing.T) {
			view := jobMonitoringSummary(record, failed, "scope-hash|65536", true, test.activity, test.activityLoaded, test.cycle, test.cycleLoaded, false, now)
			if view.AttentionReason != test.want {
				t.Fatalf("attention reason = %q, want %q", view.AttentionReason, test.want)
			}
		})
	}
}

func TestJobMonitoringSummaryNextRunUsesCronTimezoneDSTSemantics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		schedule string
		now      time.Time
		want     time.Time
	}{
		{name: "spring gap", schedule: "30 2 * * *", now: time.Date(2027, 3, 27, 12, 0, 0, 0, time.UTC), want: time.Date(2027, 3, 29, 0, 30, 0, 0, time.UTC)},
		{name: "fall repeated hour", schedule: "30 2 * * *", now: time.Date(2027, 10, 30, 12, 0, 0, 0, time.UTC), want: time.Date(2027, 10, 31, 0, 30, 0, 0, time.UTC)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := monitoringTestJob()
			record.Job.Schedule = test.schedule
			view := jobMonitoringSummary(record, store.JobExecutionSummary{}, "", true, "", true, "", true, false, test.now)
			if view.ScheduleState != "scheduled" || view.NextRunAt == nil || !view.NextRunAt.Equal(test.want) {
				t.Fatalf("next run = %+v, state %q; want %s", view.NextRunAt, view.ScheduleState, test.want)
			}
			parser := cronParserForCoverage()
			wantFromScheduler, err := parser.Parse("CRON_TZ=" + record.Job.Timezone + " " + test.schedule)
			if err != nil {
				t.Fatal(err)
			}
			if actual := wantFromScheduler.Next(test.now.UTC()); !view.NextRunAt.Equal(actual) {
				t.Fatalf("next run %s differs from scheduler semantics %s", view.NextRunAt, actual)
			}
		})
	}
}

func TestJobMonitoringSummaryScanIDsAndNullTimesRespectPermission(t *testing.T) {
	t.Parallel()
	record := monitoringTestJob()
	scan := &store.JobScanStatusSummary{ID: "scan-private-id", Status: "failed"}
	view := jobMonitoringSummary(record, store.JobExecutionSummary{LatestAttempt: scan}, "", true, "", true, "", true, false, time.Now().UTC())
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "scan-private-id") || !strings.Contains(string(encoded), `"started_at":null`) || !strings.Contains(string(encoded), `"finished_at":null`) {
		t.Fatalf("jobs.read monitoring data = %s; scan ID must be omitted and missing times explicit", encoded)
	}
	allowed := jobMonitoringSummary(record, store.JobExecutionSummary{LatestAttempt: scan}, "", true, "", true, "", true, true, time.Now().UTC())
	if allowed.LatestAttempt == nil || allowed.LatestAttempt.ScanID != scan.ID {
		t.Fatalf("scans.read latest attempt = %+v", allowed.LatestAttempt)
	}
}

func TestJobListMonitoringFieldsArePermissionScopedAndDoNotExposeScanErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	record, err := defaultTenantStore(server).CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "monitoring-permission", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"},
		TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.BudgetSkipAlertKey = "private-budget-projection|65536"
		return nil, nil
	}); err != nil {
		t.Fatalf("save scheduled budget skip: %v", err)
	}
	stamp := time.Date(2026, 10, 11, 8, 30, 0, 0, time.UTC)
	if err := db.System().SaveScan(ctx, model.Scan{ID: "private-success-id", JobID: record.ID, Job: record.Job.Name, Status: "success", StartedAt: stamp.Add(-time.Minute), FinishedAt: stamp.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := db.System().SaveScan(ctx, model.Scan{ID: "private-scan-id", JobID: record.ID, Job: record.Job.Name, Status: "failed", Error: "private diagnostic text", StartedAt: stamp, FinishedAt: stamp}); err != nil {
		t.Fatal(err)
	}
	viewerUser, err := storetest.CreateUser(ctx, db, store.DefaultTenantScope(), store.User{Username: "monitoring-viewer", DisplayName: "Viewer", Role: store.RoleViewer, PasswordHash: "unused-hash", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	viewer := store.Session{UserID: viewerUser.ID, Username: viewerUser.Username, Role: store.RoleViewer, CSRFToken: "viewer-csrf"}
	admin.CSRFToken = "admin-csrf"
	createSession := func(session store.Session, raw string) {
		t.Helper()
		now := time.Now().UTC()
		if err := storetest.CreateSession(ctx, db, session.UserID, digest(raw), session.CSRFToken, now, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	const viewerToken = "monitoring-viewer-token"
	const adminToken = "monitoring-admin-token"
	createSession(viewer, viewerToken)
	createSession(admin, adminToken)
	responseFor := func(session store.Session, token string) (map[string]any, string) {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/jobs?include_archived=true", nil)
		addTestSessionCookie(request, token)
		response := httptest.NewRecorder()
		server.api(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("GET /jobs = %d: %s", response.Code, response.Body.String())
		}
		var body struct {
			Jobs []map[string]any `json:"jobs"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Jobs) != 1 {
			t.Fatalf("GET /jobs payload = %s, %v", response.Body.String(), err)
		}
		return body.Jobs[0], response.Body.String()
	}
	viewerJob, viewerRaw := responseFor(viewer, viewerToken)
	viewerMonitoring := viewerJob["monitoring"].(map[string]any)
	viewerAttempt := viewerMonitoring["latest_attempt"].(map[string]any)
	viewerSuccess := viewerMonitoring["latest_successful_scan"].(map[string]any)
	if viewerAttempt["status"] != "failed" || viewerAttempt["scan_id"] != nil || viewerSuccess["status"] != "success" || viewerSuccess["scan_id"] != nil || viewerMonitoring["attention_reason"] != "probe_budget_skipped" || strings.Contains(viewerRaw, "private diagnostic text") || strings.Contains(viewerRaw, "private-scan-id") || strings.Contains(viewerRaw, "private-success-id") || strings.Contains(viewerRaw, "private-budget-projection") {
		t.Fatalf("jobs.read viewer response = %s", viewerRaw)
	}
	adminJob, adminRaw := responseFor(admin, adminToken)
	adminMonitoring := adminJob["monitoring"].(map[string]any)
	adminAttempt := adminMonitoring["latest_attempt"].(map[string]any)
	adminSuccess := adminMonitoring["latest_successful_scan"].(map[string]any)
	if adminAttempt["scan_id"] != "private-scan-id" || adminSuccess["scan_id"] != "private-success-id" || adminMonitoring["attention_reason"] != "probe_budget_skipped" || strings.Contains(adminRaw, "private-budget-projection") || !strings.Contains(adminRaw, "private-scan-id") || !strings.Contains(adminRaw, "private-success-id") {
		t.Fatalf("scans.read admin response = %s", adminRaw)
	}
}

func stringPointer(value string) *string { return &value }

func manualMonitoringRecord(record store.JobRecord) store.JobRecord {
	record.Job.Schedule = ""
	return record
}

func pausedMonitoringRecord(record store.JobRecord) store.JobRecord {
	record.Enabled = false
	return record
}

func archivedMonitoringRecord(record store.JobRecord) store.JobRecord {
	record.Archived = true
	return record
}

func invalidScheduleMonitoringRecord(record store.JobRecord) store.JobRecord {
	record.Job.Schedule = "not a cron expression"
	return record
}
