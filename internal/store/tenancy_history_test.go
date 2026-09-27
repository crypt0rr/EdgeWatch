package store

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// The history that addTenantHistory adds to the tenant fixture.
const (
	// tenantHistoryIncident is the key of the incident of each tenant's
	// "edge" job. Both tenants scan the same addresses, so the keys match.
	tenantHistoryIncident = "port|192.0.2.10|tcp|443"
	// tenantHistoryLegacyScan is a failed scan of the default tenant's
	// config.yaml job, which has the same name as the managed jobs.
	tenantHistoryLegacyScan = "scan-legacy-tenant-a"
)

func tenantHistoryChange() model.Change {
	return model.Change{Key: tenantHistoryIncident, Kind: "port", Target: "192.0.2.10", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}
}

// addTenantHistory gives the tenant fixture its event and incident history.
// Each tenant's "edge" job has a baseline, one incident with the same key,
// and one event, marked with the tenant, whose delivery failed for good.
// The default tenant also has the history of a config.yaml job named "edge":
// a failed scan, an event and a stored state. The platform has an event and
// a delivery that failed for good.
func addTenantHistory(t *testing.T, s *Store, ids tenantFixtureIDs) {
	t.Helper()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 13, 0, 0, 0, time.UTC)
	for _, owner := range []struct{ job, scan, marker string }{{ids.jobA, ids.scanA, "tenant-a"}, {ids.jobB, ids.scanB, "tenant-b"}} {
		if _, err := s.System().UpdateRuntimeWithOutbox(ctx, owner.job, []string{"history-destination"}, func(state *model.JobState) ([]model.Event, error) {
			state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.10", Protocol: "tcp", Ports: "443"}}}
			state.Incidents[tenantHistoryIncident] = model.Incident{Change: tenantHistoryChange(), ScanID: owner.scan, OpenedAt: at, LastSeenAt: at}
			return []model.Event{{Type: "changes-detected", Job: "edge", ScanID: owner.scan, Message: owner.marker, CreatedAt: at}}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	legacy := model.Scan{ID: tenantHistoryLegacyScan, Job: "edge", StartedAt: at.Add(-time.Minute), FinishedAt: at, Status: "failed", Error: "legacy-a"}
	if err := s.System().SaveScan(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().UpdateState(ctx, "edge", func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = tenantHistoryLegacyScan
		return []model.Event{{Type: "scan-failure", Job: "edge", ScanID: tenantHistoryLegacyScan, Message: "legacy-a", CreatedAt: at.Add(time.Minute)}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	platform := model.Event{Type: "platform-notice", Message: "platform", CreatedAt: at.Add(2 * time.Minute)}
	_, payload, err := model.MarshalBoundedEvent(platform, model.EventPayloadLimit)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertEventExec(ctx, s.DB, platform, payload, platform.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if err := s.System().QueueEvent(ctx, "history-platform-destination", platform); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET attempts=?`, deliveryMaxAttempts); err != nil {
		t.Fatal(err)
	}
}

// The history and incident cases join tenantStoreLeakCases before any test
// runs, so the completeness check and TestTenantStoreIsolation cover them as
// they cover the cases declared with the map.
func init() {
	for name, leak := range tenantHistoryLeakCases {
		if _, exists := tenantStoreLeakCases[name]; exists {
			panic("duplicate tenant leak case " + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

var tenantHistoryLeakCases = map[string]tenantLeakCase{
	"ListScans": {run: func(t *testing.T, f tenantFixture) {
		checkTenantScanLists(t, f, func(ts *TenantStore, job string) ([]string, int, error) {
			scans, err := ts.ListScans(context.Background(), job, 10)
			ids := make([]string, 0, len(scans))
			for _, scan := range scans {
				ids = append(ids, scan.ID)
			}
			return ids, len(scans), err
		})
	}},
	"ListScansPage": {run: func(t *testing.T, f tenantFixture) {
		checkTenantScanLists(t, f, func(ts *TenantStore, job string) ([]string, int, error) {
			page, err := ts.ListScansPage(context.Background(), job, 10, 0)
			ids := make([]string, 0, len(page.Items))
			for _, scan := range page.Items {
				ids = append(ids, scan.ID)
			}
			return ids, page.Total, err
		})
	}},
	"ListScanSummariesPage": {run: func(t *testing.T, f tenantFixture) {
		checkTenantScanLists(t, f, func(ts *TenantStore, job string) ([]string, int, error) {
			page, err := ts.ListScanSummariesPage(context.Background(), job, 10, 0)
			ids := make([]string, 0, len(page.Items))
			for _, scan := range page.Items {
				ids = append(ids, scan.ID)
			}
			return ids, page.Total, err
		})
	}},
	"ListEvents": {run: func(t *testing.T, f tenantFixture) {
		checkTenantEventLists(t, f, func(ts *TenantStore, job string) ([]model.Event, int, error) {
			events, err := ts.ListEvents(context.Background(), job, 10)
			return events, len(events), err
		})
	}},
	"ListEventsPage": {run: func(t *testing.T, f tenantFixture) {
		checkTenantEventLists(t, f, func(ts *TenantStore, job string) ([]model.Event, int, error) {
			page, err := ts.ListEventsPage(context.Background(), job, 10, 0)
			return page.Items, page.Total, err
		})
	}},
	"ListJobEvents": {run: func(t *testing.T, f tenantFixture) {
		checkTenantJobEventLists(t, f, func(ts *TenantStore, jobID string) ([]model.Event, int, error) {
			events, err := ts.ListJobEvents(context.Background(), jobID, 10)
			return events, len(events), err
		})
	}},
	"ListJobEventsPage": {run: func(t *testing.T, f tenantFixture) {
		checkTenantJobEventLists(t, f, func(ts *TenantStore, jobID string) ([]model.Event, int, error) {
			page, err := ts.ListJobEventsPage(context.Background(), jobID, 10, 0)
			return page.Items, page.Total, err
		})
	}},
	"ListJobIncidentsPage": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for _, check := range []struct {
			scope    TenantScope
			job      string
			wantScan string
		}{
			{f.b, f.jobA, ""},
			{f.b, f.jobB, f.scanB},
			{f.a, f.jobB, ""},
			{f.a, f.jobA, f.scanA},
		} {
			page, err := f.store.Tenant(check.scope).ListJobIncidentsPage(ctx, check.job, 10, 0)
			if err != nil {
				t.Fatal(err)
			}
			var scans []string
			for _, incident := range page.Items {
				scans = append(scans, incident.ScanID)
			}
			want := []string(nil)
			if check.wantScan != "" {
				want = []string{check.wantScan}
			}
			if !reflect.DeepEqual(scans, want) || page.Total != len(want) {
				t.Errorf("tenant %s, job %s: incidents of scans %v (total %d), want %v", check.scope.ID(), check.job, scans, page.Total, want)
			}
		}
	}},
	"ListIncidentsPage": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for scope, want := range map[TenantScope][2]string{f.a: {f.jobA, f.scanA}, f.b: {f.jobB, f.scanB}} {
			page, err := f.store.Tenant(scope).ListIncidentsPage(ctx, 10, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Items) != 1 || page.Total != 1 {
				t.Fatalf("tenant %s: incidents = %+v (total %d), want one", scope.ID(), page.Items, page.Total)
			}
			item := page.Items[0]
			if item.JobID != want[0] || item.Job != "edge" || item.Incident.ScanID != want[1] || item.Incident.Change.Key != tenantHistoryIncident {
				t.Errorf("tenant %s: incident = %+v, want job %s and scan %s", scope.ID(), item, want[0], want[1])
			}
		}
	}},
	"FailedDeliveries": {run: func(t *testing.T, f tenantFixture) {
		// Each tenant counts its own delivery. The platform's is counted by
		// the platform only, not by the default tenant.
		for scope, want := range map[TenantScope]int{f.a: 1, f.b: 1} {
			if got, err := f.store.Tenant(scope).FailedDeliveries(context.Background()); err != nil || got != want {
				t.Errorf("tenant %s: failed deliveries = %d, %v; want %d", scope.ID(), got, err, want)
			}
		}
		if got, err := f.store.Platform().FailedDeliveries(context.Background()); err != nil || got != 1 {
			t.Errorf("the platform's failed deliveries = %d, %v; want its own one", got, err)
		}
	}},
	"State": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		// A config.yaml job belongs to the default tenant. Another tenant
		// reads an empty state for the same name, as for an unknown job.
		state, err := f.store.Tenant(f.a).State(ctx, "edge")
		if err != nil || state.BaselineScanID != tenantHistoryLegacyScan {
			t.Fatalf("tenant A's config.yaml job state = %+v, %v", state, err)
		}
		for _, name := range []string{"edge", "missing"} {
			state, err := f.store.Tenant(f.b).State(ctx, name)
			if err != nil || !reflect.DeepEqual(state, emptyState()) {
				t.Errorf("tenant B's state of %s = %+v, %v; want an empty state", name, state, err)
			}
		}
	}},
	"AcceptIncidentWithExpectedOutboxAndAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		expected := &IncidentExpectation{Change: tenantHistoryChange()}
		checkTenantIncidentWrite(t, f, "incident-accepted", func(ts *TenantStore, jobID string) error {
			_, err := ts.AcceptIncidentWithExpectedOutboxAndAudit(context.Background(), jobID, "edge", tenantHistoryIncident, expected, []string{"history-destination"}, AuditEntry{Action: "incident.accepted", Detail: jobID})
			return err
		})
	}},
	"SuppressIncidentWithExpectedOutboxAndAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		expected := &IncidentExpectation{Change: tenantHistoryChange()}
		checkTenantIncidentWrite(t, f, "incident-suppressed", func(ts *TenantStore, jobID string) error {
			_, err := ts.SuppressIncidentWithExpectedOutboxAndAudit(context.Background(), jobID, "edge", tenantHistoryIncident, expected, []string{"history-destination"}, AuditEntry{Action: "incident.suppressed", Detail: jobID})
			return err
		})
	}},
	"AcceptIncidentWithOutboxAndAudit": {run: func(t *testing.T, f tenantFixture) {
		checkTenantIncidentRefused(t, f, func(ts *TenantStore, jobID, key string) error {
			_, err := ts.AcceptIncidentWithOutboxAndAudit(context.Background(), jobID, "edge", key, []string{"history-destination"}, AuditEntry{Action: "incident.accepted", Detail: jobID})
			return err
		})
	}},
	"AcceptIncidentWithAudit": {run: func(t *testing.T, f tenantFixture) {
		checkTenantIncidentRefused(t, f, func(ts *TenantStore, jobID, key string) error {
			_, err := ts.AcceptIncidentWithAudit(context.Background(), jobID, "edge", key, AuditEntry{Action: "incident.accepted", Detail: jobID})
			return err
		})
	}},
	"SuppressIncidentWithOutboxAndAudit": {run: func(t *testing.T, f tenantFixture) {
		checkTenantIncidentRefused(t, f, func(ts *TenantStore, jobID, key string) error {
			_, err := ts.SuppressIncidentWithOutboxAndAudit(context.Background(), jobID, "edge", key, []string{"history-destination"}, AuditEntry{Action: "incident.suppressed", Detail: jobID})
			return err
		})
	}},
	"SuppressIncidentWithAudit": {run: func(t *testing.T, f tenantFixture) {
		checkTenantIncidentRefused(t, f, func(ts *TenantStore, jobID, key string) error {
			_, err := ts.SuppressIncidentWithAudit(context.Background(), jobID, "edge", key, AuditEntry{Action: "incident.suppressed", Detail: jobID})
			return err
		})
	}},
}

// checkTenantScanLists checks a scan list with and without the name filter.
// Every scan of the fixture belongs to a job named "edge": tenant A's
// managed job and its config.yaml job, and tenant B's managed job.
func checkTenantScanLists(t *testing.T, f tenantFixture, list func(ts *TenantStore, job string) ([]string, int, error)) {
	t.Helper()
	for _, check := range []struct {
		scope TenantScope
		job   string
		want  []string
	}{
		{f.b, "", []string{f.scanB}},
		{f.b, "edge", []string{f.scanB}},
		{f.b, "missing", nil},
		{f.a, "", sortedIDs(f.scanA, tenantHistoryLegacyScan)},
		{f.a, "edge", sortedIDs(f.scanA, tenantHistoryLegacyScan)},
	} {
		ids, total, err := list(f.store.Tenant(check.scope), check.job)
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(ids)
		if len(ids) == 0 {
			ids = nil
		}
		if !reflect.DeepEqual(ids, check.want) || total != len(check.want) {
			t.Errorf("tenant %s, job %q: scans = %v (total %d), want %v", check.scope.ID(), check.job, ids, total, check.want)
		}
	}
}

// eventMarkers returns the messages of the events, sorted. Each event of the
// fixture's history names its owner in its message.
func eventMarkers(events []model.Event) []string {
	var markers []string
	for _, event := range events {
		markers = append(markers, event.Message)
	}
	sort.Strings(markers)
	return markers
}

// checkTenantEventLists checks an event list with and without the name
// filter. No tenant's list holds the platform's event, the default
// tenant's included.
func checkTenantEventLists(t *testing.T, f tenantFixture, list func(ts *TenantStore, job string) ([]model.Event, int, error)) {
	t.Helper()
	for _, check := range []struct {
		scope TenantScope
		job   string
		want  []string
	}{
		{f.b, "", []string{"tenant-b"}},
		{f.b, "edge", []string{"tenant-b"}},
		{f.b, "missing", nil},
		{f.a, "", []string{"legacy-a", "tenant-a"}},
		{f.a, "edge", []string{"legacy-a", "tenant-a"}},
	} {
		events, total, err := list(f.store.Tenant(check.scope), check.job)
		if err != nil {
			t.Fatal(err)
		}
		if got := eventMarkers(events); !reflect.DeepEqual(got, check.want) || total != len(check.want) {
			t.Errorf("tenant %s, job %q: events = %v (total %d), want %v", check.scope.ID(), check.job, got, total, check.want)
		}
	}
}

// checkTenantJobEventLists checks the events of each tenant's job, read
// from both tenants.
func checkTenantJobEventLists(t *testing.T, f tenantFixture, list func(ts *TenantStore, jobID string) ([]model.Event, int, error)) {
	t.Helper()
	for _, check := range []struct {
		scope TenantScope
		job   string
		want  []string
	}{
		{f.b, f.jobA, nil},
		{f.b, f.jobB, []string{"tenant-b"}},
		{f.a, f.jobB, nil},
		{f.a, f.jobA, []string{"tenant-a"}},
	} {
		events, total, err := list(f.store.Tenant(check.scope), check.job)
		if err != nil {
			t.Fatal(err)
		}
		if got := eventMarkers(events); !reflect.DeepEqual(got, check.want) || total != len(check.want) {
			t.Errorf("tenant %s, job %s: events = %v (total %d), want %v", check.scope.ID(), check.job, got, total, check.want)
		}
	}
}

// tenantAIncidentHistory renders tenant A's incident state and history: the
// runtime state and metadata of its job, its incidents and scan cycles, and
// the events and deliveries of the default tenant.
func tenantAIncidentHistory(t *testing.T, f tenantFixture) string {
	t.Helper()
	var rows []string
	for _, query := range []string{
		`SELECT quote(state_json) FROM job_runtime WHERE job_id=?`,
		`SELECT quote(baseline_scan_id)||baseline_modified||baseline_epoch||pending_count FROM job_runtime_meta WHERE job_id=?`,
		`SELECT key||quote(incident_json) FROM runtime_incidents WHERE job_id=? ORDER BY key`,
		`SELECT id||status FROM scan_cycles WHERE job_id=? ORDER BY id`,
	} {
		rows = append(rows, strings.Join(queryStrings(t, f.store.DB, query, f.jobA), "\n"))
	}
	for _, query := range []string{
		`SELECT id||type||quote(payload_json) FROM events WHERE ` + historyTenantSQL + ` ORDER BY id`,
		`SELECT id||destination||attempts FROM outbox WHERE ` + historyTenantSQL + ` ORDER BY id`,
	} {
		rows = append(rows, strings.Join(queryStrings(t, f.store.DB, query, DefaultTenantID), "\n"))
	}
	return strings.Join(rows, "\n--\n")
}

// checkTenantIncidentWrite runs an incident action from tenant B. On tenant
// A's job it is refused as an unknown job and writes nothing, not even an
// audit record. On B's own job, whose incident has the same key as A's, it
// succeeds and leaves A's incident, state and history unchanged.
func checkTenantIncidentWrite(t *testing.T, f tenantFixture, eventType string, action func(ts *TenantStore, jobID string) error) {
	t.Helper()
	before := tenantAIncidentHistory(t, f)
	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	if err := action(f.store.Tenant(f.b), f.jobA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant B acted on tenant A's incident: %v", err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("a refused action wrote %d audit records", got-audits)
	}
	if err := action(f.store.Tenant(f.b), f.jobB); err != nil {
		t.Fatalf("tenant B's own incident: %v", err)
	}
	if after := tenantAIncidentHistory(t, f); after != before {
		t.Fatalf("tenant B's action changed tenant A:\nbefore\n%s\nafter\n%s", before, after)
	}
	page, err := f.store.Tenant(f.b).ListJobIncidentsPage(context.Background(), f.jobB, 10, 0)
	if err != nil || page.Total != 0 {
		t.Fatalf("tenant B's incidents after the action = %+v, %v", page, err)
	}
	if got := tenantOf(t, f.store.DB, `SELECT tenant_id FROM events WHERE type=?`, eventType); got != secondTenantID {
		t.Fatalf("the %s event belongs to %s, want tenant B", eventType, got)
	}
}

// checkTenantIncidentRefused runs an incident action from tenant B without
// letting it succeed, so the case can share the fixture. On tenant A's job
// it is refused as an unknown job, and A is unchanged. On B's own job it
// reaches the incident lookup, which shows the refusal comes from the
// tenant and not from a broken call.
func checkTenantIncidentRefused(t *testing.T, f tenantFixture, action func(ts *TenantStore, jobID, key string) error) {
	t.Helper()
	before := tenantAIncidentHistory(t, f)
	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	if err := action(f.store.Tenant(f.b), f.jobA, tenantHistoryIncident); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant B acted on tenant A's incident: %v", err)
	}
	if err := action(f.store.Tenant(f.b), f.jobB, "missing"); !errors.Is(err, ErrIncidentNotFound) {
		t.Fatalf("tenant B's own job, unknown incident: %v", err)
	}
	if after := tenantAIncidentHistory(t, f); after != before {
		t.Fatalf("tenant B's action changed tenant A:\nbefore\n%s\nafter\n%s", before, after)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("a refused action wrote %d audit records", got-audits)
	}
}

// The history checks outside the leak suite share one copy of the fixture,
// because opening a database is the slow part of these tests.
func TestTenantHistory(t *testing.T) {
	f := newTenantFixture(t)
	t.Run("event lists read in order", func(t *testing.T) { assertTenantEventListsReadInOrder(t, f) })
	t.Run("max event ID is global", func(t *testing.T) { assertMaxEventIDCoversEveryTenant(t, f) })
	t.Run("platform history is the platform's", func(t *testing.T) { assertPlatformHistoryIsThePlatforms(t, f) })
}

// Each tenant's event list, the default tenant's included, reads its own
// rows in order from the tenant index, and so does the platform's. None
// sorts the history.
func assertTenantEventListsReadInOrder(t *testing.T, f tenantFixture) {
	for _, scope := range []TenantScope{f.a, f.b} {
		query := `SELECT payload_json ` + eventsFromSQL + ` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`
		plan := queryPlan(t, f.store.DB, query, scope.ID(), 10, 0)
		if !strings.Contains(plan, "events_tenant_id_time") || strings.Contains(plan, "TEMP B-TREE") {
			t.Errorf("tenant %s: plan = %q, want events_tenant_id_time without a sort", scope.ID(), plan)
		}
	}
	plan := queryPlan(t, f.store.DB, `SELECT payload_json FROM events WHERE `+platformHistorySQL+` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, 10, 0)
	if !strings.Contains(plan, "events_tenant_id_time") || strings.Contains(plan, "TEMP B-TREE") {
		t.Errorf("platform: plan = %q, want events_tenant_id_time without a sort", plan)
	}
}

// The platform's events and deliveries belong to the platform's history
// only. The default tenant's history does not show them, while the default
// tenant's own rows are not the platform's.
func assertPlatformHistoryIsThePlatforms(t *testing.T, f tenantFixture) {
	ctx := context.Background()
	page, err := f.store.Platform().ListEventsPage(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := eventMarkers(page.Items); !reflect.DeepEqual(got, []string{"platform"}) || page.Total != 1 {
		t.Fatalf("the platform's events = %v (total %d), want its own event", got, page.Total)
	}
	for _, scope := range []TenantScope{f.a, f.b} {
		events, err := f.store.Tenant(scope).ListEventsPage(ctx, "", 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range eventMarkers(events.Items) {
			if marker == "platform" {
				t.Errorf("tenant %s lists the platform's event", scope.ID())
			}
		}
	}
	if page, err := f.store.Platform().ListEventsPage(ctx, 10, 1); err != nil || len(page.Items) != 0 || page.Total != 1 {
		t.Fatalf("the platform's second page = %+v, %v", page, err)
	}
}

// MaxEventID stays global: the live-update IDs are one sequence for every
// stream, so the floor covers every tenant's events and the platform's. The
// fixture's last event is the platform's, above each tenant's last one. The
// web server reads it through the live-update cursor.
func assertMaxEventIDCoversEveryTenant(t *testing.T, f tenantFixture) {
	want := countRows(t, f.store.DB, `SELECT MAX(id) FROM events`)
	if tenants := countRows(t, f.store.DB, `SELECT MAX(id) FROM events WHERE tenant_id IS NOT NULL`); tenants >= want {
		t.Fatalf("the fixture's last event (%d) belongs to a tenant; want the platform's last", want)
	}
	for label, read := range map[string]func(context.Context) (uint64, error){"system": f.store.System().MaxEventID, "live-update cursor": f.store.SSECursor().MaxEventID} {
		if got, err := read(context.Background()); err != nil || got != uint64(want) {
			t.Errorf("%s: max event ID = %d, %v; want %d", label, got, err, want)
		}
	}
}
