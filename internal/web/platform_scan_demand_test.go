package web

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// demandJobTarget is the address that the scan demand tests' jobs scan.
const demandJobTarget = "203.0.113.61"

// sixtyPercentDemandJob creates an enabled hourly job in the unit of ts with
// one completed 36-minute scan of its current settings, so its estimate is
// 24 × 36 minutes, 14.4 slot-hours a day: 60% of one slot.
func sixtyPercentDemandJob(t *testing.T, db *store.Store, ts *store.TenantStore, name string) store.JobRecord {
	t.Helper()
	ctx := context.Background()
	record, err := ts.CreateJob(ctx, config.NormalizeJob(config.Job{Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{demandJobTarget}, TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"}}))
	if err != nil {
		t.Fatal(err)
	}
	key := store.NewScanDurationKey(record)
	finished := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	if err := db.System().SaveScan(ctx, model.Scan{
		ID: "scan-" + name, JobID: record.ID, Job: name, JobRevision: record.Revision,
		StartedAt: finished.Add(-36 * time.Minute), FinishedAt: finished, Status: "success", ScannerEngine: config.EngineNmap,
		ScannerProfileID: key.ScannerProfileID, ScannerProfileRevision: key.ScannerProfileRevision, ConfigHash: key.ConfigHash,
	}); err != nil {
		t.Fatal(err)
	}
	return record
}

// platformScanDemand reads the scan demand of the platform status as the
// platform administrator, with the status's raw body.
func platformScanDemand(t *testing.T, f *platformFixture) (*app.DeploymentScanDemand, string) {
	t.Helper()
	response := f.call(t, actorPlatform, http.MethodGet, "/platform/status", "")
	var status struct {
		ScanDemand *app.DeploymentScanDemand `json:"scan_demand"`
	}
	expectResponse(t, response, http.StatusOK, "platform status", &status)
	return status.ScanDemand, response.Body.String()
}

// Three active units that each schedule 60% of a one-slot pool see no
// warning in their own view, while the platform status reports that they
// need 180% of the pool together. A disabled unit's jobs add nothing. The
// platform status holds sums and counts only: no unit's or job's name or
// ID, and no address. The unit's accounts reach neither the route nor the
// aggregate.
func TestPlatformStatusReportsTheUnitsScanDemandAgainstTheSharedPool(t *testing.T) {
	t.Parallel()
	f := newPlatformFixtureWith(t, func(cfg *config.Config) { cfg.Scheduler.MaxConcurrent = 1 })
	ctx := context.Background()
	audit := store.AuditEntry{ActorUserID: f.users[actorPlatform].ID, ActorUsername: "platform-root"}
	markers := append(append(f.dataMarkers(), f.markersOf("A")...), f.markersOf("B")...)
	markers = append(markers, demandJobTarget, "Charlie Unit", "Delta Unit")
	units := []*store.TenantStore{f.a, f.b}
	var delta store.TenantRecord
	for _, unit := range []struct{ name, slug string }{{"Charlie Unit", "charlie"}, {"Delta Unit", "delta"}} {
		record, err := f.server.App.CreateUnit(ctx, unit.name, unit.slug, audit)
		if err != nil {
			t.Fatal(err)
		}
		scope, err := f.db.TenantScopeByID(ctx, record.ID)
		if err != nil {
			t.Fatal(err)
		}
		units = append(units, f.db.Tenant(scope))
		markers = append(markers, record.ID, unit.slug)
		delta = record
	}
	for i, ts := range units {
		name := []string{"alpha-demand-job", "bravo-demand-job", "charlie-demand-job", "delta-demand-job"}[i]
		record := sixtyPercentDemandJob(t, f.db, ts, name)
		markers = append(markers, name, record.ID, "scan-"+name)
	}
	if _, err := f.db.Platform().DisableTenant(ctx, delta.ID, delta.Revision, audit); err != nil {
		t.Fatal(err)
	}

	// Each unit's own estimate is 60% of the one slot, below the warning.
	for _, actor := range []string{actorAdminA, actorAdminB} {
		var own app.ScanSlotDemand
		expectResponse(t, f.call(t, actor, http.MethodGet, "/jobs/slot-demand", ""), http.StatusOK, "slot demand as "+actor, &own)
		if own.Slots != 1 || own.HistoryJobs != 1 || own.OverCapacity || math.Abs(own.UtilizationPercent-60) > 0.01 {
			t.Fatalf("the slot demand as %s = %+v, want one history job at 60%% of one slot", actor, own)
		}
	}

	demand, body := platformScanDemand(t, f)
	if demand == nil {
		t.Fatalf("platform status = %s, want scan_demand", body)
	}
	// The fixture's three jobs have no history of their current settings
	// and no configured rate, so they are unestimated and add nothing.
	want := app.DeploymentScanDemand{
		Units: 3, EnabledJobs: 6, HistoryJobs: 3, UnestimatedJobs: 3, Slots: 1,
		EstimatedSlotSecondsPerDay: 3 * 0.6 * 86400, CapacitySlotSecondsPerDay: 86400,
		UtilizationPercent: 180, OverCapacity: true,
	}
	if math.Abs(demand.EstimatedSlotSecondsPerDay-want.EstimatedSlotSecondsPerDay) > 0.01 || math.Abs(demand.UtilizationPercent-want.UtilizationPercent) > 0.01 {
		t.Fatalf("platform scan demand = %+v, want %+v", *demand, want)
	}
	demand.EstimatedSlotSecondsPerDay, demand.UtilizationPercent = want.EstimatedSlotSecondsPerDay, want.UtilizationPercent
	if *demand != want {
		t.Fatalf("platform scan demand = %+v, want %+v", *demand, want)
	}

	// The aggregate has exactly its numeric fields, and the status names
	// no unit, job, scan, or address.
	var raw struct {
		ScanDemand map[string]json.RawMessage `json:"scan_demand"`
	}
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatal(err)
	}
	var fields []string
	for field, value := range raw.ScanDemand {
		fields = append(fields, field)
		if value[0] == '"' || value[0] == '[' || value[0] == '{' {
			t.Errorf("scan_demand.%s = %s, want a number or a boolean", field, value)
		}
	}
	slices.Sort(fields)
	if wantFields := []string{"cadence_unattainable_jobs", "capacity_slot_seconds_per_day", "enabled_jobs", "estimated_slot_seconds_per_day", "history_jobs", "lower_bound_jobs", "over_capacity", "slots", "unestimated_jobs", "units", "utilization_percent"}; !reflect.DeepEqual(fields, wantFields) {
		t.Fatalf("scan_demand fields = %v, want %v", fields, wantFields)
	}
	expectNoMarkers(t, body, "platform status", markers...)

	// The route stays the platform administrator's, and a unit's status
	// carries no aggregate.
	for _, actor := range []string{actorAdminA, actorOperatorA, actorViewerA, actorAdminB} {
		response := f.call(t, actor, http.MethodGet, "/platform/status", "")
		if details := expectError(t, response, http.StatusForbidden, "forbidden", "platform status as "+actor); details["permission"] != "platform_status.read" {
			t.Fatalf("platform status as %s = %s, want 403 for platform_status.read", actor, response.Body.String())
		}
		response = f.call(t, actor, http.MethodGet, "/status", "")
		if response.Code != http.StatusOK {
			t.Fatalf("status as %s = %d %s", actor, response.Code, response.Body.String())
		}
		requireFields(t, "unit status", actor, response.Body.String(), false, "scan_demand", "estimated_slot_seconds_per_day")
	}
}

// The platform status reuses its scan demand for deploymentScanDemandTTL,
// so a job added meanwhile appears only once the estimate is older, and a
// failed estimate is not reused.
func TestPlatformStatusCachesTheScanDemand(t *testing.T) {
	t.Parallel()
	f := newPlatformFixtureWith(t, func(cfg *config.Config) { cfg.Scheduler.MaxConcurrent = 1 })
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.server.cachedDeploymentScanDemand(canceled); err == nil {
		t.Fatal("an estimate with a canceled context succeeded")
	}

	first, body := platformScanDemand(t, f)
	if first == nil || first.Units != 2 || first.EnabledJobs != 3 || first.EstimatedSlotSecondsPerDay != 0 || first.OverCapacity {
		t.Fatalf("the first platform status = %s, want the fixture's three unestimated jobs", body)
	}
	sixtyPercentDemandJob(t, f.db, f.a, "alpha-demand-job")
	if second, body := platformScanDemand(t, f); second == nil || *second != *first {
		t.Fatalf("the platform status within the minute = %s, want the cached %+v", body, *first)
	}

	f.server.deploymentScanDemand.mu.Lock()
	f.server.deploymentScanDemand.at = time.Now().Add(-deploymentScanDemandTTL)
	f.server.deploymentScanDemand.mu.Unlock()
	third, body := platformScanDemand(t, f)
	if third == nil || third.EnabledJobs != 4 || third.HistoryJobs != 1 || math.Abs(third.UtilizationPercent-60) > 0.01 || third.OverCapacity {
		t.Fatalf("the platform status after the minute = %s, want the new job at 60%%", body)
	}

	if _, err := (&Server{}).cachedDeploymentScanDemand(context.Background()); err == nil {
		t.Fatal("a server without an application estimated the scan demand")
	}
}
