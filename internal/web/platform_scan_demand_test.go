package web

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
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
	if wantFields := []string{"cadence_unattainable_jobs", "capacity_slot_seconds_per_day", "enabled_jobs", "estimated_slot_seconds_per_day", "history_jobs", "lower_bound_jobs", "over_capacity", "slots", "unestimated_jobs", "units", "utilization_percent", "work_limited_jobs"}; !reflect.DeepEqual(fields, wantFields) {
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
// so a job added meanwhile appears only once the estimate is older. The
// estimate is every request's, so a request that is canceled still
// completes the estimate it starts, for the requests that follow.
func TestPlatformStatusCachesTheScanDemand(t *testing.T) {
	t.Parallel()
	f := newPlatformFixtureWith(t, func(cfg *config.Config) { cfg.Scheduler.MaxConcurrent = 1 })
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	first, err := f.server.cachedDeploymentScanDemand(canceled)
	if err != nil || first.Units != 2 || first.EnabledJobs != 3 || first.EstimatedSlotSecondsPerDay != 0 || first.OverCapacity {
		t.Fatalf("the estimate of a canceled request = %+v, %v, want the fixture's three unestimated jobs", first, err)
	}
	if cached, body := platformScanDemand(t, f); cached == nil || *cached != first {
		t.Fatalf("the platform status after the canceled request = %s, want its cached %+v", body, first)
	}
	sixtyPercentDemandJob(t, f.db, f.a, "alpha-demand-job")
	if second, body := platformScanDemand(t, f); second == nil || *second != first {
		t.Fatalf("the platform status within the minute = %s, want the cached %+v", body, first)
	}

	f.server.deploymentScanDemand.mu.Lock()
	f.server.deploymentScanDemand.at = time.Now().Add(-deploymentScanDemandTTL)
	f.server.deploymentScanDemand.mu.Unlock()
	third, body := platformScanDemand(t, f)
	if third == nil || third.EnabledJobs != 4 || third.HistoryJobs != 1 || math.Abs(third.UtilizationPercent-60) > 0.01 || third.OverCapacity {
		t.Fatalf("the platform status after the minute = %s, want the new job at 60%%", body)
	}
}

// A failed estimate is cached for deploymentScanDemandTTL like a successful
// one: the platform status leaves the scan demand out without estimating
// again until the failure is a minute old, however often it is polled, and
// the daemon logs the failure once per estimate rather than once per poll.
// A request that stops waiting for another request's estimate logs nothing.
func TestPlatformStatusCachesAFailedScanDemandEstimate(t *testing.T) {
	t.Parallel()
	f := newPlatformFixtureWith(t, func(cfg *config.Config) { cfg.Scheduler.MaxConcurrent = 1 })
	var logs lockedBuffer
	f.server.Log = slog.New(slog.NewTextHandler(&logs, nil))
	ctx := context.Background()
	const failure = "deployment scan demand estimate failed"
	record := sixtyPercentDemandJob(t, f.db, f.b, "bravo-demand-job")
	var definition string
	if err := f.db.DB.QueryRowContext(ctx, `SELECT definition_json FROM jobs WHERE id=?`, record.ID).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE jobs SET definition_json='{' WHERE id=?`, record.ID); err != nil {
		t.Fatal(err)
	}

	if demand, body := platformScanDemand(t, f); demand != nil {
		t.Fatalf("the platform status with an unreadable job = %s, want no scan_demand", body)
	}
	if got := strings.Count(logs.String(), failure); got != 1 {
		t.Fatalf("the failed estimate logged %d warnings, want 1:\n%s", got, logs.String())
	}
	// A new estimate would succeed now, so the status can only leave the
	// demand out while it reuses the failure.
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=?`, definition, record.ID); err != nil {
		t.Fatal(err)
	}
	for poll := range 3 {
		if demand, body := platformScanDemand(t, f); demand != nil {
			t.Fatalf("platform status %d within the minute of the failure = %s, want no scan_demand", poll, body)
		}
	}
	if _, err := f.server.cachedDeploymentScanDemand(ctx); err == nil {
		t.Fatal("the cached failure was not returned")
	}

	// A request whose context ends while another request estimates gets
	// its own error, which is no failure of the estimate.
	f.server.deploymentScanDemand.mu.Lock()
	f.server.deploymentScanDemand.at = time.Now().Add(-deploymentScanDemandTTL)
	f.server.deploymentScanDemand.running = true
	running := make(chan struct{})
	f.server.deploymentScanDemand.done = running
	f.server.deploymentScanDemand.mu.Unlock()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.server.cachedDeploymentScanDemand(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("a canceled request waiting for an estimate = %v, want context.Canceled", err)
	}
	f.server.deploymentScanDemand.mu.Lock()
	f.server.deploymentScanDemand.running = false
	close(running)
	f.server.deploymentScanDemand.mu.Unlock()
	if got := strings.Count(logs.String(), failure); got != 1 {
		t.Fatalf("the polls and the canceled request logged %d failures, want only the estimate's 1:\n%s", got, logs.String())
	}

	// Once the failure is a minute old, the next poll estimates again.
	demand, body := platformScanDemand(t, f)
	if demand == nil || demand.HistoryJobs != 1 || math.Abs(demand.UtilizationPercent-60) > 0.01 || demand.OverCapacity {
		t.Fatalf("the platform status after the minute = %s, want the repaired job at 60%%", body)
	}
	if got := strings.Count(logs.String(), failure); got != 1 {
		t.Fatalf("the successful estimate logged a failure:\n%s", logs.String())
	}
}

// Each estimate runs once per deploymentScanDemandTTL, whatever it
// returns: an estimate that fails, times out, or panics is not repeated for
// the polls within the minute, and the failure is logged once. The estimate
// runs on a context that the starting request's cancellation does not end,
// within deploymentScanDemandTimeout.
func TestDeploymentScanDemandEstimatesOncePerTTL(t *testing.T) {
	t.Parallel()
	const failure = "deployment scan demand estimate failed"
	for _, test := range []struct {
		name     string
		estimate func(context.Context) (app.DeploymentScanDemand, error)
		want     string
	}{
		{"timed out", func(context.Context) (app.DeploymentScanDemand, error) {
			return app.DeploymentScanDemand{}, context.DeadlineExceeded
		}, context.DeadlineExceeded.Error()},
		{"panicked", func(context.Context) (app.DeploymentScanDemand, error) {
			panic("unreadable unit")
		}, "scan demand estimate panic: unreadable unit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var logs lockedBuffer
			var calls atomic.Int32
			server := &Server{Log: slog.New(slog.NewTextHandler(&logs, nil))}
			server.deploymentScanDemandFunc = func(ctx context.Context) (app.DeploymentScanDemand, error) {
				calls.Add(1)
				return test.estimate(ctx)
			}
			for poll := range 4 {
				if _, err := server.cachedDeploymentScanDemand(context.Background()); err == nil || err.Error() != test.want {
					t.Fatalf("poll %d = %v, want %q", poll, err, test.want)
				}
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("four polls within the minute estimated %d times, want 1", got)
			}
			if got := strings.Count(logs.String(), failure); got != 1 || !strings.Contains(logs.String(), "retry_after=1m0s") {
				t.Fatalf("four polls logged %d failures, want 1 with its retry:\n%s", got, logs.String())
			}
			server.deploymentScanDemand.mu.Lock()
			server.deploymentScanDemand.at = time.Now().Add(-deploymentScanDemandTTL)
			server.deploymentScanDemand.mu.Unlock()
			if _, err := server.cachedDeploymentScanDemand(context.Background()); err == nil || calls.Load() != 2 {
				t.Fatalf("the poll after the minute = %v after %d estimates, want a second failed estimate", err, calls.Load())
			}
		})
	}

	t.Run("canceled request", func(t *testing.T) {
		t.Parallel()
		server := &Server{}
		server.deploymentScanDemandFunc = func(ctx context.Context) (app.DeploymentScanDemand, error) {
			if err := ctx.Err(); err != nil {
				return app.DeploymentScanDemand{}, err
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > deploymentScanDemandTimeout {
				return app.DeploymentScanDemand{}, errors.New("the estimate has no timeout")
			}
			return app.DeploymentScanDemand{Units: 1, Slots: 1, CapacitySlotSecondsPerDay: 86400}, nil
		}
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		if demand, err := server.cachedDeploymentScanDemand(canceled); err != nil || demand.Units != 1 {
			t.Fatalf("the estimate of a canceled request = %+v, %v, want its demand", demand, err)
		}
	})

	t.Run("no application", func(t *testing.T) {
		t.Parallel()
		if _, err := (&Server{}).cachedDeploymentScanDemand(context.Background()); !errors.Is(err, errNoApplication) {
			t.Fatalf("a server without an application = %v, want errNoApplication", err)
		}
	})
}
