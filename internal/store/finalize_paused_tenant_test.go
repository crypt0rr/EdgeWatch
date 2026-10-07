package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

// pausedTenantDestination is the destination that the finalizations below
// queue their alerts for.
const pausedTenantDestination = "file:paused-tenant-destination"

// jobRuntimeDigest renders every row that the finalization of a scan of the
// job could change apart from the scan itself: its runtime state, baseline
// metadata, baseline hosts and incidents, its silence state, its events, the
// alerts queued in its tenant and its hosts in the latest-scan projection.
func jobRuntimeDigest(t *testing.T, s *Store, jobID string) string {
	t.Helper()
	var rows []string
	for _, query := range []string{
		`SELECT group_concat(quote(state_json)||updated_at, ',') FROM job_runtime WHERE job_id=?`,
		`SELECT group_concat(COALESCE(baseline_scan_id,'')||':'||COALESCE(baseline_epoch,0)||':'||candidate_count||':'||updated_at, ',') FROM job_runtime_meta WHERE job_id=?`,
		`SELECT COUNT(*) FROM baseline_hosts WHERE job_id=?`,
		`SELECT group_concat(key, ',') FROM runtime_incidents WHERE job_id=?`,
		`SELECT group_concat(eligible_at||':'||backoff_level||':'||next_alert_at||':'||last_success_at||':'||updated_at, ',') FROM job_silence_state WHERE job_id=?`,
		`SELECT COUNT(*) FROM events WHERE job_id=?`,
		`SELECT COUNT(*) FROM outbox WHERE tenant_id=(SELECT tenant_id FROM jobs WHERE id=?)`,
		`SELECT COUNT(*) FROM latest_scan_hosts WHERE job_id=?`,
	} {
		var value sql.NullString
		if err := s.DB.QueryRow(query, jobID).Scan(&value); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		rows = append(rows, value.String)
	}
	return strings.Join(rows, "\n")
}

// pausedTenantScan is a successful scan of the job that found two hosts.
func pausedTenantScan(ctx context.Context, t *testing.T, s *Store, scope TenantScope, jobID, id string) model.Scan {
	t.Helper()
	record, err := s.Tenant(scope).GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	return model.Scan{ID: id, JobID: jobID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now.Add(-time.Minute), FinishedAt: now, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{Hosts: fixtureHosts(0, 2)}}
}

// finalizeAsBaseline finalizes the scan with a finalizer that makes it the
// baseline and raises baseline-complete, and reports whether the finalizer
// ran.
func finalizeAsBaseline(ctx context.Context, s *Store, scan *model.Scan) ([]model.Event, bool, error) {
	ran := false
	events, err := s.System().FinalizeManagedScan(ctx, scan, scan.JobID, scan.ConfigHash, []string{pausedTenantDestination}, func(state *model.JobState, current *model.Scan) ([]model.Event, error) {
		ran = true
		state.Baseline = &current.Snapshot
		state.BaselineScanID, state.BaselineConfigHash = current.ID, current.ConfigHash
		return []model.Event{{Type: "baseline-complete", JobID: current.JobID, Job: current.Job, ScanID: current.ID, CreatedAt: current.FinishedAt}}, nil
	})
	return events, ran, err
}

// storedScanOutcome returns the status, error and cycle status of a stored
// scan, or sql.ErrNoRows.
func storedScanOutcome(s *Store, id string) (string, error) {
	var status, message, cycleStatus string
	err := s.DB.QueryRow(`SELECT status,error,cycle_status FROM scans WHERE id=?`, id).Scan(&status, &message, &cycleStatus)
	return status + "|" + message + "|" + cycleStatus, err
}

// A scan that finishes after its tenant was disabled, such as a host
// command's scan that overlapped the disable, is recorded as canceled and
// changes nothing else: the finalizer does not run, and the job's runtime
// state, baseline, incidents, silence state, events, alerts and latest hosts
// stay as they were. Enabling the tenant again lets the next scan finalize
// as before, and tenant A's scans are not affected by the pause.
func TestFinalizeManagedScanRecordsAScanOfADisabledTenantAsCanceled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	platform := f.store.Platform()
	b, err := platform.GetTenant(ctx, secondTenantID)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := platform.DisableTenant(ctx, secondTenantID, b.Revision, AuditEntry{ActorKind: AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	before := jobRuntimeDigest(t, f.store, f.jobB)

	scan := pausedTenantScan(ctx, t, f.store, f.b, f.jobB, "paused-scan-1")
	events, ran, err := finalizeAsBaseline(ctx, f.store, &scan)
	if !errors.Is(err, ErrTenantNotActive) || events != nil || ran {
		t.Fatalf("finalize a scan of a disabled tenant = %v, %v, finalizer ran %t; want %v and no finalizer", events, err, ran, ErrTenantNotActive)
	}
	if scan.Status != "canceled" || scan.Error != ScanCanceledByPauseMessage {
		t.Fatalf("the scan is %q, %q; want it canceled by the pause", scan.Status, scan.Error)
	}
	if got, err := storedScanOutcome(f.store, scan.ID); err != nil || got != "canceled|"+ScanCanceledByPauseMessage+"|" {
		t.Fatalf("stored scan = %q, %v; want the canceled scan", got, err)
	}
	var comparison string
	if err := f.store.DB.QueryRow(`SELECT comparison FROM scans WHERE id=?`, scan.ID).Scan(&comparison); err != nil || comparison != model.ScanComparisonNotCompared {
		t.Fatalf("stored scan comparison = %q, %v; want %q", comparison, err, model.ScanComparisonNotCompared)
	}
	if after := jobRuntimeDigest(t, f.store, f.jobB); after != before {
		t.Fatalf("the scan changed the disabled tenant's job:\nbefore\n%s\nafter\n%s", before, after)
	}
	if state, err := f.store.Tenant(f.b).RuntimeState(ctx, f.jobB); err != nil || state.BaselineScanID != "" {
		t.Fatalf("the disabled tenant's runtime state = %+v, %v; want no baseline scan", state, err)
	}
	if latest, err := f.store.Tenant(f.b).GetLatestSuccessfulJobScanSummary(ctx, f.jobB); err != nil || latest == nil || latest.ID != f.scanB {
		t.Fatalf("the latest successful scan = %+v, %v; want the earlier %s", latest, err, f.scanB)
	}

	// Tenant A is active, and its scan finalizes as before.
	scanA := pausedTenantScan(ctx, t, f.store, f.a, f.jobA, "active-scan-a")
	if events, ran, err := finalizeAsBaseline(ctx, f.store, &scanA); err != nil || !ran || len(events) != 1 || scanA.Status != "success" {
		t.Fatalf("finalize tenant A's scan = %v, %v, finalizer ran %t", events, err, ran)
	}
	if state, err := defaultTenant(f.store).RuntimeState(ctx, f.jobA); err != nil || state.BaselineScanID != scanA.ID {
		t.Fatalf("tenant A's runtime state = %+v, %v; want its scan as the baseline", state, err)
	}

	// Enabled again, tenant B's next scan finalizes as before.
	if _, err := platform.EnableTenant(ctx, secondTenantID, disabled.Revision, AuditEntry{ActorKind: AuditActorHost}); err != nil {
		t.Fatal(err)
	}
	next := pausedTenantScan(ctx, t, f.store, f.b, f.jobB, "paused-scan-2")
	if events, ran, err := finalizeAsBaseline(ctx, f.store, &next); err != nil || !ran || len(events) != 1 || next.Status != "success" {
		t.Fatalf("finalize after the tenant was enabled = %v, %v, finalizer ran %t", events, err, ran)
	}
	if state, err := f.store.Tenant(f.b).RuntimeState(ctx, f.jobB); err != nil || state.BaselineScanID != next.ID {
		t.Fatalf("tenant B's runtime state after it was enabled = %+v, %v; want the next scan as the baseline", state, err)
	}
	if after := jobRuntimeDigest(t, f.store, f.jobB); after == before {
		t.Fatal("the scan after the tenant was enabled changed nothing")
	}
}

// A scan of a disabled tenant that failed keeps its outcome but raises no
// scan-failure alert and counts no failure. A tenant that is being deleted
// records nothing: its data is being erased.
func TestFinalizeManagedScanOfAPausedTenantKeepsFailuresAndRecordsNothingWhileDeleting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	platform := f.store.Platform()
	b, err := platform.GetTenant(ctx, secondTenantID)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := platform.DisableTenant(ctx, secondTenantID, b.Revision, AuditEntry{ActorKind: AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	before := jobRuntimeDigest(t, f.store, f.jobB)
	failed := pausedTenantScan(ctx, t, f.store, f.b, f.jobB, "paused-failed")
	failed.Status, failed.Error = "failed", "nmap exited with status 1"
	if _, ran, err := finalizeAsBaseline(ctx, f.store, &failed); !errors.Is(err, ErrTenantNotActive) || ran {
		t.Fatalf("finalize a failed scan of a disabled tenant = %v, finalizer ran %t", err, ran)
	}
	if got, err := storedScanOutcome(f.store, failed.ID); err != nil || got != "failed|nmap exited with status 1|" {
		t.Fatalf("stored failed scan = %q, %v", got, err)
	}
	if after := jobRuntimeDigest(t, f.store, f.jobB); after != before {
		t.Fatalf("the failed scan changed the disabled tenant's job:\nbefore\n%s\nafter\n%s", before, after)
	}

	deleting := pausedTenantScan(ctx, t, f.store, f.b, f.jobB, "deleting-scan")
	if _, err := platform.RequestTenantDeletion(ctx, secondTenantID, disabled.Name, AuditEntry{ActorKind: AuditActorHost}); err != nil {
		t.Fatal(err)
	}
	if _, ran, err := finalizeAsBaseline(ctx, f.store, &deleting); !errors.Is(err, ErrTenantNotActive) || ran {
		t.Fatalf("finalize a scan of a tenant being deleted = %v, finalizer ran %t", err, ran)
	}
	if deleting.Status != "canceled" {
		t.Fatalf("the scan of a tenant being deleted is %q, want canceled", deleting.Status)
	}
	if got, err := storedScanOutcome(f.store, deleting.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("stored scan of a tenant being deleted = %q, %v; want none", got, err)
	}
	if after := jobRuntimeDigest(t, f.store, f.jobB); after != before {
		t.Fatalf("the scan changed the job of a tenant being deleted:\nbefore\n%s\nafter\n%s", before, after)
	}
}

// The final scan of a resumable cycle that completed after its tenant was
// disabled is recorded as canceled, and the cycle is
// discarded with its checkpoints, so the first run after the tenant is
// enabled again does not promote it. A cancelled attempt keeps its paused
// cycle and checkpoints, as the cancel of a running scan does, so the cycle
// resumes once the tenant is enabled.
func TestFinalizeManagedScanOfAPausedTenantDiscardsACompletedCycleAndKeepsAPausedOne(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, status, cycleStatus string
		wantScan, wantCycle       string
		wantUnits                 int
	}{
		{name: "completed", status: "success", cycleStatus: "completed", wantScan: "canceled|" + ScanCanceledByPauseMessage + "|discarded", wantCycle: "discarded", wantUnits: 0},
		{name: "paused", status: "canceled", cycleStatus: "paused", wantScan: "canceled|scan canceled|paused", wantCycle: "paused", wantUnits: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f := newTenantFixture(t)
			record, err := f.store.Tenant(f.b).GetJob(ctx, f.jobB)
			if err != nil {
				t.Fatal(err)
			}
			epoch, err := f.store.Tenant(f.b).RuntimeBaselineEpoch(ctx, f.jobB)
			if err != nil {
				t.Fatal(err)
			}
			plan := scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"127.0.0.1"}, Ports: "1", PortCount: 1, Probes: 1}}}
			cycle, err := f.store.System().CreateScanCycle(ctx, ScanCycleRecord{JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision, ConfigHash: record.Job.SecurityHash(), BaselineEpoch: epoch, Plan: plan})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.DB.ExecContext(ctx, `UPDATE scan_cycles SET status=? WHERE id=?`, tc.cycleStatus, cycle.ID); err != nil {
				t.Fatal(err)
			}
			b, err := f.store.Platform().GetTenant(ctx, secondTenantID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.Platform().DisableTenant(ctx, secondTenantID, b.Revision, AuditEntry{ActorKind: AuditActorHost}); err != nil {
				t.Fatal(err)
			}
			before := jobRuntimeDigest(t, f.store, f.jobB)
			scan := pausedTenantScan(ctx, t, f.store, f.b, f.jobB, "paused-cycle-"+tc.name)
			scan.Status, scan.Resumable, scan.CycleID, scan.CycleStatus, scan.CycleAttempt = tc.status, true, cycle.ID, tc.cycleStatus, 1
			if tc.status == "canceled" {
				scan.Error = "scan canceled"
			}
			if _, ran, err := finalizeAsBaseline(ctx, f.store, &scan); !errors.Is(err, ErrTenantNotActive) || ran {
				t.Fatalf("finalize = %v, finalizer ran %t", err, ran)
			}
			if got, err := storedScanOutcome(f.store, scan.ID); err != nil || got != tc.wantScan {
				t.Fatalf("stored scan = %q, %v; want %q", got, err, tc.wantScan)
			}
			var status string
			var units int
			if err := f.store.DB.QueryRowContext(ctx, `SELECT status,(SELECT COUNT(*) FROM scan_cycle_units WHERE cycle_id=?1) FROM scan_cycles WHERE id=?1`, cycle.ID).Scan(&status, &units); err != nil {
				t.Fatal(err)
			}
			if status != tc.wantCycle || units != tc.wantUnits {
				t.Fatalf("cycle = %s with %d units, want %s with %d", status, units, tc.wantCycle, tc.wantUnits)
			}
			if promoted, err := f.store.Tenant(f.b).ScanCycleHasScan(ctx, cycle.ID); err != nil || promoted {
				t.Fatalf("cycle promoted = %t, %v; want not promoted", promoted, err)
			}
			if after := jobRuntimeDigest(t, f.store, f.jobB); after != before {
				t.Fatalf("the scan changed the disabled tenant's job:\nbefore\n%s\nafter\n%s", before, after)
			}
		})
	}
}
