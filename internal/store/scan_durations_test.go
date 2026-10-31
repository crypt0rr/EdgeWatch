package store

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
)

func TestLatestScanRunsTimedOutUsesCurrentKeysAndNewestRuns(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("timed-out-run-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	key := NewScanDurationKey(job)
	base := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	save := func(id string, index int, status, configHash, cycleID string) {
		t.Helper()
		finished := base.Add(time.Duration(index) * time.Hour)
		saveDurationScan(t, s, model.Scan{
			ID: id, JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, FinishedAt: finished, Status: status,
			ConfigHash: configHash, ScannerProfileID: key.ScannerProfileID, ScannerProfileRevision: key.ScannerProfileRevision,
			CycleID: cycleID,
		}, time.Minute)
	}
	for i := 0; i < 11; i++ {
		save(fmt.Sprintf("timeout-evidence-%02d", i), i, "timed_out", key.ConfigHash, "")
	}
	latest, err := tenant.LatestScanRunsTimedOut(ctx, []ScanDurationKey{key}, 11)
	if err != nil || !latest[job.ID] {
		t.Fatalf("all current-key timeout runs = %v, %v; want true", latest, err)
	}

	save("timeout-evidence-success", 12, "success", key.ConfigHash, "")
	latest, err = tenant.LatestScanRunsTimedOut(ctx, []ScanDurationKey{key}, 11)
	if err != nil || latest[job.ID] {
		t.Fatalf("mixed latest current-key runs = %v, %v; want false", latest, err)
	}
	// A non-current scope timeout does not affect whether the newest matching
	// runs all timed out.
	save("timeout-evidence-other-scope", 13, "timed_out", "another-scope", "")
	latest, err = tenant.LatestScanRunsTimedOut(ctx, []ScanDurationKey{key}, 11)
	if err != nil || latest[job.ID] {
		t.Fatalf("other-scope timeout changed current-key status = %v, %v; want false", latest, err)
	}
	legacyKey := key
	legacyKey.LegacyConfigHash = "legacy-scope"
	saveDurationScan(t, s, model.Scan{
		ID: "timed-out-legacy-scope", JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		FinishedAt: base.Add(14 * time.Hour), Status: "timed_out", ConfigHash: legacyKey.LegacyConfigHash,
		ScannerProfileID: legacyKey.ScannerProfileID, ScannerProfileRevision: legacyKey.ScannerProfileRevision,
	}, time.Minute)
	latest, err = tenant.LatestScanRunsTimedOut(ctx, []ScanDurationKey{legacyKey}, 1)
	if err != nil || !latest[job.ID] {
		t.Fatalf("legacy-scope timeout = %v, %v; want true", latest, err)
	}

	cycleJob, err := tenant.CreateJob(ctx, testJob("timed-out-cycle-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	cycleKey := NewScanDurationKey(cycleJob)
	cycleID := "timed-out-current-cycle"
	cycleFinished := base.Add(24 * time.Hour)
	stamp := sqliteTimestamp
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,total_units,total_probes,started_at,updated_at,expires_at,finished_at)
		VALUES(?,?,?,?,?,?,?,'paused',0,0,?,?,?,?)`, cycleID, cycleJob.ID, cycleJob.Job.Name, cycleJob.Revision,
		cycleKey.ConfigHash, cycleKey.ExecutionHash, []byte(`{}`), stamp(cycleFinished.Add(-time.Hour)), stamp(cycleFinished), stamp(cycleFinished), stamp(cycleFinished)); err != nil {
		t.Fatal(err)
	}
	saveDurationScan(t, s, model.Scan{
		ID: "timed-out-cycle-attempt", JobID: cycleJob.ID, Job: cycleJob.Job.Name, JobRevision: cycleJob.Revision,
		FinishedAt: cycleFinished, Status: "timed_out", ConfigHash: cycleKey.ConfigHash, CycleID: cycleID,
	}, time.Hour)
	latest, err = tenant.LatestScanRunsTimedOut(ctx, []ScanDurationKey{cycleKey}, 11)
	if err != nil || !latest[cycleJob.ID] {
		t.Fatalf("current-execution-hash cycle timeout = %v, %v; want true", latest, err)
	}
	cycleKey.ExecutionHash = "another-execution"
	latest, err = tenant.LatestScanRunsTimedOut(ctx, []ScanDurationKey{cycleKey}, 11)
	if err != nil || latest[cycleJob.ID] {
		t.Fatalf("different-execution cycle timeout = %v, %v; want false", latest, err)
	}
}

func TestLatestScanRunsTimedOutFiltersSettingsBeforeHistoryLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("restored-timeout-settings"))
	if err != nil {
		t.Fatal(err)
	}
	keyA := NewScanDurationKey(job)
	base := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 11; i++ {
		saveDurationScan(t, s, model.Scan{
			ID: fmt.Sprintf("settings-a-timeout-%02d", i), JobID: job.ID, Job: job.Job.Name,
			JobRevision: job.Revision, FinishedAt: base.Add(time.Duration(i) * time.Hour), Status: "timed_out",
			ConfigHash: keyA.ConfigHash, ScannerProfileID: keyA.ScannerProfileID,
			ScannerProfileRevision: keyA.ScannerProfileRevision,
		}, time.Minute)
	}
	changedSettings := job.Job
	changedSettings.Targets = []string{"192.0.2.2"}
	jobB, _, err := tenant.UpdateJob(ctx, job.ID, job.Revision, changedSettings, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	keyB := NewScanDurationKey(jobB)
	for i := 0; i < 44; i++ {
		saveDurationScan(t, s, model.Scan{
			ID: fmt.Sprintf("settings-b-newer-%02d", i), JobID: job.ID, Job: job.Job.Name,
			JobRevision: jobB.Revision, FinishedAt: base.Add(time.Duration(100+i) * time.Hour), Status: "success",
			ConfigHash: keyB.ConfigHash, ScannerProfileID: keyB.ScannerProfileID,
			ScannerProfileRevision: keyB.ScannerProfileRevision,
		}, time.Minute)
	}

	jobA, _, err := tenant.UpdateJob(ctx, jobB.ID, jobB.Revision, job.Job, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	keyRestoredA := NewScanDurationKey(jobA)
	if keyRestoredA != keyA {
		t.Fatalf("restored settings key = %+v, want original key %+v", keyRestoredA, keyA)
	}
	latest, err := tenant.LatestScanRunsTimedOut(ctx, []ScanDurationKey{keyRestoredA}, 11)
	if err != nil || !latest[job.ID] {
		t.Fatalf("restored settings' 11 matching timeouts behind newer settings = %v, %v; want true", latest, err)
	}

	otherTenant, err := s.Platform().CreateTenant(ctx, "Other timeout tenant", "other-timeouts", AuditEntry{ActorKind: AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	otherScope, err := s.TenantScopeByID(ctx, otherTenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	otherJob, err := s.Tenant(otherScope).CreateJob(ctx, testJob("other-tenant-timeout"))
	if err != nil {
		t.Fatal(err)
	}
	otherKey := NewScanDurationKey(otherJob)
	saveDurationScan(t, s, model.Scan{
		ID: "other-tenant-timeout-scan", JobID: otherJob.ID, Job: otherJob.Job.Name,
		FinishedAt: base.Add(300 * time.Hour), Status: "timed_out", ConfigHash: otherKey.ConfigHash,
		ScannerProfileID: otherKey.ScannerProfileID, ScannerProfileRevision: otherKey.ScannerProfileRevision,
	}, time.Minute)
	foreign, err := tenant.LatestScanRunsTimedOut(ctx, []ScanDurationKey{otherKey}, 11)
	if err != nil || len(foreign) != 0 {
		t.Fatalf("timeout history for another tenant = %v, %v; want no rows", foreign, err)
	}
}

// saveDurationCycle records a completed one-attempt cycle of the job that
// ran for duration and finished at finished, with the execution hash given,
// and its saved scan.
func saveDurationCycle(t *testing.T, s *Store, job JobRecord, id, executionHash string, finished time.Time, duration time.Duration) {
	t.Helper()
	ctx := context.Background()
	started := finished.Add(-duration)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,attempt_count,total_units,total_probes,started_at,attempt_started_at,updated_at,expires_at,finished_at)
		VALUES(?,?,?,?,?,?,?,'completed',1,1,1,?,?,?,?,?)`,
		id, job.ID, job.Job.Name, job.Revision, job.Job.SecurityHash(), executionHash, []byte(`{}`),
		sqliteTimestamp(started), sqliteTimestamp(started), sqliteTimestamp(finished), sqliteTimestamp(finished), sqliteTimestamp(finished)); err != nil {
		t.Fatal(err)
	}
	if err := s.System().SaveScan(ctx, model.Scan{
		ID: "scan-" + id, JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		StartedAt: started, FinishedAt: finished, Status: "success", ConfigHash: job.Job.SecurityHash(),
		CycleID: id, CycleAttempt: 1, CycleStatus: "completed", Resumable: true,
	}); err != nil {
		t.Fatal(err)
	}
}

// sampleDurations returns the summed duration of each sample, in order.
func sampleDurations(samples []ScanDurationSample) []time.Duration {
	if samples == nil {
		return nil
	}
	durations := make([]time.Duration, len(samples))
	for i, sample := range samples {
		durations[i] = sample.Duration()
	}
	return durations
}

// saveDurationScan records a scan of the job without a cycle.
func saveDurationScan(t *testing.T, s *Store, scan model.Scan, duration time.Duration) {
	t.Helper()
	scan.StartedAt = scan.FinishedAt.Add(-duration)
	if scan.Status == "" {
		scan.Status = "success"
	}
	if err := s.System().SaveScan(context.Background(), scan); err != nil {
		t.Fatal(err)
	}
}

// A job's samples are its newest completed cycles and scans without a
// cycle, ranked together by when they finished, up to the limit of each
// job. Scans that a newer set of cycles outranks are not read at all.
func TestListCompletedScanCycleDurationsTakesEachJobsNewestSamples(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	mixed, err := tenant.CreateJob(ctx, testJob("mixed-samples"))
	if err != nil {
		t.Fatal(err)
	}
	cyclesOnly, err := tenant.CreateJob(ctx, testJob("newer-cycles"))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	// The mixed job alternates cycles and scans: sample i finished i hours
	// after base and ran i+1 minutes, so the newest four have durations 10m
	// down to 7m.
	for i := range 10 {
		finished := base.Add(time.Duration(i) * time.Hour)
		duration := time.Duration(i+1) * time.Minute
		if i%2 == 0 {
			saveDurationCycle(t, s, mixed, fmt.Sprintf("mixed-cycle-%02d", i), mixed.Job.ExecutionHash(), finished, duration)
		} else {
			saveDurationScan(t, s, model.Scan{ID: fmt.Sprintf("mixed-scan-%02d", i), JobID: mixed.ID, Job: mixed.Job.Name, FinishedAt: finished, ConfigHash: mixed.Job.SecurityHash()}, duration)
		}
	}
	// The other job's four cycles are newer than all of its scans.
	for i := range 4 {
		saveDurationCycle(t, s, cyclesOnly, fmt.Sprintf("newer-cycle-%02d", i), cyclesOnly.Job.ExecutionHash(), base.Add(time.Duration(100+i)*time.Hour), time.Duration(20+i)*time.Minute)
		saveDurationScan(t, s, model.Scan{ID: fmt.Sprintf("older-scan-%02d", i), JobID: cyclesOnly.ID, Job: cyclesOnly.Job.Name, FinishedAt: base.Add(time.Duration(i) * time.Hour), ConfigHash: cyclesOnly.Job.SecurityHash()}, time.Hour)
	}

	keys := []ScanDurationKey{NewScanDurationKey(mixed), NewScanDurationKey(cyclesOnly)}
	// A job keyed twice still counts each of its samples once.
	durations, err := tenant.ListCompletedScanCycleDurations(ctx, append(keys, keys[0]), 4)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]time.Duration{
		mixed.ID:      {10 * time.Minute, 9 * time.Minute, 8 * time.Minute, 7 * time.Minute},
		cyclesOnly.ID: {23 * time.Minute, 22 * time.Minute, 21 * time.Minute, 20 * time.Minute},
	}
	for jobID, samples := range want {
		if got := sampleDurations(durations[jobID]); !slices.Equal(got, samples) {
			t.Errorf("job %s samples = %v, want %v newest first", jobID, got, samples)
		}
		for _, sample := range durations[jobID] {
			if sample.Runs != 1 || len(sample.Attempts) != 1 {
				t.Errorf("job %s one-attempt sample = %+v, want one run", jobID, sample)
			}
		}
	}
	if len(durations) != len(want) {
		t.Errorf("durations = %v, want samples of the two keyed jobs only", durations)
	}

	// With a larger limit the older scans of the cycle job count too.
	durations, err = tenant.ListCompletedScanCycleDurations(ctx, keys[1:], 6)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sampleDurations(durations[cyclesOnly.ID]), []time.Duration{23 * time.Minute, 22 * time.Minute, 21 * time.Minute, 20 * time.Minute, time.Hour, time.Hour}; !slices.Equal(got, want) {
		t.Errorf("cycle job samples with limit 6 = %v, want %v", got, want)
	}
}

// A completed cycle counts when it recorded the job's current execution
// hash. A successful, incomplete or timed-out scan without a cycle counts
// when it recorded the job's scope hash, or the legacy alias of a stored
// job, and its current TCP scanner profile revision. Failed scans, scans of
// a cycle, unkeyed jobs and archived jobs add nothing.
func TestListCompletedScanCycleDurationsKeysSamplesOnScanSettings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("keyed-samples"))
	if err != nil {
		t.Fatal(err)
	}
	unkeyed, err := tenant.CreateJob(ctx, testJob("unkeyed"))
	if err != nil {
		t.Fatal(err)
	}
	// Store the job with a port spelling from before canonicalization, as an
	// older release did, so that it loads with a legacy scope hash.
	legacy := job.Job
	legacy.TCP.Ports = "2, 1"
	definition, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=?`, definition, job.ID); err != nil {
		t.Fatal(err)
	}
	job, err = tenant.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	key := NewScanDurationKey(job)
	if key.LegacyConfigHash == "" || key.LegacyConfigHash == key.ConfigHash {
		t.Fatalf("stored legacy job key = %+v, want a distinct legacy scope hash", key)
	}

	base := time.Date(2026, time.April, 1, 0, 0, 0, 0, time.UTC)
	at := func(hour int) time.Time { return base.Add(time.Duration(hour) * time.Hour) }
	scan := func(id string, hour int) model.Scan {
		return model.Scan{ID: id, JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, FinishedAt: at(hour), ConfigHash: key.ConfigHash}
	}
	saveDurationCycle(t, s, job, "current-execution-cycle", key.ExecutionHash, at(1), time.Minute)
	saveDurationCycle(t, s, job, "other-execution-cycle", "other-execution-hash", at(2), time.Hour)
	saveDurationScan(t, s, scan("current-scope-scan", 3), 2*time.Minute)
	legacyScan := scan("legacy-scope-scan", 4)
	legacyScan.ConfigHash = key.LegacyConfigHash
	saveDurationScan(t, s, legacyScan, 3*time.Minute)
	incomplete := scan("incomplete-scan", 5)
	incomplete.Status = "incomplete"
	saveDurationScan(t, s, incomplete, 4*time.Minute)
	otherScope := scan("other-scope-scan", 6)
	otherScope.ConfigHash = "other-scope-hash"
	saveDurationScan(t, s, otherScope, time.Hour)
	otherProfile := scan("other-profile-scan", 7)
	otherProfile.ScannerProfileID, otherProfile.ScannerProfileRevision = "tcp-profile", 3
	saveDurationScan(t, s, otherProfile, time.Hour)
	failed := scan("failed-scan", 8)
	failed.Status = "failed"
	saveDurationScan(t, s, failed, time.Hour)
	cycleAttempt := scan("cycle-attempt-scan", 9)
	cycleAttempt.CycleID, cycleAttempt.CycleAttempt, cycleAttempt.CycleStatus = "current-execution-cycle", 2, "completed"
	saveDurationScan(t, s, cycleAttempt, time.Hour)
	saveDurationScan(t, s, model.Scan{ID: "unkeyed-scan", JobID: unkeyed.ID, Job: unkeyed.Job.Name, FinishedAt: at(10), ConfigHash: unkeyed.Job.SecurityHash()}, time.Hour)
	timedOut := scan("timed-out-scan", 11)
	timedOut.Status = "timed_out"
	saveDurationScan(t, s, timedOut, 5*time.Minute)

	durations, err := tenant.ListCompletedScanCycleDurations(ctx, []ScanDurationKey{key}, 11)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sampleDurations(durations[job.ID]), []time.Duration{5 * time.Minute, 4 * time.Minute, 3 * time.Minute, 2 * time.Minute, time.Minute}; !slices.Equal(got, want) || len(durations) != 1 {
		t.Fatalf("keyed samples = %v, want %v for the keyed job only", durations, want)
	}

	// A key whose TCP scanner profile revision changed no longer matches
	// the scans, and one whose execution hash changed no longer matches the
	// cycle.
	changed := key
	changed.ScannerProfileID, changed.ScannerProfileRevision = "tcp-profile", 3
	changed.ExecutionHash = "other-execution-hash"
	durations, err = tenant.ListCompletedScanCycleDurations(ctx, []ScanDurationKey{changed}, 11)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sampleDurations(durations[job.ID]), []time.Duration{time.Hour, time.Hour}; !slices.Equal(got, want) {
		t.Fatalf("samples of the changed key = %v, want the other profile's scan and the other execution's cycle, %v", got, want)
	}

	if err := tenant.SetJobArchived(ctx, job.ID, true); err != nil {
		t.Fatal(err)
	}
	durations, err = tenant.ListCompletedScanCycleDurations(ctx, []ScanDurationKey{key}, 11)
	if err != nil || len(durations) != 0 {
		t.Fatalf("archived job samples = %v, %v; want none", durations, err)
	}
}

// A job's scans without a cycle count only among its newest successful,
// incomplete or timed-out scans, so a job whose newer scans ran with other
// settings, or belong to cycles, does not have its whole history read on
// every request. Failed scans do not take up the window.
func TestListCompletedScanCycleDurationsReadsOnlyEachJobsNewestScans(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("windowed-scans"))
	if err != nil {
		t.Fatal(err)
	}
	key := NewScanDurationKey(job)
	const limit = 2
	window := limit * scanDurationScanWindow
	base := time.Date(2026, time.May, 1, 0, 0, 0, 0, time.UTC)
	at := func(hour int) time.Time { return base.Add(time.Duration(hour) * time.Hour) }
	save := func(id string, hour int, configHash, status string) {
		t.Helper()
		saveDurationScan(t, s, model.Scan{ID: id, JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, FinishedAt: at(hour), ConfigHash: configHash, Status: status}, time.Minute)
	}
	list := func() []time.Duration {
		t.Helper()
		durations, err := tenant.ListCompletedScanCycleDurations(ctx, []ScanDurationKey{key}, limit)
		if err != nil {
			t.Fatal(err)
		}
		return sampleDurations(durations[job.ID])
	}
	// Scans with the current settings, then a window's worth of newer scans
	// with other settings, as after an edit and its reversal.
	for i := range 3 {
		save(fmt.Sprintf("older-current-%02d", i), i, key.ConfigHash, "success")
	}
	if got := list(); len(got) != limit {
		t.Fatalf("samples before newer scans = %v, want %d", got, limit)
	}
	for i := range window {
		save(fmt.Sprintf("other-settings-%02d", i), 10+i, "other-scope-hash", "success")
	}
	if got := list(); len(got) != 0 {
		t.Fatalf("samples behind %d newer scans with other settings = %v, want none read", window, got)
	}
	// A new scan with the current settings is in the window, and newer
	// failed scans do not push it out.
	save("new-current", 100, key.ConfigHash, "success")
	for i := range 2 * window {
		save(fmt.Sprintf("failed-%02d", i), 200+i, key.ConfigHash, "failed")
	}
	if got := list(); !slices.Equal(got, []time.Duration{time.Minute}) {
		t.Fatalf("samples after one new scan with the current settings = %v, want that one", got)
	}
	// A timed-out scan with the current settings is a sample too, and
	// timed-out scans with other settings take up the window.
	save("timed-out-current", 300, key.ConfigHash, "timed_out")
	if got := list(); !slices.Equal(got, []time.Duration{time.Minute, time.Minute}) {
		t.Fatalf("samples after a timed-out scan with the current settings = %v, want it and the earlier one", got)
	}
	for i := range window {
		save(fmt.Sprintf("timed-out-other-settings-%02d", i), 400+i, "other-scope-hash", "timed_out")
	}
	if got := list(); len(got) != 0 {
		t.Fatalf("samples behind %d newer timed-out scans with other settings = %v, want none read", window, got)
	}
}

// The attempts that the job's cycle in progress has recorded are runs with
// the current settings, so that cycle is the job's newest sample, of as many
// runs as it recorded, once its attempts are among the job's newest cycle
// scans with the current execution hash. A cycle in progress with other
// settings, and the attempts of a cycle that expired, are not samples. Each
// attempt records whether its timeout ended it.
func TestListCompletedScanCycleDurationsCountsTheCycleInProgress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("cycle-in-progress"))
	if err != nil {
		t.Fatal(err)
	}
	key := NewScanDurationKey(job)
	const limit = 3
	base := time.Date(2026, time.April, 1, 0, 0, 0, 0, time.UTC)
	at := func(hour int) time.Time { return base.Add(time.Duration(hour) * time.Hour) }
	saveCycle := func(id, status, executionHash string, started time.Time) {
		t.Helper()
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,attempt_count,total_units,total_probes,started_at,updated_at,expires_at)
			VALUES(?,?,?,?,?,?,?,?,9,1,1,?,?,?)`, id, job.ID, job.Job.Name, job.Revision, key.ConfigHash, executionHash, []byte(`{}`), status,
			sqliteTimestamp(started), sqliteTimestamp(started), sqliteTimestamp(started.Add(30*24*time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	saveAttempt := func(cycleID string, attempt, hour int, duration time.Duration, status string) {
		t.Helper()
		saveDurationScan(t, s, model.Scan{
			ID: fmt.Sprintf("%s-attempt-%d", cycleID, attempt), JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
			FinishedAt: at(hour), Status: status, ConfigHash: key.ConfigHash,
			CycleID: cycleID, CycleAttempt: attempt, CycleStatus: "paused", Resumable: true,
		}, duration)
	}
	list := func() []ScanDurationSample {
		t.Helper()
		durations, err := tenant.ListCompletedScanCycleDurations(ctx, []ScanDurationKey{key}, limit)
		if err != nil {
			t.Fatal(err)
		}
		return durations[job.ID]
	}
	// An older completed cycle and scan, then a cycle that expired after
	// two timed-out attempts.
	saveDurationCycle(t, s, job, "completed-before", key.ExecutionHash, at(1), 5*time.Minute)
	saveDurationScan(t, s, model.Scan{ID: "timed-out-scan", JobID: job.ID, Job: job.Job.Name, FinishedAt: at(2), Status: "timed_out", ConfigHash: key.ConfigHash}, time.Minute)
	saveCycle("expired", "expired", key.ExecutionHash, at(3))
	saveAttempt("expired", 1, 4, time.Minute, "timed_out")
	saveAttempt("expired", 2, 5, time.Minute, "timed_out")
	got := list()
	if len(got) != 2 || !slices.Equal(got[0].Attempts, []ScanDurationAttempt{{Duration: time.Minute, TimedOut: true}}) || !slices.Equal(got[1].Attempts, []ScanDurationAttempt{{Duration: 5 * time.Minute}}) {
		t.Fatalf("samples without a cycle in progress = %+v; want the timed-out scan and the completed cycle", got)
	}

	// The cycle in progress has recorded a timed-out attempt and a failed
	// one; a running attempt has no record yet.
	saveCycle("in-progress", "paused", key.ExecutionHash, at(6))
	saveAttempt("in-progress", 1, 7, 50*time.Second, "timed_out")
	saveAttempt("in-progress", 2, 8, 20*time.Second, "failed")
	got = list()
	want := []ScanDurationAttempt{{Duration: 50 * time.Second, TimedOut: true}, {Duration: 20 * time.Second}}
	if len(got) != limit || got[0].Runs != 2 || !slices.Equal(got[0].Attempts, want) || got[1].Duration() != time.Minute || got[2].Duration() != 5*time.Minute {
		t.Fatalf("samples with a cycle in progress = %+v; want its two recorded attempts as the newest sample", got)
	}

	// Only its attempts among the job's three newest cycle scans count.
	saveAttempt("in-progress", 3, 9, 30*time.Second, "timed_out")
	saveAttempt("in-progress", 4, 10, 40*time.Second, "timed_out")
	if got = list(); len(got) == 0 || got[0].Runs != limit || got[0].Duration() != 90*time.Second {
		t.Fatalf("samples after more attempts = %+v; want the cycle's three newest attempts, 1m30s", got)
	}

	// A cycle in progress with other settings is not a sample.
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET execution_hash='other-settings' WHERE id='in-progress'`); err != nil {
		t.Fatal(err)
	}
	if got = list(); len(got) != 2 || got[0].Duration() != time.Minute {
		t.Fatalf("samples with a cycle in progress of other settings = %+v; want the timed-out scan and the completed cycle", got)
	}
}

// Every lookup of the duration query is an indexed per-job lookup: no step
// scans a table or a tenant's history, sorts a job's history, or reads the
// row of a scan before the index has shown that it has no cycle or that it
// is an attempt of the job's cycle in progress.
func TestListCompletedScanCycleDurationsUsesPerJobIndexLookups(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	plan := explainPlan(t, s.DB, completedScanDurationsSQL, `[]`, DefaultTenantID, 11, 11*scanDurationScanWindow)
	joined := strings.Join(plan, " | ")
	for _, want := range []string{
		"SEARCH x USING COVERING INDEX " + scanCyclesCompletedExecutionIndex + " (job_id=? AND execution_hash=?)",
		"SEARCH v USING COVERING INDEX " + scansJobHistoryIndex + " (job_id=?)",
		"SEARCH c USING COVERING INDEX " + scanCyclesCompletedExecutionIndex + " (job_id=? AND execution_hash=? AND finished_at>?)",
		"SEARCH a USING INDEX " + scansCycleOutcomeIndex + " (cycle_id=?)",
		"SEARCH q USING COVERING INDEX " + scansTimeoutCycleKeyIndex + " (tenant_id=? AND job_id=? AND cycle_execution_hash=?)",
		"SEARCH e USING INDEX " + scanCyclesActiveIndex + " (job_id=?)",
		"SEARCH u USING COVERING INDEX " + scansTimeoutCycleKeyIndex + " (tenant_id=? AND job_id=? AND cycle_execution_hash=? AND finished_at>?)",
		"SEARCH t USING INTEGER PRIMARY KEY (rowid=?)",
		"SEARCH y USING COVERING INDEX " + scansJobHistoryIndex + " (job_id=? AND finished_at>?)",
		"SEARCH z USING COVERING INDEX " + scansCycleOutcomeIndex + " (cycle_id=? AND cycle_status=? AND status=? AND tenant_id=? AND rowid=?)",
		"SEARCH r USING INTEGER PRIMARY KEY (rowid=?)",
		"SEARCH s USING INTEGER PRIMARY KEY (rowid=?)",
	} {
		if !slices.Contains(plan, want) {
			t.Errorf("duration plan lacks %q: %s", want, joined)
		}
	}
	for _, step := range plan {
		fields := strings.Fields(step)
		if strings.Contains(step, "TEMP B-TREE") || len(fields) > 1 && fields[0] == "SCAN" && !slices.Contains([]string{"k", "w", "b", "c", "p"}, fields[1]) {
			t.Errorf("duration plan step %q scans or sorts history: %s", step, joined)
		}
	}
}

// The estimate's key follows the job's execution and scope settings, and
// not its name, schedule or notifications.
func TestNewScanDurationKeyFollowsScanSettingsOnly(t *testing.T) {
	t.Parallel()
	job := testJob("key")
	job.TCP.ProfileID, job.TCP.ProfileRevision = "tcp-profile", 2
	record := JobRecord{ID: "job-key", Job: job, Revision: 4}
	key := NewScanDurationKey(record)
	if key.JobID != "job-key" || key.ExecutionHash != job.ExecutionHash() || key.ConfigHash != job.SecurityHash() || key.LegacyConfigHash != "" || key.ScannerProfileID != "tcp-profile" || key.ScannerProfileRevision != 2 {
		t.Fatalf("key = %+v", key)
	}
	renamed := record
	renamed.Job.Name, renamed.Job.Schedule, renamed.Job.NotificationDestinations, renamed.Revision = "renamed", "*/5 * * * *", []string{}, 9
	if got := NewScanDurationKey(renamed); got != key {
		t.Fatalf("renamed key = %+v, want %+v", got, key)
	}
	udpOnly := record
	udpOnly.Job.TCP, udpOnly.Job.UDP = nil, &config.Protocol{Ports: "53", ProfileID: "udp-profile", ProfileRevision: 1}
	if got := NewScanDurationKey(udpOnly); got.ScannerProfileID != "" || got.ScannerProfileRevision != 0 || got.ExecutionHash == key.ExecutionHash {
		t.Fatalf("UDP-only key = %+v; want no TCP profile and another execution hash", got)
	}
}
