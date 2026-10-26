package store

import (
	"context"
	"encoding/json"
	"sort"
	"time"
)

// ScanDurationKey names the completed scans whose durations describe a job's
// current scan work. NewScanDurationKey derives it from the job's current
// definition; ListCompletedScanCycleDurations compares it with what each
// completed cycle and scan recorded when it ran.
type ScanDurationKey struct {
	JobID string `json:"job_id"`
	// ExecutionHash is the job's config.Job.ExecutionHash. A completed cycle
	// is a sample when it recorded the same hash. The hash covers the
	// monitored scope and the settings that change how a scan runs, such as
	// the timeout, timing, scanner profile revisions and scanner arguments,
	// but not the job's name, schedule, notifications or enabled state.
	ExecutionHash string `json:"execution_hash"`
	// ConfigHash is the job's config.Job.SecurityHash, and LegacyConfigHash
	// its pre-canonicalization alias when it has one. A completed scan
	// without a cycle is a sample when it recorded one of them as its
	// config_hash.
	ConfigHash       string `json:"config_hash"`
	LegacyConfigHash string `json:"legacy_config_hash"`
	// ScannerProfileID and ScannerProfileRevision are the TCP scanner
	// profile that a scan of the job records. A completed scan without a
	// cycle is a sample only when it recorded the same profile revision. A
	// scan records no other execution setting, so for such a scan an edit
	// of the timeout, timing or UDP scanner profile does not separate its
	// duration from the current ones.
	ScannerProfileID       string `json:"scanner_profile_id"`
	ScannerProfileRevision int64  `json:"scanner_profile_revision"`
}

// NewScanDurationKey returns the duration key of a job's current definition,
// with the hashes and scanner profile that a run of it records.
func NewScanDurationKey(record JobRecord) ScanDurationKey {
	key := ScanDurationKey{
		JobID:            record.ID,
		ExecutionHash:    record.Job.ExecutionHash(),
		ConfigHash:       record.Job.SecurityHash(),
		LegacyConfigHash: record.Job.LegacySecurityHash(),
	}
	if record.Job.TCP != nil {
		key.ScannerProfileID, key.ScannerProfileRevision = record.Job.TCP.ProfileID, record.Job.TCP.ProfileRevision
	}
	return key
}

// scanDurationScanWindow is how many of a job's newest successful or
// incomplete scans ListCompletedScanCycleDurations considers for each
// sample it returns. Only these scans are probed for a cycle and read, so
// the work of each job stays bounded whether or not its scans match its
// current key: after an edit that changes the key, a job's matching scans
// are its newest ones, and until it has run enough of them the walk stops
// at the window instead of reading its whole retained history. The window
// is a multiple of the sample count so that the scans it holds of resumable
// cycles, which the cycles branch counts instead, or of other settings,
// leave room for the job's samples without a cycle.
const scanDurationScanWindow = 4

// completedScanDurationsSQL reads the duration records of the newest
// completed samples of each keyed job of the tenant. ?1 is the JSON array of
// the keys, ?2 the tenant, ?3 the number of samples per job and ?4 the number
// of the job's newest successful or incomplete scans that the scans branch
// considers.
//
// Each job's lookups are bounded by ?3 and ?4 rather than by its history.
// bounds finds the finished_at of the job's ?3-th newest completed cycle with
// its execution hash through scan_cycles_completed_execution, and cycles reads
// the cycles from there on from the same index, which are at most ?3 unless
// some finished at the same time. A completed cycle reads its scans only when
// it had more than one attempt, or recorded none, because the cycle row holds
// the final attempt. bounds also finds the finished_at of the job's ?4-th
// newest successful or incomplete scan from scans_job_id_history alone. The
// job's scans without a cycle come from the same index, newest first, and
// none older than either bound: ?3 newer cycles already outrank such a scan,
// and older scans are outside the window. Only the scans in the window are
// probed through scans_cycle_outcome for a cycle, and only those without one
// are read. The row's config_hash and timestamps come before snapshot_json,
// so a scan of another scope is rejected before its snapshot pages are read;
// only the window's scans with the current scope hash reach the scanner
// profile columns after it.
//
// Every branch takes its jobs from wanted, which joins the keys to the
// tenant's jobs, and reads scans with the tenant predicate.
const completedScanDurationsSQL = `WITH wanted AS MATERIALIZED (
	SELECT j.id AS job_id,
		CAST(json_extract(k.value,'$.execution_hash') AS TEXT) AS execution_hash,
		CAST(json_extract(k.value,'$.config_hash') AS TEXT) AS config_hash,
		CAST(json_extract(k.value,'$.legacy_config_hash') AS TEXT) AS legacy_config_hash,
		CAST(json_extract(k.value,'$.scanner_profile_id') AS TEXT) AS profile_id,
		CAST(json_extract(k.value,'$.scanner_profile_revision') AS INTEGER) AS profile_revision
	FROM json_each(?1) AS k
	CROSS JOIN jobs AS j ON j.id=CAST(json_extract(k.value,'$.job_id') AS TEXT) AND j.tenant_id=?2
	WHERE j.archived=0
), bounds AS MATERIALIZED (
	SELECT w.job_id,w.execution_hash,w.config_hash,w.legacy_config_hash,w.profile_id,w.profile_revision,
		COALESCE((SELECT x.finished_at FROM scan_cycles AS x INDEXED BY ` + scanCyclesCompletedExecutionIndex + `
			WHERE x.job_id=w.job_id AND x.execution_hash=w.execution_hash AND x.status='completed'
			ORDER BY x.finished_at DESC,x.id DESC LIMIT 1 OFFSET ?3-1),'') AS cycle_cutoff,
		COALESCE((SELECT v.finished_at FROM scans AS v INDEXED BY ` + scansJobHistoryIndex + `
			WHERE v.job_id=w.job_id AND v.tenant_id=?2 AND v.status IN ('success','incomplete')
			ORDER BY v.finished_at DESC,v.id DESC LIMIT 1 OFFSET ?4-1),'') AS scan_window_start
	FROM wanted AS w
), cycles AS MATERIALIZED (
	SELECT b.job_id,c.id,c.attempt_count,c.started_at,c.attempt_started_at,c.finished_at
	FROM bounds AS b
	CROSS JOIN scan_cycles AS c INDEXED BY ` + scanCyclesCompletedExecutionIndex + `
		ON c.job_id=b.job_id AND c.execution_hash=b.execution_hash AND c.status='completed'
		AND c.finished_at>=b.cycle_cutoff AND c.finished_at<>''
)
SELECT c.job_id,'cycle:'||c.id,CASE WHEN c.attempt_started_at<>'' THEN c.attempt_started_at ELSE c.started_at END,c.finished_at,c.finished_at
FROM cycles AS c
WHERE c.attempt_started_at<>'' OR c.attempt_count=1
UNION ALL
SELECT c.job_id,'cycle:'||c.id,a.started_at,a.finished_at,c.finished_at
FROM cycles AS c
CROSS JOIN scans AS a INDEXED BY ` + scansCycleOutcomeIndex + ` ON a.cycle_id=c.id AND a.tenant_id=?2 AND a.job_id=c.job_id
WHERE c.attempt_count<>1 AND (c.attempt_count=0 OR (a.cycle_attempt>0 AND a.cycle_attempt<c.attempt_count))
	AND a.started_at<>'' AND a.finished_at<>'' AND julianday(a.started_at)<julianday(c.finished_at)
UNION ALL
SELECT b.job_id,'scan:'||s.id,s.started_at,s.finished_at,s.finished_at
FROM bounds AS b
CROSS JOIN scans AS s NOT INDEXED ON s.tenant_id=?2 AND s.rowid IN (
	SELECT y.rowid FROM scans AS y INDEXED BY ` + scansJobHistoryIndex + `
	CROSS JOIN scans AS z INDEXED BY ` + scansCycleOutcomeIndex + `
		ON z.cycle_id='' AND z.cycle_status='' AND z.status=y.status AND z.tenant_id=y.tenant_id AND z.rowid=y.rowid
	CROSS JOIN scans AS r ON r.rowid=y.rowid
	WHERE y.job_id=b.job_id AND y.tenant_id=?2 AND y.status IN ('success','incomplete')
		AND y.finished_at>=MAX(b.cycle_cutoff,b.scan_window_start)
		AND (r.config_hash=b.config_hash OR (b.legacy_config_hash<>'' AND r.config_hash=b.legacy_config_hash))
		AND r.started_at<>'' AND julianday(r.finished_at)>julianday(r.started_at)
		AND r.scanner_profile_id=b.profile_id AND r.scanner_profile_revision=b.profile_revision
	ORDER BY y.finished_at DESC,y.id DESC LIMIT ?3)`

// latestScanRunsTimedOutSQL checks the newest current-key run records inside
// the same bounded scan-history window used for standalone duration samples.
// It returns true only when at least one current-key run is present and every
// one of the newest perJobLimit such runs timed out. Cycle attempts are keyed
// by the cycle's execution hash; scans without a cycle use their recorded
// scope hash and TCP scanner profile, as their duration samples do.
const latestScanRunsTimedOutSQL = `WITH wanted AS MATERIALIZED (
	SELECT j.id AS job_id,
		CAST(json_extract(k.value,'$.execution_hash') AS TEXT) AS execution_hash,
		CAST(json_extract(k.value,'$.config_hash') AS TEXT) AS config_hash,
		CAST(json_extract(k.value,'$.legacy_config_hash') AS TEXT) AS legacy_config_hash,
		CAST(json_extract(k.value,'$.scanner_profile_id') AS TEXT) AS profile_id,
		CAST(json_extract(k.value,'$.scanner_profile_revision') AS INTEGER) AS profile_revision
	FROM json_each(?1) AS k
	CROSS JOIN jobs AS j ON j.id=CAST(json_extract(k.value,'$.job_id') AS TEXT) AND j.tenant_id=?2
	WHERE j.archived=0
)
SELECT w.job_id, (
	SELECT CASE WHEN COUNT(*)>0 AND SUM(CASE WHEN recent.status='timed_out' THEN 1 ELSE 0 END)=COUNT(*) THEN 1 ELSE 0 END
	FROM (
		SELECT recent.status
		FROM (
			SELECT s.id,s.job_id,s.status,s.finished_at,s.cycle_id,s.config_hash,s.scanner_profile_id,s.scanner_profile_revision
			FROM scans AS s INDEXED BY ` + scansJobHistoryIndex + `
			WHERE s.job_id=w.job_id AND s.tenant_id=?2
			ORDER BY s.finished_at DESC,s.id DESC LIMIT ?3
		) AS recent
		LEFT JOIN scan_cycles AS c ON c.id=recent.cycle_id AND c.job_id=recent.job_id
		LEFT JOIN jobs AS cycle_job ON cycle_job.id=c.job_id AND cycle_job.tenant_id=?2
		WHERE (recent.cycle_id<>'' AND cycle_job.id IS NOT NULL AND c.execution_hash=w.execution_hash)
			OR (recent.cycle_id='' AND
				(recent.config_hash=w.config_hash OR (w.legacy_config_hash<>'' AND recent.config_hash=w.legacy_config_hash))
				AND recent.scanner_profile_id=w.profile_id AND recent.scanner_profile_revision=w.profile_revision)
		ORDER BY recent.finished_at DESC,recent.id DESC LIMIT ?4
	) AS recent
) AS only_timed_out
FROM wanted AS w`

// ListCompletedScanCycleDurations returns, for each job that keys names and
// that is an unarchived job of the tenant, the durations of its perJobLimit
// newest completed samples that ran with the job's current scan settings. A
// key of another tenant's job, or of an unknown job, returns nothing.
//
// A completed cycle is one sample when its execution hash is the key's: the
// sum of its recorded earlier attempts and its final attempt's durable start
// and completion timestamps, so time between attempts is excluded and the
// final duration survives a crash before scan finalization. Recovery
// invocations that start after cycle completion are excluded because their
// duration is not scan work. A successful or incomplete scan without a cycle
// is its own sample when its config hash and TCP scanner profile revision
// are the key's, and it is one of the job's perJobLimit times
// scanDurationScanWindow newest successful or incomplete scans. A job's
// edits that do not change these, such as a rename, a schedule or
// notification edit, or a pause and resume, keep its samples. Samples are
// ranked by when they finished; the pinned plan and per-unit checkpoints
// are deliberately not loaded.
func (ts *TenantStore) ListCompletedScanCycleDurations(ctx context.Context, keys []ScanDurationKey, perJobLimit int) (map[string][]time.Duration, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	if perJobLimit < 1 || len(keys) == 0 {
		return map[string][]time.Duration{}, nil
	}
	// A job keyed twice would read its records twice; the first key counts.
	unique := make([]ScanDurationKey, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if !seen[key.JobID] {
			seen[key.JobID] = true
			unique = append(unique, key)
		}
	}
	raw, err := json.Marshal(unique)
	if err != nil {
		return nil, err
	}
	rows, err := ts.store.reader().QueryContext(ctx, completedScanDurationsSQL, string(raw), ts.scope.id, perJobLimit, perJobLimit*scanDurationScanWindow)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type sample struct {
		id       string
		at       time.Time
		duration time.Duration
	}
	byJob := make(map[string]map[string]*sample)
	for rows.Next() {
		var jobID, sampleID, started, finished, at string
		if err := rows.Scan(&jobID, &sampleID, &started, &finished, &at); err != nil {
			return nil, err
		}
		samples := byJob[jobID]
		if samples == nil {
			samples = make(map[string]*sample)
			byJob[jobID] = samples
		}
		current := samples[sampleID]
		if current == nil {
			current = &sample{id: sampleID, at: scanTime(at)}
			samples[sampleID] = current
		}
		if duration := scanTime(finished).Sub(scanTime(started)); duration > 0 {
			current.duration += duration
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make(map[string][]time.Duration, len(byJob))
	for jobID, samples := range byJob {
		ranked := make([]*sample, 0, len(samples))
		for _, candidate := range samples {
			if candidate.duration > 0 {
				ranked = append(ranked, candidate)
			}
		}
		sort.Slice(ranked, func(i, j int) bool {
			if !ranked[i].at.Equal(ranked[j].at) {
				return ranked[i].at.After(ranked[j].at)
			}
			return ranked[i].id > ranked[j].id
		})
		if len(ranked) > perJobLimit {
			ranked = ranked[:perJobLimit]
		}
		for _, kept := range ranked {
			out[jobID] = append(out[jobID], kept.duration)
		}
	}
	return out, nil
}

// LatestScanRunsTimedOut reports whether each named job's newest current-key
// run records all timed out. It examines at most perJobLimit times
// scanDurationScanWindow newest scans per job, and returns only job IDs from
// the requesting tenant. A result is true only when at least one matching
// run was found and every one of the newest matching runs timed out.
func (ts *TenantStore) LatestScanRunsTimedOut(ctx context.Context, keys []ScanDurationKey, perJobLimit int) (map[string]bool, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	if perJobLimit < 1 || len(keys) == 0 {
		return map[string]bool{}, nil
	}
	unique := make([]ScanDurationKey, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if !seen[key.JobID] {
			seen[key.JobID] = true
			unique = append(unique, key)
		}
	}
	raw, err := json.Marshal(unique)
	if err != nil {
		return nil, err
	}
	rows, err := ts.store.reader().QueryContext(ctx, latestScanRunsTimedOutSQL, string(raw), ts.scope.id, perJobLimit*scanDurationScanWindow, perJobLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]bool, len(unique))
	for rows.Next() {
		var jobID string
		var onlyTimedOut int
		if err := rows.Scan(&jobID, &onlyTimedOut); err != nil {
			return nil, err
		}
		out[jobID] = onlyTimedOut != 0
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
