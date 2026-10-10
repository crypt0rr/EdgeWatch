package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// retentionBatchRows counts the rows that one committed retention
// transaction removed.
type retentionBatchRows struct {
	table               string
	scans, hosts, words int
}

// Retention deletes the host rows of expired scans, and with them their
// search rows, in transactions of at most childBatchSize rows before it
// deletes the scans, so no transaction cascades into the hosts of broad
// scans. Another writer commits between the transactions, and a pass that
// stops after a host batch is finished by the next one.
func TestRetentionBoundsTheHostRowsOfEachTransaction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	broad, err := tenant.CreateJob(ctx, testJob("broad-retention"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := tenant.CreateJob(ctx, testJob("concurrent-writer"))
	if err != nil {
		t.Fatal(err)
	}
	// Thousands of hosts per scan; the race detector slows the inserts
	// down too much for that, so it gets a smaller fixture with the same
	// number of transactions per scan.
	hostsPerScan, hostBatch := 2000, 500
	if raceEnabled {
		hostsPerScan, hostBatch = 250, 100
	}
	expired := seedLargeEvidenceScans(t, s.DB, DefaultTenantID, broad.ID, "expired", 4, 4096, time.Now().Add(-72*time.Hour))
	seedLargeEvidenceHosts(t, s.DB, expired, hostsPerScan)
	// The newest successful scan of the job is protected, so the expired
	// ones are all candidates.
	if err := s.System().SaveScan(ctx, fixtureScan("retained", broad.ID, broad.Job.Name, time.Now().UTC(), fixtureHosts(0, 2))); err != nil {
		t.Fatal(err)
	}
	count := func(query string) int {
		t.Helper()
		var rows int
		if err := s.DB.QueryRowContext(ctx, query).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	counts := func() (scans, hosts, words int) {
		return count(`SELECT COUNT(*) FROM scans`), count(`SELECT COUNT(*) FROM scan_hosts`), count(`SELECT COUNT(*) FROM scan_host_search`)
	}
	scans, hosts, words := counts()
	if hosts != 4*hostsPerScan+2 || words != hosts {
		t.Fatalf("fixture has %d host rows and %d search rows, want %d", hosts, words, 4*hostsPerScan+2)
	}

	// A pass that stops after its first committed host batch leaves the
	// scans for the next pass.
	stop := errors.New("stop after the first host batch")
	if _, err := s.System().pruneWithStats(ctx, time.Now().Add(-time.Hour), retentionOptions{parentBatchSize: 2, childBatchSize: hostBatch, afterBatch: func(context.Context, string) error { return stop }}); !errors.Is(err, stop) {
		t.Fatalf("interrupted pass = %v, want the stop", err)
	}
	if nowScans, nowHosts, _ := counts(); nowScans != scans || nowHosts != hosts-hostBatch {
		t.Fatalf("after the interrupted pass: %d scans and %d host rows, want %d and %d", nowScans, nowHosts, scans, hosts-hostBatch)
	}
	scans, hosts, words = counts()

	var batches []retentionBatchRows
	archived := false
	stats, err := s.System().pruneWithStats(ctx, time.Now().Add(-time.Hour), retentionOptions{parentBatchSize: 2, childBatchSize: hostBatch, afterBatch: func(ctx context.Context, table string) error {
		nowScans, nowHosts, nowWords := counts()
		batches = append(batches, retentionBatchRows{table: table, scans: scans - nowScans, hosts: hosts - nowHosts, words: words - nowWords})
		scans, hosts, words = nowScans, nowHosts, nowWords
		// The writer connection is free between the transactions.
		archived = !archived
		if err := tenant.SetJobArchived(ctx, other.ID, archived); err != nil {
			return fmt.Errorf("another writer could not commit between retention batches: %w", err)
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Scans != int64(len(expired)) {
		t.Fatalf("pass deleted %d scans, want %d", stats.Scans, len(expired))
	}
	hostBatches := 0
	for _, batch := range batches {
		switch batch.table {
		case "scan_hosts":
			hostBatches++
			if batch.hosts > hostBatch || batch.words != batch.hosts || batch.scans != 0 {
				t.Errorf("host batch removed %d host rows, %d search rows and %d scans, want at most %d host rows with their search rows", batch.hosts, batch.words, batch.scans, hostBatch)
			}
		case "scans":
			if batch.hosts != 0 || batch.scans > 2 {
				t.Errorf("scan batch removed %d scans and cascaded into %d host rows", batch.scans, batch.hosts)
			}
		default:
			t.Errorf("batch of table %q", batch.table)
		}
	}
	if want := (4*hostsPerScan - hostBatch) / hostBatch; hostBatches < want {
		t.Fatalf("%d host batches, want at least %d: %+v", hostBatches, want, batches)
	}
	if nowScans, nowHosts, _ := counts(); nowScans != 1 || nowHosts != 2 {
		t.Fatalf("after retention: %d scans and %d host rows, want the retained scan and its hosts", nowScans, nowHosts)
	}
}

// completedCycleUnit creates the cycle, completes its only unit with a
// checkpoint, and returns the cycle with the unit's sequence. The cycle is
// left running.
func completedCycleUnit(ctx context.Context, t *testing.T, s *Store, record ScanCycleRecord) (ScanCycleRecord, int) {
	t.Helper()
	cycle, err := s.System().CreateScanCycle(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.System().NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	fragment := model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}}
	if err := s.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, fragment); err != nil {
		t.Fatal(err)
	}
	return cycle, unit.Sequence
}

// An expiry commits the cycle's terminal state first and empties its
// checkpoints afterwards, and a canceled context or a database error can
// stop that cleanup. Retention empties the checkpoints of expired and
// discarded cycles, which never resume, and keeps those of a paused cycle
// and of a completed cycle whose scan was not promoted yet.
func TestRetentionReclaimsCheckpointsOfExpiredAndDiscardedCycles(t *testing.T) {
	t.Parallel()
	ctx, s, job, plan := cycleFixture(t)
	record := ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan}
	checkpoint := func(cycleID string, sequence int) (string, string) {
		t.Helper()
		var payload, lastError string
		if err := s.DB.QueryRowContext(ctx, `SELECT CAST(snapshot_json AS TEXT),last_error FROM scan_cycle_units WHERE cycle_id=? AND sequence=?`, cycleID, sequence).Scan(&payload, &lastError); err != nil {
			t.Fatal(err)
		}
		return payload, lastError
	}
	now := time.Now().UTC()

	expired, expiredUnit := completedCycleUnit(ctx, t, s, record)
	// The expiry is durable, but its cleanup did not run.
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='expired',finished_at=?,last_error='scan cycle exceeded its resume window' WHERE id=?`, sqliteTimestamp(now), expired.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.System().SaveScan(ctx, model.Scan{ID: "expiry-record", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now, FinishedAt: now, Status: "timed_out", CycleID: expired.ID, CycleStatus: "expired", ConfigHash: job.Job.SecurityHash()}); err != nil {
		t.Fatal(err)
	}
	discarded, discardedUnit := completedCycleUnit(ctx, t, s, record)
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='discarded',finished_at=? WHERE id=?`, sqliteTimestamp(now), discarded.ID); err != nil {
		t.Fatal(err)
	}
	unpromoted, unpromotedUnit := completedCycleUnit(ctx, t, s, record)
	if _, err := s.System().CompleteScanCycle(ctx, unpromoted.ID); err != nil {
		t.Fatal(err)
	}
	paused, pausedUnit := completedCycleUnit(ctx, t, s, record)
	if _, err := s.System().PauseScanCycle(ctx, paused.ID, false, "operator pause"); err != nil {
		t.Fatal(err)
	}
	for _, kept := range []struct {
		id       string
		sequence int
	}{{expired.ID, expiredUnit}, {discarded.ID, discardedUnit}, {unpromoted.ID, unpromotedUnit}, {paused.ID, pausedUnit}} {
		if payload, _ := checkpoint(kept.id, kept.sequence); payload == "{}" {
			t.Fatalf("cycle %s has no checkpoint before retention", kept.id)
		}
	}

	if _, err := s.System().PruneWithStats(ctx, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if payload, lastError := checkpoint(expired.ID, expiredUnit); payload != "{}" || lastError != "cycle expired" {
		t.Fatalf("expired cycle checkpoint after retention = %q, %q; want it emptied as its expiry does", payload, lastError)
	}
	if payload, _ := checkpoint(discarded.ID, discardedUnit); payload != "{}" {
		t.Fatalf("discarded cycle checkpoint after retention = %q, want it emptied", payload)
	}
	for _, kept := range []struct {
		label    string
		id       string
		sequence int
	}{{"unpromoted completed", unpromoted.ID, unpromotedUnit}, {"paused", paused.ID, pausedUnit}} {
		if payload, _ := checkpoint(kept.id, kept.sequence); payload == "{}" {
			t.Errorf("retention emptied the checkpoint of the %s cycle", kept.label)
		}
	}
}

// Retention deletes an expired cycle's discovery checkpoints and units in
// transactions of at most childBatchSize rows before it deletes the cycle,
// so the deletion of a broad cycle cascades into none of them. A cycle that
// a retained scan references, and one that ended within retention, stay.
func TestRetentionBoundsTheUnitsOfEachCycleTransaction(t *testing.T) {
	t.Parallel()
	ctx, s, job, _ := cycleFixture(t)
	const units, childBatch = 230, 50
	old := sqliteTimestamp(time.Now().Add(-72 * time.Hour))
	recent := sqliteTimestamp(time.Now())
	for _, cycle := range []struct{ id, finished string }{{"expired-a", old}, {"expired-b", old}, {"referenced", old}, {"recent", recent}} {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,total_units,total_probes,started_at,updated_at,expires_at,finished_at) VALUES(?,?,?,?,'hash','hash','{}','expired',?,?,?,?,?,?)`, cycle.id, job.ID, job.Job.Name, job.Revision, units, units, cycle.finished, cycle.finished, cycle.finished, cycle.finished); err != nil {
			t.Fatal(err)
		}
		for _, statement := range []string{
			`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i+1<?) INSERT INTO scan_cycle_units(cycle_id,sequence,work_unit_json,status) SELECT ?,i,'{}','completed' FROM n`,
			`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i+1<?) INSERT INTO scan_cycle_discovery_checkpoints(cycle_id,sequence,processed_at) SELECT ?,i,'x' FROM n`,
		} {
			if _, err := s.DB.ExecContext(ctx, statement, units, cycle.id); err != nil {
				t.Fatal(err)
			}
		}
	}
	now := time.Now().UTC()
	if err := s.System().SaveScan(ctx, model.Scan{ID: "keeps-its-cycle", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now, FinishedAt: now, Status: "timed_out", CycleID: "referenced", CycleStatus: "expired", ConfigHash: job.Job.SecurityHash()}); err != nil {
		t.Fatal(err)
	}
	count := func(table string) int { return countRows(t, s.DB, `SELECT COUNT(*) FROM `+table) }
	tables := []string{"scan_cycles", "scan_cycle_units", "scan_cycle_discovery_checkpoints"}
	before := map[string]int{}
	for _, table := range tables {
		before[table] = count(table)
	}
	batches := map[string]int{}
	stats, err := s.System().pruneWithStats(ctx, time.Now().Add(-time.Hour), retentionOptions{parentBatchSize: 1, childBatchSize: childBatch, afterBatch: func(_ context.Context, deleted string) error {
		removed := map[string]int{}
		for _, table := range tables {
			now := count(table)
			removed[table], before[table] = before[table]-now, now
		}
		switch deleted {
		case "scan_cycle_units", "scan_cycle_discovery_checkpoints":
			batches[deleted]++
			for _, table := range tables {
				if table == deleted && removed[table] > childBatch || table != deleted && removed[table] != 0 {
					t.Errorf("%s batch removed %v", deleted, removed)
				}
			}
		case "scan_cycles":
			if removed["scan_cycles"] > 1 || removed["scan_cycle_units"] != 0 || removed["scan_cycle_discovery_checkpoints"] != 0 {
				t.Errorf("cycle batch removed %v, want one cycle and no cascade", removed)
			}
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Cycles != 2 {
		t.Fatalf("pass deleted %d cycles, want the two expired ones", stats.Cycles)
	}
	if want := 2 * units / childBatch; batches["scan_cycle_units"] < want || batches["scan_cycle_discovery_checkpoints"] < want {
		t.Fatalf("child batches = %v, want at least %d of each", batches, want)
	}
	for _, kept := range []string{"referenced", "recent"} {
		if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scan_cycle_units WHERE cycle_id=?`, kept); got != units {
			t.Errorf("cycle %s has %d units after retention, want %d", kept, got, units)
		}
	}
}
