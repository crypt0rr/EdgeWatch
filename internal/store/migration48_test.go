package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// legacyBaselineHostSearchSQL recreates the schema 40-47 projection. Search
// rows are keyed by job and address and receive rowids unrelated to
// baseline_hosts; the stale row shifts every later rowid, as in a long-lived
// installation, and must not survive the rebuild.
var legacyBaselineHostSearchSQL = []string{
	"DROP TRIGGER IF EXISTS baseline_hosts_search_ai",
	"DROP TRIGGER IF EXISTS baseline_hosts_search_au",
	"DROP TRIGGER IF EXISTS baseline_hosts_search_ad",
	"DROP TABLE IF EXISTS baseline_host_search",
	`CREATE VIRTUAL TABLE baseline_host_search USING fts5(job_id UNINDEXED, address UNINDEXED, content, tokenize='trigram')`,
	`CREATE TRIGGER baseline_hosts_search_ai AFTER INSERT ON baseline_hosts BEGIN
 INSERT INTO baseline_host_search(job_id,address,content) VALUES(NEW.job_id,NEW.address,lower(coalesce(NEW.search_text,'')));
END`,
	`CREATE TRIGGER baseline_hosts_search_au AFTER UPDATE ON baseline_hosts BEGIN
 DELETE FROM baseline_host_search WHERE job_id=OLD.job_id AND address=OLD.address;
 INSERT INTO baseline_host_search(job_id,address,content) VALUES(NEW.job_id,NEW.address,lower(coalesce(NEW.search_text,'')));
END`,
	`CREATE TRIGGER baseline_hosts_search_ad AFTER DELETE ON baseline_hosts BEGIN
 DELETE FROM baseline_host_search WHERE job_id=OLD.job_id AND address=OLD.address;
END`,
	"DELETE FROM fts_backfill_state WHERE table_name='baseline_hosts'",
	`INSERT INTO baseline_host_search(rowid,job_id,address,content) VALUES(1000000,'retired-job','203.0.113.250','retired-orphan-marker')`,
}

type baselineSearchBackfillState struct {
	lastRowID     int64
	processedRows int
	initialized   int
	complete      int
}

func readBaselineSearchBackfillState(t *testing.T, db *sql.DB) baselineSearchBackfillState {
	t.Helper()
	var state baselineSearchBackfillState
	if err := db.QueryRow(`SELECT last_rowid,processed_rows,initialized,complete FROM fts_backfill_state WHERE table_name='baseline_hosts'`).Scan(&state.lastRowID, &state.processedRows, &state.initialized, &state.complete); err != nil {
		t.Fatalf("read baseline search backfill state: %v", err)
	}
	return state
}

func countBaselineSearchRows(t *testing.T, db *sql.DB) (indexed, keyed int) {
	t.Helper()
	if err := db.QueryRow(`SELECT COUNT(*) FROM baseline_host_search`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM baseline_hosts h JOIN baseline_host_search hs ON hs.rowid=h.rowid WHERE hs.job_id=h.job_id AND hs.address=h.address`).Scan(&keyed); err != nil {
		t.Fatal(err)
	}
	return indexed, keyed
}

func assertBaselineSearchTotal(t *testing.T, s *Store, jobID, query string, want int) {
	t.Helper()
	page, err := defaultTenant(s).ListBaselineHostsPage(context.Background(), jobID, query, "", nil, 10, 0)
	if err != nil {
		t.Fatalf("baseline search %s %q: %v", jobID, query, err)
	}
	if page.Total != want {
		t.Fatalf("baseline search %s %q total = %d, want %d", jobID, query, page.Total, want)
	}
}

func TestBaselineHostSearchBackfillResumesAfterCancellation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	insertBaselineSearchJob(t, s, "resume-web", "resume-web")
	insertBaselineSearchJob(t, s, "resume-mail", "resume-mail")
	const webHosts = ftsBackfillBatchSize + 17
	if err := s.System().ReplaceBaselineHostProjection(ctx, "resume-web", baselineSearchSnapshot(1, webHosts)); err != nil {
		t.Fatal(err)
	}
	// Request the same rebuild that the schema 48 migration records.
	result, err := s.DB.ExecContext(ctx, `UPDATE fts_backfill_state SET last_rowid=0,processed_rows=0,initialized=0,complete=0 WHERE table_name='baseline_hosts'`)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		t.Fatalf("baseline search backfill state rows = %d, %v; want 1", changed, err)
	}

	backfillCtx, cancel := context.WithCancel(ctx)
	err = backfillHostSearchIndexesContextWithProgress(backfillCtx, s.DB, func(progress ftsBatchProgress) {
		if progress.table == "baseline_hosts" && progress.processedRows >= ftsBackfillBatchSize {
			cancel()
		}
	})
	cancel()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled baseline search backfill error = %v, want context.Canceled", err)
	}
	state := readBaselineSearchBackfillState(t, s.DB)
	if state.lastRowID == 0 || state.processedRows != ftsBackfillBatchSize || state.initialized != 1 || state.complete != 0 {
		t.Fatalf("cancelled baseline search checkpoint = %#v", state)
	}
	if indexed, _ := countBaselineSearchRows(t, s.DB); indexed != ftsBackfillBatchSize {
		t.Fatalf("partially rebuilt search rows = %d, want one batch of %d", indexed, ftsBackfillBatchSize)
	}
	readOnly, err := OpenReadOnlyExisting(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := readOnly.Verify(ctx)
	_ = readOnly.Close()
	if err != nil {
		t.Fatalf("verify interrupted rebuild: %v", err)
	}
	reported := false
	for _, progress := range verification.FTSBackfill {
		if progress.TableName == "baseline_hosts" {
			reported = !progress.Complete && progress.ProcessedRows == ftsBackfillBatchSize
		}
	}
	if !reported {
		t.Fatalf("verification did not report the interrupted baseline search rebuild: %#v", verification.FTSBackfill)
	}

	// A baseline written while the rebuild is interrupted is indexed by the
	// triggers; resuming must not index those rows a second time.
	if err := s.System().ReplaceBaselineHostProjection(ctx, "resume-mail", baselineSearchSnapshot(2, 3)); err != nil {
		t.Fatal(err)
	}
	if err := backfillHostSearchIndexesContext(ctx, s.DB); err != nil {
		t.Fatalf("resume baseline search backfill: %v", err)
	}
	state = readBaselineSearchBackfillState(t, s.DB)
	if state.complete != 1 {
		t.Fatalf("resumed baseline search checkpoint = %#v", state)
	}
	if indexed, keyed := countBaselineSearchRows(t, s.DB); indexed != webHosts+3 || keyed != webHosts+3 {
		t.Fatalf("resumed search rows = %d indexed, %d rowid-keyed; want %d", indexed, keyed, webHosts+3)
	}
	assertBaselineSearchTotal(t, s, "resume-web", "nginx", webHosts)
	assertBaselineSearchTotal(t, s, "resume-mail", "nginx", 3)
}

func TestBaselineHostSearchRebuildReportsStoreErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	insertBaselineSearchJob(t, s, "error-web", "error-web")
	if err := s.System().ReplaceBaselineHostProjection(ctx, "error-web", baselineSearchSnapshot(1, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE baseline_hosts SET host_json='{' WHERE address='10.1.0.1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).ListBaselineHostsPage(ctx, "error-web", "", "", nil, 10, 0); err == nil {
		t.Fatal("malformed baseline host evidence was returned without an error")
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := ensureBaselineHostSearchContext(cancelled, s.DB); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled baseline search setup error = %v", err)
	}
	if _, err := backfillBaselineHostSearchBatchContext(cancelled, s.DB); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled baseline search batch error = %v", err)
	}

	// A missing checkpoint table or row fails the rebuild instead of treating
	// the projection as current.
	if _, err := s.DB.ExecContext(ctx, `DROP TABLE fts_backfill_state`); err != nil {
		t.Fatal(err)
	}
	if err := ensureBaselineHostSearchContext(ctx, s.DB); err == nil {
		t.Fatal("baseline search setup succeeded without a checkpoint table")
	}
	if _, err := backfillBaselineHostSearchBatchContext(ctx, s.DB); err == nil {
		t.Fatal("baseline search batch succeeded without a checkpoint table")
	}
	if err := ensureFTSBackfillStateContext(ctx, s.DB); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM fts_backfill_state WHERE table_name='baseline_hosts'`); err != nil {
		t.Fatal(err)
	}
	if err := ensureBaselineHostSearchContext(ctx, s.DB); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("baseline search setup without a checkpoint row = %v", err)
	}
	if _, err := backfillBaselineHostSearchBatchContext(ctx, s.DB); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("baseline search batch without a checkpoint row = %v", err)
	}

	// Without the source table the triggers cannot be installed and no batch
	// can be read; the checkpoint stays incomplete.
	if err := ensureFTSBackfillStateContext(ctx, s.DB); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TABLE baseline_hosts`); err != nil {
		t.Fatal(err)
	}
	if err := backfillHostSearchIndexesContext(ctx, s.DB); err == nil {
		t.Fatal("host search rebuild succeeded without baseline_hosts")
	}
	if _, err := backfillBaselineHostSearchBatchContext(ctx, s.DB); err == nil {
		t.Fatal("baseline search batch succeeded without baseline_hosts")
	}
	if state := readBaselineSearchBackfillState(t, s.DB); state.complete != 0 {
		t.Fatalf("failed baseline search rebuild was recorded as complete: %#v", state)
	}
	if _, err := defaultTenant(s).ListBaselineHostsPage(ctx, "error-web", "", "", nil, 10, 0); err == nil {
		t.Fatal("baseline search succeeded without baseline_hosts")
	}
}
