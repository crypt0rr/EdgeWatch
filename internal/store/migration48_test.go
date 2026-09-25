package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
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
	page, err := s.ListBaselineHostsPage(context.Background(), jobID, query, "", nil, 10, 0)
	if err != nil {
		t.Fatalf("baseline search %s %q: %v", jobID, query, err)
	}
	if page.Total != want {
		t.Fatalf("baseline search %s %q total = %d, want %d", jobID, query, page.Total, want)
	}
}

func TestMigration48RebuildsBaselineHostSearchByRowid(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fromSchema int
		// preSearch removes the projection for databases created before
		// migration 40 introduced baseline host search.
		preSearch           bool
		webHosts, mailHosts int
		// lastWebHost is the highest web rowid, indexed by the final batch.
		lastWebHost string
	}{
		// Two jobs across more than two bounded batches.
		{name: "schema 47", fromSchema: 47, webHosts: ftsBackfillBatchSize + 11, mailHosts: ftsBackfillBatchSize + 12, lastWebHost: "10.1.2.11"},
		{name: "schema 39", fromSchema: 39, preSearch: true, webHosts: 30, mailHosts: 20, lastWebHost: "10.1.0.30"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			webHosts, mailHosts := tc.webHosts, tc.mailHosts
			totalHosts := webHosts + mailHosts
			batches := (totalHosts + ftsBackfillBatchSize - 1) / ftsBackfillBatchSize
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "baseline-search.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, statement := range legacyBaselineHostSearchSQL {
				if _, err := s.DB.ExecContext(ctx, statement); err != nil {
					s.Close()
					t.Fatalf("install legacy baseline search: %v", err)
				}
			}
			insertBaselineSearchJob(t, s, "upgrade-web", "upgrade-web")
			insertBaselineSearchJob(t, s, "upgrade-mail", "upgrade-mail")
			if err := s.ReplaceBaselineHostProjection(ctx, "upgrade-web", baselineSearchSnapshot(1, webHosts)); err != nil {
				s.Close()
				t.Fatal(err)
			}
			if err := s.ReplaceBaselineHostProjection(ctx, "upgrade-mail", baselineSearchSnapshot(2, mailHosts)); err != nil {
				s.Close()
				t.Fatal(err)
			}
			if indexed, keyed := countBaselineSearchRows(t, s.DB); indexed != totalHosts+1 || keyed != 0 {
				s.Close()
				t.Fatalf("legacy fixture search rows = %d indexed, %d rowid-keyed", indexed, keyed)
			}
			if tc.preSearch {
				for _, statement := range legacyBaselineHostSearchSQL[:4] {
					if _, err := s.DB.ExecContext(ctx, statement); err != nil {
						s.Close()
						t.Fatal(err)
					}
				}
			}
			// Record every startup heartbeat so the rebuild must report its
			// progress while it runs.
			for _, statement := range []string{
				`CREATE TABLE migration_progress_observations(phase TEXT NOT NULL,progress INTEGER NOT NULL)`,
				`CREATE TRIGGER migration_progress_capture AFTER UPDATE OF phase,updated_at,progress ON startup_state WHEN NEW.state='migrating' BEGIN INSERT INTO migration_progress_observations(phase,progress) VALUES(NEW.phase,NEW.progress); END`,
			} {
				if _, err := s.DB.ExecContext(ctx, statement); err != nil {
					s.Close()
					t.Fatal(err)
				}
			}
			if _, err := s.DB.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", tc.fromSchema)); err != nil {
				s.Close()
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			upgraded, err := Open(path)
			if err != nil {
				t.Fatalf("upgrade from schema %d: %v", tc.fromSchema, err)
			}
			defer upgraded.Close()
			var version int
			if err := upgraded.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
				t.Fatal(err)
			}
			if version != schemaVersion {
				t.Fatalf("schema version = %d, want %d", version, schemaVersion)
			}
			state := readBaselineSearchBackfillState(t, upgraded.DB)
			if state.complete != 1 || state.initialized != 1 || state.processedRows != totalHosts || state.lastRowID == 0 {
				t.Fatalf("baseline search backfill state = %#v, want complete over %d rows", state, totalHosts)
			}
			// The stale legacy row is gone and every host is keyed by its rowid.
			if indexed, keyed := countBaselineSearchRows(t, upgraded.DB); indexed != totalHosts || keyed != totalHosts {
				t.Fatalf("upgraded search rows = %d indexed, %d rowid-keyed; want %d", indexed, keyed, totalHosts)
			}
			var heartbeats, progressed int
			if err := upgraded.DB.QueryRow(`SELECT COUNT(*),COALESCE(MAX(progress),0) FROM migration_progress_observations WHERE phase='host-search:baseline_hosts'`).Scan(&heartbeats, &progressed); err != nil {
				t.Fatal(err)
			}
			if heartbeats < batches || progressed != totalHosts {
				t.Fatalf("baseline search heartbeats = %d with progress %d, want %d batches up to %d", heartbeats, progressed, batches, totalHosts)
			}
			assertBaselineHostSearchTriggersUseRowid(t, upgraded.DB)

			assertBaselineSearchTotal(t, upgraded, "upgrade-web", "nginx", webHosts)
			assertBaselineSearchTotal(t, upgraded, "upgrade-web", tc.lastWebHost, 1)
			assertBaselineSearchTotal(t, upgraded, "upgrade-web", "80", webHosts)
			assertBaselineSearchTotal(t, upgraded, "upgrade-web", "retired-orphan-marker", 0)
			assertBaselineSearchTotal(t, upgraded, "upgrade-mail", "nginx", mailHosts)
			if _, err := upgraded.DB.ExecContext(ctx, `UPDATE jobs SET name='renamed-upgrade' WHERE id='upgrade-web'`); err != nil {
				t.Fatal(err)
			}
			assertBaselineSearchTotal(t, upgraded, "upgrade-web", "renamed-upgrade", webHosts)
			assertBaselineSearchTotal(t, upgraded, "upgrade-mail", "renamed-upgrade", 0)

			// Later maintenance reuses the rowid-keyed triggers.
			if err := upgraded.ReplaceBaselineHostProjection(ctx, "upgrade-web", baselineSearchSnapshot(1, 5)); err != nil {
				t.Fatal(err)
			}
			if indexed, keyed := countBaselineSearchRows(t, upgraded.DB); indexed != 5+mailHosts || keyed != 5+mailHosts {
				t.Fatalf("replaced search rows = %d indexed, %d rowid-keyed; want %d", indexed, keyed, 5+mailHosts)
			}
			assertBaselineSearchTotal(t, upgraded, "upgrade-web", "nginx", 5)
		})
	}
}

func TestBaselineHostSearchBackfillResumesAfterCancellation(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	insertBaselineSearchJob(t, s, "resume-web", "resume-web")
	insertBaselineSearchJob(t, s, "resume-mail", "resume-mail")
	const webHosts = ftsBackfillBatchSize + 17
	if err := s.ReplaceBaselineHostProjection(ctx, "resume-web", baselineSearchSnapshot(1, webHosts)); err != nil {
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
	if err := s.ReplaceBaselineHostProjection(ctx, "resume-mail", baselineSearchSnapshot(2, 3)); err != nil {
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
	ctx := context.Background()
	s := openTestStore(t)
	insertBaselineSearchJob(t, s, "error-web", "error-web")
	if err := s.ReplaceBaselineHostProjection(ctx, "error-web", baselineSearchSnapshot(1, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE baseline_hosts SET host_json='{' WHERE address='10.1.0.1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListBaselineHostsPage(ctx, "error-web", "", "", nil, 10, 0); err == nil {
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
	if _, err := s.ListBaselineHostsPage(ctx, "error-web", "", "", nil, 10, 0); err == nil {
		t.Fatal("baseline search succeeded without baseline_hosts")
	}
}
