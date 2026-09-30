package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// tenantPurgeMarker is a DNS name that only tenant B's hosts hold, and
// tenantPurgeTrigram one of its trigrams, a term of the search indexes. The
// tests look for them where the erased rows may be left behind.
const (
	tenantPurgeMarker  = "~~~~qzqzq.tenant-b.example"
	tenantPurgeTrigram = "~qz"
)

// seedTenantPurgeMarker gives tenant B hosts that hold the marker in each
// table that a search index covers, in several transactions, so each index
// has several segments. It then truncates the write-ahead log, so every
// copy of the marker that the log holds later was written by the purge.
func seedTenantPurgeMarker(t *testing.T, f tenantFixture) {
	t.Helper()
	const (
		hosts   = `WITH RECURSIVE seq(n) AS (SELECT ?3 UNION ALL SELECT n+1 FROM seq WHERE n<?3+199) `
		address = `'10.9.'||(n/256)||'.'||(n%256)`
		names   = `'["'||?2||'"]'`
		host    = `'{"hostnames":["'||?2||'"]}'`
	)
	for _, statement := range []struct {
		query string
		owner string
	}{
		{hosts + `INSERT INTO baseline_hosts(job_id,address,address_family,dns_names_json,host_json,search_text) SELECT ?1,` + address + `,'ipv4',` + names + `,` + host + `,?2 FROM seq`, f.jobB},
		{hosts + `INSERT INTO scan_hosts(scan_id,address,address_family,dns_names_json,host_json,search_text) SELECT ?1,` + address + `,'ipv4',` + names + `,` + host + `,?2 FROM seq`, f.scanB},
		{hosts + `INSERT INTO latest_scan_hosts(address,scan_id,job_id,finished_at,address_family,dns_names_json,host_json,search_text,tenant_id) SELECT ` + address + `,?1,'` + f.jobB + `','2026-09-21T12:00:00.000000000Z','ipv4',` + names + `,` + host + `,?2,'` + secondTenantID + `' FROM seq`, f.scanB},
	} {
		for first := 1; first <= 600; first += 200 {
			if _, err := f.store.DB.Exec(statement.query, statement.owner, tenantPurgeMarker, first); err != nil {
				t.Fatalf("%s: %v", statement.query, err)
			}
		}
	}
	for _, index := range tenantPurgeSearchIndexes {
		if blocks := trigramBlocks(t, f.store, index); blocks == 0 {
			t.Fatalf("%s holds no term of tenant B's marker", index)
		}
	}
	if busy, err := checkpointTruncate(context.Background(), f.store.DB); err != nil || busy {
		t.Fatalf("truncate the write-ahead log: busy %v, %v", busy, err)
	}
}

// trigramBlocks counts the blocks of the index's data table that hold
// tenantPurgeTrigram.
func trigramBlocks(t *testing.T, s *Store, index string) int {
	t.Helper()
	var blocks int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM `+index+`_data WHERE instr(block, CAST(? AS BLOB))>0`, tenantPurgeTrigram).Scan(&blocks); err != nil {
		t.Fatal(err)
	}
	return blocks
}

// walMarkers returns the size of the write-ahead log and the copies of the
// marker it holds.
func walMarkers(t *testing.T, s *Store) (size, copies int) {
	t.Helper()
	data, err := os.ReadFile(s.Path + "-wal")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return len(data), bytes.Count(data, []byte(tenantPurgeMarker))
}

// openSnapshot opens a read transaction on the store's readers and reads in
// it, so it holds a snapshot until the test ends it, as a backup does.
func openSnapshot(t *testing.T, s *Store) *sql.Tx {
	t.Helper()
	reader, err := s.reader().BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Rollback() })
	var tenants int
	if err := reader.QueryRow(`SELECT COUNT(*) FROM tenants`).Scan(&tenants); err != nil {
		t.Fatal(err)
	}
	return reader
}

// shortenBusyTimeout lowers the busy timeout of the store's one writer
// connection, so a checkpoint that a reader keeps busy gives up sooner.
func shortenBusyTimeout(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.DB.Exec(`PRAGMA busy_timeout=200`); err != nil {
		t.Fatal(err)
	}
}

// mergeLog records, through tenantPurgeOptions.afterMerge, the indexes in
// which a compaction started a merge of every segment and those whose merge
// it continued.
type mergeLog struct{ started, continued []string }

func (l *mergeLog) afterMerge(_ context.Context, index string, pages int) error {
	if pages < 0 {
		l.started = append(l.started, index)
	} else {
		l.continued = append(l.continued, index)
	}
	return nil
}

// spentBudget is a maintenance budget that is spent before the maintenance
// starts.
func spentBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	budget, spend := context.WithCancel(ctx)
	spend()
	return budget, spend
}

// assertTenantPurgePhase checks that tenant B is still being deleted, in
// the phase given.
func assertTenantPurgePhase(t *testing.T, s *Store, phase string) {
	t.Helper()
	record, err := s.Platform().GetTenant(context.Background(), secondTenantID)
	if err != nil || record.State != TenantStateDeleting || record.PurgePhase != phase {
		t.Fatalf("tenant B = %+v, %v; want it deleting in phase %s", record, err, phase)
	}
	var purged int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action=?`, auditTenantPurged).Scan(&purged); err != nil || purged != 0 {
		t.Fatalf("the platform audit records %d purges of a tenant that is still being deleted: %v", purged, err)
	}
}

// assertNothingOfTheMarkerLeft checks that no search index, no backup made
// now, and not the write-ahead log holds tenant B's marker.
func assertNothingOfTheMarkerLeft(t *testing.T, s *Store) {
	t.Helper()
	for _, index := range tenantPurgeSearchIndexes {
		if blocks := trigramBlocks(t, s, index); blocks != 0 {
			t.Errorf("%s holds a term of the erased rows in %d blocks", index, blocks)
		}
		if _, err := s.DB.Exec(`INSERT INTO ` + index + `(` + index + `) VALUES('integrity-check')`); err != nil {
			t.Errorf("%s fails its integrity check: %v", index, err)
		}
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if _, err := s.DB.Exec(`VACUUM INTO ?`, backup); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if copies := bytes.Count(data, []byte(tenantPurgeTrigram)); copies != 0 {
		t.Errorf("a backup made after the purge holds %q %d times", tenantPurgeTrigram, copies)
	}
	if _, copies := walMarkers(t, s); copies != 0 {
		t.Errorf("the write-ahead log holds %d copies of the erased rows' marker", copies)
	}
}

// A reader that holds an older snapshot while the purge truncates the
// write-ahead log, as a running backup does, keeps the checkpoint busy.
// The pass reports the maintenance pending, and the tenant stays deleting
// in the checkpoint phase, with the log still holding the erased rows. The
// next pass, without the reader, truncates the log and makes the tombstone.
func TestTenantPurgeRetriesABusyCheckpoint(t *testing.T) {
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	seedTenantPurgeMarker(t, f)
	requestSecondTenantDeletion(t, f)
	shortenBusyTimeout(t, f.store)
	reader := openSnapshot(t, f.store)

	results, err := f.store.System().PurgeDeletingTenants(ctx)
	if err != nil || len(results) != 1 || results[0].Complete || !results[0].MaintenancePending || !results[0].CheckpointBusy || results[0].Phase != tenantPurgePhaseCheckpoint {
		t.Fatalf("purge with a reader open = %+v, %v; want the checkpoint pending", results, err)
	}
	assertTenantPurgePhase(t, f.store, tenantPurgePhaseCheckpoint)
	busySize, copies := walMarkers(t, f.store)
	if copies == 0 {
		t.Fatal("the write-ahead log holds no copy of the erased rows while a reader keeps it; the test shows nothing")
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}

	results, err = f.store.System().PurgeDeletingTenants(ctx)
	if err != nil || len(results) != 1 || !results[0].Complete || results[0].MaintenancePending || results[0].CheckpointBusy || results[0].Rows != 0 {
		t.Fatalf("the next pass = %+v, %v; want the purge complete", results, err)
	}
	if record, err := f.store.Platform().GetTenant(ctx, secondTenantID); err != nil || record.State != TenantStateDeleted || record.PurgePhase != tenantPurgePhaseComplete {
		t.Fatalf("tombstone = %+v, %v", record, err)
	}
	if size, _ := walMarkers(t, f.store); size >= busySize {
		t.Fatalf("the write-ahead log is %d bytes after the purge, %d while the reader kept it", size, busySize)
	}
	assertNothingOfTheMarkerLeft(t, f.store)
}

// A pass whose maintenance budget runs out during the compaction leaves the
// tenant deleting in the phase of the index it reached, and still runs its
// checkpoint. The next pass continues the compaction from that index, and
// only once every index is compacted and the log truncated does it make the
// tombstone: then no search index and no backup holds a term of the erased
// rows.
func TestTenantPurgeContinuesTheCompactionAfterASpentBudget(t *testing.T) {
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	seedTenantPurgeMarker(t, f)
	requestSecondTenantDeletion(t, f)

	var spent mergeLog
	var spend context.CancelFunc
	results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, maintenanceBudget: func(ctx context.Context) (context.Context, context.CancelFunc) {
		budget, cancel := context.WithCancel(ctx)
		spend = cancel
		return budget, cancel
	}, afterMerge: func(ctx context.Context, index string, pages int) error {
		// The budget runs out after the first merge.
		_ = spent.afterMerge(ctx, index, pages)
		spend()
		return ctx.Err()
	}})
	first := tenantPurgePhaseCompact + tenantPurgeSearchIndexes[0]
	if err != nil || len(results) != 1 || results[0].Complete || !results[0].MaintenancePending || results[0].CheckpointBusy || results[0].Phase != first {
		t.Fatalf("purge past its maintenance budget = %+v, %v; want it pending at %s", results, err, first)
	}
	if !slices.Equal(spent.started, tenantPurgeSearchIndexes[:1]) || len(spent.continued) != 0 {
		t.Fatalf("the pass merged %+v before its budget ran out", spent)
	}
	assertTenantPurgePhase(t, f.store, first)
	for _, index := range tenantPurgeSearchIndexes[1:] {
		if trigramBlocks(t, f.store, index) == 0 {
			t.Fatalf("%s holds no term of the erased rows before its compaction; the test shows nothing", index)
		}
	}
	if _, copies := walMarkers(t, f.store); copies != 0 {
		t.Fatalf("the write-ahead log holds %d copies of the erased rows after a pass whose budget ran out", copies)
	}

	// The next pass continues the merge of the first index rather than
	// starting it over, and starts the merge of each later one.
	var merged mergeLog
	results, err = f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, afterMerge: merged.afterMerge})
	if err != nil || len(results) != 1 || !results[0].Complete || results[0].MaintenancePending {
		t.Fatalf("the next pass = %+v, %v; want the purge complete", results, err)
	}
	if !slices.Equal(merged.started, tenantPurgeSearchIndexes[1:]) {
		t.Fatalf("the next pass started merges of %v, want %v", merged.started, tenantPurgeSearchIndexes[1:])
	}
	assertNothingOfTheMarkerLeft(t, f.store)
}

// Cancellation stops the maintenance as it does the steps: the pass
// reports it, and the tenant stays deleting in the phase it reached, for
// the next pass to resume.
func TestTenantPurgeMaintenanceStopsWhenCancelled(t *testing.T) {
	f := newTenantPurgeFixture(t)
	requestSecondTenantDeletion(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, afterMerge: func(context.Context, string, int) error {
		cancel()
		return nil
	}})
	first := tenantPurgePhaseCompact + tenantPurgeSearchIndexes[0]
	if !errors.Is(err, context.Canceled) || len(results) != 1 || results[0].Complete || results[0].MaintenancePending || results[0].Phase != first {
		t.Fatalf("cancelled maintenance = %+v, %v", results, err)
	}
	assertTenantPurgePhase(t, f.store, first)
	results, err = f.store.System().PurgeDeletingTenants(context.Background())
	if err != nil || len(results) != 1 || !results[0].Complete {
		t.Fatalf("the next pass = %+v, %v", results, err)
	}
}

// A pass resumes the maintenance at the phase it finds: the free-pages and
// checkpoint phases merge nothing, and a compaction phase that names no
// index, such as one that a later release removed, starts the compaction
// over. A tenant that leaves the deleting state stops it, and a failed
// database is reported.
func TestTenantPurgeMaintenanceResumesAtItsPhase(t *testing.T) {
	ctx := context.Background()
	for phase, want := range map[string][]string{
		tenantPurgePhaseFreePages:                 nil,
		tenantPurgePhaseCheckpoint:                nil,
		tenantPurgePhaseCompact + "retired_index": tenantPurgeSearchIndexes,
	} {
		f := newTenantPurgeFixture(t)
		requestSecondTenantDeletion(t, f)
		// A pass whose budget is spent before it starts erases the rows
		// and leaves the maintenance to the next.
		if results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, maintenanceBudget: spentBudget}); err != nil || len(results) != 1 || !results[0].MaintenancePending || results[0].Phase != tenantPurgePhaseVerify {
			t.Fatalf("purge with its budget spent = %+v, %v", results, err)
		}
		if err := setTenantPurgePhase(ctx, f.store.DB, secondTenantID, phase); err != nil {
			t.Fatal(err)
		}
		var merged mergeLog
		results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, afterMerge: merged.afterMerge})
		if err != nil || len(results) != 1 || !results[0].Complete {
			t.Fatalf("purge from phase %s = %+v, %v", phase, results, err)
		}
		if !slices.Equal(merged.started, want) || (want == nil && len(merged.continued) != 0) {
			t.Fatalf("purge from phase %s merged %+v, want merges started in %v", phase, merged, want)
		}
	}

	f := newTenantPurgeFixture(t)
	requestSecondTenantDeletion(t, f)
	results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, afterMerge: func(ctx context.Context, _ string, _ int) error {
		_, err := f.store.DB.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, TenantStateDisabled, secondTenantID)
		return err
	}})
	if !errors.Is(err, ErrConflict) || len(results) != 1 || results[0].Complete {
		t.Fatalf("maintenance of a tenant that left the deleting state = %+v, %v", results, err)
	}
	if err := setTenantPurgePhase(ctx, f.store.DB, secondTenantID, tenantPurgePhaseCheckpoint); !errors.Is(err, ErrConflict) {
		t.Fatalf("record a phase of a tenant that is not being deleted = %v", err)
	}

	s := openTestStore(t)
	_ = s.Close()
	result := TenantPurgeResult{Phase: tenantPurgePhaseVerify}
	if _, err := purgeTenantMaintenance(ctx, s.DB, secondTenantID, tenantPurgeOptions{}, &result); err == nil {
		t.Fatal("maintenance of a closed database succeeded")
	}
	result.Phase = tenantPurgePhaseCheckpoint
	if _, err := purgeTenantMaintenance(ctx, s.DB, secondTenantID, tenantPurgeOptions{}, &result); err == nil || !strings.Contains(err.Error(), "auto-vacuum") {
		t.Fatalf("maintenance of a closed database from the checkpoint phase = %v", err)
	}
	if _, err := s.System().PurgeDeletingTenants(ctx); err == nil {
		t.Fatal("a purge of a closed database succeeded")
	}
}

// A merge in progress that a positive page count does not continue, because
// a lower level holds as many segments as the merge has inputs but fewer
// than FTS5's usermerge setting, is merged again from every segment, so the
// compaction does not end while the merge's inputs still hold the erased
// rows' terms.
func TestSearchIndexCompactionFinishesAStalledMerge(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	const index = "baseline_host_search"
	insert := func(first, last int, content string) {
		t.Helper()
		if _, err := s.DB.Exec(`WITH RECURSIVE seq(n) AS (SELECT ?1 UNION ALL SELECT n+1 FROM seq WHERE n<?2)
 INSERT INTO baseline_host_search(rowid,job_id,address,content) SELECT n,'job','10.0.0.'||n,?3||' host-'||n FROM seq`, first, last, content); err != nil {
			t.Fatal(err)
		}
	}
	// One segment with rows that hold the marker, and one with the markers
	// of their deletion.
	insert(1, 1500, "kept")
	insert(1501, 3000, tenantPurgeMarker)
	if _, err := s.DB.Exec(`INSERT INTO baseline_host_search(baseline_host_search) VALUES('optimize')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DELETE FROM baseline_host_search WHERE rowid>1500`); err != nil {
		t.Fatal(err)
	}
	// A merge of both that has done one page of its work, and two new
	// segments on a lower level.
	if _, err := mergeSearchIndex(ctx, s.DB, index, -1); err != nil {
		t.Fatal(err)
	}
	insert(5001, 5003, "new")
	insert(6001, 6003, "new")
	if merged, err := mergeSearchIndex(ctx, s.DB, index, ftsMergePageLimit); err != nil || merged {
		t.Fatalf("a positive merge = %v, %v; want the merge stalled", merged, err)
	}
	if merging, err := searchIndexMerging(ctx, s.DB, index); err != nil || !merging {
		t.Fatalf("merge in progress = %v, %v", merging, err)
	}
	if trigramBlocks(t, s, index) == 0 {
		t.Fatal("the stalled merge's inputs hold no term of the erased rows; the test shows nothing")
	}

	var merged mergeLog
	if err := continueSearchIndexCompaction(ctx, s.DB, index, tenantPurgeOptions{afterMerge: merged.afterMerge}); err != nil {
		t.Fatal(err)
	}
	if merging, err := searchIndexMerging(ctx, s.DB, index); err != nil || merging || !slices.Equal(merged.started, []string{index}) {
		t.Fatalf("merge in progress after the compaction = %v, %v (merges %+v, want one started over)", merging, err, merged)
	}
	if blocks := trigramBlocks(t, s, index); blocks != 0 {
		t.Fatalf("the compacted index holds a term of the erased rows in %d blocks", blocks)
	}
	var kept int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM baseline_host_search WHERE baseline_host_search MATCH 'kept'`).Scan(&kept); err != nil || kept != 1500 {
		t.Fatalf("rows found after the compaction = %d, %v", kept, err)
	}
	if err := continueSearchIndexCompaction(ctx, s.DB, index, tenantPurgeOptions{afterMerge: func(context.Context, string, int) error {
		return errors.New("hook failed")
	}}); err != nil {
		t.Fatalf("compaction of a compacted index = %v, want no merge", err)
	}
	_ = s.Close()
	if err := continueSearchIndexCompaction(ctx, s.DB, index, tenantPurgeOptions{}); err == nil {
		t.Fatal("compaction of a closed database succeeded")
	}
	if _, err := searchIndexMerging(ctx, s.DB, index); err == nil {
		t.Fatal("the structure of a closed database was read")
	}
}

// The structure record reads as SQLite writes it, in both formats, and a
// record that does not read as one is an error.
func TestFTSStructureMerging(t *testing.T) {
	cookie := []byte{0, 0, 0, 7}
	record := func(parts ...[]byte) []byte { return bytes.Join(append([][]byte{cookie}, parts...), nil) }
	for _, tc := range []struct {
		name    string
		record  []byte
		merging bool
		err     string
	}{
		{name: "empty index", record: record([]byte{0, 0, 0})},
		{name: "no merge", record: record([]byte{2, 3, 0x81, 0x00}, []byte{0, 2, 1, 1, 0x82, 0x2c, 2, 1, 1}, []byte{0, 1, 3, 1, 9})},
		{name: "merge on the second level", record: record([]byte{2, 3, 5}, []byte{0, 1, 1, 1, 1}, []byte{2, 2, 2, 1, 1, 3, 1, 1}), merging: true},
		{name: "nine-byte write counter", record: record([]byte{1, 1}, bytes.Repeat([]byte{0xff}, 9), []byte{0, 1, 1, 1, 1})},
		{name: "V2 without a merge", record: record(ftsStructureV2, []byte{1, 1, 1}, []byte{0, 1, 1, 1, 1, 1, 2, 0, 0, 3})},
		{name: "V2 with a merge", record: record(ftsStructureV2, []byte{1, 2, 1}, []byte{2, 2, 1, 1, 1, 1, 2, 0, 0, 3, 2, 1, 1, 3, 4, 0, 0, 3}), merging: true},
		{name: "too short", record: []byte{0, 0, 1}, err: "too short"},
		{name: "ends early", record: record([]byte{1, 1, 0}, []byte{0, 1, 1, 1}), err: "ends early"},
		{name: "ends inside a varint", record: record([]byte{1, 0x81}), err: "ends early"},
		{name: "more inputs than segments", record: record([]byte{1, 1, 0}, []byte{2, 1, 1, 1, 1}), err: "merge inputs"},
		{name: "more segments than the record has", record: record([]byte{1, 1, 0}, []byte{0, 2, 1, 1, 1, 2, 1, 1}), err: "merge inputs"},
		{name: "segments on no level", record: record([]byte{1, 2, 0}, []byte{0, 1, 1, 1, 1}), err: "miss 1 segments"},
		{name: "too many levels", record: record([]byte{0x90, 0x00, 0, 0}), err: "levels"},
	} {
		merging, err := ftsStructureMerging(tc.record)
		switch {
		case tc.err == "" && (err != nil || merging != tc.merging):
			t.Errorf("%s: merging %v, %v; want %v", tc.name, merging, err, tc.merging)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s: merging %v, %v; want an error with %q", tc.name, merging, err, tc.err)
		}
	}

	// SQLite writes the V2 format for a contentless table that supports
	// deletes, and the older one for the search indexes.
	s := openTestStore(t)
	if _, err := s.DB.Exec(`CREATE VIRTUAL TABLE v2_structure USING fts5(x, content='', contentless_delete=1)`); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if _, err := s.DB.Exec(`INSERT INTO v2_structure(rowid,x) VALUES(?,'a host')`, i); err != nil {
			t.Fatal(err)
		}
	}
	for index, v2 := range map[string]bool{"v2_structure": true, "baseline_host_search": false} {
		var block []byte
		if err := s.DB.QueryRow(`SELECT block FROM ` + index + `_data WHERE id=10`).Scan(&block); err != nil {
			t.Fatal(err)
		}
		if got := bytes.HasPrefix(block[4:], ftsStructureV2); got != v2 {
			t.Errorf("%s has the V2 format: %v, want %v", index, got, v2)
		}
		if merging, err := searchIndexMerging(context.Background(), s.DB, index); err != nil || merging {
			t.Errorf("%s: merging %v, %v", index, merging, err)
		}
	}
	if _, err := s.DB.Exec(`DELETE FROM baseline_host_search_data WHERE id=10`); err != nil {
		t.Fatal(err)
	}
	if merging, err := searchIndexMerging(context.Background(), s.DB, "baseline_host_search"); err != nil || merging {
		t.Errorf("an index without a structure record: merging %v, %v", merging, err)
	}
	if _, err := s.DB.Exec(`INSERT INTO baseline_host_search_data(id,block) VALUES(10,x'00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := searchIndexMerging(context.Background(), s.DB, "baseline_host_search"); err == nil || !strings.Contains(err.Error(), "baseline_host_search") {
		t.Errorf("a record that does not read = %v", err)
	}
}

// The checkpoint reads the busy column of its result: a reader that holds
// an older snapshot keeps it busy, and the log keeps its frames; without
// one it truncates the log to zero bytes.
func TestCheckpointTruncateReportsABusyCheckpoint(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	shortenBusyTimeout(t, s)
	if _, err := s.DB.Exec(`INSERT INTO baseline_host_search(rowid,job_id,address,content) VALUES(1,'job','10.0.0.1','a host')`); err != nil {
		t.Fatal(err)
	}
	reader := openSnapshot(t, s)
	if _, err := s.DB.Exec(`DELETE FROM baseline_host_search WHERE rowid=1`); err != nil {
		t.Fatal(err)
	}
	if busy, err := checkpointTruncate(ctx, s.DB); err != nil || !busy {
		t.Fatalf("checkpoint with a reader open: busy %v, %v", busy, err)
	}
	if size, _ := walMarkers(t, s); size == 0 {
		t.Fatal("the busy checkpoint truncated the log")
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	if busy, err := checkpointTruncate(ctx, s.DB); err != nil || busy {
		t.Fatalf("checkpoint without a reader: busy %v, %v", busy, err)
	}
	if size, _ := walMarkers(t, s); size != 0 {
		t.Fatalf("the log is %d bytes after the checkpoint", size)
	}
	_ = s.Close()
	if _, err := checkpointTruncate(ctx, s.DB); err == nil {
		t.Fatal("a checkpoint of a closed database succeeded")
	}
}
