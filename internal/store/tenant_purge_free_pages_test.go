package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// freePageCopies counts the copies of marker in the pages on the freelist of
// the main database file, walking the trunk and leaf pages from the header,
// and returns the number of free pages. Run a checkpoint first, so the file
// holds what the write-ahead log does.
func freePageCopies(t *testing.T, path string, marker []byte) (copies, freePages int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pageSize := int(binary.BigEndian.Uint16(data[16:18]))
	free := map[uint32]bool{}
	for trunk := binary.BigEndian.Uint32(data[32:36]); trunk != 0; {
		free[trunk] = true
		page := data[int(trunk-1)*pageSize : int(trunk)*pageSize]
		for i := uint32(0); i < binary.BigEndian.Uint32(page[4:8]); i++ {
			free[binary.BigEndian.Uint32(page[8+4*i:12+4*i])] = true
		}
		trunk = binary.BigEndian.Uint32(page[0:4])
	}
	if want := binary.BigEndian.Uint32(data[36:40]); uint32(len(free)) != want {
		t.Fatalf("the freelist has %d pages, the header counts %d", len(free), want)
	}
	for n := range free {
		copies += bytes.Count(data[int(n-1)*pageSize:int(n)*pageSize], marker)
	}
	return copies, len(free)
}

// assertNoFreePageCopies truncates the write-ahead log and checks that no
// free page of the database file holds tenant B's marker or its trigram.
func assertNoFreePageCopies(t *testing.T, s *Store) {
	t.Helper()
	if busy, err := checkpointTruncate(context.Background(), s.DB); err != nil || busy {
		t.Fatalf("truncate the write-ahead log: busy %v, %v", busy, err)
	}
	for _, marker := range []string{tenantPurgeMarker, tenantPurgeTrigram} {
		if copies, pages := freePageCopies(t, s.Path, []byte(marker)); copies != 0 {
			t.Errorf("%d free pages hold %q %d times", pages, marker, copies)
		}
	}
}

// useAutoVacuum rebuilds the store's database in the auto-vacuum mode given.
// NONE is the mode of a database created before v0.18.31.
func useAutoVacuum(t *testing.T, s *Store, mode string) {
	t.Helper()
	for _, statement := range []string{`PRAGMA auto_vacuum=` + mode, `VACUUM`} {
		if _, err := s.DB.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// freeMarkerPages writes about the number of pages given of rows that hold
// tenantPurgeMarker, and drops them with secure_delete off, as retention
// deletes a tenant's expired history: their pages go to the freelist with
// the rows in them. It returns the number of free pages.
func freeMarkerPages(t *testing.T, s *Store, pages int) int {
	t.Helper()
	for _, statement := range []string{
		`CREATE TABLE expired_history(content TEXT)`,
		// Each row, 150 copies of the marker, fills most of a page.
		`WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<` + fmt.Sprint(pages) + `) INSERT INTO expired_history SELECT replace(hex(zeroblob(150)),'00','` + tenantPurgeMarker + `') FROM seq`,
		`DROP TABLE expired_history`,
	} {
		if _, err := s.DB.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	free := countRows(t, s.DB, `PRAGMA freelist_count`)
	if free < pages {
		t.Fatalf("the freelist has %d pages after dropping %d pages of rows", free, pages)
	}
	return free
}

// tenantContent renders every row of the tenant in the tables that hold
// tenant data, apart from the search indexes, which index the same rows.
func tenantContent(t *testing.T, s *Store, tenant string) string {
	t.Helper()
	indexes := map[string]bool{}
	for _, step := range tenantPurgeSteps {
		indexes[step.table] = step.trigger != ""
	}
	var content strings.Builder
	render := func(table string) error {
		rows, err := s.DB.Query(`SELECT * FROM `+table+` WHERE rowid IN (`+tenantPurgeOracle[table]+`) ORDER BY rowid`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		columns, err := rows.Columns()
		if err != nil {
			return err
		}
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				return err
			}
			fmt.Fprintf(&content, "%s %v\n", table, values)
		}
		return rows.Err()
	}
	for _, table := range tenantDataTables() {
		if indexes[table] {
			continue
		}
		if err := render(table); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
	}
	return content.String()
}

// assertLiveDataKept checks that the database passes its integrity check and
// that the default tenant's rows are what they were.
func assertLiveDataKept(t *testing.T, s *Store, before string) {
	t.Helper()
	var integrity string
	if err := s.DB.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity check = %q, %v", integrity, err)
	}
	if after := tenantContent(t, s, DefaultTenantID); after != before {
		t.Fatalf("the rows of the tenant that was not deleted changed:\nbefore %s\nafter %s", before, after)
	}
	if before == "" {
		t.Fatal("the tenant that was not deleted has no rows; the test shows nothing")
	}
}

// assertNoFreePagesTable checks that the scratch table of the overwrite is
// gone.
func assertNoFreePagesTable(t *testing.T, s *Store) {
	t.Helper()
	if tables := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE name=?`, freePagesTable); tables != 0 {
		t.Fatalf("the scratch table %s is left", freePagesTable)
	}
}

// freePagesLog records, through tenantPurgeOptions.afterFreePages, the steps
// of the overwrite of free pages.
type freePagesLog []freePagesStep

func (l *freePagesLog) afterFreePages(_ context.Context, step freePagesStep) error {
	*l = append(*l, step)
	return nil
}

// In a database without incremental auto-vacuum, which keeps free pages in
// the file, a unit's deletion overwrites every free page before the
// tombstone: those freed by retention before the deletion, which hold the
// unit's rows, and those that a retention merge freed between two passes,
// which hold its search terms. With incremental auto-vacuum the free pages
// go back to the file system as before, and the purge never overwrites
// them. The rows of the other unit stay as they were.
func TestPurgeLeavesNoFreePageCopies(t *testing.T) {
	for _, mode := range []string{"NONE", "INCREMENTAL"} {
		for _, route := range []string{"before the deletion", "between passes"} {
			t.Run(mode+"/"+route, func(t *testing.T) {
				ctx := context.Background()
				f := newTenantPurgeFixture(t)
				useAutoVacuum(t, f.store, mode)
				seedTenantPurgeMarker(t, f)
				kept := tenantContent(t, f.store, DefaultTenantID)
				if route == "before the deletion" {
					// Retention removes unit B's expired scan hosts.
					if _, err := f.store.DB.Exec(`DELETE FROM scan_hosts WHERE scan_id=?`, f.scanB); err != nil {
						t.Fatal(err)
					}
					if _, err := f.store.maintainSearchIndexes(ctx); err != nil {
						t.Fatal(err)
					}
					requestSecondTenantDeletion(t, f)
				} else {
					requestSecondTenantDeletion(t, f)
					// The first pass erases the rows and runs out of its budget.
					if _, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, maintenanceBudget: spentBudget}); err != nil {
						t.Fatal(err)
					}
					// A retention pass that pruned a scan of another unit.
					if _, err := f.store.maintainSearchIndexes(ctx); err != nil {
						t.Fatal(err)
					}
				}
				var steps freePagesLog
				results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, afterFreePages: steps.afterFreePages})
				if err != nil || len(results) != 1 || !results[0].Complete {
					t.Fatalf("purge = %+v, %v; want the tombstone", results, err)
				}
				switch {
				case mode == "NONE" && (len(steps) < 3 || steps[len(steps)-1] != freePagesFinished):
					t.Fatalf("the overwrite of free pages ran %v", steps)
				case mode == "INCREMENTAL" && len(steps) != 0:
					t.Fatalf("a database with incremental auto-vacuum overwrote its free pages: %v", steps)
				}
				assertNothingOfTheMarkerLeft(t, f.store)
				assertNoFreePageCopies(t, f.store)
				assertNoFreePagesTable(t, f.store)
				assertLiveDataKept(t, f.store, kept)
			})
		}
	}
}

// The overwrite of free pages is bounded per step and resumes where it
// stopped. A pass whose budget runs out while it allocates the free pages
// leaves the unit deleting in the free-pages phase, and the free pages
// still hold the rows. After a restart the next pass continues the
// allocation in the same scratch table and starts to return the pages; the
// pass after that only returns the rest, and then the tombstone follows.
func TestPurgeResumesTheOverwriteOfFreePages(t *testing.T) {
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	useAutoVacuum(t, f.store, "NONE")
	seedTenantPurgeMarker(t, f)
	freeMarkerPages(t, f.store, 2*freePagesStepPages+200)
	kept := tenantContent(t, f.store, DefaultTenantID)
	requestSecondTenantDeletion(t, f)

	// pass runs a purge pass whose budget runs out after the step given.
	pass := func(s *Store, stopAfter freePagesStep) (TenantPurgeResult, freePagesLog) {
		t.Helper()
		var steps freePagesLog
		var spend context.CancelFunc
		results, err := s.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, maintenanceBudget: func(ctx context.Context) (context.Context, context.CancelFunc) {
			budget, cancel := context.WithCancel(ctx)
			spend = cancel
			return budget, cancel
		}, afterFreePages: func(ctx context.Context, step freePagesStep) error {
			_ = steps.afterFreePages(ctx, step)
			if step == stopAfter {
				spend()
				return ctx.Err()
			}
			return nil
		}})
		if err != nil || len(results) != 1 {
			t.Fatalf("purge = %+v, %v", results, err)
		}
		return results[0], steps
	}

	result, steps := pass(f.store, freePagesAllocated)
	if result.Complete || !result.MaintenancePending || result.Phase != tenantPurgePhaseFreePages || !slices.Equal(steps, freePagesLog{freePagesAllocated}) {
		t.Fatalf("pass past its budget = %+v with steps %v; want it pending in the free-pages phase", result, steps)
	}
	assertTenantPurgePhase(t, f.store, tenantPurgePhaseFreePages)
	if rows := countRows(t, f.store.DB, `SELECT COUNT(*) FROM `+freePagesTable); rows != 1 {
		t.Fatalf("the scratch table has %d rows after one step", rows)
	}
	if left := countRows(t, f.store.DB, `PRAGMA freelist_count`); left == 0 {
		t.Fatal("no free page is left after one step; the test shows nothing")
	}
	if _, err := f.store.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if copies, _ := freePageCopies(t, f.store.Path, []byte(tenantPurgeMarker)); copies == 0 {
		t.Fatal("no free page holds the rows while the overwrite is unfinished; the test shows nothing")
	}

	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(f.store.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	// The pass continues the allocation, finds the freelist empty once, and
	// returns the pages of one row.
	result, steps = pass(restarted, freePagesReleased)
	allocated := len(steps) - 2
	want := append(slices.Repeat(freePagesLog{freePagesAllocated}, allocated), freePagesTaken, freePagesReleased)
	if result.Complete || !result.MaintenancePending || result.Phase != tenantPurgePhaseFreePages || allocated < 2 || !slices.Equal(steps, want) {
		t.Fatalf("pass after the restart = %+v with steps %v", result, steps)
	}
	if rows := countRows(t, restarted.DB, `SELECT COUNT(*) FROM `+freePagesTable); rows != allocated+1 {
		t.Fatalf("the scratch table has %d rows after one of %d was returned, want the rest and the marker", rows, allocated+1)
	}

	var rest freePagesLog
	results, err := restarted.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, afterFreePages: rest.afterFreePages})
	if err != nil || len(results) != 1 || !results[0].Complete {
		t.Fatalf("the last pass = %+v, %v; want the tombstone", results, err)
	}
	if want := append(slices.Repeat(freePagesLog{freePagesReleased}, allocated), freePagesFinished); !slices.Equal(rest, want) {
		t.Fatalf("the last pass ran %v, want %v: the rest returned without allocating again", rest, want)
	}
	assertNothingOfTheMarkerLeft(t, restarted)
	assertNoFreePageCopies(t, restarted)
	assertNoFreePagesTable(t, restarted)
	assertLiveDataKept(t, restarted, kept)
}

// The overwrite stops when the unit leaves the deleting state or the pass is
// cancelled, and reports a failed database; a pass that resumes at the
// free-pages phase in a database with incremental auto-vacuum goes to the
// checkpoint, unless a scratch table is left, which it then finishes.
func TestFreePagesOverwriteStops(t *testing.T) {
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	useAutoVacuum(t, f.store, "NONE")
	freeMarkerPages(t, f.store, 50)
	requestSecondTenantDeletion(t, f)
	results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, afterFreePages: func(ctx context.Context, _ freePagesStep) error {
		_, err := f.store.DB.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, TenantStateDisabled, secondTenantID)
		return err
	}})
	if !errors.Is(err, ErrConflict) || len(results) != 1 || results[0].Complete || results[0].Phase != tenantPurgePhaseFreePages {
		t.Fatalf("overwrite for a unit that left the deleting state = %+v, %v", results, err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	defer cancel()
	if _, err := f.store.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, TenantStateDeleting, secondTenantID); err != nil {
		t.Fatal(err)
	}
	results, err = f.store.System().purgeDeletingTenants(cancelled, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, afterFreePages: func(context.Context, freePagesStep) error {
		cancel()
		return nil
	}})
	if !errors.Is(err, context.Canceled) || len(results) != 1 || results[0].Complete || results[0].MaintenancePending || results[0].Phase != tenantPurgePhaseFreePages {
		t.Fatalf("cancelled overwrite = %+v, %v", results, err)
	}
	assertTenantPurgePhase(t, f.store, tenantPurgePhaseFreePages)

	// The operator converts the database while the overwrite is unfinished:
	// the next pass finishes it before the incremental vacuum.
	useAutoVacuum(t, f.store, "INCREMENTAL")
	var steps freePagesLog
	results, err = f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, afterFreePages: steps.afterFreePages})
	if err != nil || len(results) != 1 || !results[0].Complete || len(steps) == 0 || steps[len(steps)-1] != freePagesFinished {
		t.Fatalf("pass after the conversion = %+v, %v with steps %v", results, err, steps)
	}
	assertNoFreePagesTable(t, f.store)

	// Without a scratch table, such a database skips the phase.
	f = newTenantPurgeFixture(t)
	requestSecondTenantDeletion(t, f)
	if _, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, maintenanceBudget: spentBudget}); err != nil {
		t.Fatal(err)
	}
	if err := setTenantPurgePhase(ctx, f.store.DB, secondTenantID, tenantPurgePhaseFreePages); err != nil {
		t.Fatal(err)
	}
	steps = nil
	results, err = f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize, afterFreePages: steps.afterFreePages})
	if err != nil || len(results) != 1 || !results[0].Complete || len(steps) != 0 {
		t.Fatalf("pass from the free-pages phase with incremental auto-vacuum = %+v, %v with steps %v", results, err, steps)
	}

	s := openTestStore(t)
	_ = s.Close()
	phase := tenantPurgePhaseFreePages
	record := func(context.Context, contextExecer, string) error { return nil }
	if err := overwriteFreePages(ctx, s.DB, record, tenantPurgeOptions{}, &phase); err == nil || !strings.Contains(err.Error(), "auto-vacuum") {
		t.Fatalf("overwrite in a closed database = %v", err)
	}
	if _, err := overwriteFreePagesStep(ctx, s.DB, record); err == nil {
		t.Fatal("a step of the overwrite in a closed database succeeded")
	}
}

// A step of the overwrite that fails reports the failure and commits
// nothing, so the freelist is as it was and the next pass repeats the step.
// Recording the phase that the overwrite enters fails the phase too.
func TestFreePagesOverwriteStepReportsFailures(t *testing.T) {
	const refuse = ` BEGIN SELECT RAISE(ABORT,'refused'); END`
	table := `CREATE TABLE ` + freePagesTable + `(zeros BLOB)`
	for _, tc := range []struct {
		name  string
		setup []string
		// free makes the freelist hold pages, rather than none.
		free bool
		// failPhase is the phase whose recording fails, and cancel cancels
		// the step once it has recorded its phase.
		failPhase string
		cancel    bool
	}{
		{name: "read the freelist", cancel: true},
		{name: "read the scratch table", setup: []string{`CREATE TABLE ` + freePagesTable + `(zeros BLOB PRIMARY KEY) WITHOUT ROWID`}},
		{name: "return a row", setup: []string{table, `INSERT INTO ` + freePagesTable + `(rowid,zeros) VALUES(0,NULL),(1,x'00')`, `CREATE TRIGGER refuse BEFORE DELETE ON ` + freePagesTable + refuse}},
		{name: "drop the table", setup: []string{`CREATE TABLE ` + freePagesTable + `(id INTEGER PRIMARY KEY,zeros BLOB)`, `INSERT INTO ` + freePagesTable + `(id,zeros) VALUES(0,NULL)`, `CREATE TABLE free_pages_child(parent INTEGER REFERENCES ` + freePagesTable + `(id))`, `INSERT INTO free_pages_child VALUES(0)`}},
		{name: "record the checkpoint phase", failPhase: tenantPurgePhaseCheckpoint},
		{name: "record the empty freelist", setup: []string{table, `CREATE TRIGGER refuse BEFORE INSERT ON ` + freePagesTable + refuse}},
		{name: "create the table", setup: []string{`CREATE VIEW ` + freePagesTable + ` AS SELECT 1 AS zeros`}, free: true},
		{name: "allocate free pages", setup: []string{table, `CREATE TRIGGER refuse BEFORE INSERT ON ` + freePagesTable + refuse}, free: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			for _, statement := range tc.setup {
				if _, err := s.DB.Exec(statement); err != nil {
					t.Fatalf("%s: %v", statement, err)
				}
			}
			if tc.free {
				freeMarkerPages(t, s, 20)
			} else if _, err := s.DB.Exec(`PRAGMA incremental_vacuum`); err != nil {
				t.Fatal(err)
			}
			free := countRows(t, s.DB, `PRAGMA freelist_count`)
			if (free > 0) != tc.free {
				t.Fatalf("the freelist has %d pages", free)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			record := func(_ context.Context, _ contextExecer, phase string) error {
				if tc.cancel {
					cancel()
				}
				if phase == tc.failPhase {
					return errors.New("recording refused")
				}
				return nil
			}
			if step, err := overwriteFreePagesStep(ctx, s.DB, record); err == nil {
				t.Fatalf("the step %s succeeded", step)
			}
			if after := countRows(t, s.DB, `PRAGMA freelist_count`); after != free {
				t.Fatalf("the failed step changed the freelist from %d to %d pages", free, after)
			}
		})
	}

	s := openTestStore(t)
	phase := tenantPurgePhaseVerify
	refused := func(context.Context, contextExecer, string) error { return errors.New("recording refused") }
	if err := overwriteFreePages(context.Background(), s.DB, refused, tenantPurgeOptions{}, &phase); err == nil || phase != tenantPurgePhaseVerify {
		t.Fatalf("overwrite whose phase could not be recorded = %v in phase %s", err, phase)
	}
}
