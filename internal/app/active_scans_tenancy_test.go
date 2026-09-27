package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// Each business unit lists and cancels only its own running scans. Another
// unit's scan is not found, exactly as an unknown one, and keeps running to
// its end; a scope without a unit reaches no scan at all.
func TestActiveScansAndCancelStayInTheirUnit(t *testing.T) {
	ctx := context.Background()
	sc := gatedScanner{started: make(chan string, 1), finish: make(chan struct{})}
	f := newTwoTenants(t, sc, lifecycleJob)
	runCtx, _ := f.app.BeginRun(ctx)
	defer f.app.StopRun()
	type outcome struct {
		scan model.Scan
		err  error
	}
	run := func(record store.JobRecord) (chan outcome, model.ActiveScan) {
		t.Helper()
		done := make(chan outcome, 1)
		go func() {
			scan, _, err := f.app.RunJobRecord(runCtx, record)
			done <- outcome{scan, err}
		}()
		select {
		case <-sc.started:
		case <-time.After(10 * time.Second):
			t.Fatalf("the scan of job %s did not start", record.ID)
		}
		scope := f.a
		if record.ID == f.jobB.ID {
			scope = f.b
		}
		active := f.app.ActiveScans(scope)
		if len(active) != 1 || active[0].JobID != record.ID {
			t.Fatalf("unit %s's active scans = %+v, want its own", scope.ID(), active)
		}
		return done, active[0]
	}
	for _, check := range []struct {
		record       store.JobRecord
		owner, other store.TenantScope
	}{
		{f.jobA, f.a, f.b},
		{f.jobB, f.b, f.a},
	} {
		done, scan := run(check.record)
		if other := f.app.ActiveScans(check.other); len(other) != 0 {
			t.Fatalf("unit %s lists unit %s's scan: %+v", check.other.ID(), check.owner.ID(), other)
		}
		if none := f.app.ActiveScans(store.TenantScope{}); len(none) != 0 {
			t.Fatalf("a scope without a unit lists %+v", none)
		}
		foreign := f.app.CancelScan(check.other, scan.ID)
		unknown := f.app.CancelScan(check.other, "scan-unknown")
		if !errors.Is(foreign, store.ErrNotFound) || foreign != unknown {
			t.Fatalf("unit %s cancelled unit %s's scan: %v; an unknown scan: %v", check.other.ID(), check.owner.ID(), foreign, unknown)
		}
		if err := f.app.CancelScan(store.TenantScope{}, scan.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a scope without a unit cancelled a scan: %v", err)
		}
		if active := f.app.ActiveScans(check.owner); len(active) != 1 || active[0].Phase == "cancelling" {
			t.Fatalf("unit %s's scan after the other's cancel = %+v", check.owner.ID(), active)
		}
		if check.owner == f.a {
			// The other unit's cancel did not stop the scan: it runs to its
			// end.
			sc.finish <- struct{}{}
			if got := <-done; got.err != nil || got.scan.Status != "success" {
				t.Fatalf("unit A's scan = %+v, want a success", got)
			}
			continue
		}
		if err := f.app.CancelScan(check.owner, scan.ID); err != nil {
			t.Fatalf("unit B's own cancel: %v", err)
		}
		if got := <-done; got.scan.Status != "canceled" || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("unit B's cancelled scan = %+v", got)
		}
	}
}
