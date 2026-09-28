package app

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// Every live update of a job's work names the job's business unit, so the
// web console sends it to that unit's streams only: the events of a scan
// and a silence alert. Tenant B's events name B and tenant A's name A,
// although both jobs have the same name. No job event goes out without a
// unit.
func TestLiveUpdatesNameTheJobsBusinessUnit(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	var mu sync.Mutex
	var live []model.Event
	f.app.SetEventHandler(func(event model.Event) {
		mu.Lock()
		defer mu.Unlock()
		live = append(live, event)
	})
	for _, record := range []store.JobRecord{f.jobB, f.jobA} {
		if scan, _, err := f.app.RunJobRecord(ctx, record); err != nil || scan.Status != "success" {
			t.Fatalf("scan of %s's job = %+v, %v", record.TenantID, scan, err)
		}
	}
	// Both jobs are silent a day after their scans.
	f.app.checkJobSilence(ctx, time.Now().Add(24*time.Hour))

	mu.Lock()
	defer mu.Unlock()
	types := map[string][]string{}
	for _, event := range live {
		want := map[string]string{f.jobA.ID: store.DefaultTenantID, f.jobB.ID: secondTenantID}[event.JobID]
		if want == "" || event.TenantID != want {
			t.Errorf("live update %s of job %q names unit %q, want %q", event.Type, event.JobID, event.TenantID, want)
		}
		types[event.TenantID] = append(types[event.TenantID], event.Type)
	}
	for _, tenant := range []string{store.DefaultTenantID, secondTenantID} {
		for _, eventType := range []string{"scan.started", "baseline-complete", "scan.completed", "job-silent"} {
			if !slices.Contains(types[tenant], eventType) {
				t.Errorf("unit %s's live updates = %v, want %s", tenant, types[tenant], eventType)
			}
		}
	}
}

// Disabling a business unit, and requesting its deletion, tells the unit
// paused handler which unit was paused once the store has committed it, so
// the web console can end the unit's live-update streams. A refused request
// tells it nothing, and the application works without a handler.
func TestPausingAUnitTellsTheUnitPausedHandler(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	var mu sync.Mutex
	var paused []string
	f.app.SetUnitPausedHandler(func(tenantID string) {
		mu.Lock()
		defer mu.Unlock()
		// The pause is committed before the handler hears of it.
		paused = append(paused, tenantID+" "+tenantRecord(t, f.db, tenantID).State)
	})
	audit := store.AuditEntry{ActorKind: store.AuditActorHost}
	if _, err := f.app.RequestUnitDeletion(ctx, secondTenantID, "Second", audit); err == nil {
		t.Fatal("an active unit was deleted")
	}
	disabled, err := f.app.DisableUnit(ctx, secondTenantID, tenantRecord(t, f.db, secondTenantID).Revision, audit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.RequestUnitDeletion(ctx, secondTenantID, disabled.Name, audit); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := slices.Clone(paused)
	mu.Unlock()
	if want := []string{secondTenantID + " " + store.TenantStateDisabled, secondTenantID + " " + store.TenantStateDeleting}; !slices.Equal(got, want) {
		t.Fatalf("paused units = %q, want %q", got, want)
	}

	f.app.SetUnitPausedHandler(nil)
	f.app.pauseUnit(secondTenantID)
}
