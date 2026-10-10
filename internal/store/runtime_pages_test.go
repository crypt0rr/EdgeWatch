package store

import (
	"context"
	"reflect"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// pageRuntimeFixture writes a job whose runtime state holds the given JSON.
func pageRuntimeFixture(t *testing.T, s *Store, jobID, state string) {
	t.Helper()
	insertJobRows(t, s, jobID)
	if state == "" {
		return
	}
	if _, err := s.DB.Exec(`INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,'now')`, jobID, state); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeBaselinePageDecodesOnlyThePage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	insertJobRows(t, s, "baseline-page")
	baseline := model.Snapshot{
		Scopes:         []model.Scope{{Target: "198.51.100.0/29", Protocol: "tcp", Ports: "22"}},
		DNS:            map[string][]string{"edge.example": {"198.51.100.1"}},
		TargetFailures: []model.TargetCoverageFailure{{Target: "gone.example", Reason: "no addresses"}},
	}
	for _, address := range []string{"198.51.100.5", "198.51.100.1", "198.51.100.3", "198.51.100.2", "198.51.100.4"} {
		baseline.Units = append(baseline.Units, model.Unit{Target: address, Protocol: "tcp", Addresses: []string{address}, Ports: []model.PortState{{Port: 22, State: "open"}}})
		baseline.Hosts = append(baseline.Hosts, model.HostObservation{Address: address})
		baseline.HostStates = append(baseline.HostStates, model.HostState{Address: address, State: "up"})
	}
	stored := baseline
	stored.Units = append([]model.Unit(nil), baseline.Units...)
	if _, err := s.System().UpdateRuntime(ctx, "baseline-page", func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &stored
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	state, err := tenant.RuntimeState(ctx, "baseline-page")
	if err != nil {
		t.Fatal(err)
	}

	page, err := tenant.RuntimeBaselinePage(ctx, "baseline-page", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := RuntimeBaselinePage{Present: true, Total: 5, Snapshot: model.Snapshot{Units: state.Baseline.Units[1:3], Scopes: baseline.Scopes, DNS: baseline.DNS, TargetFailures: baseline.TargetFailures}}
	if !reflect.DeepEqual(page, want) {
		t.Fatalf("baseline page = %#v, want %#v", page, want)
	}
	page, err = tenant.RuntimeBaselinePage(ctx, "baseline-page", 2, 5)
	if err != nil || !page.Present || page.Total != 5 || page.Snapshot.Units == nil || len(page.Snapshot.Units) != 0 {
		t.Fatalf("baseline page past the units = %#v, %v", page, err)
	}

}

func TestRuntimeBaselinePageHandlesMissingAndLegacyBaselines(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	pageRuntimeFixture(t, s, "no-runtime", "")
	pageRuntimeFixture(t, s, "no-baseline", `{"candidate_count":1}`)
	pageRuntimeFixture(t, s, "null-baseline", `{"baseline":null}`)
	pageRuntimeFixture(t, s, "null-units", `{"baseline":{"units":null,"scopes":null}}`)
	pageRuntimeFixture(t, s, "null-unit", `{"baseline":{"units":[null,{"target":"198.51.100.9","protocol":"tcp"}]}}`)
	for _, jobID := range []string{"no-runtime", "no-baseline", "null-baseline", "unknown-job"} {
		page, err := tenant.RuntimeBaselinePage(ctx, jobID, 50, 0)
		if err != nil || !reflect.DeepEqual(page, RuntimeBaselinePage{}) {
			t.Errorf("%s: baseline page = %#v, %v; want no baseline", jobID, page, err)
		}
	}
	page, err := tenant.RuntimeBaselinePage(ctx, "null-units", 50, 0)
	if err != nil || !page.Present || page.Total != 0 || page.Snapshot.Units == nil || len(page.Snapshot.Units) != 0 || page.Snapshot.Scopes != nil {
		t.Errorf("null units = %#v, %v", page, err)
	}
	page, err = tenant.RuntimeBaselinePage(ctx, "null-unit", 50, 0)
	if want := []model.Unit{{}, {Target: "198.51.100.9", Protocol: "tcp"}}; err != nil || page.Total != 2 || !reflect.DeepEqual(page.Snapshot.Units, want) {
		t.Errorf("null unit = %#v, %v", page, err)
	}
}

func TestRuntimeBaselinePageReportsUnreadableBaselines(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	for jobID, state := range map[string]string{
		"invalid-json":    `{invalid`,
		"array-baseline":  `{"baseline":[]}`,
		"invalid-scopes":  `{"baseline":{"scopes":"all"}}`,
		"invalid-dns":     `{"baseline":{"dns":["edge.example"]}}`,
		"invalid-failure": `{"baseline":{"target_failures":{"target":"edge.example"}}}`,
		"invalid-unit":    `{"baseline":{"units":["198.51.100.1"]}}`,
	} {
		pageRuntimeFixture(t, s, jobID, state)
		if page, err := tenant.RuntimeBaselinePage(ctx, jobID, 50, 0); err == nil {
			t.Errorf("%s: baseline page = %#v, want an error", jobID, page)
		}
	}
}

func TestRuntimePendingChangesPageOrdersAndDecodesOnlyThePage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	insertJobRows(t, s, "pending-page")
	pending := map[string]model.Pending{
		"b": {Change: model.Change{Key: "b", Kind: "port", Target: "198.51.100.2", Protocol: "tcp", Port: 22}, Count: 2},
		"a": {Change: model.Change{Key: "a", Kind: "port", Target: "198.51.100.2", Protocol: "tcp", Port: 22}, Count: 1},
		"c": {Change: model.Change{Key: "c", Kind: "port", Target: "198.51.100.10", Protocol: "udp", Port: 53}, Count: 1},
		"d": {Change: model.Change{Key: "d", Kind: "host", Target: "198.51.100.1"}, Count: 3},
	}
	if _, err := s.System().UpdateRuntime(ctx, "pending-page", func(state *model.JobState) ([]model.Event, error) {
		state.Pending = pending
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	page, err := tenant.RuntimePendingChangesPage(ctx, "pending-page", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	// "198.51.100.10" sorts before "198.51.100.2" as text.
	want := Page[RuntimePendingChange]{Total: 4, Items: []RuntimePendingChange{
		{Key: "c", Change: pending["c"].Change, Count: 1},
		{Key: "a", Change: pending["a"].Change, Count: 1},
	}}
	if !reflect.DeepEqual(page, want) {
		t.Fatalf("pending page = %#v, want %#v", page, want)
	}

	pageRuntimeFixture(t, s, "no-pending", `{"pending":null}`)
	pageRuntimeFixture(t, s, "null-pending", `{"pending":{"x":null}}`)
	pageRuntimeFixture(t, s, "invalid-pending", `{"pending":{"x":{"change":"port"}}}`)
	pageRuntimeFixture(t, s, "invalid-json", `{invalid`)
	for _, jobID := range []string{"no-pending", "unknown-job"} {
		if page, err := tenant.RuntimePendingChangesPage(ctx, jobID, 50, 0); err != nil || page.Total != 0 || page.Items != nil {
			t.Errorf("%s: pending page = %#v, %v", jobID, page, err)
		}
	}
	if page, err := tenant.RuntimePendingChangesPage(ctx, "null-pending", 50, 0); err != nil || !reflect.DeepEqual(page.Items, []RuntimePendingChange{{Key: "x"}}) {
		t.Errorf("null pending change = %#v, %v", page, err)
	}
	for _, jobID := range []string{"invalid-pending", "invalid-json"} {
		if page, err := tenant.RuntimePendingChangesPage(ctx, jobID, 50, 0); err == nil {
			t.Errorf("%s: pending page = %#v, want an error", jobID, page)
		}
	}
}
