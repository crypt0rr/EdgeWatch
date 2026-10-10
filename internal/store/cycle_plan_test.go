package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/scanner"
)

// A cycle's units are stored once, as unit rows, and a cycle read decodes
// only the plan's job, so its cost does not grow with the cycle's scope.
func TestScanCyclePlansKeepTheirUnitsInTheUnitRows(t *testing.T) {
	t.Parallel()
	ctx, s, job, plan := cycleFixture(t)
	plan.Targets = []scanner.ResolvedTarget{{Name: "192.0.2.1", ConfiguredTarget: "192.0.2.1", Addresses: []string{"192.0.2.1"}}}
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if len(cycle.Plan.Units) != 1 {
		t.Fatalf("the created cycle lost its in-memory units: %+v", cycle.Plan)
	}
	var raw []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT plan_json FROM scan_cycles WHERE id=?`, cycle.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var stored map[string]json.RawMessage
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if string(stored["units"]) != "null" || len(stored["scopes"]) == 0 || len(stored["targets"]) == 0 {
		t.Fatalf("plan_json = %s, want its scopes and targets without units", raw)
	}
	read, err := defaultTenant(s).GetScanCycle(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if read.Plan.Job.Name != job.Job.Name || !read.Plan.CreatedAt.Equal(plan.CreatedAt) || read.Plan.TotalUnits != 1 || read.Plan.TotalProbes != 1 || read.Plan.Scopes != nil || read.Plan.Targets != nil {
		t.Fatalf("cycle read plan = %+v, want only the job and totals", read.Plan)
	}
	full, fragments, err := s.System().LoadScanCycleFragments(ctx, cycle.ID)
	if err != nil || len(fragments) != 0 || len(full.Scopes) != 1 || len(full.Targets) != 1 || full.Job.Name != job.Job.Name || full.TotalUnits != 1 || full.Units != nil {
		t.Fatalf("complete plan = %+v, %v", full, err)
	}

	// A cycle created before the units were left out keeps them in
	// plan_json; reading it skips them.
	legacy, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy), `"units":[{`) {
		t.Fatalf("legacy plan_json = %s", legacy)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET plan_json=? WHERE id=?`, legacy, cycle.ID); err != nil {
		t.Fatal(err)
	}
	full, _, err = s.System().LoadScanCycleFragments(ctx, cycle.ID)
	if err != nil || len(full.Scopes) != 1 || full.Units != nil {
		t.Fatalf("legacy complete plan = %+v, %v", full, err)
	}
	if read, err := defaultTenant(s).GetScanCycle(ctx, cycle.ID); err != nil || read.Plan.Job.Name != job.Job.Name {
		t.Fatalf("legacy cycle read = %+v, %v", read.Plan, err)
	}
}

func TestDecodeCyclePlanHeaderStopsAfterTheJob(t *testing.T) {
	t.Parallel()
	// Nothing after the job is parsed, so the members that grow with the
	// scope cost nothing to read.
	plan, err := decodeCyclePlanHeader([]byte(`{"created_at":"2026-01-02T03:04:05Z","job":{"name":"edge"},"scopes":[not json`))
	if err != nil || plan.Job.Name != "edge" || plan.CreatedAt.Year() != 2026 {
		t.Fatalf("header = %+v, %v", plan, err)
	}
	// Members in another order are still found.
	plan, err = decodeCyclePlanHeader([]byte(`{"scopes":[{"target":"192.0.2.1"}],"job":{"name":"edge"},"total_units":3}`))
	if err != nil || plan.Job.Name != "edge" || !plan.CreatedAt.IsZero() {
		t.Fatalf("reordered header = %+v, %v", plan, err)
	}
	for name, raw := range map[string]string{
		"not an object":  `[]`,
		"empty":          ``,
		"truncated":      `{"created_at":"2026-01-02T03:04:05Z",`,
		"a bad job":      `{"job":[1]}`,
		"a bad skip":     `{"scopes":[}`,
		"not a key type": `{1:2}`,
	} {
		if _, err := decodeCyclePlanHeader([]byte(raw)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// A plan whose job does not fit in the prefix of plan_json that a cycle read
// takes is read whole.
func TestScanCycleReadOfALongJobReadsTheWholePlan(t *testing.T) {
	t.Parallel()
	ctx, s, job, plan := cycleFixture(t)
	for len(plan.Job.Targets)*12 < 2*cyclePlanPrefix {
		plan.Job.Targets = append(plan.Job.Targets, "192.0.2.1")
	}
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	for name, read := range map[string]func() (ScanCycleRecord, error){
		"tenant": func() (ScanCycleRecord, error) { return defaultTenant(s).GetScanCycle(ctx, cycle.ID) },
		"system": func() (ScanCycleRecord, error) { return s.System().scanCycle(ctx, cycle.ID) },
	} {
		got, err := read()
		if err != nil || len(got.Plan.Job.Targets) != len(plan.Job.Targets) {
			t.Fatalf("%s read of a long job = %d targets, %v; want %d", name, len(got.Plan.Job.Targets), err, len(plan.Job.Targets))
		}
	}
	// A plan that is not JSON fails the read rather than looking empty.
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET plan_json=? WHERE id=?`, []byte(strings.Repeat("x", 2*cyclePlanPrefix)), cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).GetScanCycle(ctx, cycle.ID); err == nil {
		t.Fatal("a corrupt plan was read")
	}
}
