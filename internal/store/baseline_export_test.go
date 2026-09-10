package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestExportBaselinesRoundTripsManagedAndLegacyEntries(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	job := config.NormalizeJob(config.Job{
		Name: "managed-export", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.20"},
		TCP: &config.Protocol{Ports: "22,443", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced",
	})
	record, err := s.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	scan := model.Scan{ID: "export-source", JobID: record.ID, JobRevision: record.Revision, Job: job.Name, StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: job.SecurityHash(), Snapshot: model.Snapshot{Units: []model.Unit{{Target: "198.51.100.20", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: "https"}}}}}}
	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &scan.Snapshot
		state.BaselineScanID = scan.ID
		state.BaselineConfigHash = scan.ConfigHash
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	legacySnapshot := model.Snapshot{Units: []model.Unit{{Target: "198.51.100.21", Protocol: "udp", Ports: []model.PortState{{Port: 53, State: "open"}}}}}
	legacyState, err := json.Marshal(model.JobState{Baseline: &legacySnapshot, BaselineScanID: "missing-legacy-source", BaselineConfigHash: "legacy-hash"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_states(job,state_json,updated_at) VALUES(?,?,?)`, "legacy-export", legacyState, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	export, err := s.ExportBaselines(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if export.FormatVersion != BaselineExportVersion || len(export.Jobs) != 2 {
		t.Fatalf("export metadata = %#v", export)
	}
	if export.Jobs[0].Name != "legacy-export" || !export.Jobs[0].Legacy || export.Jobs[1].Name != "managed-export" || export.Jobs[1].Legacy {
		t.Fatalf("export ordering/identity = %#v", export.Jobs)
	}
	if export.Jobs[1].Baseline == nil || len(export.Jobs[1].Baseline.Units) != 1 || export.Jobs[1].SourceScan == nil || export.Jobs[1].SourceScan.ID != scan.ID {
		t.Fatalf("managed baseline export = %#v", export.Jobs[1])
	}
	encoded, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	var decoded BaselineExport
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Jobs) != len(export.Jobs) || decoded.Jobs[1].Baseline.Units[0].Ports[0].Port != 443 {
		t.Fatalf("round-trip export = %#v", decoded)
	}

	one, err := s.ExportBaselines(ctx, record.ID)
	if err != nil || len(one.Jobs) != 1 || one.Jobs[0].Name != job.Name {
		t.Fatalf("per-ID export = %#v, %v", one, err)
	}
	if _, err := s.ExportBaselines(ctx, "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown job error = %v", err)
	}
}

func TestExportBaselinesIncludesJobsWithoutReadyBaseline(t *testing.T) {
	s := openTestStore(t)
	job := config.NormalizeJob(config.Job{
		Name: "not-ready-export", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.22"},
		UDP: &config.Protocol{Ports: "53"}, Timeout: config.Duration(time.Minute), Timing: "balanced",
	})
	if _, err := s.CreateJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	export, err := s.ExportBaselines(context.Background(), job.Name)
	if err != nil || len(export.Jobs) != 1 {
		t.Fatalf("not-ready export = %#v, %v", export, err)
	}
	if export.Jobs[0].Status != "not_ready" || export.Jobs[0].Baseline != nil {
		t.Fatalf("not-ready entry = %#v", export.Jobs[0])
	}
}
