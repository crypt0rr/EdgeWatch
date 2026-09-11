package store

import (
	"bytes"
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
	legacyCollision, err := json.Marshal(model.JobState{Baseline: &legacySnapshot, BaselineScanID: "legacy-collision-source", BaselineConfigHash: "legacy-collision-hash"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_states(job,state_json,updated_at) VALUES(?,?,?)`, job.Name, legacyCollision, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	export, err := s.ExportBaselines(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if export.FormatVersion != BaselineExportVersion || len(export.Jobs) != 3 {
		t.Fatalf("export metadata = %#v", export)
	}
	var managedEntry, legacyEntry *BaselineExportEntry
	for i := range export.Jobs {
		entry := &export.Jobs[i]
		if entry.Name == job.Name && entry.Legacy {
			legacyEntry = entry
		}
		if entry.Name == job.Name && !entry.Legacy {
			managedEntry = entry
		}
	}
	if managedEntry == nil || legacyEntry == nil || legacyEntry.ShadowedByJobID != record.ID {
		t.Fatalf("export collision identity = %#v", export.Jobs)
	}
	if managedEntry.Baseline == nil || len(managedEntry.Baseline.Units) != 1 || managedEntry.SourceScan == nil || managedEntry.SourceScan.ID != scan.ID {
		t.Fatalf("managed baseline export = %#v", managedEntry)
	}
	encoded, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	var decoded BaselineExport
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	var decodedManaged, decodedLegacy *BaselineExportEntry
	for i := range decoded.Jobs {
		entry := &decoded.Jobs[i]
		if entry.Name == job.Name && entry.Legacy {
			decodedLegacy = entry
		}
		if entry.Name == job.Name && !entry.Legacy {
			decodedManaged = entry
		}
	}
	if len(decoded.Jobs) != len(export.Jobs) || decodedManaged == nil || decodedLegacy == nil || decodedManaged.Baseline == nil || len(decodedManaged.Baseline.Units) != 1 || decodedManaged.Baseline.Units[0].Ports[0].Port != 443 || decodedLegacy.ShadowedByJobID != record.ID {
		t.Fatalf("round-trip export = %#v", decoded)
	}
	if bytes.Contains(encoded, []byte(`"exported_at"`)) || !bytes.Contains(encoded, []byte(`"shadowed_by_job_id":"`+record.ID+`"`)) {
		t.Fatalf("canonical export metadata = %s", encoded)
	}
	second, err := s.ExportBaselines(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	secondEncoded, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, secondEncoded) {
		t.Fatalf("equivalent exports differ:\n%s\n%s", encoded, secondEncoded)
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
