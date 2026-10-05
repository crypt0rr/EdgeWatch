package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestHistoryByNameUsesManagedJobIdentityAcrossRename(t *testing.T) {
	ctx := context.Background()
	database := storetest.FreshPath(t)
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	tenant := s.Tenant(store.DefaultTenantScope())
	oldJob := managedCLIJob("web")
	oldRecord, err := tenant.CreateJob(ctx, oldJob)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := saveHistoryIdentityScan(ctx, s, oldRecord, oldJob.Name, "old-scan", now); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := saveHistoryIdentityEvent(ctx, s, oldRecord.ID, "web", "old-event", now); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if _, _, err := tenant.UpdateJob(ctx, oldRecord.ID, oldRecord.Revision, managedCLIJob("web-old"), oldRecord.Enabled, oldRecord.Archived, true); err != nil {
		s.Close()
		t.Fatal(err)
	}
	newJob := managedCLIJob("web")
	newRecord, err := tenant.CreateJob(ctx, newJob)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := saveHistoryIdentityScan(ctx, s, newRecord, newJob.Name, "new-scan", now.Add(time.Minute)); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := saveHistoryIdentityEvent(ctx, s, newRecord.ID, "web", "new-event", now.Add(time.Minute)); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(filepath.Dir(database), "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		wantScanID  string
		wantEventID string
	}{
		{name: "web", wantScanID: "new-scan", wantEventID: "new-event"},
		{name: "web-old", wantScanID: "old-scan", wantEventID: "old-event"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, err := captureCLIOutput(t, func() error {
				return run([]string{"history", "--config", configPath, "--job", tc.name, "--output", "json"})
			})
			if err != nil {
				t.Fatalf("history --job %s: %v", tc.name, err)
			}
			var history struct {
				Scans  []model.Scan  `json:"scans"`
				Events []model.Event `json:"events"`
			}
			if err := json.Unmarshal([]byte(stdout), &history); err != nil {
				t.Fatalf("decode history output: %v", err)
			}
			if len(history.Scans) != 1 || history.Scans[0].ID != tc.wantScanID {
				t.Fatalf("history scans = %v, want only %s", scanIDs(history.Scans), tc.wantScanID)
			}
			if len(history.Events) != 1 || history.Events[0].Message != tc.wantEventID {
				t.Fatalf("history events = %v, want only %s", eventMessages(history.Events), tc.wantEventID)
			}
		})
	}

	// An unpersisted YAML job has no managed ID; name-based filtering remains
	// available for its legacy history rows.
	legacyStore, err := store.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveLegacyHistoryIdentityRows(ctx, legacyStore, "legacy-yaml", now); err != nil {
		legacyStore.Close()
		t.Fatal(err)
	}
	if err := legacyStore.Close(); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := captureCLIOutput(t, func() error {
		return run([]string{"history", "--config", configPath, "--job", "legacy-yaml", "--output", "json"})
	})
	if err != nil {
		t.Fatalf("legacy YAML history: %v", err)
	}
	var legacy struct {
		Scans  []model.Scan  `json:"scans"`
		Events []model.Event `json:"events"`
	}
	if err := json.Unmarshal([]byte(stdout), &legacy); err != nil {
		t.Fatalf("decode legacy history output: %v", err)
	}
	if len(legacy.Scans) != 1 || legacy.Scans[0].ID != "legacy-scan" || len(legacy.Events) != 1 || legacy.Events[0].Message != "legacy-event" {
		t.Fatalf("legacy YAML history = scans %v events %v, want legacy rows", scanIDs(legacy.Scans), eventMessages(legacy.Events))
	}
}

func saveHistoryIdentityScan(ctx context.Context, s *store.Store, record store.JobRecord, jobName, id string, finished time.Time) error {
	return s.System().SaveScan(ctx, model.Scan{
		ID: id, JobID: record.ID, JobRevision: record.Revision, Job: jobName,
		StartedAt: finished, FinishedAt: finished, Status: "success", ConfigHash: "test-scope",
		Snapshot: model.Snapshot{Units: []model.Unit{{Target: "192.0.2.10", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open"}}}}},
	})
}

func saveHistoryIdentityEvent(ctx context.Context, s *store.Store, jobID, jobName, message string, createdAt time.Time) error {
	event := model.Event{Type: "test", JobID: jobID, Job: jobName, Message: message, CreatedAt: createdAt}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO events(type,job,job_id,payload_json,created_at,tenant_id) VALUES(?,?,?,?,?,?)`, event.Type, event.Job, event.JobID, payload, createdAt.Format(time.RFC3339Nano), store.DefaultTenantID)
	return err
}

func saveLegacyHistoryIdentityRows(ctx context.Context, s *store.Store, jobName string, createdAt time.Time) error {
	scan := model.Scan{ID: "legacy-scan", Job: jobName, StartedAt: createdAt, FinishedAt: createdAt, Status: "success", ConfigHash: "legacy", Snapshot: model.Snapshot{}}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scans(id,job,started_at,finished_at,status,config_hash,snapshot_json,tenant_id) VALUES(?,?,?,?,?,?,?,?)`, scan.ID, scan.Job, createdAt.Format(time.RFC3339Nano), createdAt.Format(time.RFC3339Nano), scan.Status, scan.ConfigHash, `{}`, store.DefaultTenantID); err != nil {
		return err
	}
	event := model.Event{Type: "test", Job: jobName, Message: "legacy-event", CreatedAt: createdAt}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO events(type,job,job_id,payload_json,created_at,tenant_id) VALUES(?,?,?,?,?,?)`, event.Type, event.Job, "", payload, createdAt.Format(time.RFC3339Nano), store.DefaultTenantID)
	return err
}

func scanIDs(scans []model.Scan) []string {
	ids := make([]string, len(scans))
	for i, scan := range scans {
		ids[i] = scan.ID
	}
	return ids
}

func eventMessages(events []model.Event) []string {
	messages := make([]string, len(events))
	for i, event := range events {
		messages[i] = event.Message
	}
	return messages
}
