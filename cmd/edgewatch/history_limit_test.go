package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestHistoryLimitRejectsValuesOutsideStoreMaximum(t *testing.T) {
	database := storetest.FreshPath(t)
	ctx := context.Background()
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	job := managedCLIJob("many")
	record, err := s.Tenant(store.DefaultTenantScope()).CreateJob(ctx, job)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	for i := range 60 {
		finished := time.Now().UTC().Add(-time.Duration(i) * time.Minute)
		scan := model.Scan{
			ID: "history-" + strconv.Itoa(i), JobID: record.ID, JobRevision: record.Revision,
			Job: job.Name, StartedAt: finished, FinishedAt: finished, Status: "success",
			ConfigHash: job.SecurityHash(),
			Snapshot:   model.Snapshot{Units: []model.Unit{{Target: "192.0.2.10", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open"}}}}},
		}
		if err := s.System().SaveScan(ctx, scan); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(filepath.Dir(database), "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		limit int
		want  int
	}{
		{limit: 55, want: 55},
		{limit: 1000, want: 60},
	} {
		t.Run("limit_"+strconv.Itoa(tc.limit), func(t *testing.T) {
			stdout, _, err := captureCLIOutput(t, func() error {
				return run([]string{"history", "--config", configPath, "--job", job.Name, "--limit", strconv.Itoa(tc.limit), "--output", "json"})
			})
			if err != nil {
				t.Fatalf("history --limit %d: %v", tc.limit, err)
			}
			var history struct {
				Scans []model.Scan `json:"scans"`
			}
			if err := json.Unmarshal([]byte(stdout), &history); err != nil {
				t.Fatalf("decode history output: %v", err)
			}
			if len(history.Scans) != tc.want {
				t.Fatalf("history --limit %d returned %d scans, want %d", tc.limit, len(history.Scans), tc.want)
			}
		})
	}

	for _, limit := range []string{"0", "-1", "1001"} {
		t.Run("reject_"+limit, func(t *testing.T) {
			err := run([]string{"history", "--config", configPath, "--job", job.Name, "--limit", limit})
			if err == nil || !strings.Contains(err.Error(), "--limit must be between 1 and 1000") {
				t.Fatalf("history --limit %s error = %v, want a clear 1–1000 range error", limit, err)
			}
		})
	}
}
