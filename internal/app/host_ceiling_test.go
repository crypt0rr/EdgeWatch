package app

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// Jobs whose targets expand beyond scanner.max_job_hosts are named at startup,
// in every unit, so that an upgraded deployment learns which scans now fail.
func TestJobsBeyondTheHostCeilingAreReported(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	job := func(name string, targets ...string) config.Job {
		return config.NormalizeJob(config.Job{Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: targets, MaxExpandedHosts: 1_000_000, TCP: &config.Protocol{Ports: "22", Mode: "connect"}})
	}
	wide, err := defaultTenant(s).CreateJob(ctx, job("wide", "10.0.0.0/15"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateJob(ctx, job("narrow", "10.0.0.0/24", "edge.example")); err != nil {
		t.Fatal(err)
	}
	archived, err := defaultTenant(s).CreateJob(ctx, job("archived", "10.2.0.0/15"))
	if err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SetJobArchived(ctx, archived.ID, true); err != nil {
		t.Fatal(err)
	}
	beyond, err := JobsBeyondHostCeiling(ctx, s, config.DefaultMaxJobHosts)
	if err != nil || len(beyond) != 1 || beyond[0].ID != wide.ID || beyond[0].Hosts != 131_072 {
		t.Fatalf("jobs beyond the ceiling = %+v, %v", beyond, err)
	}
	warning := HostCeilingWarning(beyond, config.DefaultMaxJobHosts)
	if !strings.Contains(warning, "the targets of 1 jobs expand to more than scanner.max_job_hosts=65536 hosts") || !strings.Contains(warning, "wide ("+wide.ID+", 131072 hosts)") {
		t.Fatalf("warning = %q", warning)
	}
	if HostCeilingWarning(nil, config.DefaultMaxJobHosts) != "" {
		t.Fatal("a warning without jobs")
	}

	var logs bytes.Buffer
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	if _, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "scanner.max_job_hosts allows one job") || !strings.Contains(logs.String(), "job_ids=["+wide.ID+"]") {
		t.Fatalf("startup log = %s", logs.String())
	}
	raised := 1_000_000
	cfg.Scanner.MaxJobHosts = &raised
	logs.Reset()
	reportJobsBeyondHostCeiling(ctx, s, cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if logs.Len() != 0 {
		t.Fatalf("a raised ceiling still warned: %s", logs.String())
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	reportJobsBeyondHostCeiling(canceled, s, cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if !strings.Contains(logs.String(), "the scan host ceiling check failed") {
		t.Fatalf("a failed check = %s", logs.String())
	}
}
