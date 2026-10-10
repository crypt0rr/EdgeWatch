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

// A job pinned to a profile revision saved before NSE arguments were limited
// to the script's own keeps scanning, and the daemon names the arguments it
// still passes.
func TestScanOfARevisionWithOtherNSEArgumentsWarns(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	var logs bytes.Buffer
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = schedulerFake{}
	for name, args := range map[string]map[string]string{
		"legacy": {"newtargets": "1", "banner.timeout": "5s"},
		"own":    {"banner.timeout": "5s"},
	} {
		record, err := defaultTenant(s).CreateJob(ctx, config.NormalizeJob(config.Job{Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
			TCP: &config.Protocol{Ports: "22", Mode: "connect", NSEProfile: "banner", NSEArgs: args}, Timeout: config.Duration(time.Minute)}))
		if err != nil {
			t.Fatal(err)
		}
		if scan, _, err := a.RunJobRecord(ctx, record); err != nil || scan.Status != "success" {
			t.Fatalf("%s scan = %s, %v", name, scan.Status, err)
		}
	}
	output := logs.String()
	if strings.Count(output, "passes NSE arguments that are not its script's own") != 1 || !strings.Contains(output, "nse_arguments=[newtargets]") {
		t.Fatalf("log = %s, want one warning naming newtargets", output)
	}
}
