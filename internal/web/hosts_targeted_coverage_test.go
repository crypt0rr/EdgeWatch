package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestExpectedHostAndPublishedHostCompatibilityBranches(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(a, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	job := config.NormalizeJob(config.Job{Name: "targeted-hosts", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.10"}, TCP: &config.Protocol{Ports: "22,443", Mode: "connect"}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{ID: "targeted-baseline", JobID: record.ID, JobRevision: record.Revision, Job: job.Name, StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: job.SecurityHash(), Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.10", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "22,443", ScannedPortCount: 2, Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}}}}
	if err := db.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApproveRuntime(ctx, record.ID, record.Job.Name, scan); err != nil {
		t.Fatal(err)
	}

	if host, found, err := server.expectedHostForScan(ctx, record.ID, "198.51.100.10", record.Job); err != nil || !found || len(host.Protocols) != 1 {
		t.Fatalf("indexed expected host = %#v, %t, %v", host, found, err)
	}
	if _, found, err := server.expectedHostForScan(ctx, record.ID, "198.51.100.99", record.Job); err != nil || found {
		t.Fatalf("unknown indexed host = %t, %v", found, err)
	}
	if _, err := server.latestPublishedHost(ctx, record.ID, "198.51.100.99"); err == nil {
		t.Fatal("unpublished host unexpectedly resolved")
	}

	// Mark the runtime baseline as an accepted overlay. The indexed projection
	// is preferred, then the JSON baseline is used as the legacy fallback when
	// the projection is absent.
	if _, err := db.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineModified = true
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if host, found, err := server.expectedHostForScan(ctx, record.ID, "198.51.100.10", record.Job); err != nil || !found || len(host.Protocols) != 1 {
		t.Fatalf("modified projected host = %#v, %t, %v", host, found, err)
	}
	if _, err := db.DB.ExecContext(ctx, `DELETE FROM baseline_hosts WHERE job_id=?`, record.ID); err != nil {
		t.Fatal(err)
	}
	if host, found, err := server.expectedHostForScan(ctx, record.ID, "198.51.100.10", record.Job); err != nil || !found || len(host.Protocols) != 1 {
		t.Fatalf("modified legacy host = %#v, %t, %v", host, found, err)
	}

	// With no overlay, remove the indexed source rows to exercise the pre-index
	// runtime snapshot fallback and its missing-address result.
	if _, err := db.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineModified = false
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `DELETE FROM scan_hosts WHERE scan_id=?`, scan.ID); err != nil {
		t.Fatal(err)
	}
	if host, found, err := server.expectedHostForScan(ctx, record.ID, "198.51.100.10", record.Job); err != nil || !found || len(host.Protocols) != 1 {
		t.Fatalf("legacy source host = %#v, %t, %v", host, found, err)
	}
	if _, found, err := server.expectedHostForScan(ctx, record.ID, "198.51.100.99", record.Job); err != nil || found {
		t.Fatalf("missing legacy source host = %t, %v", found, err)
	}

	// The wrappers use the same bounded lookup for indexed and legacy records.
	if host, summary, err := server.latestLegacyPublicHost(ctx, record.ID, "198.51.100.10"); err != nil || host.Host.Address != "198.51.100.10" || summary.ID != scan.ID {
		t.Fatalf("legacy fallback for unindexed source = %#v, %#v, %v", host, summary, err)
	}
	legacy := model.Scan{ID: "targeted-legacy", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now.Add(-time.Minute), FinishedAt: now.Add(-time.Minute), Status: "success", Snapshot: model.Snapshot{Units: []model.Unit{{Target: "198.51.100.10", Protocol: "tcp", Addresses: []string{"198.51.100.10"}, Ports: []model.PortState{{Port: 22, State: "open"}}}}}}
	if err := db.SaveScan(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if host, summary, err := server.latestLegacyPublicHost(ctx, record.ID, "198.51.100.10"); err != nil || host.Host.Address != "198.51.100.10" || summary.ID == "" {
		t.Fatalf("legacy published host = %#v, %#v, %v", host, summary, err)
	}
	if _, _, err := server.latestLegacyPublicHost(ctx, record.ID, "198.51.100.99"); err == nil {
		t.Fatal("missing legacy published host unexpectedly resolved")
	}

	// Known baseline hosts may request RDAP even when the enrichment client is
	// disabled; the endpoint remains a stable local response.
	server.RDAP = nil
	rdapResponse := httptest.NewRecorder()
	server.jobBaselineHostRDAP(rdapResponse, httptest.NewRequest(http.MethodGet, "/rdap", nil), record.ID, "198.51.100.10")
	if rdapResponse.Code != http.StatusOK || !strings.Contains(rdapResponse.Body.String(), `"status":"unavailable"`) {
		t.Fatalf("baseline RDAP fallback = %d: %s", rdapResponse.Code, rdapResponse.Body.String())
	}
}
