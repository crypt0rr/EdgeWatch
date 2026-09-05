package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestBaselineHostExplorerReturnsDetailedAndFilteredHosts(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(a, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	job := config.NormalizeJob(config.Job{Name: "host-test", Schedule: "0 * * * *", Targets: []string{"198.51.100.0/30"}, TCP: &config.Protocol{Ports: "22,443", Mode: "syn"}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{ID: "host-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.1", AddressFamily: "IPv4", SourceTargets: []string{"198.51.100.0/30"}, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "22,443", ScannedPortCount: 2, Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}, {Address: "2001:db8::1", AddressFamily: "IPv6", SourceTargets: []string{"router.example"}, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "udp", ScannedPorts: "53", ScannedPortCount: 1}}}}}}
	if err := db.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApproveRuntime(ctx, record.ID, record.Job.Name, scan); err != nil {
		t.Fatal(err)
	}
	recordRequest := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/baseline/hosts?protocol=tcp&has_open_ports=true", nil)
	recorder := httptest.NewRecorder()
	server.jobBaselineHosts(recorder, recordRequest, record.ID)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		DataQuality string        `json:"data_quality"`
		Hosts       []hostSummary `json:"hosts"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.DataQuality != "detailed" || len(response.Hosts) != 1 || response.Hosts[0].Address != "198.51.100.1" {
		t.Fatalf("unexpected host response: %#v", response)
	}

	detailRequest := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/baseline/hosts/198.51.100.1", nil)
	detailRecorder := httptest.NewRecorder()
	server.jobBaselineHost(detailRecorder, detailRequest, record.ID, "198.51.100.1")
	if detailRecorder.Code != http.StatusOK || !bytes.Contains(detailRecorder.Body.Bytes(), []byte(`"open"`)) {
		t.Fatalf("unexpected detail response %d: %s", detailRecorder.Code, detailRecorder.Body.String())
	}
}

func TestAllHostsReturnsLatestSuccessfulResultPerAddress(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(a, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	job := config.NormalizeJob(config.Job{Name: "global-hosts", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.0/30"}, TCP: &config.Protocol{Ports: "22,443", Mode: "syn"}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := model.Scan{ID: "old-host-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now.Add(-time.Minute), FinishedAt: now.Add(-time.Minute), Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.1", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "22", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 22, State: "open"}}}}}}}}
	latest := model.Scan{ID: "latest-host-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.1", SourceTargets: []string{"router.example"}, Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "443", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}, {Address: "2001:db8::1", Protocols: []model.ProtocolObservation{{Protocol: "udp", ScannedPorts: "53", ScannedPortCount: 1}}}}}}
	for _, scan := range []model.Scan{old, latest} {
		if err := db.SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts?q=198.51.100.1&protocol=tcp", nil)
	recorder := httptest.NewRecorder()
	server.listHosts(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Hosts []allHostSummary `json:"hosts"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Hosts) != 1 || response.Hosts[0].ScanID != latest.ID || response.Hosts[0].OpenPorts != 1 || response.Hosts[0].SourceTargets[0] != "router.example" {
		t.Fatalf("unexpected global host response: %#v", response.Hosts)
	}
}
