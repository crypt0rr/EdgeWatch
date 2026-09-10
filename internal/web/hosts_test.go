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

func TestAcceptedIncidentUsesMutatedRuntimeBaselineForHostListAndDetail(t *testing.T) {
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
	job := config.NormalizeJob(config.Job{Name: "accepted-host", Schedule: "0 * * * *", Targets: []string{"198.51.100.1"}, TCP: &config.Protocol{Ports: "22,443", Mode: "syn"}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{
		ID: "accepted-baseline-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: record.Job.SecurityHash(),
		Snapshot: model.Snapshot{
			Units:  []model.Unit{{Target: "198.51.100.1", Protocol: "tcp", Addresses: []string{"198.51.100.1"}, Ports: []model.PortState{{Port: 22, State: "open"}}}},
			Scopes: []model.Scope{{Target: "198.51.100.1", Protocol: "tcp", Ports: "22,443"}},
			Hosts:  []model.HostObservation{{Address: "198.51.100.1", SourceTargets: []string{"198.51.100.1"}, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "22,443", ScannedPortCount: 2, Ports: []model.PortObservation{{Port: 22, State: "open"}}}}}},
		},
	}
	if err := db.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApproveRuntime(ctx, record.ID, record.Job.Name, scan); err != nil {
		t.Fatal(err)
	}
	key := "port|198.51.100.1|tcp|443"
	if _, err := db.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "port", Target: "198.51.100.1", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, key, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}

	listRecorder := httptest.NewRecorder()
	server.jobBaselineHosts(listRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/baseline/hosts", nil), record.ID)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("baseline host list status %d: %s", listRecorder.Code, listRecorder.Body.String())
	}
	var listResponse struct {
		Hosts []hostSummary `json:"hosts"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &listResponse); err != nil {
		t.Fatal(err)
	}
	if len(listResponse.Hosts) != 1 || listResponse.Hosts[0].OpenPorts != 2 {
		t.Fatalf("accepted baseline list = %#v", listResponse.Hosts)
	}

	detailRecorder := httptest.NewRecorder()
	server.jobBaselineHost(detailRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/baseline/hosts/198.51.100.1", nil), record.ID, "198.51.100.1")
	if detailRecorder.Code != http.StatusOK {
		t.Fatalf("baseline host detail status %d: %s", detailRecorder.Code, detailRecorder.Body.String())
	}
	var detailResponse struct {
		Host model.HostObservation `json:"host"`
	}
	if err := json.Unmarshal(detailRecorder.Body.Bytes(), &detailResponse); err != nil {
		t.Fatal(err)
	}
	if len(detailResponse.Host.Protocols) != 1 || len(detailResponse.Host.Protocols[0].Ports) != 2 {
		t.Fatalf("accepted baseline detail = %#v", detailResponse.Host)
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
	latest := model.Scan{ID: "latest-host-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.1", SourceTargets: []string{"router.example"}, Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "443", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}, {Address: "198.51.100.222", SourceTargets: []string{"switch-222.example"}, Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "443", ScannedPortCount: 1}}}, {Address: "2001:db8::1", Protocols: []model.ProtocolObservation{{Protocol: "udp", ScannedPorts: "53", ScannedPortCount: 1}}}}}}
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
	queryRequest := httptest.NewRequest(http.MethodGet, "/api/v1/hosts?q=222", nil)
	queryRecorder := httptest.NewRecorder()
	server.listHosts(queryRecorder, queryRequest)
	if queryRecorder.Code != http.StatusOK {
		t.Fatalf("query status %d: %s", queryRecorder.Code, queryRecorder.Body.String())
	}
	response = struct {
		Hosts []allHostSummary `json:"hosts"`
	}{}
	if err := json.Unmarshal(queryRecorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Hosts) != 1 || response.Hosts[0].Address != "198.51.100.222" {
		t.Fatalf("query returned unrelated hosts: %#v", response.Hosts)
	}
}

func TestAllHostsSeparatesArchivedJobsAfterActiveHosts(t *testing.T) {
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
	archivedJob, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "archived-host", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.40"}, TCP: &config.Protocol{Ports: "22", Mode: "syn"}}))
	if err != nil {
		t.Fatal(err)
	}
	activeJob, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "active-host", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.41"}, TCP: &config.Protocol{Ports: "22", Mode: "syn"}}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, item := range []struct {
		job store.JobRecord
		id  string
		ip  string
	}{
		{job: archivedJob, id: "archived-host-scan", ip: "198.51.100.40"},
		{job: activeJob, id: "active-host-scan", ip: "198.51.100.41"},
	} {
		scan := model.Scan{ID: item.id, JobID: item.job.ID, JobRevision: item.job.Revision, Job: item.job.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: item.ip, Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "22", ScannedPortCount: 1}}}}}}
		if err := db.SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SetJobArchived(ctx, archivedJob.ID, true); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.listHosts(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("host list status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Hosts []allHostSummary `json:"hosts"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Hosts) != 2 || response.Hosts[0].Address != "198.51.100.41" || response.Hosts[0].Archived || response.Hosts[1].Address != "198.51.100.40" || !response.Hosts[1].Archived {
		t.Fatalf("host archive ordering = %#v", response.Hosts)
	}
}

func TestAllHostsMergesIndexedAndLegacySuccessfulScans(t *testing.T) {
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
	job, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "indexed-job", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.10"}, TCP: &config.Protocol{Ports: "22", Mode: "connect"}}))
	if err != nil {
		t.Fatal(err)
	}
	when := time.Unix(500, 0).UTC()
	indexed := model.Scan{ID: "indexed-mixed", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: when, FinishedAt: when, Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.10", SourceTargets: []string{"198.51.100.10"}, Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "22", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 22, State: "open"}}}}}}}}
	if err := db.SaveScan(ctx, indexed); err != nil {
		t.Fatal(err)
	}
	legacy := model.Scan{ID: "legacy-mixed", Job: "legacy-job", StartedAt: when.Add(-time.Minute), FinishedAt: when.Add(-time.Minute), Status: "success", Snapshot: model.Snapshot{Scopes: []model.Scope{{Target: "legacy.example", Protocol: "tcp", Ports: "80"}}, Units: []model.Unit{{Target: "legacy.example", Protocol: "tcp", Addresses: []string{"198.51.100.11"}, Ports: []model.PortState{{Port: 80, State: "open", Service: "legacy-http"}}}}}}
	if err := db.SaveScan(ctx, legacy); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	server.listHosts(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("host list status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Hosts []allHostSummary `json:"hosts"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Hosts) != 2 || response.Hosts[0].Address != "198.51.100.10" || response.Hosts[1].Address != "198.51.100.11" || !response.Hosts[1].Legacy {
		t.Fatalf("mixed host projection = %#v", response.Hosts)
	}
	queryRecorder := httptest.NewRecorder()
	server.listHosts(queryRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/hosts?q=legacy.example", nil))
	if queryRecorder.Code != http.StatusOK {
		t.Fatalf("legacy query status = %d: %s", queryRecorder.Code, queryRecorder.Body.String())
	}
	response = struct {
		Hosts []allHostSummary `json:"hosts"`
	}{}
	if err := json.Unmarshal(queryRecorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Hosts) != 1 || response.Hosts[0].Address != "198.51.100.11" {
		t.Fatalf("legacy query result = %#v", response.Hosts)
	}
	serviceRecorder := httptest.NewRecorder()
	server.listHosts(serviceRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/hosts?q=legacy-http", nil))
	if serviceRecorder.Code != http.StatusOK {
		t.Fatalf("legacy service query status = %d: %s", serviceRecorder.Code, serviceRecorder.Body.String())
	}
	response = struct {
		Hosts []allHostSummary `json:"hosts"`
	}{}
	if err := json.Unmarshal(serviceRecorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Hosts) != 1 || response.Hosts[0].Address != "198.51.100.11" {
		t.Fatalf("legacy service query result = %#v", response.Hosts)
	}
}

func TestSummaryForHostCollapsesChunkedProtocolObservations(t *testing.T) {
	host := model.HostObservation{
		Address: "198.51.100.10",
		Protocols: []model.ProtocolObservation{
			{Protocol: "tcp", ScannedPorts: "1-4096", ScannedPortCount: 4096, Ports: []model.PortObservation{{Port: 22, State: "open"}}},
			{Protocol: "tcp", ScannedPorts: "4097-8192", ScannedPortCount: 4096, Ports: []model.PortObservation{{Port: 443, State: "open|filtered"}}},
			{Protocol: "udp", ScannedPorts: "53", ScannedPortCount: 1},
		},
	}
	summary := summaryForHost(host, false)
	if len(summary.Protocols) != 2 {
		t.Fatalf("protocol summaries = %#v, want one TCP and one UDP record", summary.Protocols)
	}
	if summary.OpenPorts != 1 || summary.OpenFilteredPorts != 1 {
		t.Fatalf("positive port counts = %d open, %d open|filtered", summary.OpenPorts, summary.OpenFilteredPorts)
	}
	for _, protocol := range summary.Protocols {
		if protocol.Protocol == "tcp" && protocol.OpenPorts != 1 {
			t.Fatalf("TCP summary = %#v", protocol)
		}
	}
}
