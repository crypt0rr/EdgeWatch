package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestHistoricalHostRoutesAndLegacyFallback(t *testing.T) {
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
	job := config.NormalizeJob(config.Job{
		Name: "host-history", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.10", "2001:db8::10"},
		TCP: &config.Protocol{Ports: "22,443", Mode: "syn", ServiceDetection: true},
		UDP: &config.Protocol{Ports: "53", ServiceDetection: true},
	})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC()
	detailedHost := model.HostObservation{
		Address: "198.51.100.10", AddressFamily: "IPv4", SourceTargets: []string{"198.51.100.10"}, Status: "up", StatusReason: "syn-ack",
		Protocols: []model.ProtocolObservation{
			{Protocol: "tcp", ScanType: "syn", ScannedPorts: "22,443", ScannedPortCount: 2, ServiceDetection: true, Ports: []model.PortObservation{{Port: 443, State: "open", Reason: "syn-ack", Service: &model.ServiceObservation{Name: "https", Product: "Example", Version: "1.0"}}, {Port: 22, State: "closed", Reason: "conn-refused"}}, StateSummaries: []model.StateSummary{{State: "closed", Count: 1}}},
			{Protocol: "udp", ScannedPorts: "53", ScannedPortCount: 1, ServiceDetection: true, Ports: []model.PortObservation{{Port: 53, State: "open|filtered", Reason: "udp-response"}}},
		},
	}
	scan := model.Scan{ID: "host-history-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: when, FinishedAt: when, Status: "success", NmapVersion: "Nmap 7.99", ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{Hosts: []model.HostObservation{detailedHost}}}
	if err := db.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApproveRuntime(ctx, record.ID, record.Job.Name, scan); err != nil {
		t.Fatal(err)
	}

	call := func(path string, fn func(http.ResponseWriter, *http.Request)) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		fn(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder
	}

	if response := call("/api/v1/jobs/"+record.ID+"/scans/"+scan.ID+"/hosts", func(w http.ResponseWriter, r *http.Request) { server.jobScanHosts(w, r, record.ID, scan.ID) }); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"data_quality":"detailed"`) {
		t.Fatalf("job scan hosts = %d: %s", response.Code, response.Body.String())
	}
	if response := call("/api/v1/scans/"+scan.ID+"/hosts", func(w http.ResponseWriter, r *http.Request) { server.scanHostsRoute(w, r, scan.ID) }); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"hosts"`) {
		t.Fatalf("scan hosts route = %d: %s", response.Code, response.Body.String())
	}
	if response := call("/api/v1/jobs/"+record.ID+"/scans/"+scan.ID+"/hosts/198.51.100.10", func(w http.ResponseWriter, r *http.Request) {
		server.jobScanHost(w, r, record.ID, scan.ID, "198.51.100.10")
	}); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"https"`) || !strings.Contains(response.Body.String(), `"expected"`) {
		t.Fatalf("job scan host = %d: %s", response.Code, response.Body.String())
	}
	if response := call("/api/v1/scans/"+scan.ID+"/hosts/198.51.100.10", func(w http.ResponseWriter, r *http.Request) { server.scanHostRoute(w, r, scan.ID, "198.51.100.10") }); response.Code != http.StatusOK {
		t.Fatalf("scan host route = %d: %s", response.Code, response.Body.String())
	}

	// Disable the client for this route test so no external registry request is
	// made. The endpoint still returns a stable, independent RDAP status.
	server.RDAP = nil
	for name, fn := range map[string]func(http.ResponseWriter, *http.Request){
		"job scan RDAP": func(w http.ResponseWriter, r *http.Request) {
			server.jobScanHostRDAP(w, r, record.ID, scan.ID, "198.51.100.10")
		},
		"scan RDAP": func(w http.ResponseWriter, r *http.Request) { server.scanHostRDAPRoute(w, r, scan.ID, "198.51.100.10") },
		"baseline RDAP": func(w http.ResponseWriter, r *http.Request) {
			server.jobBaselineHostRDAP(w, r, record.ID, "198.51.100.10")
		},
	} {
		response := call("/api/v1/hosts/198.51.100.10/rdap", fn)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"unavailable"`) {
			t.Fatalf("%s = %d: %s", name, response.Code, response.Body.String())
		}
	}

	for name, fn := range map[string]func(http.ResponseWriter, *http.Request){
		"missing scan host": func(w http.ResponseWriter, r *http.Request) {
			server.jobScanHost(w, r, record.ID, scan.ID, "198.51.100.11")
		},
		"invalid scan host": func(w http.ResponseWriter, r *http.Request) {
			server.jobScanHost(w, r, record.ID, scan.ID, "not-an-ip")
		},
		"missing scan RDAP": func(w http.ResponseWriter, r *http.Request) {
			server.jobScanHostRDAP(w, r, record.ID, scan.ID, "198.51.100.11")
		},
		"missing baseline RDAP": func(w http.ResponseWriter, r *http.Request) {
			server.jobBaselineHostRDAP(w, r, record.ID, "198.51.100.11")
		},
	} {
		response := call("/api/v1/missing", fn)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d: %s", name, response.Code, response.Body.String())
		}
	}
	for name, path := range map[string]string{
		"bad limit":       "/api/v1/jobs/" + record.ID + "/scans/" + scan.ID + "/hosts?limit=101",
		"bad open filter": "/api/v1/jobs/" + record.ID + "/scans/" + scan.ID + "/hosts?has_open_ports=maybe",
		"bad protocol":    "/api/v1/jobs/" + record.ID + "/scans/" + scan.ID + "/hosts?protocol=sctp",
	} {
		response := call(path, func(w http.ResponseWriter, r *http.Request) { server.jobScanHosts(w, r, record.ID, scan.ID) })
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d: %s", name, response.Code, response.Body.String())
		}
	}

	// A legacy scan has no host index. The additive top-level routes must
	// derive effective hosts from logical units without loading unrelated rows.
	legacy := model.Scan{ID: "legacy-host-scan", Job: "legacy-job", StartedAt: when.Add(-time.Hour), FinishedAt: when.Add(-time.Hour), Status: "success", Snapshot: model.Snapshot{
		Scopes: []model.Scope{{Target: "legacy.example", Protocol: "tcp", Ports: "80-81", ServiceDetection: false}},
		Units:  []model.Unit{{Target: "legacy.example", Protocol: "tcp", Addresses: []string{"2001:db8::20"}, Ports: []model.PortState{{Port: 80, State: "open", Service: "http"}}}},
	}}
	if err := db.SaveScan(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	legacyCalls := []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"legacy hosts", func(w http.ResponseWriter, r *http.Request) { server.scanHostsRoute(w, r, legacy.ID) }},
		{"legacy host", func(w http.ResponseWriter, r *http.Request) { server.scanHostRoute(w, r, legacy.ID, "2001:db8::20") }},
		{"legacy RDAP", func(w http.ResponseWriter, r *http.Request) {
			server.scanHostRDAPRoute(w, r, legacy.ID, "2001:db8::20")
		}},
	}
	for _, item := range legacyCalls {
		response := call("/api/v1/scans/"+legacy.ID, item.fn)
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", item.name, response.Code, response.Body.String())
		}
		if item.name == "legacy hosts" && !strings.Contains(response.Body.String(), `"data_quality":"legacy"`) {
			t.Fatalf("legacy hosts response missing quality: %s", response.Body.String())
		}
	}

	latest, err := server.latestScannedHosts(ctx)
	if err != nil || len(latest) == 0 {
		t.Fatalf("latest legacy hosts = %#v, %v", latest, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(call("/api/v1", func(w http.ResponseWriter, r *http.Request) { server.scanHostsRoute(w, r, scan.ID) }).Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
}
