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

func TestHostHelpersCoverLegacyAndFilterEdges(t *testing.T) {
	if canonicalHostAddress("  192.0.2.1 ") != "192.0.2.1" || canonicalHostAddress("logical.example") != "logical.example" {
		t.Fatal("host address canonicalization failed")
	}
	if familyForAddress("192.0.2.1") != "IPv4" || familyForAddress("2001:db8::1") != "IPv6" || familyForAddress("name") != "" {
		t.Fatal("address family detection failed")
	}
	if portCount("bad-range") != 0 || portCount("1-3") != 3 {
		t.Fatal("port count handling failed")
	}
	protocol := model.ProtocolObservation{}
	addLegacySummary(&protocol, "closed")
	addLegacySummary(&protocol, "closed")
	addLegacySummary(&protocol, "filtered")
	if len(protocol.StateSummaries) != 2 || protocol.StateSummaries[0].Count != 2 {
		t.Fatalf("legacy state summary = %#v", protocol.StateSummaries)
	}
	host := model.HostObservation{Address: "192.0.2.3"}
	mergeLegacyProtocol(&host, model.ProtocolObservation{Protocol: "tcp", ScannedPorts: "1", ScannedPortCount: 1})
	mergeLegacyProtocol(&host, model.ProtocolObservation{Protocol: "tcp", ScannedPorts: "2", ScannedPortCount: 2, ServiceDetection: true, Ports: []model.PortObservation{{Port: 2, State: "open"}}})
	mergeLegacyProtocol(&host, model.ProtocolObservation{Protocol: "udp", ScannedPorts: "53", ScannedPortCount: 1})
	if len(host.Protocols) != 2 || host.Protocols[0].ScannedPorts != "1" || !host.Protocols[0].ServiceDetection || len(host.Protocols[0].Ports) != 1 {
		t.Fatalf("merged legacy protocols = %#v", host.Protocols)
	}
	if len(scopesForJob(config.Job{})) != 0 || len(scopesForJob(config.Job{TCP: &config.Protocol{Ports: "1"}, UDP: &config.Protocol{Ports: "53"}})) != 2 {
		t.Fatal("scope conversion failed")
	}

	// A unit without addresses falls back to its logical target. Legacy snapshots
	// may also contain a non-IP logical address; the global index filters those
	// out before presenting effective hosts.
	snapshot := model.Snapshot{Units: []model.Unit{
		{Target: "192.0.2.10", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "closed"}}},
		{Target: "logical.example", Protocol: "udp", Addresses: []string{"bad-address"}, Ports: []model.PortState{{Port: 53, State: "open"}}},
	}}
	hosts := deriveLegacyHosts(snapshot)
	if len(hosts) != 2 || hosts[0].Address != "192.0.2.10" {
		t.Fatalf("fallback legacy hosts = %#v", hosts)
	}
	page, err := observationsForSnapshot(model.Snapshot{})
	if err != nil || page.DataQuality != "legacy" || len(page.Items) != 0 {
		t.Fatalf("empty snapshot observations = %#v, %v", page, err)
	}
	detailed, err := observationsForSnapshot(model.Snapshot{Hosts: []model.HostObservation{{Address: "192.0.2.11", Protocols: []model.ProtocolObservation{{Protocol: "tcp"}}}}, Scopes: []model.Scope{{Protocol: "tcp", Ports: "22"}}})
	if err != nil || detailed.DataQuality != "detailed" || detailed.Items[0].Protocols[0].ScannedPorts != "22" {
		t.Fatalf("scope restoration = %#v, %v", detailed, err)
	}

	open := true
	closed := false
	withHost := model.HostObservation{Address: "192.0.2.20", SourceTargets: []string{"target"}, DNSNames: []string{"dns.example"}, Hostnames: []model.Hostname{{Name: "host.example"}}, Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 1, State: "open"}}}}}
	summary := summaryForHost(withHost, false)
	for _, query := range []string{"target", "dns", "host", "192.0.2.20"} {
		if !hostMatches(withHost, summary, query, "", nil) {
			t.Errorf("query %q did not match", query)
		}
	}
	if hostMatches(withHost, summary, "missing", "", nil) || hostMatches(withHost, summary, "", "udp", nil) || hostMatches(withHost, summary, "", "tcp", &closed) {
		t.Fatal("host mismatch filter unexpectedly matched")
	}
	if !hostMatches(withHost, summary, "", "tcp", &open) {
		t.Fatal("host open filter did not match")
	}
	if summaryForHost(model.HostObservation{Address: "192.0.2.21", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 1, State: "closed"}}}}}, true).HasOpenPorts {
		t.Fatal("closed host reported open")
	}
	if _, total := filterHosts([]model.HostObservation{withHost}, "detailed", "", "", nil, 1, 10); total != 1 {
		t.Fatal("filter total was not retained for out-of-range page")
	}
}

func newHostHandlerServer(t *testing.T) (*Server, *store.Store, store.JobRecord) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(a, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	job := config.NormalizeJob(config.Job{Name: "host-handler", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.0/30"}, TCP: &config.Protocol{Ports: "22", Mode: "syn"}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	return server, db, record
}

func TestHostHandlersRejectInvalidOwnershipAndPagination(t *testing.T) {
	server, db, record := newHostHandlerServer(t)
	ctx := context.Background()
	call := func(fn func(http.ResponseWriter, *http.Request), path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		fn(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder
	}
	if got := call(func(w http.ResponseWriter, r *http.Request) { server.jobBaselineHosts(w, r, "missing") }, "/api/v1/jobs/missing/baseline/hosts"); got.Code != http.StatusNotFound {
		t.Fatalf("missing baseline job status = %d", got.Code)
	}
	if got := call(func(w http.ResponseWriter, r *http.Request) { server.jobBaselineHosts(w, r, record.ID) }, "/api/v1/jobs/"+record.ID+"/baseline/hosts?limit=bad"); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid baseline pagination status = %d", got.Code)
	}
	if got := call(func(w http.ResponseWriter, r *http.Request) { server.jobBaselineHosts(w, r, record.ID) }, "/api/v1/jobs/"+record.ID+"/baseline/hosts?protocol=icmp"); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid baseline protocol status = %d", got.Code)
	}
	if got := call(func(w http.ResponseWriter, r *http.Request) { server.jobBaselineHost(w, r, record.ID, "not-an-ip") }, "/api/v1/jobs/"+record.ID+"/baseline/hosts/not-an-ip"); got.Code != http.StatusNotFound {
		t.Fatalf("invalid baseline host status = %d", got.Code)
	}
	if got := call(func(w http.ResponseWriter, r *http.Request) { server.jobBaselineHost(w, r, record.ID, "198.51.100.1") }, "/api/v1/jobs/"+record.ID+"/baseline/hosts/198.51.100.1"); got.Code != http.StatusNotFound {
		t.Fatalf("host without baseline status = %d", got.Code)
	}
	if got := call(func(w http.ResponseWriter, r *http.Request) { server.jobBaselineHostRDAP(w, r, record.ID, "not-an-ip") }, "/api/v1/jobs/"+record.ID+"/baseline/hosts/not-an-ip/rdap"); got.Code != http.StatusNotFound {
		t.Fatalf("invalid baseline RDAP status = %d", got.Code)
	}
	if got := call(func(w http.ResponseWriter, r *http.Request) {
		server.jobBaselineHostRDAP(w, r, "missing", "198.51.100.1")
	}, "/api/v1/jobs/missing/baseline/hosts/198.51.100.1/rdap"); got.Code != http.StatusNotFound {
		t.Fatalf("missing RDAP job status = %d", got.Code)
	}
	if got := call(func(w http.ResponseWriter, r *http.Request) { server.jobScanHosts(w, r, "missing", "scan") }, "/api/v1/jobs/missing/scans/scan/hosts"); got.Code != http.StatusNotFound {
		t.Fatalf("missing scan job status = %d", got.Code)
	}
	if got := call(func(w http.ResponseWriter, r *http.Request) { server.scanHostsRoute(w, r, "missing") }, "/api/v1/scans/missing/hosts"); got.Code != http.StatusNotFound {
		t.Fatalf("missing scan route status = %d", got.Code)
	}
	if got := call(func(w http.ResponseWriter, r *http.Request) { server.scanHostRoute(w, r, "missing", "1.2.3.4") }, "/api/v1/scans/missing/hosts/1.2.3.4"); got.Code != http.StatusNotFound {
		t.Fatalf("missing scan detail status = %d", got.Code)
	}
	if got := call(func(w http.ResponseWriter, r *http.Request) { server.scanHostRDAPRoute(w, r, "missing", "1.2.3.4") }, "/api/v1/scans/missing/hosts/1.2.3.4/rdap"); got.Code != http.StatusNotFound {
		t.Fatalf("missing scan RDAP status = %d", got.Code)
	}
	if _, err := db.RuntimeState(ctx, record.ID); err != nil {
		t.Fatal(err)
	}
}

func TestHistoricalHostHandlersUseLegacyFallback(t *testing.T) {
	server, db, record := newHostHandlerServer(t)
	ctx := context.Background()
	now := time.Now().UTC()
	scan := model.Scan{ID: "legacy-host-handler", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{Units: []model.Unit{{Target: "198.51.100.1", Protocol: "tcp", Addresses: []string{"198.51.100.1"}, Ports: []model.PortState{{Port: 22, State: "open", Service: "ssh"}}}}, Scopes: []model.Scope{{Target: "198.51.100.1", Protocol: "tcp", Ports: "22"}}}}
	if err := db.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.jobScanHosts(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/scans/"+scan.ID+"/hosts?has_open_ports=true", nil), record.ID, scan.ID)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"data_quality":"legacy"`) {
		t.Fatalf("legacy host list = %d %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.jobScanHost(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/scans/"+scan.ID+"/hosts/198.51.100.1", nil), record.ID, scan.ID, "198.51.100.1")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"legacy"`) {
		t.Fatalf("legacy host detail = %d %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.jobScanHost(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/scans/"+scan.ID+"/hosts/198.51.100.99", nil), record.ID, scan.ID, "198.51.100.99")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown legacy host status = %d", recorder.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		// The error response is still JSON; this guards the handler contract.
		t.Fatal(err)
	}
}

func TestHostRDAPUnavailableForKnownHistoricalHost(t *testing.T) {
	server, db, record := newHostHandlerServer(t)
	ctx := context.Background()
	now := time.Now().UTC()
	scan := model.Scan{ID: "indexed-rdap-host", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.12", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}}}}
	if err := db.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.jobScanHostRDAP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/scans/"+scan.ID+"/hosts/198.51.100.12/rdap", nil), record.ID, scan.ID, "198.51.100.12")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), "rdap") {
		t.Fatalf("historical RDAP response = %d %s", recorder.Code, recorder.Body.String())
	}
	// The public API must never accept a non-IP host path.
	if _, err := normalizedHostAddress("%zz"); err == nil {
		t.Fatal("malformed escaped address accepted")
	}
}
