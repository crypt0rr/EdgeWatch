package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/rdap"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestIsPrivateAddressClassifiesSpecialAndPublicRanges(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1", "0.0.0.0", "169.254.1.1", "224.0.0.1", "ff02::1", "10.1.2.3", "172.16.1.1", "192.168.1.1", "100.64.1.1", "fd00::1"} {
		if !isPrivateAddress(net.ParseIP(address)) {
			t.Errorf("%s was classified as public", address)
		}
	}
	for _, address := range []string{"8.8.8.8", "198.51.100.10", "2001:db8::10"} {
		if isPrivateAddress(net.ParseIP(address)) {
			t.Errorf("%s was classified as private", address)
		}
	}
}

func TestPublicHostProjectionRedactsAndSortsPositivePorts(t *testing.T) {
	s := &Server{}
	host := model.HostObservation{Address: " 198.51.100.10 ", Protocols: []model.ProtocolObservation{
		{Protocol: "udp", Ports: []model.PortObservation{{Port: 53, State: "open|filtered", Reason: "response", Service: &model.ServiceObservation{Name: "domain", Product: "BIND", Version: "9"}}, {Port: 54, State: "closed", Service: &model.ServiceObservation{Name: "hidden"}}}},
		{Protocol: "tcp", Ports: []model.PortObservation{{Port: 443, State: "open", Service: &model.ServiceObservation{Name: "https", Product: "nginx", Version: "1.2", ExtraInfo: "must not leak"}}, {Port: 22, State: "filtered"}}},
	}}
	response := s.publicHostFromObservation(context.Background(), "public-job", host, model.ScanSummary{FinishedAt: time.Unix(10, 0).UTC()})
	if response.Address != "198.51.100.10" || !response.Public || response.Private || len(response.OpenPorts) != 1 || len(response.OpenFiltered) != 1 {
		t.Fatalf("projection = %#v", response)
	}
	if response.OpenPorts[0].Protocol != "tcp" || response.OpenPorts[0].Service != "https" || response.OpenPorts[0].Product != "nginx" || response.OpenPorts[0].Version != "1.2" || response.OpenPorts[0].Port != 443 {
		t.Fatalf("open projection = %#v", response.OpenPorts)
	}
	if response.OpenFiltered[0].Protocol != "udp" || response.OpenFiltered[0].Port != 53 || response.OpenFiltered[0].Service != "domain" {
		t.Fatalf("open-filtered projection = %#v", response.OpenFiltered)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || containsJSONField(encoded, "extra_info") || containsJSONField(encoded, "reason") {
		t.Fatalf("private evidence leaked into public projection: %s", encoded)
	}
	private := s.publicHostFromObservation(context.Background(), "private-job", model.HostObservation{Address: "192.168.1.4"}, model.ScanSummary{})
	if !private.Private || private.Public {
		t.Fatalf("private projection = %#v", private)
	}
}

func TestPublicRdapProjectionAndCachedPayloadValidation(t *testing.T) {
	result := rdap.Result{Status: "success", Address: "198.51.100.10", NetworkName: "Example", Country: "NL", Registry: "ripe", Organizations: []string{"Example Org"}, SourceURL: "https://registry.example/rdap/ip/198.51.100.10"}
	projected := publicRdapFromResult(result)
	if projected.Status != "success" || projected.NetworkName != "Example" || len(projected.Organization) != 1 {
		t.Fatalf("projected RDAP = %#v", projected)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeCachedPublicRDAP(raw)
	if err != nil || decoded.SourceURL != result.SourceURL || decoded.NetworkName != result.NetworkName {
		t.Fatalf("cached RDAP = %#v, %v", decoded, err)
	}
	if _, err := decodeCachedPublicRDAP([]byte("not-json")); err == nil {
		t.Fatal("malformed cached RDAP was accepted")
	}
}

func TestPublicAPIDisabledEnabledAndRateLimited(t *testing.T) {
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
	call := func(method, path, remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		server.publicAPI(rec, req)
		return rec
	}
	if rec := call(http.MethodGet, "/api/public/v1/dashboard", "198.51.100.20:1000"); rec.Code != http.StatusNotFound || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Robots-Tag") != "noindex, nofollow" {
		t.Fatalf("disabled public API = %d, headers=%v", rec.Code, rec.Header())
	}
	if rec := call(http.MethodPost, "/api/public/v1/dashboard", "198.51.100.20:1001"); rec.Code != http.StatusNotFound {
		t.Fatalf("wrong-method public API = %d", rec.Code)
	}
	if err := db.SavePublicDashboard(ctx, store.PublicDashboard{Enabled: true, Title: "Public"}, nil, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if rec := call(http.MethodGet, "/api/public/v1/dashboard/", "198.51.100.20:1002"); rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("enabled public API = %d: %s", rec.Code, rec.Body.String())
	}
	server.publicHits = map[string][]time.Time{}
	for i := 0; i < 120; i++ {
		if !server.allowPublicRequest(httptest.NewRequest(http.MethodGet, "/", nil)) {
			t.Fatalf("request %d unexpectedly rate limited", i+1)
		}
	}
	if server.allowPublicRequest(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("121st request was not rate limited")
	}
	old := time.Now().UTC().Add(-2 * time.Minute)
	server.publicHits = map[string][]time.Time{}
	for i := 0; i < 4096; i++ {
		server.publicHits["old-"+strconv.Itoa(i)] = []time.Time{old}
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "new-client:1234"
	if !server.allowPublicRequest(request) {
		t.Fatal("new client was unexpectedly rate limited")
	}
	if len(server.publicHits) != 1 {
		t.Fatalf("expired rate-limit entries were not removed: %d remain", len(server.publicHits))
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if rec := call(http.MethodGet, "/api/public/v1/dashboard", "198.51.100.21:1000"); rec.Code != http.StatusInternalServerError {
		t.Fatalf("public API store failure status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPublicDashboardAdminRouteValidatesSelectionsAndPublishesHosts(t *testing.T) {
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
	admin := store.Session{UserID: store.LegacyAdminUserID, Username: "admin", Role: store.RoleAdministrator}
	get := httptest.NewRecorder()
	server.publicDashboardRoute(get, httptest.NewRequest(http.MethodGet, "/api/v1/public-dashboard", nil), admin)
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "EdgeWatch public status") {
		t.Fatalf("default public dashboard = %d: %s", get.Code, get.Body.String())
	}
	badText := httptest.NewRequest(http.MethodPut, "/api/v1/public-dashboard", strings.NewReader(`{"title":"bad\ntitle"}`))
	badText.Header.Set("Content-Type", "application/json")
	badTextRecorder := httptest.NewRecorder()
	server.publicDashboardRoute(badTextRecorder, badText, admin)
	if badTextRecorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid public text status = %d: %s", badTextRecorder.Code, badTextRecorder.Body.String())
	}
	job := config.NormalizeJob(config.Job{Name: "public-route", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.10"}, TCP: &config.Protocol{Ports: "443", Mode: "syn"}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{ID: "public-route-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.10", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "443", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 443, State: "open", Service: &model.ServiceObservation{Name: "https"}}}}}}}}}
	if err := db.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	unknownHost := httptest.NewRequest(http.MethodPut, "/api/v1/public-dashboard", strings.NewReader(`{"enabled":true,"title":"Status","hosts":[{"job_id":"`+record.ID+`","address":"198.51.100.11"}]}`))
	unknownHost.Header.Set("Content-Type", "application/json")
	unknownRecorder := httptest.NewRecorder()
	server.publicDashboardRoute(unknownRecorder, unknownHost, admin)
	if unknownRecorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown host status = %d: %s", unknownRecorder.Code, unknownRecorder.Body.String())
	}
	// Older console builds round-tripped the read-only created_at field as an
	// empty string. The write API accepts that compatibility field while only
	// persisting the job/address selection.
	publish := httptest.NewRequest(http.MethodPut, "/api/v1/public-dashboard", strings.NewReader(`{"enabled":true,"title":"Status","introduction":"Selected host","hosts":[{"job_id":"`+record.ID+`","address":"198.51.100.10","created_at":""}]}`))
	publish.Header.Set("Content-Type", "application/json")
	publishRecorder := httptest.NewRecorder()
	server.publicDashboardRoute(publishRecorder, publish, admin)
	if publishRecorder.Code != http.StatusOK || !strings.Contains(publishRecorder.Body.String(), "198.51.100.10") {
		t.Fatalf("published dashboard = %d: %s", publishRecorder.Code, publishRecorder.Body.String())
	}
	publicResponse, err := server.publicDashboardResponse(ctx, store.PublicDashboard{Title: "Status", Hosts: []store.PublicDashboardHost{{JobID: record.ID, Address: "198.51.100.10"}}})
	if err != nil || len(publicResponse.Hosts) != 1 || len(publicResponse.Hosts[0].OpenPorts) != 1 {
		t.Fatalf("public response = %#v, %v", publicResponse, err)
	}
}

func containsJSONField(raw []byte, field string) bool {
	needle := `"` + field + `"`
	return strings.Contains(string(raw), needle)
}
