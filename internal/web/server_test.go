package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type fakeScanner struct{}

func (fakeScanner) Version(context.Context) string { return "fake" }
func (fakeScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	return model.Snapshot{Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}}, nil
}

type sequenceScanner struct {
	mu        sync.Mutex
	snapshots []model.Snapshot
	calls     int
}

func (s *sequenceScanner) Version(context.Context) string { return "fake-sequence" }
func (s *sequenceScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.calls
	s.calls++
	if index >= len(s.snapshots) {
		index = len(s.snapshots) - 1
	}
	return s.snapshots[index], nil
}
func TestConsoleSetupLoginCreateAndRun(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: filepath.Join(t.TempDir(), "edgewatch.db"), Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = fakeScanner{}
	setupAuth := auth.NewManager(s)
	token, err := setupAuth.EnsureSetupToken(ctx)
	if err != nil || token == "" {
		t.Fatalf("setup token %q: %v", token, err)
	}
	server := NewServer(a, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := httptest.NewServer(server.Handler())
	defer h.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	post := func(path, body string, csrf string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, h.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return resp
	}
	resp := post("/api/v1/setup", `{"token":"`+token+`","password":"correct horse battery staple"}`, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("setup status %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = post("/api/v1/auth/login", `{"password":"correct horse battery staple"}`, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var loginResult struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&loginResult)
	resp.Body.Close()
	if loginResult.CSRF == "" {
		t.Fatal("missing csrf token")
	}
	req, _ := http.NewRequest(http.MethodPost, h.URL+"/api/v1/jobs", strings.NewReader(`{"name":"local","schedule":"0 * * * *","timezone":"UTC","targets":["127.0.0.1"],"tcp":{"ports":"1","mode":"connect"},"timeout":"1m","timing":"balanced","baseline_samples":1,"change_confirmations":1,"max_expanded_hosts":256,"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", loginResult.CSRF)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status %d", resp.StatusCode)
	}
	var created struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
		Enabled  bool   `json:"enabled"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == "" {
		t.Fatal("missing job id")
	}
	if created.Revision != 1 || created.Enabled {
		t.Fatalf("created paused job was not persisted atomically: %#v", created)
	}
	resp = post("/api/v1/jobs/"+created.ID+"/run", "{}", loginResult.CSRF)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("run status %d", resp.StatusCode)
	}
	resp.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		scans, scanErr := s.ListJobScans(ctx, created.ID, 5)
		if scanErr != nil {
			t.Fatal(scanErr)
		}
		if len(scans) > 0 {
			if scans[0].Status != "success" {
				t.Fatalf("scan status %s: %s", scans[0].Status, scans[0].Error)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("scan did not finish")
}

func TestListenAddressIsLoopbackOnly(t *testing.T) {
	if err := validateListenAddress("127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"0.0.0.0:8080", ":8080", "127.0.0.1:0"} {
		if err := validateListenAddress(address); err == nil {
			t.Fatalf("unsafe listener accepted: %s", address)
		}
	}
}

func TestSetupStatusDoesNotExposeOperationalDetails(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	hash, err := auth.PasswordHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAdmin(ctx, store.Admin{Username: "admin", PasswordHash: hash, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Version:   1,
		Database:  "test",
		Retention: config.Duration(24 * time.Hour),
		Scheduler: config.Scheduler{MaxConcurrent: 3},
		Web:       config.Web{Listen: "127.0.0.1:8080"},
		Jobs:      []config.Job{{Name: "legacy-secret"}},
		Notifications: config.Notifications{URLs: []string{
			"generic://example.invalid/token",
		}},
	}
	a, err := app.New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(NewServer(a, s, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer h.Close()

	resp, err := http.Get(h.URL + "/api/v1/setup/status")
	if err != nil {
		t.Fatal(err)
	}
	var public map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&public); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup status returned %d", resp.StatusCode)
	}
	for _, key := range []string{"notifications", "notification_destinations", "retention", "max_concurrent_scans", "legacy_yaml_jobs"} {
		if _, ok := public[key]; ok {
			t.Fatalf("unauthenticated setup status exposed %q: %#v", key, public)
		}
	}

	loginRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	loginRequest.RemoteAddr = "127.0.0.1:1234"
	sessionToken, _, err := auth.NewManager(s).Login(ctx, loginRequest, "correct horse battery staple", "", "")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, h.URL+"/api/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: sessionToken})
	resp, err = (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var private map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&private); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated status returned %d", resp.StatusCode)
	}
	for _, key := range []string{"notifications", "retention", "max_concurrent_scans", "legacy_yaml_jobs"} {
		if _, ok := private[key]; !ok {
			t.Fatalf("authenticated status omitted %q: %#v", key, private)
		}
	}
}

func TestSSEHistoryAssignsIDsAndSupportsReplay(t *testing.T) {
	s := &Server{subscribers: map[chan sseMessage]struct{}{}}
	ch := make(chan sseMessage, 4)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	s.broadcast(map[string]any{"type": "first"})
	s.broadcast(map[string]any{"type": "second"})
	first, second := <-ch, <-ch
	if first.id == 0 || second.id != first.id+1 {
		t.Fatalf("SSE IDs were not monotonic: %d, %d", first.id, second.id)
	}
	s.mu.Lock()
	replay := s.replayLocked(first.id)
	delete(s.subscribers, ch)
	s.mu.Unlock()
	if len(replay) != 1 || replay[0].id != second.id || !strings.Contains(string(replay[0].payload), "second") {
		t.Fatalf("unexpected replay after event %d: %#v", first.id, replay)
	}
	for i := 0; i < 300; i++ {
		s.broadcast(map[string]any{"type": "bulk"})
	}
	s.mu.Lock()
	gap := s.replayLocked(1)
	s.mu.Unlock()
	if len(gap) == 0 || !strings.Contains(string(gap[0].payload), "refresh_required") {
		t.Fatalf("history gap did not request refresh: %#v", gap)
	}
	slow := &Server{subscribers: map[chan sseMessage]struct{}{}}
	slowCh := make(chan sseMessage, 1)
	slow.subscribers[slowCh] = struct{}{}
	slow.broadcast(map[string]any{"type": "queued"})
	slow.broadcast(map[string]any{"type": "new"})
	select {
	case marker := <-slowCh:
		if !strings.Contains(string(marker.payload), "refresh_required") {
			t.Fatalf("slow subscriber received a silent drop instead of refresh marker: %s", marker.payload)
		}
	default:
		t.Fatal("slow subscriber did not receive an update")
	}
}

func TestSSEPayloadAndHistoryAreByteBounded(t *testing.T) {
	s := &Server{subscribers: map[chan sseMessage]struct{}{}}
	large := strings.Repeat("x", maxSSEPayloadBytes+1024)
	s.broadcast(map[string]any{"type": "scan.completed", "message": large})
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.history) != 1 || len(s.history[0].payload) > maxSSEPayloadBytes {
		t.Fatalf("oversized SSE payload was retained: history=%d bytes=%d", len(s.history), len(s.history[0].payload))
	}
	if !strings.Contains(string(s.history[0].payload), "refresh_required") {
		t.Fatalf("oversized SSE payload was not replaced with refresh marker: %s", s.history[0].payload)
	}
}

func TestAPIRequiresSessionCSRFAndRejectsUnvalidatedOptions(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	hash, err := auth.PasswordHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAdmin(ctx, store.Admin{Username: "admin", PasswordHash: hash, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(NewServer(a, s, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer h.Close()
	client := &http.Client{}
	resp, err := client.Get(h.URL + "/api/v1/jobs")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		resp.Body.Close()
		t.Fatalf("unauthenticated request returned %d", resp.StatusCode)
	}
	resp.Body.Close()
	loginRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	loginRequest.RemoteAddr = "127.0.0.1:1234"
	raw, _, err := auth.NewManager(s).Login(ctx, loginRequest, "correct horse battery staple", "", "")
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: auth.SessionCookie, Value: raw}
	request := func(method, path, body, csrf string) *http.Response {
		req, requestErr := http.NewRequest(method, h.URL+path, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.AddCookie(cookie)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		response, requestErr := client.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}
	resp = request(http.MethodPost, "/api/v1/jobs", `{}`, "")
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("missing CSRF token returned %d", resp.StatusCode)
	}
	resp.Body.Close()
	session, err := s.GetSession(ctx, digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	resp = request(http.MethodPost, "/api/v1/jobs", `{"nmap_args":"--script vuln"}`, session.CSRFToken)
	var failure map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&failure); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || failure["error"].(map[string]any)["code"] != "invalid_json" {
		t.Fatalf("arbitrary scanner option was accepted: status=%d body=%#v", resp.StatusCode, failure)
	}
}

func TestSensitiveJobMutationFailsClosedWhenAuditUnavailable(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	hash, err := auth.PasswordHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAdmin(ctx, store.Admin{Username: "admin", PasswordHash: hash, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	loginRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	loginRequest.RemoteAddr = "127.0.0.1:1234"
	raw, _, err := auth.NewManager(s).Login(ctx, loginRequest, "correct horse battery staple", "", "")
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.GetSession(ctx, digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_job_audit BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(NewServer(a, s, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer h.Close()
	req, err := http.NewRequest(http.MethodPost, h.URL+"/api/v1/jobs", strings.NewReader(`{"name":"audit-blocked","schedule":"0 * * * *","timezone":"UTC","targets":["127.0.0.1"],"tcp":{"ports":"1","mode":"connect"},"timeout":"1m","timing":"balanced","baseline_samples":1,"change_confirmations":1}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", session.CSRFToken)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("audit failure returned status %d", resp.StatusCode)
	}
	if _, err := s.GetJobByName(ctx, "audit-blocked"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("job committed despite audit failure: %v", err)
	}
}

func TestConsoleBaselineChangeIncidentFlow(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	base := model.Snapshot{Scopes: []model.Scope{{Target: "127.0.0.1", Protocol: "tcp", Ports: "1"}}, Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}}
	changed := model.Snapshot{Scopes: base.Scopes}
	sequence := &sequenceScanner{snapshots: []model.Snapshot{base, changed}}
	a.Scanner = sequence
	token, err := auth.NewManager(s).EnsureSetupToken(ctx)
	if err != nil || token == "" {
		t.Fatalf("setup token %q: %v", token, err)
	}
	h := httptest.NewServer(NewServer(a, s, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer h.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	request := func(method, path, body, csrf string) *http.Response {
		req, requestErr := http.NewRequest(method, h.URL+path, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return resp
	}
	resp := request(http.MethodPost, "/api/v1/setup", `{"token":"`+token+`","password":"correct horse battery staple"}`, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("setup status %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = request(http.MethodPost, "/api/v1/auth/login", `{"password":"correct horse battery staple"}`, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var loginResult struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResult); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp = request(http.MethodPost, "/api/v1/jobs", `{"name":"incident-flow","schedule":"0 * * * *","timezone":"UTC","targets":["127.0.0.1"],"tcp":{"ports":"1","mode":"connect"},"timeout":"1m","timing":"balanced","baseline_samples":1,"change_confirmations":1}`, loginResult.CSRF)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status %d", resp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if created.ID == "" {
		t.Fatal("missing job id")
	}
	run := func(expected int) {
		resp = request(http.MethodPost, "/api/v1/jobs/"+created.ID+"/run", "{}", loginResult.CSRF)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("run status %d", resp.StatusCode)
		}
		resp.Body.Close()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			scans, scanErr := s.ListJobScans(ctx, created.ID, 5)
			if scanErr != nil {
				t.Fatal(scanErr)
			}
			if len(scans) >= expected {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("scan did not finish")
	}
	run(1)
	resp = request(http.MethodGet, "/api/v1/jobs/"+created.ID, "", "")
	var job map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	baseline, _ := job["baseline"].(map[string]any)
	if baseline["status"] != "complete" {
		t.Fatalf("baseline not complete: %#v", baseline)
	}
	run(2)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp = request(http.MethodGet, "/api/v1/incidents", "", "")
		var incidents struct {
			Incidents []map[string]any `json:"incidents"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&incidents); err != nil {
			resp.Body.Close()
			t.Fatal(err)
		}
		resp.Body.Close()
		if len(incidents.Incidents) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	resp = request(http.MethodGet, "/api/v1/incidents", "", "")
	var incidents struct {
		Incidents []map[string]any `json:"incidents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&incidents); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(incidents.Incidents) != 1 {
		t.Fatal("incident did not open")
	}
	// Historical scan details must remain reproducible after the current
	// baseline is reset or replaced.
	scans, err := s.ListJobScans(ctx, created.ID, 5)
	if err != nil || len(scans) < 2 {
		t.Fatalf("scan history: %v (%d rows)", err, len(scans))
	}
	changedScan := scans[0]
	if changedScan.BaselineScanID == "" || len(changedScan.Changes) == 0 {
		t.Fatalf("changed scan did not persist its scan-time comparison: %#v", changedScan)
	}
	if _, err := s.ResetRuntime(ctx, created.ID, "incident-flow"); err != nil {
		t.Fatal(err)
	}
	resp = request(http.MethodGet, "/api/v1/jobs/"+created.ID+"/scans/"+changedScan.ID, "", "")
	var detail struct {
		Scan             map[string]any `json:"scan"`
		Changes          []model.Change `json:"changes"`
		ComparisonSource string         `json:"comparison_source"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if detail.ComparisonSource != "scan_time" || len(detail.Changes) != len(changedScan.Changes) {
		t.Fatalf("historical scan comparison changed after reset: source=%q changes=%d want=%d", detail.ComparisonSource, len(detail.Changes), len(changedScan.Changes))
	}
	if _, present := detail.Scan["snapshot"]; present {
		t.Fatal("scan detail eagerly returned the full snapshot")
	}
}

func TestHistoryEndpointsExposePaginationAndScopedResults(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.NewManager(s).EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(NewServer(a, s, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer h.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	setup := func(method, path, body, csrf string) *http.Response {
		req, requestErr := http.NewRequest(method, h.URL+path, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return resp
	}
	resp := setup(http.MethodPost, "/api/v1/setup", `{"token":"`+token+`","password":"correct horse battery staple"}`, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("setup status %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = setup(http.MethodPost, "/api/v1/auth/login", `{"password":"correct horse battery staple"}`, "")
	var login struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&login); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	record, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "paged-api", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced"}))
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := s.SaveScan(ctx, model.Scan{ID: string(rune('a' + i)), JobID: record.ID, JobRevision: 1, Job: record.Job.Name, StartedAt: when, FinishedAt: when, Status: "success", Snapshot: model.Snapshot{Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp", Ports: []model.PortState{{Port: i + 1, State: "open"}}}}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
			return []model.Event{{Type: "history", Job: record.Job.Name, CreatedAt: when}}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	resp = setup(http.MethodGet, "/api/v1/jobs/"+record.ID+"/scans?limit=2&offset=1", "", "")
	var scans struct {
		Scans      []model.ScanSummary `json:"scans"`
		Pagination map[string]any      `json:"pagination"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&scans); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(scans.Scans) != 2 || scans.Pagination["total"] != float64(3) || scans.Pagination["has_more"] != false {
		t.Fatalf("unexpected paginated scans: %#v", scans)
	}
	resp = setup(http.MethodGet, "/api/v1/jobs/"+record.ID+"/scans/a/results?limit=1", "", "")
	var results struct {
		Results    []model.Unit   `json:"results"`
		Pagination map[string]any `json:"pagination"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(results.Results) != 1 || results.Pagination["total"] != float64(1) {
		t.Fatalf("unexpected paginated results: %#v", results)
	}
	resp = setup(http.MethodGet, "/api/v1/events?job_id="+record.ID+"&limit=2&offset=1", "", "")
	var events struct {
		Events     []model.Event  `json:"events"`
		Pagination map[string]any `json:"pagination"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(events.Events) != 2 || events.Pagination["total"] != float64(3) {
		t.Fatalf("unexpected paginated events: %#v", events)
	}
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Units: []model.Unit{
			{Target: "127.0.0.1", Protocol: "tcp"},
			{Target: "127.0.0.2", Protocol: "tcp"},
		}}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	resp = setup(http.MethodGet, "/api/v1/jobs/"+record.ID+"/baseline?limit=1&offset=1", "", "")
	var baseline struct {
		Snapshot   *model.Snapshot `json:"snapshot"`
		Pagination map[string]any  `json:"pagination"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&baseline); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if baseline.Snapshot == nil || len(baseline.Snapshot.Units) != 1 || baseline.Pagination["total"] != float64(2) {
		t.Fatalf("unexpected paginated baseline: %#v", baseline)
	}
	_ = login
}

func TestLifecycleEndpointsRequireCurrentRevision(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	hash, err := auth.PasswordHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAdmin(ctx, store.Admin{Username: "admin", PasswordHash: hash, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(NewServer(a, s, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer h.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginRequest, _ := http.NewRequest(http.MethodPost, h.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"correct horse battery staple"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse, err := client.Do(loginRequest)
	if err != nil {
		t.Fatal(err)
	}
	var login struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(loginResponse.Body).Decode(&login); err != nil {
		loginResponse.Body.Close()
		t.Fatal(err)
	}
	loginResponse.Body.Close()
	if login.CSRF == "" {
		t.Fatal("missing CSRF token")
	}
	record, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "lifecycle-api", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced"}))
	if err != nil {
		t.Fatal(err)
	}
	request := func(path, body string) *http.Response {
		req, requestErr := http.NewRequest(http.MethodPost, h.URL+path, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", login.CSRF)
		response, requestErr := client.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}
	response := request("/api/v1/jobs/"+record.ID+"/pause", `{}`)
	if response.StatusCode != http.StatusBadRequest {
		response.Body.Close()
		t.Fatalf("missing revision returned %d", response.StatusCode)
	}
	response.Body.Close()
	changed := record.Job
	changed.Timeout = config.Duration(2 * time.Minute)
	updated, _, err := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	response = request("/api/v1/jobs/"+record.ID+"/pause", fmt.Sprintf(`{"revision":%d}`, record.Revision))
	if response.StatusCode != http.StatusConflict {
		response.Body.Close()
		t.Fatalf("stale pause returned %d", response.StatusCode)
	}
	response.Body.Close()
	response = request("/api/v1/jobs/"+record.ID+"/pause", fmt.Sprintf(`{"revision":%d}`, updated.Revision))
	if response.StatusCode != http.StatusNoContent {
		response.Body.Close()
		t.Fatalf("current pause returned %d", response.StatusCode)
	}
	response.Body.Close()
}

func TestNotificationAPIIsWriteOnlyAndUsesOptimisticConcurrency(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	hash, err := auth.PasswordHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAdmin(ctx, store.Admin{Username: "admin", PasswordHash: hash, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	deploymentURL := "generic://localhost/deployment?disabletls=yes&template=json"
	cfg := &config.Config{Version: 1, Database: database, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}, Notifications: config.Notifications{URLs: []string{deploymentURL}}}
	a, err := app.New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(NewServer(a, s, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer h.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	request := func(method, path, body, csrf string) *http.Response {
		req, requestErr := http.NewRequest(method, h.URL+path, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		response, requestErr := client.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}
	response := request(http.MethodPost, "/api/v1/auth/login", `{"password":"correct horse battery staple"}`, "")
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("login status %d", response.StatusCode)
	}
	var login struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&login); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	managedURL := "generic://localhost/managed?disabletls=yes&template=json"
	response = request(http.MethodPost, "/api/v1/notifications/destinations", `{"name":"Operations","url":"`+managedURL+`","password":"correct horse battery staple"}`, login.CSRF)
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("create status %d: %s", response.StatusCode, body)
	}
	createdBody, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if strings.Contains(string(createdBody), managedURL) || strings.Contains(string(createdBody), `"url"`) {
		t.Fatalf("create response exposed URL: %s", createdBody)
	}
	var created notify.DestinationView
	if err := json.Unmarshal(createdBody, &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Revision != 1 || created.Source != "web" {
		t.Fatalf("unexpected created destination: %#v", created)
	}
	var ciphertext []byte
	if err := s.DB.QueryRow(`SELECT ciphertext FROM managed_notifications WHERE id=?`, created.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ciphertext), managedURL) {
		t.Fatal("managed URL was stored in plaintext")
	}
	response = request(http.MethodGet, "/api/v1/notifications/destinations", "", "")
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(string(body), managedURL) || strings.Contains(string(body), deploymentURL) || strings.Contains(string(body), `"url"`) {
		t.Fatalf("notification listing leaked URL: status=%d body=%s", response.StatusCode, body)
	}
	if !strings.Contains(string(body), `"source":"deployment"`) || !strings.Contains(string(body), `"source":"web"`) {
		t.Fatalf("listing did not retain both destination sources: %s", body)
	}
	response = request(http.MethodPut, "/api/v1/notifications/destinations/"+created.ID, `{"name":"Operations","password":"correct horse battery staple","revision":99}`, login.CSRF)
	if response.StatusCode != http.StatusConflict {
		response.Body.Close()
		t.Fatalf("stale notification update status %d", response.StatusCode)
	}
	response.Body.Close()
	secretURL := "unknown://secret-token@example.invalid/path"
	response = request(http.MethodPost, "/api/v1/notifications/destinations", `{"name":"Bad","url":"`+secretURL+`","password":"correct horse battery staple"}`, login.CSRF)
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || strings.Contains(string(body), "secret-token") {
		t.Fatalf("invalid URL response leaked input: status=%d body=%s", response.StatusCode, body)
	}
	response = request(http.MethodPost, "/api/v1/notifications/destinations", `{"name":"Wrong password","url":"`+managedURL+`","password":"incorrect password"}`, login.CSRF)
	if response.StatusCode != http.StatusUnauthorized {
		response.Body.Close()
		t.Fatalf("wrong password status %d", response.StatusCode)
	}
	response.Body.Close()
	response = request(http.MethodPut, "/api/v1/notifications/destinations/"+created.ID, `{"name":"Operations","password":"correct horse battery staple","revision":1,"enabled":false}`, login.CSRF)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("disable status %d: %s", response.StatusCode, body)
	}
	response.Body.Close()
	rows, err := s.DB.Query(`SELECT detail FROM security_audit WHERE action LIKE 'notifications.%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, managedURL) || strings.Contains(detail, "secret-token") {
			t.Fatalf("notification URL leaked into audit detail: %s", detail)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
