package web

import (
	"context"
	"encoding/json"
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
	req, _ := http.NewRequest(http.MethodPost, h.URL+"/api/v1/jobs", strings.NewReader(`{"name":"local","schedule":"0 * * * *","timezone":"UTC","targets":["127.0.0.1"],"tcp":{"ports":"1","mode":"connect"},"timeout":"1m","timing":"balanced","baseline_samples":1,"change_confirmations":1,"max_expanded_hosts":256}`))
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
		ID string `json:"id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == "" {
		t.Fatal("missing job id")
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
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("incident did not open")
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
		Scans      []model.Scan   `json:"scans"`
		Pagination map[string]any `json:"pagination"`
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
	_ = login
}
