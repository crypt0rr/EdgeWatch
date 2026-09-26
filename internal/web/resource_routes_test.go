package web

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"modernc.org/sqlite"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// resourceLookups counts the read-pool statements behind Store.GetJob,
// Store.GetScanSummary and Store.GetScan, keyed by the requested ID. It lets
// the route tests prove that a job or scan named in the path is loaded once
// per request, and it can fail those lookups to exercise each route's store
// error response. Reads inside write transactions use the writer pool and are
// deliberately not counted: revision-guarded writes re-read on purpose.
type resourceLookups struct {
	mu            sync.Mutex
	jobs          map[string]int
	scanSummaries map[string]int
	scans         map[string]int
	failJobs      bool
	failSummaries bool
	failScans     bool
}

var errInjectedLookup = errors.New("injected lookup failure")

func (l *resourceLookups) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.jobs, l.scanSummaries, l.scans = map[string]int{}, map[string]int{}, map[string]int{}
	l.failJobs, l.failSummaries, l.failScans = false, false, false
}

func (l *resourceLookups) total(counts func(*resourceLookups) map[string]int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	sum := 0
	for _, count := range counts(l) {
		sum += count
	}
	return sum
}

func (l *resourceLookups) jobLookups() int {
	return l.total(func(l *resourceLookups) map[string]int { return l.jobs })
}

func (l *resourceLookups) scanSummaryLookups() int {
	return l.total(func(l *resourceLookups) map[string]int { return l.scanSummaries })
}

func (l *resourceLookups) scanLookups() int {
	return l.total(func(l *resourceLookups) map[string]int { return l.scans })
}

// observe records a lookup and reports whether it must fail.
func (l *resourceLookups) observe(query string, args []driver.NamedValue) error {
	query = strings.TrimSpace(query)
	id := ""
	if len(args) > 0 {
		id, _ = args[0].Value.(string)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case strings.HasSuffix(query, "FROM jobs WHERE id=? AND tenant_id=?"):
		l.jobs[id]++
		if l.failJobs {
			return errInjectedLookup
		}
	case strings.HasSuffix(query, "baseline_config_hash FROM scans WHERE id=?"):
		l.scanSummaries[id]++
		if l.failSummaries {
			return errInjectedLookup
		}
	case strings.HasSuffix(query, "snapshot_json FROM scans WHERE id=?"):
		l.scans[id]++
		if l.failScans {
			return errInjectedLookup
		}
	}
	return nil
}

type lookupCountingConnector struct {
	driver.Connector
	lookups *resourceLookups
}

func (c lookupCountingConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &lookupCountingConn{Conn: conn, lookups: c.lookups}, nil
}

type lookupCountingConn struct {
	driver.Conn
	lookups *resourceLookups
}

func (c *lookupCountingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	if err := c.lookups.observe(query, args); err != nil {
		return nil, err
	}
	return queryer.QueryContext(ctx, query, args)
}

func (c *lookupCountingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return execer.ExecContext(ctx, query, args)
}

func (c *lookupCountingConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if preparer, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return preparer.PrepareContext(ctx, query)
	}
	return c.Prepare(query)
}

func (c *lookupCountingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if beginner, ok := c.Conn.(driver.ConnBeginTx); ok {
		return beginner.BeginTx(ctx, opts)
	}
	return nil, errors.New("SQLite driver does not support BeginTx")
}

func (c *lookupCountingConn) ResetSession(ctx context.Context) error {
	if resetter, ok := c.Conn.(driver.SessionResetter); ok {
		return resetter.ResetSession(ctx)
	}
	return nil
}

func (c *lookupCountingConn) IsValid() bool {
	if validator, ok := c.Conn.(driver.Validator); ok {
		return validator.IsValid()
	}
	return true
}

// countResourceLookups routes the store's read pool through a counting
// connection for the rest of the test.
func countResourceLookups(t *testing.T, db *store.Store) *resourceLookups {
	t.Helper()
	connector, err := sqlite.NewConnector(db.Path)
	if err != nil {
		t.Fatal(err)
	}
	lookups := &resourceLookups{}
	lookups.reset()
	counted := sql.OpenDB(lookupCountingConnector{Connector: connector, lookups: lookups})
	previous := db.ReadDB
	db.ReadDB = counted
	t.Cleanup(func() {
		db.ReadDB = previous
		_ = counted.Close()
	})
	return lookups
}

func wantErrorBody(t *testing.T, code, message string, details any) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"error": map[string]any{"code": code, "message": message, "details": details}})
	if err != nil {
		t.Fatal(err)
	}
	return string(body) + "\n"
}

type resourceRouteFixture struct {
	server    *Server
	db        *store.Store
	lookups   *resourceLookups
	active    store.JobRecord
	archived  store.JobRecord
	scan      model.Scan
	legacy    model.Scan
	cookies   map[string]string
	csrf      map[string]string
	hostAddr  string
	missingID string
	badID     string
}

func newResourceRouteFixture(t *testing.T) *resourceRouteFixture {
	t.Helper()
	ctx := context.Background()
	server, db, _ := newUsersTestServer(t)
	// Route tests never contact a public registry.
	server.RDAP = nil
	fixture := &resourceRouteFixture{server: server, db: db, cookies: map[string]string{}, csrf: map[string]string{}, hostAddr: "192.0.2.10", missingID: "00000000-0000-4000-8000-000000000000", badID: "not a job'--"}
	newJob := func(name string) store.JobRecord {
		record, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{
			Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{fixture.hostAddr},
			TCP: &config.Protocol{Ports: "443", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced",
		}))
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	fixture.active = newJob("resolve-once-active")
	fixture.archived = newJob("resolve-once-archived")
	if err := db.SetJobArchived(ctx, fixture.archived.ID, true); err != nil {
		t.Fatal(err)
	}
	var err error
	if fixture.archived, err = db.GetJob(ctx, fixture.archived.ID); err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC()
	units := []model.Unit{{Target: fixture.hostAddr, Protocol: "tcp", Addresses: []string{fixture.hostAddr}, Ports: []model.PortState{{Port: 443, State: "open"}}}}
	fixture.scan = model.Scan{ID: "resolve-once-scan", JobID: fixture.active.ID, JobRevision: fixture.active.Revision, Job: fixture.active.Job.Name, StartedAt: when, FinishedAt: when, Status: "success", ConfigHash: fixture.active.Job.SecurityHash(), Snapshot: model.Snapshot{Units: units}}
	fixture.legacy = model.Scan{ID: "resolve-once-legacy", Job: "resolve-once-legacy-job", StartedAt: when.Add(-time.Hour), FinishedAt: when.Add(-time.Hour), Status: "success", Snapshot: model.Snapshot{Units: units}}
	for _, scan := range []model.Scan{fixture.scan, fixture.legacy} {
		if err := db.SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := auth.PasswordHash("operator account password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(ctx, store.User{Username: "operator", DisplayName: "Operator", Role: store.RoleOperator, PasswordHash: hash, Enabled: true}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	for username, password := range map[string]string{"admin": "administrator password", "operator": "operator account password"} {
		raw, _, loginErr := server.Auth.LoginAs(ctx, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil), username, password, "", "")
		if loginErr != nil {
			t.Fatal(loginErr)
		}
		session, sessionErr := db.GetSession(ctx, digest(raw))
		if sessionErr != nil {
			t.Fatal(sessionErr)
		}
		fixture.cookies[username], fixture.csrf[username] = raw, session.CSRFToken
	}
	fixture.lookups = countResourceLookups(t, db)
	return fixture
}

// serve sends an authenticated request through the API router, so route
// authorization, resource resolution and dispatch are all exercised.
func (f *resourceRouteFixture) serve(user, method, target, body string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	var request *http.Request
	if reader != nil {
		request = httptest.NewRequest(method, "/api/v1"+target, reader)
		request.Header.Set("Content-Type", "application/json")
	} else {
		request = httptest.NewRequest(method, "/api/v1"+target, nil)
	}
	request.RemoteAddr = "127.0.0.1:9000"
	request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: f.cookies[user]})
	if method != http.MethodGet {
		request.Header.Set("X-CSRF-Token", f.csrf[user])
	}
	recorder := httptest.NewRecorder()
	f.server.api(recorder, request)
	return recorder
}

func (f *resourceRouteFixture) expand(path, jobID, scanID string) string {
	return strings.NewReplacer("{job}", url.PathEscape(jobID), "{scan}", url.PathEscape(scanID), "{host}", f.hostAddr).Replace(path)
}

// jobRouteCase describes one /jobs/{id}/* route. Existing jobs use the active
// job unless useArchived is set.
type jobRouteCase struct {
	name        string
	method      string
	path        string
	body        string
	useArchived bool
	// resolved routes load the job once in the router. The lifecycle writes
	// and the baseline host RDAP route never loaded the job record.
	resolved       bool
	existingStatus int
	existingSubstr string
	// scanSummaries is the number of scan summary lookups for an existing job.
	scanSummaries int
	// missingStatus and missingBody answer both a missing and a malformed ID.
	missingStatus int
	missingBody   string
	// failureStatus and failureBody answer a store failure of the job lookup.
	failureStatus int
	failureBody   string
}

func jobRouteCases(t *testing.T, f *resourceRouteFixture) []jobRouteCase {
	t.Helper()
	jobNotFound := wantErrorBody(t, "not_found", "job not found", nil)
	internal := wantErrorBody(t, "store", "internal server error", nil)
	jobDetail := wantErrorBody(t, "store", "job detail could not be loaded", nil)
	hostDetail := wantErrorBody(t, "store", "host detail could not be loaded", nil)
	stale := fromConfig(f.active.Job)
	stale.Revision = f.active.Revision + 50
	staleBody, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	incident := `{"key":"port|192.0.2.10|tcp|443","expected_change":{"key":"port|192.0.2.10|tcp|443","kind":"port"}}`
	return []jobRouteCase{
		{name: "get job", method: http.MethodGet, path: "/jobs/{job}", resolved: true, existingStatus: http.StatusOK, existingSubstr: `"name":"resolve-once-active"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusNotFound, failureBody: jobNotFound},
		{name: "update job", method: http.MethodPut, path: "/jobs/{job}", body: string(staleBody), resolved: true, existingStatus: http.StatusConflict, existingSubstr: `"job was modified; reload before saving"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: internal},
		{name: "permanent delete", method: http.MethodDelete, path: "/jobs/{job}?permanent=true", body: `{"confirm_name":"wrong"}`, resolved: true, existingStatus: http.StatusBadRequest, existingSubstr: `"confirmation_required"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusNotFound, failureBody: jobNotFound},
		{name: "archive by delete", method: http.MethodDelete, path: "/jobs/{job}", body: `{"revision":999}`, existingStatus: http.StatusConflict, existingSubstr: `"job was modified; reload before changing its lifecycle"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound},
		{name: "archive", method: http.MethodPost, path: "/jobs/{job}/archive", body: `{"revision":999}`, existingStatus: http.StatusConflict, existingSubstr: `"conflict"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound},
		{name: "restore", method: http.MethodPost, path: "/jobs/{job}/restore", body: `{"revision":999}`, useArchived: true, existingStatus: http.StatusConflict, existingSubstr: `"conflict"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound},
		{name: "pause", method: http.MethodPost, path: "/jobs/{job}/pause", body: `{"revision":999}`, existingStatus: http.StatusConflict, existingSubstr: `"conflict"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound},
		{name: "resume", method: http.MethodPost, path: "/jobs/{job}/resume", body: `{"revision":999}`, existingStatus: http.StatusConflict, existingSubstr: `"conflict"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound},
		{name: "run", method: http.MethodPost, path: "/jobs/{job}/run", useArchived: true, resolved: true, existingStatus: http.StatusConflict, existingSubstr: `"archived jobs cannot run"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusNotFound, failureBody: jobNotFound},
		{name: "scan cycle", method: http.MethodGet, path: "/jobs/{job}/scan-cycle", resolved: true, existingStatus: http.StatusOK, existingSubstr: `"cycle":null`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: internal},
		{name: "discard scan cycle", method: http.MethodDelete, path: "/jobs/{job}/scan-cycle/no-such-cycle", resolved: true, existingStatus: http.StatusNotFound, existingSubstr: `"scan cycle not found"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: internal},
		{name: "job scans", method: http.MethodGet, path: "/jobs/{job}/scans", resolved: true, existingStatus: http.StatusOK, existingSubstr: `"resolve-once-scan"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: internal},
		{name: "latest successful scan", method: http.MethodGet, path: "/jobs/{job}/scans/latest-successful", resolved: true, existingStatus: http.StatusOK, existingSubstr: `"resolve-once-scan"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusNotFound, failureBody: jobNotFound},
		{name: "job scan", method: http.MethodGet, path: "/jobs/{job}/scans/{scan}", resolved: true, scanSummaries: 1, existingStatus: http.StatusOK, existingSubstr: `"current_security_hash"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: internal},
		{name: "job scan results", method: http.MethodGet, path: "/jobs/{job}/scans/{scan}/results", resolved: true, scanSummaries: 1, existingStatus: http.StatusOK, existingSubstr: `"results"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: internal},
		{name: "job scan hosts", method: http.MethodGet, path: "/jobs/{job}/scans/{scan}/hosts", resolved: true, scanSummaries: 1, existingStatus: http.StatusOK, existingSubstr: `"job":"resolve-once-active"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: internal},
		{name: "job scan host", method: http.MethodGet, path: "/jobs/{job}/scans/{scan}/hosts/{host}", resolved: true, scanSummaries: 1, existingStatus: http.StatusOK, existingSubstr: `"job":"resolve-once-active"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: jobDetail},
		{name: "job scan host RDAP", method: http.MethodGet, path: "/jobs/{job}/scans/{scan}/hosts/{host}/rdap", resolved: true, scanSummaries: 1, existingStatus: http.StatusOK, existingSubstr: `"status":"unavailable"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: hostDetail},
		{name: "job scan changes", method: http.MethodGet, path: "/jobs/{job}/scans/{scan}/changes", resolved: true, scanSummaries: 1, existingStatus: http.StatusOK, existingSubstr: `"comparison_state"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: internal},
		{name: "baseline hosts", method: http.MethodGet, path: "/jobs/{job}/baseline/hosts", resolved: true, existingStatus: http.StatusOK, existingSubstr: `"job":"resolve-once-active"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: internal},
		{name: "baseline host", method: http.MethodGet, path: "/jobs/{job}/baseline/hosts/{host}", resolved: true, existingStatus: http.StatusNotFound, existingSubstr: `"baseline host not found"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: internal},
		{name: "baseline host RDAP", method: http.MethodGet, path: "/jobs/{job}/baseline/hosts/{host}/rdap", existingStatus: http.StatusNotFound, existingSubstr: `"baseline host not found"`, missingStatus: http.StatusNotFound, missingBody: wantErrorBody(t, "not_found", "baseline host not found", nil)},
		{name: "incidents", method: http.MethodGet, path: "/jobs/{job}/incidents", resolved: true, existingStatus: http.StatusOK, existingSubstr: `"job":"resolve-once-active"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusNotFound, failureBody: jobNotFound},
		{name: "accept incident", method: http.MethodPost, path: "/jobs/{job}/incidents/accept", body: incident, resolved: true, existingStatus: http.StatusConflict, existingSubstr: `"baseline_not_ready"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: internal},
		{name: "suppress incident", method: http.MethodPost, path: "/jobs/{job}/incidents/suppress", body: incident, resolved: true, existingStatus: http.StatusNotFound, existingSubstr: `"incident is no longer active"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusInternalServerError, failureBody: internal},
		{name: "events", method: http.MethodGet, path: "/jobs/{job}/events", resolved: true, existingStatus: http.StatusOK, existingSubstr: `"events"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusNotFound, failureBody: jobNotFound},
		{name: "baseline", method: http.MethodGet, path: "/jobs/{job}/baseline", resolved: true, existingStatus: http.StatusOK, existingSubstr: `"job":"resolve-once-active"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusNotFound, failureBody: jobNotFound},
		{name: "reset baseline", method: http.MethodPost, path: "/jobs/{job}/baseline/reset", body: `{"expected_baseline_scan_id":"stale-baseline"}`, resolved: true, existingStatus: http.StatusConflict, existingSubstr: `"baseline_conflict"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusNotFound, failureBody: jobNotFound},
		{name: "approve baseline", method: http.MethodPost, path: "/jobs/{job}/baseline/approve", body: `{"scan_id":"no-such-scan"}`, resolved: true, existingStatus: http.StatusBadRequest, existingSubstr: `"invalid_scan"`, missingStatus: http.StatusNotFound, missingBody: jobNotFound, failureStatus: http.StatusNotFound, failureBody: jobNotFound},
	}
}

func TestJobRoutesResolveTheJobOnceAndKeepTheirResponses(t *testing.T) {
	f := newResourceRouteFixture(t)
	for _, tc := range jobRouteCases(t, f) {
		t.Run(tc.name, func(t *testing.T) {
			wantLookups := 0
			if tc.resolved {
				wantLookups = 1
			}
			existing := f.active
			if tc.useArchived {
				existing = f.archived
			}
			f.lookups.reset()
			response := f.serve("admin", tc.method, f.expand(tc.path, existing.ID, f.scan.ID), tc.body)
			if response.Code != tc.existingStatus || !strings.Contains(response.Body.String(), tc.existingSubstr) {
				t.Fatalf("existing job = %d, want %d containing %s: %s", response.Code, tc.existingStatus, tc.existingSubstr, response.Body.String())
			}
			if got := f.lookups.jobLookups(); got != wantLookups {
				t.Fatalf("existing job lookups = %d, want %d", got, wantLookups)
			}
			if got := f.lookups.scanSummaryLookups(); got != tc.scanSummaries {
				t.Fatalf("existing job scan summary lookups = %d, want %d", got, tc.scanSummaries)
			}

			for label, id := range map[string]string{"missing": f.missingID, "malformed": f.badID} {
				f.lookups.reset()
				response := f.serve("admin", tc.method, f.expand(tc.path, id, f.scan.ID), tc.body)
				if response.Code != tc.missingStatus || response.Body.String() != tc.missingBody {
					t.Fatalf("%s job = %d %q, want %d %q", label, response.Code, response.Body.String(), tc.missingStatus, tc.missingBody)
				}
				if got := f.lookups.jobLookups(); got != wantLookups {
					t.Fatalf("%s job lookups = %d, want %d", label, got, wantLookups)
				}
				if got := f.lookups.scanSummaryLookups(); got != 0 {
					t.Fatalf("%s job loaded a scan summary %d times", label, got)
				}
			}

			if !tc.resolved {
				return
			}
			f.lookups.reset()
			f.lookups.failJobs = true
			response = f.serve("admin", tc.method, f.expand(tc.path, existing.ID, f.scan.ID), tc.body)
			if response.Code != tc.failureStatus || response.Body.String() != tc.failureBody {
				t.Fatalf("failed job lookup = %d %q, want %d %q", response.Code, response.Body.String(), tc.failureStatus, tc.failureBody)
			}
			if got := f.lookups.jobLookups(); got != 1 {
				t.Fatalf("failed job lookup attempts = %d, want 1", got)
			}
		})
	}
}

// Request validation that ran before the job lookup still answers first, so
// a malformed request for a missing job is rejected as malformed, and the
// in-handler administrator check still answers before the lookup.
func TestJobRoutesValidateRequestsBeforeResolvingTheJob(t *testing.T) {
	f := newResourceRouteFixture(t)
	for _, tc := range []struct {
		name, user, method, path, body string
		status                         int
		body200                        string
	}{
		{"update without revision", "admin", http.MethodPut, "/jobs/{job}", `{}`, http.StatusBadRequest, wantErrorBody(t, "revision_required", "job revision is required", map[string]string{"revision": "job revision is required"})},
		{"update with invalid duration", "admin", http.MethodPut, "/jobs/{job}", `{"revision":1,"timeout":"soon"}`, http.StatusBadRequest, ""},
		{"permanent delete by operator", "operator", http.MethodDelete, "/jobs/{job}?permanent=true", `{"confirm_name":"x"}`, http.StatusForbidden, wantErrorBody(t, "forbidden", "your account is not allowed to perform this action", map[string]string{"permission": auth.PermissionJobsDelete})},
		{"permanent delete with invalid body", "admin", http.MethodDelete, "/jobs/{job}?permanent=true", `not json`, http.StatusBadRequest, ""},
		{"archive without revision", "admin", http.MethodPost, "/jobs/{job}/archive", `{}`, http.StatusBadRequest, wantErrorBody(t, "revision_required", "job revision is required", nil)},
		{"pause without revision", "admin", http.MethodPost, "/jobs/{job}/pause", `{}`, http.StatusBadRequest, wantErrorBody(t, "revision_required", "job revision is required", nil)},
		{"accept without key", "admin", http.MethodPost, "/jobs/{job}/incidents/accept", `{}`, http.StatusBadRequest, wantErrorBody(t, "key_required", "incident key is required", map[string]string{"key": "incident key is required"})},
		{"suppress without reviewed change", "admin", http.MethodPost, "/jobs/{job}/incidents/suppress", `{"key":"k"}`, http.StatusBadRequest, wantErrorBody(t, "expected_change_required", "the reviewed incident change is required; refresh before retrying", map[string]string{"expected_change": "reload the incident before confirming this action"})},
		{"reset with invalid body", "admin", http.MethodPost, "/jobs/{job}/baseline/reset", `{"expected_baseline_scan_id":5}`, http.StatusBadRequest, ""},
		{"approve with invalid body", "admin", http.MethodPost, "/jobs/{job}/baseline/approve", `not json`, http.StatusBadRequest, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, id := range []string{f.missingID, f.badID} {
				f.lookups.reset()
				response := f.serve(tc.user, tc.method, f.expand(tc.path, id, ""), tc.body)
				if response.Code != tc.status || (tc.body200 != "" && response.Body.String() != tc.body200) {
					t.Fatalf("%s = %d %q, want %d %q", id, response.Code, response.Body.String(), tc.status, tc.body200)
				}
				if got := f.lookups.jobLookups(); got != 0 {
					t.Fatalf("%s loaded the job %d times before rejecting the request", id, got)
				}
			}
		})
	}
	// The API authorizes a permanent delete before the router runs. The job
	// router repeats the administrator check ahead of the lookup, so a direct
	// operator call also learns nothing about the job.
	operator := store.Session{UserID: "operator", Username: "operator", Role: store.RoleOperator}
	for _, id := range []string{f.missingID, f.active.ID} {
		f.lookups.reset()
		request := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs/"+id+"?permanent=true", strings.NewReader(`{"confirm_name":"x"}`))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		f.server.jobRoute(recorder, request, operator, id)
		if want := wantErrorBody(t, "forbidden", "only an administrator can permanently delete a job", map[string]string{"permission": auth.PermissionJobsDelete}); recorder.Code != http.StatusForbidden || recorder.Body.String() != want {
			t.Fatalf("operator permanent delete of %s = %d %q, want 403 %q", id, recorder.Code, recorder.Body.String(), want)
		}
		if got := f.lookups.jobLookups(); got != 0 {
			t.Fatalf("operator permanent delete loaded the job %d times", got)
		}
	}

	// Paths that name no job, or no known sub-route, keep their router
	// responses and never load a job.
	for _, tc := range []struct {
		rest string
		body string
	}{
		{"", wantErrorBody(t, "not_found", "job not found", nil)},
		{f.active.ID + "/no-such-route", wantErrorBody(t, "not_found", "job endpoint not found", nil)},
		{f.missingID + "/scans/" + f.scan.ID + "/no-such-route", wantErrorBody(t, "not_found", "job endpoint not found", nil)},
	} {
		f.lookups.reset()
		recorder := httptest.NewRecorder()
		f.server.jobRoute(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+tc.rest, nil), store.Session{}, tc.rest)
		if recorder.Code != http.StatusNotFound || recorder.Body.String() != tc.body {
			t.Fatalf("job route %q = %d %q, want 404 %q", tc.rest, recorder.Code, recorder.Body.String(), tc.body)
		}
		if got := f.lookups.jobLookups(); got != 0 {
			t.Fatalf("job route %q loaded the job %d times", tc.rest, got)
		}
	}
}

type scanRouteCase struct {
	name string
	path string
	// legacy runs the case against the scan without a job ID.
	legacy         bool
	existingStatus int
	existingSubstr string
	// Lookups of the scan (summary or full record) and of its owning job for
	// an existing scan.
	summaries, scans, jobs int
	missingBody            string
	// Responses when the scan lookup, or the owning job lookup, fails.
	scanFailureStatus int
	scanFailureBody   string
	jobFailureBody    string
}

func TestScanRoutesResolveTheScanOnceAndKeepTheirResponses(t *testing.T) {
	f := newResourceRouteFixture(t)
	scanNotFound := wantErrorBody(t, "not_found", "scan not found", nil)
	internal := wantErrorBody(t, "store", "internal server error", nil)
	scanDetail := wantErrorBody(t, "store", "scan detail could not be loaded", nil)
	for _, tc := range []scanRouteCase{
		{name: "full scan", path: "/scans/{scan}", existingStatus: http.StatusOK, existingSubstr: `"snapshot"`, scans: 1, missingBody: scanNotFound, scanFailureStatus: http.StatusNotFound, scanFailureBody: scanNotFound},
		{name: "legacy full scan", path: "/scans/{scan}", legacy: true, existingStatus: http.StatusOK, existingSubstr: `"snapshot"`, scans: 1, missingBody: scanNotFound, scanFailureStatus: http.StatusNotFound, scanFailureBody: scanNotFound},
		{name: "summary", path: "/scans/{scan}/summary", existingStatus: http.StatusOK, existingSubstr: `"resolve-once-scan"`, summaries: 1, missingBody: scanNotFound, scanFailureStatus: http.StatusInternalServerError, scanFailureBody: internal},
		{name: "hosts", path: "/scans/{scan}/hosts", existingStatus: http.StatusOK, existingSubstr: `"job":"resolve-once-active"`, summaries: 1, jobs: 1, missingBody: scanNotFound, scanFailureStatus: http.StatusInternalServerError, scanFailureBody: internal, jobFailureBody: internal},
		{name: "legacy hosts", path: "/scans/{scan}/hosts", legacy: true, existingStatus: http.StatusOK, existingSubstr: `"job":"resolve-once-legacy-job"`, summaries: 1, missingBody: scanNotFound, scanFailureStatus: http.StatusInternalServerError, scanFailureBody: internal},
		{name: "host", path: "/scans/{scan}/hosts/{host}", existingStatus: http.StatusOK, existingSubstr: `"job":"resolve-once-active"`, summaries: 1, jobs: 1, missingBody: scanNotFound, scanFailureStatus: http.StatusInternalServerError, scanFailureBody: scanDetail, jobFailureBody: wantErrorBody(t, "store", "job detail could not be loaded", nil)},
		{name: "legacy host", path: "/scans/{scan}/hosts/{host}", legacy: true, existingStatus: http.StatusOK, existingSubstr: `"job":"resolve-once-legacy-job"`, summaries: 1, missingBody: scanNotFound, scanFailureStatus: http.StatusInternalServerError, scanFailureBody: scanDetail},
		{name: "host RDAP", path: "/scans/{scan}/hosts/{host}/rdap", existingStatus: http.StatusOK, existingSubstr: `"status":"unavailable"`, summaries: 1, jobs: 1, missingBody: scanNotFound, scanFailureStatus: http.StatusInternalServerError, scanFailureBody: scanDetail, jobFailureBody: wantErrorBody(t, "store", "host detail could not be loaded", nil)},
		{name: "legacy host RDAP", path: "/scans/{scan}/hosts/{host}/rdap", legacy: true, existingStatus: http.StatusOK, existingSubstr: `"status":"unavailable"`, summaries: 1, missingBody: scanNotFound, scanFailureStatus: http.StatusInternalServerError, scanFailureBody: scanDetail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existing := f.scan
			if tc.legacy {
				existing = f.legacy
			}
			f.lookups.reset()
			response := f.serve("admin", http.MethodGet, f.expand(tc.path, "", existing.ID), "")
			if response.Code != tc.existingStatus || !strings.Contains(response.Body.String(), tc.existingSubstr) {
				t.Fatalf("existing scan = %d, want %d containing %s: %s", response.Code, tc.existingStatus, tc.existingSubstr, response.Body.String())
			}
			if summaries, scans, jobs := f.lookups.scanSummaryLookups(), f.lookups.scanLookups(), f.lookups.jobLookups(); summaries != tc.summaries || jobs != tc.jobs || (tc.scans > 0 && scans != tc.scans) {
				t.Fatalf("existing scan lookups: summaries=%d scans=%d jobs=%d, want %d %d %d", summaries, scans, jobs, tc.summaries, tc.scans, tc.jobs)
			}

			for label, id := range map[string]string{"missing": "no-such-scan", "malformed": "not a scan'--"} {
				f.lookups.reset()
				response := f.serve("admin", http.MethodGet, f.expand(tc.path, "", id), "")
				if response.Code != http.StatusNotFound || response.Body.String() != tc.missingBody {
					t.Fatalf("%s scan = %d %q, want 404 %q", label, response.Code, response.Body.String(), tc.missingBody)
				}
				if got := f.lookups.scanSummaryLookups() + f.lookups.scanLookups(); got != 1 {
					t.Fatalf("%s scan lookups = %d, want 1", label, got)
				}
				if got := f.lookups.jobLookups(); got != 0 {
					t.Fatalf("%s scan loaded a job %d times", label, got)
				}
			}

			f.lookups.reset()
			f.lookups.failSummaries, f.lookups.failScans = true, true
			response = f.serve("admin", http.MethodGet, f.expand(tc.path, "", existing.ID), "")
			if response.Code != tc.scanFailureStatus || response.Body.String() != tc.scanFailureBody {
				t.Fatalf("failed scan lookup = %d %q, want %d %q", response.Code, response.Body.String(), tc.scanFailureStatus, tc.scanFailureBody)
			}
			if tc.jobFailureBody == "" {
				return
			}
			f.lookups.reset()
			f.lookups.failJobs = true
			response = f.serve("admin", http.MethodGet, f.expand(tc.path, "", existing.ID), "")
			if response.Code != http.StatusInternalServerError || response.Body.String() != tc.jobFailureBody {
				t.Fatalf("failed owning job lookup = %d %q, want 500 %q", response.Code, response.Body.String(), tc.jobFailureBody)
			}
		})
	}

	// Cancellation acts on the in-memory active scan and never loads a stored
	// scan record, so it keeps answering an inactive or unknown ID with 409.
	for _, id := range []string{f.scan.ID, "no-such-scan"} {
		f.lookups.reset()
		response := f.serve("admin", http.MethodPost, "/scans/"+id+"/cancel", "")
		if want := wantErrorBody(t, "scan_not_active", "scan is no longer active", nil); response.Code != http.StatusConflict || response.Body.String() != want {
			t.Fatalf("cancel %s = %d %q, want 409 %q", id, response.Code, response.Body.String(), want)
		}
		if got := f.lookups.scanSummaryLookups() + f.lookups.scanLookups(); got != 0 {
			t.Fatalf("cancel %s loaded the scan %d times", id, got)
		}
	}
}
