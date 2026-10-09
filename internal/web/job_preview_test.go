package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type previewResponse struct {
	Job      jobPayload          `json:"job"`
	Estimate config.WorkEstimate `json:"scan_estimate"`
	Budget   struct {
		Exceeded         bool  `json:"exceeded"`
		EstimatedProbes  int64 `json:"estimated_probes"`
		Limit            int64 `json:"limit"`
		ApprovalWouldFit bool  `json:"approval_would_fit"`
	} `json:"scan_budget"`
	Warnings []jobPreviewWarning `json:"warnings"`
}

func validPreviewPayload(name string) jobPayload {
	return jobPayload{
		Name: name, Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.10"}, MaxExpandedHosts: 256,
		TCP:    &protocolPayload{Ports: "443", Mode: "connect", Engine: config.EngineNmap},
		Timing: "balanced", Timeout: "1m", BaselineSamples: 2, ChangeConfirmations: 2,
	}
}

func previewHandlerRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/preview", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

type previewCountingScanner struct{ calls int }

func (s *previewCountingScanner) Version(context.Context) string { return "preview-counting" }
func (s *previewCountingScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	s.calls++
	return model.Snapshot{}, nil
}

func marshalPreviewPayload(t *testing.T, payload jobPayload) string {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func previewAPICall(t *testing.T, server *Server, account *routeMatrixSession, body, origin string, csrf bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/jobs/preview", strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:9000"
	request.Header.Set("Content-Type", "application/json")
	if account != nil {
		request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: account.raw})
		if csrf {
			request.Header.Set("X-CSRF-Token", account.session.CSRFToken)
		}
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	recorder := httptest.NewRecorder()
	server.api(recorder, request)
	return recorder
}

func decodePreviewResponse(t *testing.T, recorder *httptest.ResponseRecorder) previewResponse {
	t.Helper()
	var response previewResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode preview response %s: %v", recorder.Body.String(), err)
	}
	return response
}

func TestJobPreviewNormalizesSharedCreationConfigurationWithoutWrites(t *testing.T) {
	t.Parallel()
	server, db, admin := newUsersTestServer(t)
	server.App.Config.Timezone = "Europe/Amsterdam"
	scanner := &previewCountingScanner{}
	server.App.Scanner = scanner
	payload := validPreviewPayload("preview-equivalence")
	payload.Timezone = ""
	payload.Targets = []string{"edgewatch-preview.invalid"}
	payload.TCP.Ports = "22"
	payload.TCP.Engine = ""
	payload.TCP.Mode = ""
	payload.UDP = &protocolPayload{Ports: "53", ServiceDetection: false}
	body := marshalPreviewPayload(t, payload)
	// The direct handler test focuses on preview effects; the HTTP gate is
	// exercised separately below with persisted sessions for every role.
	request := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/jobs/preview", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	before := previewMonitoringRows(t, db)
	server.mu.Lock()
	historyBefore := len(server.history)
	server.mu.Unlock()
	recorder := httptest.NewRecorder()
	server.previewJob(recorder, request, admin, defaultTenantStore(server))
	if recorder.Code != http.StatusOK {
		t.Fatalf("preview = %d: %s", recorder.Code, recorder.Body.String())
	}
	preview := decodePreviewResponse(t, recorder)
	if preview.Job.Timezone != "Europe/Amsterdam" || preview.Job.TCP == nil || preview.Job.TCP.Engine != config.EngineNaabuNmap || preview.Job.TCP.ProfileID != store.BuiltinNaabuProfileID || preview.Job.TCP.ProfileRevision < 1 || preview.Job.TCP.Ports != config.NaabuFullPortExpression {
		t.Fatalf("normalized preview job = %#v", preview.Job)
	}
	if preview.Job.UDP == nil || preview.Job.UDP.Ports != "53" {
		t.Fatalf("optional UDP normalization = %#v", preview.Job.UDP)
	}
	if preview.Job.Enabled == nil || !*preview.Job.Enabled {
		t.Fatalf("preview did not report the created job's enabled default: %#v", preview.Job.Enabled)
	}
	if preview.Estimate.UnknownDNS != 1 || preview.Estimate.TCPPorts != 65535 || preview.Estimate.UDPPorts != 1 || preview.Estimate.Probes != 65536 || preview.Budget.Exceeded {
		t.Fatalf("preview estimate/budget = %+v / %+v", preview.Estimate, preview.Budget)
	}
	warningCodes := map[string]bool{}
	for _, warning := range preview.Warnings {
		warningCodes[warning.Code] = true
	}
	for _, code := range []string{"elapsed_time_unknown", "dns_expansion_unknown", "naabu_enrichment_data_dependent"} {
		if !warningCodes[code] {
			t.Errorf("preview warnings missing %q: %+v", code, preview.Warnings)
		}
	}
	if len(preview.Warnings) > maxJobPreviewWarnings {
		t.Fatalf("preview returned %d warnings; maximum is %d", len(preview.Warnings), maxJobPreviewWarnings)
	}
	if after := previewMonitoringRows(t, db); !reflect.DeepEqual(before, after) {
		t.Fatalf("preview changed monitoring data:\nbefore %+v\nafter  %+v", before, after)
	}
	server.mu.Lock()
	historyAfter := len(server.history)
	server.mu.Unlock()
	if historyAfter != historyBefore {
		t.Fatalf("preview published an SSE event: history %d -> %d", historyBefore, historyAfter)
	}
	if scanner.calls != 0 {
		t.Fatalf("preview invoked scanner %d times", scanner.calls)
	}

	// Create runs the same preparation and keeps the selected revision. Its
	// public job projection differs only by top-level lifecycle metadata.
	createPayload := payload
	createPayload.Name = "created-equivalence"
	createRecorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/jobs", strings.NewReader(marshalPreviewPayload(t, createPayload)))
	createRequest.Header.Set("Content-Type", "application/json")
	server.createJob(createRecorder, createRequest, admin, defaultTenantStore(server))
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", createRecorder.Code, createRecorder.Body.String())
	}
	var created struct {
		Job jobPayload `json:"job"`
	}
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	preview.Job.Name = createPayload.Name
	preview.Job.Enabled = nil
	if !reflect.DeepEqual(preview.Job, created.Job) {
		t.Fatalf("preview and create public jobs differ:\npreview %#v\ncreated %#v", preview.Job, created.Job)
	}
}

func TestJobPreviewKeepsExplicitPortNmapAndCreateEquivalent(t *testing.T) {
	t.Parallel()
	server, _, admin := newUsersTestServer(t)
	payload := validPreviewPayload("selected-port-nmap")
	payload.TCP.Ports = "22,443"
	payload.TCP.Engine = config.EngineNmap
	previewRecorder := httptest.NewRecorder()
	server.previewJob(previewRecorder, previewHandlerRequest(marshalPreviewPayload(t, payload)), admin, defaultTenantStore(server))
	if previewRecorder.Code != http.StatusOK {
		t.Fatalf("preview = %d: %s", previewRecorder.Code, previewRecorder.Body.String())
	}
	preview := decodePreviewResponse(t, previewRecorder)
	if preview.Job.TCP == nil || preview.Job.TCP.Engine != config.EngineNmap || preview.Job.TCP.Ports != "22,443" || preview.Estimate.TCPPorts != 2 || preview.Estimate.Probes != 2 {
		t.Fatalf("selected-port Nmap scope changed: job=%#v estimate=%+v", preview.Job.TCP, preview.Estimate)
	}
	partialCoverageWarning := false
	for _, warning := range preview.Warnings {
		partialCoverageWarning = partialCoverageWarning || warning.Code == "tcp_partial_coverage"
	}
	if !partialCoverageWarning {
		t.Fatalf("selected-port Nmap preview lacks partial-coverage warning: %+v", preview.Warnings)
	}

	createPayload := payload
	createPayload.Name = "selected-port-nmap-created"
	createRequest := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(marshalPreviewPayload(t, createPayload)))
	createRequest.Header.Set("Content-Type", "application/json")
	createRecorder := httptest.NewRecorder()
	server.createJob(createRecorder, createRequest, admin, defaultTenantStore(server))
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", createRecorder.Code, createRecorder.Body.String())
	}
	var created struct {
		Job jobPayload `json:"job"`
	}
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	preview.Job.Name = createPayload.Name
	preview.Job.Enabled = nil
	if !reflect.DeepEqual(preview.Job, created.Job) {
		t.Fatalf("explicit Nmap preview/create differ:\npreview %#v\ncreated %#v", preview.Job, created.Job)
	}
}

func previewMonitoringRows(t *testing.T, db *store.Store) map[string]int {
	t.Helper()
	rows := map[string]int{}
	for _, table := range []string{
		"jobs", "job_revisions", "job_runtime", "baseline_hosts", "scans", "scan_hosts", "latest_scan_hosts",
		"scan_cycles", "scan_cycle_units", "scan_cycle_discovery_checkpoints", "events", "outbox", "security_audit",
	} {
		var count int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		rows[table] = count
	}
	return rows
}

func TestJobPreviewUsesTargetExclusionsAndCreateValidation(t *testing.T) {
	t.Parallel()
	server, _, admin := newUsersTestServer(t)
	payload := validPreviewPayload("blocked-by-policy")
	payload.Targets = []string{"127.0.0.1"}
	if err := server.Store.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	body := marshalPreviewPayload(t, payload)
	preview := httptest.NewRecorder()
	server.previewJob(preview, previewHandlerRequest(body), admin, defaultTenantStore(server))
	create := httptest.NewRecorder()
	createRequest := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(body))
	createRequest.Header.Set("Content-Type", "application/json")
	server.createJob(create, createRequest, admin, defaultTenantStore(server))
	if preview.Code != http.StatusBadRequest || preview.Body.String() != create.Body.String() || !strings.Contains(preview.Body.String(), "excluded") {
		t.Fatalf("preview policy result = %d %s; create = %d %s", preview.Code, preview.Body.String(), create.Code, create.Body.String())
	}

	// A nil policy means deployment policy was not installed; an explicit
	// empty policy permits every otherwise valid target, matching Store's
	// existing create semantics in both cases.
	for _, exclusions := range [][]string{nil, {}} {
		if err := server.Store.SetTargetExclusions(exclusions); err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		server.previewJob(recorder, previewHandlerRequest(body), admin, defaultTenantStore(server))
		if recorder.Code != http.StatusOK {
			t.Errorf("preview under policy %#v = %d: %s", exclusions, recorder.Code, recorder.Body.String())
		}
	}
}

func TestJobPreviewValidationAndNoInputEcho(t *testing.T) {
	t.Parallel()
	server, _, admin := newUsersTestServer(t)
	cases := []struct {
		name   string
		mutate func(*jobPayload)
		field  string
	}{
		{"target", func(payload *jobPayload) { payload.Targets = []string{"not a valid target"} }, "targets"},
		{"duration", func(payload *jobPayload) { payload.Timeout = "not-a-duration" }, "timeout"},
		{"ports", func(payload *jobPayload) { payload.TCP.Ports = "not-a-port" }, "tcp"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			payload := validPreviewPayload("invalid-" + test.name)
			test.mutate(&payload)
			body := marshalPreviewPayload(t, payload)
			recorder := httptest.NewRecorder()
			server.previewJob(recorder, previewHandlerRequest(body), admin, defaultTenantStore(server))
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), test.field) {
				t.Fatalf("preview = %d %s, want validation error for %s", recorder.Code, recorder.Body.String(), test.field)
			}
		})
	}

	secret := "credential-that-must-not-echo"
	body := marshalPreviewPayload(t, validPreviewPayload("unknown-field"))
	body = strings.TrimSuffix(body, "}") + `,"password":"` + secret + `"}`
	recorder := httptest.NewRecorder()
	server.previewJob(recorder, previewHandlerRequest(body), admin, defaultTenantStore(server))
	if recorder.Code != http.StatusBadRequest || strings.Contains(recorder.Body.String(), secret) || strings.Contains(recorder.Body.String(), "password") {
		t.Fatalf("unknown credential-shaped input response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestJobPreviewReportsBudgetOutcomesForBothEnginesAndHardCeiling(t *testing.T) {
	t.Parallel()
	server, _, admin := newUsersTestServer(t)
	server.App.Config.Scheduler.MaxProbeCount = 100
	server.App.Config.Scheduler.MaxNaabuProbeCount = 100
	tests := []struct {
		name             string
		payload          jobPayload
		wantProbes       int64
		wantLimit        int64
		wantApprovalFits bool
	}{
		{
			name: "Nmap budget",
			payload: func() jobPayload {
				payload := validPreviewPayload("nmap-budget")
				payload.TCP.Ports = "1-101"
				return payload
			}(),
			wantProbes: 101, wantLimit: 100, wantApprovalFits: true,
		},
		{
			name: "Naabu budget",
			payload: func() jobPayload {
				payload := validPreviewPayload("naabu-budget")
				payload.TCP.Engine = ""
				payload.TCP.Mode = ""
				return payload
			}(),
			wantProbes: 65535, wantLimit: 100, wantApprovalFits: true,
		},
		{
			name: "absolute ceiling",
			payload: func() jobPayload {
				payload := validPreviewPayload("absolute-ceiling")
				payload.Targets = []string{"198.51.0.0/15"}
				payload.TCP.Ports = "1-1000"
				return payload
			}(),
			wantProbes: 131072000, wantLimit: config.MaxProbeCountLimit, wantApprovalFits: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			body := marshalPreviewPayload(t, test.payload)
			server.previewJob(recorder, previewHandlerRequest(body), admin, defaultTenantStore(server))
			if recorder.Code != http.StatusOK {
				t.Fatalf("preview = %d: %s", recorder.Code, recorder.Body.String())
			}
			response := decodePreviewResponse(t, recorder)
			if !response.Budget.Exceeded || response.Budget.EstimatedProbes != test.wantProbes || response.Budget.Limit != test.wantLimit || response.Budget.ApprovalWouldFit != test.wantApprovalFits {
				t.Fatalf("budget = %+v, estimate = %+v", response.Budget, response.Estimate)
			}
		})
	}
}

func TestJobPreviewBudgetUnavailableIsNotReportedAsFit(t *testing.T) {
	t.Parallel()
	server, db, admin := newUsersTestServer(t)
	if err := db.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if db.ReadDB != nil {
		if err := db.ReadDB.Close(); err != nil {
			t.Fatal(err)
		}
	}
	payload := validPreviewPayload("unavailable-budget")
	recorder := httptest.NewRecorder()
	server.previewJob(recorder, previewHandlerRequest(marshalPreviewPayload(t, payload)), admin, defaultTenantStore(server))
	response := decodeAPIError(t, recorder)
	if recorder.Code != http.StatusServiceUnavailable || response.Error.Code != "preview_unavailable" || response.Error.Details["reason"] != "scan_budget_unavailable" || strings.Contains(recorder.Body.String(), `"scan_budget"`) {
		t.Fatalf("unavailable budget response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestJobPreviewAuthCSRFOriginAndHighCostMatrix(t *testing.T) {
	t.Parallel()
	server, accounts := newRouteMatrixSessions(t)
	payload := validPreviewPayload("auth-matrix")
	body := marshalPreviewPayload(t, payload)
	for _, account := range accounts {
		recorder := previewAPICall(t, server, &account, body, "", true)
		want := http.StatusForbidden
		if account.role == store.RoleAdministrator || account.role == store.RoleOperator {
			want = http.StatusOK
		}
		if recorder.Code != want {
			t.Errorf("%s preview = %d %s, want %d", account.role, recorder.Code, recorder.Body.String(), want)
		}
	}
	if recorder := previewAPICall(t, server, nil, body, "", false); recorder.Code != http.StatusUnauthorized {
		t.Errorf("anonymous preview = %d %s, want 401", recorder.Code, recorder.Body.String())
	}
	if recorder := previewAPICall(t, server, &accounts[0], body, "http://example.com", false); recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), `"code":"csrf"`) {
		t.Errorf("missing-CSRF preview = %d %s, want csrf refusal", recorder.Code, recorder.Body.String())
	}
	// Authenticated mutations keep the established session+CSRF policy. A
	// supplied Origin does not replace CSRF or add a route-specific origin gate.
	for _, origin := range []string{"http://example.com", "https://other.example"} {
		if recorder := previewAPICall(t, server, &accounts[0], body, origin, true); recorder.Code != http.StatusOK {
			t.Errorf("preview with Origin %q = %d %s, want the existing CSRF-authenticated behavior", origin, recorder.Code, recorder.Body.String())
		}
	}

	approvedPayload := validPreviewPayload("high-cost-operator")
	approved := true
	approvedPayload.AllowHighCost = &approved
	approvedBody := marshalPreviewPayload(t, approvedPayload)
	if recorder := previewAPICall(t, server, &accounts[1], approvedBody, "", true); recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "high_cost_admin_required") {
		t.Errorf("operator high-cost preview = %d %s, want administrator restriction", recorder.Code, recorder.Body.String())
	}
	approvedPayload.Name = "high-cost-admin"
	if recorder := previewAPICall(t, server, &accounts[0], marshalPreviewPayload(t, approvedPayload), "", true); recorder.Code != http.StatusOK {
		t.Errorf("administrator high-cost preview = %d %s, want 200", recorder.Code, recorder.Body.String())
	}
}

func TestJobPreviewHidesCrossUnitProfilesAndDestinations(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	account := f.sessions[actorAdminB]
	profilePayload := validPreviewPayload("cross-unit-profile")
	profilePayload.TCP.ProfileID = f.profileA
	profilePayload.TCP.ProfileRevision = 1
	profileForeign := callAPI(t, f.server, account, http.MethodPost, "/jobs/preview", marshalPreviewPayload(t, profilePayload))
	profilePayload.TCP.ProfileID = unknownIsolationIDs.profile
	profileUnknown := callAPI(t, f.server, account, http.MethodPost, "/jobs/preview", marshalPreviewPayload(t, profilePayload))
	if profileForeign.Code != http.StatusBadRequest || profileForeign.Code != profileUnknown.Code || profileForeign.Body.String() != profileUnknown.Body.String() {
		t.Fatalf("foreign profile = %d %s; unknown profile = %d %s", profileForeign.Code, profileForeign.Body.String(), profileUnknown.Code, profileUnknown.Body.String())
	}

	destinationID := f.destinationA
	destinationPayload := validPreviewPayload("cross-unit-destination")
	destinationPayload.NotificationDestinations = &[]string{destinationID}
	destinationForeign := callAPI(t, f.server, account, http.MethodPost, "/jobs/preview", marshalPreviewPayload(t, destinationPayload))
	destinationPayload.NotificationDestinations = &[]string{unknownIsolationIDs.destination}
	destinationUnknown := callAPI(t, f.server, account, http.MethodPost, "/jobs/preview", marshalPreviewPayload(t, destinationPayload))
	if destinationForeign.Code != http.StatusBadRequest || destinationForeign.Code != destinationUnknown.Code || destinationForeign.Body.String() != destinationUnknown.Body.String() {
		t.Fatalf("foreign destination = %d %s; unknown destination = %d %s", destinationForeign.Code, destinationForeign.Body.String(), destinationUnknown.Code, destinationUnknown.Body.String())
	}

	ownPayload := validPreviewPayload("own-resources")
	ownPayload.TCP.ProfileID = f.profileB
	ownPayload.TCP.ProfileRevision = 1
	ownPayload.NotificationDestinations = &[]string{f.destinationB}
	own := callAPI(t, f.server, account, http.MethodPost, "/jobs/preview", marshalPreviewPayload(t, ownPayload))
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), f.profileB) || !strings.Contains(own.Body.String(), f.destinationB) {
		t.Fatalf("tenant B preview with own resources = %d %s", own.Code, own.Body.String())
	}
}

func TestJobPreviewDisabledUnitIsRefused(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	if _, err := f.db.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, store.TenantStateDisabled, f.unitB); err != nil {
		t.Fatal(err)
	}
	account := f.sessions[actorAdminB]
	recorder := callAPI(t, f.server, account, http.MethodPost, "/jobs/preview", marshalPreviewPayload(t, validPreviewPayload("disabled-unit")))
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), `"permission":"route"`) {
		t.Fatalf("disabled-unit preview = %d %s, want unit-scoped refusal", recorder.Code, recorder.Body.String())
	}
}

func TestJobPreviewReportsLargeCIDREstimateWithoutExpansion(t *testing.T) {
	t.Parallel()
	server, _, admin := newUsersTestServer(t)
	payload := validPreviewPayload("large-cidr")
	payload.Targets = []string{"2001:db8::/32"}
	payload.TCP.Ports = "443"
	recorder := httptest.NewRecorder()
	server.previewJob(recorder, previewHandlerRequest(marshalPreviewPayload(t, payload)), admin, defaultTenantStore(server))
	if recorder.Code != http.StatusOK {
		t.Fatalf("large CIDR preview = %d: %s", recorder.Code, recorder.Body.String())
	}
	response := decodePreviewResponse(t, recorder)
	if response.Estimate.Hosts != int64(^uint64(0)>>1) || response.Estimate.Probes != int64(^uint64(0)>>1) || !response.Budget.Exceeded || response.Budget.Limit != config.MaxProbeCountLimit {
		t.Fatalf("large CIDR estimate was not bounded and budgeted: %+v / %+v", response.Estimate, response.Budget)
	}
}

func TestJobPreviewHistoricalAndStaleProfileRevisionRules(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	account := f.sessions[actorAdminA]
	profile, err := f.a.GetScannerProfile(context.Background(), f.profileA)
	if err != nil {
		t.Fatal(err)
	}
	profile.Definition.Description = "updated"
	if _, err := f.a.UpdateScannerProfile(context.Background(), f.profileA, profile.Revision, profile.Name, profile.Description, profile.Definition, "fixture"); err != nil {
		t.Fatal(err)
	}
	payload := validPreviewPayload("stale-profile")
	payload.TCP.ProfileID = f.profileA
	payload.TCP.ProfileRevision = 1
	recorder := callAPI(t, f.server, account, http.MethodPost, "/jobs/preview", marshalPreviewPayload(t, payload))
	if recorder.Code != http.StatusOK {
		t.Fatalf("administrator historical profile preview = %d %s; creation permits pinned historical revisions", recorder.Code, recorder.Body.String())
	}

	operator := f.sessions[actorOperatorA]
	otherProfilePayload := validPreviewPayload("stale-operator-profile")
	otherProfilePayload.TCP.ProfileID = f.profileA
	otherProfilePayload.TCP.ProfileRevision = 1
	stale := callAPI(t, f.server, operator, http.MethodPost, "/jobs/preview", marshalPreviewPayload(t, otherProfilePayload))
	if stale.Code != http.StatusConflict || !strings.Contains(stale.Body.String(), "profile_conflict") {
		t.Fatalf("operator stale profile preview = %d %s, want profile conflict", stale.Code, stale.Body.String())
	}
}
