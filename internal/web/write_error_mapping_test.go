package web

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// maxJobNameCharacters is the documented API limit, config.MaxJobNameRunes.
// config's own tests pin the constant; these tests pin the API contract.
const maxJobNameCharacters = 200

type apiErrorBody struct {
	Error struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Details map[string]string `json:"details"`
	} `json:"error"`
}

func decodeAPIError(t *testing.T, recorder *httptest.ResponseRecorder) apiErrorBody {
	t.Helper()
	var body apiErrorBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not JSON: %s (%v)", recorder.Body.String(), err)
	}
	return body
}

// assertRedactedInternalError checks the writeInternalError contract: a
// generic 500 with the request ID, and the storage text only in the log.
func assertRedactedInternalError(t *testing.T, name string, recorder *httptest.ResponseRecorder, requestID string, leaked string, logs *bytes.Buffer) {
	t.Helper()
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("%s status = %d, want 500: %s", name, recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), leaked) {
		t.Fatalf("%s leaked storage text to the client: %s", name, recorder.Body.String())
	}
	body := decodeAPIError(t, recorder)
	if body.Error.Code != "store" || body.Error.Message != "internal server error" || body.Error.Details["request_id"] != requestID {
		t.Fatalf("%s error = %#v, want a generic store error with request_id %q", name, body.Error, requestID)
	}
	if !strings.Contains(logs.String(), leaked) || !strings.Contains(logs.String(), "request_id="+requestID) {
		t.Fatalf("%s storage detail was not logged with the request ID: %s", name, logs.String())
	}
}

func failTableWrites(t *testing.T, db *store.Store, table, operation, message string) func() {
	t.Helper()
	name := "fail_" + table + "_" + strings.ToLower(operation)
	if _, err := db.DB.ExecContext(context.Background(), `CREATE TRIGGER `+name+` BEFORE `+operation+` ON `+table+` BEGIN SELECT RAISE(ABORT, '`+message+`'); END`); err != nil {
		t.Fatal(err)
	}
	return func() {
		if _, err := db.DB.ExecContext(context.Background(), `DROP TRIGGER `+name); err != nil {
			t.Fatal(err)
		}
	}
}

func jobWriteRequest(method, path, body, requestID string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request.WithContext(context.WithValue(request.Context(), requestIDContextKey{}, requestID))
}

func TestJobWritesReportStorageFailuresAsInternalErrors(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	var logs bytes.Buffer
	server.Log = slog.New(slog.NewTextHandler(&logs, nil))
	operator := admin
	operator.Role = store.RoleOperator
	record, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "storage-failure", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect", Engine: config.EngineNmap}}))
	if err != nil {
		t.Fatal(err)
	}
	const locked = "database is locked (5) (SQLITE_BUSY)"

	// Both roles that may write jobs get the same redacted error while
	// another connection holds the SQLite write lock.
	restoreInsert := failTableWrites(t, db, "jobs", "INSERT", locked)
	for _, session := range []store.Session{admin, operator} {
		requestID := "create-" + session.Role
		body := `{"name":"created-` + session.Role + `","schedule":"0 * * * *","timezone":"UTC","targets":["192.0.2.11"],"tcp":{"ports":"80","mode":"connect","engine":"nmap"}}`
		recorder := httptest.NewRecorder()
		server.createJob(recorder, jobWriteRequest(http.MethodPost, "/api/v1/jobs", body, requestID), session)
		assertRedactedInternalError(t, "create as "+session.Role, recorder, requestID, locked, &logs)
	}
	restoreInsert()

	restoreUpdate := failTableWrites(t, db, "jobs", "UPDATE", locked)
	scheduleOnly := fromConfig(record.Job)
	scheduleOnly.Revision = record.Revision
	scheduleOnly.Schedule = "30 * * * *"
	raw, err := json.Marshal(scheduleOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range []store.Session{admin, operator} {
		requestID := "update-" + session.Role
		recorder := httptest.NewRecorder()
		server.jobRoute(recorder, jobWriteRequest(http.MethodPut, "/api/v1/jobs/"+record.ID, string(raw), requestID), session, record.ID)
		assertRedactedInternalError(t, "update as "+session.Role, recorder, requestID, locked, &logs)
	}

	// Real validation failures keep their 400 contract and field details,
	// even while writes would fail.
	invalid := fromConfig(record.Job)
	invalid.Revision = record.Revision
	invalid.Schedule = "not a schedule"
	raw, err = json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.jobRoute(recorder, jobWriteRequest(http.MethodPut, "/api/v1/jobs/"+record.ID, string(raw), "invalid-update"), operator, record.ID)
	if body := decodeAPIError(t, recorder); recorder.Code != http.StatusBadRequest || body.Error.Code != "validation_failed" || body.Error.Details["schedule"] == "" {
		t.Fatalf("invalid schedule = %d %#v", recorder.Code, body.Error)
	}
	restoreUpdate()

	// With the store healthy again the same update succeeds.
	raw, err = json.Marshal(scheduleOnly)
	if err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	server.jobRoute(recorder, jobWriteRequest(http.MethodPut, "/api/v1/jobs/"+record.ID, string(raw), "recovered-update"), operator, record.ID)
	if recorder.Code != http.StatusOK {
		t.Fatalf("recovered update = %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestJobProfileRevisionLookupFailureIsAnInternalError(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	var logs bytes.Buffer
	server.Log = slog.New(slog.NewTextHandler(&logs, nil))
	profile, err := db.CreateScannerProfile(ctx, "Revisioned", "", config.BuiltinNmapProfile(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateScannerProfile(ctx, profile.ID, profile.Revision, "Revisioned", "second", config.BuiltinNmapProfile(), "admin"); err != nil {
		t.Fatal(err)
	}
	// An administrator may roll a job back to a historical profile revision.
	// A failed revision read is a storage failure, not a bad selection.
	breakReadProjection(t, db, "scanner_profile_revisions")
	body := `{"name":"historical-profile","schedule":"0 * * * *","timezone":"UTC","targets":["192.0.2.12"],"tcp":{"ports":"80","mode":"connect","engine":"nmap","profile_id":"` + profile.ID + `","profile_revision":1}}`
	recorder := httptest.NewRecorder()
	server.createJob(recorder, jobWriteRequest(http.MethodPost, "/api/v1/jobs", body, "profile-revision"), admin)
	assertRedactedInternalError(t, "historical profile create", recorder, "profile-revision", "no such table", &logs)
}

func TestJobProfileSelectionErrorsRemainFieldValidation(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	operator := admin
	operator.Role = store.RoleOperator
	tunable := config.BuiltinNaabuProfile()
	tunable.OperatorAdjustable = []string{"scan_type", "rate"}
	tunable.OperatorBounds = map[string]config.NumericBound{"rate": {Min: 100, Max: 2000}}
	profile, err := db.CreateScannerProfile(ctx, "Tunable", "", tunable, "admin")
	if err != nil {
		t.Fatal(err)
	}
	archived, err := db.CreateScannerProfile(ctx, "Retired", "", config.BuiltinNmapProfile(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetScannerProfileArchived(ctx, archived.ID, true, archived.Revision, "admin"); err != nil {
		t.Fatal(err)
	}
	create := func(tcp string) *httptest.ResponseRecorder {
		body := `{"name":"profile-selection","schedule":"0 * * * *","timezone":"UTC","targets":["192.0.2.40"],"tcp":` + tcp + `}`
		recorder := httptest.NewRecorder()
		server.createJob(recorder, jobWriteRequest(http.MethodPost, "/api/v1/jobs", body, "profile-selection"), operator)
		return recorder
	}
	for name, tc := range map[string]struct{ tcp, field string }{
		"archived profile":   {`{"ports":"443","mode":"connect","profile_id":"` + archived.ID + `"}`, "profile"},
		"missing profile":    {`{"ports":"443","mode":"connect","profile_id":"00000000-0000-0000-0000-00000000beef"}`, "profile"},
		"rate out of bounds": {`{"ports":"1-65535","mode":"connect","engine":"naabu_nmap","profile_id":"` + profile.ID + `","naabu":{"rate":5000}}`, "rate"},
		"invalid scan type":  {`{"ports":"1-65535","mode":"connect","engine":"naabu_nmap","profile_id":"` + profile.ID + `","naabu":{"scan_type":"stealth"}}`, "scan_type"},
	} {
		recorder := create(tc.tcp)
		body := decodeAPIError(t, recorder)
		if recorder.Code != http.StatusBadRequest || body.Error.Code != "validation_failed" || body.Error.Details[tc.field] == "" {
			t.Fatalf("%s = %d %#v, want 400 with details.%s", name, recorder.Code, body.Error, tc.field)
		}
	}

	// Switching an existing job to an archived profile is rejected the same way.
	record, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "existing-selection", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.41"}, TCP: &config.Protocol{Ports: "443", Mode: "connect", Engine: config.EngineNmap}}))
	if err != nil {
		t.Fatal(err)
	}
	switched := fromConfig(record.Job)
	switched.Revision = record.Revision
	switched.TCP.ProfileID = archived.ID
	raw, err := json.Marshal(switched)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.jobRoute(recorder, jobWriteRequest(http.MethodPut, "/api/v1/jobs/"+record.ID, string(raw), "switch-profile"), operator, record.ID)
	if body := decodeAPIError(t, recorder); recorder.Code != http.StatusBadRequest || body.Error.Details["profile"] == "" {
		t.Fatalf("switch to archived profile = %d %#v", recorder.Code, body.Error)
	}

	// A failed job read is a storage failure, not a missing job.
	var logs bytes.Buffer
	server.Log = slog.New(slog.NewTextHandler(&logs, nil))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	server.jobRoute(recorder, jobWriteRequest(http.MethodPut, "/api/v1/jobs/"+record.ID, string(raw), "closed-store"), operator, record.ID)
	assertRedactedInternalError(t, "update with a closed store", recorder, "closed-store", "database is closed", &logs)
}

func TestScannerProfileWritesMapStorageFailuresAndMissingProfiles(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	var logs bytes.Buffer
	server.Log = slog.New(slog.NewTextHandler(&logs, nil))
	profileRequest := func(session store.Session, method, rest, body, requestID string) *httptest.ResponseRecorder {
		request := jobWriteRequest(method, "/api/v1/scanner-profiles/"+rest, body, requestID)
		recorder := httptest.NewRecorder()
		server.scannerProfilesRoute(recorder, request, session, rest)
		return recorder
	}
	profile, err := db.CreateScannerProfile(ctx, "Existing", "", config.BuiltinNmapProfile(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	const ioFailure = "disk I/O error (10) (SQLITE_IOERR)"

	restoreInsert := failTableWrites(t, db, "scanner_profiles", "INSERT", ioFailure)
	created := profileRequest(admin, http.MethodPost, "", `{"name":"Created","engine":"nmap","password":"administrator password"}`, "profile-create")
	assertRedactedInternalError(t, "profile create", created, "profile-create", ioFailure, &logs)
	restoreInsert()

	restoreUpdate := failTableWrites(t, db, "scanner_profiles", "UPDATE", ioFailure)
	updated := profileRequest(admin, http.MethodPut, profile.ID, `{"name":"Renamed","engine":"nmap","password":"administrator password","revision":1}`, "profile-update")
	assertRedactedInternalError(t, "profile update", updated, "profile-update", ioFailure, &logs)
	archived := profileRequest(admin, http.MethodDelete, profile.ID, `{"password":"administrator password","revision":1}`, "profile-archive")
	assertRedactedInternalError(t, "profile archive", archived, "profile-archive", ioFailure, &logs)
	restoreUpdate()

	// A profile deleted before the write is a missing resource, not invalid input.
	missing := profileRequest(admin, http.MethodPut, "00000000-0000-0000-0000-00000000dead", `{"name":"Gone","engine":"nmap","password":"administrator password","revision":1}`, "profile-missing")
	if body := decodeAPIError(t, missing); missing.Code != http.StatusNotFound || body.Error.Code != "not_found" {
		t.Fatalf("missing profile update = %d %#v", missing.Code, body.Error)
	}

	// Validation failures keep their field-level 400 response.
	invalid := profileRequest(admin, http.MethodPost, "", `{"name":"","engine":"nmap","password":"administrator password"}`, "profile-invalid")
	if body := decodeAPIError(t, invalid); invalid.Code != http.StatusBadRequest || body.Error.Code != "validation_failed" || body.Error.Details["name"] == "" {
		t.Fatalf("invalid profile create = %d %#v", invalid.Code, body.Error)
	}
	builtin := profileRequest(admin, http.MethodPut, store.BuiltinNmapProfileID, `{"name":"Built-in","engine":"nmap","password":"administrator password","revision":1}`, "profile-builtin")
	if body := decodeAPIError(t, builtin); builtin.Code != http.StatusBadRequest || body.Error.Code != "validation_failed" {
		t.Fatalf("built-in profile update = %d %#v", builtin.Code, body.Error)
	}

	// Scanner-profile writes stay administrator-only.
	operator := admin
	operator.Role = store.RoleOperator
	if denied := profileRequest(operator, http.MethodPut, profile.ID, `{"name":"Operator","engine":"nmap","password":"administrator password","revision":1}`, "profile-operator"); denied.Code != http.StatusForbidden {
		t.Fatalf("operator profile update = %d: %s", denied.Code, denied.Body.String())
	}
}

func TestJobNamesAreBoundedAndRejectControlCharacters(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	operator := admin
	operator.Role = store.RoleOperator
	jobBody := func(name string) string {
		encoded, err := json.Marshal(name)
		if err != nil {
			t.Fatal(err)
		}
		return `{"name":` + string(encoded) + `,"schedule":"0 * * * *","timezone":"UTC","targets":["192.0.2.20"],"tcp":{"ports":"443","mode":"connect","engine":"nmap"}}`
	}
	tooLong := strings.Repeat("n", maxJobNameCharacters+1)
	for _, session := range []store.Session{admin, operator} {
		for name, value := range map[string]string{"too long": tooLong, "control character": "edge\u0007job", "line break": "edge\njob"} {
			recorder := httptest.NewRecorder()
			server.createJob(recorder, jobWriteRequest(http.MethodPost, "/api/v1/jobs", jobBody(value), "name"), session)
			body := decodeAPIError(t, recorder)
			if recorder.Code != http.StatusBadRequest || body.Error.Code != "validation_failed" || body.Error.Details["name"] == "" {
				t.Fatalf("%s create as %s = %d %#v", name, session.Role, recorder.Code, body.Error)
			}
			if strings.Contains(recorder.Body.String(), tooLong) {
				t.Fatalf("%s create echoed the rejected name", name)
			}
		}
	}
	jobs, err := db.ListJobs(ctx, true)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("rejected names created jobs: %d (%v)", len(jobs), err)
	}

	// The limit counts characters, so a name at the limit is accepted even
	// when every character takes four bytes.
	longest := strings.Repeat("🙂", maxJobNameCharacters)
	recorder := httptest.NewRecorder()
	server.createJob(recorder, jobWriteRequest(http.MethodPost, "/api/v1/jobs", jobBody(longest), "longest"), operator)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("maximum-length name create = %d: %s", recorder.Code, recorder.Body.String())
	}
	var created struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	record, err := db.GetJob(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	rename := fromConfig(record.Job)
	rename.Revision = record.Revision
	rename.Name = longest + "x"
	raw, err := json.Marshal(rename)
	if err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	server.jobRoute(recorder, jobWriteRequest(http.MethodPut, "/api/v1/jobs/"+record.ID, string(raw), "rename"), operator, record.ID)
	if body := decodeAPIError(t, recorder); recorder.Code != http.StatusBadRequest || body.Error.Details["name"] == "" {
		t.Fatalf("over-long rename = %d %#v", recorder.Code, body.Error)
	}
}

func TestMaximumLengthJobNameKeepsEventWritesWorking(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	name := strings.Repeat("🙂", maxJobNameCharacters)
	if utf8.RuneCountInString(name) != maxJobNameCharacters {
		t.Fatalf("test name has %d characters", utf8.RuneCountInString(name))
	}
	body, err := json.Marshal(map[string]any{"name": name, "schedule": "0 * * * *", "timezone": "UTC", "targets": []string{"192.0.2.30"}, "tcp": map[string]any{"ports": "443", "mode": "connect", "engine": "nmap"}, "baseline_samples": 1, "change_confirmations": 1})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.createJob(recorder, jobWriteRequest(http.MethodPost, "/api/v1/jobs", string(body), "max-name"), admin)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("maximum-length job create = %d: %s", recorder.Code, recorder.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	record, err := db.GetJob(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}

	reset := httptest.NewRecorder()
	server.jobRoute(reset, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/baseline/reset", nil), admin, record.ID+"/baseline/reset")
	if reset.Code != http.StatusOK || !strings.Contains(reset.Body.String(), "baseline-reset") {
		t.Fatalf("maximum-length baseline reset = %d: %s", reset.Code, reset.Body.String())
	}

	e := engine.Engine{Store: db}
	now := time.Now().UTC()
	failed := model.Scan{ID: "max-name-failed", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, ConfigHash: record.Job.SecurityHash(), Status: "failed", Error: "scanner exited with status 1", StartedAt: now, FinishedAt: now}
	if _, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &failed, nil); err != nil {
		t.Fatalf("finalize failed scan: %v", err)
	}
	success := model.Scan{ID: "max-name-success", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, ConfigHash: record.Job.SecurityHash(), Status: "success", StartedAt: now, FinishedAt: now.Add(time.Second),
		Snapshot: model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.30", Protocol: "tcp", Ports: "443"}}, Units: []model.Unit{{Target: "192.0.2.30", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}}}}
	success.Snapshot.Normalize()
	if _, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &success, nil); err != nil {
		t.Fatalf("finalize successful scan: %v", err)
	}
	for _, id := range []string{failed.ID, success.ID} {
		if _, err := db.GetScan(ctx, id); err != nil {
			t.Fatalf("scan %s was not persisted: %v", id, err)
		}
	}
}
