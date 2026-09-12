package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestBaselineCycleLifecycleAndJobArchiveHandlers(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{Name: "lifecycle", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"}, Baseline: config.Baseline{Samples: 1}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}

	reset := httptest.NewRecorder()
	server.resetBaseline(reset, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/baseline/reset", nil), admin, record.ID)
	if reset.Code != http.StatusOK || !strings.Contains(reset.Body.String(), "baseline-reset") {
		t.Fatalf("baseline reset = %d: %s", reset.Code, reset.Body.String())
	}
	now := time.Now().UTC()
	scan := model.Scan{ID: "lifecycle-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: []model.PortState{{Port: 443, State: "open"}}}}}}
	if err := db.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	approveBody := strings.NewReader(`{"scan_id":"` + scan.ID + `"}`)
	approveRequest := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/baseline/approve", approveBody)
	approveRequest.Header.Set("Content-Type", "application/json")
	approve := httptest.NewRecorder()
	server.approveBaseline(approve, approveRequest, admin, record.ID)
	if approve.Code != http.StatusOK || !strings.Contains(approve.Body.String(), "baseline-approved") {
		t.Fatalf("baseline approval = %d: %s", approve.Code, approve.Body.String())
	}
	invalidApproveRequest := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/baseline/approve", strings.NewReader(`{"scan_id":"missing"}`))
	invalidApproveRequest.Header.Set("Content-Type", "application/json")
	invalidApprove := httptest.NewRecorder()
	server.approveBaseline(invalidApprove, invalidApproveRequest, admin, record.ID)
	if invalidApprove.Code != http.StatusBadRequest {
		t.Fatalf("invalid baseline approval status = %d", invalidApprove.Code)
	}

	plan := scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Family: 4, Addresses: []string{"192.0.2.1"}, Ports: "443", PortCount: 1, Probes: 1}}}
	cycle, err := db.CreateScanCycle(ctx, store.ScanCycleRecord{ID: "lifecycle-cycle", JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision, ConfigHash: record.Job.SecurityHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	cycleResponse := httptest.NewRecorder()
	server.scanCycle(cycleResponse, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/scan-cycle", nil), record.ID)
	if cycleResponse.Code != http.StatusOK || !strings.Contains(cycleResponse.Body.String(), cycle.ID) || !strings.Contains(cycleResponse.Body.String(), `"units"`) {
		t.Fatalf("scan cycle response = %d: %s", cycleResponse.Code, cycleResponse.Body.String())
	}
	discardRequest := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/scan-cycle/"+cycle.ID+"/discard", nil)
	discard := httptest.NewRecorder()
	server.discardScanCycle(discard, discardRequest, admin, record.ID, cycle.ID)
	if discard.Code != http.StatusNoContent {
		t.Fatalf("cycle discard = %d: %s", discard.Code, discard.Body.String())
	}
	noCycle := httptest.NewRecorder()
	server.scanCycle(noCycle, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/scan-cycle", nil), record.ID)
	if noCycle.Code != http.StatusOK || !strings.Contains(noCycle.Body.String(), `"cycle":null`) {
		t.Fatalf("empty cycle response = %d: %s", noCycle.Code, noCycle.Body.String())
	}

	current, err := db.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	archiveRequest := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/archive", strings.NewReader(`{"revision":1}`))
	archiveRequest.Header.Set("Content-Type", "application/json")
	archive := httptest.NewRecorder()
	server.archiveJob(archive, archiveRequest, admin, record.ID, true)
	if archive.Code != http.StatusNoContent {
		t.Fatalf("archive = %d: %s", archive.Code, archive.Body.String())
	}
	archived, err := db.GetJob(ctx, record.ID)
	if err != nil || !archived.Archived || archived.Revision <= current.Revision {
		t.Fatalf("archived job = %#v, %v", archived, err)
	}
	restoreRequest := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/restore", strings.NewReader(`{"revision":2}`))
	restoreRequest.Header.Set("Content-Type", "application/json")
	restore := httptest.NewRecorder()
	server.archiveJob(restore, restoreRequest, admin, record.ID, false)
	if restore.Code != http.StatusNoContent {
		t.Fatalf("restore = %d: %s", restore.Code, restore.Body.String())
	}

	second, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "delete-me", Schedule: "0 * * * *", Targets: []string{"192.0.2.2"}, TCP: &config.Protocol{Ports: "22", Mode: "connect"}}))
	if err != nil {
		t.Fatal(err)
	}
	wrongName := httptest.NewRecorder()
	wrongRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs/"+second.ID, strings.NewReader(`{"confirm_name":"wrong"}`))
	wrongRequest.Header.Set("Content-Type", "application/json")
	server.permanentDelete(wrongName, wrongRequest, admin, second.ID)
	if wrongName.Code != http.StatusBadRequest {
		t.Fatalf("wrong delete confirmation = %d", wrongName.Code)
	}
	activeName := httptest.NewRecorder()
	activeRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs/"+second.ID, strings.NewReader(`{"confirm_name":"delete-me"}`))
	activeRequest.Header.Set("Content-Type", "application/json")
	server.permanentDelete(activeName, activeRequest, admin, second.ID)
	if activeName.Code != http.StatusConflict {
		t.Fatalf("unarchived delete = %d: %s", activeName.Code, activeName.Body.String())
	}
	archiveSecondRequest := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+second.ID+"/archive", strings.NewReader(`{"revision":1}`))
	archiveSecondRequest.Header.Set("Content-Type", "application/json")
	archiveSecond := httptest.NewRecorder()
	server.archiveJob(archiveSecond, archiveSecondRequest, admin, second.ID, true)
	if archiveSecond.Code != http.StatusNoContent {
		t.Fatalf("second archive = %d: %s", archiveSecond.Code, archiveSecond.Body.String())
	}
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs/"+second.ID, strings.NewReader(`{"confirm_name":"delete-me"}`))
	deleteRequest.Header.Set("Content-Type", "application/json")
	deleted := httptest.NewRecorder()
	server.permanentDelete(deleted, deleteRequest, admin, second.ID)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("permanent delete = %d: %s", deleted.Code, deleted.Body.String())
	}
}

func TestLifecycleActionsRejectActiveScans(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{Name: "active-lifecycle", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AcquireJobLease(ctx, record.ID, "running-scan", time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.ReleaseJobLease(ctx, record.ID, "running-scan"); err != nil {
			t.Errorf("release test lease: %v", err)
		}
	}()

	archiveRequest := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/archive", strings.NewReader(`{"revision":1}`))
	archiveRequest.Header.Set("Content-Type", "application/json")
	archive := httptest.NewRecorder()
	server.archiveJob(archive, archiveRequest, admin, record.ID, true)
	if archive.Code != http.StatusConflict || !strings.Contains(archive.Body.String(), "job_active") || !strings.Contains(archive.Body.String(), "wait") {
		t.Fatalf("active archive response = %d: %s", archive.Code, archive.Body.String())
	}

	pauseRequest := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/pause", strings.NewReader(`{"revision":1}`))
	pauseRequest.Header.Set("Content-Type", "application/json")
	pause := httptest.NewRecorder()
	server.enableJob(pause, pauseRequest, admin, record.ID, false)
	if pause.Code != http.StatusConflict || !strings.Contains(pause.Body.String(), "job_active") || !strings.Contains(pause.Body.String(), "wait") {
		t.Fatalf("active pause response = %d: %s", pause.Code, pause.Body.String())
	}
	unchanged, err := db.GetJob(ctx, record.ID)
	if err != nil || unchanged.Archived || !unchanged.Enabled || unchanged.Revision != record.Revision {
		t.Fatalf("active lifecycle actions changed job: %#v", unchanged)
	}
}

func TestNotificationRoutesAndRateLimit(t *testing.T) {
	server, _, admin := newUsersTestServer(t)
	missingRequest := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations", strings.NewReader(`{"name":"Ops","url":"generic://localhost/ops"}`))
	missingRequest.Header.Set("Content-Type", "application/json")
	missingPassword := httptest.NewRecorder()
	server.createNotificationDestination(missingPassword, missingRequest, admin)
	if missingPassword.Code != http.StatusBadRequest || !strings.Contains(missingPassword.Body.String(), "password_required") {
		t.Fatalf("missing notification password = %d: %s", missingPassword.Code, missingPassword.Body.String())
	}
	createRequest := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations", strings.NewReader(`{"name":"Ops","url":"generic://localhost/ops?disabletls=yes","password":"administrator password"}`))
	createRequest.Header.Set("Content-Type", "application/json")
	createRequest.RemoteAddr = "127.0.0.1:2"
	created := httptest.NewRecorder()
	server.createNotificationDestination(created, createRequest, admin)
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), "disabletls") {
		t.Fatalf("notification create = %d: %s", created.Code, created.Body.String())
	}
	var createdView struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdView); err != nil || createdView.ID == "" || createdView.Revision != 1 {
		t.Fatalf("created notification view = %s (%v)", created.Body.String(), err)
	}

	getRequest := httptest.NewRequest(http.MethodGet, "/api/v1/notifications/destinations/"+createdView.ID, nil)
	getResponse := httptest.NewRecorder()
	server.notificationDestinationRoute(getResponse, getRequest, admin, createdView.ID)
	if getResponse.Code != http.StatusOK || strings.Contains(getResponse.Body.String(), "disabletls") {
		t.Fatalf("notification get = %d: %s", getResponse.Code, getResponse.Body.String())
	}
	updateRequest := httptest.NewRequest(http.MethodPut, "/api/v1/notifications/destinations/"+createdView.ID, strings.NewReader(`{"name":"Ops updated","password":"administrator password","revision":1,"enabled":false}`))
	updateRequest.Header.Set("Content-Type", "application/json")
	updateResponse := httptest.NewRecorder()
	server.notificationDestinationRoute(updateResponse, updateRequest, admin, createdView.ID)
	if updateResponse.Code != http.StatusOK || !strings.Contains(updateResponse.Body.String(), "Ops updated") {
		t.Fatalf("notification update = %d: %s", updateResponse.Code, updateResponse.Body.String())
	}
	routingRequest := httptest.NewRequest(http.MethodPut, "/api/v1/notifications/update-routing", strings.NewReader(`{"destinations":["`+createdView.ID+`"],"password":"administrator password"}`))
	routingRequest.Header.Set("Content-Type", "application/json")
	routingResponse := httptest.NewRecorder()
	server.updateNotificationRouting(routingResponse, routingRequest, admin)
	if routingResponse.Code != http.StatusOK || !strings.Contains(routingResponse.Body.String(), createdView.ID) {
		t.Fatalf("update notification routing = %d: %s", routingResponse.Code, routingResponse.Body.String())
	}
	routingState, err := server.Store.GetApplicationUpdateState(context.Background())
	if err != nil || !routingState.UpdateNotificationDestinationsConfigured || len(routingState.UpdateNotificationDestinations) != 1 || routingState.UpdateNotificationDestinations[0] != createdView.ID {
		t.Fatalf("stored update routing = %#v, %v", routingState, err)
	}
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/notifications/destinations/"+createdView.ID, strings.NewReader(`{"password":"administrator password","revision":2}`))
	deleteRequest.Header.Set("Content-Type", "application/json")
	deleteResponse := httptest.NewRecorder()
	server.notificationDestinationRoute(deleteResponse, deleteRequest, admin, createdView.ID)
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("notification delete = %d: %s", deleteResponse.Code, deleteResponse.Body.String())
	}
	missing := httptest.NewRecorder()
	server.notificationDestinationRoute(missing, httptest.NewRequest(http.MethodGet, "/api/v1/notifications/destinations/"+createdView.ID, nil), admin, createdView.ID)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("deleted notification status = %d", missing.Code)
	}

	firstTest := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/test", nil)
	firstTest.RemoteAddr = "127.0.0.1:3"
	firstResponse := httptest.NewRecorder()
	server.notificationTest(firstResponse, firstTest, admin)
	if firstResponse.Code != http.StatusOK || !strings.Contains(firstResponse.Body.String(), `"sent":0`) {
		t.Fatalf("empty notification test = %d: %s", firstResponse.Code, firstResponse.Body.String())
	}
	secondTest := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/test", nil)
	secondTest.RemoteAddr = "127.0.0.1:3"
	secondResponse := httptest.NewRecorder()
	server.notificationTest(secondResponse, secondTest, admin)
	if secondResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited notification test = %d: %s", secondResponse.Code, secondResponse.Body.String())
	}
	if !server.allowNotificationTest(httptest.NewRequest(http.MethodPost, "/", nil)) {
		t.Fatal("new notification test identity was unexpectedly limited")
	}
}
