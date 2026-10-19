package web

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestCancelChangeWindowKeepsHeldAlertsWhenDestinationsCannotBeLoaded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, db, admin := newUsersTestServer(t)
	server := newRoutingTestServer(t, db, "generic://localhost/edgewatch?disabletls=yes&template=json")
	ts := defaultTenantStore(server)
	job, err := ts.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "cancel-window-destination-failure", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", admin.UserID, admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	closedWindow, err := ts.CreateChangeWindow(ctx, job.ID, time.Now().UTC().Add(time.Hour), time.Now().UTC().Add(2*time.Hour), false, "scheduled", admin.UserID, admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := ts.CancelScheduledChangeWindow(ctx, job.ID, closedWindow.ID, admin.UserID, admin.Username, store.AuditEntry{}); err != nil || !changed {
		t.Fatalf("prepare closed window = changed %v, err %v", changed, err)
	}
	other, err := db.Platform().CreateTenant(ctx, "Other unit", "other-unit-window-cancel", store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	otherScope, err := db.TenantScopeByID(ctx, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	otherTS := db.Tenant(otherScope)
	otherJob, err := otherTS.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "other-unit-window-cancel", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.11"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	otherWindow, err := otherTS.CreateChangeWindow(ctx, otherJob.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "other unit", admin.UserID, admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.System().QueueEvent(ctx, "held-change-alert", model.Event{
		Type: "changes-detected", JobID: job.ID, Job: job.Job.Name, ScanID: "cancel-window-read-failure",
		Message: "change detected", CreatedAt: time.Now().UTC(),
		Changes: []model.Change{{Key: "port|192.0.2.10|tcp|443", Kind: "port", Severity: "high", Target: "192.0.2.10", Protocol: "tcp", Port: 443}},
	}); err != nil {
		t.Fatal(err)
	}

	// Replace the destination table with a view whose source is missing. This
	// makes the notifier's real tenant-scoped SELECT fail while leaving the
	// change-window writer and outbox tables writable for the handler.
	const savedTable = "managed_notifications_saved_for_cancel_test"
	const brokenSource = "missing_managed_notifications_for_cancel_test"
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications RENAME TO `+savedTable); err != nil {
		t.Fatal(err)
	}
	viewInstalled := false
	var logs strings.Builder
	server.Log = slog.New(slog.NewTextHandler(&logs, nil))
	restoreMetadata := func() error {
		if _, err := db.DB.ExecContext(ctx, `DROP VIEW IF EXISTS managed_notifications`); err != nil {
			return err
		}
		if _, err := db.DB.ExecContext(ctx, `ALTER TABLE `+savedTable+` RENAME TO managed_notifications`); err != nil {
			return err
		}
		viewInstalled = false
		return nil
	}
	t.Cleanup(func() {
		if viewInstalled {
			if err := restoreMetadata(); err != nil {
				t.Errorf("restore destination schema: %v", err)
			}
		}
	})
	_, err = db.DB.ExecContext(ctx, `CREATE VIEW managed_notifications(id,tenant_id,name,provider,ciphertext,nonce,enabled,revision,credential_revision,created_at,updated_at) AS SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM `+brokenSource)
	if err != nil {
		t.Fatal(err)
	}
	viewInstalled = true
	if _, err := server.App.Notifier.Tenant(ts).QueueDestinationsForJob(ctx, job.Job); err == nil {
		t.Fatal("destination lookup succeeded with a broken metadata source")
	}

	cancel := func(windowID, requestID string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]string{"window_id": windowID})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs/"+job.ID+"/change-windows", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), requestIDContextKey{}, requestID))
		response := httptest.NewRecorder()
		server.cancelChangeWindow(response, req, admin, ts, job)
		return response
	}
	missing := cancel("unknown-window", "missing-window-request")
	foreign := cancel(otherWindow.ID, "foreign-window-request")
	if missing.Code != http.StatusNotFound || foreign.Code != http.StatusNotFound || missing.Body.String() != foreign.Body.String() {
		t.Fatalf("unknown window = %d %s; another unit's window = %d %s; want identical 404 answers", missing.Code, missing.Body.String(), foreign.Code, foreign.Body.String())
	}
	closedResponse := cancel(closedWindow.ID, "closed-window-request")
	if closedResponse.Code != http.StatusConflict || !strings.Contains(closedResponse.Body.String(), `"code":"conflict"`) {
		t.Fatalf("closed window = %d %s; want 409 conflict", closedResponse.Code, closedResponse.Body.String())
	}
	failed := cancel(window.ID, "active-window-request")
	if failed.Code != http.StatusInternalServerError || !strings.Contains(failed.Body.String(), `"code":"notification"`) || strings.Contains(failed.Body.String(), brokenSource) {
		t.Fatalf("cancel with unavailable destinations = %d %s; want a redacted 500 notification error", failed.Code, failed.Body.String())
	}
	if !strings.Contains(failed.Body.String(), "active-window-request") || !strings.Contains(logs.String(), brokenSource) || !strings.Contains(logs.String(), "request_id=active-window-request") {
		t.Fatalf("started-window failure lost its request ID or destination cause: response=%q logs=%q", failed.Body.String(), logs.String())
	}
	open, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || open.ClosedAt != nil || open.ReviewState != "none" {
		t.Fatalf("window after failed destination read = %+v, %v; want unchanged and open", open, err)
	}
	var heldRows, coalescedRows, summaryRows, cancelAudits int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(coalesced_at<>''),0) FROM outbox WHERE change_window_id=?`, window.ID).Scan(&heldRows, &coalescedRows); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND event_job_id=?`, job.ID).Scan(&summaryRows); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE tenant_id=? AND action='change_window.cancelled'`, store.DefaultTenantID).Scan(&cancelAudits); err != nil {
		t.Fatal(err)
	}
	// The one audit entry is the setup cancellation of closedWindow. Failed
	// requests against missing, foreign, closed, and destination-blocked active
	// windows must not add another audit record.
	if heldRows != 1 || coalescedRows != 0 || summaryRows != 0 || cancelAudits != 1 {
		t.Fatalf("failed cancel side effects: held=%d coalesced=%d summaries=%d cancel audits=%d; want 1,0,0,1", heldRows, coalescedRows, summaryRows, cancelAudits)
	}

	if err := restoreMetadata(); err != nil {
		t.Fatal(err)
	}
	wantDestinations, err := server.App.Notifier.Tenant(ts).QueueDestinationsForJob(ctx, job.Job)
	if err != nil || len(wantDestinations) != 1 {
		t.Fatalf("healthy destination lookup = %v, %v; want one configured destination", wantDestinations, err)
	}
	retried := cancel(window.ID, "healthy-retry-request")
	if retried.Code != http.StatusOK {
		t.Fatalf("healthy retry = %d: %s", retried.Code, retried.Body.String())
	}
	closed, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || closed.ClosedAt == nil || closed.ReviewState != "due" {
		t.Fatalf("window after healthy retry = %+v, %v; want closed with due review", closed, err)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(coalesced_at<>''),0) FROM outbox WHERE change_window_id=?`, window.ID).Scan(&heldRows, &coalescedRows); err != nil {
		t.Fatal(err)
	}
	rows, err := db.DB.QueryContext(ctx, `SELECT destination FROM outbox WHERE event_type='change-window-summary' AND event_job_id=? ORDER BY destination`, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	gotDestinations := make([]string, 0, len(wantDestinations))
	for rows.Next() {
		var destination string
		if err := rows.Scan(&destination); err != nil {
			t.Fatal(err)
		}
		gotDestinations = append(gotDestinations, destination)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(wantDestinations)
	if heldRows != 1 || coalescedRows != 1 || !reflect.DeepEqual(gotDestinations, wantDestinations) || len(gotDestinations) != 1 {
		t.Fatalf("healthy retry deliveries: held=%d coalesced=%d summaries=%v; want one held coalesced row and destinations %v", heldRows, coalescedRows, gotDestinations, wantDestinations)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE tenant_id=? AND action='change_window.cancelled'`, store.DefaultTenantID).Scan(&cancelAudits); err != nil {
		t.Fatal(err)
	}
	if cancelAudits != 2 {
		t.Fatalf("cancel audit count after healthy retry = %d; want the setup and successful cancellation", cancelAudits)
	}
}

func TestCancelScheduledChangeWindowSucceedsWhenDestinationsCannotBeLoaded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, db, admin := newUsersTestServer(t)
	server := newRoutingTestServer(t, db, "generic://localhost/edgewatch?disabletls=yes&template=json")
	ts := defaultTenantStore(server)
	job, err := ts.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "cancel-scheduled-window-destination-failure", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window, err := ts.CreateChangeWindow(ctx, job.ID, start, start.Add(time.Hour), false, "maintenance", admin.UserID, admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.System().QueueEvent(ctx, "held-scheduled-change-alert", model.Event{
		Type: "changes-detected", JobID: job.ID, Job: job.Job.Name, ScanID: "cancel-scheduled-window-read-failure",
		Message: "change detected", CreatedAt: time.Now().UTC(),
		Changes: []model.Change{{Key: "port|192.0.2.10|tcp|443", Kind: "port", Severity: "high", Target: "192.0.2.10", Protocol: "tcp", Port: 443}},
	}); err != nil {
		t.Fatal(err)
	}

	const savedTable = "managed_notifications_saved_for_scheduled_cancel_test"
	const brokenSource = "missing_managed_notifications_for_scheduled_cancel_test"
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications RENAME TO `+savedTable); err != nil {
		t.Fatal(err)
	}
	viewInstalled := false
	restoreMetadata := func() error {
		if _, err := db.DB.ExecContext(ctx, `DROP VIEW IF EXISTS managed_notifications`); err != nil {
			return err
		}
		if _, err := db.DB.ExecContext(ctx, `ALTER TABLE `+savedTable+` RENAME TO managed_notifications`); err != nil {
			return err
		}
		viewInstalled = false
		return nil
	}
	t.Cleanup(func() {
		if viewInstalled {
			if err := restoreMetadata(); err != nil {
				t.Errorf("restore destination schema: %v", err)
			}
		}
	})
	if _, err := db.DB.ExecContext(ctx, `CREATE VIEW managed_notifications(id,tenant_id,name,provider,ciphertext,nonce,enabled,revision,credential_revision,created_at,updated_at) AS SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM `+brokenSource); err != nil {
		t.Fatal(err)
	}
	viewInstalled = true
	if _, err := server.App.Notifier.Tenant(ts).QueueDestinationsForJob(ctx, job.Job); err == nil {
		t.Fatal("destination lookup succeeded with a broken metadata source")
	}

	body, err := json.Marshal(map[string]string{"window_id": window.ID})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs/"+job.ID+"/change-windows", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.cancelChangeWindow(response, req, admin, ts, job)
	if response.Code != http.StatusOK {
		t.Fatalf("scheduled cancel with unavailable destinations = %d: %s; want 200", response.Code, response.Body.String())
	}
	var payload struct {
		Window store.ChangeWindow `json:"window"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Window.ID != window.ID || payload.Window.Status != "cancelled" || payload.Window.EndReason != "cancelled-before-start" || payload.Window.ClosedAt == nil || payload.Window.ReviewState != "none" || payload.Window.Summary != nil {
		t.Fatalf("scheduled cancel response = %+v; want cancelled-before-start without a closing review", payload.Window)
	}
	var linkedWindow, coalesced string
	if err := db.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at FROM outbox WHERE destination='held-scheduled-change-alert' AND event_job_id=?`, job.ID).Scan(&linkedWindow, &coalesced); err != nil {
		t.Fatal(err)
	}
	if linkedWindow != "" || coalesced != "" {
		t.Fatalf("held alert after scheduled cancellation = window %q coalesced %q; want released unchanged", linkedWindow, coalesced)
	}
	var summaries, cancelAudits int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND event_job_id=?`, job.ID).Scan(&summaries); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE tenant_id=? AND action='change_window.cancelled'`, store.DefaultTenantID).Scan(&cancelAudits); err != nil {
		t.Fatal(err)
	}
	if summaries != 0 || cancelAudits != 1 {
		t.Fatalf("scheduled cancellation side effects: summaries=%d cancel audits=%d; want 0 and 1", summaries, cancelAudits)
	}
}
