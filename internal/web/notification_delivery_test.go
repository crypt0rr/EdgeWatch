package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// queueTerminalDelivery queues an alert for unit A's destination and ends it
// for good, as a provider outage longer than the retry schedule does.
func (f *platformFixture) queueTerminalDelivery(t *testing.T) int64 {
	t.Helper()
	ctx := context.Background()
	view, err := f.server.App.Notifier.Tenant(f.a).Destination(ctx, f.destinationA)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.System().QueueEvent(ctx, "managed:"+f.destinationA+":"+strconv.FormatInt(view.Revision, 10), model.Event{Type: "changes-detected", Job: "shared-job", Message: "alpha-alert-body", TenantID: store.DefaultTenantID, CreatedAt: time.Now().UTC().Add(-80 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := f.db.DB.QueryRowContext(ctx, `UPDATE outbox SET attempts=15,terminal_at=?,last_error='delivery_failed' WHERE destination LIKE ? RETURNING id`, time.Now().UTC().Format(time.RFC3339Nano), "managed:"+f.destinationA+":%").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// Only a unit's administrators list and redeliver a destination's failed
// alerts. The list carries metadata only, never the alert's message or the
// destination's URL, and a redelivery queues the alert again, is audited,
// and leaves another unit's destination alone.
func TestTerminalDeliveryRoutesByRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPlatformFixture(t)
	id := f.queueTerminalDelivery(t)
	list := "/notifications/destinations/" + f.destinationA + "/deliveries"
	redeliver := list + "/redeliver"
	for _, actor := range []string{actorOperatorA, actorViewerA} {
		if response := f.call(t, actor, http.MethodGet, list, ""); response.Code != http.StatusForbidden {
			t.Errorf("%s listed failed alerts: %d %s", actor, response.Code, response.Body.String())
		}
		if response := f.call(t, actor, http.MethodPost, redeliver, `{}`); response.Code != http.StatusForbidden {
			t.Errorf("%s redelivered failed alerts: %d %s", actor, response.Code, response.Body.String())
		}
	}
	response := f.call(t, actorAdminA, http.MethodGet, list+"?state=terminal&limit=10", "")
	if response.Code != http.StatusOK {
		t.Fatalf("administrator list = %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, secret := range []string{"alpha-alert-body", "generic://", "localhost"} {
		if strings.Contains(body, secret) {
			t.Fatalf("the failed alert list names %q: %s", secret, body)
		}
	}
	var listed struct {
		Deliveries []struct {
			ID        int64  `json:"id"`
			EventType string `json:"event_type"`
			Job       string `json:"job"`
			EventAt   string `json:"event_at"`
			Attempts  int    `json:"attempts"`
			ErrorCode string `json:"error_code"`
		} `json:"deliveries"`
		NextBefore *int64 `json:"next_before"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Deliveries) != 1 || listed.Deliveries[0].ID != id || listed.Deliveries[0].EventType != "changes-detected" || listed.Deliveries[0].Job != "shared-job" || listed.Deliveries[0].EventAt == "" || listed.Deliveries[0].Attempts != 15 || listed.Deliveries[0].ErrorCode != "delivery_failed" || listed.NextBefore != nil {
		t.Fatalf("failed alerts = %s", body)
	}
	for query, field := range map[string]string{"?state=sent": "state", "?limit=0": "limit", "?limit=101": "limit", "?before=x": "before", "?before=0": "before"} {
		if response := f.call(t, actorAdminA, http.MethodGet, list+query, ""); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"`+field+`"`) {
			t.Errorf("list%s = %d: %s", query, response.Code, response.Body.String())
		}
	}
	if response := f.call(t, actorAdminA, http.MethodPost, redeliver, `{"delivery_ids":[]}`); response.Code != http.StatusBadRequest {
		t.Errorf("an empty selection = %d: %s", response.Code, response.Body.String())
	}
	tooMany := make([]string, store.MaxTerminalDeliveriesPage+1)
	for i := range tooMany {
		tooMany[i] = strconv.Itoa(i + 1)
	}
	if response := f.call(t, actorAdminA, http.MethodPost, redeliver, `{"delivery_ids":[`+strings.Join(tooMany, ",")+`]}`); response.Code != http.StatusBadRequest {
		t.Errorf("an oversized selection = %d: %s", response.Code, response.Body.String())
	}
	if response := f.call(t, actorAdminB, http.MethodPost, redeliver, `{}`); response.Code != http.StatusNotFound {
		t.Errorf("unit B redelivered unit A's alerts: %d %s", response.Code, response.Body.String())
	}
	response = f.call(t, actorAdminA, http.MethodPost, redeliver, `{"delivery_ids":[`+strconv.FormatInt(id, 10)+`]}`)
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"redelivered":1}` {
		t.Fatalf("redeliver = %d: %s", response.Code, response.Body.String())
	}
	var terminal string
	var attempts int
	if err := f.db.DB.QueryRowContext(ctx, `SELECT terminal_at,attempts FROM outbox WHERE id=?`, id).Scan(&terminal, &attempts); err != nil || terminal != "" || attempts != 0 {
		t.Fatalf("redelivered row: terminal %q, attempts %d, %v", terminal, attempts, err)
	}
	var audited int
	if err := f.db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='notifications.redelivered' AND tenant_id=? AND detail LIKE '%redelivered 1 failed deliveries%'`, store.DefaultTenantID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("redelivery audits = %d, %v", audited, err)
	}
	if response := f.call(t, actorAdminA, http.MethodPost, redeliver, `{}`); response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"redelivered":0}` {
		t.Fatalf("a redelivery with nothing left = %d: %s", response.Code, response.Body.String())
	}
	if response := f.call(t, actorAdminA, http.MethodGet, "/notifications/destinations/"+unknownIsolationIDs.destination+"/deliveries", ""); response.Code != http.StatusNotFound {
		t.Fatalf("an unknown destination = %d: %s", response.Code, response.Body.String())
	}
}

// A single-destination test that the provider does not answer in time is a
// 504 timeout, not a save failure, and names no URL. Only administrators can
// send it.
func TestDestinationTestTimeoutIsReportedAsATimeout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPlatformFixture(t)
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(func() { close(release); hung.Close() })
	parsed, err := url.Parse(hung.URL)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := f.server.App.Notifier.Tenant(f.a).CreateManagedWithAudit(ctx, "Hanging", "generic://"+parsed.Host+"/hook?disabletls=yes", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	path := "/notifications/destinations/" + destination.ID + "/test"
	for _, actor := range []string{actorOperatorA, actorViewerA} {
		if response := f.call(t, actor, http.MethodPost, path, ""); response.Code != http.StatusForbidden {
			t.Errorf("%s tested a destination: %d %s", actor, response.Code, response.Body.String())
		}
	}
	response := f.call(t, actorAdminA, http.MethodPost, path, "")
	if response.Code != http.StatusGatewayTimeout || !strings.Contains(response.Body.String(), `"notification_timeout"`) {
		t.Fatalf("a test that timed out = %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), parsed.Host) || strings.Contains(response.Body.String(), "could not be saved") {
		t.Fatalf("the timeout response = %s", response.Body.String())
	}
	recorder := httptest.NewRecorder()
	f.server.writeNotificationError(recorder, context.DeadlineExceeded)
	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("a deadline = %d", recorder.Code)
	}
}

// With the default target exclusions, a unit administrator cannot create or
// repoint a destination at a loopback or link-local address; the answer is a
// fixed validation error that does not echo the URL. A public address is
// accepted.
func TestExcludedDestinationIsRefusedByTheAPI(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	if err := f.server.App.Notifier.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"generic://127.0.0.1:8080/hook?disabletls=yes", "generic://169.254.169.254/latest", "generic://[::1]/hook"} {
		response := f.call(t, actorAdminA, http.MethodPost, "/notifications/destinations", confirmBody(`"name":"refused","url":"`+raw+`"`))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "does not allow") {
			t.Errorf("create %s = %d: %s", raw, response.Code, response.Body.String())
		}
		for _, secret := range []string{raw, "127.0.0.1", "169.254", "::1"} {
			if strings.Contains(response.Body.String(), secret) {
				t.Errorf("create %s: the response names %q: %s", raw, secret, response.Body.String())
			}
		}
	}
	response := f.call(t, actorAdminA, http.MethodPost, "/notifications/destinations", confirmBody(`"name":"public","url":"generic://203.0.113.10/hook"`))
	if response.Code != http.StatusCreated {
		t.Fatalf("a public destination = %d: %s", response.Code, response.Body.String())
	}
	var created notify.DestinationView
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	response = f.call(t, actorAdminA, http.MethodPut, "/notifications/destinations/"+created.ID, confirmBody(`"name":"public","revision":`+strconv.FormatInt(created.Revision, 10)+`,"url":"generic://127.0.0.1/hook"`))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"url"`) {
		t.Fatalf("repointing at loopback = %d: %s", response.Code, response.Body.String())
	}
}

// keep_pending moves a destination's queued alerts to its replacement URL
// and records the count; without it they are discarded as before.
func TestReplacingAURLCanKeepQueuedAlerts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPlatformFixture(t)
	view, err := f.server.App.Notifier.Tenant(f.a).Destination(ctx, f.destinationA)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.System().QueueEvent(ctx, "managed:"+f.destinationA+":"+strconv.FormatInt(view.Revision, 10), model.Event{Type: "changes-detected", Job: "shared-job", TenantID: store.DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	response := f.call(t, actorAdminA, http.MethodPut, "/notifications/destinations/"+f.destinationA, confirmBody(`"name":"alpha-destination","revision":`+strconv.FormatInt(view.Revision, 10)+`,"url":"generic://localhost/repaired?disabletls=yes","keep_pending":true`))
	if response.Code != http.StatusOK {
		t.Fatalf("replace keeping alerts = %d: %s", response.Code, response.Body.String())
	}
	var updated notify.DestinationView
	if err := json.Unmarshal(response.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	var kept int
	if err := f.db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=? AND sent_at IS NULL`, "managed:"+f.destinationA+":"+strconv.FormatInt(updated.Revision, 10)).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("kept alerts = %d, %v; want 1", kept, err)
	}
	var audited int
	if err := f.db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='notifications.pending_kept' AND detail LIKE 'kept 1 pending and 0 failed%'`).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("keep audits = %d, %v", audited, err)
	}
	response = f.call(t, actorAdminA, http.MethodPut, "/notifications/destinations/"+f.destinationA, confirmBody(`"name":"alpha-destination","revision":`+strconv.FormatInt(updated.Revision, 10)+`,"url":"generic://localhost/rotated?disabletls=yes"`))
	if response.Code != http.StatusOK {
		t.Fatalf("replace = %d: %s", response.Code, response.Body.String())
	}
	if err := f.db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination LIKE ? AND sent_at IS NULL`, "managed:"+f.destinationA+":%").Scan(&kept); err != nil || kept != 0 {
		t.Fatalf("alerts after a plain replacement = %d, %v; want them discarded", kept, err)
	}
}
