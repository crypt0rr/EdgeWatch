package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The notification routes resolve destinations and update routing through
// the session's tenant. An administrator of another tenant sees only its own
// destinations and routing. Reading, changing, deleting, or testing the
// first tenant's destination fails exactly as for an unknown one, and so
// does selecting it for a job or for the update routing. The first tenant's
// destination and routing stay as they are, and no response names a URL.
func TestNotificationRoutesUseTheSessionTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{Name: "routed", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}})
	jobA, err := defaultTenantStore(server).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}

	// The other tenant has an administrator with the same password and a
	// copy of the job. No product API creates a tenant yet.
	const otherTenantID = "00000000-0000-0000-0000-000000000200"
	const jobB = "00000000-0000-0000-0000-000000000b01"
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	other, err := defaultTenant(db).CreateUser(ctx, store.User{Username: "other-admin", DisplayName: "Other", Role: store.RoleAdministrator, PasswordHash: "unused-hash", Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, []any{otherTenantID, stamp, stamp}},
		{`UPDATE users SET tenant_id=?,password_hash=(SELECT password_hash FROM users WHERE id=?) WHERE id=?`, []any{otherTenantID, admin.UserID, other.ID}},
		{`INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) SELECT ?1,?3,name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs WHERE id=?2`, []any{jobB, jobA.ID, otherTenantID}},
		{`INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) SELECT ?1,revision,definition_json,security_hash,created_at FROM job_revisions WHERE job_id=?2`, []any{jobB, jobA.ID}},
		{`INSERT INTO job_silence_state(job_id,eligible_at,updated_at) SELECT ?1,eligible_at,updated_at FROM job_silence_state WHERE job_id=?2`, []any{jobB, jobA.ID}},
	} {
		if _, err := db.DB.ExecContext(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("%s: %v", statement.sql, err)
		}
	}
	cookies := map[string]string{}
	for name, userID := range map[string]string{"own": admin.UserID, "other": other.ID} {
		raw := "tenant-notification-" + name
		if err := db.CreateSessionForUserWithAudit(ctx, userID, digest(raw), "csrf-"+name, now, now.Add(time.Hour), "", ""); err != nil {
			t.Fatal(err)
		}
		cookies[name] = raw
	}
	enrollAdministratorsInTOTP(t, db)
	var bodies []string
	call := func(account, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "edgewatch_session", Value: cookies[account]})
		req.Header.Set("X-CSRF-Token", "csrf-"+account)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.api(rec, req)
		bodies = append(bodies, rec.Body.String())
		return rec
	}
	const password = `"password":"administrator password"`
	urls := map[string]string{"own": "generic://127.0.0.1:9/own-secret?disabletls=yes&template=json", "other": "generic://127.0.0.1:9/other-secret?disabletls=yes&template=json"}
	ids := map[string]string{}
	for _, account := range []string{"own", "other"} {
		// Both tenants use the same name.
		rec := call(account, http.MethodPost, "/api/v1/notifications/destinations", fmt.Sprintf(`{"name":"Operations","url":%q,%s}`, urls[account], password))
		var created struct {
			ID string `json:"id"`
		}
		if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &created) != nil || created.ID == "" {
			t.Fatalf("%s tenant: create = %d: %s", account, rec.Code, rec.Body.String())
		}
		ids[account] = created.ID
		if rec := call(account, http.MethodPut, "/api/v1/notifications/update-routing", fmt.Sprintf(`{"destinations":[%q],%s}`, created.ID, password)); rec.Code != http.StatusOK {
			t.Fatalf("%s tenant: routing = %d: %s", account, rec.Code, rec.Body.String())
		}
	}

	type listing struct {
		Destinations []struct {
			ID string `json:"id"`
		} `json:"destinations"`
		Status        map[string]any `json:"status"`
		UpdateRouting struct {
			Configured   bool     `json:"configured"`
			Destinations []string `json:"destinations"`
		} `json:"update_routing"`
	}
	list := func(account, path string) listing {
		t.Helper()
		var view listing
		rec := call(account, http.MethodGet, path, "")
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &view) != nil {
			t.Fatalf("%s tenant: %s = %d: %s", account, path, rec.Code, rec.Body.String())
		}
		return view
	}
	checkLists := func() {
		t.Helper()
		for _, account := range []string{"own", "other"} {
			for _, path := range []string{"/api/v1/notifications/destinations", "/api/v1/notifications/options"} {
				view := list(account, path)
				if len(view.Destinations) != 1 || view.Destinations[0].ID != ids[account] || view.Status["managed"] != float64(1) {
					t.Errorf("%s tenant: %s destinations = %+v, status %v", account, path, view.Destinations, view.Status)
				}
				if !view.UpdateRouting.Configured || !reflect.DeepEqual(view.UpdateRouting.Destinations, []string{ids[account]}) {
					t.Errorf("%s tenant: %s update routing = %+v", account, path, view.UpdateRouting)
				}
			}
		}
	}
	checkLists()

	// sameAsUnknown sends the request for the first tenant's destination and
	// for an unknown one as the other tenant, and requires the same answer
	// apart from the ID that a validation message repeats.
	const unknown = "00000000-0000-0000-0000-00000000dead"
	sameAsUnknown := func(method, path, body string, status int) {
		t.Helper()
		resetTestLimiter := func() {
			server.testMu.Lock()
			server.testLast = make(map[string]time.Time)
			server.testMu.Unlock()
		}
		// Compare tenant isolation with each request starting outside the rate
		// limit window so this assertion tests destination lookup, not throttling.
		resetTestLimiter()
		leaked := call("other", method, strings.ReplaceAll(path, "{id}", ids["own"]), strings.ReplaceAll(body, "{id}", ids["own"]))
		resetTestLimiter()
		missing := call("other", method, strings.ReplaceAll(path, "{id}", unknown), strings.ReplaceAll(body, "{id}", unknown))
		if leaked.Code != status || leaked.Code != missing.Code || strings.ReplaceAll(leaked.Body.String(), ids["own"], "ID") != strings.ReplaceAll(missing.Body.String(), unknown, "ID") {
			t.Errorf("other tenant: %s %s = %d %s; unknown destination = %d %s; want %d for both", method, path, leaked.Code, leaked.Body.String(), missing.Code, missing.Body.String(), status)
		}
	}
	destination := "/api/v1/notifications/destinations/{id}"
	sameAsUnknown(http.MethodGet, destination, "", http.StatusNotFound)
	sameAsUnknown(http.MethodPost, destination+"/test", "", http.StatusNotFound)
	sameAsUnknown(http.MethodPut, destination, fmt.Sprintf(`{"name":"stolen","url":%q,"enabled":true,"revision":1,%s}`, urls["other"], password), http.StatusNotFound)
	sameAsUnknown(http.MethodDelete, destination, `{"revision":1,`+password+`}`, http.StatusNotFound)
	sameAsUnknown(http.MethodPut, "/api/v1/notifications/update-routing", `{"destinations":["{id}"],`+password+`}`, http.StatusBadRequest)
	newJob := `{"name":"routed-elsewhere","schedule":"0 * * * *","timezone":"UTC","targets":["192.0.2.20"],"tcp":{"ports":"1","mode":"connect"},"notification_destinations":["{id}"]}`
	sameAsUnknown(http.MethodPost, "/api/v1/jobs", newJob, http.StatusBadRequest)
	update := fromConfig(job)
	update.Revision = 1
	update.NotificationDestinations = &[]string{"{id}"}
	updateBody, err := json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	sameAsUnknown(http.MethodPut, "/api/v1/jobs/"+jobB, string(updateBody), http.StatusBadRequest)

	// The first tenant's destination, routing, and job are unchanged, and
	// each tenant still sees only its own.
	stored, err := defaultTenantStore(server).GetManagedNotification(ctx, ids["own"])
	if err != nil || stored.Name != "Operations" || stored.Revision != 1 || !stored.Enabled {
		t.Fatalf("the first tenant's destination changed: %+v, %v", stored, err)
	}
	checkLists()

	// A selection saved before the check, which names the first tenant's
	// destination, is shown to the other tenant as missing.
	if _, err := db.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=json_set(definition_json,'$.notification_destinations',json_array(?,?)) WHERE id=?`, ids["own"], ids["other"], jobB); err != nil {
		t.Fatal(err)
	}
	var shown struct {
		Missing []string `json:"missing_notification_destinations"`
	}
	if rec := call("other", http.MethodGet, "/api/v1/jobs/"+jobB, ""); rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &shown) != nil || !reflect.DeepEqual(shown.Missing, []string{ids["own"]}) {
		t.Fatalf("other tenant: job = %d: %s", rec.Code, rec.Body.String())
	}

	// Each tenant manages its own destination.
	if rec := call("other", http.MethodDelete, "/api/v1/notifications/destinations/"+ids["other"], `{"revision":1,`+password+`}`); rec.Code != http.StatusNoContent {
		t.Fatalf("other tenant: delete its own destination = %d: %s", rec.Code, rec.Body.String())
	}
	if view := list("own", "/api/v1/notifications/destinations"); len(view.Destinations) != 1 || !reflect.DeepEqual(view.UpdateRouting.Destinations, []string{ids["own"]}) {
		t.Fatalf("the other tenant's delete changed the first tenant: %+v", view)
	}
	for _, body := range bodies {
		if strings.Contains(body, "own-secret") || strings.Contains(body, "other-secret") {
			t.Fatalf("a response names a URL: %s", body)
		}
	}
}

// A tenant store without a tenant, which the router never passes, fails the
// notification routes closed instead of reading any tenant's destinations.
func TestNotificationRoutesFailClosedWithoutATenant(t *testing.T) {
	t.Parallel()
	server, _, admin := newUsersTestServer(t)
	none := server.Store.Tenant(store.TenantScope{})
	rec := httptest.NewRecorder()
	server.listNotificationDestinations(rec, httptest.NewRequest(http.MethodGet, "/api/v1/notifications/destinations", nil), none)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "notification state could not be loaded") {
		t.Fatalf("list = %d: %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/notifications/update-routing", strings.NewReader(`{"destinations":["x"],"password":"administrator password"}`))
	req.Header.Set("Content-Type", "application/json")
	server.updateNotificationRouting(rec, req, admin, none)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "notification destinations could not be loaded") {
		t.Fatalf("update routing = %d: %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	if server.validateNotificationSelection(rec, httptest.NewRequest(http.MethodPost, "/api/v1/jobs", nil), none, config.Job{NotificationDestinations: []string{"x"}}) || rec.Code != http.StatusInternalServerError {
		t.Fatalf("job selection = %d: %s", rec.Code, rec.Body.String())
	}
}
