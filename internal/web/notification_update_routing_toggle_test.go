package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func createUpdateRoutingTestDestination(t *testing.T, server *Server, admin store.Session, name, path string) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	body := fmt.Sprintf(`{"name":%q,"url":%q,"password":"administrator password"}`, name, "generic://localhost/"+path+"?disabletls=yes")
	server.createNotificationDestination(recorder, routingRequest(t, http.MethodPost, "/api/v1/notifications/destinations", body), admin, defaultTenantStore(server))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create destination %q = %d: %s", name, recorder.Code, recorder.Body.String())
	}
	var result struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.ID
}

func toggleUpdateRoutingRequest(t *testing.T, server *Server, admin store.Session, destinationID string, enabled bool) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	body := fmt.Sprintf(`{"destination_id":%q,"enabled":%t,"password":"administrator password"}`, destinationID, enabled)
	toggleUpdateRoutingBody(t, server, admin, body, recorder)
	return recorder
}

func toggleUpdateRoutingBody(t *testing.T, server *Server, admin store.Session, body string, recorder *httptest.ResponseRecorder) {
	t.Helper()
	server.toggleNotificationUpdateRouting(recorder, routingRequest(t, http.MethodPatch, "/api/v1/notifications/update-routing", body), admin, defaultTenantStore(server))
}

func TestNotificationRoutingTogglePreservesConcurrentDestinations(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	defer db.Close()
	ts := defaultTenantStore(server)
	a := createUpdateRoutingTestDestination(t, server, admin, "First", "first")
	b := createUpdateRoutingTestDestination(t, server, admin, "Second", "second")
	c := createUpdateRoutingTestDestination(t, server, admin, "Third", "third")
	if err := ts.SetApplicationUpdateDestinations(ctx, []string{a}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	paused := false
	if _, err := server.App.Notifier.Tenant(ts).UpdateManagedWithAudit(ctx, a, 1, "First", nil, &paused, store.AuditEntry{Action: "notifications.updated", ActorUserID: admin.UserID, ActorUsername: admin.Username}); err != nil {
		t.Fatalf("pause selected destination: %v", err)
	}

	results := make([]*httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for index, id := range []string{b, c} {
		wg.Add(1)
		go func(index int, id string) {
			defer wg.Done()
			results[index] = toggleUpdateRoutingRequest(t, server, admin, id, true)
		}(index, id)
	}
	wg.Wait()
	for _, result := range results {
		if result.Code != http.StatusOK {
			t.Fatalf("toggle = %d: %s", result.Code, result.Body.String())
		}
	}
	state, err := ts.ApplicationUpdateRouting(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{a, b, c}
	slices.Sort(want)
	if !state.Configured || !slices.Equal(state.Destinations, want) {
		t.Fatalf("routing = %#v, want all concurrent changes %v", state, want)
	}
}

func TestNotificationRoutingToggleMaterializesLegacySelection(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	defer db.Close()
	ts := defaultTenantStore(server)
	a := createUpdateRoutingTestDestination(t, server, admin, "First", "first")
	b := createUpdateRoutingTestDestination(t, server, admin, "Second", "second")
	c := createUpdateRoutingTestDestination(t, server, admin, "Third", "third")
	state, err := ts.ApplicationUpdateRouting(ctx)
	if err != nil || state.Configured {
		t.Fatalf("initial routing = %#v, %v; want legacy routing", state, err)
	}
	paused := false
	pausedDestination, err := server.App.Notifier.Tenant(ts).UpdateManagedWithAudit(ctx, a, 1, "First", nil, &paused, store.AuditEntry{Action: "notifications.updated", ActorUserID: admin.UserID, ActorUsername: admin.Username})
	if err != nil || pausedDestination.Enabled {
		t.Fatalf("pause first destination = %+v, %v", pausedDestination, err)
	}
	legacy, err := server.App.Notifier.Tenant(ts).LegacySelection(ctx)
	wantLegacy := []string{a, b, c}
	slices.Sort(wantLegacy)
	if err != nil || !slices.Equal(legacy, wantLegacy) {
		t.Fatalf("legacy selection = %v, %v", legacy, err)
	}
	result := toggleUpdateRoutingRequest(t, server, admin, c, false)
	if result.Code != http.StatusOK {
		t.Fatalf("toggle = %d: %s", result.Code, result.Body.String())
	}
	state, err = ts.ApplicationUpdateRouting(ctx)
	want := []string{a, b}
	slices.Sort(want)
	if err != nil || !state.Configured || !slices.Equal(state.Destinations, want) {
		t.Fatalf("routing after first toggle = %#v, %v; want explicit %v", state, err, want)
	}
	keys, err := server.App.Notifier.Tenant(ts).QueueDestinationsForSelection(ctx, state.Destinations)
	if err != nil || !slices.Equal(keys, []string{"managed:" + b + ":1"}) {
		t.Fatalf("update routing while First is paused queues %v, %v; want only Second", keys, err)
	}
	enabled := true
	resumedDestination, err := server.App.Notifier.Tenant(ts).UpdateManagedWithAudit(ctx, a, pausedDestination.Revision, "First", nil, &enabled, store.AuditEntry{Action: "notifications.updated", ActorUserID: admin.UserID, ActorUsername: admin.Username})
	if err != nil || !resumedDestination.Enabled {
		t.Fatalf("resume first destination = %+v, %v", resumedDestination, err)
	}
	keys, err = server.App.Notifier.Tenant(ts).QueueDestinationsForSelection(ctx, state.Destinations)
	wantKeys := []string{"managed:" + a + ":" + fmt.Sprint(resumedDestination.Revision), "managed:" + b + ":1"}
	slices.Sort(wantKeys)
	if err != nil || !slices.Equal(keys, wantKeys) {
		t.Fatalf("update routing after First resumes queues %v, %v; want %v", keys, err, wantKeys)
	}
	result = toggleUpdateRoutingRequest(t, server, admin, b, false)
	if result.Code != http.StatusOK {
		t.Fatalf("disable Second = %d: %s", result.Code, result.Body.String())
	}
	result = toggleUpdateRoutingRequest(t, server, admin, a, false)
	if result.Code != http.StatusOK {
		t.Fatalf("disable remaining destination = %d: %s", result.Code, result.Body.String())
	}
	state, err = ts.ApplicationUpdateRouting(ctx)
	if err != nil || !state.Configured || len(state.Destinations) != 0 {
		t.Fatalf("routing after disabling final destination = %#v, %v; want configured empty", state, err)
	}
}

func TestNotificationRoutingToggleCanonicalizesLegacyDeploymentSelector(t *testing.T) {
	ctx := context.Background()
	_, db, admin := newUsersTestServer(t)
	defer db.Close()
	const url = "generic://localhost/hook?token=legacy-token&disabletls=yes&template=json"
	digest := sha256.Sum256([]byte(url))
	legacySelector := "file:" + hex.EncodeToString(digest[:])
	if err := defaultTenant(db).SetApplicationUpdateDestinations(ctx, []string{legacySelector}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	server := newRoutingTestServer(t, db, url)
	canonicalSelector := legacySelection(t, server)[0]
	if canonicalSelector == legacySelector {
		t.Fatalf("deployment selector was not opaque: %q", canonicalSelector)
	}

	result := toggleUpdateRoutingRequest(t, server, admin, canonicalSelector, false)
	if result.Code != http.StatusOK {
		t.Fatalf("disable update routing = %d: %s", result.Code, result.Body.String())
	}
	state, err := defaultTenantStore(server).ApplicationUpdateRouting(ctx)
	if err != nil || !state.Configured || len(state.Destinations) != 0 {
		t.Fatalf("routing after disabling legacy destination = %#v, %v; want explicit empty selection", state, err)
	}
	keys, err := server.App.Notifier.Tenant(defaultTenantStore(server)).QueueDestinationsForSelection(ctx, state.Destinations)
	if err != nil || len(keys) != 0 {
		t.Fatalf("disabled update routing queues %v, %v; want no destinations", keys, err)
	}
	listed := httptest.NewRecorder()
	server.listNotificationDestinations(listed, routingRequest(t, http.MethodGet, "/api/v1/notifications/destinations", ""), defaultTenantStore(server))
	var listedRouting struct {
		UpdateRouting struct {
			Configured   bool     `json:"configured"`
			Destinations []string `json:"destinations"`
		} `json:"update_routing"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &listedRouting); err != nil || listed.Code != http.StatusOK || !listedRouting.UpdateRouting.Configured || len(listedRouting.UpdateRouting.Destinations) != 0 {
		t.Fatalf("destination list after disabling legacy selector = %d %s (%v); want an explicit empty selection", listed.Code, listed.Body.String(), err)
	}

	result = toggleUpdateRoutingRequest(t, server, admin, canonicalSelector, true)
	if result.Code != http.StatusOK {
		t.Fatalf("enable update routing = %d: %s", result.Code, result.Body.String())
	}
	state, err = defaultTenantStore(server).ApplicationUpdateRouting(ctx)
	if err != nil || !state.Configured || !slices.Equal(state.Destinations, []string{canonicalSelector}) {
		t.Fatalf("routing after enabling deployment destination = %#v, %v; want only canonical selector %q", state, err, canonicalSelector)
	}
	keys, err = server.App.Notifier.Tenant(defaultTenantStore(server)).QueueDestinationsForSelection(ctx, state.Destinations)
	if err != nil || len(keys) != 1 {
		t.Fatalf("enabled update routing queues %v, %v; want the deployment destination", keys, err)
	}
}

func TestNotificationRoutingToggleFailsClosedWhenDestinationsCannotBeCanonicalized(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	defer db.Close()
	if err := defaultTenantStore(server).SetApplicationUpdateDestinations(ctx, []string{}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`DROP TABLE managed_notifications`); err != nil {
		t.Fatal(err)
	}
	result := toggleUpdateRoutingRequest(t, server, admin, "unknown-destination", true)
	if result.Code != http.StatusInternalServerError || !strings.Contains(result.Body.String(), `"code":"notification_failed"`) {
		t.Fatalf("toggle with unreadable destination set = %d: %s; want fail-closed notification error", result.Code, result.Body.String())
	}
}

func TestNotificationDestinationListFailsClosedWhenRoutingCannotBeRead(t *testing.T) {
	server, db, _ := newUsersTestServer(t)
	defer db.Close()
	if _, err := db.DB.Exec(`UPDATE tenants SET update_destinations_json='{' WHERE id=?`, store.DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.listNotificationDestinations(recorder, routingRequest(t, http.MethodGet, "/api/v1/notifications/destinations", ""), defaultTenantStore(server))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("destination list status = %d, want 500: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), `"update_routing"`) {
		t.Fatalf("failed routing read returned fabricated selection: %s", recorder.Body.String())
	}
}

func TestNotificationDestinationListFailsClosedWhenCanonicalSelectionCannotBeRead(t *testing.T) {
	server, db, _ := newUsersTestServer(t)
	defer db.Close()
	// The update-routing row remains readable, but loading the tenant-owned
	// destination set fails while canonicalizing its selectors.
	if _, err := db.DB.Exec(`DROP TABLE managed_notifications`); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.listNotificationDestinations(recorder, routingRequest(t, http.MethodGet, "/api/v1/notifications/destinations", ""), defaultTenantStore(server))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("destination list status = %d, want 500: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), `"update_routing"`) {
		t.Fatalf("failed canonicalization returned a fabricated selection: %s", recorder.Body.String())
	}
}

func TestNotificationRoutingToggleRejectsInvalidInputAndStorageFailures(t *testing.T) {
	server, db, admin := newUsersTestServer(t)
	defer db.Close()
	ts := defaultTenantStore(server)
	destination := createUpdateRoutingTestDestination(t, server, admin, "Operations", "operations")

	tests := []struct {
		name   string
		body   string
		status int
		code   string
	}{
		{name: "invalid JSON", body: `{`, status: http.StatusBadRequest, code: "invalid_json"},
		{name: "missing fields", body: `{"password":"administrator password"}`, status: http.StatusBadRequest, code: "validation_failed"},
		{name: "missing password", body: fmt.Sprintf(`{"destination_id":%q,"enabled":true}`, destination), status: http.StatusBadRequest, code: "password_required"},
		{name: "wrong password", body: fmt.Sprintf(`{"destination_id":%q,"enabled":true,"password":"wrong password"}`, destination), status: http.StatusUnauthorized, code: "invalid_password"},
		{name: "unknown destination", body: `{"destination_id":"unknown","enabled":true,"password":"administrator password"}`, status: http.StatusBadRequest, code: "validation_failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			toggleUpdateRoutingBody(t, server, admin, test.body, recorder)
			expectError(t, recorder, test.status, test.code, test.name)
		})
	}

	if _, err := db.DB.Exec(`UPDATE tenants SET update_destinations_json='{' WHERE id=?`, store.DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	stateFailure := toggleUpdateRoutingRequest(t, server, admin, destination, true)
	expectError(t, stateFailure, http.StatusInternalServerError, "notification_failed", "unreadable routing state")
	if _, err := db.DB.Exec(`UPDATE tenants SET update_destinations_json='' WHERE id=?`, store.DefaultTenantID); err != nil {
		t.Fatal(err)
	}

	removeAuditFailure := failTableWrites(t, db, "security_audit", "INSERT", "audit unavailable")
	auditFailure := toggleUpdateRoutingRequest(t, server, admin, destination, true)
	expectError(t, auditFailure, http.StatusServiceUnavailable, "audit_unavailable", "routing audit failure")
	removeAuditFailure()

	state, err := ts.ApplicationUpdateRouting(context.Background())
	if err != nil || state.Configured {
		t.Fatalf("failed toggle changed routing = %#v, %v; want unconfigured", state, err)
	}
}

func TestPlatformNotificationListFailsClosedWhenRoutingCannotBeRead(t *testing.T) {
	f := newPlatformFixture(t)
	if _, err := f.db.DB.Exec(`UPDATE application_update_state SET notification_destinations_json='{' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	recorder := f.call(t, actorPlatform, http.MethodGet, "/platform/notifications", "")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("platform notification list status = %d, want 500: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), `"update_routing"`) {
		t.Fatalf("failed platform routing read returned fabricated selection: %s", recorder.Body.String())
	}
}

func TestPlatformNotificationRoutingToggleValidationAndRecovery(t *testing.T) {
	f := newPlatformFixture(t)
	if recorder := f.call(t, actorPlatform, http.MethodGet, "/platform/notifications", ""); recorder.Code != http.StatusOK {
		t.Fatalf("initial platform notification list = %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, err := f.db.DB.Exec(`UPDATE application_update_state SET notification_destinations_json='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	create := f.call(t, actorPlatform, http.MethodPost, "/platform/notifications", confirmBody(`"name":"Operations","url":"generic://localhost/platform-operations?disabletls=yes"`))
	var destination struct {
		ID string `json:"id"`
	}
	expectResponse(t, create, http.StatusCreated, "create platform destination", &destination)

	tests := []struct {
		name   string
		body   string
		status int
		code   string
	}{
		{name: "invalid JSON", body: `{`, status: http.StatusBadRequest, code: "invalid_json"},
		{name: "missing fields", body: confirmBody(""), status: http.StatusBadRequest, code: "validation_failed"},
		{name: "wrong password", body: fmt.Sprintf(`{"password":"wrong password","destination_id":%q,"enabled":true}`, destination.ID), status: http.StatusUnauthorized, code: "invalid_password"},
		{name: "unknown destination", body: confirmBody(`"destination_id":"unknown","enabled":true`), status: http.StatusBadRequest, code: "validation_failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectError(t, f.call(t, actorPlatform, http.MethodPatch, "/platform/notifications/update-routing", test.body), test.status, test.code, test.name)
		})
	}

	// The first explicit toggle starts from platform routing's empty default.
	firstToggle := f.call(t, actorPlatform, http.MethodPatch, "/platform/notifications/update-routing", confirmBody(fmt.Sprintf(`"destination_id":%q,"enabled":true`, destination.ID)))
	expectResponse(t, firstToggle, http.StatusOK, "toggle from unconfigured state", nil)

	if _, err := f.db.DB.Exec(`UPDATE application_update_state SET notification_destinations_json='{' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	stateFailure := f.call(t, actorPlatform, http.MethodPatch, "/platform/notifications/update-routing", confirmBody(fmt.Sprintf(`"destination_id":%q,"enabled":false`, destination.ID)))
	expectError(t, stateFailure, http.StatusInternalServerError, "notification_failed", "unreadable platform routing")

	if _, err := f.db.DB.Exec(`UPDATE application_update_state SET notification_destinations_json='["unknown"]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	unknownStored := f.call(t, actorPlatform, http.MethodPatch, "/platform/notifications/update-routing", confirmBody(fmt.Sprintf(`"destination_id":%q,"enabled":false`, destination.ID)))
	expectError(t, unknownStored, http.StatusBadRequest, "validation_failed", "unknown stored platform selector")

	if _, err := f.db.DB.Exec(`UPDATE application_update_state SET notification_destinations_json='[]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	removeAuditFailure := failTableWrites(t, f.db, "security_audit", "INSERT", "audit unavailable")
	auditFailure := f.call(t, actorPlatform, http.MethodPatch, "/platform/notifications/update-routing", confirmBody(fmt.Sprintf(`"destination_id":%q,"enabled":true`, destination.ID)))
	expectError(t, auditFailure, http.StatusServiceUnavailable, "audit_unavailable", "platform routing audit failure")
	removeAuditFailure()
}

func TestPlatformNotificationRoutingTogglePreservesConcurrentDestinations(t *testing.T) {
	f := newPlatformFixture(t)
	create := func(name string) string {
		t.Helper()
		recorder := f.call(t, actorPlatform, http.MethodPost, "/platform/notifications", confirmBody(fmt.Sprintf(`"name":%q,"url":%q`, name, "generic://localhost/"+name+"?disabletls=yes")))
		var response struct {
			ID string `json:"id"`
		}
		expectResponse(t, recorder, http.StatusCreated, "create platform destination", &response)
		return response.ID
	}
	a := create("First")
	b := create("Second")
	c := create("Third")
	ctx := context.Background()
	actor := store.AuditEntry{ActorUserID: f.users[actorPlatform].ID, ActorUsername: "platform-root", ActorKind: store.AuditActorPlatform}
	if err := f.db.Platform().SetPlatformUpdateDestinations(ctx, []string{a}, actor); err != nil {
		t.Fatal(err)
	}
	paused := false
	if _, err := f.server.App.Notifier.Platform(f.db.Platform()).UpdateManagedWithAudit(ctx, a, 1, "First", nil, &paused, actor); err != nil {
		t.Fatalf("pause selected platform destination: %v", err)
	}
	second, err := f.db.GetAccount(ctx, f.secondPlatformAdmin)
	if err != nil {
		t.Fatal(err)
	}
	const secondPlatformActor = "second platform administrator"
	f.users[secondPlatformActor] = second
	f.sessions[secondPlatformActor] = f.signIn(t, secondPlatformActor)

	results := make([]*httptest.ResponseRecorder, 2)
	actors := []string{actorPlatform, secondPlatformActor}
	var wg sync.WaitGroup
	for index, id := range []string{b, c} {
		wg.Add(1)
		go func(index int, id string) {
			defer wg.Done()
			body := confirmBody(fmt.Sprintf(`"destination_id":%q,"enabled":true`, id))
			account := f.sessions[actors[index]]
			request := httptest.NewRequest(http.MethodPatch, consoleAPIBase+"/platform/notifications/update-routing", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-CSRF-Token", account.session.CSRFToken)
			request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: account.raw})
			results[index] = httptest.NewRecorder()
			f.server.api(results[index], request)
		}(index, id)
	}
	wg.Wait()
	for _, result := range results {
		if result.Code != http.StatusOK {
			t.Fatalf("platform toggle = %d: %s", result.Code, result.Body.String())
		}
	}
	state, err := f.db.Platform().GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{a, b, c}
	slices.Sort(want)
	if !state.UpdateNotificationDestinationsConfigured || !slices.Equal(state.UpdateNotificationDestinations, want) {
		t.Fatalf("platform routing = %#v, want both concurrent changes %v", state, want)
	}
}
