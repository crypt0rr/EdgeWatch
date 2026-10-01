package web

import (
	"context"
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
	server.toggleNotificationUpdateRouting(recorder, routingRequest(t, http.MethodPatch, "/api/v1/notifications/update-routing", body), admin, defaultTenantStore(server))
	return recorder
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
	state, err := ts.ApplicationUpdateRouting(ctx)
	if err != nil || state.Configured {
		t.Fatalf("initial routing = %#v, %v; want legacy routing", state, err)
	}
	legacy, err := server.App.Notifier.Tenant(ts).LegacySelection(ctx)
	wantLegacy := []string{a, b}
	slices.Sort(wantLegacy)
	if err != nil || !slices.Equal(legacy, wantLegacy) {
		t.Fatalf("legacy selection = %v, %v", legacy, err)
	}
	result := toggleUpdateRoutingRequest(t, server, admin, a, false)
	if result.Code != http.StatusOK {
		t.Fatalf("toggle = %d: %s", result.Code, result.Body.String())
	}
	state, err = ts.ApplicationUpdateRouting(ctx)
	if err != nil || !state.Configured || !slices.Equal(state.Destinations, []string{b}) {
		t.Fatalf("routing after first toggle = %#v, %v; want explicit [%s]", state, err, b)
	}
	result = toggleUpdateRoutingRequest(t, server, admin, b, false)
	if result.Code != http.StatusOK {
		t.Fatalf("disable final destination = %d: %s", result.Code, result.Body.String())
	}
	state, err = ts.ApplicationUpdateRouting(ctx)
	if err != nil || !state.Configured || len(state.Destinations) != 0 {
		t.Fatalf("routing after disabling final destination = %#v, %v; want configured empty", state, err)
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
