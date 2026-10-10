package web

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// alertRoutingResponse is the answer of a routing change.
type alertRoutingResponse struct {
	Configured   bool     `json:"configured"`
	Destinations []string `json:"destinations"`
}

func decodeAlertRouting(t *testing.T, body []byte) alertRoutingResponse {
	t.Helper()
	var routing alertRoutingResponse
	if err := json.Unmarshal(body, &routing); err != nil {
		t.Fatalf("routing %s: %v", body, err)
	}
	return routing
}

// createPlatformDestination creates a platform destination through the API
// and returns its ID.
func createPlatformDestination(t *testing.T, f *platformFixture, name string) string {
	t.Helper()
	response := f.call(t, actorPlatform, http.MethodPost, "/platform/notifications", confirmBody(`"name":"`+name+`","url":"generic://localhost/`+name+`?disabletls=yes"`))
	if response.Code != http.StatusCreated {
		t.Fatalf("create platform destination = %d: %s", response.Code, response.Body.String())
	}
	var view struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil || view.ID == "" {
		t.Fatalf("platform destination %s: %v", response.Body.String(), err)
	}
	return view.ID
}

// A unit administrator turns its unit's security alerts on and off per
// destination. The routing selects only the unit's own destinations:
// another unit's, a platform destination, and an unknown one are refused
// alike. The destination list reports the routing.
func TestUnitSecurityRouting(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	platformDestination := createPlatformDestination(t, f, "platform-pager")
	response := f.call(t, actorAdminB, http.MethodPatch, "/notifications/security-routing", confirmBody(`"destination_id":"`+f.destinationB+`","enabled":true`))
	if response.Code != http.StatusOK {
		t.Fatalf("enable security alerts = %d: %s", response.Code, response.Body.String())
	}
	if routing := decodeAlertRouting(t, response.Body.Bytes()); !routing.Configured || !reflect.DeepEqual(routing.Destinations, []string{f.destinationB}) {
		t.Errorf("routing = %+v", routing)
	}
	list := f.call(t, actorAdminB, http.MethodGet, "/notifications/destinations", "")
	var listed struct {
		Security alertRoutingResponse `json:"security_routing"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil || !reflect.DeepEqual(listed.Security.Destinations, []string{f.destinationB}) {
		t.Errorf("listed security routing = %+v, %v: %s", listed.Security, err, list.Body.String())
	}
	if routing, err := f.a.SecurityAlertRouting(context.Background()); err != nil || len(routing) != 0 {
		t.Errorf("unit A's security routing = %v, %v", routing, err)
	}
	for _, foreign := range []string{f.destinationA, platformDestination, "00000000-0000-0000-0000-00000000dead"} {
		for _, request := range []struct{ method, body string }{
			{http.MethodPatch, confirmBody(`"destination_id":"` + foreign + `","enabled":true`)},
			{http.MethodPut, confirmBody(`"destinations":["` + foreign + `"]`)},
		} {
			refused := f.call(t, actorAdminB, request.method, "/notifications/security-routing", request.body)
			if refused.Code != http.StatusBadRequest || !strings.Contains(refused.Body.String(), "was not found") {
				t.Errorf("%s with %s = %d: %s", request.method, foreign, refused.Code, refused.Body.String())
			}
		}
	}
	for _, body := range []string{`{"destination_id":"` + f.destinationB + `","enabled":false}`, confirmBody(`"enabled":false`)} {
		if refused := f.call(t, actorAdminB, http.MethodPatch, "/notifications/security-routing", body); refused.Code != http.StatusBadRequest {
			t.Errorf("PATCH %s = %d", body, refused.Code)
		}
	}
	if refused := f.call(t, actorAdminB, http.MethodPut, "/notifications/security-routing", confirmBody("")); refused.Code != http.StatusBadRequest {
		t.Errorf("PUT without destinations = %d", refused.Code)
	}
	response = f.call(t, actorAdminB, http.MethodPut, "/notifications/security-routing", confirmBody(`"destinations":[]`))
	if routing := decodeAlertRouting(t, response.Body.Bytes()); response.Code != http.StatusOK || len(routing.Destinations) != 0 || routing.Destinations == nil {
		t.Errorf("turn security alerts off = %d %+v", response.Code, routing)
	}
	for _, actor := range []string{actorOperatorA, actorViewerA, actorPlatform} {
		if denied := f.call(t, actor, http.MethodPatch, "/notifications/security-routing", confirmBody(`"destination_id":"`+f.destinationA+`","enabled":true`)); denied.Code != http.StatusForbidden {
			t.Errorf("%s changed unit A's security routing: %d", actor, denied.Code)
		}
	}
}

// Platform administrators choose the platform destinations of the
// platform's security alerts and of the deployment alerts, and the list of
// platform destinations reports both. A unit's destination is refused.
func TestPlatformAlertRouting(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	platformDestination := createPlatformDestination(t, f, "platform-pager")
	for _, path := range []string{"/platform/notifications/security-routing", "/platform/notifications/health-routing"} {
		response := f.call(t, actorPlatform, http.MethodPatch, path, confirmBody(`"destination_id":"`+platformDestination+`","enabled":true`))
		if routing := decodeAlertRouting(t, response.Body.Bytes()); response.Code != http.StatusOK || !reflect.DeepEqual(routing.Destinations, []string{platformDestination}) {
			t.Errorf("PATCH %s = %d %+v", path, response.Code, routing)
		}
		refused := f.call(t, actorPlatform, http.MethodPut, path, confirmBody(`"destinations":["`+f.destinationB+`"]`))
		if refused.Code != http.StatusBadRequest {
			t.Errorf("PUT %s with a unit destination = %d: %s", path, refused.Code, refused.Body.String())
		}
		if refused := f.call(t, actorPlatform, http.MethodPut, path, confirmBody("")); refused.Code != http.StatusBadRequest {
			t.Errorf("PUT %s without destinations = %d", path, refused.Code)
		}
		if refused := f.call(t, actorPlatform, http.MethodPatch, path, confirmBody(`"enabled":true`)); refused.Code != http.StatusBadRequest {
			t.Errorf("PATCH %s without a destination = %d", path, refused.Code)
		}
		if denied := f.call(t, actorAdminA, http.MethodPatch, path, confirmBody(`"destination_id":"`+platformDestination+`","enabled":false`)); denied.Code != http.StatusForbidden {
			t.Errorf("a unit administrator changed %s: %d", path, denied.Code)
		}
	}
	response := f.call(t, actorPlatform, http.MethodPut, "/platform/notifications/health-routing", confirmBody(`"destinations":[]`))
	if routing := decodeAlertRouting(t, response.Body.Bytes()); response.Code != http.StatusOK || len(routing.Destinations) != 0 {
		t.Errorf("PUT health routing [] = %d %+v", response.Code, routing)
	}
	list := f.call(t, actorPlatform, http.MethodGet, "/platform/notifications", "")
	var listed struct {
		Security alertRoutingResponse `json:"security_routing"`
		Health   alertRoutingResponse `json:"health_routing"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil || !reflect.DeepEqual(listed.Security.Destinations, []string{platformDestination}) || listed.Health.Destinations == nil || len(listed.Health.Destinations) != 0 {
		t.Errorf("listed platform routing = %+v, %v", listed, err)
	}
}

// A platform administrator's password reset for unit B's administrator
// through the console queues one security alert to unit B's destination
// only, without the link's token or a URL.
func TestPlatformResetAlertsTheUnitThroughTheConsole(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	platformDestination := createPlatformDestination(t, f, "platform-pager")
	for _, change := range []struct{ actor, path, destination string }{
		{actorAdminA, "/notifications/security-routing", f.destinationA},
		{actorAdminB, "/notifications/security-routing", f.destinationB},
		{actorPlatform, "/platform/notifications/security-routing", platformDestination},
	} {
		if response := f.call(t, change.actor, http.MethodPatch, change.path, confirmBody(`"destination_id":"`+change.destination+`","enabled":true`)); response.Code != http.StatusOK {
			t.Fatalf("%s routing = %d: %s", change.actor, response.Code, response.Body.String())
		}
	}
	reset := f.call(t, actorPlatform, http.MethodPost, "/platform/units/"+f.unitB+"/accounts/"+f.users[actorAdminB].ID+"/password-reset", confirmBody(""))
	if reset.Code != http.StatusOK {
		t.Fatalf("reset = %d: %s", reset.Code, reset.Body.String())
	}
	var issued struct {
		Token string `json:"activation_token"`
	}
	if err := json.Unmarshal(reset.Body.Bytes(), &issued); err != nil || issued.Token == "" {
		t.Fatalf("reset answer %s: %v", reset.Body.String(), err)
	}
	rows, err := f.db.DB.Query(`SELECT COALESCE(tenant_id,''),destination,CAST(payload_json AS TEXT) FROM outbox WHERE json_extract(CAST(payload_json AS TEXT),'$.type')=?`, model.EventSecurityAlert)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var alerts []string
	for rows.Next() {
		var tenant, destination, payload string
		if err := rows.Scan(&tenant, &destination, &payload); err != nil {
			t.Fatal(err)
		}
		if tenant != f.unitB || !strings.HasPrefix(destination, "managed:"+f.destinationB+":") {
			t.Errorf("security alert of %q went to %s", tenant, destination)
		}
		for _, secret := range []string{issued.Token, "://", "127.0.0.1"} {
			if strings.Contains(payload, secret) {
				t.Errorf("alert payload %s contains %q", payload, secret)
			}
		}
		alerts = append(alerts, payload)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || !strings.Contains(alerts[0], `"account":"bravo-admin"`) {
		t.Fatalf("security alerts = %v, want one about bravo-admin", alerts)
	}
}
