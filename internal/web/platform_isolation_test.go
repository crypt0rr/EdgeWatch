package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// isolationIDs are the values that the isolation matrix puts in a route's
// placeholders.
type isolationIDs struct {
	job, scan, cycle, address, profile, user, destination string
	unit, account, admin, platformDestination             string
}

// unknownIsolationIDs name nothing in the fixture.
var unknownIsolationIDs = isolationIDs{
	job: "00000000-0000-0000-0000-00000000dead", scan: "00000000-0000-0000-0000-00000000dead", cycle: "00000000-0000-0000-0000-00000000dead",
	address: "203.0.113.254", profile: "00000000-0000-0000-0000-00000000dead", user: "00000000-0000-0000-0000-00000000dead",
	destination: "00000000-0000-0000-0000-00000000dead", unit: "00000000-0000-0000-0000-00000000dead", account: "00000000-0000-0000-0000-00000000dead",
	admin: "00000000-0000-0000-0000-00000000dead", platformDestination: "00000000-0000-0000-0000-00000000dead",
}

// unitIDs returns the IDs of a unit's resources in the fixture.
func (f *platformFixture) unitIDs(unit string) isolationIDs {
	if unit == "A" {
		return isolationIDs{job: f.jobA, scan: f.scanA, cycle: unknownIsolationIDs.cycle, address: "192.0.2.10", profile: f.profileA, user: f.users[actorViewerA].ID, destination: f.destinationA,
			unit: store.DefaultTenantID, account: f.users[actorAdminA].ID, admin: f.secondPlatformAdmin, platformDestination: unknownIsolationIDs.platformDestination}
	}
	return isolationIDs{job: f.jobB, scan: f.scanB, cycle: unknownIsolationIDs.cycle, address: platformFixtureAddress, profile: f.profileB, user: f.viewerB, destination: f.destinationB,
		unit: f.unitB, account: f.users[actorAdminB].ID, admin: f.secondPlatformAdmin, platformDestination: unknownIsolationIDs.platformDestination}
}

// path fills the template's placeholders with the IDs. A placeholder the
// matrix does not know fails the test, so a new route cannot skip it.
func (ids isolationIDs) path(t *testing.T, template string) string {
	t.Helper()
	segments := strings.Split(template, "/")
	for index, segment := range segments {
		if !isRoutePlaceholder(segment) {
			continue
		}
		value := ""
		switch segment {
		case "{scan}":
			value = ids.scan
		case "{cycle}":
			value = ids.cycle
		case "{address}":
			value = ids.address
		case "{uid}":
			value = ids.account
		case "{id}":
			switch segments[index-1] {
			case "jobs":
				value = ids.job
			case "scans":
				value = ids.scan
			case "scanner-profiles", "profiles":
				value = ids.profile
			case "users":
				value = ids.user
			case "destinations":
				value = ids.destination
			case "units":
				value = ids.unit
			case "admins":
				value = ids.admin
			case "notifications":
				value = ids.platformDestination
			}
		}
		if value == "" {
			t.Fatalf("the isolation matrix has no value for %s in %s; teach isolationIDs.path the new placeholder", segment, template)
		}
		segments[index] = value
	}
	return strings.Join(segments, "/")
}

// isolationBody is the request body the matrix sends to a route that
// changes something. It carries what each handler checks before it looks
// the resource up, so a foreign ID reaches the lookup.
func isolationBody(route apiRoute) string {
	if !route.Mutates {
		return ""
	}
	switch route.Method + " " + route.Template {
	case "PATCH /users/{id}":
		return `{"display_name":"renamed"}`
	case "PUT /jobs/{id}":
		return `{"name":"renamed","schedule":"0 * * * *","timezone":"UTC","targets":["192.0.2.1"],"tcp":{"ports":"1","mode":"connect"},"revision":1}`
	case "DELETE /jobs/{id}", "POST /jobs/{id}/archive", "POST /jobs/{id}/restore", "POST /jobs/{id}/pause", "POST /jobs/{id}/resume":
		if route.Query != "" {
			return `{"confirm_name":"shared-job"}`
		}
		return `{"revision":1}`
	case "POST /jobs/{id}/incidents/accept", "POST /jobs/{id}/incidents/suppress":
		return `{"key":"incident","expected_change":{}}`
	case "PUT /scanner-profiles/{id}", "PUT /scanner/profiles/{id}":
		return confirmBody(`"revision":1,"name":"renamed","engine":"nmap"`)
	case "POST /scanner-profiles/{id}/validate", "POST /scanner-profiles/{id}/preview", "POST /scanner/profiles/{id}/validate", "POST /scanner/profiles/{id}/preview":
		return `{"name":"renamed","engine":"nmap"}`
	case "PUT /notifications/destinations/{id}":
		return confirmBody(`"name":"renamed","revision":1`)
	case "POST /notifications/destinations/{id}/deliveries/redeliver":
		return `{}`
	}
	switch {
	case strings.HasPrefix(route.Template, "/jobs/"):
		return `{}`
	case strings.HasPrefix(route.Template, "/scanner"), strings.HasPrefix(route.Template, "/notifications/destinations/"), strings.HasPrefix(route.Template, "/platform/"):
		return confirmBody(`"revision":1`)
	}
	return confirmBody("")
}

// isolationNotFoundExceptions are the routes that take an ID but answer a
// foreign ID, like an unknown one, with something other than 404, and why.
var isolationNotFoundExceptions = map[string]string{
	"POST /scans/{id}/cancel":              "cancels only a running scan of the session's unit; any other ID is 409 scan_not_active",
	"POST /scanner-profiles/{id}/validate": "validates the submitted definition and never reads the profile",
	"POST /scanner-profiles/{id}/preview":  "renders the submitted definition and never reads the profile",
	"POST /scanner/profiles/{id}/validate": "validates the submitted definition and never reads the profile",
	"POST /scanner/profiles/{id}/preview":  "renders the submitted definition and never reads the profile",
}

// markersOf returns the strings that name a unit or its data in the
// fixture, for a search of a response that must not contain them.
func (f *platformFixture) markersOf(unit string) []string {
	if unit == "A" {
		return []string{"alpha", store.DefaultTenantID, f.jobA, f.scanA, f.profileA, f.destinationA, f.users[actorAdminA].ID, f.users[actorOperatorA].ID, f.users[actorViewerA].ID}
	}
	return []string{"bravo", platformFixtureAddress, f.unitB, f.jobB, f.sharedJobB, f.scanB, f.profileB, f.destinationB, f.viewerB, f.users[actorAdminB].ID}
}

// dataMarkers name the units' data, which even the platform never sees.
func (f *platformFixture) dataMarkers() []string {
	return []string{"shared-job", "bravo-job", "bravo-profile", "bravo-destination", "bravo-data-audit", "alpha-profile", "alpha-destination", "alpha-data-audit", platformFixtureAddress, "192.0.2.10", f.jobA, f.jobB, f.sharedJobB, f.scanA, f.scanB, f.profileA, f.profileB, f.destinationA, f.destinationB}
}

// isolationRequest sends a request of the matrix as the actor.
func (f *platformFixture) isolationRequest(t *testing.T, actor string, route apiRoute, path string) routeMatrixResponse {
	t.Helper()
	target := consoleAPIBase + path
	if route.Query != "" {
		target += "?" + route.Query
	}
	account := f.sessions[actor]
	body := isolationBody(route)
	if body == "" {
		return serveRouteMatrixRequest(t, f.server.api, route.Method, target, &account, true, "")
	}
	response := callAPI(t, f.server, account, route.Method, strings.TrimPrefix(target, consoleAPIBase), body)
	result := routeMatrixResponse{status: response.Code, body: response.Body.String()}
	var envelope struct {
		Error *struct {
			Code    string         `json:"code"`
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(response.Body.Bytes(), &envelope) == nil && envelope.Error != nil {
		result.code, result.message, result.details = envelope.Error.Code, envelope.Error.Message, envelope.Error.Details
	}
	return result
}

// The isolation matrix sends every session route of the inventory as each
// actor: unit A's administrator, operator and viewer, unit B's
// administrator, and the platform administrator. A route the actor may not
// use is refused with 403 and its permission. A route it may use is sent
// with the IDs of another unit's resources and with unknown IDs: both must
// get byte-identical responses, a 404 unless the route is a documented
// exception, and neither may name the other unit. Unit A's accounts send
// unit B's IDs; unit B's administrator sends unit A's. A route without an ID
// is read, never changed, and must not name the other unit either. The
// platform administrator reaches no unit's route, and its own routes, sent
// with unit B's IDs, name no unit's data. Unit B's data is unchanged
// afterwards.
func TestIsolationMatrix(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	before := f.unitBSnapshot(t)
	resetNotificationTestLimiter := func() {
		f.server.testMu.Lock()
		for key := range f.server.testLast {
			delete(f.server.testLast, key)
		}
		f.server.testMu.Unlock()
	}
	var checked, foreignChecked int
	excepted := map[string]bool{}
	// The first pass sends the requests without another unit's IDs, so the
	// audit that it reads records none of the IDs that the second pass
	// sends.
	for _, idPass := range []bool{false, true} {
		for _, route := range apiRoutes {
			if route.Access != routeSession || route.NoHandler || route.Permission == auth.PermissionAccountSelf {
				continue
			}
			for _, actor := range platformActors {
				name := routeInventoryName(route) + " as " + actor
				allowed := auth.HasPermission(f.sessions[actor].session, route.Permission)
				foreignID := allowed && actor != actorPlatform && strings.Contains(route.Template, "{")
				if foreignID != idPass {
					continue
				}
				if !allowed {
					response := f.isolationRequest(t, actor, route, f.unitIDs("B").path(t, route.Template))
					if response.status != http.StatusForbidden || response.code != "forbidden" || response.details["permission"] != route.Permission {
						t.Errorf("%s = %d %s, want 403 for %s", name, response.status, response.body, route.Permission)
					}
					checked++
					continue
				}
				other, markers := "B", f.markersOf("B")
				switch actor {
				case actorAdminB:
					other, markers = "A", f.markersOf("A")
				case actorPlatform:
					markers = f.dataMarkers()
				}
				if !foreignID {
					if route.Mutates {
						// Changes without another unit's ID, and the
						// platform's own changes, are covered by their route
						// tests.
						continue
					}
					response := f.isolationRequest(t, actor, route, f.unitIDs(other).path(t, route.Template))
					if response.routeGateRejected() || response.status == http.StatusNotFound {
						t.Errorf("%s = %d %s, want the handler to answer", name, response.status, response.body)
					}
					expectNoMarkers(t, response.body, name, markers...)
					checked++
					continue
				}
				if route.Method == http.MethodPost && route.Template == "/notifications/destinations/{id}/test" {
					// Keep this response comparison outside the rate-limit window;
					// throttling has a separate regression test.
					resetNotificationTestLimiter()
				}
				foreign := f.isolationRequest(t, actor, route, f.unitIDs(other).path(t, route.Template))
				if route.Method == http.MethodPost && route.Template == "/notifications/destinations/{id}/test" {
					resetNotificationTestLimiter()
				}
				unknown := f.isolationRequest(t, actor, route, unknownIsolationIDs.path(t, route.Template))
				if foreign.status != unknown.status || foreign.body != unknown.body {
					t.Errorf("%s with unit %s's IDs = %d %s; with unknown IDs = %d %s", name, other, foreign.status, foreign.body, unknown.status, unknown.body)
				}
				key := route.Method + " " + route.Template
				if _, exception := isolationNotFoundExceptions[key]; exception && foreign.status != http.StatusNotFound {
					excepted[key] = true
				} else if foreign.status != http.StatusNotFound {
					t.Errorf("%s with unit %s's IDs = %d %s, want 404", name, other, foreign.status, foreign.body)
				}
				expectNoMarkers(t, foreign.body, name, markers...)
				checked++
				foreignChecked++
			}
		}
	}
	if checked == 0 || foreignChecked == 0 {
		t.Fatalf("the matrix checked %d requests, %d with foreign IDs", checked, foreignChecked)
	}
	for key, reason := range isolationNotFoundExceptions {
		if !excepted[key] {
			t.Errorf("%s answers a foreign ID with 404 now; remove its exception (%s)", key, reason)
		}
	}
	if after := f.unitBSnapshot(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("unit B changed during the matrix:\nbefore %v\nafter  %v", before, after)
	}
}

// unitBSnapshot reads what a foreign request could change in unit B: its
// jobs, users, sessions, invites, destinations, profiles and scans.
func (f *platformFixture) unitBSnapshot(t *testing.T) map[string]string {
	t.Helper()
	snapshot := map[string]string{}
	for name, query := range map[string]string{
		"jobs":         `SELECT group_concat(id||':'||revision||':'||archived||':'||enabled,',') FROM (SELECT * FROM jobs WHERE tenant_id=? ORDER BY id)`,
		"users":        `SELECT group_concat(id||':'||revision||':'||enabled||':'||display_name,',') FROM (SELECT * FROM users WHERE tenant_id=? ORDER BY id)`,
		"sessions":     `SELECT COUNT(*) FROM sessions WHERE user_id IN (SELECT id FROM users WHERE tenant_id=?)`,
		"invites":      `SELECT COUNT(*) FROM user_invites WHERE user_id IN (SELECT id FROM users WHERE tenant_id=?)`,
		"destinations": `SELECT group_concat(id||':'||revision,',') FROM (SELECT * FROM managed_notifications WHERE tenant_id=? ORDER BY id)`,
		"profiles":     `SELECT group_concat(id||':'||revision||':'||archived,',') FROM (SELECT * FROM scanner_profiles WHERE tenant_id=? ORDER BY id)`,
		"scans":        `SELECT group_concat(id||':'||status,',') FROM (SELECT * FROM scans WHERE tenant_id=? ORDER BY id)`,
	} {
		var value sql.NullString
		if err := f.db.DB.QueryRow(query, f.unitB).Scan(&value); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		snapshot[name] = value.String
	}
	return snapshot
}

// Each role reaches exactly what it should, with its own unit's IDs: a
// unit's accounts read their unit's resources, and the platform
// administrator reads unit B through its console.
func TestPositiveMatrix(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	owned := []string{"/jobs/{id}", "/jobs/{id}/scans", "/jobs/{id}/scans/{scan}", "/scans/{id}", "/scans/{id}/summary", "/scans/{id}/hosts", "/scans/{id}/hosts/{address}", "/users/{id}", "/notifications/destinations/{id}", "/scanner-profiles/{id}", "/scanner/profiles/{id}", "/jobs/{id}/baseline", "/audit"}
	platformOwned := []string{"/platform/units", "/platform/units/{id}", "/platform/units/{id}/capacity", "/platform/units/{id}/accounts", "/platform/admins", "/platform/audit", "/platform/notifications", "/platform/status"}
	reached := map[string][]string{}
	for _, route := range apiRoutes {
		if route.Access != routeSession || route.Mutates || route.NoHandler {
			continue
		}
		for _, actor := range platformActors {
			account := f.sessions[actor]
			if !auth.HasPermission(account.session, route.Permission) {
				continue
			}
			unit := "A"
			if actor == actorAdminB || actor == actorPlatform {
				unit = "B"
			}
			response := f.isolationRequest(t, actor, route, f.unitIDs(unit).path(t, route.Template))
			if response.routeGateRejected() {
				t.Errorf("%s as %s = %d %s, want it admitted", routeInventoryName(route), actor, response.status, response.body)
			}
			if slices.Contains(owned, route.Template) || slices.Contains(platformOwned, route.Template) {
				if response.status != http.StatusOK {
					t.Errorf("%s as %s with its own IDs = %d %s, want 200", routeInventoryName(route), actor, response.status, response.body)
				}
				reached[actor] = append(reached[actor], route.Template)
			}
		}
	}
	want := map[string]int{actorAdminA: 13, actorOperatorA: 11, actorViewerA: 2, actorAdminB: 13, actorPlatform: 8}
	for actor, count := range want {
		if len(reached[actor]) != count {
			sort.Strings(reached[actor])
			t.Errorf("%s reached %d of the checked routes, want %d: %v", actor, len(reached[actor]), count, reached[actor])
		}
	}
	for _, actor := range []string{actorAdminA, actorOperatorA, actorViewerA, actorAdminB} {
		for _, template := range reached[actor] {
			if strings.HasPrefix(template, "/platform/") {
				t.Errorf("%s reached %s", actor, template)
			}
		}
	}
	for _, template := range reached[actorPlatform] {
		if !strings.HasPrefix(template, "/platform/") {
			t.Errorf("the platform administrator reached unit route %s", template)
		}
	}
}

// The platform console's handler checks the role again: a session that is
// not a platform administrator's is refused like an unknown route, even if
// it reached the handler, and an unknown platform path is not found.
func TestPlatformRouteRefusesUnitSessions(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	for _, actor := range []string{actorAdminA, actorOperatorA, actorViewerA, actorAdminB} {
		recorder := httptest.NewRecorder()
		f.server.platformRoute(recorder, httptest.NewRequest(http.MethodGet, consoleAPIBase+"/platform/units", nil), f.sessions[actor].session, "units")
		if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), `"route"`) {
			t.Errorf("platformRoute as %s = %d %s", actor, recorder.Code, recorder.Body.String())
		}
	}
	recorder := httptest.NewRecorder()
	f.server.platformRoute(recorder, httptest.NewRequest(http.MethodGet, consoleAPIBase+"/platform/unknown", nil), f.sessions[actorPlatform].session, "unknown")
	if recorder.Code != http.StatusNotFound {
		t.Errorf("platformRoute of an unknown path = %d %s", recorder.Code, recorder.Body.String())
	}
}

// sessionKeys decodes a JSON object and returns its keys, sorted.
func sessionKeys(t *testing.T, body []byte) (map[string]any, []string) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return payload, keys
}

// The session names its console and its unit, and whether more than one
// unit exists; an administrator's permissions include the unit audit.
func TestSessionDescribesTheBusinessUnit(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	for actor, want := range map[string]struct {
		scope string
		unit  any
		// highCost is high_cost_override: only a session that may approve
		// high-cost scans carries it.
		highCost any
	}{
		actorAdminA:   {"unit", map[string]any{"id": store.DefaultTenantID, "name": "Default", "slug": "default"}, true},
		actorViewerA:  {"unit", map[string]any{"id": store.DefaultTenantID, "name": "Default", "slug": "default"}, nil},
		actorAdminB:   {"unit", map[string]any{"id": f.unitB, "name": "Bravo Unit", "slug": "bravo"}, true},
		actorPlatform: {"platform", nil, nil},
	} {
		response := f.call(t, actor, http.MethodGet, "/auth/session", "")
		expectResponse(t, response, http.StatusOK, actor+" session", nil)
		payload, _ := sessionKeys(t, response.Body.Bytes())
		if payload["scope"] != want.scope || !reflect.DeepEqual(payload["unit"], want.unit) || payload["multi_unit"] != true || payload["high_cost_override"] != want.highCost {
			t.Errorf("%s session = %s", actor, response.Body.String())
		}
	}
	var session struct {
		Permissions []string `json:"permissions"`
	}
	expectResponse(t, f.call(t, actorAdminA, http.MethodGet, "/auth/session", ""), http.StatusOK, "administrator session", &session)
	if !slices.Contains(session.Permissions, auth.PermissionAuditRead) {
		t.Fatalf("administrator permissions = %v", session.Permissions)
	}
	// With a single unit left, multi_unit is false.
	expectResponse(t, f.call(t, actorPlatform, http.MethodPost, "/platform/units/"+f.unitB+"/disable", confirmBody("")), http.StatusOK, "disable unit B", nil)
	expectResponse(t, f.call(t, actorPlatform, http.MethodDelete, "/platform/units/"+f.unitB, confirmBody(`"confirm_name":"Bravo Unit"`)), http.StatusOK, "delete unit B", nil)
	if _, err := f.db.DB.Exec(`UPDATE tenants SET state='deleted' WHERE id=?`, f.unitB); err != nil {
		t.Fatal(err)
	}
	payload, _ := sessionKeys(t, f.call(t, actorViewerA, http.MethodGet, "/auth/session", "").Body.Bytes())
	if payload["multi_unit"] != false {
		t.Fatalf("single-unit session = %v", payload)
	}
}

// The jobs in config.yaml predate business units and belong to the default
// unit, so only its administrators and operators find them in the status,
// as the CLI status lists them for the default unit only. Another unit's
// status leaves the key out, and a viewer's never has it.
func TestLegacyYAMLJobsAreOnlyInTheDefaultUnitStatus(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	f.server.App.Config.Jobs = []config.Job{{Name: "alpha-legacy-perimeter"}, {Name: "alpha-legacy-office"}}
	// The fixture's unit B has an administrator and a viewer; add an
	// operator, and sign in the two accounts the fixture leaves signed out.
	const operatorB, viewerB = "unit B operator", "unit B viewer"
	operator, err := storetest.CreateUser(context.Background(), f.db, f.scopeB, store.User{Username: "bravo-operator", DisplayName: "bravo-operator", Role: store.RoleOperator, PasswordHash: cheapPasswordHash(platformFixturePassword), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	f.users[operatorB] = operator
	f.sessions[operatorB] = f.signIn(t, operatorB)
	f.sessions[viewerB] = f.signIn(t, viewerB)
	for actor, want := range map[string][]any{
		actorAdminA:    {"alpha-legacy-perimeter", "alpha-legacy-office"},
		actorOperatorA: {"alpha-legacy-perimeter", "alpha-legacy-office"},
		actorViewerA:   nil,
		actorAdminB:    nil,
		operatorB:      nil,
		viewerB:        nil,
	} {
		response := f.call(t, actor, http.MethodGet, "/status", "")
		var status map[string]any
		expectResponse(t, response, http.StatusOK, actor+" status", &status)
		legacy, present := status["legacy_yaml_jobs"]
		if want == nil {
			if present || strings.Contains(response.Body.String(), "alpha-legacy") {
				t.Errorf("%s status names the default unit's YAML jobs: %s", actor, response.Body.String())
			}
			continue
		}
		if !reflect.DeepEqual(legacy, want) {
			t.Errorf("%s legacy_yaml_jobs = %v, want %v", actor, legacy, want)
		}
	}
}

// In a single-unit installation, the session describes the account as
// before business units plus its console, its unit, the default one, and
// multi_unit false; an administrator's permissions include the unit audit,
// in the session, the status and the sign-in responses alike, and the
// sign-in response keeps its keys.
func TestSingleUnitSessionResponses(t *testing.T) {
	t.Parallel()
	server, accounts := newRouteMatrixSessions(t)
	admin := accounts[0]
	full := auth.PermissionsForRole(store.RoleAdministrator)
	if !slices.Contains(full, auth.PermissionAuditRead) {
		t.Fatalf("administrator permissions = %v, want the unit audit", full)
	}
	response := callAPI(t, server, admin, http.MethodGet, "/auth/session", "")
	expectResponse(t, response, http.StatusOK, "session", nil)
	payload, keys := sessionKeys(t, response.Body.Bytes())
	if want := []string{"csrf_token", "display_name", "high_cost_override", "multi_unit", "password_requirements", "permissions", "role", "scope", "timezone", "totp_enabled", "unit", "user_id", "username"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("session keys = %v, want %v", keys, want)
	}
	if payload["scope"] != "unit" || payload["multi_unit"] != false || !reflect.DeepEqual(payload["unit"], map[string]any{"id": store.DefaultTenantID, "name": "Default", "slug": "default"}) {
		t.Fatalf("session = %s", response.Body.String())
	}
	if !reflect.DeepEqual(payload["permissions"], toAnySlice(full)) {
		t.Fatalf("session permissions = %v, want %v", payload["permissions"], full)
	}
	status := callAPI(t, server, admin, http.MethodGet, "/status", "")
	statusPayload, _ := sessionKeys(t, status.Body.Bytes())
	if !reflect.DeepEqual(statusPayload["permissions"], toAnySlice(full)) {
		t.Fatalf("status permissions = %v", statusPayload["permissions"])
	}
	login := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/auth/login", strings.NewReader(`{"username":"admin","password":"administrator password"}`))
	login.RemoteAddr = "127.0.0.1:9000"
	login.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.api(recorder, login)
	loginPayload, loginKeys := sessionKeys(t, recorder.Body.Bytes())
	if want := []string{"csrf_token", "display_name", "high_cost_override", "permissions", "role", "totp_required", "username"}; !reflect.DeepEqual(loginKeys, want) || !reflect.DeepEqual(loginPayload["permissions"], toAnySlice(full)) {
		t.Fatalf("login = %s", recorder.Body.String())
	}
}

// A platform administrator's session and sign-in list the platform
// permissions and name the platform console. The unit status is refused to
// it, and its own account's routes work.
func TestPlatformAdministratorSessionListsThePlatformPermissions(t *testing.T) {
	t.Parallel()
	server, accounts := newRouteMatrixSessions(t)
	platform := accounts[3]
	if platform.role != store.RolePlatformAdmin {
		t.Fatalf("fixture account 3 = %s", platform.role)
	}
	permissions := toAnySlice(auth.PermissionsForRole(store.RolePlatformAdmin))
	response := callAPI(t, server, platform, http.MethodGet, "/auth/session", "")
	expectResponse(t, response, http.StatusOK, "platform session", nil)
	payload, _ := sessionKeys(t, response.Body.Bytes())
	if payload["role"] != store.RolePlatformAdmin || !reflect.DeepEqual(payload["permissions"], permissions) || payload["scope"] != "platform" || payload["unit"] != nil || payload["multi_unit"] != false {
		t.Fatalf("platform session = %s", response.Body.String())
	}
	login := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/auth/login", strings.NewReader(`{"username":"platform","password":"platform administrator password"}`))
	login.RemoteAddr = "127.0.0.1:9000"
	login.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.api(recorder, login)
	if loginPayload, _ := sessionKeys(t, recorder.Body.Bytes()); recorder.Code != http.StatusOK || !reflect.DeepEqual(loginPayload["permissions"], permissions) {
		t.Fatalf("platform sign-in = %d %s", recorder.Code, recorder.Body.String())
	}
	expectResponse(t, callAPI(t, server, platform, http.MethodGet, "/status", ""), http.StatusForbidden, "platform status", nil)
	expectResponse(t, callAPI(t, server, platform, http.MethodPut, "/auth/display-name", `{"display_name":"Platform Root"}`), http.StatusOK, "platform display name", nil)
}

func toAnySlice(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
