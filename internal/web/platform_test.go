package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// expectResponse fails the test unless the response has the status, and
// decodes its JSON body into target when target is not nil.
func expectResponse(t *testing.T, response *httptest.ResponseRecorder, status int, step string, target any) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("%s = %d, want %d: %s", step, response.Code, status, response.Body.String())
	}
	if target != nil {
		if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
			t.Fatalf("%s: %v: %s", step, err, response.Body.String())
		}
	}
}

// expectError fails the test unless the response is an API error with the
// status and code.
func expectError(t *testing.T, response *httptest.ResponseRecorder, status int, code, step string) map[string]any {
	t.Helper()
	var envelope struct {
		Error struct {
			Code    string         `json:"code"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	expectResponse(t, response, status, step, &envelope)
	if envelope.Error.Code != code {
		t.Fatalf("%s error code = %q, want %q: %s", step, envelope.Error.Code, code, response.Body.String())
	}
	return envelope.Error.Details
}

// expectNoMarkers fails the test when the body contains one of the markers.
func expectNoMarkers(t *testing.T, body, step string, markers ...string) {
	t.Helper()
	lower := strings.ToLower(body)
	for _, marker := range markers {
		if marker != "" && strings.Contains(lower, strings.ToLower(marker)) {
			t.Errorf("%s response contains %q: %s", step, marker, body)
		}
	}
}

// auditRecords returns the audit records of a tenant, or of the platform
// for "", as action, actor kind and source address.
func auditRecords(t *testing.T, db *store.Store, tenantID string) []string {
	t.Helper()
	query := `SELECT action,actor_kind,source_ip FROM security_audit WHERE tenant_id IS NULL ORDER BY id`
	args := []any{}
	if tenantID != "" {
		query = `SELECT action,actor_kind,source_ip FROM security_audit WHERE tenant_id=? ORDER BY id`
		args = append(args, tenantID)
	}
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var records []string
	for rows.Next() {
		var action, kind, source string
		if err := rows.Scan(&action, &kind, &source); err != nil {
			t.Fatal(err)
		}
		records = append(records, action+"/"+kind+"/"+source)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return records
}

func containsRecord(records []string, prefix string) bool {
	for _, record := range records {
		if strings.HasPrefix(record, prefix) {
			return true
		}
	}
	return false
}

type unitPayload struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Slug           string `json:"slug"`
	Status         string `json:"status"`
	IsDefault      bool   `json:"is_default"`
	Revision       int64  `json:"revision"`
	Accounts       int    `json:"accounts"`
	Administrators int    `json:"administrators"`
	Jobs           int    `json:"jobs"`
	StoredScans    int64  `json:"stored_scans"`
	Purge          *struct {
		Phase string `json:"phase"`
	} `json:"purge"`
}

// The platform administrator lists the units with their counts only,
// creates, renames, disables, enables and deletes a unit, and each change
// is recorded in the platform audit. A unit's data never appears.
func TestPlatformUnitLifecycle(t *testing.T) {
	f := newPlatformFixture(t)
	var list struct {
		Units  []unitPayload      `json:"units"`
		Limits platformLimitsView `json:"limits"`
	}
	response := f.call(t, actorPlatform, http.MethodGet, "/platform/units", "")
	expectResponse(t, response, http.StatusOK, "list units", &list)
	if len(list.Units) != 2 || !list.Units[0].IsDefault || list.Units[1].ID != f.unitB || list.Limits.MaxConcurrentScans != 2 {
		t.Fatalf("units = %+v, limits %+v", list.Units, list.Limits)
	}
	if a, b := list.Units[0], list.Units[1]; a.Accounts != 3 || a.Administrators != 1 || a.Jobs != 1 || b.Accounts != 2 || b.Administrators != 1 || b.Jobs != 2 || b.Status != store.TenantStateActive {
		t.Fatalf("unit counts = %+v", list.Units)
	}
	expectNoMarkers(t, response.Body.String(), "unit list", "shared-job", "bravo-job", "bravo-destination", "bravo-profile", platformFixtureAddress, "bravo-admin", f.jobB)

	var created unitPayload
	expectResponse(t, f.call(t, actorPlatform, http.MethodPost, "/platform/units", `{"name":"Charlie Unit"}`), http.StatusCreated, "create unit", &created)
	if created.Slug != "charlie-unit" || created.Status != store.TenantStateActive || created.IsDefault || created.Revision != 1 {
		t.Fatalf("created unit = %+v", created)
	}
	if details := expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/units", `{"name":"charlie unit","slug":"other-slug"}`), http.StatusConflict, "conflict", "duplicate name"); details["name"] == nil {
		t.Fatalf("duplicate name details = %v", details)
	}
	if details := expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/units", `{"name":"Delta","slug":"bravo"}`), http.StatusConflict, "conflict", "duplicate slug"); details["slug"] == nil {
		t.Fatalf("duplicate slug details = %v", details)
	}
	for _, body := range []string{`{"name":"Delta","slug":"platform"}`, `{"name":"Delta","slug":"Not A Slug"}`, `{"name":"!!"}`} {
		if details := expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/units", body), http.StatusBadRequest, "validation_failed", "invalid slug "+body); details["slug"] == nil {
			t.Fatalf("invalid slug %s details = %v", body, details)
		}
	}
	expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/units", `{"name":""}`), http.StatusBadRequest, "validation_failed", "empty name")

	unitPath := "/platform/units/" + created.ID
	var detail unitPayload
	expectResponse(t, f.call(t, actorPlatform, http.MethodGet, unitPath, ""), http.StatusOK, "get unit", &detail)
	if detail.ID != created.ID || detail.Name != "Charlie Unit" {
		t.Fatalf("unit detail = %+v", detail)
	}
	unknown := f.call(t, actorPlatform, http.MethodGet, "/platform/units/00000000-0000-0000-0000-00000000dead", "")
	expectError(t, unknown, http.StatusNotFound, "not_found", "unknown unit")

	expectError(t, f.call(t, actorPlatform, http.MethodPatch, unitPath, `{"name":"Charlie Renamed"}`), http.StatusBadRequest, "revision_required", "rename without revision")
	var renamed unitPayload
	expectResponse(t, f.call(t, actorPlatform, http.MethodPatch, unitPath, `{"revision":1,"name":"Charlie Renamed","slug":"charlie"}`), http.StatusOK, "rename", &renamed)
	if renamed.Name != "Charlie Renamed" || renamed.Slug != "charlie" || renamed.Revision != 2 {
		t.Fatalf("renamed unit = %+v", renamed)
	}
	if details := expectError(t, f.call(t, actorPlatform, http.MethodPatch, unitPath, `{"revision":1,"name":"Stale"}`), http.StatusConflict, "conflict", "stale rename"); details["current"] == nil {
		t.Fatalf("stale rename details = %v", details)
	}
	expectError(t, f.call(t, actorPlatform, http.MethodPatch, "/platform/units/00000000-0000-0000-0000-00000000dead", `{"revision":1}`), http.StatusNotFound, "not_found", "rename unknown")

	expectError(t, f.call(t, actorPlatform, http.MethodDelete, unitPath, confirmBody(`"confirm_name":"Charlie Renamed"`)), http.StatusConflict, "unit_state", "delete an active unit")
	expectError(t, f.call(t, actorPlatform, http.MethodPost, unitPath+"/disable", `{"password":"wrong password"}`), http.StatusUnauthorized, "invalid_password", "disable with a wrong password")
	var disabled unitPayload
	expectResponse(t, f.call(t, actorPlatform, http.MethodPost, unitPath+"/disable", confirmBody("")), http.StatusOK, "disable", &disabled)
	if disabled.Status != store.TenantStateDisabled {
		t.Fatalf("disabled unit = %+v", disabled)
	}
	expectError(t, f.call(t, actorPlatform, http.MethodPost, unitPath+"/disable", confirmBody("")), http.StatusConflict, "unit_state", "disable twice")
	expectError(t, f.call(t, actorPlatform, http.MethodDelete, unitPath, confirmBody("")), http.StatusBadRequest, "validation_failed", "delete without the typed name")
	if details := expectError(t, f.call(t, actorPlatform, http.MethodDelete, unitPath, confirmBody(`"confirm_name":"charlie renamed"`)), http.StatusBadRequest, "validation_failed", "delete with a wrong name"); details["confirm_name"] == nil {
		t.Fatalf("wrong name details = %v", details)
	}
	expectError(t, f.call(t, actorPlatform, http.MethodDelete, unitPath, `{"confirm_name":"Charlie Renamed","password":"wrong password"}`), http.StatusUnauthorized, "invalid_password", "delete with a wrong password")
	expectError(t, f.call(t, actorPlatform, http.MethodDelete, "/platform/units/"+store.DefaultTenantID, confirmBody(`"confirm_name":"Default"`)), http.StatusConflict, "default_unit", "delete the default unit")
	var deleting unitPayload
	expectResponse(t, f.call(t, actorPlatform, http.MethodDelete, unitPath, confirmBody(`"confirm_name":"Charlie Renamed"`)), http.StatusOK, "delete", &deleting)
	if deleting.Status != store.TenantStateDeleting || deleting.Purge == nil {
		t.Fatalf("deleting unit = %+v", deleting)
	}
	expectResponse(t, f.call(t, actorPlatform, http.MethodGet, unitPath, ""), http.StatusOK, "get a deleting unit", nil)
	expectError(t, f.call(t, actorPlatform, http.MethodPost, unitPath+"/enable", confirmBody("")), http.StatusConflict, "unit_state", "enable a deleting unit")

	// Disabling unit B ends its administrator's session and closes it out
	// of every route; enabling it lets the administrator sign in again.
	expectResponse(t, f.call(t, actorAdminB, http.MethodGet, "/jobs", ""), http.StatusOK, "unit B jobs before the disable", nil)
	expectResponse(t, f.call(t, actorPlatform, http.MethodPost, "/platform/units/"+f.unitB+"/disable", confirmBody(`"revision":1`)), http.StatusOK, "disable unit B", nil)
	expectError(t, f.call(t, actorAdminB, http.MethodGet, "/jobs", ""), http.StatusUnauthorized, "unauthorized", "unit B jobs after the disable")
	var enabled unitPayload
	expectResponse(t, f.call(t, actorPlatform, http.MethodPost, "/platform/units/"+f.unitB+"/enable", confirmBody("")), http.StatusOK, "enable unit B", &enabled)
	if enabled.Status != store.TenantStateActive {
		t.Fatalf("enabled unit = %+v", enabled)
	}
	f.sessions[actorAdminB] = f.signIn(t, actorAdminB)
	expectResponse(t, f.call(t, actorAdminB, http.MethodGet, "/jobs", ""), http.StatusOK, "unit B jobs after the enable", nil)

	records := auditRecords(t, f.db, "")
	for _, action := range []string{"tenant.created", "tenant.renamed", "tenant.disabled", "tenant.enabled", "tenant.deletion_requested"} {
		if !containsRecord(records, action+"/"+store.AuditActorPlatform+"/") {
			t.Errorf("platform audit has no %s by the platform: %v", action, records)
		}
	}
}

// The platform administrator manages a unit's administrators: it lists the
// unit's accounts without their credentials, invites an administrator, and
// issues a password reset or revokes the sessions of one, each recorded in
// the unit's audit as a platform action. It invites and resets only
// administrators, and an account of another unit is not found, with the
// same response as an unknown ID.
func TestPlatformUnitAccounts(t *testing.T) {
	f := newPlatformFixture(t)
	accountsPath := "/platform/units/" + f.unitB + "/accounts"
	var list struct {
		Accounts []store.UserSummary `json:"accounts"`
	}
	response := f.call(t, actorPlatform, http.MethodGet, accountsPath, "")
	expectResponse(t, response, http.StatusOK, "list accounts", &list)
	if len(list.Accounts) != 2 || list.Accounts[0].Username != "bravo-admin" || !list.Accounts[0].TOTPEnabled || list.Accounts[1].Role != store.RoleViewer {
		t.Fatalf("unit B accounts = %+v", list.Accounts)
	}
	expectNoMarkers(t, response.Body.String(), "account list", "password", "totp_secret", "alpha-", "bravo-job", platformFixtureAddress)
	expectError(t, f.call(t, actorPlatform, http.MethodGet, "/platform/units/00000000-0000-0000-0000-00000000dead/accounts", ""), http.StatusNotFound, "not_found", "accounts of an unknown unit")

	if details := expectError(t, f.call(t, actorPlatform, http.MethodPost, accountsPath, confirmBody(`"username":"bravo-operator","role":"operator"`)), http.StatusBadRequest, "validation_failed", "invite an operator"); details["role"] == nil {
		t.Fatalf("operator invitation details = %v", details)
	}
	expectError(t, f.call(t, actorPlatform, http.MethodPost, accountsPath, `{"username":"bravo-second","password":"wrong password"}`), http.StatusUnauthorized, "invalid_password", "invite with a wrong password")
	expectError(t, f.call(t, actorPlatform, http.MethodPost, accountsPath, confirmBody(`"username":"alpha-admin"`)), http.StatusConflict, "conflict", "invite a taken username")
	expectError(t, f.call(t, actorPlatform, http.MethodPost, accountsPath, confirmBody(`"username":""`)), http.StatusBadRequest, "validation_failed", "invite without a username")
	var invitation struct {
		User            store.UserSummary `json:"user"`
		ActivationToken string            `json:"activation_token"`
		ActivationPath  string            `json:"activation_path"`
	}
	expectResponse(t, f.call(t, actorPlatform, http.MethodPost, accountsPath, confirmBody(`"username":"bravo-second","display_name":"Bravo Second"`)), http.StatusCreated, "invite an administrator", &invitation)
	if invitation.User.Role != store.RoleAdministrator || !invitation.User.Pending || invitation.ActivationToken == "" || !strings.Contains(invitation.ActivationPath, invitation.ActivationToken) {
		t.Fatalf("invitation = %+v", invitation)
	}
	if !containsRecord(auditRecords(t, f.db, f.unitB), "user.created/"+store.AuditActorPlatform+"/") {
		t.Fatalf("unit B audit has no platform invitation: %v", auditRecords(t, f.db, f.unitB))
	}

	adminB := f.users[actorAdminB].ID
	type resetPayload struct {
		ActivationToken string `json:"activation_token"`
		TOTPEnrolled    *bool  `json:"totp_enrolled"`
	}
	var reset resetPayload
	expectResponse(t, f.call(t, actorPlatform, http.MethodPost, accountsPath+"/"+adminB+"/password-reset", confirmBody("")), http.StatusOK, "reset unit B's administrator", &reset)
	if reset.ActivationToken == "" || reset.TOTPEnrolled == nil || !*reset.TOTPEnrolled {
		t.Fatalf("reset = %+v", reset)
	}
	reset = resetPayload{}
	expectResponse(t, f.call(t, actorPlatform, http.MethodPost, accountsPath+"/"+invitation.User.ID+"/password-reset", confirmBody("")), http.StatusOK, "reset a pending administrator", &reset)
	if reset.TOTPEnrolled == nil || *reset.TOTPEnrolled {
		t.Fatalf("pending administrator reset = %+v", reset)
	}
	expectError(t, f.call(t, actorPlatform, http.MethodPost, accountsPath+"/"+f.viewerB+"/password-reset", confirmBody("")), http.StatusForbidden, "not_permitted", "reset a viewer")
	if !containsRecord(auditRecords(t, f.db, f.unitB), "user.password_reset_issued/"+store.AuditActorPlatform+"/") {
		t.Fatalf("unit B audit has no platform reset: %v", auditRecords(t, f.db, f.unitB))
	}

	// Another unit's account and the platform administrator's own account
	// are not accounts of unit B: each is refused exactly as an unknown ID.
	for _, suffix := range []string{"/password-reset", "/sessions"} {
		method := http.MethodPost
		if suffix == "/sessions" {
			method = http.MethodDelete
		}
		unknown := f.call(t, actorPlatform, method, accountsPath+"/00000000-0000-0000-0000-00000000dead"+suffix, confirmBody(""))
		expectError(t, unknown, http.StatusNotFound, "not_found", "unknown account"+suffix)
		for _, foreign := range []string{f.users[actorAdminA].ID, f.users[actorOperatorA].ID} {
			response := f.call(t, actorPlatform, method, accountsPath+"/"+foreign+suffix, confirmBody(""))
			if response.Code != unknown.Code || response.Body.String() != unknown.Body.String() {
				t.Errorf("unit A account %s under unit B%s = %d %s, want %s", foreign, suffix, response.Code, response.Body.String(), unknown.Body.String())
			}
		}
	}
	expectError(t, f.call(t, actorPlatform, http.MethodDelete, "/platform/units/00000000-0000-0000-0000-00000000dead/accounts/"+adminB+"/sessions", confirmBody("")), http.StatusNotFound, "not_found", "sessions in an unknown unit")

	expectResponse(t, f.call(t, actorAdminB, http.MethodGet, "/jobs", ""), http.StatusOK, "unit B jobs before the revocation", nil)
	expectResponse(t, f.call(t, actorPlatform, http.MethodDelete, accountsPath+"/"+adminB+"/sessions", confirmBody("")), http.StatusNoContent, "revoke unit B administrator's sessions", nil)
	expectError(t, f.call(t, actorAdminB, http.MethodGet, "/jobs", ""), http.StatusUnauthorized, "unauthorized", "unit B jobs after the revocation")
	if !containsRecord(auditRecords(t, f.db, f.unitB), "user.sessions_revoked/"+store.AuditActorPlatform+"/") {
		t.Fatalf("unit B audit has no platform revocation: %v", auditRecords(t, f.db, f.unitB))
	}
	if records := auditRecords(t, f.db, store.DefaultTenantID); containsRecord(records, "user.sessions_revoked/") || containsRecord(records, "user.password_reset_issued/") {
		t.Fatalf("unit A audit records unit B's account changes: %v", records)
	}
}

// The platform administrator reads and changes a unit's capacity: an
// absent setting keeps its value, null inherits the deployment's, and a
// value outside the deployment's limits is refused.
func TestPlatformUnitCapacity(t *testing.T) {
	f := newPlatformFixture(t)
	capacityPath := "/platform/units/" + f.unitB + "/capacity"
	var view platformCapacityView
	expectResponse(t, f.call(t, actorPlatform, http.MethodGet, capacityPath, ""), http.StatusOK, "capacity", &view)
	if view.UnitID != f.unitB || view.Capacity.MaxConcurrentScans != nil || view.Capacity.HighCostCeiling == nil || view.Limits.MaxConcurrentScans != 2 || view.Slots.Limit != 2 {
		t.Fatalf("initial capacity = %+v", view)
	}
	ceiling := *view.Capacity.HighCostCeiling
	view = platformCapacityView{}
	expectResponse(t, f.call(t, actorPlatform, http.MethodPatch, capacityPath, `{"max_concurrent_scans":1,"max_probe_count":1000}`), http.StatusOK, "cap the unit", &view)
	if view.Capacity.MaxConcurrentScans == nil || *view.Capacity.MaxConcurrentScans != 1 || view.Capacity.MaxProbeCount == nil || *view.Capacity.MaxProbeCount != 1000 || view.Capacity.HighCostCeiling == nil || *view.Capacity.HighCostCeiling != ceiling || view.Slots.Limit != 1 {
		t.Fatalf("capped capacity = %+v", view)
	}
	view = platformCapacityView{}
	expectResponse(t, f.call(t, actorPlatform, http.MethodPatch, capacityPath, `{"high_cost_ceiling":null,"max_probe_count":null}`), http.StatusOK, "inherit", &view)
	if view.Capacity.HighCostCeiling != nil || view.Capacity.MaxProbeCount != nil || view.Capacity.MaxConcurrentScans == nil {
		t.Fatalf("inherited capacity = %+v", view)
	}
	for body, field := range map[string]string{`{"max_concurrent_scans":5}`: "max_concurrent_scans", `{"max_concurrent_scans":0}`: "max_concurrent_scans", `{"max_naabu_probe_count":0}`: "max_naabu_probe_count", `{"high_cost_ceiling":0}`: "high_cost_ceiling"} {
		if details := expectError(t, f.call(t, actorPlatform, http.MethodPatch, capacityPath, body), http.StatusBadRequest, "validation_failed", "capacity "+body); details[field] == nil {
			t.Errorf("capacity %s details = %v, want %s", body, details, field)
		}
	}
	expectError(t, f.call(t, actorPlatform, http.MethodPatch, capacityPath, `{"max_concurrent_scans":"two"}`), http.StatusBadRequest, "invalid_json", "capacity of the wrong type")
	expectError(t, f.call(t, actorPlatform, http.MethodPatch, "/platform/units/00000000-0000-0000-0000-00000000dead/capacity", `{}`), http.StatusNotFound, "not_found", "capacity of an unknown unit")
	expectError(t, f.call(t, actorPlatform, http.MethodGet, "/platform/units/00000000-0000-0000-0000-00000000dead/capacity", ""), http.StatusNotFound, "not_found", "read capacity of an unknown unit")
	if !containsRecord(auditRecords(t, f.db, f.unitB), "tenant.capacity_changed/"+store.AuditActorPlatform+"/") {
		t.Fatalf("unit B audit has no capacity change: %v", auditRecords(t, f.db, f.unitB))
	}
}

// A unit's status reports the scan capacity that the scheduler enforces for
// the unit: its own caps where it has them, the deployment's settings
// otherwise. A unit without caps reports exactly the deployment's settings,
// with one unit or several. A viewer's status still has no capacity.
func TestUnitStatusReportsTheUnitsCapacity(t *testing.T) {
	statusCapacity := func(t *testing.T, server *Server, account routeMatrixSession) store.CapacityLimits {
		t.Helper()
		var status struct {
			Slots  *int   `json:"max_concurrent_scans"`
			Probes *int64 `json:"max_probe_count"`
			Naabu  *int64 `json:"max_naabu_probe_count"`
		}
		response := callAPI(t, server, account, http.MethodGet, "/status", "")
		expectResponse(t, response, http.StatusOK, "status", &status)
		if status.Slots == nil || status.Probes == nil || status.Naabu == nil {
			t.Fatalf("status without capacity: %s", response.Body.String())
		}
		return store.CapacityLimits{MaxConcurrentScans: *status.Slots, MaxProbeCount: *status.Probes, MaxNaabuProbeCount: *status.Naabu}
	}
	f := newPlatformFixture(t)
	scheduler := &f.server.App.Config.Scheduler
	scheduler.MaxProbeCount, scheduler.MaxNaabuProbeCount = config.DefaultMaxProbeCount, config.DefaultNaabuMaxProbeCount
	deployment := store.CapacityLimits{MaxConcurrentScans: scheduler.MaxConcurrent, MaxProbeCount: scheduler.MaxProbeCount, MaxNaabuProbeCount: scheduler.MaxNaabuProbeCount}
	for _, actor := range []string{actorAdminA, actorOperatorA, actorAdminB} {
		if got := statusCapacity(t, f.server, f.sessions[actor]); got != deployment {
			t.Errorf("capacity as %s without caps = %+v, want %+v", actor, got, deployment)
		}
	}
	expectResponse(t, f.call(t, actorPlatform, http.MethodPatch, "/platform/units/"+f.unitB+"/capacity", `{"max_concurrent_scans":1,"max_probe_count":1000,"max_naabu_probe_count":3000}`), http.StatusOK, "cap unit B", nil)
	capped := store.CapacityLimits{MaxConcurrentScans: 1, MaxProbeCount: 1000, MaxNaabuProbeCount: 3000}
	if got := statusCapacity(t, f.server, f.sessions[actorAdminB]); got != capped {
		t.Errorf("capacity of capped unit B = %+v, want %+v", got, capped)
	}
	if got := statusCapacity(t, f.server, f.sessions[actorAdminA]); got != deployment {
		t.Errorf("capacity of unit A beside capped unit B = %+v, want %+v", got, deployment)
	}
	if body := f.call(t, actorViewerA, http.MethodGet, "/status", "").Body.String(); strings.Contains(body, "max_concurrent_scans") || strings.Contains(body, "probe_count") {
		t.Fatalf("viewer status = %s", body)
	}

	server, _, _ := newUsersTestServer(t)
	server.App.Config.Scheduler = config.Scheduler{MaxConcurrent: 3, MaxProbeCount: 4_000_000, MaxNaabuProbeCount: 30_000_000}
	admin := signIn(t, server, store.RoleAdministrator, "admin", "administrator password", "")
	response := callAPI(t, server, admin, http.MethodGet, "/status", "")
	for _, field := range []string{`"max_concurrent_scans":3,`, `"max_probe_count":4000000,`, `"max_naabu_probe_count":30000000,`} {
		if !strings.Contains(response.Body.String(), field) {
			t.Errorf("single-unit status has no %s: %s", field, response.Body.String())
		}
	}
}

// The platform administrator lists the platform administrators, invites
// another one, who activates the invitation and signs in, and enables and
// disables another one. It cannot change its own account there, a pending
// account cannot be enabled, and a unit's account is not found.
func TestPlatformAdmins(t *testing.T) {
	f := newPlatformFixture(t)
	var list struct {
		Admins []store.UserSummary `json:"admins"`
	}
	expectResponse(t, f.call(t, actorPlatform, http.MethodGet, "/platform/admins", ""), http.StatusOK, "list admins", &list)
	if len(list.Admins) != 2 || list.Admins[0].Username != "platform-root" || list.Admins[1].ID != f.secondPlatformAdmin {
		t.Fatalf("platform admins = %+v", list.Admins)
	}

	var invitation struct {
		User            store.UserSummary `json:"user"`
		ActivationToken string            `json:"activation_token"`
	}
	expectResponse(t, f.call(t, actorPlatform, http.MethodPost, "/platform/admins", confirmBody(`"username":"platform-third"`)), http.StatusCreated, "invite", &invitation)
	if invitation.User.Role != store.RolePlatformAdmin || !invitation.User.Pending || invitation.User.Enabled || invitation.ActivationToken == "" {
		t.Fatalf("invitation = %+v", invitation)
	}
	expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/admins", confirmBody(`"username":"bravo-admin"`)), http.StatusConflict, "conflict", "invite a taken username")
	expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/admins", confirmBody(`"username":"`+strings.Repeat("x", store.MaxUsernameBytes+1)+`"`)), http.StatusBadRequest, "validation_failed", "invite an invalid username")
	if details := expectError(t, f.call(t, actorPlatform, http.MethodPatch, "/platform/admins/"+invitation.User.ID, confirmBody(`"enabled":true`)), http.StatusForbidden, "not_permitted", "enable a pending admin"); details != nil {
		t.Fatalf("pending details = %v", details)
	}
	if !containsRecord(auditRecords(t, f.db, ""), "platform_admin.invited/"+store.AuditActorPlatform+"/") {
		t.Fatalf("platform audit has no invitation: %v", auditRecords(t, f.db, ""))
	}

	activate := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/auth/activate", strings.NewReader(`{"token":"`+invitation.ActivationToken+`","password":"third platform password"}`))
	activate.RemoteAddr = "127.0.0.1:9000"
	activate.Header.Set("Content-Type", "application/json")
	activated := httptest.NewRecorder()
	f.server.api(activated, activate)
	expectResponse(t, activated, http.StatusOK, "activate", nil)
	login := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/auth/login", nil)
	login.RemoteAddr = "127.0.0.1:9000"
	if _, user, err := f.server.Auth.LoginAs(context.Background(), login, "platform-third", "third platform password", "", ""); err != nil || user.Role != store.RolePlatformAdmin || user.TenantID != "" {
		t.Fatalf("sign-in of the invited platform administrator = %+v, %v", user, err)
	}

	second := "/platform/admins/" + f.secondPlatformAdmin
	f.users["second"] = store.User{ID: f.secondPlatformAdmin, Role: store.RolePlatformAdmin}
	secondSession := f.signIn(t, "second")
	expectError(t, f.call(t, actorPlatform, http.MethodPatch, second, confirmBody("")), http.StatusBadRequest, "validation_failed", "update without enabled")
	expectError(t, f.call(t, actorPlatform, http.MethodPatch, second, `{"enabled":false,"password":"wrong password"}`), http.StatusUnauthorized, "invalid_password", "disable with a wrong password")
	expectError(t, f.call(t, actorPlatform, http.MethodPatch, "/platform/admins/"+f.users[actorPlatform].ID, confirmBody(`"enabled":false`)), http.StatusBadRequest, "self_admin_change", "disable self")
	expectError(t, f.call(t, actorPlatform, http.MethodPatch, second, confirmBody(`"enabled":false,"revision":7`)), http.StatusConflict, "conflict", "stale disable")
	var disabled store.UserSummary
	expectResponse(t, f.call(t, actorPlatform, http.MethodPatch, second, confirmBody(`"enabled":false`)), http.StatusOK, "disable", &disabled)
	if disabled.Enabled || disabled.Revision != 2 {
		t.Fatalf("disabled platform admin = %+v", disabled)
	}
	if response := callAPI(t, f.server, secondSession, http.MethodGet, "/platform/units", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("disabled platform admin's session = %d: %s", response.Code, response.Body.String())
	}
	var enabled store.UserSummary
	expectResponse(t, f.call(t, actorPlatform, http.MethodPatch, second, confirmBody(`"enabled":true,"revision":2`)), http.StatusOK, "enable", &enabled)
	if !enabled.Enabled {
		t.Fatalf("enabled platform admin = %+v", enabled)
	}
	unknown := f.call(t, actorPlatform, http.MethodPatch, "/platform/admins/00000000-0000-0000-0000-00000000dead", confirmBody(`"enabled":false`))
	expectError(t, unknown, http.StatusNotFound, "not_found", "unknown admin")
	for _, unitAccount := range []string{f.users[actorAdminA].ID, f.users[actorAdminB].ID} {
		if response := f.call(t, actorPlatform, http.MethodPatch, "/platform/admins/"+unitAccount, confirmBody(`"enabled":false`)); response.Code != unknown.Code || response.Body.String() != unknown.Body.String() {
			t.Errorf("unit account %s as a platform admin = %d %s, want %s", unitAccount, response.Code, response.Body.String(), unknown.Body.String())
		}
	}
	if !containsRecord(auditRecords(t, f.db, ""), "platform_admin.updated/"+store.AuditActorPlatform+"/") {
		t.Fatalf("platform audit has no update: %v", auditRecords(t, f.db, ""))
	}
}

type destinationsPayload struct {
	Destinations []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Revision int64  `json:"revision"`
	} `json:"destinations"`
	UpdateRouting struct {
		Configured   bool     `json:"configured"`
		Destinations []string `json:"destinations"`
	} `json:"update_routing"`
}

// The platform administrator manages the platform's own notification
// destinations and routes the platform's update alerts to them. URLs are
// write-only, a unit's destination is not found, exactly as an unknown one,
// and neither a unit's destinations nor the platform's cross over.
func TestPlatformNotifications(t *testing.T) {
	f := newPlatformFixture(t)
	var list destinationsPayload
	expectResponse(t, f.call(t, actorPlatform, http.MethodGet, "/platform/notifications", ""), http.StatusOK, "empty list", &list)
	if len(list.Destinations) != 0 || list.UpdateRouting.Destinations == nil {
		t.Fatalf("initial platform destinations = %+v", list)
	}
	const secretURL = "generic://localhost/platform-secret-hook?disabletls=yes"
	expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/notifications", `{"name":"platform-ops","url":"`+secretURL+`"}`), http.StatusBadRequest, "password_required", "create without a password")
	expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/notifications", confirmBody(`"name":"platform-ops"`)), http.StatusBadRequest, "validation_failed", "create without a URL")
	expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/notifications", confirmBody(`"name":"platform-ops","url":"not a url"`)), http.StatusBadRequest, "validation_failed", "create with an invalid URL")
	created := f.call(t, actorPlatform, http.MethodPost, "/platform/notifications", confirmBody(`"name":"platform-ops","url":"`+secretURL+`"`))
	var view struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Revision int64  `json:"revision"`
	}
	expectResponse(t, created, http.StatusCreated, "create", &view)
	expectNoMarkers(t, created.Body.String(), "created destination", "platform-secret-hook")
	expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/notifications", confirmBody(`"name":"platform-ops","url":"`+secretURL+`"`)), http.StatusConflict, "conflict", "duplicate name")
	listed := f.call(t, actorPlatform, http.MethodGet, "/platform/notifications", "")
	list = destinationsPayload{}
	expectResponse(t, listed, http.StatusOK, "list", &list)
	if len(list.Destinations) != 1 || list.Destinations[0].ID != view.ID {
		t.Fatalf("platform destinations = %+v", list)
	}
	expectNoMarkers(t, listed.Body.String(), "platform destinations", "platform-secret-hook", "bravo-destination", "alpha-destination", f.destinationB)
	if unit := f.call(t, actorAdminB, http.MethodGet, "/notifications/destinations", ""); unit.Code != http.StatusOK || strings.Contains(unit.Body.String(), "platform-ops") {
		t.Fatalf("unit B destinations = %d: %s", unit.Code, unit.Body.String())
	}

	routing := func(body string) *httptest.ResponseRecorder {
		return f.call(t, actorPlatform, http.MethodPut, "/platform/notifications/update-routing", body)
	}
	expectError(t, routing(confirmBody("")), http.StatusBadRequest, "validation_failed", "routing without destinations")
	unknownSelection := routing(confirmBody(`"destinations":["00000000-0000-0000-0000-00000000dead"]`))
	expectError(t, unknownSelection, http.StatusBadRequest, "validation_failed", "route to an unknown destination")
	for _, foreign := range []string{f.destinationB, f.destinationA, "file:deployment"} {
		response := routing(confirmBody(`"destinations":["` + foreign + `"]`))
		expectError(t, response, http.StatusBadRequest, "validation_failed", "route to "+foreign)
		expectNoMarkers(t, response.Body.String(), "routing to "+foreign, "bravo-destination", "alpha-destination")
	}
	var routed struct {
		Configured   bool     `json:"configured"`
		Destinations []string `json:"destinations"`
	}
	expectResponse(t, routing(confirmBody(`"destinations":["`+view.ID+`"]`)), http.StatusOK, "route", &routed)
	if !routed.Configured || len(routed.Destinations) != 1 || routed.Destinations[0] != view.ID {
		t.Fatalf("routing = %+v", routed)
	}
	if state, err := f.db.Platform().GetApplicationUpdateState(context.Background()); err != nil || len(state.UpdateNotificationDestinations) != 1 {
		t.Fatalf("stored platform routing = %+v, %v", state.UpdateNotificationDestinations, err)
	}

	destinationPath := "/platform/notifications/" + view.ID
	expectError(t, f.call(t, actorPlatform, http.MethodPatch, destinationPath, confirmBody(`"name":"renamed"`)), http.StatusBadRequest, "revision_required", "update without a revision")
	var updated struct {
		Name     string `json:"name"`
		Revision int64  `json:"revision"`
		Enabled  bool   `json:"enabled"`
	}
	expectResponse(t, f.call(t, actorPlatform, http.MethodPatch, destinationPath, confirmBody(`"revision":1,"name":"platform-renamed","enabled":false`)), http.StatusOK, "rename", &updated)
	if updated.Name != "platform-renamed" || updated.Revision != 2 || updated.Enabled {
		t.Fatalf("updated destination = %+v", updated)
	}
	expectResponse(t, f.call(t, actorPlatform, http.MethodPatch, destinationPath, confirmBody(`"revision":2,"url":"`+secretURL+`","enabled":true`)), http.StatusOK, "replace the URL", &updated)
	if updated.Name != "platform-renamed" || updated.Revision != 3 || !updated.Enabled {
		t.Fatalf("destination with a new URL = %+v", updated)
	}
	expectError(t, f.call(t, actorPlatform, http.MethodPatch, destinationPath, confirmBody(`"revision":1,"name":"stale"`)), http.StatusConflict, "conflict", "stale update")
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		unknown := f.call(t, actorPlatform, method, "/platform/notifications/00000000-0000-0000-0000-00000000dead", confirmBody(`"revision":1`))
		expectError(t, unknown, http.StatusNotFound, "not_found", method+" unknown destination")
		for _, foreign := range []string{f.destinationB, f.destinationA} {
			if response := f.call(t, actorPlatform, method, "/platform/notifications/"+foreign, confirmBody(`"revision":1`)); response.Code != unknown.Code || response.Body.String() != unknown.Body.String() {
				t.Errorf("%s unit destination %s = %d %s, want %s", method, foreign, response.Code, response.Body.String(), unknown.Body.String())
			}
		}
	}
	if _, err := f.b.GetManagedNotification(context.Background(), f.destinationB); err != nil {
		t.Fatalf("unit B destination after the platform's attempts: %v", err)
	}
	expectError(t, f.call(t, actorPlatform, http.MethodDelete, destinationPath, confirmBody("")), http.StatusBadRequest, "revision_required", "delete without a revision")
	expectResponse(t, f.call(t, actorPlatform, http.MethodDelete, destinationPath, confirmBody(`"revision":3`)), http.StatusNoContent, "delete", nil)
	list = destinationsPayload{}
	expectResponse(t, f.call(t, actorPlatform, http.MethodGet, "/platform/notifications", ""), http.StatusOK, "list after delete", &list)
	if len(list.Destinations) != 0 || len(list.UpdateRouting.Destinations) != 0 || !list.UpdateRouting.Configured {
		t.Fatalf("after delete = %+v", list)
	}
	records := auditRecords(t, f.db, "")
	for _, action := range []string{"platform_notifications.created", "platform_notifications.update_routing", "platform_notifications.updated", "platform_notifications.deleted"} {
		if !containsRecord(records, action+"/"+store.AuditActorPlatform+"/") {
			t.Errorf("platform audit has no %s: %v", action, records)
		}
	}
	expectNoMarkers(t, strings.Join(records, "\n"), "platform audit", "platform-secret-hook")
}

// The store checks an update routing selection again when it writes it, for
// a caller that skipped the notifier's check or a destination deleted since
// that check. Its refusal gets the answer of the notifier's check byte for
// byte, for a unit's routing and for the platform's, so the API tells
// neither which check refused a selection nor another owner's destination
// from an unknown one.
func TestUpdateRoutingStoreRefusalAnswersAsTheNotifierCheck(t *testing.T) {
	ctx := context.Background()
	f := newPlatformFixture(t)
	platformActor := store.AuditEntry{ActorUserID: f.users[actorPlatform].ID, ActorUsername: f.users[actorPlatform].Username}
	for _, owner := range []struct {
		actor, path string
		foreign     []string
		write       func(selection []string) error
	}{
		{actorAdminB, "/notifications/update-routing", []string{f.destinationA}, func(selection []string) error {
			return f.b.SetApplicationUpdateDestinations(ctx, selection, store.AuditEntry{})
		}},
		{actorPlatform, "/platform/notifications/update-routing", []string{f.destinationA, f.destinationB}, func(selection []string) error {
			return f.db.Platform().SetPlatformUpdateDestinations(ctx, selection, platformActor)
		}},
	} {
		for _, selector := range append(owner.foreign, "file:deployment", "00000000-0000-0000-0000-00000000dead") {
			checked := f.call(t, owner.actor, http.MethodPut, owner.path, confirmBody(`"destinations":["`+selector+`"]`))
			refused := httptest.NewRecorder()
			if err := owner.write([]string{selector}); !writeDestinationSelectionError(refused, err) {
				t.Fatalf("%s: the store's refusal of %s = %v, not a selection error", owner.actor, selector, err)
			}
			if checked.Code != http.StatusBadRequest || refused.Code != checked.Code || refused.Body.String() != checked.Body.String() {
				t.Errorf("%s: routing to %s = %d %s from the store, %d %s from the notifier", owner.actor, selector, refused.Code, refused.Body.String(), checked.Code, checked.Body.String())
			}
		}
	}
	if writeDestinationSelectionError(httptest.NewRecorder(), store.ErrNotFound) {
		t.Fatal("another store error was answered as a selection error")
	}
	// Another refusal of the platform routing write keeps its own answer: an
	// account that is not a platform administrator by the time of the write
	// is refused by the store, not as a selection.
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, consoleAPIBase+"/platform/notifications/update-routing", strings.NewReader(confirmBody(`"destinations":[]`)))
	request.Header.Set("Content-Type", "application/json")
	f.server.updatePlatformNotificationRouting(recorder, request, f.sessions[actorAdminB].session)
	expectError(t, recorder, http.StatusForbidden, "not_permitted", "platform routing written by a unit's administrator")
}

// A unit that the platform creates starts with update alerts off: its
// administrator sees its update routing configured and selecting none of
// its destinations, so the console shows every Update alerts toggle off,
// until the administrator selects one. The default unit's routing that was
// never saved is still reported as not configured, which the console shows
// as each enabled destination selected, as before business units.
func TestNewUnitStartsWithUpdateAlertsOff(t *testing.T) {
	f := newPlatformFixture(t)
	var unit destinationsPayload
	expectResponse(t, f.call(t, actorAdminB, http.MethodGet, "/notifications/destinations", ""), http.StatusOK, "the new unit's destinations", &unit)
	if len(unit.Destinations) != 1 || unit.Destinations[0].ID != f.destinationB || !unit.UpdateRouting.Configured || unit.UpdateRouting.Destinations == nil || len(unit.UpdateRouting.Destinations) != 0 {
		t.Fatalf("the new unit's destinations = %+v, want its destination with configured, empty update routing", unit)
	}
	var defaultUnit destinationsPayload
	expectResponse(t, f.call(t, actorAdminA, http.MethodGet, "/notifications/destinations", ""), http.StatusOK, "the default unit's destinations", &defaultUnit)
	if defaultUnit.UpdateRouting.Configured || len(defaultUnit.UpdateRouting.Destinations) != 0 {
		t.Fatalf("the default unit's update routing = %+v, want it never configured", defaultUnit.UpdateRouting)
	}
	var saved struct {
		Configured   bool     `json:"configured"`
		Destinations []string `json:"destinations"`
	}
	expectResponse(t, f.call(t, actorAdminB, http.MethodPut, "/notifications/update-routing", confirmBody(`"destinations":["`+f.destinationB+`"]`)), http.StatusOK, "select the new unit's destination", &saved)
	if !saved.Configured || len(saved.Destinations) != 1 || saved.Destinations[0] != f.destinationB {
		t.Fatalf("the new unit's saved update routing = %+v, want its destination", saved)
	}
}

// The platform status reports the deployment as numbers only.
func TestPlatformStatus(t *testing.T) {
	f := newPlatformFixture(t)
	response := f.call(t, actorPlatform, http.MethodGet, "/platform/status", "")
	var status struct {
		Version        string         `json:"version"`
		Units          map[string]int `json:"units"`
		Accounts       int            `json:"accounts"`
		Jobs           int            `json:"jobs"`
		PlatformAdmins map[string]int `json:"platform_admins"`
		Capacity       struct {
			Limits platformLimitsView `json:"limits"`
			Slots  map[string]int     `json:"slots"`
		} `json:"capacity"`
		Updates map[string]any `json:"updates"`
	}
	expectResponse(t, response, http.StatusOK, "status", &status)
	if status.Version == "" || status.Units["total"] != 2 || status.Units[store.TenantStateActive] != 2 || status.Accounts != 5 || status.Jobs != 3 || status.PlatformAdmins["total"] != 2 || status.PlatformAdmins["enabled"] != 2 || status.Capacity.Limits.MaxConcurrentScans != 2 || status.Capacity.Slots["capacity"] != 2 || status.Updates["current_version"] == nil {
		t.Fatalf("platform status = %s", response.Body.String())
	}
	expectNoMarkers(t, response.Body.String(), "platform status", "bravo", "alpha", "shared-job", platformFixtureAddress)
}

// The platform console counts each unit's stored scans in the unit list, the
// unit detail and the status total, the scans of an archived job included,
// and never another unit's. It gets the number only, never a scan. No route
// that a unit's account may read carries the count, and the platform routes
// stay refused to them.
func TestPlatformUnitsReportStoredScans(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	// Unit B's "shared-job" is archived with a failed scan it keeps.
	finished := time.Now().UTC()
	archived := model.Scan{ID: "scan-bravo-archived", JobID: f.sharedJobB, Job: "shared-job", StartedAt: finished.Add(-time.Minute), FinishedAt: finished, Status: "failed", Error: "nmap exited"}
	if err := f.db.System().SaveScan(ctx, archived); err != nil {
		t.Fatal(err)
	}
	if err := f.b.SetJobArchived(ctx, f.sharedJobB, true); err != nil {
		t.Fatal(err)
	}

	var list struct {
		Units []unitPayload `json:"units"`
	}
	response := f.call(t, actorPlatform, http.MethodGet, "/platform/units", "")
	expectResponse(t, response, http.StatusOK, "list units", &list)
	counts := map[string]int64{}
	for _, unit := range list.Units {
		counts[unit.ID] = unit.StoredScans
	}
	if want := map[string]int64{store.DefaultTenantID: 1, f.unitB: 2}; !reflect.DeepEqual(counts, want) {
		t.Fatalf("stored scans in the unit list = %v, want %v: %s", counts, want, response.Body.String())
	}
	expectNoMarkers(t, response.Body.String(), "unit list", f.dataMarkers()...)
	expectNoMarkers(t, response.Body.String(), "unit list", archived.ID, archived.Error)

	var detail unitPayload
	response = f.call(t, actorPlatform, http.MethodGet, "/platform/units/"+f.unitB, "")
	expectResponse(t, response, http.StatusOK, "unit B", &detail)
	if detail.StoredScans != 2 || !strings.Contains(response.Body.String(), `"stored_scans":2`) {
		t.Fatalf("unit B's detail = %s, want 2 stored scans", response.Body.String())
	}
	expectNoMarkers(t, response.Body.String(), "unit B", f.dataMarkers()...)
	expectNoMarkers(t, response.Body.String(), "unit B", archived.ID, archived.Error)

	var created unitPayload
	expectResponse(t, f.call(t, actorPlatform, http.MethodPost, "/platform/units", `{"name":"Charlie Unit"}`), http.StatusCreated, "create unit", &created)
	response = f.call(t, actorPlatform, http.MethodGet, "/platform/units/"+created.ID, "")
	expectResponse(t, response, http.StatusOK, "new unit", &detail)
	if detail.StoredScans != 0 || !strings.Contains(response.Body.String(), `"stored_scans":0`) {
		t.Fatalf("a new unit's detail = %s, want 0 stored scans", response.Body.String())
	}

	var status struct {
		StoredScans *int64 `json:"stored_scans"`
	}
	expectResponse(t, f.call(t, actorPlatform, http.MethodGet, "/platform/status", ""), http.StatusOK, "status", &status)
	if status.StoredScans == nil || *status.StoredScans != 3 {
		t.Fatalf("platform status stored scans = %v, want 3", status.StoredScans)
	}

	// A unit's accounts read their own routes without the count, and the
	// platform routes refuse them.
	checked := 0
	for _, route := range apiRoutes {
		if route.Access != routeSession || route.Mutates || route.NoHandler {
			continue
		}
		for _, actor := range []string{actorAdminA, actorOperatorA, actorViewerA, actorAdminB} {
			unit := "A"
			if actor == actorAdminB {
				unit = "B"
			}
			name := routeInventoryName(route) + " as " + actor
			response := f.isolationRequest(t, actor, route, f.unitIDs(unit).path(t, route.Template))
			if strings.Contains(response.body, "stored_scans") {
				t.Errorf("%s = %d %s, want no stored scan count", name, response.status, response.body)
			}
			if strings.HasPrefix(route.Template, "/platform/") && (response.status != http.StatusForbidden || response.code != "forbidden") {
				t.Errorf("%s = %d %s, want 403", name, response.status, response.body)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no route was read as a unit's account")
	}
}

// The platform audit shows the platform's records and the account and
// platform records of every unit, never a unit's data records, and names
// each record's unit. The unit audit shows only the unit's own records, and
// hides the source address of a platform administrator's actions. Both page
// with a keyset, and a cursor that names another view's entry is not found,
// exactly as an unknown one.
func TestPlatformAndUnitAuditViews(t *testing.T) {
	f := newPlatformFixture(t)
	expectResponse(t, f.call(t, actorPlatform, http.MethodPatch, "/platform/units/"+f.unitB+"/capacity", `{"max_concurrent_scans":1}`), http.StatusOK, "cap unit B", nil)

	var page struct {
		Entries []struct {
			ID       int64  `json:"id"`
			Action   string `json:"action"`
			Category string `json:"category"`
			Detail   string `json:"detail"`
			SourceIP string `json:"source_ip"`
			Actor    struct {
				Kind     string `json:"kind"`
				Username string `json:"username"`
			} `json:"actor"`
			Unit *unitRefView `json:"unit"`
		} `json:"entries"`
		NextBefore *int64 `json:"next_before"`
	}
	platformView := f.call(t, actorPlatform, http.MethodGet, "/platform/audit", "")
	expectResponse(t, platformView, http.StatusOK, "platform audit", &page)
	expectNoMarkers(t, platformView.Body.String(), "platform audit", "bravo-data-audit", "alpha-data-audit")
	found := map[string]bool{}
	for _, entry := range page.Entries {
		found[entry.Action+"/"+entry.Detail] = true
		if entry.Detail == "bravo-account-audit" && (entry.Unit == nil || entry.Unit.Name != "Bravo Unit" || entry.SourceIP != "203.0.113.20") {
			t.Errorf("unit B account record = %+v", entry)
		}
		if entry.Action == "tenant.capacity_changed" && (entry.SourceIP != "127.0.0.1" || entry.Actor.Kind != store.AuditActorPlatform || entry.Unit == nil || entry.Unit.ID != f.unitB) {
			t.Errorf("capacity record in the platform view = %+v", entry)
		}
		if entry.Action == "tenant.created" && entry.Unit != nil {
			t.Errorf("platform-scope record names a unit: %+v", entry)
		}
	}
	if !found["user.created/bravo-account-audit"] || page.NextBefore != nil {
		t.Fatalf("platform audit = %s", platformView.Body.String())
	}
	var filtered = page
	filtered.Entries = nil
	expectResponse(t, f.call(t, actorPlatform, http.MethodGet, "/platform/audit?unit="+f.unitB+"&action=tenant.", ""), http.StatusOK, "platform audit of unit B", &filtered)
	if len(filtered.Entries) != 1 || filtered.Entries[0].Action != "tenant.capacity_changed" {
		t.Fatalf("filtered platform audit = %+v", filtered.Entries)
	}
	first := page
	first.Entries = nil
	expectResponse(t, f.call(t, actorPlatform, http.MethodGet, "/platform/audit?limit=1", ""), http.StatusOK, "first page", &first)
	if len(first.Entries) != 1 || first.NextBefore == nil {
		t.Fatalf("first page = %+v", first)
	}
	next := page
	next.Entries = nil
	expectResponse(t, f.call(t, actorPlatform, http.MethodGet, "/platform/audit?limit=1&before="+strconv.FormatInt(*first.NextBefore, 10), ""), http.StatusOK, "second page", &next)
	if len(next.Entries) != 1 || next.Entries[0].ID >= first.Entries[0].ID {
		t.Fatalf("second page = %+v after %+v", next.Entries, first.Entries)
	}
	for query, field := range map[string]string{"before=x": "before", "before=-1": "before", "limit=0": "limit", "limit=201": "limit", "since=yesterday": "since", "until=1": "until", "action=Bad*": "action"} {
		if details := expectError(t, f.call(t, actorPlatform, http.MethodGet, "/platform/audit?"+query, ""), http.StatusBadRequest, "validation_failed", "platform audit ?"+query); details[field] == nil {
			t.Errorf("?%s details = %v, want %s", query, details, field)
		}
	}

	unitView := f.call(t, actorAdminB, http.MethodGet, "/audit", "")
	var unitPage = page
	unitPage.Entries = nil
	expectResponse(t, unitView, http.StatusOK, "unit B audit", &unitPage)
	expectNoMarkers(t, unitView.Body.String(), "unit B audit", "alpha-", "127.0.0.1", "tenant.created")
	unitFound := map[string]bool{}
	for _, entry := range unitPage.Entries {
		unitFound[entry.Action] = true
		if entry.Unit != nil {
			t.Errorf("unit audit names a unit: %+v", entry)
		}
		if entry.Action == "tenant.capacity_changed" && (entry.Actor.Kind != store.AuditActorPlatform || entry.SourceIP != "") {
			t.Errorf("platform action in the unit audit = %+v", entry)
		}
	}
	if !unitFound["job.created"] || !unitFound["user.created"] || !unitFound["tenant.capacity_changed"] {
		t.Fatalf("unit B audit = %s", unitView.Body.String())
	}
	sinceView := f.call(t, actorAdminB, http.MethodGet, "/audit?since=2000-01-01T00:00:00Z&until=2999-01-01T00:00:00Z&actor="+f.users[actorAdminB].ID, "")
	expectResponse(t, sinceView, http.StatusOK, "filtered unit audit", nil)
	expectNoMarkers(t, sinceView.Body.String(), "filtered unit audit", "tenant.capacity_changed")
	aView := f.call(t, actorAdminA, http.MethodGet, "/audit", "")
	expectResponse(t, aView, http.StatusOK, "unit A audit", nil)
	expectNoMarkers(t, aView.Body.String(), "unit A audit", "bravo", f.unitB, "tenant.capacity_changed")

	// A cursor that names another unit's entry, or a platform record, is
	// refused exactly as an unknown one.
	var foreignID, platformID int64
	if err := f.db.DB.QueryRow(`SELECT id FROM security_audit WHERE tenant_id=? LIMIT 1`, store.DefaultTenantID).Scan(&foreignID); err != nil {
		t.Fatal(err)
	}
	if err := f.db.DB.QueryRow(`SELECT id FROM security_audit WHERE tenant_id IS NULL LIMIT 1`).Scan(&platformID); err != nil {
		t.Fatal(err)
	}
	unknown := f.call(t, actorAdminB, http.MethodGet, "/audit?before=999999", "")
	expectError(t, unknown, http.StatusNotFound, "not_found", "unknown cursor")
	for _, id := range []int64{foreignID, platformID} {
		if response := f.call(t, actorAdminB, http.MethodGet, fmt.Sprintf("/audit?before=%d", id), ""); response.Code != unknown.Code || response.Body.String() != unknown.Body.String() {
			t.Errorf("foreign cursor %d = %d %s, want %s", id, response.Code, response.Body.String(), unknown.Body.String())
		}
	}
	var dataID int64
	if err := f.db.DB.QueryRow(`SELECT id FROM security_audit WHERE detail='bravo-data-audit'`).Scan(&dataID); err != nil {
		t.Fatal(err)
	}
	platformUnknown := f.call(t, actorPlatform, http.MethodGet, "/platform/audit?before=999999", "")
	expectError(t, platformUnknown, http.StatusNotFound, "not_found", "unknown platform cursor")
	if response := f.call(t, actorPlatform, http.MethodGet, fmt.Sprintf("/platform/audit?before=%d", dataID), ""); response.Body.String() != platformUnknown.Body.String() {
		t.Errorf("data record cursor in the platform view = %d %s", response.Code, response.Body.String())
	}
	expectError(t, f.call(t, actorAdminB, http.MethodGet, "/audit?limit=abc", ""), http.StatusBadRequest, "validation_failed", "unit audit bad limit")
	expectError(t, f.call(t, actorAdminB, http.MethodGet, "/audit?action=%20Bad", ""), http.StatusBadRequest, "validation_failed", "unit audit bad action")
	for _, actor := range []string{actorOperatorA, actorViewerA, actorPlatform} {
		if details := expectError(t, f.call(t, actor, http.MethodGet, "/audit", ""), http.StatusForbidden, "forbidden", actor+" unit audit"); details["permission"] != auth.PermissionAuditRead {
			t.Errorf("%s unit audit details = %v", actor, details)
		}
	}
}

// The platform handlers refuse what the store refuses: a reset for a
// disabled administrator or in a disabled unit, an invitation into a
// disabled unit, and a wrong password. A store that cannot be read is an
// internal error, never a partial answer.
func TestPlatformHandlersReportRefusalsAndFailures(t *testing.T) {
	ctx := context.Background()
	f := newPlatformFixture(t)
	accountsPath := "/platform/units/" + f.unitB + "/accounts"
	disabled, err := f.b.CreateUser(ctx, store.User{Username: "bravo-disabled", Role: store.RoleAdministrator, PasswordHash: cheapPasswordHash(platformFixturePassword), Enabled: false}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	expectError(t, f.call(t, actorPlatform, http.MethodPost, accountsPath+"/"+disabled.ID+"/password-reset", confirmBody("")), http.StatusConflict, "user_disabled", "reset a disabled administrator")
	expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/units/00000000-0000-0000-0000-00000000dead/accounts/"+disabled.ID+"/password-reset", confirmBody("")), http.StatusNotFound, "not_found", "reset in an unknown unit")
	expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/units/00000000-0000-0000-0000-00000000dead/accounts", confirmBody(`"username":"nobody"`)), http.StatusNotFound, "not_found", "invite into an unknown unit")
	expectError(t, f.call(t, actorPlatform, http.MethodPost, "/platform/notifications", `{"name":"x","url":"generic://localhost/x","password":"wrong password"}`), http.StatusUnauthorized, "invalid_password", "create a destination with a wrong password")
	expectError(t, f.call(t, actorPlatform, http.MethodPatch, "/platform/notifications/00000000-0000-0000-0000-00000000dead", confirmBody(`"revision":1,"url":"not a url"`)), http.StatusNotFound, "not_found", "update an unknown destination")

	expectResponse(t, f.call(t, actorPlatform, http.MethodPost, "/platform/units/"+f.unitB+"/disable", confirmBody("")), http.StatusOK, "disable unit B", nil)
	expectError(t, f.call(t, actorPlatform, http.MethodPost, accountsPath+"/"+f.users[actorAdminB].ID+"/password-reset", confirmBody("")), http.StatusConflict, "unit_not_active", "reset in a disabled unit")
	expectError(t, f.call(t, actorPlatform, http.MethodPost, accountsPath, confirmBody(`"username":"bravo-late"`)), http.StatusConflict, "unit_not_active", "invite into a disabled unit")
	var accounts struct {
		Accounts []store.UserSummary `json:"accounts"`
	}
	expectResponse(t, f.call(t, actorPlatform, http.MethodGet, accountsPath, ""), http.StatusOK, "accounts of a disabled unit", &accounts)
	if len(accounts.Accounts) != 3 {
		t.Fatalf("accounts of a disabled unit = %+v", accounts.Accounts)
	}

	// With the database closed, every read is an internal error.
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, rest := range []string{"units", "units/" + f.unitB, "units/" + f.unitB + "/capacity", "units/" + f.unitB + "/accounts", "admins", "audit", "notifications", "status"} {
		recorder := httptest.NewRecorder()
		f.server.platformRoute(recorder, httptest.NewRequest(http.MethodGet, consoleAPIBase+"/platform/"+rest, nil), f.sessions[actorPlatform].session, rest)
		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("GET /platform/%s with the database closed = %d %s", rest, recorder.Code, recorder.Body.String())
		}
	}
	recorder := httptest.NewRecorder()
	f.server.unitAudit(recorder, httptest.NewRequest(http.MethodGet, consoleAPIBase+"/audit", nil), f.b)
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("unit audit with the database closed = %d %s", recorder.Code, recorder.Body.String())
	}
	scopeless := httptest.NewRecorder()
	f.server.session(scopeless, httptest.NewRequest(http.MethodGet, consoleAPIBase+"/auth/session", nil), f.sessions[actorAdminA].session)
	if scopeless.Code != http.StatusInternalServerError {
		t.Errorf("session with the database closed = %d %s", scopeless.Code, scopeless.Body.String())
	}
}
