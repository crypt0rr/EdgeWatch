package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// activateLink redeems an activation or password-reset link through the
// API, from its own client address so the attempts share no rate limit.
func activateLink(t *testing.T, server *Server, token, password, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/auth/activate", strings.NewReader(`{"token":"`+token+`","password":"`+password+`"}`))
	request.RemoteAddr = remoteAddr
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.api(recorder, request)
	return recorder
}

// linkRevocationRecord is the attribution and detail of the one
// user.activation_revoked record of the unit.
type linkRevocationRecord struct{ kind, actorID, actorName, detail string }

func onlyLinkRevocation(t *testing.T, db *store.Store, tenantID string) linkRevocationRecord {
	t.Helper()
	if got := countWhere(t, db, `SELECT COUNT(*) FROM security_audit WHERE action='user.activation_revoked' AND tenant_id=?`, tenantID); got != 1 {
		t.Fatalf("link revocation records in %s = %d, want 1", tenantID, got)
	}
	var record linkRevocationRecord
	if err := db.DB.QueryRow(`SELECT actor_kind,actor_user_id,actor_username,detail FROM security_audit WHERE action='user.activation_revoked' AND tenant_id=?`, tenantID).Scan(&record.kind, &record.actorID, &record.actorName, &record.detail); err != nil {
		t.Fatal(err)
	}
	return record
}

// An account's own password change ends the password-reset link that an
// administrator issued for it before the change, and records the
// revocation with the account as its actor. Another account's link still
// works, and so does a link issued for the account after the change.
func TestOwnPasswordChangeRevokesTheAccountsResetLink(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	operator, viewer := f.users[actorOperatorA], f.users[actorViewerA]
	issue := func(id, step string) string {
		t.Helper()
		var issued struct {
			ActivationToken string `json:"activation_token"`
		}
		expectResponse(t, f.call(t, actorAdminA, http.MethodPost, "/users/"+id+"/password-reset", confirmBody("")), http.StatusOK, step, &issued)
		if issued.ActivationToken == "" {
			t.Fatalf("%s returned no link", step)
		}
		return issued.ActivationToken
	}
	before := issue(operator.ID, "issue the operator's reset link")
	viewerLink := issue(viewer.ID, "issue the viewer's reset link")

	expectResponse(t, f.call(t, actorOperatorA, http.MethodPut, "/auth/password", `{"current_password":"`+platformFixturePassword+`","new_password":"operator's own new password"}`), http.StatusNoContent, "the operator changes its own password", nil)
	expectError(t, activateLink(t, f.server, before, "password from the old link", "127.0.0.1:9101"), http.StatusBadRequest, "activation_failed", "redeem the link issued before the password change")
	record := onlyLinkRevocation(t, f.db, store.DefaultTenantID)
	if record.kind != store.AuditActorUnit || record.actorID != operator.ID || record.actorName != operator.Username || !strings.Contains(record.detail, operator.Username) {
		t.Fatalf("link revocation record = %+v, want the operator %s naming itself", record, operator.Username)
	}

	expectResponse(t, activateLink(t, f.server, viewerLink, "viewer's password from its link", "127.0.0.1:9102"), http.StatusOK, "redeem another account's link", nil)
	after := issue(operator.ID, "issue a reset link after the password change")
	expectResponse(t, activateLink(t, f.server, after, "password from the new link", "127.0.0.1:9103"), http.StatusOK, "redeem the link issued after the password change", nil)
}

// A reset link that the platform administrator issued for a unit's
// administrator stops working once the unit changes that account's role,
// and the revocation is recorded with the unit administrator who changed
// it. The platform administrator's link for another administrator of the
// unit still works.
func TestUnitRoleChangeRevokesThePlatformAdministratorsResetLink(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPlatformFixture(t)
	second, err := f.b.CreateUser(ctx, store.User{Username: "bravo-admin-two", DisplayName: "bravo-admin-two", Role: store.RoleAdministrator, PasswordHash: cheapPasswordHash(platformFixturePassword), Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	accountsPath := "/platform/units/" + f.unitB + "/accounts/"
	issue := func(id, step string) string {
		t.Helper()
		var issued struct {
			ActivationToken string `json:"activation_token"`
		}
		expectResponse(t, f.call(t, actorPlatform, http.MethodPost, accountsPath+id+"/password-reset", confirmBody("")), http.StatusOK, step, &issued)
		if issued.ActivationToken == "" {
			t.Fatalf("%s returned no link", step)
		}
		return issued.ActivationToken
	}
	demotedLink := issue(second.ID, "the platform administrator resets the second administrator")
	keptLink := issue(f.users[actorAdminB].ID, "the platform administrator resets the first administrator")

	expectResponse(t, f.call(t, actorAdminB, http.MethodPatch, "/users/"+second.ID, confirmBody(`"role":"operator"`)), http.StatusOK, "the unit demotes the second administrator", nil)
	expectError(t, activateLink(t, f.server, demotedLink, "password from the platform's link", "127.0.0.1:9201"), http.StatusBadRequest, "activation_failed", "redeem the platform's link after the demotion")
	admin := f.users[actorAdminB]
	record := onlyLinkRevocation(t, f.db, f.unitB)
	if record.kind != store.AuditActorUnit || record.actorID != admin.ID || record.actorName != admin.Username || !strings.Contains(record.detail, second.Username) {
		t.Fatalf("link revocation record = %+v, want %s naming %s", record, admin.Username, second.Username)
	}
	expectResponse(t, activateLink(t, f.server, keptLink, "password from the kept link", "127.0.0.1:9202"), http.StatusOK, "redeem the platform's link for the administrator whose role did not change", nil)
}
