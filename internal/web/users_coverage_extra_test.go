package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestUserHandlersCoverValidationAndStoreFailures(t *testing.T) {
	server, db, admin := newUsersTestServer(t)
	call := func(method, rest, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/users"+rest, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		server.usersRoute(rec, req, admin, strings.TrimPrefix(rest, "/"))
		return rec
	}

	if rec := call(http.MethodPatch, "/unknown", `{}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unsupported user route = %d", rec.Code)
	}
	if rec := call(http.MethodPost, "", `{`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed create = %d", rec.Code)
	}
	if rec := call(http.MethodPost, "", `{"display_name":"Missing username"}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "username") {
		t.Fatalf("missing username = %d: %s", rec.Code, rec.Body.String())
	}
	created := call(http.MethodPost, "", `{"username":"revokable","display_name":""}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("empty display name should use username default = %d: %s", created.Code, created.Body.String())
	}
	var createdResponse struct {
		User store.UserSummary `json:"user"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdResponse); err != nil {
		t.Fatal(err)
	}
	if rec := call(http.MethodDelete, "/"+createdResponse.User.ID+"/activation", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke activation = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodDelete, "/"+createdResponse.User.ID+"/activation", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("revoke missing activation = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "", `{"username":"bad","display_name":"bad\nname"}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "display_name") {
		t.Fatalf("control display name = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "", `{"username":"bad","display_name":"`+strings.Repeat("x", maxDisplayNameRunes+1)+`"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("long display name = %d", rec.Code)
	}

	if rec := call(http.MethodPatch, "/missing", `{}`); rec.Code != http.StatusNotFound {
		t.Fatalf("missing update = %d", rec.Code)
	}
	if rec := call(http.MethodPatch, "/"+store.LegacyAdminUserID, `{`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed update = %d", rec.Code)
	}
	if rec := call(http.MethodPatch, "/"+store.LegacyAdminUserID, `{"display_name":""}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid display update = %d", rec.Code)
	}
	if rec := call(http.MethodPatch, "/"+store.LegacyAdminUserID, `{"role":"invalid"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid role update = %d", rec.Code)
	}
	if rec := call(http.MethodPatch, "/"+store.LegacyAdminUserID, `{"enabled":false}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "self") {
		t.Fatalf("self disable = %d: %s", rec.Code, rec.Body.String())
	}

	otherActor := store.Session{UserID: "different-actor", Username: "other", Role: store.RoleAdministrator}
	lastAdminRequest := httptest.NewRequest(http.MethodPatch, "/api/v1/users/"+store.LegacyAdminUserID, strings.NewReader(`{"role":"viewer"}`))
	lastAdminRequest.Header.Set("Content-Type", "application/json")
	lastAdmin := httptest.NewRecorder()
	server.updateUser(lastAdmin, lastAdminRequest, otherActor, store.LegacyAdminUserID)
	if lastAdmin.Code != http.StatusBadRequest || !strings.Contains(lastAdmin.Body.String(), "last_admin") {
		t.Fatalf("last-admin demotion = %d: %s", lastAdmin.Code, lastAdmin.Body.String())
	}

	hash, err := auth.PasswordHash("operator account password")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := db.CreateUser(context.Background(), store.User{Username: "handler-operator", DisplayName: "Operator", Role: store.RoleOperator, PasswordHash: hash, Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSessionForUserWithAudit(context.Background(), operator.ID, "idempotent-user-update", "csrf", time.Now().UTC(), time.Now().UTC().Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	// Supplying an unchanged role is not a security transition and must not
	// revoke the account's active sessions.
	if rec := call(http.MethodPatch, "/"+operator.ID, `{"role":"operator"}`); rec.Code != http.StatusOK {
		t.Fatalf("idempotent role update = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := db.GetSession(context.Background(), "idempotent-user-update"); err != nil {
		t.Fatalf("idempotent role update revoked session: %v", err)
	}
	if rec := call(http.MethodPost, "/"+operator.ID+"/activation", "{}"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "activation_token") {
		t.Fatalf("activation issue = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "/missing/activation", "{}"); rec.Code != http.StatusNotFound {
		t.Fatalf("missing activation = %d", rec.Code)
	}

	missingToken := httptest.NewRecorder()
	missingTokenRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/activate", strings.NewReader(`{"password":"operator account password"}`))
	missingTokenRequest.Header.Set("Content-Type", "application/json")
	server.activateUser(missingToken, missingTokenRequest)
	if missingToken.Code != http.StatusBadRequest || !strings.Contains(missingToken.Body.String(), "token") {
		t.Fatalf("missing activation token = %d: %s", missingToken.Code, missingToken.Body.String())
	}
	badToken := httptest.NewRecorder()
	badTokenRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/activate", strings.NewReader(`{"token":"does-not-exist","password":"operator account password"}`))
	badTokenRequest.Header.Set("Content-Type", "application/json")
	server.activateUser(badToken, badTokenRequest)
	if badToken.Code != http.StatusBadRequest {
		t.Fatalf("invalid activation token = %d: %s", badToken.Code, badToken.Body.String())
	}

	disabled, err := db.CreateUser(context.Background(), store.User{Username: "disabled-user", DisplayName: "Disabled", Role: store.RoleViewer, PasswordHash: hash, Enabled: false}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"activation", "password-reset"} {
		rec := call(http.MethodPost, "/"+disabled.ID+"/"+action, "{}")
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "user_disabled") {
			t.Fatalf("disabled %s issue = %d: %s", action, rec.Code, rec.Body.String())
		}
	}

	locked, err := db.CreateUser(context.Background(), store.User{Username: "locked-totp", DisplayName: "Locked TOTP", Role: store.RoleViewer, PasswordHash: hash, Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(context.Background(), `UPDATE users SET totp_enabled=1,totp_secret='' WHERE id=?`, locked.ID); err != nil {
		t.Fatal(err)
	}
	lockedUpdate := call(http.MethodPatch, "/"+locked.ID, `{"display_name":"still locked"}`)
	if lockedUpdate.Code != http.StatusServiceUnavailable || !strings.Contains(lockedUpdate.Body.String(), "totp_locked") || strings.Contains(lockedUpdate.Body.String(), "cannot be decrypted") {
		t.Fatalf("locked TOTP update = %d: %s", lockedUpdate.Code, lockedUpdate.Body.String())
	}

	closedServer, closedDB, closedAdmin := newUsersTestServer(t)
	if err := closedDB.Close(); err != nil {
		t.Fatal(err)
	}
	for _, run := range []func(*httptest.ResponseRecorder){
		func(w *httptest.ResponseRecorder) {
			closedServer.listUsers(w, httptest.NewRequest(http.MethodGet, "/", nil))
		},
		func(w *httptest.ResponseRecorder) {
			closedServer.getUser(w, httptest.NewRequest(http.MethodGet, "/", nil), closedAdmin.UserID)
		},
		func(w *httptest.ResponseRecorder) {
			closedServer.issueActivation(w, httptest.NewRequest(http.MethodPost, "/", nil), closedAdmin, closedAdmin.UserID, "user.activation_issued")
		},
	} {
		rec := httptest.NewRecorder()
		run(rec)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("closed-store user handler status = %d: %s", rec.Code, rec.Body.String())
		}
	}
}

func TestUserSecurityHandlersCoverOperatorAndTOTPSuccess(t *testing.T) {
	ctx := context.Background()
	server, db, _ := newUsersTestServer(t)
	hash, err := auth.PasswordHash("operator account password")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := db.CreateUser(ctx, store.User{Username: "security-operator", DisplayName: "Operator", Role: store.RoleOperator, PasswordHash: hash, Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	session := store.Session{UserID: operator.ID, Username: operator.Username, Role: operator.Role, CSRFToken: "csrf"}

	display := httptest.NewRecorder()
	displayRequest := httptest.NewRequest(http.MethodPut, "/api/v1/auth/display-name", strings.NewReader(`{"display_name":" Operations "}`))
	displayRequest.Header.Set("Content-Type", "application/json")
	server.changeDisplayName(display, displayRequest, session)
	if display.Code != http.StatusOK || !strings.Contains(display.Body.String(), "Operations") {
		t.Fatalf("operator display name = %d: %s", display.Code, display.Body.String())
	}

	password := httptest.NewRecorder()
	passwordRequest := httptest.NewRequest(http.MethodPut, "/api/v1/auth/password", strings.NewReader(`{"current_password":"operator account password","new_password":"replacement operator password"}`))
	passwordRequest.Header.Set("Content-Type", "application/json")
	server.changePassword(password, passwordRequest, session)
	if password.Code != http.StatusNoContent {
		t.Fatalf("operator password change = %d: %s", password.Code, password.Body.String())
	}

	cookieValue := "operator-totp-session"
	setupRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/setup", strings.NewReader(`{"password":"replacement operator password"}`))
	setupRequest.Header.Set("Content-Type", "application/json")
	setupRequest.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: cookieValue})
	setup := httptest.NewRecorder()
	server.totpSetup(setup, setupRequest, session)
	if setup.Code != http.StatusOK {
		t.Fatalf("operator TOTP setup = %d: %s", setup.Code, setup.Body.String())
	}
	var setupValue struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(setup.Body.Bytes(), &setupValue); err != nil || setupValue.Secret == "" {
		t.Fatalf("operator TOTP setup payload = %s (%v)", setup.Body.String(), err)
	}

	enableRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/enable", strings.NewReader(`{"code":"`+coverageTOTPCode(setupValue.Secret, time.Now().Unix()/30)+`"}`))
	enableRequest.Header.Set("Content-Type", "application/json")
	enableRequest.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: cookieValue})
	enable := httptest.NewRecorder()
	server.totpEnable(enable, enableRequest, session)
	if enable.Code != http.StatusOK || !strings.Contains(enable.Body.String(), "recovery_codes") {
		t.Fatalf("operator TOTP enable = %d: %s", enable.Code, enable.Body.String())
	}

	secondEnable := httptest.NewRecorder()
	server.totpEnable(secondEnable, enableRequest, session)
	if secondEnable.Code != http.StatusBadRequest {
		t.Fatalf("reused pending TOTP setup = %d: %s", secondEnable.Code, secondEnable.Body.String())
	}
	disableRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/totp", strings.NewReader(`{"password":"replacement operator password"}`))
	disableRequest.Header.Set("Content-Type", "application/json")
	disable := httptest.NewRecorder()
	server.totpDisable(disable, disableRequest, session)
	if disable.Code != http.StatusNoContent {
		t.Fatalf("operator TOTP disable = %d: %s", disable.Code, disable.Body.String())
	}
}

func coverageTOTPCode(secret string, counter int64) string {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return ""
	}
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(counter))
	h := hmac.New(sha1.New, raw)
	_, _ = h.Write(message[:])
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1000000)
}
