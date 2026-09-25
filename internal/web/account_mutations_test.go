package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestCreateUserRejectsUsernamesTheStoreRejectsAsFieldErrors(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	create := func(username string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]string{"username": username, "display_name": "Alice", "role": store.RoleViewer, "password": "administrator password"})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		server.usersRoute(recorder, request, admin, "")
		return recorder
	}
	before, err := db.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for name, username := range map[string]string{
		"backslash":          `corp\alice`,
		"colon":              "ops:alice",
		"slash":              "a/b",
		"control character":  "alice\u0007",
		"tab":                "ali\tce",
		"81 ASCII bytes":     strings.Repeat("a", 81),
		"82 bytes, 41 chars": strings.Repeat("é", 41),
	} {
		recorder := create(username)
		body := decodeAPIError(t, recorder)
		if recorder.Code != http.StatusBadRequest || body.Error.Code != "validation_failed" || body.Error.Details["username"] == "" {
			t.Fatalf("%s username = %d %#v, want 400 with details.username", name, recorder.Code, body.Error)
		}
	}
	after, err := db.ListUsers(ctx)
	if err != nil || len(after) != len(before) {
		t.Fatalf("rejected usernames created accounts: before=%d after=%d (%v)", len(before), len(after), err)
	}
	for _, username := range []string{"alice", strings.Repeat("é", 40)} {
		if recorder := create(username); recorder.Code != http.StatusCreated {
			t.Fatalf("valid username %q = %d: %s", username, recorder.Code, recorder.Body.String())
		}
	}
}

func TestPasswordResetActivationClosesTheAccountsStreams(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	hash, err := auth.PasswordHash("operator account password")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := db.CreateUser(ctx, store.User{Username: "streaming-operator", DisplayName: "Streaming operator", Role: store.RoleOperator, PasswordHash: hash, Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := server.Auth.LoginAs(ctx, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil), "streaming-operator", "operator account password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	authRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	authRequest.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
	session, ok := server.Auth.AuthenticateReadOnly(ctx, authRequest)
	if !ok || session.UserID != operator.ID {
		t.Fatalf("operator session = %#v, ok=%v", session, ok)
	}
	adminRaw, adminSession := loginSSETestSession(t, server)
	writer, cancel, done := startCookieSSEStream(server, raw, session)
	defer cancel()
	adminWriter, adminCancel, adminDone := startCookieSSEStream(server, adminRaw, adminSession)
	defer adminCancel()
	waitForSSESubscribers(t, server, 2)
	waitForSSECacheEntries(t, server, 2)

	resetRequest := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+operator.ID+"/password-reset", strings.NewReader(`{"password":"administrator password"}`))
	resetRequest.Header.Set("Content-Type", "application/json")
	reset := httptest.NewRecorder()
	server.usersRoute(reset, resetRequest, admin, operator.ID+"/password-reset")
	if reset.Code != http.StatusOK {
		t.Fatalf("password reset issue = %d: %s", reset.Code, reset.Body.String())
	}
	var issued struct {
		Token string `json:"activation_token"`
	}
	if err := json.Unmarshal(reset.Body.Bytes(), &issued); err != nil || issued.Token == "" {
		t.Fatalf("password reset response = %s (%v)", reset.Body.String(), err)
	}
	activateRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/activate", strings.NewReader(`{"token":"`+issued.Token+`","password":"new operator password"}`))
	activateRequest.Header.Set("Content-Type", "application/json")
	activateRequest.RemoteAddr = "127.0.0.1:9010"
	activated := httptest.NewRecorder()
	server.activateUser(activated, activateRequest)
	if activated.Code != http.StatusOK {
		t.Fatalf("password reset activation = %d: %s", activated.Code, activated.Body.String())
	}

	// An event broadcast right after the reset must not reach the stream
	// that the old session opened, and the stream must release its slot.
	server.broadcast(map[string]any{"type": "test", "token": "after-password-reset"})
	waitForSSEStreamClose(t, done, "password-reset")
	writer.mu.Lock()
	leaked := strings.Contains(writer.body.String(), "after-password-reset")
	writer.mu.Unlock()
	if leaked {
		t.Fatal("event broadcast after the password reset reached the revoked stream")
	}
	waitForSSESubscribers(t, server, 1)
	waitForSSECacheEntries(t, server, 1)
	// Other accounts' streams are unaffected.
	assertSSEStreamStillOpen(t, adminDone, "administrator")
	waitForSSEBody(t, adminWriter, "after-password-reset")
}

func TestFirstActivationOfAnInviteeStillSucceeds(t *testing.T) {
	server, _, admin := newUsersTestServer(t)
	adminRaw, adminSession := loginSSETestSession(t, server)
	_, adminCancel, adminDone := startCookieSSEStream(server, adminRaw, adminSession)
	defer adminCancel()
	waitForSSESubscribers(t, server, 1)
	createRequest := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"invitee","display_name":"Invitee","role":"viewer","password":"administrator password"}`))
	createRequest.Header.Set("Content-Type", "application/json")
	created := httptest.NewRecorder()
	server.usersRoute(created, createRequest, admin, "")
	if created.Code != http.StatusCreated {
		t.Fatalf("invite = %d: %s", created.Code, created.Body.String())
	}
	var invite struct {
		Token string `json:"activation_token"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &invite); err != nil || invite.Token == "" {
		t.Fatalf("invite response = %s (%v)", created.Body.String(), err)
	}
	activateRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/activate", strings.NewReader(`{"token":"`+invite.Token+`","password":"invitee account password"}`))
	activateRequest.Header.Set("Content-Type", "application/json")
	activated := httptest.NewRecorder()
	server.activateUser(activated, activateRequest)
	if activated.Code != http.StatusOK {
		t.Fatalf("first activation = %d: %s", activated.Code, activated.Body.String())
	}
	assertSSEStreamStillOpen(t, adminDone, "administrator")
	waitForSSESubscribers(t, server, 1)
}

func countAuditRows(t *testing.T, db *store.Store, action, actorUserID string) int {
	t.Helper()
	var count int
	if err := db.DB.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM security_audit WHERE action=? AND actor_user_id=?`, action, actorUserID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestDisplayNameChangesAreAuditedForEveryAccount(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	selfRename := func(session store.Session, name string) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPut, "/api/v1/auth/display-name", strings.NewReader(`{"display_name":"`+name+`"}`))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		server.changeDisplayName(recorder, request, session)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s self rename = %d: %s", session.Role, recorder.Code, recorder.Body.String())
		}
	}
	adminPatch := func(id, body string) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPatch, "/api/v1/users/"+id, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		server.usersRoute(recorder, request, admin, id)
		if recorder.Code != http.StatusOK {
			t.Fatalf("administrator PATCH = %d: %s", recorder.Code, recorder.Body.String())
		}
	}

	for _, role := range []string{store.RoleOperator, store.RoleViewer} {
		user, err := db.CreateUser(ctx, store.User{Username: "rename-" + role, DisplayName: "Before", Role: role, PasswordHash: "unused-hash", Enabled: true}, store.AuditEntry{})
		if err != nil {
			t.Fatal(err)
		}
		session := store.Session{UserID: user.ID, Username: user.Username, Role: role}

		selfRename(session, "Administrator")
		if got := countAuditRows(t, db, "user.display_name_changed", user.ID); got != 1 {
			t.Fatalf("%s self rename audit rows = %d, want 1", role, got)
		}
		// Saving the current name again changes nothing and is not audited.
		selfRename(session, "Administrator")
		if got := countAuditRows(t, db, "user.display_name_changed", user.ID); got != 1 {
			t.Fatalf("%s no-op self rename audit rows = %d, want 1", role, got)
		}

		adminPatch(user.ID, `{"display_name":"Renamed by admin"}`)
		if got := countAuditRows(t, db, "user.updated", admin.UserID); got != 1 {
			t.Fatalf("administrator rename of %s audit rows = %d, want 1", role, got)
		}
		adminPatch(user.ID, `{"display_name":"Renamed by admin"}`)
		if got := countAuditRows(t, db, "user.updated", admin.UserID); got != 1 {
			t.Fatalf("no-op administrator PATCH of %s audit rows = %d, want 1", role, got)
		}
		stored, err := db.GetUser(ctx, user.ID)
		if err != nil || stored.DisplayName != "Renamed by admin" {
			t.Fatalf("stored display name = %q (%v)", stored.DisplayName, err)
		}
		if _, err := db.DB.ExecContext(ctx, `DELETE FROM security_audit WHERE actor_user_id=?`, admin.UserID); err != nil {
			t.Fatal(err)
		}
	}
}
