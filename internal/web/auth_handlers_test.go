package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestLogoutHandlerClearsCookieAndRevokesSession(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	now := time.Now().UTC()
	if err := db.CreateSessionForUserWithAudit(ctx, admin.UserID, digest("logout-session"), "csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "logout-session"})
	rec := httptest.NewRecorder()
	server.logout(rec, req, admin)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := db.GetSession(ctx, digest("logout-session")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session after logout = %v", err)
	}
	cleared := rec.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != auth.SessionCookie || cleared[0].MaxAge != -1 || !cleared[0].HttpOnly {
		t.Fatalf("logout cookie = %#v", cleared)
	}
}

func TestPasswordAndTOTPHandlersValidateCredentialsAndSessionCookie(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	invalid := httptest.NewRequest(http.MethodPut, "/api/v1/auth/password", strings.NewReader(`{"current_password":"wrong password","new_password":"new administrator password"}`))
	invalid.Header.Set("Content-Type", "application/json")
	invalidRecorder := httptest.NewRecorder()
	server.changePassword(invalidRecorder, invalid, admin)
	if invalidRecorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid password status = %d", invalidRecorder.Code)
	}
	short := httptest.NewRequest(http.MethodPut, "/api/v1/auth/password", strings.NewReader(`{"current_password":"administrator password","new_password":"short"}`))
	short.Header.Set("Content-Type", "application/json")
	shortRecorder := httptest.NewRecorder()
	server.changePassword(shortRecorder, short, admin)
	if shortRecorder.Code != http.StatusBadRequest {
		t.Fatalf("short password status = %d", shortRecorder.Code)
	}
	if err := db.CreateSessionForUserWithAudit(ctx, admin.UserID, "password-session", "csrf", time.Now().UTC(), time.Now().UTC().Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	change := httptest.NewRequest(http.MethodPut, "/api/v1/auth/password", strings.NewReader(`{"current_password":"administrator password","new_password":"new administrator password"}`))
	change.Header.Set("Content-Type", "application/json")
	changed := httptest.NewRecorder()
	server.changePassword(changed, change, admin)
	if changed.Code != http.StatusNoContent {
		t.Fatalf("password change status = %d: %s", changed.Code, changed.Body.String())
	}
	if _, err := db.GetSession(ctx, "password-session"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("password change left session active: %v", err)
	}
	updated, err := db.GetUser(ctx, admin.UserID)
	if err != nil || !auth.VerifyPassword(updated.PasswordHash, "new administrator password") {
		t.Fatalf("password was not updated: %#v, %v", updated, err)
	}

	missingCookie := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/setup", strings.NewReader(`{"password":"new administrator password"}`))
	missingCookie.Header.Set("Content-Type", "application/json")
	missingRecorder := httptest.NewRecorder()
	server.totpSetup(missingRecorder, missingCookie, admin)
	if missingRecorder.Code != http.StatusBadRequest {
		t.Fatalf("missing-cookie TOTP setup status = %d", missingRecorder.Code)
	}
	setup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/setup", strings.NewReader(`{"password":"new administrator password"}`))
	setup.Header.Set("Content-Type", "application/json")
	setup.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "totp-session"})
	setupRecorder := httptest.NewRecorder()
	server.totpSetup(setupRecorder, setup, admin)
	if setupRecorder.Code != http.StatusOK || !strings.Contains(setupRecorder.Body.String(), "otpauth://totp") {
		t.Fatalf("TOTP setup response = %d: %s", setupRecorder.Code, setupRecorder.Body.String())
	}
	missingEnable := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/enable", strings.NewReader(`{"code":"000000"}`))
	missingEnable.Header.Set("Content-Type", "application/json")
	missingEnableRecorder := httptest.NewRecorder()
	server.totpEnable(missingEnableRecorder, missingEnable, admin)
	if missingEnableRecorder.Code != http.StatusBadRequest {
		t.Fatalf("missing-cookie TOTP enable status = %d", missingEnableRecorder.Code)
	}
	invalidEnable := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/enable", strings.NewReader(`{"code":"000000"}`))
	invalidEnable.Header.Set("Content-Type", "application/json")
	invalidEnable.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "totp-session"})
	invalidEnableRecorder := httptest.NewRecorder()
	server.totpEnable(invalidEnableRecorder, invalidEnable, admin)
	if invalidEnableRecorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid TOTP code status = %d", invalidEnableRecorder.Code)
	}
	disable := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/totp", strings.NewReader(`{"password":"new administrator password"}`))
	disable.Header.Set("Content-Type", "application/json")
	disableRecorder := httptest.NewRecorder()
	server.totpDisable(disableRecorder, disable, admin)
	if disableRecorder.Code != http.StatusNoContent {
		t.Fatalf("TOTP disable status = %d: %s", disableRecorder.Code, disableRecorder.Body.String())
	}
}
