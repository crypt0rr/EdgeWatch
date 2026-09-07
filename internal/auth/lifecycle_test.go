package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestCookieHelpersLogoutAndPasswordRequirements(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewManager(db)
	token, err := m.EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(ctx, token, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "127.0.0.1:7000"
	raw, _, err := m.Login(ctx, request, "correct horse battery staple", "", "")
	if err != nil {
		t.Fatal(err)
	}
	session, err := db.GetSession(ctx, digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: raw})
	if err := m.LogoutSession(ctx, request, session); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetSession(ctx, digest(raw)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("logged-out session lookup = %v", err)
	}
	if err := m.Logout(ctx, httptest.NewRequest(http.MethodPost, "/", nil)); err != nil {
		t.Fatal(err)
	}

	cookieRecorder := httptest.NewRecorder()
	SetSessionCookie(cookieRecorder, "raw-token")
	setCookie := cookieRecorder.Result().Cookies()[0]
	if !setCookie.HttpOnly || setCookie.SameSite != http.SameSiteStrictMode || setCookie.Path != "/" || setCookie.MaxAge != int(SessionTTL/time.Second) {
		t.Fatalf("session cookie = %#v", setCookie)
	}
	clearRecorder := httptest.NewRecorder()
	ClearSessionCookie(clearRecorder)
	clearCookie := clearRecorder.Result().Cookies()[0]
	if !clearCookie.HttpOnly || clearCookie.SameSite != http.SameSiteStrictMode || clearCookie.MaxAge != -1 || clearCookie.Value != "" {
		t.Fatalf("clear cookie = %#v", clearCookie)
	}
	requirements := PasswordRequirements()
	if requirements["minimum_length"] != PasswordMin || requirements["algorithm"] != "argon2id" {
		t.Fatalf("password requirements = %#v", requirements)
	}
	if VerifyTOTPAt("not-base32", "123456", time.Now()) || VerifyTOTPAt("JBSWY3DPEHPK3PXP", "１２３４５６", time.Now()) || VerifyTOTPAt("JBSWY3DPEHPK3PXP", "12345", time.Now()) {
		t.Fatal("invalid TOTP input was accepted")
	}
}

func TestActivateRequestConsumesInviteOnceAndEnforcesPasswordLength(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewManager(db)
	plain, hash, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().UTC()
	user, err := db.CreateUserWithInvite(ctx, store.User{Username: "invitee", DisplayName: "Invitee", Role: store.RoleViewer, PasswordHash: "!pending", Enabled: false}, hash, created, created.Add(time.Hour), store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/activate", nil)
	request.RemoteAddr = "198.51.100.40:8000"
	if err := m.ActivateRequest(ctx, request, plain, "short"); err == nil {
		t.Fatal("short activation password was accepted")
	}
	if err := m.ActivateRequest(ctx, request, plain, "invitee account password"); err != nil {
		t.Fatal(err)
	}
	if err := m.ActivateRequest(ctx, request, plain, "another account password"); err == nil {
		t.Fatal("activation invite was reusable")
	}
	activated, err := db.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !activated.Enabled || activated.PasswordHash == "!pending" || strings.HasPrefix(activated.PasswordHash, "!") {
		t.Fatalf("activated account = %#v", activated)
	}
}
