package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestCookieHelpersLogoutAndPasswordRequirements(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
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
	raw, _, err := m.LoginAs(ctx, request, "admin", "correct horse battery staple", "", "")
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
	SetSessionCookie(cookieRecorder, "raw-token", false)
	setCookie := cookieRecorder.Result().Cookies()[0]
	if !setCookie.HttpOnly || setCookie.Secure || setCookie.SameSite != http.SameSiteStrictMode || setCookie.Path != "/" || setCookie.MaxAge != int(SessionTTL/time.Second) {
		t.Fatalf("session cookie = %#v", setCookie)
	}
	secureRecorder := httptest.NewRecorder()
	SetSessionCookie(secureRecorder, "secure-token", true)
	secureCookie := secureRecorder.Result().Cookies()[0]
	if !secureCookie.Secure || !secureCookie.HttpOnly || secureCookie.SameSite != http.SameSiteStrictMode || secureCookie.Path != "/" || secureCookie.MaxAge != int(SessionTTL/time.Second) {
		t.Fatalf("secure session cookie = %#v", secureCookie)
	}
	clearRecorder := httptest.NewRecorder()
	ClearSessionCookie(clearRecorder, false)
	clearCookie := clearRecorder.Result().Cookies()[0]
	if !clearCookie.HttpOnly || clearCookie.Secure || clearCookie.SameSite != http.SameSiteStrictMode || clearCookie.MaxAge != -1 || clearCookie.Value != "" {
		t.Fatalf("clear cookie = %#v", clearCookie)
	}
	secureClearRecorder := httptest.NewRecorder()
	ClearSessionCookie(secureClearRecorder, true)
	secureClearCookie := secureClearRecorder.Result().Cookies()[0]
	if !secureClearCookie.Secure || !secureClearCookie.HttpOnly || secureClearCookie.SameSite != http.SameSiteStrictMode || secureClearCookie.MaxAge != -1 || secureClearCookie.Value != "" {
		t.Fatalf("secure clear cookie = %#v", secureClearCookie)
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
	t.Parallel()
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
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
	admin, err := storetest.CreateUser(ctx, db, store.DefaultTenantScope(), store.User{Username: "admin", Role: store.RoleAdministrator, PasswordHash: "unused-hash", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.Tenant(store.DefaultTenantScope()).CreateUserWithInvite(ctx, store.User{Username: "invitee", DisplayName: "Invitee", Role: store.RoleViewer, PasswordHash: "!pending", Enabled: false}, hash, created, created.Add(time.Hour), store.AuditEntry{ActorUserID: admin.ID})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/activate", nil)
	request.RemoteAddr = "198.51.100.40:8000"
	if _, err := m.ActivateRequest(ctx, request, plain, "short"); err == nil {
		t.Fatal("short activation password was accepted")
	}
	activatedID, err := m.ActivateRequest(ctx, request, plain, "invitee account password")
	if err != nil {
		t.Fatal(err)
	}
	// The web handler uses the returned ID to close the account's streams.
	if activatedID != user.ID {
		t.Fatalf("activated user ID = %q, want %q", activatedID, user.ID)
	}
	if _, err := m.ActivateRequest(ctx, request, plain, "another account password"); err == nil {
		t.Fatal("activation invite was reusable")
	}
	activated, err := db.Tenant(store.DefaultTenantScope()).GetUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !activated.Enabled || activated.PasswordHash == "!pending" || strings.HasPrefix(activated.PasswordHash, "!") {
		t.Fatalf("activated account = %#v", activated)
	}
}

// tokenRequest returns an anonymous request from a client with its own
// address, as setup and activation get.
func tokenRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup", nil)
	r.RemoteAddr = "198.51.100.41:8000"
	return r
}

// Setup accepts its token between white space, as a copied log line often
// has, and redeems the token it checked: the token without the white
// space. It is redeemed once, and a wrong token still fails. The platform
// setup already normalizes its token once for both steps and still accepts
// it the same way.
func TestSetupRedeemsTheTokenItChecks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewManager(db)
	now := time.Now().UTC()
	m.Now = func() time.Time { return now }

	token, err := m.EnsureSetupToken(ctx)
	if err != nil || token == "" {
		t.Fatalf("setup token = %q, %v", token, err)
	}
	if err := m.SetupRequest(ctx, tokenRequest(), "not-the-setup-token", "administrator password"); err == nil {
		t.Fatal("setup with a wrong token succeeded")
	}
	if err := m.SetupRequest(ctx, tokenRequest(), " \t"+token+"\r\n", "administrator password"); err != nil {
		t.Fatalf("setup with the token between white space = %v", err)
	}
	if err := m.SetupRequest(ctx, tokenRequest(), token, "another administrator password"); err == nil {
		t.Fatal("the setup token was redeemed twice")
	}
	if raw, _, err := m.LoginAs(ctx, tokenRequest(), "admin", "administrator password", "", ""); err != nil || raw == "" {
		t.Fatalf("sign-in of the new administrator = %q, %v", raw, err)
	}

	// A platform setup token is issued at least a minute after the previous
	// setup token.
	now = now.Add(2 * time.Minute)
	platformToken, err := m.IssuePlatformSetupToken(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	root, err := m.PlatformSetupRequest(ctx, tokenRequest(), " "+platformToken+"\n", "root", "platform administrator password")
	if err != nil || root.Role != store.RolePlatformAdmin {
		t.Fatalf("platform setup with the token between white space = %+v, %v", root, err)
	}
}

// Activation accepts its token between white space, as a copied link often
// has, and redeems the token it checked: the token without the white
// space. It is redeemed once, and a wrong token still fails.
func TestActivationRedeemsTheTokenItChecks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewManager(db)
	unit := db.Tenant(store.DefaultTenantScope())
	admin, err := storetest.CreateUser(ctx, db, store.DefaultTenantScope(), store.User{Username: "admin", Role: store.RoleAdministrator, PasswordHash: "unused-hash", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	plain, hash, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().UTC()
	invitee, err := unit.CreateUserWithInvite(ctx, store.User{Username: "invitee", DisplayName: "Invitee", Role: store.RoleViewer, PasswordHash: "!pending", Enabled: false}, hash, created, created.Add(time.Hour), store.AuditEntry{ActorUserID: admin.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ActivateRequest(ctx, tokenRequest(), "not-the-activation-token", "invitee account password"); err == nil {
		t.Fatal("activation with a wrong token succeeded")
	}
	activatedID, err := m.ActivateRequest(ctx, tokenRequest(), "  "+plain+"\n", "invitee account password")
	if err != nil || activatedID != invitee.ID {
		t.Fatalf("activation with the token between white space = %q, %v; want %q", activatedID, err, invitee.ID)
	}
	if _, err := m.ActivateRequest(ctx, tokenRequest(), plain, "another account password"); err == nil {
		t.Fatal("the activation token was redeemed twice")
	}
	if raw, _, err := m.LoginAs(ctx, tokenRequest(), "invitee", "invitee account password", "", ""); err != nil || raw == "" {
		t.Fatalf("sign-in of the activated account = %q, %v", raw, err)
	}
}
