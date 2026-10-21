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
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/auth/login", nil)
	request.RemoteAddr = "127.0.0.1:7000"
	raw, _, err := m.LoginAs(ctx, request, "admin", "correct horse battery staple", "", "")
	if err != nil {
		t.Fatal(err)
	}
	session, err := db.GetSession(ctx, digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	addAuthTestSessionCookie(request, raw)
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
	if secureCookie.Name != SecureSessionCookie || !secureCookie.Secure || !secureCookie.HttpOnly || secureCookie.SameSite != http.SameSiteStrictMode || secureCookie.Path != "/" || secureCookie.Domain != "" || secureCookie.MaxAge != int(SessionTTL/time.Second) {
		t.Fatalf("secure session cookie = %#v", secureCookie)
	}
	clearRecorder := httptest.NewRecorder()
	ClearSessionCookie(clearRecorder, false)
	clearedCookies := clearRecorder.Result().Cookies()
	if len(clearedCookies) != 2 || clearedCookies[0].Name != SessionCookie || clearedCookies[0].Secure || clearedCookies[1].Name != SecureSessionCookie || !clearedCookies[1].Secure {
		t.Fatalf("clear cookies = %#v", clearedCookies)
	}
	for _, clearedCookie := range clearedCookies {
		if !clearedCookie.HttpOnly || clearedCookie.SameSite != http.SameSiteStrictMode || clearedCookie.Path != "/" || clearedCookie.Domain != "" || clearedCookie.MaxAge != -1 || clearedCookie.Value != "" {
			t.Fatalf("clear cookie = %#v", clearedCookie)
		}
	}
	secureClearRecorder := httptest.NewRecorder()
	ClearSessionCookie(secureClearRecorder, true)
	secureClearedCookies := secureClearRecorder.Result().Cookies()
	if len(secureClearedCookies) != 2 || secureClearedCookies[0].Name != SessionCookie || !secureClearedCookies[0].Secure || secureClearedCookies[1].Name != SecureSessionCookie || !secureClearedCookies[1].Secure {
		t.Fatalf("secure clear cookies = %#v", secureClearedCookies)
	}
	for _, clearedCookie := range secureClearedCookies {
		if !clearedCookie.HttpOnly || clearedCookie.SameSite != http.SameSiteStrictMode || clearedCookie.Path != "/" || clearedCookie.Domain != "" || clearedCookie.MaxAge != -1 || clearedCookie.Value != "" {
			t.Fatalf("secure clear cookie = %#v", clearedCookie)
		}
	}
	requirements := PasswordRequirements()
	if requirements["minimum_length"] != PasswordMin || requirements["algorithm"] != "argon2id" {
		t.Fatalf("password requirements = %#v", requirements)
	}
	if VerifyTOTPAt("not-base32", "123456", time.Now()) || VerifyTOTPAt("JBSWY3DPEHPK3PXP", "１２３４５６", time.Now()) || VerifyTOTPAt("JBSWY3DPEHPK3PXP", "12345", time.Now()) {
		t.Fatal("invalid TOTP input was accepted")
	}
}

func TestSessionCookieFromRequestRejectsDuplicatesAndWrongTransportName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		url       string
		cookie    string
		secure    bool
		want      bool
		wantValue string
	}{
		{name: "loopback plain cookie", url: "http://127.0.0.1/", cookie: SessionCookie + "=local", want: true, wantValue: "local"},
		{name: "secure prefixed cookie", url: "https://console.example.test/", cookie: SecureSessionCookie + "=secure", secure: true, want: true, wantValue: "secure"},
		{name: "duplicate plain cookies", url: "http://127.0.0.1/", cookie: SessionCookie + "=attacker; " + SessionCookie + "=victim", want: false},
		{name: "duplicate secure cookies", url: "https://console.example.test/", cookie: SecureSessionCookie + "=attacker; " + SecureSessionCookie + "=victim", secure: true, want: false},
		{name: "secure cookie alongside ignored legacy name", url: "https://console.example.test/", cookie: SessionCookie + "=legacy; " + SecureSessionCookie + "=new", secure: true, want: true, wantValue: "new"},
		{name: "loopback cookie alongside ignored secure name", url: "http://127.0.0.1/", cookie: SecureSessionCookie + "=stale; " + SessionCookie + "=local", want: true, wantValue: "local"},
		{name: "plain cookie on secure request", url: "https://console.example.test/", cookie: SessionCookie + "=old", secure: true, want: false},
		{name: "prefixed cookie on loopback http", url: "http://127.0.0.1/", cookie: SecureSessionCookie + "=secure", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.url, nil)
			request.Header.Set("Cookie", test.cookie)
			cookie, ok := SessionCookieFromRequest(request, test.secure)
			if ok != test.want {
				t.Fatalf("SessionCookieFromRequest() = (%#v, %t), want valid=%t", cookie, ok, test.want)
			}
			if ok && cookie.Value != test.wantValue {
				t.Fatalf("session cookie value = %q, want %q", cookie.Value, test.wantValue)
			}
		})
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
