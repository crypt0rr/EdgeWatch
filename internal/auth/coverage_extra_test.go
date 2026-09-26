package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestAuthValidationBranchesAndSetupRequest(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m := NewManager(db)
	m.Now = nil
	if m.now().IsZero() {
		t.Fatal("nil clock did not fall back to current time")
	}
	if err := m.Setup(ctx, "", "administrator password"); err == nil || !strings.Contains(err.Error(), "setup token") {
		t.Fatalf("empty setup token error = %v", err)
	}
	if err := m.Setup(ctx, "token", "short"); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("short setup password error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/setup", nil)
	request.RemoteAddr = "198.51.100.10:8080"
	token, err := m.EnsureSetupToken(ctx)
	if err != nil || token == "" {
		t.Fatalf("setup token = %q, %v", token, err)
	}
	if err := m.SetupRequest(ctx, request, token, "administrator password"); err != nil {
		t.Fatalf("setup request failed: %v", err)
	}
	if got, err := m.EnsureSetupToken(ctx); err != nil || got != "" {
		t.Fatalf("configured setup token = %q, %v", got, err)
	}
	if _, err := m.ReissueSetupToken(ctx); err == nil || !strings.Contains(err.Error(), "already configured") {
		t.Fatalf("configured reissue error = %v", err)
	}

	// A consumed token cannot be used by the request wrapper and contributes
	// to the source's failure budget just like an invalid password.
	if err := m.SetupRequest(ctx, request, token, "another administrator password"); err == nil {
		t.Fatal("consumed setup token was accepted")
	}
	if _, err := m.ActivateRequest(ctx, nil, "", "short"); err == nil {
		t.Fatal("short activation password was accepted")
	}
}

func TestEnsureSetupTokenReusesAndReplacesExpiredTokens(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	m := NewManager(db)
	m.Now = func() time.Time { return now }
	first, err := m.EnsureSetupToken(ctx)
	if err != nil || first == "" {
		t.Fatalf("first token = %q, %v", first, err)
	}
	if second, err := m.EnsureSetupToken(ctx); err != nil || second != "" {
		t.Fatalf("existing token was reissued: %q, %v", second, err)
	}
	if err := db.PutSetupTokenAt(ctx, digest("expired"), now.Add(-time.Minute), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	replacement, err := m.EnsureSetupToken(ctx)
	if err != nil || replacement == "" || replacement == first {
		t.Fatalf("expired token replacement = %q, %v", replacement, err)
	}
}

func TestVerifyPasswordRejectsMalformedEncodings(t *testing.T) {
	cases := []string{
		"",
		"not-an-edgewatch-hash",
		"$bad$argon2id$v=19$m=19456,t=2,p=1$YWJj$YWJj",
		"$ew$argon2id$v=18$m=19456,t=2,p=1$YWJj$YWJj",
		"$ew$argon2id$v=19$not-params$YWJj$YWJj",
		"$ew$argon2id$v=19$m=1,t=2,p=1$YWJj$YWJj",
		"$ew$argon2id$v=19$m=19456,t=0,p=1$YWJj$YWJj",
		"$ew$argon2id$v=19$m=19456,t=11,p=1$YWJj$YWJj",
		"$ew$argon2id$v=19$m=19456,t=2,p=0$YWJj$YWJj",
		"$ew$argon2id$v=19$m=19456,t=2,p=33$YWJj$YWJj",
		"$ew$argon2id$v=19$m=19456,t=2,p=1$%%%$YWJj",
		"$ew$argon2id$v=19$m=19456,t=2,p=1$YWJj$%%%",
		"$ew$argon2id$v=19$m=19456,t=2,p=1$YWJj$",
	}
	for _, encoded := range cases {
		if VerifyPassword(encoded, "administrator password") {
			t.Fatalf("malformed password hash was accepted: %q", encoded)
		}
	}
}

// replaceAdministratorWithAdminsRow deletes the original administrator's
// users row and writes its credentials to the admins row that schema 52
// retired, as a database changed by hand could hold them.
func replaceAdministratorWithAdminsRow(t *testing.T, db *store.Store) {
	t.Helper()
	ctx := context.Background()
	for _, statement := range []string{
		`INSERT INTO admins(id,username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at) SELECT 1,username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at FROM users WHERE id=?`,
		`DELETE FROM users WHERE id=?`,
	} {
		if _, err := db.DB.ExecContext(ctx, statement, store.LegacyAdminUserID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoginAfterAdminsRetirementAndAuthenticationFailureModes(t *testing.T) {
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
	if token == "" {
		t.Fatal("a fresh install did not issue a setup token")
	}
	if err := m.Setup(ctx, token, "administrator password"); err != nil {
		t.Fatal(err)
	}
	// The first setup creates the administrator in users only, in the
	// default tenant, and login uses that row.
	var legacyRows int
	var tenant string
	if err := db.DB.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM admins),(SELECT tenant_id FROM users WHERE id=?)`, store.LegacyAdminUserID).Scan(&legacyRows, &tenant); err != nil || legacyRows != 0 || tenant != store.DefaultTenantID {
		t.Fatalf("after setup: admins rows = %d, administrator tenant = %q, %v", legacyRows, tenant, err)
	}
	if again, err := m.EnsureSetupToken(ctx); err != nil || again != "" {
		t.Fatalf("setup token after setup = %q, %v", again, err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "203.0.113.20:9000"
	raw, user, err := m.LoginAs(ctx, request, " ADMIN ", "administrator password", "", "")
	if err != nil || raw == "" || user.ID != store.LegacyAdminUserID || user.Role != store.RoleAdministrator {
		t.Fatalf("administrator login = %q %#v, %v", raw, user, err)
	}

	if _, ok := m.Authenticate(ctx, httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Fatal("missing authentication cookie was accepted")
	}
	emptyCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	emptyCookie.AddCookie(&http.Cookie{Name: SessionCookie, Value: ""})
	if _, ok := m.Authenticate(ctx, emptyCookie); ok {
		t.Fatal("empty authentication cookie was accepted")
	}
	unknownCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	unknownCookie.AddCookie(&http.Cookie{Name: SessionCookie, Value: "unknown"})
	if _, ok := m.Authenticate(ctx, unknownCookie); ok {
		t.Fatal("unknown authentication cookie was accepted")
	}

	valid := httptest.NewRequest(http.MethodGet, "/", nil)
	valid.AddCookie(&http.Cookie{Name: SessionCookie, Value: raw})
	if _, ok := m.Authenticate(ctx, valid); !ok {
		t.Fatal("administrator session did not authenticate")
	}

	now := time.Now().UTC()
	if err := db.CreateSessionForUserWithAudit(ctx, store.LegacyAdminUserID, digest("expired-auth"), "csrf", now.Add(-2*time.Hour), now.Add(-time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	expired := httptest.NewRequest(http.MethodGet, "/", nil)
	expired.AddCookie(&http.Cookie{Name: SessionCookie, Value: "expired-auth"})
	m.Now = func() time.Time { return now }
	if _, ok := m.Authenticate(ctx, expired); ok {
		t.Fatal("expired session was accepted")
	}
	if err := db.CreateSessionForUserWithAudit(ctx, store.LegacyAdminUserID, digest("idle-auth"), "csrf", now.Add(-26*time.Hour), now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	idle := httptest.NewRequest(http.MethodGet, "/", nil)
	idle.AddCookie(&http.Cookie{Name: SessionCookie, Value: "idle-auth"})
	if _, ok := m.Authenticate(ctx, idle); ok {
		t.Fatal("idle session was accepted")
	}

	// Without its users row the administrator cannot sign in, even when an
	// admins row still holds the same credentials: that row has no tenant.
	replaceAdministratorWithAdminsRow(t, db)
	m.Now = time.Now
	fallback := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	fallback.RemoteAddr = "203.0.113.21:9000"
	if raw, user, err := m.LoginAs(ctx, fallback, "admin", "administrator password", "", ""); err == nil || raw != "" || user.ID != "" {
		t.Fatalf("login from the admins row = %q %#v, %v; want invalid credentials", raw, user, err)
	}
	if _, ok := m.Authenticate(ctx, valid); ok {
		t.Fatal("session of the removed administrator was accepted")
	}
}

// Password and TOTP confirmation use the users row only. A missing users row
// fails even for the original administrator's ID, whatever the admins row
// holds.
func TestConfirmationRequiresTheUsersRow(t *testing.T) {
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
	if err := m.Setup(ctx, token, "administrator password"); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations", nil)
	request.RemoteAddr = "198.51.100.240:8080"
	if err := m.ConfirmPasswordForUser(ctx, request, store.LegacyAdminUserID, "administrator password"); err != nil {
		t.Fatalf("administrator confirmation failed: %v", err)
	}
	replaceAdministratorWithAdminsRow(t, db)
	if err := m.ConfirmPasswordForUser(ctx, request, store.LegacyAdminUserID, "administrator password"); err == nil {
		t.Fatal("password confirmation from the admins row was accepted")
	}
	if err := m.ConfirmTOTPForUser(ctx, request, store.LegacyAdminUserID, "000000", "RECOVERY"); err == nil {
		t.Fatal("TOTP confirmation from the admins row was accepted")
	}
	if err := m.ConfirmPasswordForUser(ctx, request, "missing-user", "administrator password"); err == nil {
		t.Fatal("missing arbitrary user was accepted")
	}
}

func TestLogoutSessionEmptyCookieNoop(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewManager(db)
	if err := m.LogoutSession(ctx, httptest.NewRequest(http.MethodPost, "/", nil), store.Session{}); err != nil {
		t.Fatal(err)
	}
	empty := httptest.NewRequest(http.MethodPost, "/", nil)
	empty.AddCookie(&http.Cookie{Name: SessionCookie, Value: ""})
	if err := m.LogoutSession(ctx, empty, store.Session{}); err != nil {
		t.Fatal(err)
	}
}
