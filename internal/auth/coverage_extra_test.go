package auth

import (
	"context"
	"fmt"
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
	if err := m.ActivateRequest(ctx, nil, "", "short"); err == nil {
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

func TestLoginLegacyFallbackAndAuthenticationFailureModes(t *testing.T) {
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
	// Remove only the migrated authoritative row to exercise the compatibility
	// lookup against the legacy admins table.
	if _, err := db.DB.ExecContext(ctx, "DELETE FROM users WHERE id=?", store.LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "203.0.113.20:9000"
	raw, user, err := m.LoginAs(ctx, request, " ADMIN ", "administrator password", "", "")
	if err != nil || raw == "" || user.ID != store.LegacyAdminUserID || user.Role != store.RoleAdministrator {
		t.Fatalf("legacy login = %q %#v, %v", raw, user, err)
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

	// Restore the migrated row so the session identity can be resolved.
	admin, err := db.GetAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	valid := httptest.NewRequest(http.MethodGet, "/", nil)
	valid.AddCookie(&http.Cookie{Name: SessionCookie, Value: raw})
	if _, ok := m.Authenticate(ctx, valid); !ok {
		t.Fatal("legacy session did not authenticate after migration row restore")
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
}

func TestLogoutSessionAndLimiterBookkeepingBranches(t *testing.T) {
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

	m.mu.Lock()
	m.blocked["blocked-only"] = time.Now().Add(time.Minute)
	m.fails["with-fails"] = []time.Time{time.Now()}
	if got := m.limiterEntryCountLocked(); got != 2 {
		t.Fatalf("limiter entry count = %d", got)
	}
	m.fails["empty"] = nil
	m.evictLimiterEntryLocked(time.Now())
	m.mu.Unlock()

	// The normal cap is intentionally large; directly fill the maps to exercise
	// the blocked-only eviction branch without making this test slow.
	m.mu.Lock()
	m.fails = map[string][]time.Time{}
	m.blocked = map[string]time.Time{}
	for i := 0; i < authLimiterMaxEntries; i++ {
		m.blocked[fmt.Sprintf("blocked-%d", i)] = time.Now().Add(time.Minute)
	}
	m.evictLimiterEntryLocked(time.Now())
	if m.limiterEntryCountLocked() != authLimiterMaxEntries-1 {
		t.Fatalf("blocked limiter eviction count = %d", m.limiterEntryCountLocked())
	}
	m.mu.Unlock()
}
