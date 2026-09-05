package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestPasswordHashAndVerification(t *testing.T) {
	hash, err := PasswordHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("password did not verify")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Fatal("wrong password verified")
	}
	if _, err := PasswordHash("too-short"); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestSetupTokenIsSingleUse(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := NewManager(s)
	token, err := m.EnsureSetupToken(context.Background())
	if err != nil || token == "" {
		t.Fatalf("token %q: %v", token, err)
	}
	if err := m.Setup(context.Background(), token, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(context.Background(), token, "another correct password"); err == nil {
		t.Fatal("setup token reused")
	}
}

func TestReissueSetupTokenReplacesPreviousTokenAndIsRateLimited(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	m := NewManager(s)
	m.Now = func() time.Time { return now }
	first, err := m.EnsureSetupToken(context.Background())
	if err != nil || first == "" {
		t.Fatalf("initial token %q: %v", first, err)
	}
	if _, err := m.ReissueSetupToken(context.Background()); !errors.Is(err, store.ErrSetupTokenRateLimited) {
		t.Fatalf("immediate reissue error = %v", err)
	}
	now = now.Add(time.Minute + time.Second)
	second, err := m.ReissueSetupToken(context.Background())
	if err != nil || second == "" || second == first {
		t.Fatalf("replacement token %q: %v", second, err)
	}
	if err := m.Setup(context.Background(), first, "correct horse battery staple"); err == nil {
		t.Fatal("replaced token was accepted")
	}
	if err := m.Setup(context.Background(), second, "correct horse battery staple"); err != nil {
		t.Fatalf("replacement token setup failed: %v", err)
	}
	if _, err := m.ReissueSetupToken(context.Background()); err == nil || !strings.Contains(err.Error(), "already configured") {
		t.Fatalf("post-setup reissue error = %v", err)
	}
}

func TestSessionAuthenticationAndCSRF(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := NewManager(s)
	token, _ := m.EnsureSetupToken(context.Background())
	if err := m.Setup(context.Background(), token, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	raw, _, err := m.Login(context.Background(), r, "correct horse battery staple", "", "")
	if err != nil {
		t.Fatal(err)
	}
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: raw})
	session, ok := m.Authenticate(context.Background(), r)
	if !ok || session.CSRFToken == "" {
		t.Fatal("session did not authenticate")
	}
	if m.CheckCSRF(r, session) {
		t.Fatal("empty CSRF token accepted")
	}
	r.Header.Set("X-CSRF-Token", session.CSRFToken)
	if !m.CheckCSRF(r, session) {
		t.Fatal("valid CSRF token rejected")
	}
}

func TestConfirmPasswordUsesGenericErrorsAndRateLimit(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := NewManager(s)
	ctx := context.Background()
	token, err := m.EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(ctx, token, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/notifications/destinations", nil)
	request.RemoteAddr = "127.0.0.1:9876"
	if err := m.ConfirmPassword(ctx, request, "wrong password"); err == nil || strings.Contains(err.Error(), "admin") {
		t.Fatalf("unexpected wrong-password error: %v", err)
	}
	if err := m.ConfirmPassword(ctx, request, "correct horse battery staple"); err != nil {
		t.Fatalf("correct password rejected: %v", err)
	}
	for i := 0; i < 5; i++ {
		_ = m.ConfirmPassword(ctx, request, "wrong password")
	}
	if err := m.ConfirmPassword(ctx, request, "correct horse battery staple"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("rate-limit error = %v", err)
	}
}

func TestAuthLimiterBoundsRotatingSourcesAndExpiresEntries(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := NewManager(s)
	now := time.Unix(1_700_000_000, 0).UTC()
	m.Now = func() time.Time { return now }
	for i := 0; i < authLimiterMaxEntries+500; i++ {
		m.failed(fmt.Sprintf("rotating-source-%d", i))
	}
	m.mu.Lock()
	count := m.limiterEntryCountLocked()
	m.mu.Unlock()
	if count > authLimiterMaxEntries {
		t.Fatalf("limiter grew beyond cap: %d", count)
	}

	now = now.Add(authFailureWindow + time.Second)
	if !m.allow("rotating-source-0") {
		t.Fatal("expired limiter entry remained blocked")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if got := m.limiterEntryCountLocked(); got != 0 {
		t.Fatalf("expired limiter entries were not swept: %d", got)
	}
}

func TestSessionLifetimeRemainsAbsoluteWhenTouched(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := NewManager(s)
	now := time.Unix(1_700_000_000, 0).UTC()
	m.Now = func() time.Time { return now }
	token, err := m.EnsureSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(context.Background(), token, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	raw, _, err := m.Login(context.Background(), request, "correct horse battery staple", "", "")
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: raw})
	original, err := s.GetSession(context.Background(), digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(23 * time.Hour)
	if _, ok := m.Authenticate(context.Background(), request); !ok {
		t.Fatal("session should still be valid before idle expiry")
	}
	refreshed, err := s.GetSession(context.Background(), digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !refreshed.ExpiresAt.Equal(original.ExpiresAt) {
		t.Fatalf("session expiry moved from %s to %s", original.ExpiresAt, refreshed.ExpiresAt)
	}
	now = original.ExpiresAt.Add(-30 * time.Minute)
	if err := s.TouchSession(context.Background(), digest(raw), now, original.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	now = original.ExpiresAt.Add(time.Minute)
	if _, ok := m.Authenticate(context.Background(), request); ok {
		t.Fatal("session exceeded absolute lifetime")
	}
}

func TestTOTPCodeWindow(t *testing.T) {
	// RFC 6238 test secret; the implementation accepts the current 30-second
	// window, so exercise the generated secret path without depending on time.
	secret, err := NewTOTPSecret()
	if err != nil || secret == "" {
		t.Fatal(err)
	}
	if VerifyTOTP(secret, "000000") {
		t.Fatal("invalid TOTP code accepted")
	}
}

func TestTOTPUsesInjectedTime(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	at := time.Unix(59, 0).UTC()
	code := totpCode(secret, at.Unix()/30)
	if !VerifyTOTPAt(secret, code, at) {
		t.Fatalf("valid code rejected at %s", at)
	}
}

func TestRecoveryCodeIsCaseInsensitiveAndSingleUse(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := NewManager(s)
	ctx := context.Background()
	token, err := m.EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(ctx, token, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	admin, err := s.GetAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	admin.TOTPEnabled = true
	admin.TOTPSecret = "JBSWY3DPEHPK3PXP"
	if err := s.SaveAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	plain, hashes, err := RecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRecoveryCodes(ctx, hashes); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	if _, _, err := m.Login(ctx, request, "correct horse battery staple", "", strings.ToLower(plain[0])); err != nil {
		t.Fatalf("lowercase recovery code rejected: %v", err)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	if _, _, err := m.Login(ctx, request, "correct horse battery staple", "", plain[0]); err == nil {
		t.Fatal("recovery code was reusable")
	}
}
