// Package auth implements the deliberately small, single-administrator
// authentication surface used by the local EdgeWatch console.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/crypt0rr/edgewatch/internal/store"
	"golang.org/x/crypto/argon2"
)

const (
	SessionCookie = "edgewatch_session"
	PasswordMin   = 12
	SessionTTL    = 30 * 24 * time.Hour
	IdleTTL       = 24 * time.Hour

	authFailureWindow    = 5 * time.Minute
	authFailureThreshold = 5
	authBlockDuration    = 5 * time.Minute
	// The limiter is process-local by design, but it must remain bounded when
	// an attacker rotates source addresses. Keys are evicted oldest-first once
	// this ceiling is reached; expired entries are swept on every decision.
	authLimiterMaxEntries = 4096
)

var ErrRateLimited = errors.New("too many authentication attempts; try again later")

type Manager struct {
	Store *store.Store
	Now   func() time.Time

	mu      sync.Mutex
	fails   map[string][]time.Time
	blocked map[string]time.Time
}

func NewManager(s *store.Store) *Manager {
	return &Manager{Store: s, Now: time.Now, fails: map[string][]time.Time{}, blocked: map[string]time.Time{}}
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func digest(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

func (m *Manager) EnsureSetupToken(ctx context.Context) (string, error) {
	if _, err := m.Store.GetAdmin(ctx); err == nil {
		return "", nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	if token, err := m.Store.GetSetupToken(ctx); err == nil && !token.Used && m.now().Before(token.ExpiresAt) {
		// The clear token is intentionally only emitted when generated. It is
		// never persisted or returned by the API.
		return "", nil
	}
	raw, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	plain := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	now := m.now()
	if err := m.Store.PutSetupTokenAt(ctx, digest(plain), now.Add(15*time.Minute), now); err != nil {
		return "", err
	}
	return plain, nil
}

// ReissueSetupToken creates a fresh setup token for a clean installation. The
// store performs the administrator-exists check, persists the issue time for a
// cross-process rate limit, and records an opaque audit event.
func (m *Manager) ReissueSetupToken(ctx context.Context) (string, error) {
	if _, err := m.Store.GetAdmin(ctx); err == nil {
		return "", errors.New("administrator is already configured")
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	raw, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	plain := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	now := m.now()
	if err := m.Store.ReissueSetupToken(ctx, digest(plain), now.Add(15*time.Minute), now); err != nil {
		return "", err
	}
	return plain, nil
}

func PasswordHash(password string) (string, error) {
	if utf8.RuneCountInString(password) < PasswordMin {
		return "", fmt.Errorf("password must be at least %d characters", PasswordMin)
	}
	salt, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	const memory, iterations, threads, keyLen = 19 * 1024, 2, 1, 32
	key := argon2.IDKey([]byte(password), salt, iterations, memory, threads, keyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$ew$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, iterations, threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 7 || parts[1] != "ew" || parts[2] != "argon2id" || parts[3] != "v=19" {
		return false
	}
	var memory, iterations, threads uint32
	if _, err := fmt.Sscanf(parts[4], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil || memory < 8*threads || memory > 1024*1024 || iterations == 0 || iterations > 10 || threads == 0 || threads > 32 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[5])
	expected, err2 := base64.RawStdEncoding.DecodeString(parts[6])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(expected) == 0 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, uint8(threads), uint32(len(expected)))
	return hmac.Equal(actual, expected)
}

func (m *Manager) Setup(ctx context.Context, token, password string) error {
	if token == "" {
		return errors.New("setup token is required")
	}
	hash, err := PasswordHash(password)
	if err != nil {
		return err
	}
	now := m.now()
	return m.Store.CompleteSetup(ctx, digest(token), store.Admin{Username: "admin", PasswordHash: hash, CreatedAt: now, UpdatedAt: now}, now)
}

// SetupRequest applies the same short-lived per-client failure budget as
// login. The non-HTTP Setup method remains available to trusted callers and
// tests, while the web endpoint should use this wrapper.
func (m *Manager) SetupRequest(ctx context.Context, request *http.Request, token, password string) error {
	if !m.allow(request.RemoteAddr) {
		return errors.New("too many setup attempts; try again later")
	}
	if err := m.Setup(ctx, token, password); err != nil {
		m.failed(request.RemoteAddr)
		return err
	}
	m.clear(request.RemoteAddr)
	return nil
}

func (m *Manager) Login(ctx context.Context, request *http.Request, password, otp, recovery string) (string, store.Admin, error) {
	if !m.allow(request.RemoteAddr) {
		return "", store.Admin{}, errors.New("too many login attempts; try again later")
	}
	admin, err := m.Store.GetAdmin(ctx)
	if err != nil {
		return "", admin, errors.New("administrator is not configured")
	}
	if !VerifyPassword(admin.PasswordHash, password) {
		m.failed(request.RemoteAddr)
		return "", admin, errors.New("invalid credentials")
	}
	if admin.TOTPEnabled {
		valid := admin.TOTPSecretError == nil && VerifyTOTPAt(admin.TOTPSecret, otp, m.now())
		if !valid && recovery != "" {
			valid, err = m.Store.ConsumeRecoveryCode(ctx, digest(strings.ToUpper(strings.TrimSpace(recovery))), m.now())
		}
		if !valid {
			m.failed(request.RemoteAddr)
			return "", admin, errors.New("one-time code is required")
		}
	}
	sessionRaw, err := randomBytes(32)
	if err != nil {
		return "", admin, err
	}
	csrfRaw, err := randomBytes(32)
	if err != nil {
		return "", admin, err
	}
	session := base64.RawURLEncoding.EncodeToString(sessionRaw)
	csrf := base64.RawURLEncoding.EncodeToString(csrfRaw)
	now := m.now()
	if err := m.Store.CreateSessionWithAudit(ctx, digest(session), csrf, now, now.Add(SessionTTL), "admin.login", "successful login"); err != nil {
		return "", admin, err
	}
	m.clear(request.RemoteAddr)
	return session, admin, nil
}

// ConfirmPassword applies the same per-client failure budget as login to
// sensitive, already-authenticated operations such as managing notification
// credentials. It intentionally returns only generic errors so callers cannot
// distinguish a missing administrator from a wrong password.
func (m *Manager) ConfirmPassword(ctx context.Context, request *http.Request, password string) error {
	if !m.allow(request.RemoteAddr) {
		return ErrRateLimited
	}
	admin, err := m.Store.GetAdmin(ctx)
	if err != nil || !VerifyPassword(admin.PasswordHash, password) {
		m.failed(request.RemoteAddr)
		return errors.New("password confirmation failed")
	}
	m.clear(request.RemoteAddr)
	return nil
}

func (m *Manager) allow(remote string) bool {
	key := limiterKey(remote)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.sweepLimiterLocked(now)
	if until, ok := m.blocked[key]; ok && now.Before(until) {
		return false
	}
	return true
}

func (m *Manager) failed(remote string) {
	key := limiterKey(remote)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.sweepLimiterLocked(now)
	if _, exists := m.fails[key]; !exists {
		if _, exists := m.blocked[key]; !exists {
			m.evictLimiterEntryLocked(now)
		}
	}
	values := m.fails[key]
	cut := now.Add(-authFailureWindow)
	var kept []time.Time
	for _, v := range values {
		if v.After(cut) {
			kept = append(kept, v)
		}
	}
	kept = append(kept, now)
	if len(kept) > authFailureThreshold {
		kept = kept[len(kept)-authFailureThreshold:]
	}
	m.fails[key] = kept
	if len(kept) >= authFailureThreshold {
		m.blocked[key] = now.Add(authBlockDuration)
	}
}

func (m *Manager) clear(remote string) {
	key := limiterKey(remote)
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.fails, key)
	delete(m.blocked, key)
}

func limiterKey(remote string) string {
	if host, _, err := netSplitHostPort(remote); err == nil {
		return host
	}
	return remote
}

func (m *Manager) sweepLimiterLocked(now time.Time) {
	cut := now.Add(-authFailureWindow)
	for key, values := range m.fails {
		kept := values[:0]
		for _, value := range values {
			if value.After(cut) {
				kept = append(kept, value)
			}
		}
		if len(kept) == 0 {
			delete(m.fails, key)
			continue
		}
		if len(kept) > authFailureThreshold {
			kept = kept[len(kept)-authFailureThreshold:]
		}
		m.fails[key] = kept
	}
	for key, until := range m.blocked {
		if !now.Before(until) {
			delete(m.blocked, key)
		}
	}
}

func (m *Manager) limiterEntryCountLocked() int {
	count := len(m.fails)
	for key := range m.blocked {
		if _, present := m.fails[key]; !present {
			count++
		}
	}
	return count
}

func (m *Manager) evictLimiterEntryLocked(now time.Time) {
	if m.limiterEntryCountLocked() < authLimiterMaxEntries {
		return
	}
	oldestKey := ""
	oldestAt := now
	for key, values := range m.fails {
		if len(values) == 0 {
			continue
		}
		activity := values[len(values)-1]
		if oldestKey == "" || activity.Before(oldestAt) {
			oldestKey, oldestAt = key, activity
		}
	}
	for key, until := range m.blocked {
		activity := until.Add(-authBlockDuration)
		if oldestKey == "" || activity.Before(oldestAt) {
			oldestKey, oldestAt = key, activity
		}
	}
	if oldestKey != "" {
		delete(m.fails, oldestKey)
		delete(m.blocked, oldestKey)
	}
}

// netSplitHostPort avoids treating a malformed RemoteAddr as fatal during
// tests and on unusual reverse-proxy setups.
func netSplitHostPort(v string) (string, string, error) {
	for i := len(v) - 1; i >= 0; i-- {
		if v[i] == ':' {
			return v[:i], v[i+1:], nil
		}
	}
	return "", "", errors.New("not host:port")
}

func (m *Manager) Authenticate(ctx context.Context, r *http.Request) (store.Session, bool) {
	cookie, err := r.Cookie(SessionCookie)
	if err != nil || cookie.Value == "" {
		return store.Session{}, false
	}
	session, err := m.Store.GetSession(ctx, digest(cookie.Value))
	if err != nil {
		return store.Session{}, false
	}
	now := m.now()
	if !now.Before(session.ExpiresAt) || now.Sub(session.LastSeenAt) > IdleTTL {
		_ = m.Store.DeleteSession(ctx, session.IDHash)
		return store.Session{}, false
	}
	// Keep the trusted-browser lifetime absolute from the original login. The
	// idle timestamp is refreshed on activity, but an active browser cannot
	// extend a session beyond its 30-day expiry.
	_ = m.Store.TouchSession(ctx, session.IDHash, now, session.ExpiresAt)
	return session, true
}

func (m *Manager) Logout(ctx context.Context, r *http.Request) error {
	if cookie, err := r.Cookie(SessionCookie); err == nil {
		return m.Store.DeleteSessionWithAudit(ctx, digest(cookie.Value), "admin.logout", "session ended")
	}
	return nil
}

func (m *Manager) CheckCSRF(r *http.Request, session store.Session) bool {
	return hmac.Equal([]byte(session.CSRFToken), []byte(r.Header.Get("X-CSRF-Token")))
}

func SetSessionCookie(w http.ResponseWriter, raw string) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: raw, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(SessionTTL / time.Second)})
}

func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func NewTOTPSecret() (string, error) {
	raw, err := randomBytes(20)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

func VerifyTOTP(secret, code string) bool {
	return VerifyTOTPAt(secret, code, time.Now())
}

// VerifyTOTPAt validates a six-digit RFC 6238 code around the supplied time.
// Keeping the clock injectable makes authentication tests deterministic while
// the public VerifyTOTP helper remains convenient for callers.
func VerifyTOTPAt(secret, code string, at time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	now := at.Unix() / 30
	for offset := int64(-1); offset <= 1; offset++ {
		if totpCode(secret, now+offset) == code {
			return true
		}
	}
	return false
}

func totpCode(secret string, counter int64) string {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	h := hmac.New(sha1.New, raw)
	_, _ = h.Write(msg[:])
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	n := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	return fmt.Sprintf("%06d", n%1000000)
}

func RecoveryCodes() ([]string, []string, error) {
	plain := make([]string, 10)
	hashes := make([]string, 10)
	for i := range plain {
		raw, err := randomBytes(5)
		if err != nil {
			return nil, nil, err
		}
		plain[i] = strings.ToUpper(hex.EncodeToString(raw))
		hashes[i] = digest(plain[i])
	}
	return plain, hashes, nil
}

func PasswordRequirements() map[string]any {
	return map[string]any{"minimum_length": PasswordMin, "algorithm": "argon2id"}
}
