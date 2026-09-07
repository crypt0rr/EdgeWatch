// Package auth implements the local EdgeWatch authentication surface. The
// first-run account remains the stable administrator for compatibility, while
// subsequent users authenticate through the same opaque-session machinery.
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

// NewOpaqueToken returns a URL-safe one-time token and its SHA-256 digest.
// Callers persist only the digest; the clear token is returned once to the
// administrator or activation flow.
func NewOpaqueToken() (string, string, error) {
	raw, err := randomBytes(32)
	if err != nil {
		return "", "", err
	}
	plain := base64.RawURLEncoding.EncodeToString(raw)
	return plain, digest(plain), nil
}

func digest(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

func (m *Manager) EnsureSetupToken(ctx context.Context) (string, error) {
	configured, err := m.Store.HasAdministrator(ctx)
	if err != nil {
		return "", err
	}
	if configured {
		return "", nil
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
	configured, err := m.Store.HasAdministrator(ctx)
	if err != nil {
		return "", err
	}
	if configured {
		return "", errors.New("administrator is already configured")
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
	remote := requestRemote(request)
	if !m.allow(remote) {
		return ErrRateLimited
	}
	if err := m.Setup(ctx, token, password); err != nil {
		m.failed(remote)
		return err
	}
	m.clear(remote)
	return nil
}

// ActivateRequest protects one-time user activation/password-reset links with
// the same per-source failure budget as setup and login. The token digest and
// Argon2id hash are handled inside the store transaction; a failed attempt
// never consumes the invite.
func (m *Manager) ActivateRequest(ctx context.Context, request *http.Request, token, password string) error {
	remote := requestRemote(request)
	if !m.allow(remote) {
		return ErrRateLimited
	}
	hash, err := PasswordHash(password)
	if err != nil {
		m.failed(remote)
		return err
	}
	now := m.now()
	if _, err := m.Store.ActivateUser(ctx, digest(token), hash, now, store.AuditEntry{Action: "user.activated", Detail: "user account activated"}); err != nil {
		m.failed(remote)
		return err
	}
	m.clear(remote)
	return nil
}

func (m *Manager) Login(ctx context.Context, request *http.Request, password, otp, recovery string) (string, store.Admin, error) {
	raw, user, err := m.LoginAs(ctx, request, "admin", password, otp, recovery)
	if err != nil {
		return "", store.Admin{}, err
	}
	return raw, store.Admin{Username: user.Username, DisplayName: user.DisplayName, PasswordHash: user.PasswordHash, TOTPSecret: user.TOTPSecret, TOTPSecretStored: user.TOTPSecretStored, TOTPEnabled: user.TOTPEnabled, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt}, nil
}

// LoginAs authenticates any enabled EdgeWatch user. The legacy Login method
// above intentionally remains as a compatibility wrapper for CLI and tests
// that always sign in as the original administrator.
func (m *Manager) LoginAs(ctx context.Context, request *http.Request, username, password, otp, recovery string) (string, store.User, error) {
	remote := requestRemote(request)
	if !m.allow(remote) {
		return "", store.User{}, ErrRateLimited
	}
	user, err := m.Store.GetUserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) && strings.EqualFold(strings.TrimSpace(username), "admin") {
		// Databases created by older test fixtures may not have the migrated
		// users row yet. Preserve the original administrator behavior while the
		// normal Open path always creates it through migration 12.
		admin, adminErr := m.Store.GetAdmin(ctx)
		if adminErr != nil {
			return "", store.User{}, errors.New("administrator is not configured")
		}
		user = store.User{ID: store.LegacyAdminUserID, Username: admin.Username, DisplayName: admin.DisplayName, Role: store.RoleAdministrator, PasswordHash: admin.PasswordHash, TOTPSecret: admin.TOTPSecret, TOTPSecretStored: admin.TOTPSecretStored, TOTPSecretError: admin.TOTPSecretError, TOTPEnabled: admin.TOTPEnabled, Enabled: true, CreatedAt: admin.CreatedAt, UpdatedAt: admin.UpdatedAt}
		err = nil
	}
	if err != nil {
		// Unknown usernames still consume the failure budget. Otherwise an
		// attacker could bypass the login limiter by rotating arbitrary account
		// names while probing the endpoint for a real administrator or invitee.
		m.failed(remote)
		return "", store.User{}, errors.New("invalid credentials")
	}
	if !user.Enabled {
		m.failed(remote)
		// Keep disabled accounts indistinguishable from unknown usernames. This
		// prevents the login endpoint from becoming an account-enumeration oracle
		// while the administration UI can still show the disabled state.
		return "", user, errors.New("invalid credentials")
	}
	if !VerifyPassword(user.PasswordHash, password) {
		m.failed(remote)
		return "", user, errors.New("invalid credentials")
	}
	if user.TOTPEnabled {
		valid := user.TOTPSecretError == nil && VerifyTOTPAt(user.TOTPSecret, otp, m.now())
		if !valid && recovery != "" {
			valid, err = m.Store.ConsumeRecoveryCodeForUser(ctx, user.ID, digest(strings.ToUpper(strings.TrimSpace(recovery))), m.now())
		}
		if !valid {
			m.failed(remote)
			return "", user, errors.New("one-time code is required")
		}
	}
	sessionRaw, err := randomBytes(32)
	if err != nil {
		return "", user, err
	}
	csrfRaw, err := randomBytes(32)
	if err != nil {
		return "", user, err
	}
	session := base64.RawURLEncoding.EncodeToString(sessionRaw)
	csrf := base64.RawURLEncoding.EncodeToString(csrfRaw)
	now := m.now()
	action := "user.login"
	if user.Role == store.RoleAdministrator {
		action = "admin.login"
	}
	if err := m.Store.CreateSessionForUserWithAuditEntry(ctx, user.ID, digest(session), csrf, now, now.Add(SessionTTL), store.AuditEntry{Action: action, Detail: "successful login", ActorUserID: user.ID, ActorUsername: user.Username}); err != nil {
		return "", user, err
	}
	_ = m.Store.SetUserLastLogin(ctx, user.ID, now)
	m.clear(remote)
	return session, user, nil
}

// ConfirmPassword applies the same per-client failure budget as login to
// sensitive, already-authenticated operations such as managing notification
// credentials. It intentionally returns only generic errors so callers cannot
// distinguish a missing administrator from a wrong password.
func (m *Manager) ConfirmPassword(ctx context.Context, request *http.Request, password string) error {
	return m.ConfirmPasswordForUser(ctx, request, store.LegacyAdminUserID, password)
}

// ConfirmPasswordForUser applies the password confirmation budget to the
// authenticated account that is about to perform a sensitive operation. The
// legacy ConfirmPassword wrapper remains for callers that predate RBAC, but
// web-managed administrators must be able to confirm with their own password
// rather than the original admin account's credential.
func (m *Manager) ConfirmPasswordForUser(ctx context.Context, request *http.Request, userID, password string) error {
	remote := requestRemote(request)
	if !m.allow(remote) {
		return ErrRateLimited
	}
	user, err := m.Store.GetUser(ctx, userID)
	if err != nil || !user.Enabled || !VerifyPassword(user.PasswordHash, password) {
		m.failed(remote)
		return errors.New("password confirmation failed")
	}
	m.clear(remote)
	return nil
}

func requestRemote(request *http.Request) string {
	if request == nil {
		return "unknown"
	}
	return request.RemoteAddr
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
	if session.UserID == "" {
		session.UserID = store.LegacyAdminUserID
	}
	user, err := m.Store.GetUser(ctx, session.UserID)
	if err != nil || !user.Enabled {
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
	session.Username, session.DisplayName, session.Role = user.Username, user.DisplayName, user.Role
	return session, true
}

func (m *Manager) Logout(ctx context.Context, r *http.Request) error {
	if cookie, err := r.Cookie(SessionCookie); err == nil {
		return m.Store.DeleteSessionWithAudit(ctx, digest(cookie.Value), "admin.logout", "session ended")
	}
	return nil
}

// LogoutSession is the role-aware variant used by the web API. It keeps the
// legacy Logout method above for CLI/tests while attributing new sign-outs to
// the actual account and avoiding a second session lookup.
func (m *Manager) LogoutSession(ctx context.Context, r *http.Request, session store.Session) error {
	cookie, err := r.Cookie(SessionCookie)
	if err != nil || cookie.Value == "" {
		return nil
	}
	action := "user.logout"
	if session.Role == store.RoleAdministrator {
		action = "admin.logout"
	}
	return m.Store.DeleteSessionWithAuditEntry(ctx, digest(cookie.Value), store.AuditEntry{Action: action, Detail: "session ended", ActorUserID: session.UserID, ActorUsername: session.Username})
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
