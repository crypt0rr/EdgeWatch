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
	"log/slog"
	"net"
	"net/http"
	"strconv"
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
	// Session activity writes are coalesced across tabs so a user can keep a
	// session alive without turning every keypress or click into a SQLite write.
	sessionActivityTouchInterval = 5 * time.Minute
	sessionActivityWriteTimeout  = 250 * time.Millisecond

	// Argon2id parameters are kept in one place so newly-created passwords
	// and the login-time upgrade path always agree on the current work factor.
	argon2Memory     uint32 = 19 * 1024
	argon2Iterations uint32 = 2
	argon2Threads    uint32 = 1
	argon2KeyLength  uint32 = 32

	authFailureWindow    = 5 * time.Minute
	authFailureThreshold = 5
	// The source bucket is a backstop for high-volume abuse, not the primary
	// login lockout: a reverse proxy or SSH tunnel may legitimately carry many
	// administrators' requests. Logins through a shared loopback peer use one
	// short source-wide cooldown instead of the normal hard lockout, keeping
	// responses independent of whether a submitted account exists.
	authSourceFailureThreshold = 100
	authBlockDuration          = 5 * time.Minute
	// A shared loopback peer cannot safely receive a hard source lockout. This
	// short source-wide cooldown bounds guesses without making any account
	// unavailable for five minutes or revealing whether a username exists.
	authSharedLoopbackRetryDelay = 2 * time.Second
	// The limiter is process-local by design, but it must remain bounded when
	// an attacker rotates source addresses. Keys are evicted oldest-first once
	// this ceiling is reached; expired entries are swept on every decision.
	authLimiterMaxEntries = 4096
	// Argon2id deliberately uses a meaningful memory cost. Keep the number of
	// requests that may enter the work factor bounded so a burst of invalid
	// credentials cannot exhaust the daemon's memory or CPU. A short queue
	// timeout gives callers a deterministic 429 instead of admitting unbounded
	// work while still allowing normal bursts to drain.
	authArgon2MaxConcurrent = 4
	authArgon2QueueTimeout  = 250 * time.Millisecond
)

var ErrRateLimited = errors.New("too many authentication attempts; try again later")

type retryAfterRateLimit struct {
	delay time.Duration
}

func (e *retryAfterRateLimit) Error() string { return ErrRateLimited.Error() }

func (e *retryAfterRateLimit) Is(target error) bool { return target == ErrRateLimited }

// RetryAfterHeaderValue returns the shared-loopback cooldown when applicable,
// or the normal hard-lockout duration for other rate-limit errors.
func RetryAfterHeaderValue(err error) string {
	var limited *retryAfterRateLimit
	if errors.As(err, &limited) && limited.delay > 0 {
		seconds := int((limited.delay-1)/time.Second) + 1
		return strconv.Itoa(seconds)
	}
	return strconv.Itoa(int(authBlockDuration / time.Second))
}

// dummyPasswordHash is used for unknown and disabled accounts so an invalid
// login spends the same Argon2id work regardless of whether the username is
// present. It is generated once with the same parameters as real passwords.
var dummyPasswordHash = func() string {
	hash, err := PasswordHash("edgewatch-invalid-login-sentinel")
	if err != nil {
		panic(fmt.Sprintf("create authentication timing sentinel: %v", err))
	}
	return hash
}()

const (
	forwardedHeaderXForwardedFor = "x-forwarded-for"
	forwardedHeaderForwarded     = "forwarded"
	forwardedHeaderNone          = "none"
)

type Manager struct {
	Store *store.Store
	Now   func() time.Time

	mu sync.Mutex
	// fails and blocked are the source-address backstop. Scoped authentication
	// paths use the account and unknown-source maps below so different
	// operations and accounts do not share a lockout bucket.
	fails                map[string][]time.Time
	blocked              map[string]time.Time
	accountFails         map[string][]time.Time
	accountBlocked       map[string]time.Time
	unknownSourceFails   map[string][]time.Time
	unknownSourceBlocked map[string]time.Time
	sourceInFlight       map[string]int
	accountInFlight      map[string]int
	unknownInFlight      map[string]int
	rateAudit            map[string]time.Time
	trustedProxies       []*net.IPNet
	forwardedHeader      string
	argon2Sem            chan struct{}
}

func NewManager(s *store.Store) *Manager {
	return &Manager{
		Store: s, Now: time.Now,
		forwardedHeader: forwardedHeaderXForwardedFor,
		fails:           map[string][]time.Time{}, blocked: map[string]time.Time{},
		accountFails: map[string][]time.Time{}, accountBlocked: map[string]time.Time{},
		unknownSourceFails: map[string][]time.Time{}, unknownSourceBlocked: map[string]time.Time{},
		sourceInFlight: map[string]int{}, accountInFlight: map[string]int{}, unknownInFlight: map[string]int{},
		rateAudit: map[string]time.Time{}, argon2Sem: make(chan struct{}, authArgon2MaxConcurrent),
	}
}

// withArgon2 admits one password hash/verification operation to the bounded
// authentication work pool. The callback runs while holding the slot and the
// slot is always released before returning. A caller that cannot enter within
// the short queue window receives the same typed rate-limit error used by the
// request limiter, allowing HTTP handlers to return a bounded 429 response.
func (m *Manager) withArgon2(ctx context.Context, fn func() error) error {
	m.mu.Lock()
	if m.argon2Sem == nil {
		m.argon2Sem = make(chan struct{}, authArgon2MaxConcurrent)
	}
	sem := m.argon2Sem
	m.mu.Unlock()

	timer := time.NewTimer(authArgon2QueueTimeout)
	defer timer.Stop()
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
		return fn()
	case <-ctx.Done():
		return ErrRateLimited
	case <-timer.C:
		return ErrRateLimited
	}
}

// SetTrustedProxies enables forwarding-header processing for the explicitly
// configured proxy networks. An empty list keeps the secure default: all
// forwarding headers are ignored and the directly connected peer is used.
func (m *Manager) SetTrustedProxies(values []string) error {
	networks := make([]*net.IPNet, 0, len(values))
	for index, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return fmt.Errorf("trusted proxy %d is empty", index)
		}
		if ip := net.ParseIP(value); ip != nil {
			bits := 128
			if ip.To4() != nil {
				ip = ip.To4()
				bits = 32
			}
			networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return fmt.Errorf("trusted proxy %d is not an IP address or CIDR: %q", index, raw)
		}
		networks = append(networks, network)
	}
	m.mu.Lock()
	m.trustedProxies = networks
	m.mu.Unlock()
	return nil
}

// SetForwardedHeader selects the single forwarding header trusted proxies use
// to report the original client address. Headers are never merged because a
// proxy that appends one convention while a client controls another could
// otherwise let the client choose its rate-limit and audit identity.
func (m *Manager) SetForwardedHeader(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = forwardedHeaderXForwardedFor
	}
	switch value {
	case forwardedHeaderXForwardedFor, forwardedHeaderForwarded, forwardedHeaderNone:
	default:
		return fmt.Errorf("forwarded header must be one of %q, %q, or %q", forwardedHeaderXForwardedFor, forwardedHeaderForwarded, forwardedHeaderNone)
	}
	m.mu.Lock()
	m.forwardedHeader = value
	m.mu.Unlock()
	return nil
}

// IsTrustedProxy reports whether the directly connected peer belongs to the
// explicitly configured proxy networks. It is intentionally limited to the
// peer address and never considers forwarded headers; callers can therefore
// use it as the gate before trusting another proxy-controlled header.
func (m *Manager) IsTrustedProxy(request *http.Request) bool {
	if m == nil || request == nil {
		return false
	}
	peer := net.ParseIP(strings.TrimSpace(limiterKey(requestRemote(request))))
	if peer == nil {
		return false
	}
	m.mu.Lock()
	trusted := append([]*net.IPNet(nil), m.trustedProxies...)
	m.mu.Unlock()
	return ipInNetworks(peer, trusted)
}

// ClientIP resolves the request identity for rate limiting and audit records.
// Forwarding headers are considered only when the directly connected peer is
// in the configured trusted-proxy set. The chain is walked from right to left
// and stops at the first untrusted hop, preventing clients from spoofing an
// address through an untrusted connection.
func (m *Manager) ClientIP(request *http.Request) string {
	remote := limiterKey(requestRemote(request))
	peer := net.ParseIP(strings.TrimSpace(remote))
	if peer == nil {
		return remote
	}
	m.mu.Lock()
	trusted := append([]*net.IPNet(nil), m.trustedProxies...)
	forwardedHeader := m.forwardedHeader
	m.mu.Unlock()
	if !ipInNetworks(peer, trusted) {
		return peer.String()
	}
	if forwardedHeader == "" {
		forwardedHeader = forwardedHeaderXForwardedFor
	}
	current := peer
	candidates := forwardedCandidatesFor(request, forwardedHeader)
	for index := len(candidates) - 1; index >= 0; index-- {
		if !ipInNetworks(current, trusted) {
			break
		}
		parsed := net.ParseIP(candidates[index])
		if parsed == nil {
			break
		}
		current = parsed
	}
	return current.String()
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func forwardedCandidates(request *http.Request) []string {
	return forwardedCandidatesFor(request, forwardedHeaderXForwardedFor)
}

func forwardedCandidatesFor(request *http.Request, header string) []string {
	if request == nil {
		return nil
	}
	// Parse only the configured convention; an alternate header must not
	// override or suppress the trusted proxy's selected client identity.
	if values := request.Header.Values("Forwarded"); len(values) > 0 && strings.EqualFold(header, forwardedHeaderForwarded) {
		var candidates []string
		for _, value := range values {
			for _, element := range strings.Split(value, ",") {
				for _, parameter := range strings.Split(element, ";") {
					key, raw, ok := strings.Cut(strings.TrimSpace(parameter), "=")
					if !ok || !strings.EqualFold(key, "for") {
						continue
					}
					candidates = append(candidates, parseForwardedAddress(raw))
					break
				}
			}
		}
		return candidates
	}
	if values := request.Header.Values("X-Forwarded-For"); len(values) > 0 && strings.EqualFold(header, forwardedHeaderXForwardedFor) {
		var candidates []string
		for _, value := range values {
			for _, item := range strings.Split(value, ",") {
				// Keep an empty sentinel for malformed hops. Dropping an invalid
				// middle value could make an untrusted client look adjacent to a
				// trusted proxy and would weaken the chain validation.
				candidates = append(candidates, parseForwardedAddress(item))
			}
		}
		return candidates
	}
	return nil
}

func parseForwardedAddress(raw string) string {
	value := strings.Trim(strings.TrimSpace(raw), `"`)
	if value == "" || value == "unknown" || strings.HasPrefix(value, "_") {
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	if strings.HasPrefix(value, "[") {
		if end := strings.IndexByte(value, ']'); end > 1 {
			if ip := net.ParseIP(value[1:end]); ip != nil {
				return ip.String()
			}
		}
	}
	if host, _, err := netSplitHostPort(value); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			return ip.String()
		}
	}
	return ""
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
	key := argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, uint8(argon2Threads), argon2KeyLength)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$ew$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argon2Memory, argon2Iterations, argon2Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

func passwordHashParameters(encoded string) (memory, iterations, threads uint32, salt, expected []byte, ok bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 7 || parts[1] != "ew" || parts[2] != "argon2id" || parts[3] != "v=19" {
		return 0, 0, 0, nil, nil, false
	}
	if _, err := fmt.Sscanf(parts[4], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil || memory < 8*threads || memory > 1024*1024 || iterations == 0 || iterations > 10 || threads == 0 || threads > 32 {
		return 0, 0, 0, nil, nil, false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[5])
	expected, err2 := base64.RawStdEncoding.DecodeString(parts[6])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(expected) == 0 {
		return 0, 0, 0, nil, nil, false
	}
	return memory, iterations, threads, salt, expected, true
}

func VerifyPassword(encoded, password string) bool {
	memory, iterations, threads, salt, expected, ok := passwordHashParameters(encoded)
	if !ok {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, uint8(threads), uint32(len(expected)))
	return hmac.Equal(actual, expected)
}

// passwordHashNeedsRehash reports whether a valid hash uses a weaker Argon2id
// work factor than the current policy. A malformed hash is not considered an
// upgrade candidate because VerifyPassword will reject it first.
func passwordHashNeedsRehash(encoded string) bool {
	memory, iterations, threads, _, expected, ok := passwordHashParameters(encoded)
	if !ok {
		return false
	}
	return memory < argon2Memory || iterations < argon2Iterations || threads < argon2Threads || uint32(len(expected)) < argon2KeyLength
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
	source := m.sourceScopeFor(request, "setup")
	account := "setup:" + digest(strings.TrimSpace(token))
	if !m.allowScoped(source, account) {
		m.auditRateLimit(ctx, "setup", request)
		return ErrRateLimited
	}
	defer m.releaseScoped(source, account)
	usable, checkErr := m.Store.SetupTokenUsable(ctx, digest(strings.TrimSpace(token)), m.now())
	if checkErr != nil {
		m.auditAuthFailure(ctx, "auth.setup_failed", "setup", request)
		return errors.New("administrator setup could not be completed")
	}
	if !usable {
		m.failedScoped(source, account, "", false)
		m.auditAuthFailure(ctx, "auth.setup_failed", "setup", request)
		return errors.New("administrator setup could not be completed")
	}
	var setupErr error
	if err := m.withArgon2(ctx, func() error {
		setupErr = m.Setup(ctx, token, password)
		return setupErr
	}); err != nil {
		if errors.Is(err, ErrRateLimited) {
			m.auditRateLimit(ctx, "setup", request)
			return err
		}
		// withArgon2 only returns the callback error after releasing the
		// semaphore, so preserve the existing setup failure accounting below.
		setupErr = err
	}
	if setupErr != nil {
		m.failedScoped(source, account, "", false)
		m.auditAuthFailure(ctx, "auth.setup_failed", "setup", request)
		return setupErr
	}
	m.clearScoped(source, account, "")
	return nil
}

// ActivateRequest protects one-time user activation/password-reset links with
// the same per-source failure budget as setup and login. The token digest and
// Argon2id hash are handled inside the store transaction; a failed attempt
// never consumes the invite. On success it returns the activated user's ID so
// the caller can close live-update streams opened with the sessions that the
// activation revoked.
func (m *Manager) ActivateRequest(ctx context.Context, request *http.Request, token, password string) (string, error) {
	source := m.sourceScopeFor(request, "activation")
	account := "activation:" + digest(strings.TrimSpace(token))
	if !m.allowScoped(source, account) {
		m.auditRateLimit(ctx, "activation", request)
		return "", ErrRateLimited
	}
	defer m.releaseScoped(source, account)
	usable, checkErr := m.Store.ActivationTokenUsable(ctx, digest(strings.TrimSpace(token)), m.now())
	if checkErr != nil {
		m.auditAuthFailure(ctx, "auth.activation_failed", "activation", request)
		return "", errors.New("activation could not be completed")
	}
	if !usable {
		m.failedScoped(source, account, "", false)
		m.auditAuthFailure(ctx, "auth.activation_failed", "activation", request)
		return "", errors.New("activation could not be completed")
	}
	var hash string
	if err := m.withArgon2(ctx, func() error {
		var hashErr error
		hash, hashErr = PasswordHash(password)
		return hashErr
	}); err != nil {
		if errors.Is(err, ErrRateLimited) {
			m.auditRateLimit(ctx, "activation", request)
			return "", err
		}
		m.failedScoped(source, account, "", false)
		m.auditAuthFailure(ctx, "auth.activation_failed", "activation", request)
		return "", err
	}
	now := m.now()
	activated, err := m.Store.ActivateUser(ctx, digest(token), hash, now, store.AuditEntry{Action: "user.activated", Detail: "user account activated"})
	if err != nil {
		m.failedScoped(source, account, "", false)
		m.auditAuthFailure(ctx, "auth.activation_failed", "activation", request)
		return "", err
	}
	m.clearScoped(source, account, "")
	return activated.ID, nil
}

// LoginAs authenticates any enabled EdgeWatch user.
func (m *Manager) LoginAs(ctx context.Context, request *http.Request, username, password, otp, recovery string) (string, store.User, error) {
	identity := normalizeLoginIdentity(username)
	source := m.sourceScopeFor(request, "login")
	account := "login:" + identity
	unknownSource := "unknown-login:" + strings.TrimPrefix(source, "source:")
	if !m.allowScoped(source, account) {
		m.auditRateLimit(ctx, "login:"+identity, request)
		return "", store.User{}, m.rateLimitError(source, account)
	}
	defer m.releaseScoped(source, account)
	// Only a users row can sign in. Schema 52 retired the legacy admins row,
	// so the original administrator is the users row with LegacyAdminUserID.
	user, err := m.Store.GetUserByUsername(ctx, identity)
	if err != nil {
		if !sharedLoopbackLoginSource(source, account) {
			if !m.allowUnknownSource(unknownSource) {
				m.auditRateLimit(ctx, "unknown-login:"+identity, request)
				return "", store.User{}, ErrRateLimited
			}
			defer m.releaseUnknownSource(unknownSource)
		}
		// Unknown usernames consume the same failure budget as known accounts.
		// Shared loopback peers use the source-wide cooldown so the response does
		// not expose account existence; other peers retain the unknown-name
		// source bucket to prevent bypass by rotating account names.
		m.failedScoped(source, account, unknownSource, true)
		if err := m.withArgon2(ctx, func() error {
			_ = VerifyPassword(dummyPasswordHash, password)
			return nil
		}); err != nil {
			if errors.Is(err, ErrRateLimited) {
				m.auditRateLimit(ctx, "login:"+identity, request)
			}
			return "", store.User{}, err
		}
		m.auditAuthFailure(ctx, "auth.login_failed", identity, request)
		return "", store.User{}, errors.New("invalid credentials")
	}
	if !user.Enabled {
		m.failedScoped(source, account, "", false)
		// Keep disabled accounts indistinguishable from unknown usernames. This
		// prevents the login endpoint from becoming an account-enumeration oracle
		// while the administration UI can still show the disabled state.
		if err := m.withArgon2(ctx, func() error {
			_ = VerifyPassword(dummyPasswordHash, password)
			return nil
		}); err != nil {
			if errors.Is(err, ErrRateLimited) {
				m.auditRateLimit(ctx, "login:"+identity, request)
			}
			return "", user, err
		}
		m.auditAuthFailure(ctx, "auth.login_failed", identity, request)
		return "", user, errors.New("invalid credentials")
	}
	var passwordValid bool
	if err := m.withArgon2(ctx, func() error {
		passwordValid = VerifyPassword(user.PasswordHash, password)
		return nil
	}); err != nil {
		if errors.Is(err, ErrRateLimited) {
			m.auditRateLimit(ctx, "login:"+identity, request)
		}
		return "", user, err
	}
	if !passwordValid {
		m.failedScoped(source, account, "", false)
		m.auditAuthFailure(ctx, "auth.login_failed", identity, request)
		return "", user, errors.New("invalid credentials")
	}
	totpAccepted := false
	acceptedTOTPStep := int64(-1)
	acceptedTOTPSecret := ""
	if user.TOTPEnabled {
		valid := false
		if user.TOTPSecretError == nil {
			if step, stepValid := VerifyTOTPAtStep(user.TOTPSecret, otp, m.now()); stepValid {
				consumed, consumeErr := m.Store.ConsumeTOTPStep(ctx, user.ID, step, m.now())
				if consumeErr != nil {
					return "", user, consumeErr
				}
				valid, totpAccepted = consumed, consumed
				if consumed {
					acceptedTOTPStep = step
					acceptedTOTPSecret = user.TOTPSecret
				}
			}
		}
		if !valid && recovery != "" {
			valid, err = m.Store.ConsumeRecoveryCodeTextForUser(ctx, user.ID, recovery, m.now())
			if valid {
				m.auditAuthFailure(ctx, "auth.recovery_code_used", identity, request)
			}
		}
		if !valid {
			m.failedScoped(source, account, "", false)
			m.auditAuthFailure(ctx, "auth.totp_failed", identity, request)
			return "", user, errors.New("one-time code is required")
		}
	}
	// Successful logins are an opportunity to move hashes created with an
	// older, weaker Argon2id policy to the current parameters. Keep the login
	// successful if a legacy password does not meet today's minimum length; the
	// account can still be changed through the normal password-management flow.
	upgradedHash := ""
	if passwordHashNeedsRehash(user.PasswordHash) {
		if err := m.withArgon2(ctx, func() error {
			candidate, hashErr := PasswordHash(password)
			if hashErr == nil {
				upgradedHash = candidate
			}
			return hashErr
		}); err != nil && errors.Is(err, ErrRateLimited) {
			m.auditRateLimit(ctx, "login:"+identity, request)
			return "", user, err
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
	audit := store.AuditEntry{Action: action, Detail: "successful login", ActorUserID: user.ID, ActorUsername: user.Username, SourceIP: m.ClientIP(request)}
	createSession := func(candidate store.User, hash string, revision int64, totpEnabled bool) error {
		if hash != "" {
			return m.Store.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, candidate.ID, candidate.PasswordHash, hash, revision, totpEnabled, digest(session), csrf, now, now.Add(SessionTTL), audit)
		}
		return m.Store.CreateSessionForUserIfCurrent(ctx, candidate.ID, candidate.PasswordHash, revision, totpEnabled, digest(session), csrf, now, now.Add(SessionTTL), audit)
	}
	if err := createSession(user, upgradedHash, user.Revision, user.TOTPEnabled); err != nil {
		if !errors.Is(err, store.ErrSessionCredentialsChanged) && !errors.Is(err, store.ErrPasswordChangedDuringLogin) {
			return "", user, err
		}
		// Credential state changed after the initial password/TOTP checks. Re-read
		// the authoritative row and repeat both checks before retrying; otherwise
		// a stale login could create a session after a password, TOTP, or disable
		// operation won the race.
		current, readErr := m.Store.GetUser(ctx, user.ID)
		if readErr != nil || !current.Enabled {
			if readErr != nil {
				return "", user, readErr
			}
			return "", user, errors.New("credentials changed during login")
		}
		fallbackValid := false
		verifyErr := m.withArgon2(ctx, func() error {
			fallbackValid = VerifyPassword(current.PasswordHash, password)
			return nil
		})
		if errors.Is(verifyErr, ErrRateLimited) {
			m.auditRateLimit(ctx, "login:"+identity, request)
			return "", user, verifyErr
		}
		if verifyErr != nil || !fallbackValid {
			return "", user, errors.New("credentials changed during login")
		}
		if current.TOTPEnabled {
			// A password change or display-name edit may legitimately race the
			// session insert, but a TOTP re-enrolment must invalidate the factor
			// that was verified before the retry. Only reuse the already-consumed
			// step when the authoritative encrypted secret is unchanged; otherwise
			// validate and consume the code against the new secret.
			otpValid := totpAccepted && acceptedTOTPStep >= 0 && current.TOTPSecret == acceptedTOTPSecret
			if !otpValid && current.TOTPSecretError == nil {
				if step, stepValid := VerifyTOTPAtStep(current.TOTPSecret, otp, m.now()); stepValid {
					var consumeErr error
					otpValid, consumeErr = m.Store.ConsumeTOTPStep(ctx, current.ID, step, m.now())
					if consumeErr != nil {
						return "", user, consumeErr
					}
				}
			}
			if !otpValid {
				return "", user, errors.New("credentials changed during login")
			}
		}
		if retryErr := createSession(current, "", current.Revision, current.TOTPEnabled); retryErr != nil {
			return "", user, retryErr
		}
		user = current
	} else if upgradedHash != "" {
		user.PasswordHash = upgradedHash
		user.Revision++
	}
	if upgradedHash == "" {
		_ = m.Store.SetUserLastLogin(ctx, user.ID, now)
	}
	m.clearScoped(source, account, "")
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
	source := m.sourceScopeFor(request, "confirmation")
	account := "confirm:" + strings.TrimSpace(userID)
	if !m.allowScoped(source, account) {
		m.auditRateLimit(ctx, "password-confirmation", request)
		return ErrRateLimited
	}
	defer m.releaseScoped(source, account)
	user, err := m.Store.GetUser(ctx, userID)
	var passwordValid bool
	if err == nil && user.Enabled {
		if verifyErr := m.withArgon2(ctx, func() error {
			passwordValid = VerifyPassword(user.PasswordHash, password)
			return nil
		}); verifyErr != nil {
			if errors.Is(verifyErr, ErrRateLimited) {
				m.auditRateLimit(ctx, "password-confirmation", request)
				return verifyErr
			}
			err = verifyErr
		}
	}
	if err != nil || !user.Enabled || !passwordValid {
		m.failedScoped(source, account, "", false)
		m.auditAuthFailure(ctx, "auth.password_confirmation_failed", userID, request)
		return errors.New("password confirmation failed")
	}
	m.clearScoped(source, account, "")
	return nil
}

// ConfirmTOTPForUser proves the currently configured second factor for a
// sensitive security mutation. Unlike VerifyTOTPAt it consumes the accepted
// time step (or a one-use recovery code), so a captured factor cannot be
// replayed to disable or replace TOTP.
func (m *Manager) ConfirmTOTPForUser(ctx context.Context, request *http.Request, userID, otp, recovery string) error {
	source := m.sourceScopeFor(request, "totp-confirmation")
	account := "totp-confirm:" + strings.TrimSpace(userID)
	if !m.allowScoped(source, account) {
		m.auditRateLimit(ctx, "totp-confirmation", request)
		return ErrRateLimited
	}
	defer m.releaseScoped(source, account)
	user, err := m.Store.GetUser(ctx, userID)
	valid := false
	if err == nil && user.Enabled && user.TOTPEnabled && user.TOTPSecretError == nil {
		if step, stepValid := VerifyTOTPAtStep(user.TOTPSecret, otp, m.now()); stepValid {
			valid, err = m.Store.ConsumeTOTPStep(ctx, user.ID, step, m.now())
		}
	}
	if !valid && err == nil && recovery != "" {
		valid, err = m.Store.ConsumeRecoveryCodeTextForUser(ctx, user.ID, recovery, m.now())
	}
	if err != nil {
		if errors.Is(err, ErrRateLimited) {
			m.auditRateLimit(ctx, "totp-confirmation", request)
			return err
		}
		valid = false
	}
	if !valid {
		m.failedScoped(source, account, "", false)
		m.auditAuthFailure(ctx, "auth.totp_confirmation_failed", userID, request)
		return errors.New("current one-time code is required")
	}
	m.clearScoped(source, account, "")
	return nil
}

// auditAuthFailure records an authentication security event without allowing
// an unavailable audit table to alter the response to the original request.
// Values are bounded and never contain passwords, OTPs, or recovery codes.
func (m *Manager) auditAuthFailure(ctx context.Context, action, subject string, request *http.Request) {
	subject = strings.TrimSpace(subject)
	if len(subject) > 80 {
		subject = subject[:80]
	}
	if err := m.Store.AuditEntry(ctx, store.AuditEntry{
		Action:        action,
		Detail:        "authentication event for " + subject,
		ActorUsername: subject,
		SourceIP:      m.ClientIP(request),
	}); err != nil {
		// Authentication failure records are deliberately best-effort so they do
		// not change the generic response contract, but a storage failure must
		// remain observable for operators. Store.AuditEntry persists through a
		// bounded context detached from request cancellation.
		slog.Default().Warn("security audit write failed", "action", action, "error", err)
	}
}

// auditRateLimit records only the transition into a rate-limited episode. A
// blocked client can send an unbounded number of rejected requests; writing an
// audit row for each one would turn the protection itself into a storage DoS.
func (m *Manager) auditRateLimit(ctx context.Context, subject string, request *http.Request) {
	// A blocked episode belongs to the resolved source and endpoint, not to
	// attacker-controlled account text. In particular, unknown-login subjects
	// include the supplied username; using that value here would let a caller
	// rotate usernames and force one durable audit row per attempt. Keep the
	// account/identity in the audit detail for diagnostics, but coalesce the
	// suppression key to the endpoint bucket so one source produces at most one
	// rate-limit transition per window for that operation.
	key := rateAuditEndpoint(subject) + "\x00" + m.sourceScopeFor(request, "rate")
	now := m.now()
	m.mu.Lock()
	m.ensureScopedLimiterMapsLocked()
	last, exists := m.rateAudit[key]
	if exists && now.Sub(last) < authFailureWindow {
		m.mu.Unlock()
		return
	}
	m.rateAudit[key] = now
	if len(m.rateAudit) > authLimiterMaxEntries {
		for candidate, timestamp := range m.rateAudit {
			if now.Sub(timestamp) >= authFailureWindow {
				delete(m.rateAudit, candidate)
			}
		}
	}
	m.mu.Unlock()
	m.auditAuthFailure(ctx, "auth.rate_limited", subject, request)
}

func rateAuditEndpoint(subject string) string {
	subject = strings.TrimSpace(subject)
	switch {
	case subject == "setup":
		return "setup"
	case subject == "activation":
		return "activation"
	case subject == "password-confirmation":
		return "password-confirmation"
	case strings.HasPrefix(subject, "login:"), strings.HasPrefix(subject, "unknown-login:"):
		return "login"
	default:
		return subject
	}
}

func requestRemote(request *http.Request) string {
	if request == nil {
		return "unknown"
	}
	return request.RemoteAddr
}

func sourceScope(request *http.Request) string {
	return "source:" + limiterKey(requestRemote(request))
}

func (m *Manager) sourceScope(request *http.Request) string {
	return m.sourceScopeFor(request, "auth")
}

func (m *Manager) sourceScopeFor(request *http.Request, namespace string) string {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		namespace = "auth"
	}
	return "source:" + namespace + ":" + limiterKey(m.ClientIP(request))
}

func normalizeLoginIdentity(username string) string {
	identity := strings.ToLower(strings.TrimSpace(username))
	if identity == "" {
		return "admin"
	}
	return identity
}

// allowScoped checks the source backstop for an authentication operation.
// Account and token failure state is scoped to the operation, account, and
// resolved source. A single client behind a trusted proxy can be throttled
// without blocking the same account from another client. Unknown-login probing
// has a separate source bucket for trustworthy client identities. Shared
// loopback login sources instead use the same brief source-wide cooldown for
// existing and unknown usernames to prevent account enumeration.
func (m *Manager) allowScoped(source, account string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.ensureScopedLimiterMapsLocked()
	m.sweepLimiterLocked(now)
	// A loopback peer is not a trustworthy client identity when EdgeWatch is
	// behind an unconfigured tunnel or reverse proxy: every remote client can
	// collapse to 127.0.0.1 or ::1. Do not turn that shared identity into a
	// long hard lockout. A short source-wide cooldown still bounds sequential
	// guesses and keeps rate-limit behavior the same for existing and unknown
	// usernames. The Argon2 admission semaphore and in-flight caps below also
	// bound concurrent work. Once a proxy is explicitly trusted, ClientIP
	// resolves the forwarded address and this exception no longer applies, so
	// normal hard source/account limits remain for trustworthy client identities.
	sharedLoopbackLogin := sharedLoopbackLoginSource(source, account)
	accountKey := scopedAccountKey(source, account)
	if !sharedLoopbackLogin {
		if legacy := legacySourceScope(source); legacy != "" {
			if until, ok := m.blocked[legacy]; ok && now.Before(until) {
				return false
			}
		}
		if until, ok := m.blocked[source]; ok && now.Before(until) {
			return false
		}
		if account != "" {
			if until, ok := m.accountBlocked[scopedAccountKey(source, account)]; ok && now.Before(until) {
				return false
			}
		}
	} else if until, ok := m.blocked[source]; ok && now.Before(until) {
		return false
	}
	// Reserve the bounded admission while the caller performs Argon2 or a
	// storage lookup. Without this compare-and-reserve step a burst of
	// concurrent requests could all pass the check before any failure was
	// recorded, defeating the account/source thresholds.
	if sharedLoopbackLogin {
		// Keep a small per-peer admission ceiling for an untrusted shared
		// identity. Sequential attempts remain subject to the Argon2 work factor,
		// while a burst cannot consume every authentication worker.
		if m.sourceInFlight[source] >= authArgon2MaxConcurrent {
			return false
		}
		if accountKey != "" && m.accountInFlight[accountKey] >= authArgon2MaxConcurrent {
			return false
		}
	} else {
		if len(m.fails[source])+m.sourceInFlight[source] >= authSourceFailureThreshold {
			return false
		}
		if accountKey != "" && len(m.accountFails[accountKey])+m.accountInFlight[accountKey] >= authFailureThreshold {
			return false
		}
	}
	m.sourceInFlight[source]++
	if accountKey != "" {
		m.accountInFlight[accountKey]++
	}
	return true
}

func (m *Manager) rateLimitError(source, account string) error {
	if !sharedLoopbackLoginSource(source, account) {
		return ErrRateLimited
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	until, ok := m.blocked[source]
	if !ok {
		return &retryAfterRateLimit{delay: authSharedLoopbackRetryDelay}
	}
	if remaining := until.Sub(m.now()); remaining > 0 {
		return &retryAfterRateLimit{delay: remaining}
	}
	return &retryAfterRateLimit{delay: authSharedLoopbackRetryDelay}
}

func (m *Manager) allowUnknownSource(scope string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.ensureScopedLimiterMapsLocked()
	m.sweepLimiterLocked(now)
	until, ok := m.unknownSourceBlocked[scope]
	if ok && now.Before(until) {
		return false
	}
	if len(m.unknownSourceFails[scope])+m.unknownInFlight[scope] >= authFailureThreshold {
		return false
	}
	m.unknownInFlight[scope]++
	return true
}

// releaseScoped drops an admission reservation made before the expensive or
// failure-prone portion of an authentication request. Failure recording is
// deliberately separate so successful requests do not consume the budget.
func (m *Manager) releaseScoped(source, account string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureScopedLimiterMapsLocked()
	if m.sourceInFlight[source] > 1 {
		m.sourceInFlight[source]--
	} else {
		delete(m.sourceInFlight, source)
	}
	key := scopedAccountKey(source, account)
	if key == "" {
		return
	}
	if m.accountInFlight[key] > 1 {
		m.accountInFlight[key]--
	} else {
		delete(m.accountInFlight, key)
	}
}

func (m *Manager) releaseUnknownSource(scope string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureScopedLimiterMapsLocked()
	if m.unknownInFlight[scope] > 1 {
		m.unknownInFlight[scope]--
	} else {
		delete(m.unknownInFlight, scope)
	}
}

func (m *Manager) failedScoped(source, account, unknownSource string, unknown bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.ensureScopedLimiterMapsLocked()
	m.sweepLimiterLocked(now)
	if source != "" {
		recordFailureLocked(now, source, authSourceFailureThreshold, m.fails, m.blocked)
	}
	if account != "" && !sharedLoopbackLoginSource(source, account) {
		// Keep normal failure buckets source-scoped. Shared loopback logins use
		// one short source-wide cooldown instead of account-specific blocks, so
		// rate-limit responses do not disclose whether the account exists.
		accountKey := scopedAccountKey(source, account)
		recordFailureLocked(now, accountKey, authFailureThreshold, m.accountFails, m.accountBlocked)
	}
	if unknown && unknownSource != "" && !sharedLoopbackLoginSource(source, account) {
		recordFailureLocked(now, unknownSource, authFailureThreshold, m.unknownSourceFails, m.unknownSourceBlocked)
	}
	if sharedLoopbackLoginSource(source, account) && len(m.fails[source]) >= authFailureThreshold {
		// The normal source backstop is five minutes at a much higher threshold.
		// Replace it for a shared loopback login with the same brief cooldown for
		// known-account and unknown-account failures.
		m.blocked[source] = now.Add(authSharedLoopbackRetryDelay)
	}
}

func (m *Manager) clearScoped(source, account, unknownSource string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureScopedLimiterMapsLocked()
	accountKey := scopedAccountKey(source, account)
	delete(m.accountFails, accountKey)
	delete(m.accountBlocked, accountKey)
	delete(m.unknownSourceFails, unknownSource)
	delete(m.unknownSourceBlocked, unknownSource)
	delete(m.fails, source)
	delete(m.blocked, source)
	// Clear a legacy bucket as well when a compatibility caller and a normal
	// request share a source. This avoids a successful login being followed by
	// a stale test/old-client lockout.
	legacy := legacySourceScope(source)
	delete(m.fails, legacy)
	delete(m.blocked, legacy)
}

func scopedAccountKey(source, account string) string {
	if strings.TrimSpace(account) == "" {
		return ""
	}
	return strings.TrimSpace(source) + "\x00" + strings.TrimSpace(account)
}

func sharedLoopbackLoginSource(source, account string) bool {
	if !strings.HasPrefix(strings.TrimSpace(account), "login:") {
		return false
	}
	address := legacySourceScope(source)
	ip := net.ParseIP(address)
	return ip != nil && ip.IsLoopback()
}

func legacySourceScope(source string) string {
	if !strings.HasPrefix(source, "source:") {
		return ""
	}
	value := strings.TrimPrefix(source, "source:")
	// Scoped source keys are encoded as source:<namespace>:<client>. Split
	// only at the namespace delimiter so IPv6 literals keep all of their
	// colons. The legacy form source:<client> is returned unchanged.
	if index := strings.IndexByte(value, ':'); index >= 0 {
		if address := value[index+1:]; address != "" {
			return address
		}
		return ""
	}
	return value
}

func limiterKey(remote string) string {
	value := strings.TrimSpace(remote)
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[]")
	}
	// RemoteAddr normally includes a port, but callers and tests may provide a
	// bare address. Parse it as a complete IP before attempting any permissive
	// fallback; splitting a bare IPv6 literal at its last colon would silently
	// turn one client into a different limiter bucket.
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return ip.String()
	}
	return value
}

func (m *Manager) ensureScopedLimiterMapsLocked() {
	if m.fails == nil {
		m.fails = map[string][]time.Time{}
	}
	if m.blocked == nil {
		m.blocked = map[string]time.Time{}
	}
	if m.accountFails == nil {
		m.accountFails = map[string][]time.Time{}
	}
	if m.accountBlocked == nil {
		m.accountBlocked = map[string]time.Time{}
	}
	if m.unknownSourceFails == nil {
		m.unknownSourceFails = map[string][]time.Time{}
	}
	if m.unknownSourceBlocked == nil {
		m.unknownSourceBlocked = map[string]time.Time{}
	}
	if m.sourceInFlight == nil {
		m.sourceInFlight = map[string]int{}
	}
	if m.accountInFlight == nil {
		m.accountInFlight = map[string]int{}
	}
	if m.unknownInFlight == nil {
		m.unknownInFlight = map[string]int{}
	}
	if m.rateAudit == nil {
		m.rateAudit = map[string]time.Time{}
	}
}

func recordFailureLocked(now time.Time, key string, threshold int, fails map[string][]time.Time, blocked map[string]time.Time) {
	if _, exists := fails[key]; !exists {
		if _, exists := blocked[key]; !exists {
			evictFailureBucketLocked(now, fails, blocked)
		}
	}
	values := fails[key]
	cut := now.Add(-authFailureWindow)
	kept := values[:0]
	for _, value := range values {
		if value.After(cut) {
			kept = append(kept, value)
		}
	}
	kept = append(kept, now)
	if len(kept) > threshold {
		kept = kept[len(kept)-threshold:]
	}
	fails[key] = kept
	if len(kept) >= threshold {
		blocked[key] = now.Add(authBlockDuration)
	}
}

func evictFailureBucketLocked(now time.Time, fails map[string][]time.Time, blocked map[string]time.Time) {
	count := len(fails)
	for key := range blocked {
		if _, present := fails[key]; !present {
			count++
		}
	}
	if count < authLimiterMaxEntries {
		return
	}
	oldestKey := ""
	oldestAt := now
	for key, values := range fails {
		if len(values) == 0 {
			continue
		}
		activity := values[len(values)-1]
		if oldestKey == "" || activity.Before(oldestAt) {
			oldestKey, oldestAt = key, activity
		}
	}
	for key, until := range blocked {
		activity := until.Add(-authBlockDuration)
		if oldestKey == "" || activity.Before(oldestAt) {
			oldestKey, oldestAt = key, activity
		}
	}
	if oldestKey != "" {
		delete(fails, oldestKey)
		delete(blocked, oldestKey)
	}
}

func (m *Manager) sweepLimiterLocked(now time.Time) {
	sweepFailureBucketLocked(now, m.fails, m.blocked, authSourceFailureThreshold)
	if m.accountFails != nil {
		sweepFailureBucketLocked(now, m.accountFails, m.accountBlocked, authFailureThreshold)
	}
	if m.unknownSourceFails != nil {
		sweepFailureBucketLocked(now, m.unknownSourceFails, m.unknownSourceBlocked, authFailureThreshold)
	}
}

func sweepFailureBucketLocked(now time.Time, fails map[string][]time.Time, blocked map[string]time.Time, threshold int) {
	cut := now.Add(-authFailureWindow)
	for key, values := range fails {
		kept := values[:0]
		for _, value := range values {
			if value.After(cut) {
				kept = append(kept, value)
			}
		}
		if len(kept) == 0 {
			delete(fails, key)
			continue
		}
		if len(kept) > threshold {
			kept = kept[len(kept)-threshold:]
		}
		fails[key] = kept
	}
	for key, until := range blocked {
		if !now.Before(until) {
			delete(blocked, key)
		}
	}
}

// netSplitHostPort delegates to the standard parser so bracketed IPv6
// addresses are handled correctly. Callers that need to tolerate a bare
// address should use limiterKey's explicit IP fallback instead of guessing
// where an IPv6 host ends and a port begins.
func netSplitHostPort(v string) (string, string, error) {
	return net.SplitHostPort(strings.TrimSpace(v))
}

func (m *Manager) Authenticate(ctx context.Context, r *http.Request) (store.Session, bool) {
	return m.authenticate(ctx, r, true)
}

// AuthenticateReadOnly validates a session without refreshing its idle
// timestamp. It is used for API reads, including background polling, and for
// long-lived SSE connections so automated requests cannot keep an otherwise
// idle session alive or contend for SQLite's writer connection.
func (m *Manager) AuthenticateReadOnly(ctx context.Context, r *http.Request) (store.Session, bool) {
	return m.authenticate(ctx, r, false)
}

// RecordActivity advances the idle deadline after real user activity. It is
// intentionally separate from authentication so background GET polling stays
// read-only. The store performs a conditional update, which coalesces activity
// across concurrent browser tabs as well as within one tab.
func (m *Manager) RecordActivity(ctx context.Context, session store.Session) error {
	now := m.now()
	if now.Sub(session.LastSeenAt) < sessionActivityTouchInterval {
		return nil
	}
	writeCtx, cancel := context.WithTimeout(ctx, sessionActivityWriteTimeout)
	defer cancel()
	_, err := m.Store.TouchSessionIfStale(writeCtx, session.IDHash, now, session.ExpiresAt, now.Add(-sessionActivityTouchInterval))
	return err
}

func (m *Manager) authenticate(ctx context.Context, r *http.Request, touch bool) (store.Session, bool) {
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
		// Expired sessions are rejected immediately, but do not synchronously
		// delete them here: authentication is on the request path and SQLite may
		// be busy with a long-running writer. Absolute-expiry cleanup removes old
		// rows in the background.
		return store.Session{}, false
	}
	// Keep the trusted-browser lifetime absolute from the original login. The
	// idle timestamp is refreshed on activity, but an active browser cannot
	// extend a session beyond its 30-day expiry.
	if touch {
		_ = m.Store.TouchSession(ctx, session.IDHash, now, session.ExpiresAt)
	}
	session.Username, session.DisplayName, session.Role = user.Username, user.DisplayName, user.Role
	session.SourceIP = m.ClientIP(r)
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
	if r == nil || session.CSRFToken == "" {
		return false
	}
	token := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	if token == "" {
		return false
	}
	return hmac.Equal([]byte(session.CSRFToken), []byte(token))
}

func SetSessionCookie(w http.ResponseWriter, raw string, secure bool) {
	if secure {
		http.SetCookie(w, newSessionCookie(raw, int(SessionTTL/time.Second), true))
		return
	}
	setLoopbackSessionCookie(w, raw, int(SessionTTL/time.Second))
}

func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	if secure {
		http.SetCookie(w, newSessionCookie("", -1, true))
		return
	}
	setLoopbackSessionCookie(w, "", -1)
}

func newSessionCookie(raw string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{Name: SessionCookie, Value: raw, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge}
}

func setLoopbackSessionCookie(w http.ResponseWriter, raw string, maxAge int) {
	// This is the only intentionally insecure-cookie branch: it is selected
	// exclusively for direct loopback HTTP access when no trusted proxy has
	// supplied HTTPS evidence; all externally served requests use Secure.
	// codeql[go/cookie-secure-not-set]
	http.SetCookie(w, newSessionCookie(raw, maxAge, false))
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
	_, ok := VerifyTOTPAtStep(secret, code, at)
	return ok
}

// VerifyTOTPAtStep validates a code and returns the exact accepted time step.
// Callers that authenticate a user must persist that step with the store's
// atomic replay guard; the pure VerifyTOTPAt helper remains suitable for
// validating a pending enrollment secret.
func VerifyTOTPAtStep(secret, code string, at time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	raw, err := decodeTOTPSecret(secret)
	if err != nil || len(raw) < 10 {
		return 0, false
	}
	now := at.Unix() / 30
	for offset := int64(-1); offset <= 1; offset++ {
		step := now + offset
		if step >= 0 && totpCodeRaw(raw, step) == code {
			return step, true
		}
	}
	return 0, false
}

func totpCode(secret string, counter int64) string {
	raw, err := decodeTOTPSecret(secret)
	if err != nil {
		return ""
	}
	return totpCodeRaw(raw, counter)
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil, errors.New("TOTP secret is empty")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
}

func totpCodeRaw(raw []byte, counter int64) string {
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
		raw, err := randomBytes(16)
		if err != nil {
			return nil, nil, err
		}
		plain[i] = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		salt, err := randomBytes(16)
		if err != nil {
			return nil, nil, err
		}
		h := sha256.New()
		_, _ = h.Write(salt)
		_, _ = h.Write([]byte(plain[i]))
		hashes[i] = "v2$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + hex.EncodeToString(h.Sum(nil))
	}
	return plain, hashes, nil
}

func PasswordRequirements() map[string]any {
	return map[string]any{"minimum_length": PasswordMin, "algorithm": "argon2id"}
}
