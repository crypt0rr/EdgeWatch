package auth

import (
	"context"
	"encoding/base32"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// platformSetupTokenTTL is how long a platform setup token is valid, as long
// as the initial setup token.
const platformSetupTokenTTL = 15 * time.Minute

// IssuePlatformSetupToken creates a one-time token, valid for 15 minutes,
// that creates a platform administrator. It is for the host CLI: the clear
// token is returned only to that caller, and the store keeps its hash. The
// store refuses it while an enabled platform administrator exists, before
// the first administrator setup, within a minute of the previous token, and,
// unless replace confirms it, while an unused token is still valid.
func (m *Manager) IssuePlatformSetupToken(ctx context.Context, replace bool) (string, error) {
	raw, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	plain := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	now := m.now()
	if err := m.Store.Platform().IssuePlatformSetupToken(ctx, digest(plain), now.Add(platformSetupTokenTTL), now, replace); err != nil {
		return "", err
	}
	return plain, nil
}

// CompletePlatformSetup redeems a platform setup token and creates the
// platform administrator with the username and password. The token is
// checked before the password is hashed, so a wrong token costs no Argon2id
// work, and the store checks it again in the transaction that creates the
// account and consumes the token.
func (m *Manager) CompletePlatformSetup(ctx context.Context, token, username, password string) (store.User, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return store.User{}, errors.New("setup token is required")
	}
	usable, err := m.Store.Platform().PlatformSetupTokenUsable(ctx, digest(token), m.now())
	if err != nil {
		return store.User{}, err
	}
	if !usable {
		return store.User{}, errors.New("platform administrator setup could not be completed")
	}
	var hash string
	if err := m.withArgon2(ctx, func() error {
		var hashErr error
		hash, hashErr = PasswordHash(password)
		return hashErr
	}); err != nil {
		return store.User{}, err
	}
	return m.Store.Platform().CompletePlatformSetup(ctx, digest(token), username, hash, m.now())
}

// PlatformSetupRequest is CompletePlatformSetup for the web console, with
// the per-client failure budget of the first setup: a client that sends too
// many wrong tokens is refused with ErrRateLimited before any check, and
// each failure is recorded in platform scope. The token's own failure count
// is kept apart from the first setup's.
func (m *Manager) PlatformSetupRequest(ctx context.Context, request *http.Request, token, username, password string) (store.User, error) {
	source := m.sourceScopeFor(request, "platform-setup")
	account := "platform-setup:" + digest(strings.TrimSpace(token))
	if !m.allowScoped(source, account) {
		m.auditRateLimitIn(ctx, "platform-setup", request, true)
		return store.User{}, m.rateLimitError(source, account)
	}
	defer m.releaseScoped(source, account)
	user, err := m.CompletePlatformSetup(ctx, token, username, password)
	if err != nil {
		if !errors.Is(err, ErrRateLimited) {
			m.failedScoped(source, account, "")
		}
		m.recordAuthEvent(ctx, "auth.platform_setup_failed", "platform-setup", "", true, request)
		return store.User{}, err
	}
	m.clearScoped(source, account)
	return user, nil
}

// TOTPEnrollmentRequired reports whether the account must enrol an
// authenticator before it may do more than manage its own account. Once
// more than one business unit exists, every unit administrator and platform
// administrator must use TOTP; with a single unit nothing changes. An
// operator or viewer, and an account with TOTP, never needs to enrol. When
// the units cannot be counted, the rule fails closed and requires it.
func (m *Manager) TOTPEnrollmentRequired(ctx context.Context, user store.User) bool {
	if user.TOTPEnabled || (user.Role != store.RoleAdministrator && user.Role != store.RolePlatformAdmin) {
		return false
	}
	multiple, err := m.Store.Platform().HasMultipleTenants(ctx)
	return err != nil || multiple
}
