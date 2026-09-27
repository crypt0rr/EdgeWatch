package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// DefaultTenantID identifies the default tenant. Schema 51 creates it with
// this fixed ID, like LegacyAdminUserID and the built-in scanner profile IDs,
// so existing rows can be attributed to it with a constant column default
// instead of a lookup. Every installation has exactly one tenant for now, and
// it owns the update alert routing and the public status page.
const DefaultTenantID = "00000000-0000-0000-0000-000000000100"

// RolePlatformAdmin is the role of a platform administrator. Schema 52 allows
// it only on an account without a tenant. No product API creates such an
// account yet, and ValidateUserRole does not accept the role.
const RolePlatformAdmin = "platform_admin"

// Tenant states, as tenants.state stores them.
const (
	TenantStateActive   = "active"
	TenantStateDisabled = "disabled"
	TenantStateDeleting = "deleting"
	TenantStateDeleted  = "deleted"
)

// ErrNoTenantScope reports that an account, a tenant ID, or a TenantStore
// names no tenant whose data may be used. It wraps ErrNotFound, so a caller
// that maps a missing resource to "not found" keeps failing closed.
var ErrNoTenantScope = fmt.Errorf("%w: no tenant scope", ErrNotFound)

// TenantScope names the one tenant whose data a TenantStore reads and writes.
// Its field is unexported, so only this package makes a scope: from the
// signed-in account with TenantScopeForSession, from a tenant ID for the host
// CLI and system code with TenantScopeByID, or with DefaultTenantScope. The
// zero value names no tenant, and every TenantStore method refuses it.
type TenantScope struct{ id string }

// DefaultTenantScope returns the scope of the default tenant.
func DefaultTenantScope() TenantScope { return TenantScope{id: DefaultTenantID} }

// ID returns the tenant ID, or "" for the zero scope.
func (scope TenantScope) ID() string { return scope.id }

// Valid reports whether the scope names a tenant.
func (scope TenantScope) Valid() bool { return scope.id != "" }

// TenantScopeForSession returns the scope of the signed-in account's tenant.
// It reads the account's tenant from users, so a session row cannot choose
// the tenant. A platform administrator has no tenant, and a tenant that is
// not active lends no scope; both are refused with ErrNoTenantScope.
// GetSession reads Session.TenantID from users in the same way. A session
// that names another tenant than its account has now is refused too, so a
// request never acts in a tenant other than the one it authenticated in.
func (s *Store) TenantScopeForSession(ctx context.Context, session Session) (TenantScope, error) {
	if session.Role == RolePlatformAdmin || session.UserID == "" {
		return TenantScope{}, ErrNoTenantScope
	}
	var role, tenantID, state string
	err := s.reader().QueryRowContext(ctx, `SELECT u.role,COALESCE(u.tenant_id,''),COALESCE(t.state,'') FROM users AS u LEFT JOIN tenants AS t ON t.id=u.tenant_id WHERE u.id=?`, session.UserID).Scan(&role, &tenantID, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return TenantScope{}, fmt.Errorf("%w: user %s", ErrNoTenantScope, session.UserID)
	}
	if err != nil {
		return TenantScope{}, err
	}
	if role == RolePlatformAdmin || tenantID == "" || state != TenantStateActive || (session.TenantID != "" && session.TenantID != tenantID) {
		return TenantScope{}, fmt.Errorf("%w: user %s", ErrNoTenantScope, session.UserID)
	}
	return TenantScope{id: tenantID}, nil
}

// TenantScopeByID returns the scope of the tenant with the given ID. It is
// for the host CLI and for system code that works through the tenants in
// turn. Web handlers take their scope from the session instead, and a test
// keeps internal/web from calling this. A missing or deleted tenant has no
// scope. The other states do, because retention runs for a disabled tenant
// and the purge for a tenant being deleted; the caller decides what the
// state allows.
func (s *Store) TenantScopeByID(ctx context.Context, id string) (TenantScope, error) {
	var state string
	err := s.reader().QueryRowContext(ctx, `SELECT state FROM tenants WHERE id=?`, id).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && state == TenantStateDeleted) {
		return TenantScope{}, fmt.Errorf("%w: tenant %s", ErrNoTenantScope, id)
	}
	if err != nil {
		return TenantScope{}, err
	}
	return TenantScope{id: id}, nil
}

// Why a method may stay on Store. Store itself holds no tenant scope, so it
// keeps only what is global: work on one tenant's data goes through Tenant
// or Public, the daemon's work across tenants through System, and platform
// data through Platform.
const (
	// globalLifecycle: construction, lifecycle and deployment settings.
	globalLifecycle = "lifecycle"
	// globalScopes: the scoped stores and the resolvers that make their
	// scopes.
	globalScopes = "scopes"
	// globalMaintenance: backup, verification and startup migration of the
	// whole database.
	globalMaintenance = "maintenance"
	// globalAccount: sign-in, sessions, one-time codes, recovery codes,
	// invitations and the audit records of sign-in and the host CLI. They run
	// before any tenant scope exists and act on one account, named by its
	// ID, a username, a session, or a token, whatever its tenant. What they
	// return carries the account's tenant, from which TenantScopeForSession
	// makes the scope. Expiry and "sign out everyone" act on every account.
	globalAccount = "account"
	// globalLegacyAdmin: the original administrator's account, fixed to
	// LegacyAdminUserID in the default tenant, which the host CLI resets
	// without a scope and whose owner changes it from the console.
	globalLegacyAdmin = "legacy administrator"
	// globalShared: data that every tenant shares, the public RDAP cache and
	// the identifiers of live updates.
	globalShared = "shared"
)

// globalStoreMethods lists every method that stays on Store, exported or
// not, with the reason it is global. A test keeps the list in step with the
// methods, so a method that works on one tenant's data cannot be added to
// Store. The tenant SQL lint accepts statements that touch tenant data
// without the tenant predicate only in the account and legacy administrator
// methods, which are global by design.
var globalStoreMethods = map[string]string{
	"Close":               globalLifecycle,
	"FilePath":            globalLifecycle,
	"SetAuthKeyPath":      globalLifecycle,
	"SetTargetExclusions": globalLifecycle,
	"authKeyForWrite":     globalLifecycle,
	"reader":              globalLifecycle,
	"validateManagedJob":  globalLifecycle,

	"Tenant":                globalScopes,
	"System":                globalScopes,
	"Platform":              globalScopes,
	"Public":                globalScopes,
	"TenantScopeForSession": globalScopes,
	"TenantScopeByID":       globalScopes,
	"PublicScopeBySlug":     globalScopes,

	"Backup":                    globalMaintenance,
	"Verify":                    globalMaintenance,
	"MigrateAdminCompatibility": globalMaintenance,
	"maintainSearchIndexes":     globalMaintenance,
	"rebuildLatestScanHosts":    globalMaintenance,
	"repairLatestScanHosts":     globalMaintenance,

	"GetSession":                              globalAccount,
	"GetAccount":                              globalAccount,
	"GetUserByUsername":                       globalAccount,
	"readUser":                                globalAccount,
	"SetUserLastLogin":                        globalAccount,
	"ActivateUser":                            globalAccount,
	"ActivationTokenUsable":                   globalAccount,
	"ConsumeUserInvite":                       globalAccount,
	"ConsumeTOTPStep":                         globalAccount,
	"CreateSession":                           globalAccount,
	"CreateSessionWithAudit":                  globalAccount,
	"CreateSessionForUserWithAudit":           globalAccount,
	"CreateSessionForUserWithAuditEntry":      globalAccount,
	"CreateSessionForUserIfCurrent":           globalAccount,
	"CreateSessionForUserWithPasswordUpgrade": globalAccount,
	"CreateSessionForUserWithPasswordUpgradeIfCurrent": globalAccount,
	"TouchSession":                   globalAccount,
	"TouchSessionIfStale":            globalAccount,
	"DeleteSession":                  globalAccount,
	"DeleteSessionWithAudit":         globalAccount,
	"DeleteSessionWithAuditEntry":    globalAccount,
	"deleteSessionWithoutAudit":      globalAccount,
	"DeleteAllSessions":              globalAccount,
	"DeleteAllSessionsWithAudit":     globalAccount,
	"DeleteExpiredSessions":          globalAccount,
	"SaveRecoveryCodes":              globalAccount,
	"SaveRecoveryCodesForUser":       globalAccount,
	"ConsumeRecoveryCode":            globalAccount,
	"ConsumeRecoveryCodeForUser":     globalAccount,
	"ConsumeRecoveryCodeTextForUser": globalAccount,
	"RecoveryCodeCount":              globalAccount,
	"Audit":                          globalAccount,
	"AuditEntry":                     globalAccount,
	"sealTOTPSecret":                 globalAccount,
	"sealTOTPSecretForOwner":         globalAccount,
	"sealTOTPSecretVersion":          globalAccount,
	"openTOTPSecret":                 globalAccount,
	"openTOTPSecretForOwner":         globalAccount,
	"userTOTPForSave":                globalAccount,

	"GetAdmin":                   globalLegacyAdmin,
	"SaveAdmin":                  globalLegacyAdmin,
	"SaveAdminSecurity":          globalLegacyAdmin,
	"SaveAdminSecurityWithAudit": globalLegacyAdmin,
	"SaveAdminSecurityWithAuditPreservingSession": globalLegacyAdmin,
	"adminTOTPForSave": globalLegacyAdmin,

	"GetRDAPCache": globalShared,
	"PutRDAPCache": globalShared,
	"SSECursor":    globalShared,
}

// TenantStore reads and writes the data of one tenant. Every method puts the
// tenant predicate in the same SQL statement that reads the rows: a table
// with a tenant_id column is filtered on it, and a table that belongs to a
// job, a scan, or an account is joined to that parent's tenant. A row of
// another tenant is therefore not found. A TenantStore without a valid scope
// refuses every call with ErrNoTenantScope before it reads anything.
type TenantStore struct {
	store *Store
	scope TenantScope
}

// Tenant returns the store bound to the given tenant.
func (s *Store) Tenant(scope TenantScope) *TenantStore {
	return &TenantStore{store: s, scope: scope}
}

// Scope returns the scope of the store's tenant. It names the tenant of work
// that is not in the database, such as the scans that are running, so that a
// request acts on its own tenant's work only. A store without a valid scope
// returns ErrNoTenantScope.
func (ts *TenantStore) Scope() (TenantScope, error) {
	if err := ts.ready(); err != nil {
		return TenantScope{}, err
	}
	return ts.scope, nil
}

// ready returns ErrNoTenantScope unless the store is bound to a tenant.
func (ts *TenantStore) ready() error {
	if ts == nil || ts.store == nil || !ts.scope.Valid() {
		return ErrNoTenantScope
	}
	return nil
}

// SystemStore is the daemon's access to the data of every tenant: the
// scheduler, retention, the delivery worker, scan cycles, and the tenant
// purge. Web handlers never use it, and a test keeps internal/web from
// calling Store.System.
type SystemStore struct{ store *Store }

// System returns the daemon's cross-tenant store.
func (s *Store) System() *SystemStore { return &SystemStore{store: s} }

// TenantScopes returns the scope of every tenant that has not been deleted,
// the default tenant first, so daemon work can go through the tenants in
// turn.
func (ss *SystemStore) TenantScopes(ctx context.Context) ([]TenantScope, error) {
	return ss.tenantScopes(ctx, `SELECT id FROM tenants WHERE state<>? ORDER BY is_default DESC, id`, TenantStateDeleted)
}

// ActiveTenantScopes returns the scope of every active tenant, the default
// tenant first. The scheduler and the silence watchdog go through these, so
// a paused tenant's jobs are neither scheduled nor judged silent.
func (ss *SystemStore) ActiveTenantScopes(ctx context.Context) ([]TenantScope, error) {
	return ss.tenantScopes(ctx, `SELECT id FROM tenants WHERE state=? ORDER BY is_default DESC, id`, TenantStateActive)
}

// tenantScopes returns a scope for each tenant ID that query selects.
func (ss *SystemStore) tenantScopes(ctx context.Context, query string, args ...any) ([]TenantScope, error) {
	rows, err := ss.store.reader().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scopes []TenantScope
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		scopes = append(scopes, TenantScope{id: id})
	}
	return scopes, rows.Err()
}

// PlatformStore holds the data that belongs to the platform instead of a
// tenant: the tenants themselves, platform administrator accounts, platform
// notification destinations, the update check, and platform audit records.
type PlatformStore struct{ store *Store }

// Platform returns the store for platform data.
func (s *Store) Platform() *PlatformStore { return &PlatformStore{store: s} }

// Tenant describes a tenant as the platform manages it.
type Tenant struct {
	ID        string
	Name      string
	Slug      string
	State     string
	IsDefault bool
}

// Tenants returns every tenant that has not been deleted, the default tenant
// first and the others by name.
func (ps *PlatformStore) Tenants(ctx context.Context) ([]Tenant, error) {
	rows, err := ps.store.reader().QueryContext(ctx, `SELECT id,name,slug,state,is_default FROM tenants WHERE state<>? ORDER BY is_default DESC, name, id`, TenantStateDeleted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []Tenant
	for rows.Next() {
		var tenant Tenant
		var isDefault int
		if err := rows.Scan(&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.State, &isDefault); err != nil {
			return nil, err
		}
		tenant.IsDefault = isDefault != 0
		tenants = append(tenants, tenant)
	}
	return tenants, rows.Err()
}

// PublicScope names the tenant whose published status page an anonymous
// request reads. It carries no account, so a public read returns only what
// the tenant explicitly published. The legacy /public path serves the
// default tenant.
type PublicScope struct{ tenant TenantScope }

// DefaultPublicScope returns the public scope of the default tenant.
func DefaultPublicScope() PublicScope { return PublicScope{tenant: DefaultTenantScope()} }

// TenantID returns the ID of the tenant whose page the scope reads, or "" for
// the zero scope.
func (scope PublicScope) TenantID() string { return scope.tenant.id }
