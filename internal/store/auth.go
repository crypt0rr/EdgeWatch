package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrAuditUnavailable indicates that a security-sensitive mutation could not
// record its required audit row. Callers should fail closed (or report the
// operation as degraded) rather than claiming a successful audited action.
var ErrAuditUnavailable = errors.New("security audit unavailable")

// auditPersistenceTimeout bounds standalone audit writes while detaching them
// from a request's cancellation and deadline. Mutations that include an audit
// row in their own transaction continue to use the caller context so they can
// roll back together; this helper is only for post-action, non-transactional
// audit records.
const auditPersistenceTimeout = 5 * time.Second

func auditPersistenceContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), auditPersistenceTimeout)
}

// AuditEntry describes a security event that should be committed together
// with the state mutation that caused it. Keeping this small value type in the
// store package lets job, baseline, and notification transactions share the
// same fail-closed audit boundary without exposing database handles to callers.
type AuditEntry struct {
	Action        string
	Detail        string
	ActorUserID   string
	ActorUsername string
	SourceIP      string
	RequestID     string
	// TenantID is the tenant the record belongs to. A TenantStore sets it
	// to its own tenant, which is also the tenant of the account that an
	// account action changes. When it is empty, the record takes the tenant
	// of the account in ActorUserID, which for a console action is the
	// session's tenant, and a record without an account belongs to the
	// default tenant.
	TenantID string
	// ActorKind says who acted: AuditActorUnit, AuditActorHost,
	// AuditActorSystem, or AuditActorPlatform. When it is empty, a record
	// with an ActorUserID takes the kind of that account, and a record
	// without one is the daemon's.
	ActorKind string
	// platform records the entry in platform scope, with no tenant, whatever
	// TenantID and the actor say. Only the store's platform writers set it,
	// so no caller outside the store can move a record out of a tenant's
	// audit.
	platform bool
}

// Audit actor kinds, as security_audit.actor_kind stores them. A record
// written before schema 51 has an empty kind.
const (
	// AuditActorUnit is an account of a tenant, or a request to a tenant's
	// console that has not signed in.
	AuditActorUnit = "unit"
	// AuditActorHost is the host CLI.
	AuditActorHost = "host"
	// AuditActorSystem is the daemon acting on its own.
	AuditActorSystem = "system"
	// AuditActorPlatform is a platform administrator.
	AuditActorPlatform = "platform"
)

// Admin is the original administrator: the account with LegacyAdminUserID,
// which setup creates in the default tenant. The Admin methods of Store are
// compatibility methods for that one account, bound to the default tenant.
type Admin struct {
	// Username is the stable administrator identity used for authentication.
	Username string
	// DisplayName is the label shown in the web console. It is deliberately
	// separate from Username so changing the label never changes sign-in.
	DisplayName  string
	PasswordHash string
	TOTPSecret   string
	TOTPEnabled  bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	// TOTPSecretStored retains the encrypted database value when the key is
	// unavailable, so unrelated admin updates do not overwrite it.
	TOTPSecretStored string
	TOTPSecretError  error
	// Revision mirrors the authoritative users row for the legacy administrator
	// identity. It lets compatibility admin writers participate in the same
	// optimistic-concurrency guard as multi-user updates.
	Revision int64
}

type Session struct {
	IDHash      string
	UserID      string
	Username    string
	DisplayName string
	Role        string
	// TenantID is the tenant of the session's account, read from users as
	// TenantScopeForSession reads it, so the session row cannot choose it.
	// It is empty for a platform administrator and for an account that no
	// longer exists.
	TenantID   string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	CSRFToken  string
	// SourceIP is populated by the HTTP authentication layer after resolving
	// a trusted proxy chain. It is not persisted in the session row.
	SourceIP string
	// TOTPEnrollmentRequired restricts the session to the account's own
	// self-service until the account enrols an authenticator. The HTTP
	// authentication layer sets it on every request, from the account and
	// the number of tenants. It is not persisted in the session row.
	TOTPEnrollmentRequired bool
}

type SetupToken struct {
	ExpiresAt time.Time
	IssuedAt  time.Time
	Used      bool
}

// GetAdmin returns the original administrator, the users row with
// LegacyAdminUserID in the default tenant, without mutating the database.
// Schema 52 retired the legacy admins row, so a missing users row is
// ErrNotFound. TOTP ciphertext upgrades are performed by
// MigrateAdminCompatibility during daemon startup.
func (s *Store) GetAdmin(ctx context.Context) (Admin, error) {
	var a Admin
	var stored, created, updated string
	var totp int
	err := s.reader().QueryRowContext(ctx, `SELECT username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at,revision FROM users WHERE id=? AND tenant_id=?`, LegacyAdminUserID, DefaultTenantID).
		Scan(&a.Username, &a.DisplayName, &a.PasswordHash, &stored, &totp, &created, &updated, &a.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, ErrNotFound
	}
	if err != nil {
		return Admin{}, err
	}
	a.DisplayName = adminDisplayName(a)
	a.TOTPEnabled = totp != 0
	a.CreatedAt, a.UpdatedAt = scanTime(created), scanTime(updated)
	a.TOTPSecretStored = stored
	secret, _, secretErr := s.openTOTPSecretForOwner(LegacyAdminUserID, stored)
	if secretErr != nil {
		a.TOTPSecretError = secretErr
	} else {
		a.TOTPSecret = secret
	}
	return a, nil
}

// HasAdministrator reports whether the installation is configured: whether
// an administrator account exists in any tenant. Setup creates the first
// one, so setup stays closed once any tenant has an administrator. Only
// users counts: schema 52 retired the legacy admins row, and a database
// without a users table is an error rather than an unconfigured one.
func (ps *PlatformStore) HasAdministrator(ctx context.Context) (bool, error) {
	var present int
	err := ps.store.reader().QueryRowContext(ctx, `SELECT 1 FROM users WHERE role=? LIMIT 1`, RoleAdministrator).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SaveAdmin writes the original administrator to its users row, and creates
// that row in the default tenant when it is missing.
func (s *Store) SaveAdmin(ctx context.Context, a Admin) error {
	stored, err := s.adminTOTPForSave(a)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := saveAdminExec(ctx, tx, a, stored); err != nil {
		return err
	}
	return tx.Commit()
}

type contextExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func saveAdminExec(ctx context.Context, execer contextExecer, a Admin, stored string) error {
	// Create the users row when it is missing. The update below writes the
	// values in both cases.
	if _, err := execer.ExecContext(ctx, `INSERT OR IGNORE INTO users(id,tenant_id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, LegacyAdminUserID, DefaultTenantID, a.Username, adminDisplayName(a), RoleAdministrator, a.PasswordHash, stored, boolInt(a.TOTPEnabled), 1, a.CreatedAt.UTC().Format(time.RFC3339Nano), a.UpdatedAt.UTC().Format(time.RFC3339Nano), ""); err != nil {
		return err
	}
	expectedRevision := a.Revision
	if expectedRevision > 0 {
		result, updateErr := execer.ExecContext(ctx, `UPDATE users SET username=?,display_name=?,password_hash=?,totp_secret=?,totp_enabled=?,updated_at=?,revision=revision+1 WHERE id=? AND tenant_id=? AND revision=?`, a.Username, adminDisplayName(a), a.PasswordHash, stored, boolInt(a.TOTPEnabled), a.UpdatedAt.UTC().Format(time.RFC3339Nano), LegacyAdminUserID, DefaultTenantID, expectedRevision)
		if updateErr != nil {
			return updateErr
		}
		if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
			if affectedErr != nil {
				return affectedErr
			}
			return ErrConflict
		}
		return nil
	}
	result, err := execer.ExecContext(ctx, `UPDATE users SET username=?,display_name=?,password_hash=?,totp_secret=?,totp_enabled=?,updated_at=?,revision=revision+1 WHERE id=? AND tenant_id=?`, a.Username, adminDisplayName(a), a.PasswordHash, stored, boolInt(a.TOTPEnabled), a.UpdatedAt.UTC().Format(time.RFC3339Nano), LegacyAdminUserID, DefaultTenantID)
	if err != nil {
		return err
	}
	// The insert above creates the row when it can. An original
	// administrator that is still missing, because another account holds
	// the username, or that is outside the default tenant, is not updated
	// and is reported instead of being skipped silently.
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
		if affectedErr != nil {
			return affectedErr
		}
		return ErrNotFound
	}
	return nil
}

func adminDisplayName(a Admin) string {
	if name := strings.TrimSpace(a.DisplayName); name != "" {
		return name
	}
	if username := strings.TrimSpace(a.Username); username != "" {
		return username
	}
	return "admin"
}

// SaveAdminSecurity commits an administrator mutation and its dependent
// authentication state as one transaction. A nil recoveryCodes slice leaves
// existing recovery codes untouched; a non-nil slice replaces them (including
// an empty slice, which clears them). This prevents a successful credential
// update from being reported when session revocation, recovery-code rotation,
// or the corresponding audit record failed.
func (s *Store) SaveAdminSecurity(ctx context.Context, a Admin, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, auditAction, auditDetail string) error {
	return s.SaveAdminSecurityWithAudit(ctx, a, recoveryCodes, replaceRecoveryCodes, revokeSessions, AuditEntry{Action: auditAction, Detail: auditDetail})
}

// SaveAdminSecurityWithAudit is the actor-aware form used by the web console.
// The legacy string-argument wrapper above remains for CLI and older callers.
func (s *Store) SaveAdminSecurityWithAudit(ctx context.Context, a Admin, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit AuditEntry) error {
	return s.SaveAdminSecurityWithAuditPreservingSession(ctx, a, recoveryCodes, replaceRecoveryCodes, revokeSessions, audit, "", NoTOTPStep)
}

// SaveAdminSecurityWithAuditPreservingSession applies an administrator security
// mutation while revoking every other session for that account. The optional
// preserved hash is used by TOTP enrollment so the browser can keep displaying
// the one-time recovery codes returned by the same request. An empty hash keeps
// the historical behavior and revokes all administrator sessions. A TOTP
// enrolment passes the time step of the code that confirmed the new secret
// as totpStep, which is recorded as used in the same transaction, so that
// code is not accepted again; any other save passes NoTOTPStep.
func (s *Store) SaveAdminSecurityWithAuditPreservingSession(ctx context.Context, a Admin, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit AuditEntry, preserveSessionHash string, totpStep int64) error {
	stored, err := s.adminTOTPForSave(a)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The current state tells what the save changes. The save writes neither
	// the role nor the enabled state, and a missing account, which the save
	// creates, changes nothing that it had.
	current := accountState{role: RoleAdministrator, enabled: true, passwordHash: a.PasswordHash}
	var currentEnabled int
	if err := tx.QueryRowContext(ctx, `SELECT role,enabled,password_hash FROM users WHERE id=? AND tenant_id=?`, LegacyAdminUserID, DefaultTenantID).Scan(&current.role, &currentEnabled, &current.passwordHash); err == nil {
		current.enabled = currentEnabled != 0
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := saveAdminExec(ctx, tx, a, stored); err != nil {
		return err
	}
	if err := recordEnrolledTOTPStepTx(ctx, tx, LegacyAdminUserID, totpStep, time.Now().UTC()); err != nil {
		return err
	}
	if replaceRecoveryCodes {
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=?`, LegacyAdminUserID); err != nil {
			return err
		}
		for _, hash := range recoveryCodes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(id_hash,user_id) VALUES(?,?)`, hash, LegacyAdminUserID); err != nil {
				return err
			}
		}
	}
	// The records belong to the account's tenant, the default tenant.
	audit.TenantID = DefaultTenantID
	// Password and TOTP changes for the compatibility administrator end its
	// own sessions, not those of unrelated operator and viewer accounts.
	// Older databases have its sessions attributed to the stable legacy
	// administrator ID by migration 12, or to no account.
	after := current
	after.passwordHash = a.PasswordHash
	records, err := applyAccountTransitionTx(ctx, tx, accountTransition{
		userID: LegacyAdminUserID, username: a.Username, tenantID: DefaultTenantID,
		before: current, after: after,
		revokeSessions: revokeSessions, preserveSessionHash: preserveSessionHash, at: time.Now().UTC(), audit: audit,
	})
	if err != nil {
		return err
	}
	if err := insertAuditEntries(ctx, tx, append([]AuditEntry{audit}, records...), time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) adminTOTPForSave(a Admin) (string, error) {
	if !a.TOTPEnabled || a.TOTPSecret == "" {
		if a.TOTPEnabled && a.TOTPSecret == "" && a.TOTPSecretStored != "" {
			return a.TOTPSecretStored, nil
		}
		if a.TOTPEnabled {
			return "", ErrTOTPSecretLocked
		}
		return "", nil
	}
	return s.sealTOTPSecretForOwner(LegacyAdminUserID, a.TOTPSecret)
}

// PutSetupTokenAt stores a fresh setup token and records when it was issued.
// The timestamp is persisted so host recovery commands can enforce a rate
// limit across short-lived CLI processes.
func (ps *PlatformStore) PutSetupTokenAt(ctx context.Context, hash string, expires, issuedAt time.Time) error {
	_, err := ps.store.DB.ExecContext(ctx, initialSetupTokenSQL, hash, expires.UTC().Format(time.RFC3339Nano), issuedAt.UTC().Format(time.RFC3339Nano))
	return err
}

// Setup token purposes, as setup_tokens.purpose stores them. The table holds
// one token at a time: an initial token creates the default tenant's first
// administrator, and a platform token creates a platform administrator. Each
// token is accepted only for its own purpose.
const (
	SetupTokenPurposeInitial  = "initial"
	SetupTokenPurposePlatform = "platform"
)

// initialSetupTokenSQL replaces the setup token with an initial one. REPLACE
// deletes the previous row, so the new row takes the purpose column's
// default, the initial purpose, whatever the previous token was for. The
// statement names no purpose so that it also fits a database before schema
// 51, which a host command may open without migrating it.
const initialSetupTokenSQL = `INSERT OR REPLACE INTO setup_tokens(id,token_hash,expires_at,used_at,issued_at) VALUES(1,?,?,NULL,?)`

// GetSetupToken returns the state of the initial setup token, or ErrNotFound
// when none was issued. A platform setup token is not reported.
func (ps *PlatformStore) GetSetupToken(ctx context.Context) (SetupToken, error) {
	var expires string
	var issued string
	var used sql.NullString
	err := ps.store.reader().QueryRowContext(ctx, `SELECT expires_at,used_at,issued_at FROM setup_tokens WHERE id=1 AND purpose=?`, SetupTokenPurposeInitial).Scan(&expires, &used, &issued)
	if errors.Is(err, sql.ErrNoRows) {
		return SetupToken{}, ErrNotFound
	}
	if err != nil {
		return SetupToken{}, err
	}
	return SetupToken{ExpiresAt: scanTime(expires), IssuedAt: scanTime(issued), Used: used.Valid}, nil
}

var ErrSetupTokenRateLimited = errors.New("setup token was issued too recently; try again later")

// ReissueSetupToken atomically replaces the one-time setup token, but only
// while no administrator exists. It is intended for a host-authorized CLI
// recovery path; the token itself is returned only to that caller and never
// enters an API response or audit detail.
func (ps *PlatformStore) ReissueSetupToken(ctx context.Context, hash string, expires, now time.Time) error {
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := requireNoAdministratorTx(ctx, tx); err != nil {
		return err
	}
	var issued string
	if err = tx.QueryRowContext(ctx, `SELECT issued_at FROM setup_tokens WHERE id=1`).Scan(&issued); err == nil {
		if previous := scanTime(issued); !previous.IsZero() && now.UTC().Sub(previous) < time.Minute {
			return ErrSetupTokenRateLimited
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err = tx.ExecContext(ctx, initialSetupTokenSQL, hash, expires.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	// The token creates the default tenant's first administrator, so the
	// record belongs to that tenant, as it did before tenants existed.
	if err = insertAuditEntryExec(ctx, tx, AuditEntry{Action: "admin.setup_token_reissued", Detail: "setup token reissued from host CLI", TenantID: DefaultTenantID, ActorKind: AuditActorHost}, now.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// requireNoAdministratorTx fails when an administrator account exists. It is
// the in-transaction form of HasAdministrator for the setup token writers.
func requireNoAdministratorTx(ctx context.Context, tx *sql.Tx) error {
	var administrators int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role=?`, RoleAdministrator).Scan(&administrators); err != nil {
		return err
	}
	if administrators > 0 {
		return errors.New("administrator is already configured")
	}
	return nil
}

// CompleteSetup consumes the token and creates the one permitted administrator
// in the default tenant in one transaction, preventing a token race from
// creating two accounts.
func (ps *PlatformStore) CompleteSetup(ctx context.Context, tokenHash string, admin Admin, now time.Time) error {
	storedSecret, err := ps.store.adminTOTPForSave(admin)
	if err != nil {
		return err
	}
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var expires string
	var used sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT expires_at,used_at FROM setup_tokens WHERE id=1 AND token_hash=? AND purpose=?`, tokenHash, SetupTokenPurposeInitial).Scan(&expires, &used); errors.Is(err, sql.ErrNoRows) {
		return errors.New("invalid setup token")
	} else if err != nil {
		return err
	}
	if used.Valid || !now.Before(scanTime(expires)) {
		return errors.New("setup token expired or already used")
	}
	if err := requireNoAdministratorTx(ctx, tx); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, LegacyAdminUserID, DefaultTenantID, admin.Username, adminDisplayName(admin), RoleAdministrator, admin.PasswordHash, storedSecret, boolInt(admin.TOTPEnabled), 1, admin.CreatedAt.UTC().Format(time.RFC3339Nano), admin.UpdatedAt.UTC().Format(time.RFC3339Nano), ""); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE setup_tokens SET used_at=? WHERE id=1 AND used_at IS NULL AND purpose=?`, now.UTC().Format(time.RFC3339Nano), SetupTokenPurposeInitial)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("setup token expired or already used")
	}
	// Setup is a request to the console that creates the default tenant's
	// first administrator, so the record belongs to that tenant.
	if err = insertAuditEntryExec(ctx, tx, AuditEntry{Action: "admin.setup", Detail: "administrator created", TenantID: DefaultTenantID, ActorKind: AuditActorUnit}, now.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// ErrTenantNotActive reports that an account or a job belongs to a tenant
// that is not active. A tenant that is disabled or being deleted stops
// sign-in, the redemption of its activation links, and the start of its
// scans.
var ErrTenantNotActive = errors.New("the tenant is not active")

// RequireActiveAccountTenant fails with ErrTenantNotActive when the account
// belongs to a tenant that is not active, as the session insert does. Sign-in
// checks it before it spends a one-time factor, so a sign-in that the
// session insert would refuse uses up no recovery code or TOTP time step.
// The session insert checks again in its own transaction, which stays the
// authoritative check.
func (s *Store) RequireActiveAccountTenant(ctx context.Context, userID string) error {
	return requireActiveAccountTenantTx(ctx, s.reader(), userID)
}

// requireActiveAccountTenantTx fails with ErrTenantNotActive when the
// account belongs to a tenant that is not active. It reads the tenant from
// users, as TenantScopeForSession does. An account without a tenant, a
// platform administrator, has no tenant to check, and neither has an
// unknown account; the caller's own checks refuse those. queryer is the
// caller's transaction, or the store's reader for the check before one.
func requireActiveAccountTenantTx(ctx context.Context, queryer rowQueryer, userID string) error {
	var state string
	err := queryer.QueryRowContext(ctx, `SELECT t.state FROM users AS u JOIN tenants AS t ON t.id=u.tenant_id WHERE u.id=?`, userID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if state != TenantStateActive {
		return ErrTenantNotActive
	}
	return nil
}

// SessionIdleTimeout is how long a session stays valid without activity.
// Authentication refuses a session idle for longer, and the expired-session
// cleanup removes it.
const SessionIdleTimeout = 24 * time.Hour

// MaxSessionsPerAccount is the number of sessions one account keeps. A new
// session removes the account's least recently used sessions beyond it, so
// repeated sign-ins cannot grow the sessions table without bound.
const MaxSessionsPerAccount = 20

// insertSessionTx inserts a session of the account in tx, and removes the
// account's least recently used sessions beyond MaxSessionsPerAccount. The
// new session is the most recently used one, so it always stays.
func insertSessionTx(ctx context.Context, tx *sql.Tx, idHash, userID, csrf string, created, expires time.Time) error {
	stamp := created.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?,?)`, idHash, userID, stamp, stamp, expires.UTC().Format(time.RFC3339Nano), csrf); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? AND id_hash IN (SELECT id_hash FROM sessions WHERE user_id=? AND id_hash<>? ORDER BY julianday(last_seen_at) DESC, julianday(created_at) DESC, id_hash DESC LIMIT -1 OFFSET ?)`, userID, userID, idHash, MaxSessionsPerAccount-1)
	return err
}

// ErrRecoveryCodeUsed reports that the recovery code a sign-in presented was
// used, or replaced, before the sign-in could record it.
var ErrRecoveryCodeUsed = errors.New("recovery code was already used")

// SignInFactor is the one-time factor that a sign-in verified with the
// password: the time step of an accepted TOTP code, or the stored hash of a
// matched recovery code. CreateSignInSession records it in the transaction
// that creates the session, so a sign-in that creates no session spends no
// factor.
type SignInFactor struct {
	// TOTPStep is the time step of the accepted TOTP code, or NoTOTPStep.
	TOTPStep int64
	// RecoveryCodeHash is the stored hash of the matched recovery code, or
	// empty.
	RecoveryCodeHash string
}

// NoSignInFactor is the factor of a sign-in without a one-time code.
var NoSignInFactor = SignInFactor{TOTPStep: NoTOTPStep}

// SignInSession is the session that a sign-in creates, with the account's
// credential state that the sign-in verified and the one-time factor that it
// presented.
type SignInSession struct {
	UserID string
	// PasswordHash is the password hash that the sign-in verified.
	PasswordHash string
	// UpgradedPasswordHash, when set, replaces PasswordHash in the
	// transaction: the same password hashed with the current work factor.
	UpgradedPasswordHash string
	// Revision and TOTPEnabled are the account's state that the sign-in read.
	Revision    int64
	TOTPEnabled bool
	Factor      SignInFactor
	IDHash      string
	CSRF        string
	Created     time.Time
	Expires     time.Time
	Audit       AuditEntry
}

// CreateSignInSession creates the session of a sign-in in one transaction
// with its checks and records: the account's password, revision, TOTP state,
// and enabled state must still be those the sign-in verified, or it fails with
// ErrSessionCredentialsChanged; its tenant must be active, or it fails with
// ErrTenantNotActive; and the sign-in's one-time factor must still be unused.
// It records the factor, the TOTP time step in the account's replay guard or
// the recovery code as used, failing with ErrTOTPReplay or
// ErrRecoveryCodeUsed when another sign-in recorded it first. It then
// upgrades the password hash when the sign-in asks for it, inserts the
// session, removing the account's least recently used sessions beyond
// MaxSessionsPerAccount, and writes the audit record. When any step fails,
// nothing is kept: the factor stays unused.
func (s *Store) CreateSignInSession(ctx context.Context, session SignInSession) error {
	upgrade := session.UpgradedPasswordHash != ""
	if upgrade && strings.TrimSpace(session.UpgradedPasswordHash) == "" {
		return errors.New("upgraded password hash is required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stamp := session.Created.UTC().Format(time.RFC3339Nano)
	if upgrade {
		if err := requireActiveAccountTenantTx(ctx, tx, session.UserID); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=?,last_login_at=?,updated_at=?,revision=revision+1 WHERE id=? AND password_hash=? AND revision=? AND totp_enabled=? AND enabled=1`, session.UpgradedPasswordHash, stamp, stamp, session.UserID, session.PasswordHash, session.Revision, boolInt(session.TOTPEnabled))
		if err != nil {
			return err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return ErrSessionCredentialsChanged
		}
	} else {
		var passwordHash string
		var totpEnabled, enabled int
		var revision int64
		err = tx.QueryRowContext(ctx, `SELECT password_hash,totp_enabled,enabled,revision FROM users WHERE id=?`, session.UserID).Scan(&passwordHash, &totpEnabled, &enabled, &revision)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSessionCredentialsChanged
		}
		if err != nil {
			return err
		}
		if enabled == 0 || revision != session.Revision || passwordHash != session.PasswordHash || (totpEnabled != 0) != session.TOTPEnabled {
			return ErrSessionCredentialsChanged
		}
		if err := requireActiveAccountTenantTx(ctx, tx, session.UserID); err != nil {
			return err
		}
	}
	if err := recordSignInFactorTx(ctx, tx, session.UserID, session.Factor, session.Created); err != nil {
		return err
	}
	if err := insertSessionTx(ctx, tx, session.IDHash, session.UserID, session.CSRF, session.Created, session.Expires); err != nil {
		return err
	}
	if session.Audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, session.Audit, session.Created.UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// recordSignInFactorTx records the sign-in's one-time factor as spent in tx:
// it raises the account's TOTP replay guard to the accepted step, and marks
// the recovery code used. A factor that another sign-in recorded first fails
// with ErrTOTPReplay or ErrRecoveryCodeUsed. The caller has checked in tx
// that the account may sign in.
func recordSignInFactorTx(ctx context.Context, tx *sql.Tx, userID string, factor SignInFactor, now time.Time) error {
	if factor.TOTPStep >= 0 {
		advanced, err := advanceTOTPStepTx(ctx, tx, userID, factor.TOTPStep, now)
		if err != nil {
			return err
		}
		if !advanced {
			return ErrTOTPReplay
		}
	}
	if factor.RecoveryCodeHash != "" {
		result, err := tx.ExecContext(ctx, `UPDATE recovery_codes SET used_at=? WHERE user_id=? AND id_hash=? AND used_at IS NULL`, now.UTC().Format(time.RFC3339Nano), userID, factor.RecoveryCodeHash)
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err != nil {
			return err
		} else if affected != 1 {
			return ErrRecoveryCodeUsed
		}
	}
	return nil
}

// CreateSessionForUserIfCurrent creates a session only when the credential
// material that was verified by the authentication layer is still current.
// The comparison and insert share one transaction so a password, TOTP, or
// enabled-state change cannot race a successful login and leave a stale
// session behind. It is CreateSignInSession without a one-time factor.
func (s *Store) CreateSessionForUserIfCurrent(ctx context.Context, userID, expectedPasswordHash string, expectedRevision int64, expectedTOTPEnabled bool, idHash, csrf string, created, expires time.Time, audit AuditEntry) error {
	return s.CreateSignInSession(ctx, SignInSession{UserID: userID, PasswordHash: expectedPasswordHash, Revision: expectedRevision, TOTPEnabled: expectedTOTPEnabled, Factor: NoSignInFactor, IDHash: idHash, CSRF: csrf, Created: created, Expires: expires, Audit: audit})
}

// CreateSessionForUserWithPasswordUpgradeIfCurrent atomically upgrades a
// verified legacy password and creates its session only when every credential
// revision still matches the values read before Argon2id verification. It is
// CreateSignInSession with an upgraded hash and without a one-time factor.
func (s *Store) CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx context.Context, userID, previousHash, upgradedHash string, expectedRevision int64, expectedTOTPEnabled bool, idHash, csrf string, created, expires time.Time, audit AuditEntry) error {
	if strings.TrimSpace(upgradedHash) == "" {
		return errors.New("upgraded password hash is required")
	}
	return s.CreateSignInSession(ctx, SignInSession{UserID: userID, PasswordHash: previousHash, UpgradedPasswordHash: upgradedHash, Revision: expectedRevision, TOTPEnabled: expectedTOTPEnabled, Factor: NoSignInFactor, IDHash: idHash, CSRF: csrf, Created: created, Expires: expires, Audit: audit})
}

// GetSession returns the session with the given hash, with the tenant of
// its account. It stays global: authentication reads it before any tenant
// scope exists. The tenant comes from users, as TenantScopeForSession reads
// it; a session row from before accounts existed, with no user ID, belongs
// to the original administrator.
func (s *Store) GetSession(ctx context.Context, idHash string) (Session, error) {
	var v Session
	var created, lastSeen, expires string
	err := s.reader().QueryRowContext(ctx, `SELECT s.id_hash,s.user_id,s.created_at,s.last_seen_at,s.expires_at,s.csrf_token,COALESCE(u.tenant_id,'') FROM sessions AS s LEFT JOIN users AS u ON u.id=CASE WHEN s.user_id='' THEN ? ELSE s.user_id END WHERE s.id_hash=?`, LegacyAdminUserID, idHash).Scan(&v.IDHash, &v.UserID, &created, &lastSeen, &expires, &v.CSRFToken, &v.TenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	v.CreatedAt, v.LastSeenAt, v.ExpiresAt = scanTime(created), scanTime(lastSeen), scanTime(expires)
	return v, nil
}

func (s *Store) TouchSession(ctx context.Context, idHash string, lastSeen, expires time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET last_seen_at=?,expires_at=? WHERE id_hash=?`, lastSeen.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano), idHash)
	return err
}

// TouchSessionIfStale advances a session's idle timestamp only when its
// current timestamp is at or before staleBefore. The predicate makes refreshes
// from multiple tabs coalesce to one writer operation per activity interval.
func (s *Store) TouchSessionIfStale(ctx context.Context, idHash string, lastSeen, expires, staleBefore time.Time) (bool, error) {
	result, err := s.DB.ExecContext(ctx, `UPDATE sessions SET last_seen_at=?,expires_at=? WHERE id_hash=? AND julianday(last_seen_at) <= julianday(?)`, lastSeen.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano), idHash, staleBefore.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows > 0, err
}

func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	return s.DeleteSessionWithAuditEntry(ctx, idHash, AuditEntry{})
}

func (s *Store) DeleteSessionWithAudit(ctx context.Context, idHash, action, detail string) error {
	return s.DeleteSessionWithAuditEntry(ctx, idHash, AuditEntry{Action: action, Detail: detail})
}

// DeleteSessionWithAuditEntry removes one session and records the actor that
// ended it. The actor fields are additive, so older callers can keep using
// DeleteSessionWithAudit without losing compatibility.
func (s *Store) DeleteSessionWithAuditEntry(ctx context.Context, idHash string, audit AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=?`, idHash); err != nil {
		return err
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, time.Now().UTC()); err != nil {
			// Revocation is security-critical and must not be rolled back just
			// because the audit table is unavailable. Retry the deletion in a
			// detached short-lived context, then report the audit failure so the
			// caller can surface a degraded-but-safe response.
			_ = tx.Rollback()
			if revokeErr := s.deleteSessionWithoutAudit(ctx, idHash); revokeErr != nil {
				return errors.Join(err, revokeErr)
			}
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) deleteSessionWithoutAudit(ctx context.Context, idHash string) error {
	persistCtx, cancel := auditPersistenceContext(ctx)
	defer cancel()
	_, err := s.DB.ExecContext(persistCtx, `DELETE FROM sessions WHERE id_hash=?`, idHash)
	return err
}

// DeleteExpiredSessions removes sessions past their absolute expiry and
// sessions idle for longer than SessionIdleTimeout, which authentication
// already refuses. It is safe to run during maintenance because the
// predicate cannot match a newly touched active session.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	idleBefore := now.Add(-SessionIdleTimeout)
	result, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ? OR julianday(last_seen_at) < julianday(?)`, now.UTC().Format(time.RFC3339Nano), idleBefore.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ConsumeRecoveryCodeTextForUser verifies a presented recovery code against
// the user's unused v2 codes and atomically marks the matching row consumed.
// Unsalted legacy SHA-256 digests are retired by schema migration 38 and are
// never accepted on the authentication path.
func (s *Store) ConsumeRecoveryCodeTextForUser(ctx context.Context, userID, code string, now time.Time) (bool, error) {
	match, err := s.MatchRecoveryCodeForUser(ctx, userID, code)
	if err != nil || match == "" {
		return false, err
	}
	result, err := s.DB.ExecContext(ctx, `UPDATE recovery_codes SET used_at=? WHERE user_id=? AND id_hash=? AND used_at IS NULL`, now.UTC().Format(time.RFC3339Nano), userID, match)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

// MatchRecoveryCodeForUser returns the stored hash of the user's unused v2
// recovery code that matches the presented code, or "" when none does. It
// records nothing: sign-in passes the hash to CreateSignInSession, which
// marks the code used in the transaction that creates the session.
func (s *Store) MatchRecoveryCodeForUser(ctx context.Context, userID, code string) (string, error) {
	code = strings.ToUpper(strings.Join(strings.Fields(code), ""))
	if code == "" {
		return "", nil
	}
	rows, err := s.reader().QueryContext(ctx, `SELECT id_hash FROM recovery_codes WHERE user_id=? AND used_at IS NULL`, userID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var stored string
		if err := rows.Scan(&stored); err != nil {
			return "", err
		}
		if recoveryCodeMatches(stored, code) {
			return stored, nil
		}
	}
	return "", rows.Err()
}

func recoveryCodeMatches(stored, code string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 3 || parts[0] != "v2" {
		return false
	}
	salt, saltErr := base64.RawStdEncoding.DecodeString(parts[1])
	expected, hashErr := hex.DecodeString(parts[2])
	if saltErr != nil || hashErr != nil || len(salt) < 16 || len(expected) != sha256.Size {
		return false
	}
	h := sha256.New()
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte(code))
	return hmac.Equal(h.Sum(nil), expected)
}

// Audit records a security event without an actor outside a transaction.
// The record belongs to the default tenant and to the daemon.
func (s *Store) Audit(ctx context.Context, action, detail string) error {
	persistCtx, cancel := auditPersistenceContext(ctx)
	defer cancel()
	return insertAuditExec(persistCtx, s.DB, action, detail, time.Now().UTC())
}

// AuditEntry records a security event with optional actor attribution. It is
// kept as a small convenience wrapper for mutations that cannot share a
// transaction with their state change (for example, a failed notification
// delivery or a host-initiated recovery action).
//
// It is global, for callers without a tenant scope: authentication, which
// runs before a scope exists, and the host CLI. The record belongs to
// entry.TenantID, or else to the tenant of the account in ActorUserID, or
// else to the default tenant; see AuditEntry. A caller that holds a
// TenantStore uses TenantStore.AuditEntry, which records in the store's
// tenant.
func (s *Store) AuditEntry(ctx context.Context, entry AuditEntry) error {
	persistCtx, cancel := auditPersistenceContext(ctx)
	defer cancel()
	return insertAuditEntryExec(persistCtx, s.DB, entry, time.Now().UTC())
}

// Audit records a security event of the tenant without an actor, outside a
// transaction. The record belongs to the store's tenant and to the daemon.
func (ts *TenantStore) Audit(ctx context.Context, action, detail string) error {
	return ts.AuditEntry(ctx, AuditEntry{Action: action, Detail: detail})
}

// AuditEntry records a security event of the tenant outside a transaction,
// for an action that cannot share one with its state change. The record
// belongs to the store's tenant, whatever tenant the entry names, so a
// tenant cannot write into another tenant's audit.
func (ts *TenantStore) AuditEntry(ctx context.Context, entry AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	persistCtx, cancel := auditPersistenceContext(ctx)
	defer cancel()
	return ts.insertAuditEntry(persistCtx, ts.store.DB, entry, time.Now().UTC())
}

// insertAuditEntry writes an audit record of the store's tenant. The audit
// writes of TenantStore methods go through it or insertAuditEntries, so each
// record belongs to the tenant whose data the method read or changed,
// whatever tenant the entry names. The actor kind still comes from the
// entry or its actor: a platform administrator acting on a tenant is
// recorded in that tenant as a platform actor.
func (ts *TenantStore) insertAuditEntry(ctx context.Context, execer contextExecer, entry AuditEntry, now time.Time) error {
	entry.TenantID, entry.platform = ts.scope.id, false
	return insertAuditEntryExec(ctx, execer, entry, now)
}

// insertPlatformAuditEntry writes an audit record in platform scope: its
// tenant is NULL, whatever the entry or its actor names, so the record
// belongs to the platform's audit and to no tenant's.
func insertPlatformAuditEntry(ctx context.Context, execer contextExecer, entry AuditEntry, now time.Time) error {
	entry.TenantID, entry.platform = "", true
	return insertAuditEntryExec(ctx, execer, entry, now)
}

// insertAuditEntries writes the entries that have an action, each as
// insertAuditEntry does.
func (ts *TenantStore) insertAuditEntries(ctx context.Context, execer contextExecer, entries []AuditEntry, now time.Time) error {
	for _, entry := range entries {
		if strings.TrimSpace(entry.Action) == "" {
			continue
		}
		if err := ts.insertAuditEntry(ctx, execer, entry, now); err != nil {
			return err
		}
	}
	return nil
}

func insertAuditExec(ctx context.Context, execer contextExecer, action, detail string, now time.Time) error {
	return insertAuditEntryExec(ctx, execer, AuditEntry{Action: action, Detail: detail}, now)
}

// auditInsertSQL writes one audit record. A record in platform scope has no
// tenant. Otherwise its tenant and actor kind come from the entry when the
// entry names them, or else from the account in actor_user_id, read in the
// same statement: the account's tenant, which is NULL for a platform
// administrator, and the platform kind for a platform administrator or the
// unit kind for any other account. A record without an account belongs to
// the default tenant and to the daemon. The last four arguments are the
// entry's tenant, actor kind, and actor account, and 1 for platform scope.
const auditInsertSQL = `INSERT INTO security_audit(action,detail,actor_user_id,actor_username,source_ip,request_id,category,created_at,tenant_id,actor_kind) ` +
	`SELECT ?,?,?,?,?,?,?,?,` +
	`CASE WHEN entry.platform=1 THEN NULL WHEN entry.tenant<>'' THEN entry.tenant WHEN actor.id IS NOT NULL THEN actor.tenant_id ELSE '` + DefaultTenantID + `' END,` +
	`CASE WHEN entry.kind<>'' THEN entry.kind WHEN actor.role='` + RolePlatformAdmin + `' THEN '` + AuditActorPlatform + `' WHEN entry.actor<>'' THEN '` + AuditActorUnit + `' ELSE '` + AuditActorSystem + `' END ` +
	`FROM (SELECT ? AS tenant,? AS kind,? AS actor,? AS platform) AS entry LEFT JOIN users AS actor ON actor.id=entry.actor`

func insertAuditEntryExec(ctx context.Context, execer contextExecer, entry AuditEntry, now time.Time) error {
	if strings.TrimSpace(entry.Action) == "" {
		return nil
	}
	switch entry.ActorKind {
	case "", AuditActorUnit, AuditActorHost, AuditActorSystem, AuditActorPlatform:
	default:
		return fmt.Errorf("%w: unknown audit actor kind %q", ErrAuditUnavailable, entry.ActorKind)
	}
	requestContext := auditContextFromContext(ctx)
	if strings.TrimSpace(entry.RequestID) == "" {
		entry.RequestID = requestContext.RequestID
	}
	if strings.TrimSpace(entry.SourceIP) == "" {
		entry.SourceIP = requestContext.SourceIP
	}
	createdAt := now.UTC().Format(time.RFC3339Nano)
	_, err := execer.ExecContext(ctx, auditInsertSQL, entry.Action, entry.Detail, entry.ActorUserID, entry.ActorUsername, entry.SourceIP, entry.RequestID, auditCategory(entry.Action), createdAt, entry.TenantID, entry.ActorKind, entry.ActorUserID, boolInt(entry.platform))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	return nil
}

// insertAuditEntries writes the entries that have an action. A TenantStore
// method uses TenantStore.insertAuditEntries instead, which records them in
// its tenant.
func insertAuditEntries(ctx context.Context, execer contextExecer, entries []AuditEntry, now time.Time) error {
	for _, entry := range entries {
		if strings.TrimSpace(entry.Action) == "" {
			continue
		}
		if err := insertAuditEntryExec(ctx, execer, entry, now); err != nil {
			return err
		}
	}
	return nil
}
