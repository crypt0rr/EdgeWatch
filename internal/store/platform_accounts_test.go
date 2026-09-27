package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Platform administrators of the fixtures. insertTenantUser names each
// after its ID.
const (
	platformRoot  = "00000000-0000-0000-0000-00000000fa01"
	platformOther = "00000000-0000-0000-0000-00000000fa02"
)

// platformAudit is the audit entry of an action by the platform
// administrator platformRoot.
func platformAudit(action string) AuditEntry {
	return AuditEntry{Action: action, Detail: "test", ActorUserID: platformRoot, ActorUsername: platformRoot}
}

// A platform setup token lives in the one setup token row with the platform
// purpose:
//
//   - it is issued only once the first setup is complete and while no
//     enabled platform administrator exists, at most once a minute, and it
//     replaces an unused token only when asked; each issue is recorded in
//     platform scope with the host as its actor;
//   - the initial setup neither reports nor accepts it, and it accepts no
//     initial token;
//   - redeeming it creates an enabled platform administrator without a
//     tenant, with a username unique across tenants, uses the token, and
//     records the creation in platform scope; a wrong, expired, or used
//     token, or an enabled platform administrator that already exists,
//     writes nothing.
func TestPlatformSetupTokenLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	ps := f.store.Platform()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

	for _, invalid := range []struct {
		hash    string
		expires time.Time
	}{{" ", now.Add(time.Hour)}, {"platform-hash", now}} {
		if err := ps.IssuePlatformSetupToken(ctx, invalid.hash, invalid.expires, now, false); err == nil {
			t.Fatalf("token %q expiring %s was issued", invalid.hash, invalid.expires)
		}
	}
	if err := ps.IssuePlatformSetupToken(ctx, "platform-hash", now.Add(15*time.Minute), now, false); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM setup_tokens WHERE id=1 AND token_hash='platform-hash' AND purpose=? AND used_at IS NULL`, SetupTokenPurposePlatform); got != 1 {
		t.Fatalf("platform setup token rows = %d", got)
	}
	if got, want := lastAudit(t, f.store, "platform_admin.setup_token_issued"), (auditRecord{"<null>", AuditActorHost}); got != want {
		t.Fatalf("token audit record = %+v, want %+v", got, want)
	}

	// The initial setup does not report or accept a platform token.
	if _, err := ps.GetSetupToken(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("initial setup token = %v, want ErrNotFound", err)
	}
	if usable, err := ps.SetupTokenUsable(ctx, "platform-hash", now); err != nil || usable {
		t.Fatalf("platform token usable for the first setup = %v, %v", usable, err)
	}
	if err := ps.CompleteSetup(ctx, "platform-hash", Admin{Username: "second-admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}, now); err == nil || !strings.Contains(err.Error(), "invalid setup token") {
		t.Fatalf("first setup with a platform token = %v", err)
	}
	if err := ps.ConsumeSetupToken(ctx, "platform-hash", now); err == nil {
		t.Fatal("an initial-token consumer used the platform token")
	}

	// Within a minute nothing is issued, not even to replace the token.
	if err := ps.IssuePlatformSetupToken(ctx, "second-hash", now.Add(16*time.Minute), now.Add(30*time.Second), true); !errors.Is(err, ErrSetupTokenRateLimited) {
		t.Fatalf("token within a minute = %v, want ErrSetupTokenRateLimited", err)
	}
	later := now.Add(2 * time.Minute)
	if err := ps.IssuePlatformSetupToken(ctx, "second-hash", later.Add(15*time.Minute), later, false); !errors.Is(err, ErrSetupTokenOutstanding) {
		t.Fatalf("unconfirmed replacement = %v, want ErrSetupTokenOutstanding", err)
	}
	if err := ps.IssuePlatformSetupToken(ctx, "second-hash", later.Add(15*time.Minute), later, true); err != nil {
		t.Fatal(err)
	}
	if usable, err := ps.PlatformSetupTokenUsable(ctx, "platform-hash", later); err != nil || usable {
		t.Fatalf("replaced token usable = %v, %v", usable, err)
	}
	if usable, err := ps.PlatformSetupTokenUsable(ctx, "second-hash", later); err != nil || !usable {
		t.Fatalf("new token usable = %v, %v", usable, err)
	}

	// An initial token is never a platform token.
	if err := ps.PutSetupTokenAt(ctx, "initial-hash", later.Add(time.Hour), later); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM setup_tokens WHERE purpose=?`, SetupTokenPurposeInitial); got != 1 {
		t.Fatalf("initial tokens after the replacement = %d", got)
	}
	if _, err := ps.CompletePlatformSetup(ctx, "initial-hash", "root", "hash-root", later); err == nil || !strings.Contains(err.Error(), "invalid setup token") {
		t.Fatalf("platform setup with an initial token = %v", err)
	}
	later = later.Add(2 * time.Minute)
	if err := ps.IssuePlatformSetupToken(ctx, "third-hash", later.Add(15*time.Minute), later, true); err != nil {
		t.Fatal(err)
	}

	users := countRows(t, f.store.DB, `SELECT COUNT(*) FROM users`)
	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	for _, refused := range []struct {
		name, hash, username, passwordHash string
		at                                 time.Time
		want                               string
	}{
		{"wrong token", "wrong-hash", "root", "hash-root", later, "invalid setup token"},
		{"expired token", "third-hash", "root", "hash-root", later.Add(15 * time.Minute), "expired or already used"},
		{"username of a unit's account", "third-hash", "ADMIN-B", "hash-root", later, ErrUsernameUnavailable.Error()},
		{"invalid username", "third-hash", "root/admin", "hash-root", later, "username must not contain"},
		{"no password", "third-hash", "root", "!pending", later, "password hash is required"},
	} {
		if _, err := ps.CompletePlatformSetup(ctx, refused.hash, refused.username, refused.passwordHash, refused.at); err == nil || !strings.Contains(err.Error(), refused.want) {
			t.Errorf("%s: %v, want %q", refused.name, err, refused.want)
		}
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM users`); got != users {
		t.Fatalf("refused setups wrote %d accounts", got-users)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("refused setups wrote %d audit records", got-audits)
	}

	root, err := ps.CompletePlatformSetup(ctx, "third-hash", " Root ", "hash-root", later)
	if err != nil {
		t.Fatal(err)
	}
	if root.Role != RolePlatformAdmin || root.TenantID != "" || root.Username != "root" || !root.Enabled || root.Revision != 1 {
		t.Fatalf("platform administrator = %+v", root)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM users WHERE id=? AND tenant_id IS NULL AND role=? AND enabled=1 AND password_hash='hash-root'`, root.ID, RolePlatformAdmin); got != 1 {
		t.Fatalf("platform administrator rows = %d", got)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM setup_tokens WHERE id=1 AND used_at IS NOT NULL`); got != 1 {
		t.Fatal("the platform setup token was not used")
	}
	if got, want := lastAudit(t, f.store, "platform_admin.setup"), (auditRecord{"<null>", AuditActorPlatform}); got != want {
		t.Fatalf("setup audit record = %+v, want %+v", got, want)
	}
	// The account belongs to no tenant.
	for _, scope := range []TenantScope{f.a, f.b} {
		if _, err := f.store.Tenant(scope).GetUser(ctx, root.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("tenant %s reads the platform administrator: %v", scope.ID(), err)
		}
	}
	if _, err := f.store.TenantScopeForSession(ctx, Session{UserID: root.ID, Role: RolePlatformAdmin}); !errors.Is(err, ErrNoTenantScope) {
		t.Fatalf("platform administrator scope = %v", err)
	}
	if _, err := ps.CompletePlatformSetup(ctx, "third-hash", "root-again", "hash", later); err == nil || !strings.Contains(err.Error(), "expired or already used") {
		t.Fatalf("used token = %v", err)
	}

	// No token is issued while an enabled platform administrator exists.
	later = later.Add(2 * time.Minute)
	if err := ps.IssuePlatformSetupToken(ctx, "fourth-hash", later.Add(15*time.Minute), later, true); !errors.Is(err, ErrPlatformAdminConfigured) {
		t.Fatalf("token with a platform administrator = %v, want ErrPlatformAdminConfigured", err)
	}
	// A disabled one does not count, but a token cannot create a second
	// administrator once one is enabled again.
	if _, err := f.store.DB.Exec(`UPDATE users SET enabled=0 WHERE id=?`, root.ID); err != nil {
		t.Fatal(err)
	}
	if err := ps.IssuePlatformSetupToken(ctx, "fourth-hash", later.Add(15*time.Minute), later, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`UPDATE users SET enabled=1 WHERE id=?`, root.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ps.CompletePlatformSetup(ctx, "fourth-hash", "second-root", "hash", later); !errors.Is(err, ErrPlatformAdminConfigured) {
		t.Fatalf("second platform administrator = %v, want ErrPlatformAdminConfigured", err)
	}

	// The schema keeps a platform administrator without a tenant, and a
	// tenant's account with one.
	for _, statement := range []string{
		`UPDATE users SET tenant_id='` + DefaultTenantID + `' WHERE id='` + root.ID + `'`,
		`UPDATE users SET role='administrator' WHERE id='` + root.ID + `'`,
		`UPDATE users SET role='platform_admin' WHERE id='` + accountAdminA + `'`,
		`UPDATE users SET tenant_id=NULL WHERE id='` + accountOperatorB + `'`,
	} {
		if _, err := f.store.DB.Exec(statement); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
			t.Errorf("%s: %v, want a CHECK constraint failure", statement, err)
		}
	}
}

// Before the first setup there is no platform setup token: the initial
// token comes first, and it stays as it is.
func TestPlatformSetupTokenNeedsTheFirstSetup(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.Platform().PutSetupTokenAt(ctx, "initial-hash", now.Add(time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Platform().IssuePlatformSetupToken(ctx, "platform-hash", now.Add(time.Hour), now, true); !errors.Is(err, ErrSetupIncomplete) {
		t.Fatalf("token before the first setup = %v, want ErrSetupIncomplete", err)
	}
	if usable, err := s.Platform().SetupTokenUsable(ctx, "initial-hash", now); err != nil || !usable {
		t.Fatalf("initial token after the refusal = %v, %v", usable, err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM security_audit WHERE action='platform_admin.setup_token_issued'`); got != 0 {
		t.Fatalf("refused token wrote %d audit records", got)
	}
}

// A platform administrator invites only a unit's administrators, into an
// active unit, and only when it is an enabled platform administrator. The
// invitation is recorded in the unit's audit with the platform actor kind,
// and the other unit is untouched.
func TestPlatformInvitesOnlyUnitAdministrators(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	ps := f.store.Platform()
	now := time.Now().UTC()
	beforeA, beforeB := tenantAccountDigest(t, f.store, f.a), tenantAccountDigest(t, f.store, f.b)
	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	invite := func(tenantID, username, role string, audit AuditEntry) (User, error) {
		return ps.InviteUnitAdmin(ctx, tenantID, User{Username: username, Role: role, PasswordHash: "!pending"}, "invite-"+username, now, now.Add(time.Hour), audit)
	}

	for _, refused := range []struct {
		name, tenant, role string
		audit              AuditEntry
		want               error
	}{
		{"an operator", secondTenantID, RoleOperator, platformAudit("user.created"), ErrAccountNotPermitted},
		{"a viewer", secondTenantID, RoleViewer, platformAudit("user.created"), ErrAccountNotPermitted},
		{"a platform administrator", secondTenantID, RolePlatformAdmin, platformAudit("user.created"), ErrAccountNotPermitted},
		{"by a unit's administrator", secondTenantID, RoleAdministrator, accountAudit("user.created"), ErrAccountNotPermitted},
		{"by nobody", secondTenantID, RoleAdministrator, AuditEntry{Action: "user.created"}, ErrAccountNotPermitted},
		{"into an unknown unit", accountUnknown, RoleAdministrator, platformAudit("user.created"), ErrNotFound},
		{"into no unit", "", RoleAdministrator, platformAudit("user.created"), ErrNotFound},
	} {
		if _, err := invite(refused.tenant, "invitee", refused.role, refused.audit); !errors.Is(err, refused.want) {
			t.Errorf("invite %s = %v, want %v", refused.name, err, refused.want)
		}
	}
	for _, invalid := range []struct {
		hash    string
		expires time.Time
	}{{" ", now.Add(time.Hour)}, {"invite", now}} {
		if _, err := ps.InviteUnitAdmin(ctx, secondTenantID, User{Username: "invitee", PasswordHash: "!pending"}, invalid.hash, now, invalid.expires, platformAudit("user.created")); err == nil {
			t.Errorf("invite with token %q expiring %s was stored", invalid.hash, invalid.expires)
		}
	}
	if tenantAccountDigest(t, f.store, f.a) != beforeA || tenantAccountDigest(t, f.store, f.b) != beforeB {
		t.Fatal("a refused invitation changed a unit's accounts")
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("refused invitations wrote %d audit records", got-audits)
	}

	// The invitee chooses its own password: one that the platform
	// administrator names is ignored.
	user, err := ps.InviteUnitAdmin(ctx, secondTenantID, User{Username: "new-admin-b", PasswordHash: "chosen-by-the-platform", TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP"}, "invite-new-admin-b", now, now.Add(time.Hour), platformAudit("user.created"))
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != RoleAdministrator || user.TenantID != secondTenantID || user.Enabled || user.PasswordHash != "!pending" || user.TOTPEnabled {
		t.Fatalf("invited administrator = %+v", user)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM users WHERE id=? AND password_hash='!pending' AND totp_enabled=0 AND totp_secret=''`, user.ID); got != 1 {
		t.Fatal("the invited administrator's credentials were set by the platform")
	}
	if _, err := f.store.Tenant(f.b).GetUser(ctx, user.ID); err != nil {
		t.Fatalf("unit B's invited administrator: %v", err)
	}
	if _, err := f.store.Tenant(f.a).GetUser(ctx, user.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unit A reads unit B's invited administrator: %v", err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites WHERE id_hash='invite-new-admin-b' AND user_id=? AND issuer_user_id=? AND used_at IS NULL`, user.ID, platformRoot); got != 1 {
		t.Fatalf("invitation rows = %d", got)
	}
	if got, want := lastAudit(t, f.store, "user.created"), (auditRecord{secondTenantID, AuditActorPlatform}); got != want {
		t.Fatalf("invitation audit record = %+v, want %+v", got, want)
	}
	if tenantAccountDigest(t, f.store, f.a) != beforeA {
		t.Fatal("an invitation into unit B changed unit A's accounts")
	}

	// A unit that is not active takes no invitation, and neither does the
	// platform administrator's own tenant, which it has none of.
	if _, err := f.store.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, TenantStateDisabled, secondTenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := invite(secondTenantID, "paused-admin-b", RoleAdministrator, platformAudit("user.created")); !errors.Is(err, ErrTenantNotActive) {
		t.Fatalf("invite into a disabled unit = %v, want ErrTenantNotActive", err)
	}
	if _, err := f.store.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, TenantStateDeleted, secondTenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := invite(secondTenantID, "gone-admin-b", RoleAdministrator, platformAudit("user.created")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invite into a deleted unit = %v, want ErrNotFound", err)
	}
}

// A platform administrator resets only a unit's administrators. The rule
// keys on the account: an operator or another platform administrator is not
// permitted, and an account of another unit than the one named is not
// found. A unit's administrator cannot act through the platform's store.
// The reset link is recorded in the account's unit with the platform actor
// kind.
func TestPlatformResetsOnlyUnitAdministrators(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	insertTenantUser(t, f.store, platformOther, nil, RolePlatformAdmin)
	ps := f.store.Platform()
	now := time.Now().UTC()
	beforeA, beforeB := tenantAccountDigest(t, f.store, f.a), tenantAccountDigest(t, f.store, f.b)
	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	reset := func(tenantID, userID string, audit AuditEntry) error {
		return ps.IssueUnitAdminPasswordReset(ctx, tenantID, userID, "reset-"+userID, now, now.Add(time.Hour), audit)
	}
	for _, refused := range []struct {
		name, tenant, user string
		audit              AuditEntry
		want               error
	}{
		{"a unit's operator", secondTenantID, accountOperatorB, platformAudit("user.password_reset_issued"), ErrAccountNotPermitted},
		{"another platform administrator", secondTenantID, platformOther, platformAudit("user.password_reset_issued"), ErrAccountNotPermitted},
		{"another platform administrator without a unit", "", platformOther, platformAudit("user.password_reset_issued"), ErrNotFound},
		{"itself", secondTenantID, platformRoot, platformAudit("user.password_reset_issued"), ErrAccountNotPermitted},
		{"another unit's administrator", secondTenantID, accountAdminA, platformAudit("user.password_reset_issued"), ErrNotFound},
		{"an administrator in the wrong unit", DefaultTenantID, accountAdminB, platformAudit("user.password_reset_issued"), ErrNotFound},
		{"an unknown account", secondTenantID, accountUnknown, platformAudit("user.password_reset_issued"), ErrNotFound},
		{"by a unit's administrator", secondTenantID, accountAdminB, accountAudit("user.password_reset_issued"), ErrAccountNotPermitted},
	} {
		if err := reset(refused.tenant, refused.user, refused.audit); !errors.Is(err, refused.want) {
			t.Errorf("reset %s = %v, want %v", refused.name, err, refused.want)
		}
	}
	if tenantAccountDigest(t, f.store, f.a) != beforeA || tenantAccountDigest(t, f.store, f.b) != beforeB {
		t.Fatal("a refused reset changed a unit's accounts")
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites WHERE user_id IN (?,?)`, platformRoot, platformOther); got != 0 {
		t.Fatalf("refused resets stored %d links for platform administrators", got)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("refused resets wrote %d audit records", got-audits)
	}

	if err := reset(secondTenantID, accountAdminB, platformAudit("user.password_reset_issued")); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites WHERE id_hash=? AND user_id=? AND issuer_user_id=? AND used_at IS NULL`, "reset-"+accountAdminB, accountAdminB, platformRoot); got != 1 {
		t.Fatalf("reset link rows = %d", got)
	}
	if got, want := lastAudit(t, f.store, "user.password_reset_issued"), (auditRecord{secondTenantID, AuditActorPlatform}); got != want {
		t.Fatalf("reset audit record = %+v, want %+v", got, want)
	}
	if tenantAccountDigest(t, f.store, f.a) != beforeA {
		t.Fatal("a reset in unit B changed unit A's accounts")
	}

	// A unit that is not active takes no reset.
	if _, err := f.store.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, TenantStateDisabled, secondTenantID); err != nil {
		t.Fatal(err)
	}
	if err := ps.IssueUnitAdminPasswordReset(ctx, secondTenantID, accountAdminB, "reset-paused", now, now.Add(time.Hour), platformAudit("user.password_reset_issued")); !errors.Is(err, ErrTenantNotActive) {
		t.Fatalf("reset in a disabled unit = %v, want ErrTenantNotActive", err)
	}
}

// A unit's administrator resets and changes only its own unit's accounts:
// each unit's store finds neither the other unit's administrator nor a
// platform administrator, and writes nothing for them.
func TestUnitAdministratorsCannotTouchOtherAccounts(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	now := time.Now().UTC()
	beforeA, beforeB := tenantAccountDigest(t, f.store, f.a), tenantAccountDigest(t, f.store, f.b)
	for _, check := range []struct {
		scope   TenantScope
		account string
		actor   string
	}{
		{f.a, accountAdminB, accountAdminA},
		{f.b, accountAdminA, accountAdminB},
		{f.a, platformRoot, accountAdminA},
		{f.b, platformRoot, accountAdminB},
	} {
		ts := f.store.Tenant(check.scope)
		audit := AuditEntry{Action: "user.password_reset_issued", ActorUserID: check.actor}
		if err := ts.CreateUserInviteWithAudit(ctx, "cross-"+check.account, check.account, now, now.Add(time.Hour), audit); !errors.Is(err, ErrNotFound) {
			t.Errorf("unit %s reset %s: %v, want ErrNotFound", check.scope.ID(), check.account, err)
		}
		target := fixtureAccount(t, f, check.account)
		// A tenant's store refuses the platform role on its own; with a
		// tenant's role, the account is still not found.
		target.Role, target.Enabled = RoleAdministrator, false
		if err := ts.UpdateUser(ctx, target, true, audit); !errors.Is(err, ErrNotFound) {
			t.Errorf("unit %s disabled %s: %v, want ErrNotFound", check.scope.ID(), check.account, err)
		}
		if err := ts.DeleteUserSessionsWithAudit(ctx, check.account, audit); !errors.Is(err, ErrNotFound) {
			t.Errorf("unit %s signed out %s: %v, want ErrNotFound", check.scope.ID(), check.account, err)
		}
	}
	if tenantAccountDigest(t, f.store, f.a) != beforeA || tenantAccountDigest(t, f.store, f.b) != beforeB {
		t.Fatal("a unit changed another unit's accounts")
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM users WHERE id=? AND enabled=1`, platformRoot); got != 1 {
		t.Fatal("a unit disabled the platform administrator")
	}
}

// A platform administrator's own account is changed through a store bound
// to it: it reaches no other account, the role never changes, the last
// enabled platform administrator stays enabled, and every change is
// recorded in platform scope.
func TestPlatformAccountStoreAndLastPlatformAdmin(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	insertTenantUser(t, f.store, platformOther, nil, RolePlatformAdmin)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	for _, session := range []struct{ hash, user string }{{"root-1", platformRoot}, {"root-2", platformRoot}, {"other-1", platformOther}} {
		if _, err := f.store.DB.Exec(`INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?,'csrf')`, session.hash, session.user, stamp, stamp, expires); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.store.DB.Exec(`INSERT INTO user_invites(id_hash,user_id,issuer_user_id,created_at,expires_at,used_at) VALUES('root-issued',?,?,?,?,NULL)`, accountAdminB, platformRoot, stamp, expires); err != nil {
		t.Fatal(err)
	}
	beforeA, beforeB := tenantAccountDigest(t, f.store, f.a), tenantAccountDigest(t, f.store, f.b)
	root := f.store.Platform().Account(platformRoot)
	user, err := root.GetUser(ctx, platformRoot)
	if err != nil || user.Role != RolePlatformAdmin || user.TenantID != "" {
		t.Fatalf("platform administrator = %+v, %v", user, err)
	}

	// The store reaches only its own account.
	other, err := f.store.Platform().Account(platformOther).GetUser(ctx, platformOther)
	if err != nil {
		t.Fatal(err)
	}
	var nilStore *PlatformAccountStore
	unitAdmin := fixtureAccount(t, f, accountAdminA)
	unitAdmin.Role = RolePlatformAdmin
	for name, write := range map[string]func() error{
		"read another platform administrator": func() error { _, err := root.GetUser(ctx, platformOther); return err },
		"update another platform administrator": func() error {
			other.PasswordHash = "stolen"
			return root.UpdateUser(ctx, other, true, platformAudit("user.password_changed"))
		},
		"save another platform administrator": func() error {
			return root.SaveUserSecurity(ctx, other, []string{}, true, true, platformAudit("user.totp_disabled"))
		},
		"sign out another platform administrator": func() error {
			return root.DeleteUserSessionsWithAudit(ctx, platformOther, platformAudit("user.sessions_revoked"))
		},
		"read a unit's administrator": func() error {
			_, err := f.store.Platform().Account(accountAdminA).GetUser(ctx, accountAdminA)
			return err
		},
		"sign out a unit's administrator": func() error {
			return f.store.Platform().Account(accountAdminA).DeleteUserSessionsWithAudit(ctx, accountAdminA, platformAudit("user.sessions_revoked"))
		},
		"save a unit's administrator": func() error {
			return f.store.Platform().Account(accountAdminA).SaveUserSecurity(ctx, unitAdmin, nil, false, true, platformAudit("user.password_reset"))
		},
		"use a nil store": func() error { _, err := nilStore.GetUser(ctx, ""); return err },
	} {
		if err := write(); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v, want ErrNotFound", name, err)
		}
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, platformOther); got != 1 {
		t.Fatalf("the other platform administrator has %d sessions, want 1", got)
	}

	// The role never changes.
	demoted := user
	demoted.Role = RoleAdministrator
	if err := root.UpdateUser(ctx, demoted, true, platformAudit("user.updated")); !errors.Is(err, ErrAccountNotPermitted) {
		t.Fatalf("demotion = %v, want ErrAccountNotPermitted", err)
	}

	// Self-service writes, each recorded in platform scope.
	user.DisplayName, user.PasswordHash = "Root", "new-hash"
	if err := root.UpdateUser(ctx, user, true, platformAudit("user.password_changed")); err != nil {
		t.Fatal(err)
	}
	if got, want := lastAudit(t, f.store, "user.password_changed"), (auditRecord{"<null>", AuditActorPlatform}); got != want {
		t.Fatalf("password audit record = %+v, want %+v", got, want)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, platformRoot); got != 0 {
		t.Fatalf("a password change kept %d sessions", got)
	}
	if err := root.UpdateUser(ctx, user, false, platformAudit("user.updated")); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision = %v, want ErrConflict", err)
	}
	user, err = root.GetUser(ctx, platformRoot)
	if err != nil || user.DisplayName != "Root" || user.PasswordHash != "new-hash" || user.Revision != 2 {
		t.Fatalf("after the password change = %+v, %v", user, err)
	}
	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	if err := root.UpdateUser(ctx, user, false, platformAudit("user.updated")); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatal("an update that changed nothing was recorded")
	}
	user.Revision++
	renamed := user
	renamed.Username = "admin-a"
	if err := root.UpdateUser(ctx, renamed, false, platformAudit("user.updated")); !errors.Is(err, ErrUsernameUnavailable) {
		t.Fatalf("rename to a unit's username = %v, want ErrUsernameUnavailable", err)
	}
	renamed.Username = "bad/name"
	if err := root.UpdateUser(ctx, renamed, false, platformAudit("user.updated")); err == nil {
		t.Fatal("an invalid username was saved")
	}
	for _, hash := range []string{"session-a", "session-b"} {
		if _, err := f.store.DB.Exec(`INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?,'csrf')`, hash, platformRoot, stamp, stamp, expires); err != nil {
			t.Fatal(err)
		}
	}
	user.TOTPEnabled, user.TOTPSecret = true, "JBSWY3DPEHPK3PXP"
	if err := root.SaveUserSecurityPreservingSession(ctx, user, []string{"v2$root-code"}, true, true, platformAudit("user.totp_enabled"), "session-a"); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, platformRoot); got != 1 {
		t.Fatalf("TOTP enrolment kept %d sessions, want the preserved one", got)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE user_id=? AND id_hash='session-a'`, platformRoot); got != 1 {
		t.Fatal("TOTP enrolment did not keep the preserved session")
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM recovery_codes WHERE user_id=?`, platformRoot); got != 1 {
		t.Fatalf("recovery codes = %d, want 1", got)
	}
	if err := root.DeleteUserSessionsWithAudit(ctx, platformRoot, platformAudit("user.sessions_revoked")); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, platformRoot); got != 0 {
		t.Fatalf("sessions after revocation = %d", got)
	}
	for _, action := range []string{"user.totp_enabled", "user.sessions_revoked"} {
		if got, want := lastAudit(t, f.store, action), (auditRecord{"<null>", AuditActorPlatform}); got != want {
			t.Errorf("%s audit record = %+v, want %+v", action, got, want)
		}
	}

	// One of two enabled platform administrators may be disabled, which
	// signs it out and revokes the links it issued; the last may not.
	user, err = root.GetUser(ctx, platformRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES('root-3',?,?,?,?,'csrf')`, platformRoot, stamp, stamp, expires); err != nil {
		t.Fatal(err)
	}
	user.Enabled = false
	if err := root.UpdateUser(ctx, user, false, platformAudit("user.updated")); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, platformRoot); got != 0 {
		t.Fatalf("a disabled platform administrator kept %d sessions", got)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites WHERE id_hash='root-issued' AND used_at IS NOT NULL`); got != 1 {
		t.Fatal("a disabled platform administrator's link stayed usable")
	}
	last := f.store.Platform().Account(platformOther)
	other, err = last.GetUser(ctx, platformOther)
	if err != nil {
		t.Fatal(err)
	}
	other.Enabled = false
	if err := last.UpdateUser(ctx, other, false, platformAudit("user.updated")); !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("disabling the last platform administrator = %v, want ErrLastPlatformAdmin", err)
	}
	if err := last.SaveUserSecurity(ctx, other, nil, false, true, platformAudit("user.password_reset")); !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("disabling the last platform administrator's security = %v, want ErrLastPlatformAdmin", err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM users WHERE id=? AND enabled=1`, platformOther); got != 1 {
		t.Fatal("the last platform administrator was disabled")
	}
	if tenantAccountDigest(t, f.store, f.a) != beforeA {
		t.Fatal("platform account changes changed unit A's accounts")
	}
	if after := tenantAccountDigest(t, f.store, f.b); after == beforeB {
		t.Fatal("disabling the issuer left its link in unit B usable")
	}
}

// The platform audit writer records in platform scope, whatever tenant the
// entry or its actor names, and more than one tenant is counted only while
// the second is not deleted.
func TestPlatformAuditAndTenantCount(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	if err := f.store.Platform().AuditEntry(ctx, AuditEntry{Action: "auth.login_failed", TenantID: secondTenantID, ActorUserID: accountAdminB, ActorKind: AuditActorUnit}); err != nil {
		t.Fatal(err)
	}
	if got, want := lastAudit(t, f.store, "auth.login_failed"), (auditRecord{"<null>", AuditActorUnit}); got != want {
		t.Fatalf("platform audit record = %+v, want %+v", got, want)
	}
	// A tenant's own writer cannot be moved to platform scope.
	entry := AuditEntry{Action: "user.logout", ActorUserID: accountAdminB}
	entry.platform = true
	if err := f.store.Tenant(f.b).AuditEntry(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if got, want := lastAudit(t, f.store, "user.logout"), (auditRecord{secondTenantID, AuditActorUnit}); got != want {
		t.Fatalf("tenant audit record = %+v, want %+v", got, want)
	}

	if multiple, err := f.store.Platform().HasMultipleTenants(ctx); err != nil || !multiple {
		t.Fatalf("two tenants counted as multiple = %v, %v", multiple, err)
	}
	for _, state := range []string{TenantStateDisabled, TenantStateDeleting} {
		if _, err := f.store.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, state, secondTenantID); err != nil {
			t.Fatal(err)
		}
		if multiple, err := f.store.Platform().HasMultipleTenants(ctx); err != nil || !multiple {
			t.Fatalf("a %s second tenant counted as multiple = %v, %v", state, multiple, err)
		}
	}
	if _, err := f.store.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, TenantStateDeleted, secondTenantID); err != nil {
		t.Fatal(err)
	}
	if multiple, err := f.store.Platform().HasMultipleTenants(ctx); err != nil || multiple {
		t.Fatalf("a deleted second tenant counted as multiple = %v, %v", multiple, err)
	}
}
