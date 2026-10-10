package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// linkUnused reports whether the activation or password-reset link with the
// token hash is still unused.
func linkUnused(t *testing.T, s *Store, hash string) bool {
	t.Helper()
	return countRows(t, s.DB, `SELECT COUNT(*) FROM user_invites WHERE id_hash=? AND used_at IS NULL`, hash) == 1
}

// linkRevocation is the attribution and detail of one audit record of
// revoked links.
type linkRevocation struct{ tenant, kind, actorID, actorName, detail string }

// linkRevocations returns the audit records with the action, oldest first.
func linkRevocations(t *testing.T, s *Store, action string) []linkRevocation {
	t.Helper()
	rows, err := s.DB.Query(`SELECT COALESCE(tenant_id,'<null>'),actor_kind,actor_user_id,actor_username,detail FROM security_audit WHERE action=? ORDER BY id`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var records []linkRevocation
	for rows.Next() {
		var record linkRevocation
		if err := rows.Scan(&record.tenant, &record.kind, &record.actorID, &record.actorName, &record.detail); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return records
}

// assertOneLinkRevocation fails unless exactly one record with the action
// exists, in the tenant ("<null>" for the platform), by the actor, naming
// the account and the reason.
func assertOneLinkRevocation(t *testing.T, s *Store, action string, want linkRevocation, account, reason string) {
	t.Helper()
	records := linkRevocations(t, s, action)
	if len(records) != 1 {
		t.Fatalf("%s records = %+v, want one", action, records)
	}
	got := records[0]
	if got.tenant != want.tenant || got.kind != want.kind || got.actorID != want.actorID || got.actorName != want.actorName {
		t.Fatalf("%s record = %+v, want %+v", action, got, want)
	}
	if !strings.Contains(got.detail, account) || !strings.Contains(got.detail, reason) {
		t.Fatalf("%s detail %q does not name the account %s and %q", action, got.detail, account, reason)
	}
}

// Changing an account's password by any path ends every other unused
// activation or password-reset link for the account, whoever issued it:
// the account's own change, the host's reset, and the redemption of another
// link, for a unit's account, a platform administrator, and the original
// administrator. Each revocation of a link that was still redeemable is
// recorded with the change's actor and names the account. Another
// account's link stays usable, and a link issued after the change works.
func TestPasswordChangeRevokesTheAccountsOtherLinks(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	t.Run("the account's own change", func(t *testing.T) {
		ctx := context.Background()
		f := newTenantFixture(t)
		ts := f.store.Tenant(f.b)
		operator := fixtureAccount(t, f, accountOperatorB)
		operator.PasswordHash, operator.UpdatedAt = "hash-changed", now
		if err := ts.UpdateUser(ctx, operator, true, AuditEntry{Action: "user.password_changed", Detail: "password changed", ActorUserID: accountOperatorB, ActorUsername: "operator-b"}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.ActivateUser(ctx, "invite-operator-b", "hash-from-old-link", now.Add(time.Minute), AuditEntry{Action: "user.activated"}); err == nil {
			t.Fatal("the reset link issued before the password change set the password")
		}
		if linkUnused(t, f.store, "invite-operator-b") {
			t.Fatal("the reset link issued before the password change is still unused")
		}
		if !linkUnused(t, f.store, "invite-operator-a") {
			t.Fatal("another account's link was revoked")
		}
		assertOneLinkRevocation(t, f.store, "user.activation_revoked", linkRevocation{secondTenantID, AuditActorUnit, accountOperatorB, "operator-b", ""}, "operator-b", "password changed")

		// A link issued after the change sets the password.
		if err := ts.CreateUserInviteWithAudit(ctx, "after-change-b", accountOperatorB, now.Add(time.Minute), now.Add(30*time.Minute), accountAudit("user.password_reset_issued")); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.ActivateUser(ctx, "after-change-b", "hash-from-new-link", now.Add(2*time.Minute), AuditEntry{Action: "user.activated"}); err != nil {
			t.Fatalf("a link issued after the password change: %v", err)
		}
		if account, err := f.store.GetAccount(ctx, accountOperatorB); err != nil || account.PasswordHash != "hash-from-new-link" {
			t.Fatalf("password after the new link = %q, %v", account.PasswordHash, err)
		}
	})
	t.Run("the host's reset", func(t *testing.T) {
		ctx := context.Background()
		f := newTenantFixture(t)
		operator := fixtureAccount(t, f, accountOperatorA)
		operator.PasswordHash, operator.UpdatedAt = "hash-reset", now
		if err := f.store.Tenant(f.a).SaveUserSecurity(ctx, operator, nil, false, true, AuditEntry{Action: "user.password_reset", Detail: "reset", ActorUsername: "host-cli", ActorKind: AuditActorHost}); err != nil {
			t.Fatal(err)
		}
		if usable, err := f.store.ActivationTokenUsable(ctx, "invite-operator-a", now.Add(time.Minute)); err != nil || usable {
			t.Fatalf("the reset link issued before the host's reset is usable = %v, %v", usable, err)
		}
		if linkUnused(t, f.store, "invite-operator-a") {
			t.Fatal("the reset link issued before the host's reset is still unused")
		}
		if !linkUnused(t, f.store, "invite-operator-b") {
			t.Fatal("another account's link was revoked")
		}
		assertOneLinkRevocation(t, f.store, "user.activation_revoked", linkRevocation{DefaultTenantID, AuditActorHost, "", "host-cli", ""}, "operator-a", "password changed")
	})
	t.Run("the redemption of another link", func(t *testing.T) {
		ctx := context.Background()
		f := newTenantFixture(t)
		// The console's issue paths revoke an account's older links, but
		// the fixture leaves them, so the account has two.
		if err := createTestLink(ctx, f.store.Tenant(f.b), "second-operator-b", accountOperatorB, now, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.ActivateUser(ctx, "second-operator-b", "hash-from-second-link", now, AuditEntry{Action: "user.activated", Detail: "activated"}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.ActivateUser(ctx, "invite-operator-b", "hash-from-first-link", now.Add(time.Minute), AuditEntry{Action: "user.activated"}); err == nil {
			t.Fatal("the other link replaced the password that the redeemed link set")
		}
		if !linkUnused(t, f.store, "invite-operator-a") {
			t.Fatal("another account's link was revoked")
		}
		assertOneLinkRevocation(t, f.store, "user.activation_revoked", linkRevocation{secondTenantID, AuditActorUnit, accountOperatorB, "operator-b", ""}, "operator-b", "password changed")
	})
	t.Run("a platform administrator", func(t *testing.T) {
		ctx := context.Background()
		f := newTenantFixture(t)
		insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
		if _, err := f.store.DB.Exec(`INSERT INTO user_invites(id_hash,user_id,issuer_user_id,created_at,expires_at) VALUES('link-root',?,'',?,?)`, platformRoot, now.Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		account := f.store.Platform().Account(platformRoot)
		root, err := account.GetUser(ctx, platformRoot)
		if err != nil {
			t.Fatal(err)
		}
		root.PasswordHash, root.UpdatedAt = "hash-changed", now
		if err := account.UpdateUser(ctx, root, true, platformAudit("user.password_changed")); err != nil {
			t.Fatal(err)
		}
		if linkUnused(t, f.store, "link-root") {
			t.Fatal("the platform administrator's link is still unused")
		}
		if !linkUnused(t, f.store, "invite-operator-a") || !linkUnused(t, f.store, "invite-operator-b") {
			t.Fatal("a unit account's link was revoked")
		}
		assertOneLinkRevocation(t, f.store, auditPlatformAdminActivationRevoked, linkRevocation{"<null>", AuditActorPlatform, platformRoot, platformRoot, ""}, platformRoot, "password changed")
	})
	t.Run("the original administrator", func(t *testing.T) {
		ctx := context.Background()
		f := newTenantFixture(t)
		seedDefaultAdministrator(t, f.store)
		if err := f.store.Tenant(f.a).CreateUserInviteWithAudit(ctx, "link-admin", LegacyAdminUserID, now, now.Add(30*time.Minute), actorAudit(accountAdminA, "user.password_reset_issued")); err != nil {
			t.Fatal(err)
		}
		admin, err := f.store.GetAdmin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		admin.PasswordHash, admin.UpdatedAt = "hash-changed", now
		if err := f.store.SaveAdminSecurityWithAudit(ctx, admin, nil, false, true, AuditEntry{Action: "admin.password_changed", Detail: "password changed", ActorUserID: LegacyAdminUserID, ActorUsername: "admin"}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.ActivateUser(ctx, "link-admin", "hash-from-old-link", now.Add(time.Minute), AuditEntry{Action: "user.activated"}); err == nil {
			t.Fatal("the reset link issued before the password change set the password")
		}
		if linkUnused(t, f.store, "link-admin") {
			t.Fatal("the original administrator's reset link is still unused")
		}
		if !linkUnused(t, f.store, "invite-operator-a") {
			t.Fatal("another account's link was revoked")
		}
		assertOneLinkRevocation(t, f.store, "user.activation_revoked", linkRevocation{DefaultTenantID, AuditActorUnit, LegacyAdminUserID, "admin", ""}, "admin", "password changed")
	})
}

// Revoking an account's links is part of the change that ends them: when
// the revocation fails, the change fails and writes nothing, so a password
// or role never changes while an older link still works.
func TestFailedLinkRevocationStopsTheChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC()
	f := newTenantFixture(t)
	seedDefaultAdministrator(t, f.store)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	for _, link := range []struct{ hash, account string }{{"link-root", platformRoot}, {"link-admin", LegacyAdminUserID}, {"second-operator-b", accountOperatorB}} {
		if _, err := f.store.DB.Exec(`INSERT INTO user_invites(id_hash,user_id,issuer_user_id,created_at,expires_at) VALUES(?,?,'',?,?)`, link.hash, link.account, now.Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.store.DB.Exec(`CREATE TRIGGER keep_links BEFORE UPDATE ON user_invites WHEN OLD.id_hash IN ('invite-operator-a','invite-operator-b','link-root','link-admin') BEGIN SELECT RAISE(ABORT, 'links are protected'); END`); err != nil {
		t.Fatal(err)
	}
	// The accounts as each change writes them. A failed change leaves the
	// account as it was, so the next change starts from the same revision.
	withPassword := func(id string) User {
		t.Helper()
		account := fixtureAccount(t, f, id)
		account.PasswordHash, account.UpdatedAt = "hash-changed", now
		return account
	}
	ownChange, hostReset, rootChange := withPassword(accountOperatorB), withPassword(accountOperatorA), withPassword(platformRoot)
	roleChange := fixtureAccount(t, f, accountOperatorB)
	roleChange.Role = RoleViewer
	for _, change := range []struct {
		name, account string
		run           func() error
	}{
		{"the account's own change", accountOperatorB, func() error {
			return f.store.Tenant(f.b).UpdateUser(ctx, ownChange, true, AuditEntry{Action: "user.password_changed", ActorUserID: accountOperatorB, ActorUsername: "operator-b"})
		}},
		{"a role change", accountOperatorB, func() error {
			return f.store.Tenant(f.b).UpdateUserByAdministrator(ctx, roleChange, true, accountAudit("user.updated"))
		}},
		{"the host's reset", accountOperatorA, func() error {
			return f.store.Tenant(f.a).SaveUserSecurity(ctx, hostReset, nil, false, true, AuditEntry{Action: "user.password_reset", ActorUsername: "host-cli", ActorKind: AuditActorHost})
		}},
		{"a platform administrator's change", platformRoot, func() error {
			return f.store.Platform().Account(platformRoot).UpdateUser(ctx, rootChange, true, platformAudit("user.password_changed"))
		}},
		{"the original administrator's change", LegacyAdminUserID, func() error {
			admin, err := f.store.GetAdmin(ctx)
			if err != nil {
				return err
			}
			admin.PasswordHash = "hash-changed"
			return f.store.SaveAdminSecurityWithAudit(ctx, admin, nil, false, true, AuditEntry{Action: "admin.password_changed", ActorUserID: LegacyAdminUserID, ActorUsername: "admin"})
		}},
		{"the redemption of another link", accountOperatorB, func() error {
			_, err := f.store.ActivateUser(ctx, "second-operator-b", "hash-changed", now, AuditEntry{Action: "user.activated"})
			return err
		}},
	} {
		before := fixtureAccount(t, f, change.account)
		audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
		if err := change.run(); err == nil || !strings.Contains(err.Error(), "links are protected") {
			t.Fatalf("%s with a failed revocation = %v, want the failure", change.name, err)
		}
		if after := fixtureAccount(t, f, change.account); after.PasswordHash != before.PasswordHash || after.Role != before.Role || after.Revision != before.Revision {
			t.Fatalf("%s with a failed revocation changed the account: %+v", change.name, after)
		}
		if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
			t.Fatalf("%s with a failed revocation recorded %d audit records", change.name, got-audits)
		}
	}
	if !linkUnused(t, f.store, "second-operator-b") {
		t.Fatal("a failed redemption used its link")
	}
}

// A write that changes neither the password nor the role keeps the
// account's links: a display name edit, a recovery code rotation, and a
// save of the same password. Nothing records a revocation.
func TestAccountWritesWithoutPasswordOrRoleChangeKeepTheLinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	ts := f.store.Tenant(f.b)
	operator := fixtureAccount(t, f, accountOperatorB)
	operator.DisplayName = "Renamed operator"
	if err := ts.UpdateUser(ctx, operator, false, accountAudit("user.updated")); err != nil {
		t.Fatal(err)
	}
	operator = fixtureAccount(t, f, accountOperatorB)
	if err := ts.SaveUserSecurity(ctx, operator, []string{"v2$rotated-code"}, true, true, accountAudit("user.totp_recovery_codes_rotated")); err != nil {
		t.Fatal(err)
	}
	operator = fixtureAccount(t, f, accountOperatorB)
	if err := ts.SetUserPassword(ctx, accountOperatorB, operator.PasswordHash, true, accountAudit("user.password_changed")); err != nil {
		t.Fatal(err)
	}
	if !linkUnused(t, f.store, "invite-operator-b") {
		t.Fatal("a write that changed neither the password nor the role revoked the link")
	}
	if records := linkRevocations(t, f.store, "user.activation_revoked"); len(records) != 0 {
		t.Fatalf("revocation records = %+v, want none", records)
	}
}

// A change of an account's role ends its unused links, whoever issued
// them: a reset link that the platform administrator issued for a unit
// administrator stops working once the unit demotes that account, and a
// promotion ends the account's links too. The revocation is recorded with
// the unit administrator who changed the role and names the account.
// Another account's link stays usable.
func TestRoleChangeRevokesTheAccountsLinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC()
	f := newTenantFixture(t)
	const secondAdminB = "00000000-0000-0000-0000-00000000bc03"
	insertTenantUser(t, f.store, secondAdminB, secondTenantID, RoleAdministrator)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	if err := f.store.Platform().IssueUnitAdminPasswordReset(ctx, secondTenantID, accountAdminB, "platform-reset-admin-b", now, now.Add(30*time.Minute), platformAudit("user.password_reset_issued")); err != nil {
		t.Fatal(err)
	}
	ts := f.store.Tenant(f.b)
	demoted := fixtureAccount(t, f, accountAdminB)
	demoted.Role, demoted.UpdatedAt = RoleOperator, now
	if err := ts.UpdateUserByAdministrator(ctx, demoted, true, actorAudit(secondAdminB, "user.updated")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ActivateUser(ctx, "platform-reset-admin-b", "hash-from-platform-link", now.Add(time.Minute), AuditEntry{Action: "user.activated"}); err == nil {
		t.Fatal("the platform administrator's reset link set the password of the demoted account")
	}
	if linkUnused(t, f.store, "platform-reset-admin-b") {
		t.Fatal("the platform administrator's reset link for the demoted account is still unused")
	}
	if !linkUnused(t, f.store, "invite-operator-b") || !linkUnused(t, f.store, "invite-operator-a") {
		t.Fatal("another account's link was revoked")
	}
	assertOneLinkRevocation(t, f.store, "user.activation_revoked", linkRevocation{secondTenantID, AuditActorUnit, secondAdminB, "actor", ""}, "admin-b", "role changed")

	promoted := fixtureAccount(t, f, accountOperatorB)
	promoted.Role, promoted.UpdatedAt = RoleAdministrator, now
	if err := ts.UpdateUserByAdministrator(ctx, promoted, true, actorAudit(secondAdminB, "user.updated")); err != nil {
		t.Fatal(err)
	}
	if linkUnused(t, f.store, "invite-operator-b") {
		t.Fatal("the link of the promoted account is still unused")
	}
	if !linkUnused(t, f.store, "invite-operator-a") {
		t.Fatal("another account's link was revoked")
	}
}

// The accounts that newTransitionFixture adds to the tenant fixture, beside
// the original administrator, actorSecondAdminB, platformRoot, and
// platformOther: a pending invitee of unit B, and a pending platform
// administrator.
const (
	transitionPendingB        = "00000000-0000-0000-0000-00000000bc06"
	transitionPendingPlatform = "00000000-0000-0000-0000-00000000fa03"
)

// transitionLinks are the links that newTransitionFixture adds, each for an
// account and by its issuer. An expired link had stopped working before any
// change.
var transitionLinks = []struct {
	hash, account, issuer string
	expired               bool
}{
	{"own-admin-b", accountAdminB, actorSecondAdminB, false},
	{"issued-pending-b", transitionPendingB, accountAdminB, false},
	{"issued-expired-operator-b", accountOperatorB, accountAdminB, true},
	{"own-other", platformOther, platformRoot, false},
	{"own-other-second", platformOther, platformRoot, false},
	{"other-issued-admin-b", accountAdminB, platformOther, false},
	{"other-issued-pending", transitionPendingPlatform, platformOther, false},
	{"other-issued-expired-admin-a", accountAdminA, platformOther, true},
	{"own-admin", LegacyAdminUserID, accountAdminA, false},
	{"own-admin-second", LegacyAdminUserID, accountAdminA, false},
}

// newTransitionFixture is the tenant fixture with the accounts, links, and
// sessions of the account transitions. Unit B keeps a second enabled
// administrator, and the platform a second enabled platform administrator,
// so neither change is refused as the last one's. Each changed account has
// a session besides the fixture's, and the original administrator one from
// before accounts existed, which names no account.
func newTransitionFixture(t *testing.T) tenantFixture {
	t.Helper()
	f := newTenantFixture(t)
	seedDefaultAdministrator(t, f.store)
	insertTenantUser(t, f.store, actorSecondAdminB, secondTenantID, RoleAdministrator)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	insertTenantUser(t, f.store, platformOther, nil, RolePlatformAdmin)
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	for _, pending := range []struct {
		id, username string
		tenant       any
		role         string
	}{{transitionPendingB, "pending-b", secondTenantID, RoleViewer}, {transitionPendingPlatform, "pending-platform", nil, RolePlatformAdmin}} {
		if _, err := f.store.DB.Exec(`INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,enabled,created_at,updated_at) VALUES(?,?,?,?,?,'!pending',0,?,?)`, pending.id, pending.tenant, pending.username, pending.username, pending.role, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range transitionLinks {
		expires := now.Add(time.Hour)
		if link.expired {
			expires = now.Add(-time.Minute)
		}
		if _, err := f.store.DB.Exec(`INSERT INTO user_invites(id_hash,user_id,issuer_user_id,created_at,expires_at) VALUES(?,?,?,?,?)`, link.hash, link.account, link.issuer, now.Add(-time.Hour).Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	for _, session := range []struct{ hash, account string }{{"browser-admin-b", accountAdminB}, {"session-other", platformOther}, {"browser-other", platformOther}, {"session-admin", LegacyAdminUserID}, {"session-legacy", ""}} {
		if _, err := f.store.DB.Exec(`INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?,'csrf')`, session.hash, session.account, stamp, stamp, now.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// transitionOutcome is what a change to an account leaves: the account's
// sessions that stay, the links that the change used or ended, and its
// records of ended links, each as its tenant ("<null>" for platform scope)
// and detail.
type transitionOutcome struct {
	account string
	keep    []string
	ended   []string
	records [][2]string
}

// sortedStrings returns the rows of a one-column query, sorted.
func sortedStrings(t *testing.T, s *Store, query string, args ...any) []string {
	t.Helper()
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	values := []string{}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(values)
	return values
}

// Every writer of an account's role, enabled state, or password ends the
// same sessions and links for the same change, and records the same
// revocations, through applyAccountTransitionTx:
//
//   - a password change ends the account's sessions and its unused links,
//     whoever issued them, also when another link sets the password;
//   - a role change and a disable end them too, and an administrator's
//     demotion or disable also ends the links it issued, here a pending
//     invitee's activation link, which no record named before;
//   - disabling a platform administrator ends its links and those it
//     issued, for a unit's administrator and for a pending platform
//     administrator;
//   - a TOTP change keeps the browser that made it, and ends no link.
//
// Each link that could still have been redeemed gets exactly one record,
// for its account, in the account's unit or, for a platform administrator,
// in platform scope, with the change's actor. An expired link is ended
// without a record, and no other account's sessions or links change.
func TestAccountTransitionsEndTheSameSessionsAndLinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	revoked := func(username, reason string) string {
		return "activation links revoked for " + username + " because " + reason
	}
	adminBLinks := []string{"own-admin-b", "other-issued-admin-b"}
	adminBIssued := []string{"issued-pending-b", "issued-expired-operator-b"}
	otherLinks := []string{"own-other", "own-other-second"}
	otherIssued := []string{"other-issued-admin-b", "other-issued-pending", "other-issued-expired-admin-a"}
	adminBPassword := transitionOutcome{account: accountAdminB, ended: adminBLinks, records: [][2]string{{secondTenantID, revoked("admin-b", "its password changed")}}}
	adminBDemotion := transitionOutcome{account: accountAdminB, ended: append(slices.Clone(adminBLinks), adminBIssued...), records: [][2]string{
		{secondTenantID, revoked("admin-b", "its role changed")},
		{secondTenantID, revoked("pending-b", "their issuer admin-b was demoted")},
	}}
	adminBDisable := transitionOutcome{account: accountAdminB, ended: adminBDemotion.ended, records: [][2]string{
		{secondTenantID, revoked("admin-b", "it was disabled")},
		{secondTenantID, revoked("pending-b", "their issuer admin-b was disabled")},
	}}
	adminBTOTP := transitionOutcome{account: accountAdminB, keep: []string{"browser-admin-b"}}
	otherPassword := transitionOutcome{account: platformOther, ended: otherLinks, records: [][2]string{{"<null>", revoked(platformOther, "its password changed")}}}
	otherDisable := transitionOutcome{account: platformOther, ended: append(slices.Clone(otherLinks), otherIssued...), records: [][2]string{
		{"<null>", revoked(platformOther, "it was disabled")},
		{secondTenantID, revoked("admin-b", "their issuer "+platformOther+" was disabled")},
		{"<null>", revoked("pending-platform", "their issuer "+platformOther+" was disabled")},
	}}
	otherTOTP := transitionOutcome{account: platformOther, keep: []string{"browser-other"}}
	adminLinks := []string{"own-admin", "own-admin-second"}
	adminPassword := transitionOutcome{account: LegacyAdminUserID, ended: adminLinks, records: [][2]string{{DefaultTenantID, revoked("admin", "its password changed")}}}
	adminDisable := transitionOutcome{account: LegacyAdminUserID, ended: adminLinks, records: [][2]string{{DefaultTenantID, revoked("admin", "it was disabled")}}}

	hostAudit := func(action string) AuditEntry {
		return AuditEntry{Action: action, Detail: "test", ActorUsername: "host-cli", ActorKind: AuditActorHost}
	}
	tenantAccount := func(t *testing.T, f tenantFixture, id string, change func(*User)) User {
		account := fixtureAccount(t, f, id)
		change(&account)
		account.UpdatedAt = time.Now().UTC()
		return account
	}
	platformAccount := func(t *testing.T, f tenantFixture, change func(*User)) User {
		account, err := f.store.Platform().Account(platformOther).GetUser(ctx, platformOther)
		if err != nil {
			t.Fatal(err)
		}
		change(&account)
		account.UpdatedAt = time.Now().UTC()
		return account
	}
	newPassword := func(u *User) { u.PasswordHash = "hash-changed" }
	demote := func(u *User) { u.Role = RoleOperator }
	disable := func(u *User) { u.Enabled = false }
	keep := func(*User) {}
	for _, change := range []struct {
		name string
		want transitionOutcome
		// actor and kind are the actor of the records.
		actor, kind string
		run         func(t *testing.T, f tenantFixture) error
	}{
		{"UpdateUser changes a unit account's password", adminBPassword, accountAdminB, AuditActorUnit, func(t *testing.T, f tenantFixture) error {
			return f.store.Tenant(f.b).UpdateUser(ctx, tenantAccount(t, f, accountAdminB, newPassword), true, AuditEntry{Action: "user.password_changed", ActorUserID: accountAdminB, ActorUsername: "admin-b"})
		}},
		{"SaveUserSecurity resets a unit account's password", adminBPassword, "", AuditActorHost, func(t *testing.T, f tenantFixture) error {
			return f.store.Tenant(f.b).SaveUserSecurity(ctx, tenantAccount(t, f, accountAdminB, newPassword), nil, false, true, hostAudit("user.password_reset"))
		}},
		{"ActivateUser sets a unit account's password", adminBPassword, accountAdminB, AuditActorUnit, func(t *testing.T, f tenantFixture) error {
			_, err := f.store.ActivateUser(ctx, "own-admin-b", "hash-changed", time.Now().UTC(), AuditEntry{Action: "user.activated"})
			return err
		}},
		{"UpdateUserByAdministrator demotes a unit administrator", adminBDemotion, actorSecondAdminB, AuditActorUnit, func(t *testing.T, f tenantFixture) error {
			return f.store.Tenant(f.b).UpdateUserByAdministrator(ctx, tenantAccount(t, f, accountAdminB, demote), true, actorAudit(actorSecondAdminB, "user.updated"))
		}},
		{"SaveUserSecurity demotes a unit administrator", adminBDemotion, "", AuditActorHost, func(t *testing.T, f tenantFixture) error {
			return f.store.Tenant(f.b).SaveUserSecurity(ctx, tenantAccount(t, f, accountAdminB, demote), nil, false, false, hostAudit("user.updated"))
		}},
		{"UpdateUserByAdministrator disables a unit administrator", adminBDisable, actorSecondAdminB, AuditActorUnit, func(t *testing.T, f tenantFixture) error {
			return f.store.Tenant(f.b).UpdateUserByAdministrator(ctx, tenantAccount(t, f, accountAdminB, disable), false, actorAudit(actorSecondAdminB, "user.updated"))
		}},
		{"SaveUserSecurity disables a unit administrator", adminBDisable, "", AuditActorHost, func(t *testing.T, f tenantFixture) error {
			return f.store.Tenant(f.b).SaveUserSecurity(ctx, tenantAccount(t, f, accountAdminB, disable), nil, false, false, hostAudit("user.updated"))
		}},
		{"SaveUserSecurityPreservingSession changes a unit account's TOTP", adminBTOTP, accountAdminB, AuditActorUnit, func(t *testing.T, f tenantFixture) error {
			return f.store.Tenant(f.b).SaveUserSecurityPreservingSession(ctx, tenantAccount(t, f, accountAdminB, keep), []string{"v2$rotated"}, true, true, AuditEntry{Action: "user.totp_recovery_codes_rotated", ActorUserID: accountAdminB, ActorUsername: "admin-b"}, "browser-admin-b", NoTOTPStep)
		}},
		{"PlatformAccountStore changes a platform administrator's password", otherPassword, platformOther, AuditActorPlatform, func(t *testing.T, f tenantFixture) error {
			return f.store.Platform().Account(platformOther).UpdateUser(ctx, platformAccount(t, f, newPassword), true, AuditEntry{Action: "user.password_changed", ActorUserID: platformOther, ActorUsername: platformOther})
		}},
		{"PlatformAccountStore resets a platform administrator's password", otherPassword, "", AuditActorHost, func(t *testing.T, f tenantFixture) error {
			return f.store.Platform().Account(platformOther).SaveUserSecurity(ctx, platformAccount(t, f, newPassword), nil, false, true, hostAudit("user.password_reset"))
		}},
		{"ActivateUser sets a platform administrator's password", otherPassword, platformOther, AuditActorPlatform, func(t *testing.T, f tenantFixture) error {
			_, err := f.store.ActivateUser(ctx, "own-other", "hash-changed", time.Now().UTC(), AuditEntry{Action: "user.activated"})
			return err
		}},
		{"SetPlatformAdminEnabled disables a platform administrator", otherDisable, platformRoot, AuditActorPlatform, func(t *testing.T, f tenantFixture) error {
			_, err := f.store.Platform().SetPlatformAdminEnabled(ctx, platformOther, 0, false, platformAudit(""))
			return err
		}},
		{"PlatformAccountStore disables a platform administrator", otherDisable, "", AuditActorHost, func(t *testing.T, f tenantFixture) error {
			return f.store.Platform().Account(platformOther).UpdateUser(ctx, platformAccount(t, f, disable), false, hostAudit("platform_admin.updated"))
		}},
		{"PlatformAccountStore changes a platform administrator's TOTP", otherTOTP, platformOther, AuditActorPlatform, func(t *testing.T, f tenantFixture) error {
			return f.store.Platform().Account(platformOther).SaveUserSecurityPreservingSession(ctx, platformAccount(t, f, keep), []string{"v2$rotated"}, true, true, AuditEntry{Action: "user.totp_recovery_codes_rotated", ActorUserID: platformOther, ActorUsername: platformOther}, "browser-other", NoTOTPStep)
		}},
		{"SaveAdminSecurityWithAudit changes the original administrator's password", adminPassword, LegacyAdminUserID, AuditActorUnit, func(t *testing.T, f tenantFixture) error {
			admin, err := f.store.GetAdmin(ctx)
			if err != nil {
				return err
			}
			admin.PasswordHash = "hash-changed"
			return f.store.SaveAdminSecurityWithAudit(ctx, admin, nil, false, true, AuditEntry{Action: "admin.password_changed", ActorUserID: LegacyAdminUserID, ActorUsername: "admin"})
		}},
		{"ActivateUser sets the original administrator's password", adminPassword, LegacyAdminUserID, AuditActorUnit, func(t *testing.T, f tenantFixture) error {
			_, err := f.store.ActivateUser(ctx, "own-admin", "hash-changed", time.Now().UTC(), AuditEntry{Action: "user.activated"})
			return err
		}},
		{"UpdateUserByAdministrator disables the original administrator", adminDisable, accountAdminA, AuditActorUnit, func(t *testing.T, f tenantFixture) error {
			return f.store.Tenant(f.a).UpdateUserByAdministrator(ctx, tenantAccount(t, f, LegacyAdminUserID, disable), false, actorAudit(accountAdminA, "user.updated"))
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			t.Parallel()
			f := newTransitionFixture(t)
			account := `user_id=?`
			if change.want.account == LegacyAdminUserID {
				account = `(user_id=? OR user_id='')`
			}
			otherSessions := sortedStrings(t, f.store, `SELECT id_hash FROM sessions WHERE NOT `+account, change.want.account)
			if err := change.run(t, f); err != nil {
				t.Fatal(err)
			}
			if got := sortedStrings(t, f.store, `SELECT id_hash FROM sessions WHERE `+account, change.want.account); !slices.Equal(got, sortedCopy(change.want.keep)) {
				t.Errorf("the account's sessions = %v, want %v", got, change.want.keep)
			}
			if got := sortedStrings(t, f.store, `SELECT id_hash FROM sessions WHERE NOT `+account, change.want.account); !slices.Equal(got, otherSessions) {
				t.Errorf("other accounts' sessions = %v, want %v", got, otherSessions)
			}
			if got := sortedStrings(t, f.store, `SELECT id_hash FROM user_invites WHERE used_at IS NOT NULL`); !slices.Equal(got, sortedCopy(change.want.ended)) {
				t.Errorf("used or ended links = %v, want %v", got, sortedCopy(change.want.ended))
			}
			var records [][2]string
			for _, record := range append(linkRevocations(t, f.store, "user.activation_revoked"), linkRevocations(t, f.store, auditPlatformAdminActivationRevoked)...) {
				if record.actorID != change.actor || record.kind != change.kind {
					t.Errorf("record %+v, want the actor %q of kind %s", record, change.actor, change.kind)
				}
				if (record.tenant == "<null>") != strings.HasPrefix(linkRevocationAction(t, f.store, record.detail), "platform_admin.") {
					t.Errorf("record %+v has the action of another scope", record)
				}
				records = append(records, [2]string{record.tenant, record.detail})
			}
			slices.SortFunc(records, func(a, b [2]string) int { return strings.Compare(a[1], b[1]) })
			want := slices.Clone(change.want.records)
			slices.SortFunc(want, func(a, b [2]string) int { return strings.Compare(a[1], b[1]) })
			if !slices.Equal(records, want) {
				t.Errorf("revocation records = %v, want %v", records, want)
			}
		})
	}
}

// linkRevocationAction returns the action of the revocation record with the
// detail.
func linkRevocationAction(t *testing.T, s *Store, detail string) string {
	t.Helper()
	var action string
	if err := s.DB.QueryRow(`SELECT action FROM security_audit WHERE detail=? AND action IN ('user.activation_revoked',?)`, detail, auditPlatformAdminActivationRevoked).Scan(&action); err != nil {
		t.Fatal(err)
	}
	return action
}

// A disabled account that redeemed its activation link gets no new link,
// whichever administrator issues it: the unit's administrator and the
// platform administrator are refused with ErrAccountDisabled in the
// transaction that would store the link, so a link raced past the disable
// is not stored, and none works once the account is enabled again. The
// refusal writes no record. A pending invitee, which is disabled until it
// redeems its activation link, still gets a new one.
func TestInviteAndResetLinksRefuseDisabledAccounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, actorSecondAdminB, secondTenantID, RoleAdministrator)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	ts := f.store.Tenant(f.b)
	now := time.Now().UTC()
	for _, id := range []string{accountAdminB, accountOperatorB} {
		account := fixtureAccount(t, f, id)
		account.Enabled = false
		if err := ts.UpdateUserByAdministrator(ctx, account, true, actorAudit(actorSecondAdminB, "user.updated")); err != nil {
			t.Fatal(err)
		}
	}
	links := countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites`)
	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	if err := ts.CreateUserInviteWithAudit(ctx, "raced-operator-b", accountOperatorB, now, now.Add(30*time.Minute), actorAudit(actorSecondAdminB, "user.password_reset_issued")); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("a unit administrator's link for a disabled account = %v, want ErrAccountDisabled", err)
	}
	if err := f.store.Platform().IssueUnitAdminPasswordReset(ctx, secondTenantID, accountAdminB, "raced-admin-b", now, now.Add(30*time.Minute), platformAudit("user.password_reset_issued")); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("a platform administrator's link for a disabled administrator = %v, want ErrAccountDisabled", err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites`); got != links {
		t.Fatalf("the refused links stored %d rows", got-links)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("the refused links recorded %d audit records", got-audits)
	}
	for _, id := range []string{accountAdminB, accountOperatorB} {
		account := fixtureAccount(t, f, id)
		account.Enabled = true
		if err := ts.UpdateUserByAdministrator(ctx, account, true, actorAudit(actorSecondAdminB, "user.updated")); err != nil {
			t.Fatal(err)
		}
	}
	for _, hash := range []string{"raced-operator-b", "raced-admin-b", "invite-operator-b"} {
		if link, err := f.store.CheckActivationToken(ctx, hash, now.Add(time.Minute)); err != nil || link.Usable {
			t.Fatalf("link %s after the account was enabled again = %+v, %v", hash, link, err)
		}
	}

	pending, err := ts.CreateUserWithInvite(ctx, User{Username: "pending-b", Role: RoleViewer, PasswordHash: "!pending"}, "first-pending-b", now, now.Add(30*time.Minute), actorAudit(actorSecondAdminB, "user.created"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.CreateUserInviteWithAudit(ctx, "renewed-pending-b", pending.ID, now, now.Add(30*time.Minute), actorAudit(actorSecondAdminB, "user.activation_issued")); err != nil {
		t.Fatalf("a pending invitee's new activation link = %v", err)
	}
	if link, err := f.store.CheckActivationToken(ctx, "renewed-pending-b", now.Add(time.Minute)); err != nil || !link.Usable {
		t.Fatalf("the pending invitee's new activation link = %+v, %v", link, err)
	}
}
