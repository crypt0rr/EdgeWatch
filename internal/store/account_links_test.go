package store

import (
	"context"
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
		// CreateUserInvite leaves them, so the account has two.
		if err := f.store.Tenant(f.b).CreateUserInvite(ctx, "second-operator-b", accountOperatorB, now, now.Add(time.Hour)); err != nil {
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
