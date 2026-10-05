package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// More accounts of unit B for the actor checks, added directly in SQL.
const (
	actorViewerB        = "00000000-0000-0000-0000-00000000bc03"
	actorDisabledAdminB = "00000000-0000-0000-0000-00000000bc04"
	actorSecondAdminB   = "00000000-0000-0000-0000-00000000bc05"
)

// unitAdministratorWrite is one of the account writes that a unit's
// administrator makes, through the unit's store with the audit entry. Each
// run names new rows, so a write may run again after a refusal.
type unitAdministratorWrite struct {
	name, action string
	run          func(t *testing.T, f tenantFixture, ts *TenantStore, audit AuditEntry, run int) error
}

var unitAdministratorWrites = []unitAdministratorWrite{
	{"CreateUserWithInvite", "user.created", func(t *testing.T, f tenantFixture, ts *TenantStore, audit AuditEntry, run int) error {
		now := time.Now().UTC()
		username := fmt.Sprintf("invitee-b-%d", run)
		_, err := ts.CreateUserWithInvite(context.Background(), User{Username: username, Role: RoleAdministrator, PasswordHash: "!pending"}, "invite-"+username, now, now.Add(time.Hour), audit)
		return err
	}},
	{"CreateUserInviteWithAudit", "user.password_reset_issued", func(t *testing.T, f tenantFixture, ts *TenantStore, audit AuditEntry, run int) error {
		now := time.Now().UTC()
		return ts.CreateUserInviteWithAudit(context.Background(), fmt.Sprintf("reset-admin-b-%d", run), accountAdminB, now, now.Add(time.Hour), audit)
	}},
	{"RevokeUserInvitesWithAudit", "user.activation_revoked", func(t *testing.T, f tenantFixture, ts *TenantStore, audit AuditEntry, run int) error {
		revoked, err := ts.RevokeUserInvitesWithAudit(context.Background(), accountOperatorB, time.Now().UTC(), audit)
		if err == nil && revoked != 1 {
			return fmt.Errorf("revoked %d links, want 1", revoked)
		}
		return err
	}},
	{"UpdateUserByAdministrator", "user.updated", func(t *testing.T, f tenantFixture, ts *TenantStore, audit AuditEntry, run int) error {
		user := fixtureAccount(t, f, accountOperatorB)
		user.Role = RoleViewer
		return ts.UpdateUserByAdministrator(context.Background(), user, true, audit)
	}},
	{"DeleteUserSessionsByAdministrator", "user.sessions_revoked", func(t *testing.T, f tenantFixture, ts *TenantStore, audit AuditEntry, run int) error {
		return ts.DeleteUserSessionsByAdministrator(context.Background(), accountOperatorB, audit)
	}},
}

// actorAudit is the audit entry of an account write by the actor.
func actorAudit(actorID, action string) AuditEntry {
	return AuditEntry{Action: action, Detail: "test", ActorUserID: actorID, ActorUsername: "actor"}
}

// seedDefaultAdministrator adds the legacy administrator to the default
// tenant directly in SQL, unless the database has it, so a test can make an
// administrator's account write as it (see defaultAdministratorAudit).
func seedDefaultAdministrator(t *testing.T, s *Store) {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT OR IGNORE INTO users(id,tenant_id,username,display_name,role,password_hash,created_at,updated_at) VALUES(?,?,'admin','admin',?,'hash',?,?)`, LegacyAdminUserID, DefaultTenantID, RoleAdministrator, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

// defaultAdministratorAudit is the audit entry of an account write by the
// administrator that seedDefaultAdministrator adds.
func defaultAdministratorAudit(action string) AuditEntry {
	return AuditEntry{Action: action, ActorUserID: LegacyAdminUserID, ActorUsername: "admin"}
}

// An administrator's account write checks in its own transaction that the
// actor is still an enabled administrator of the unit and that the unit is
// still active, as the platform's writes do. Every other actor is
// ErrAccountNotPermitted: the unit's operator and viewer, a disabled
// administrator, another unit's administrator, a platform administrator, an
// unknown account, and no actor. A disabled unit or one being deleted is
// ErrTenantNotActive, and a deleted one ErrNoTenantScope. A refused write
// changes no account, link, session, or audit record of either unit. The
// unit's enabled administrator of an active unit succeeds, with its record
// in the unit's audit.
func TestUnitAdministratorAccountWritesRecheckTheActor(t *testing.T) {
	t.Parallel()
	for _, write := range unitAdministratorWrites {
		t.Run(write.name, func(t *testing.T) {
			f := newTenantFixture(t)
			insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
			insertTenantUser(t, f.store, actorViewerB, secondTenantID, RoleViewer)
			insertTenantUser(t, f.store, actorDisabledAdminB, secondTenantID, RoleAdministrator)
			if _, err := f.store.DB.Exec(`UPDATE users SET enabled=0 WHERE id=?`, actorDisabledAdminB); err != nil {
				t.Fatal(err)
			}
			ts := f.store.Tenant(f.b)
			beforeA, beforeB := tenantAccountDigest(t, f.store, f.a), tenantAccountDigest(t, f.store, f.b)
			audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
			assertUnchanged := func(t *testing.T, refusal string) {
				t.Helper()
				if tenantAccountDigest(t, f.store, f.a) != beforeA || tenantAccountDigest(t, f.store, f.b) != beforeB {
					t.Fatalf("the write refused %s changed a unit's accounts", refusal)
				}
				if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
					t.Fatalf("the write refused %s recorded %d audit records", refusal, got-audits)
				}
			}
			run := 0
			for _, refused := range []struct {
				name, actor string
			}{
				{"the unit's operator", accountOperatorB},
				{"the unit's viewer", actorViewerB},
				{"a disabled administrator of the unit", actorDisabledAdminB},
				{"another unit's administrator", accountAdminA},
				{"a platform administrator", platformRoot},
				{"an unknown account", accountUnknown},
				{"no actor", ""},
			} {
				run++
				if err := write.run(t, f, ts, actorAudit(refused.actor, write.action), run); !errors.Is(err, ErrAccountNotPermitted) {
					t.Errorf("write by %s = %v, want ErrAccountNotPermitted", refused.name, err)
				}
				assertUnchanged(t, "for "+refused.name)
			}
			for _, state := range []struct {
				state string
				want  error
			}{
				{TenantStateDisabled, ErrTenantNotActive},
				{TenantStateDeleting, ErrTenantNotActive},
				{TenantStateDeleted, ErrNoTenantScope},
			} {
				if _, err := f.store.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, state.state, secondTenantID); err != nil {
					t.Fatal(err)
				}
				run++
				if err := write.run(t, f, ts, actorAudit(accountAdminB, write.action), run); !errors.Is(err, state.want) {
					t.Errorf("write in a %s unit = %v, want %v", state.state, err, state.want)
				}
				assertUnchanged(t, "in a "+state.state+" unit")
			}

			// The unit's enabled administrator writes in the active unit.
			if _, err := f.store.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, TenantStateActive, secondTenantID); err != nil {
				t.Fatal(err)
			}
			run++
			if err := write.run(t, f, ts, actorAudit(accountAdminB, write.action), run); err != nil {
				t.Fatalf("write by the unit's administrator: %v", err)
			}
			if got, want := lastAudit(t, f.store, write.action), (auditRecord{secondTenantID, AuditActorUnit}); got != want {
				t.Fatalf("%s audit record = %+v, want %+v", write.action, got, want)
			}
			if tenantAccountDigest(t, f.store, f.a) != beforeA {
				t.Fatal("unit B's write changed unit A's accounts")
			}
		})
	}
}

// A link that an administrator issued is revoked when a later change
// demotes it, and a link that it tries to issue after the demotion is
// refused, so neither order leaves the demoted administrator's link usable.
func TestDemotedAdministratorLeavesNoUsableLink(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, actorSecondAdminB, secondTenantID, RoleAdministrator)
	ts := f.store.Tenant(f.b)
	now := time.Now().UTC()
	if err := ts.CreateUserInviteWithAudit(ctx, "before-demotion", accountOperatorB, now, now.Add(time.Hour), actorAudit(actorSecondAdminB, "user.password_reset_issued")); err != nil {
		t.Fatal(err)
	}
	demoted := fixtureAccount(t, f, actorSecondAdminB)
	demoted.Role = RoleViewer
	if err := ts.UpdateUserByAdministrator(ctx, demoted, true, accountAudit("user.updated")); err != nil {
		t.Fatal(err)
	}
	if usable, err := f.store.ActivationTokenUsable(ctx, "before-demotion", now); err != nil || usable {
		t.Fatalf("link issued before the demotion usable = %v, %v", usable, err)
	}
	if err := ts.CreateUserInviteWithAudit(ctx, "after-demotion", accountOperatorB, now, now.Add(time.Hour), actorAudit(actorSecondAdminB, "user.password_reset_issued")); !errors.Is(err, ErrAccountNotPermitted) {
		t.Fatalf("link issued after the demotion = %v, want ErrAccountNotPermitted", err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites WHERE issuer_user_id=? AND used_at IS NULL`, actorSecondAdminB); got != 0 {
		t.Fatalf("the demoted administrator has %d usable links", got)
	}
}

// The account's own changes and the host CLI's keep writing without an
// administrator actor: UpdateUser and DeleteUserSessionsWithAudit do not
// check one.
func TestSelfServiceAccountWritesNeedNoAdministrator(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	ts := f.store.Tenant(f.b)
	operator := fixtureAccount(t, f, accountOperatorB)
	operator.DisplayName = "Renamed by itself"
	if err := ts.UpdateUser(ctx, operator, false, actorAudit(accountOperatorB, "user.display_name_changed")); err != nil {
		t.Fatalf("an operator's own change: %v", err)
	}
	if err := ts.DeleteUserSessionsWithAudit(ctx, accountOperatorB, actorAudit(accountOperatorB, "user.sessions_revoked")); err != nil {
		t.Fatalf("an operator's own sign-out everywhere: %v", err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, accountOperatorB); got != 0 {
		t.Fatalf("the operator kept %d sessions", got)
	}
}
