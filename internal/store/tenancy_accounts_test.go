package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
)

// The accounts that addTenantAccounts gives the tenant fixture. Each tenant
// has an enabled administrator with a recovery code and an enabled operator
// with an outstanding password-reset link, and each account has a session.
// Usernames are unique across tenants, so the two tenants' names differ.
const (
	accountAdminA    = "00000000-0000-0000-0000-00000000ac01"
	accountOperatorA = "00000000-0000-0000-0000-00000000ac02"
	accountAdminB    = "00000000-0000-0000-0000-00000000bc01"
	accountOperatorB = "00000000-0000-0000-0000-00000000bc02"
	// accountUnknown is an ID that no account has.
	accountUnknown = "00000000-0000-0000-0000-00000000cc99"
)

// tenantAccount is one account of the fixture.
type tenantAccount struct{ id, tenant, username, role string }

var tenantFixtureAccounts = []tenantAccount{
	{accountAdminA, DefaultTenantID, "admin-a", RoleAdministrator},
	{accountOperatorA, DefaultTenantID, "operator-a", RoleOperator},
	{accountAdminB, secondTenantID, "admin-b", RoleAdministrator},
	{accountOperatorB, secondTenantID, "operator-b", RoleOperator},
}

// addTenantAccounts adds the accounts to the tenant fixture directly in SQL,
// with placeholder password hashes, because hashing a password is slow and
// the store never checks one. Each account's session, recovery code, and
// link are named after its username.
func addTenantAccounts(t *testing.T, s *Store) {
	t.Helper()
	stamp := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	expires := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	for _, account := range tenantFixtureAccounts {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)`, []any{account.id, account.tenant, account.username, account.username, account.role, "hash-" + account.username, stamp, stamp}},
			{`INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?,?)`, []any{"session-" + account.username, account.id, stamp, stamp, expires, "csrf-" + account.username}},
		} {
			if _, err := s.DB.Exec(statement.query, statement.args...); err != nil {
				t.Fatal(err)
			}
		}
		switch account.role {
		case RoleAdministrator:
			if _, err := s.DB.Exec(`INSERT INTO recovery_codes(id_hash,user_id) VALUES(?,?)`, "recovery-"+account.username, account.id); err != nil {
				t.Fatal(err)
			}
		default:
			if _, err := s.DB.Exec(`INSERT INTO user_invites(id_hash,user_id,issuer_user_id,created_at,expires_at,used_at) VALUES(?,?,'',?,?,NULL)`, "invite-"+account.username, account.id, stamp, expires); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// The account cases join tenantStoreLeakCases before any test runs, as the
// other slices' cases do.
func init() {
	for name, leak := range accountLeakCases {
		if _, duplicate := tenantStoreLeakCases[name]; duplicate {
			panic("two leak cases for TenantStore." + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

// tenantAccountTables are the tables that hold a tenant's accounts and its
// audit, each with the predicate that selects the tenant's rows.
var tenantAccountTables = []struct{ table, predicate string }{
	{"users", "tenant_id=?1"},
	{"sessions", "user_id IN (SELECT id FROM users WHERE tenant_id=?1)"},
	{"user_invites", "user_id IN (SELECT id FROM users WHERE tenant_id=?1)"},
	{"recovery_codes", "user_id IN (SELECT id FROM users WHERE tenant_id=?1)"},
	{"totp_replay", "user_id IN (SELECT id FROM users WHERE tenant_id=?1)"},
	{"security_audit", "tenant_id=?1"},
}

// tenantAccountDigest returns a digest of the tenant's accounts, their
// credentials and sessions, and the tenant's audit records.
func tenantAccountDigest(t *testing.T, s *Store, tenant TenantScope) string {
	t.Helper()
	digest := sha256.New()
	for _, source := range tenantAccountTables {
		fmt.Fprintf(digest, "%s:%s\n", source.table, tenantRows(t, s, source.table, source.predicate, tenant))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// fixtureAccount returns the account with the ID as the store has it, so a
// write through another tenant can name it exactly, revision and all. An
// unknown ID gets a plausible account of its own.
func fixtureAccount(t *testing.T, f tenantFixture, id string) User {
	t.Helper()
	user, err := f.store.GetAccount(context.Background(), id)
	if errors.Is(err, ErrNotFound) {
		return User{ID: id, Username: "ghost", DisplayName: "Ghost", Role: RoleViewer, PasswordHash: "hash-ghost", Enabled: true, Revision: 1}
	}
	if err != nil {
		t.Fatal(err)
	}
	return user
}

// auditRecord is the attribution of one audit record.
type auditRecord struct{ tenant, kind string }

// lastAudit returns the tenant, "<null>" for the platform, and the actor
// kind of the newest audit record with the action.
func lastAudit(t *testing.T, s *Store, action string) auditRecord {
	t.Helper()
	var record auditRecord
	if err := s.DB.QueryRow(`SELECT COALESCE(tenant_id,'<null>'),actor_kind FROM security_audit WHERE action=? ORDER BY id DESC LIMIT 1`, action).Scan(&record.tenant, &record.kind); err != nil {
		t.Fatalf("audit record %s: %v", action, err)
	}
	return record
}

// tenantAccountWrite is one write to an account, named by its ID.
type tenantAccountWrite func(ts *TenantStore, id string) error

// assertTenantWritesOnlyItsAccounts runs the write through tenant B against
// each of tenant A's accounts and an unknown ID. Each is ErrNotFound, and A's
// accounts, credentials, sessions, and audit are unchanged; no audit record
// is written anywhere. Then the write succeeds on B's own account, still
// without changing A, and its audit record, when it writes one, belongs to
// B with the unit kind of its actor.
func assertTenantWritesOnlyItsAccounts(t *testing.T, f tenantFixture, write tenantAccountWrite, own, action string) {
	t.Helper()
	before := tenantAccountDigest(t, f.store, f.a)
	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	for _, id := range []string{accountAdminA, accountOperatorA, accountUnknown} {
		if err := write(f.store.Tenant(f.b), id); !errors.Is(err, ErrNotFound) {
			t.Errorf("tenant B wrote account %s: %v, want ErrNotFound", id, err)
		}
	}
	if after := tenantAccountDigest(t, f.store, f.a); after != before {
		t.Fatal("a write through tenant B changed tenant A's accounts")
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("refused writes recorded %d audit records", got-audits)
	}
	if err := write(f.store.Tenant(f.b), own); err != nil {
		t.Fatalf("tenant B's own account %s: %v", own, err)
	}
	if after := tenantAccountDigest(t, f.store, f.a); after != before {
		t.Fatal("tenant B's write to its own account changed tenant A's accounts")
	}
	if action != "" {
		if got, want := lastAudit(t, f.store, action), (auditRecord{secondTenantID, AuditActorUnit}); got != want {
			t.Fatalf("%s audit record = %+v, want %+v", action, got, want)
		}
	}
}

// accountAudit is the audit entry of an account action by tenant B's
// administrator.
func accountAudit(action string) AuditEntry {
	return AuditEntry{Action: action, Detail: "test", ActorUserID: accountAdminB, ActorUsername: "admin-b"}
}

// usernames returns the usernames of the accounts, in order.
func usernames(users []UserSummary) []string {
	names := make([]string, 0, len(users))
	for _, user := range users {
		names = append(names, user.Username)
	}
	return names
}

var accountLeakCases = map[string]tenantLeakCase{
	"GetUser": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for scope, check := range map[TenantScope]struct{ own, other []string }{
			f.a: {own: []string{accountAdminA, accountOperatorA}, other: []string{accountAdminB, accountOperatorB, accountUnknown}},
			f.b: {own: []string{accountAdminB, accountOperatorB}, other: []string{accountAdminA, accountOperatorA, accountUnknown}},
		} {
			for _, id := range check.other {
				if user, err := f.store.Tenant(scope).GetUser(ctx, id); !errors.Is(err, ErrNotFound) || user.ID != "" {
					t.Errorf("tenant %s read account %s: %+v, %v", scope.ID(), id, user, err)
				}
			}
			for _, id := range check.own {
				if user, err := f.store.Tenant(scope).GetUser(ctx, id); err != nil || user.ID != id || user.TenantID != scope.ID() {
					t.Errorf("tenant %s's own account %s = %+v, %v", scope.ID(), id, user, err)
				}
			}
		}
	}},
	"ListUsers": {run: func(t *testing.T, f tenantFixture) {
		for scope, want := range map[TenantScope][]string{f.a: {"admin-a", "operator-a"}, f.b: {"admin-b", "operator-b"}} {
			users, err := f.store.Tenant(scope).ListUsers(context.Background())
			if err != nil || !reflect.DeepEqual(usernames(users), want) {
				t.Errorf("tenant %s: users = %v, %v; want %v", scope.ID(), usernames(users), err, want)
			}
		}
	}},
	"CountEnabledAdministrators": {run: func(t *testing.T, f tenantFixture) {
		for _, scope := range []TenantScope{f.a, f.b} {
			if count, err := f.store.Tenant(scope).CountEnabledAdministrators(context.Background()); err != nil || count != 1 {
				t.Errorf("tenant %s: enabled administrators = %d, %v; want 1", scope.ID(), count, err)
			}
		}
	}},
	"CreateUser": {writes: true, run: func(t *testing.T, f tenantFixture) {
		checkTenantAccountCreate(t, f, "user.created", func(ts *TenantStore, user User) (User, error) {
			return ts.CreateUser(context.Background(), user, accountAudit("user.created"))
		})
	}},
	"CreateUserWithInvite": {writes: true, run: func(t *testing.T, f tenantFixture) {
		now := time.Now().UTC()
		checkTenantAccountCreate(t, f, "user.created", func(ts *TenantStore, user User) (User, error) {
			return ts.CreateUserWithInvite(context.Background(), user, "invite-"+user.Username, now, now.Add(time.Hour), accountAudit("user.created"))
		})
		var issuer string
		if err := f.store.DB.QueryRow(`SELECT issuer_user_id FROM user_invites WHERE id_hash='invite-new-b'`).Scan(&issuer); err != nil || issuer != accountAdminB {
			t.Fatalf("tenant B's new invite issuer = %q, %v", issuer, err)
		}
		if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites WHERE id_hash IN ('invite-admin-a','invite-ADMIN-A')`); got != 0 {
			t.Fatalf("a refused account left %d invites", got)
		}
	}},
	"UpdateUser": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantWritesOnlyItsAccounts(t, f, func(ts *TenantStore, id string) error {
			user := fixtureAccount(t, f, id)
			user.DisplayName, user.Role = "Renamed", RoleViewer
			return ts.UpdateUser(context.Background(), user, true, accountAudit("user.updated"))
		}, accountOperatorB, "user.updated")
		// The role change revoked B's operator's session and left A's.
		for session, want := range map[string]int{"session-operator-b": 0, "session-operator-a": 1} {
			if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE id_hash=?`, session); got != want {
				t.Errorf("%s: %d rows, want %d", session, got, want)
			}
		}
		// Each tenant keeps its own last enabled administrator: A's
		// administrator does not count for B.
		for scope, id := range map[TenantScope]string{f.a: accountAdminA, f.b: accountAdminB} {
			admin := fixtureAccount(t, f, id)
			admin.Role = RoleViewer
			if err := f.store.Tenant(scope).UpdateUser(context.Background(), admin, false, accountAudit("user.updated")); !errors.Is(err, ErrLastAdministrator) {
				t.Errorf("tenant %s demoted its last administrator: %v", scope.ID(), err)
			}
		}
	}},
	"UpdateUserByAdministrator": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantWritesOnlyItsAccounts(t, f, func(ts *TenantStore, id string) error {
			user := fixtureAccount(t, f, id)
			user.DisplayName, user.Role = "Renamed", RoleViewer
			return ts.UpdateUserByAdministrator(context.Background(), user, true, accountAudit("user.updated"))
		}, accountOperatorB, "user.updated")
		for session, want := range map[string]int{"session-operator-b": 0, "session-operator-a": 1} {
			if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE id_hash=?`, session); got != want {
				t.Errorf("%s: %d rows, want %d", session, got, want)
			}
		}
	}},
	"SetUserPassword": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantWritesOnlyItsAccounts(t, f, func(ts *TenantStore, id string) error {
			return ts.SetUserPassword(context.Background(), id, "hash-new", true, accountAudit("user.password_reset"))
		}, accountOperatorB, "user.password_reset")
		if user, err := f.store.GetAccount(context.Background(), accountOperatorB); err != nil || user.PasswordHash != "hash-new" {
			t.Fatalf("tenant B's operator after the reset = %+v, %v", user, err)
		}
	}},
	"SaveUserSecurity": {writes: true, run: func(t *testing.T, f tenantFixture) {
		checkTenantSecurityWrite(t, f, func(ts *TenantStore, user User, codes []string) error {
			return ts.SaveUserSecurity(context.Background(), user, codes, true, true, accountAudit("user.totp_disabled"))
		}, "session-admin-b", 0)
	}},
	"SaveUserSecurityPreservingSession": {writes: true, run: func(t *testing.T, f tenantFixture) {
		checkTenantSecurityWrite(t, f, func(ts *TenantStore, user User, codes []string) error {
			// Name the session of the account written, so a write that
			// reached A's account could keep A's session, and record a TOTP
			// time step, so a write that reached A's account would record
			// A's.
			return ts.SaveUserSecurityPreservingSession(context.Background(), user, codes, true, true, accountAudit("user.totp_disabled"), "session-"+user.Username, 7)
		}, "session-admin-b", 1)
		for query, want := range map[string]int{
			`SELECT COUNT(*) FROM totp_replay WHERE user_id='` + accountAdminB + `' AND last_step=7`: 1,
			`SELECT COUNT(*) FROM totp_replay WHERE user_id<>'` + accountAdminB + `'`:                0,
		} {
			if got := countRows(t, f.store.DB, query); got != want {
				t.Errorf("%s = %d, want %d", query, got, want)
			}
		}
	}},
	"DeleteUserSessionsWithAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantWritesOnlyItsAccounts(t, f, func(ts *TenantStore, id string) error {
			return ts.DeleteUserSessionsWithAudit(context.Background(), id, accountAudit("user.sessions_revoked"))
		}, accountOperatorB, "user.sessions_revoked")
		if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, accountOperatorB); got != 0 {
			t.Fatalf("tenant B's operator kept %d sessions", got)
		}
	}},
	"DeleteUserSessionsByAdministrator": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertTenantWritesOnlyItsAccounts(t, f, func(ts *TenantStore, id string) error {
			return ts.DeleteUserSessionsByAdministrator(context.Background(), id, accountAudit("user.sessions_revoked"))
		}, accountOperatorB, "user.sessions_revoked")
		for user, want := range map[string]int{accountOperatorB: 0, accountOperatorA: 1} {
			if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, user); got != want {
				t.Errorf("sessions of %s = %d, want %d", user, got, want)
			}
		}
	}},
	"CreateUserInvite": {writes: true, run: func(t *testing.T, f tenantFixture) {
		now := time.Now().UTC()
		assertTenantWritesOnlyItsAccounts(t, f, func(ts *TenantStore, id string) error {
			return ts.CreateUserInvite(context.Background(), "link-"+id, id, now, now.Add(time.Hour))
		}, accountOperatorB, "")
		if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites WHERE id_hash LIKE 'link-%'`); got != 1 {
			t.Fatalf("links stored = %d, want tenant B's one", got)
		}
	}},
	"CreateUserInviteWithAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		now := time.Now().UTC()
		assertTenantWritesOnlyItsAccounts(t, f, func(ts *TenantStore, id string) error {
			return ts.CreateUserInviteWithAudit(context.Background(), "link-"+id, id, now, now.Add(time.Hour), accountAudit("user.password_reset_issued"))
		}, accountOperatorB, "user.password_reset_issued")
		// B's new link replaced B's old one, and A's old link is still usable.
		for link, usable := range map[string]bool{"invite-operator-b": false, "link-" + accountOperatorB: true, "invite-operator-a": true} {
			if got, err := f.store.ActivationTokenUsable(context.Background(), link, now); err != nil || got != usable {
				t.Errorf("link %s usable = %v, %v; want %v", link, got, err, usable)
			}
		}
	}},
	"RevokeUserInvitesWithAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		now := time.Now().UTC()
		assertTenantWritesOnlyItsAccounts(t, f, func(ts *TenantStore, id string) error {
			revoked, err := ts.RevokeUserInvitesWithAudit(context.Background(), id, now, accountAudit("user.activation_revoked"))
			if err == nil && revoked != 1 {
				return fmt.Errorf("revoked %d links, want 1", revoked)
			}
			return err
		}, accountOperatorB, "user.activation_revoked")
		for link, usable := range map[string]bool{"invite-operator-b": false, "invite-operator-a": true} {
			if got, err := f.store.ActivationTokenUsable(context.Background(), link, now); err != nil || got != usable {
				t.Errorf("link %s usable = %v, %v; want %v", link, got, err, usable)
			}
		}
	}},
	"Audit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		before := tenantAccountDigest(t, f.store, f.a)
		if err := f.store.Tenant(f.b).Audit(context.Background(), "scan.run_requested", "test"); err != nil {
			t.Fatal(err)
		}
		if after := tenantAccountDigest(t, f.store, f.a); after != before {
			t.Fatal("tenant B's audit record changed tenant A's audit")
		}
		if got, want := lastAudit(t, f.store, "scan.run_requested"), (auditRecord{secondTenantID, AuditActorSystem}); got != want {
			t.Fatalf("audit record = %+v, want %+v", got, want)
		}
	}},
	"AuditEntry": {writes: true, run: func(t *testing.T, f tenantFixture) {
		before := tenantAccountDigest(t, f.store, f.a)
		// An entry cannot name another tenant: the store's tenant wins, even
		// over an actor of tenant A.
		for _, entry := range []AuditEntry{
			{Action: "scan.run_requested", ActorUserID: accountAdminB, TenantID: DefaultTenantID},
			{Action: "scan.cancel_requested", ActorUserID: accountAdminA},
		} {
			if err := f.store.Tenant(f.b).AuditEntry(context.Background(), entry); err != nil {
				t.Fatal(err)
			}
			if got, want := lastAudit(t, f.store, entry.Action), (auditRecord{secondTenantID, AuditActorUnit}); got != want {
				t.Fatalf("%s audit record = %+v, want %+v", entry.Action, got, want)
			}
		}
		if after := tenantAccountDigest(t, f.store, f.a); after != before {
			t.Fatal("tenant B's audit records changed tenant A's audit")
		}
	}},
}

// checkTenantAccountCreate creates accounts through tenant B. A new name
// belongs to B. A name that tenant A holds, in any case, is refused with an
// error that names neither the tenant nor the column, and so is the
// platform administrator role; A is unchanged.
func checkTenantAccountCreate(t *testing.T, f tenantFixture, action string, create func(ts *TenantStore, user User) (User, error)) {
	t.Helper()
	before := tenantAccountDigest(t, f.store, f.a)
	ts := f.store.Tenant(f.b)
	for _, name := range []string{"admin-a", "ADMIN-A"} {
		_, err := create(ts, User{Username: name, Role: RoleViewer, PasswordHash: "!pending"})
		if !errors.Is(err, ErrUsernameUnavailable) || err.Error() != "username is not available" {
			t.Fatalf("tenant B took tenant A's username %s: %v", name, err)
		}
	}
	if _, err := create(ts, User{Username: "platform-b", Role: RolePlatformAdmin, PasswordHash: "!pending"}); err == nil || errors.Is(err, ErrUsernameUnavailable) {
		t.Fatalf("tenant B created a platform administrator: %v", err)
	}
	if after := tenantAccountDigest(t, f.store, f.a); after != before {
		t.Fatal("tenant B's refused accounts changed tenant A")
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM users WHERE username IN ('platform-b') OR role=?`, RolePlatformAdmin); got != 0 {
		t.Fatalf("a refused account was stored: %d rows", got)
	}
	created, err := create(ts, User{Username: "new-b", Role: RoleViewer, PasswordHash: "!pending"})
	if err != nil || created.TenantID != secondTenantID {
		t.Fatalf("tenant B's new account = %+v, %v", created, err)
	}
	if got := tenantOf(t, f.store.DB, `SELECT tenant_id FROM users WHERE username='new-b'`); got != secondTenantID {
		t.Fatalf("tenant B's new account belongs to %s", got)
	}
	if got, want := lastAudit(t, f.store, action), (auditRecord{secondTenantID, AuditActorUnit}); got != want {
		t.Fatalf("%s audit record = %+v, want %+v", action, got, want)
	}
	if after := tenantAccountDigest(t, f.store, f.a); after != before {
		t.Fatal("tenant B's new account changed tenant A")
	}
}

// checkTenantSecurityWrite replaces recovery codes and revokes sessions
// through tenant B. On A's accounts it is refused, and A's recovery codes
// and sessions stay. On B's administrator it replaces B's code; the session
// named keeps preserved rows. Each tenant keeps its last enabled
// administrator.
func checkTenantSecurityWrite(t *testing.T, f tenantFixture, save func(ts *TenantStore, user User, codes []string) error, session string, preserved int) {
	t.Helper()
	assertTenantWritesOnlyItsAccounts(t, f, func(ts *TenantStore, id string) error {
		user := fixtureAccount(t, f, id)
		user.DisplayName = "Rotated"
		return save(ts, user, []string{"recovery-new-" + id})
	}, accountAdminB, "user.totp_disabled")
	for query, want := range map[string]int{
		`SELECT COUNT(*) FROM recovery_codes WHERE id_hash='recovery-admin-a'`:                   1,
		`SELECT COUNT(*) FROM recovery_codes WHERE user_id='` + accountAdminB + `'`:              1,
		`SELECT COUNT(*) FROM recovery_codes WHERE id_hash='recovery-new-` + accountAdminB + `'`: 1,
		`SELECT COUNT(*) FROM sessions WHERE id_hash='session-admin-a'`:                          1,
		`SELECT COUNT(*) FROM sessions WHERE id_hash='` + session + `'`:                          preserved,
	} {
		if got := countRows(t, f.store.DB, query); got != want {
			t.Errorf("%s = %d, want %d", query, got, want)
		}
	}
	for scope, id := range map[TenantScope]string{f.a: accountAdminA, f.b: accountAdminB} {
		admin := fixtureAccount(t, f, id)
		admin.Enabled = false
		if err := save(f.store.Tenant(scope), admin, nil); !errors.Is(err, ErrLastAdministrator) {
			t.Errorf("tenant %s disabled its last administrator: %v", scope.ID(), err)
		}
	}
}

// The accounts' global paths, which run before a tenant scope exists, find
// an account of any tenant and carry its tenant: the session, the account
// lookups, a link's redemption, a one-time code, a recovery code, and the
// sign-in timestamp. A tenant that is not active stops sign-in and the
// redemption of its links, and nothing else. The checks share one copy of
// the fixture, because opening a database is the slow part of these tests.
func TestAccountGlobalPathsCarryTheTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	now := time.Now().UTC()
	for account, tenant := range map[string]string{"admin-a": DefaultTenantID, "admin-b": secondTenantID} {
		session, err := f.store.GetSession(ctx, "session-"+account)
		if err != nil || session.TenantID != tenant {
			t.Fatalf("%s session = %+v, %v; want tenant %s", account, session, err, tenant)
		}
		// The session's scope is the tenant its account has now, and only
		// that one.
		if scope, err := f.store.TenantScopeForSession(ctx, session); err != nil || scope.ID() != tenant {
			t.Fatalf("%s session scope = %q, %v", account, scope.ID(), err)
		}
		byName, err := f.store.GetUserByUsername(ctx, strings.ToUpper(account))
		if err != nil || byName.TenantID != tenant || byName.ID != session.UserID {
			t.Fatalf("%s by username = %+v, %v", account, byName, err)
		}
		if byID, err := f.store.GetAccount(ctx, session.UserID); err != nil || byID.TenantID != tenant || byID.Username != account {
			t.Fatalf("%s by ID = %+v, %v", account, byID, err)
		}
	}
	session, err := f.store.GetSession(ctx, "session-admin-b")
	if err != nil {
		t.Fatal(err)
	}
	session.TenantID = DefaultTenantID
	if scope, err := f.store.TenantScopeForSession(ctx, session); !errors.Is(err, ErrNoTenantScope) || scope.Valid() {
		t.Fatalf("a session naming another tenant than its account's = %q, %v", scope.ID(), err)
	}
	if _, err := f.store.GetAccount(ctx, accountUnknown); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown account = %v", err)
	}

	// Tenant B's account signs in, with its one-time code and recovery code,
	// and the audit record belongs to B.
	if ok, err := f.store.ConsumeTOTPStep(ctx, accountAdminB, 7, now); err != nil || !ok {
		t.Fatalf("tenant B's one-time code = %v, %v", ok, err)
	}
	if ok, err := f.store.ConsumeTOTPStep(ctx, accountAdminB, 7, now); err != nil || ok {
		t.Fatalf("tenant B's replayed one-time code = %v, %v", ok, err)
	}
	if ok, err := f.store.ConsumeRecoveryCodeForUser(ctx, accountAdminB, "recovery-admin-b", now); err != nil || !ok {
		t.Fatalf("tenant B's recovery code = %v, %v", ok, err)
	}
	admin := fixtureAccount(t, f, accountAdminB)
	login := AuditEntry{Action: "admin.login", ActorUserID: accountAdminB, ActorUsername: "admin-b"}
	if err := f.store.CreateSessionForUserIfCurrent(ctx, accountAdminB, admin.PasswordHash, admin.Revision, false, "login-b", "csrf", now, now.Add(time.Hour), login); err != nil {
		t.Fatal(err)
	}
	if got, want := lastAudit(t, f.store, "admin.login"), (auditRecord{secondTenantID, AuditActorUnit}); got != want {
		t.Fatalf("tenant B's sign-in audit record = %+v, want %+v", got, want)
	}
	if err := f.store.SetUserLastLogin(ctx, accountAdminB, now); err != nil {
		t.Fatal(err)
	}
	if user, err := f.store.GetAccount(ctx, accountAdminB); err != nil || !user.LastLoginAt.Equal(now) {
		t.Fatalf("tenant B's last sign-in = %v, %v", user.LastLoginAt, err)
	}

	// Tenant B's link redeems, and the activation belongs to B.
	if usable, err := f.store.ActivationTokenUsable(ctx, "invite-operator-b", now); err != nil || !usable {
		t.Fatalf("tenant B's link usable = %v, %v", usable, err)
	}
	activated, err := f.store.ActivateUser(ctx, "invite-operator-b", "hash-activated", now, AuditEntry{Action: "user.activated"})
	if err != nil || activated.ID != accountOperatorB || activated.TenantID != secondTenantID {
		t.Fatalf("tenant B's activation = %+v, %v", activated, err)
	}
	if got, want := lastAudit(t, f.store, "user.activated"), (auditRecord{secondTenantID, AuditActorUnit}); got != want {
		t.Fatalf("tenant B's activation audit record = %+v, want %+v", got, want)
	}
	if err := f.store.Tenant(f.b).CreateUserInvite(ctx, "consume-b", accountOperatorB, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Tenant(f.b).CreateUserInvite(ctx, "paused-b", accountOperatorB, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if user, err := f.store.ConsumeUserInvite(ctx, "consume-b", now); err != nil || user.TenantID != secondTenantID {
		t.Fatalf("tenant B's consumed link = %+v, %v", user, err)
	}

	// A tenant that is not active stops sign-in and link redemption, and
	// the link stays unused. The default tenant is unaffected.
	for _, state := range []string{TenantStateDisabled, TenantStateDeleting} {
		setTenantState(t, f.store, secondTenantID, state)
		admin := fixtureAccount(t, f, accountAdminB)
		for label, create := range map[string]func() error{
			// Sign-in checks the tenant before it spends a one-time factor.
			"the check before a one-time factor": func() error {
				return f.store.RequireActiveAccountTenant(ctx, accountAdminB)
			},
			"sign-in": func() error {
				return f.store.CreateSessionForUserIfCurrent(ctx, accountAdminB, admin.PasswordHash, admin.Revision, false, "paused-login", "csrf", now, now.Add(time.Hour), login)
			},
			"sign-in with a password upgrade": func() error {
				return f.store.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, accountAdminB, admin.PasswordHash, "hash-upgraded", admin.Revision, false, "paused-login", "csrf", now, now.Add(time.Hour), login)
			},
			"legacy password upgrade": func() error {
				return f.store.CreateSessionForUserWithPasswordUpgrade(ctx, accountAdminB, admin.PasswordHash, "hash-upgraded", "paused-login", "csrf", now, now.Add(time.Hour), login)
			},
			"session": func() error {
				return f.store.CreateSessionForUserWithAuditEntry(ctx, accountAdminB, "paused-login", "csrf", now, now.Add(time.Hour), login)
			},
			"activation": func() error {
				_, err := f.store.ActivateUser(ctx, "paused-b", "hash-paused", now, AuditEntry{Action: "user.activated"})
				return err
			},
			"invite": func() error {
				_, err := f.store.ConsumeUserInvite(ctx, "paused-b", now)
				return err
			},
		} {
			if err := create(); !errors.Is(err, ErrTenantNotActive) {
				t.Errorf("%s tenant: %s = %v, want ErrTenantNotActive", state, label, err)
			}
		}
		if usable, err := f.store.ActivationTokenUsable(ctx, "paused-b", now); err != nil || usable {
			t.Errorf("%s tenant: link usable = %v, %v", state, usable, err)
		}
		if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE id_hash='paused-login'`); got != 0 {
			t.Errorf("%s tenant: %d sessions created", state, got)
		}
		if user, err := f.store.GetAccount(ctx, accountAdminB); err != nil || user.PasswordHash != admin.PasswordHash || user.Revision != admin.Revision {
			t.Errorf("%s tenant: the refused sign-in changed the account: %+v, %v", state, user, err)
		}
		adminA := fixtureAccount(t, f, accountAdminA)
		if err := f.store.RequireActiveAccountTenant(ctx, accountAdminA); err != nil {
			t.Errorf("%s tenant B: tenant A's check before a one-time factor = %v", state, err)
		}
		if err := f.store.CreateSessionForUserIfCurrent(ctx, accountAdminA, adminA.PasswordHash, adminA.Revision, false, "login-a-"+state, "csrf", now, now.Add(time.Hour), AuditEntry{}); err != nil {
			t.Errorf("%s tenant B: tenant A's sign-in = %v", state, err)
		}
	}
	setTenantState(t, f.store, secondTenantID, TenantStateActive)
	if usable, err := f.store.ActivationTokenUsable(ctx, "paused-b", now); err != nil || !usable {
		t.Fatalf("active tenant again: link usable = %v, %v", usable, err)
	}
	// An account of an active tenant passes the check, and so does an ID
	// that no account has, which the sign-in refuses on its own.
	for _, id := range []string{accountAdminB, accountUnknown} {
		if err := f.store.RequireActiveAccountTenant(ctx, id); err != nil {
			t.Errorf("active tenant again: the check before a one-time factor for %s = %v", id, err)
		}
	}
}

// Tenant B's actions on its own data are recorded in B's audit, and tenant
// A's audit is unchanged: every audited write of a job, an incident, a
// baseline reset with the discarded delivery it audits, a scanner profile,
// the update routing, a notification destination, the public status page,
// and an account. The store's tenant decides, not the entry: an entry
// without an actor, one that names the default tenant, and one whose actor
// is tenant A's administrator are all recorded in B. The actor kind is the
// actor's.
func TestTenantActionsAuditInTheActingTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	b := f.store.Tenant(f.b)
	destinations, profiles := tenantFixtureNotifications, tenantFixtureProfiles
	destination, err := b.GetManagedNotification(ctx, destinations.b)
	if err != nil {
		t.Fatal(err)
	}
	byAdminB := func(action string) AuditEntry {
		return AuditEntry{Action: action, Detail: "test", ActorUserID: accountAdminB, ActorUsername: "admin-b"}
	}
	operator := fixtureAccount(t, f, accountOperatorB)
	operator.DisplayName = "Operator B"
	// newJob and newProfile are created by the first checks and changed by
	// later ones, each at its current revision.
	var newJob JobRecord
	var newProfile ScannerProfileRecord
	current := func(id string) JobRecord {
		t.Helper()
		record, err := b.GetJob(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	beforeA := tenantRows(t, f.store, "security_audit", "tenant_id=?1", f.a)
	for _, check := range []struct {
		action string
		want   auditRecord
		run    func() error
	}{
		{"job.created", auditRecord{secondTenantID, AuditActorSystem}, func() (err error) {
			newJob, err = b.CreateJobWithEnabledAndAudit(ctx, testJob("edge-b-new"), true, AuditEntry{Action: "job.created", Detail: "edge-b-new"})
			return err
		}},
		{"job.disabled", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			return b.SetJobEnabledWithRevisionAndAudit(ctx, newJob.ID, false, current(newJob.ID).Revision, byAdminB("job.disabled"))
		}},
		{"job.archived", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			return b.SetJobArchivedWithRevisionAndAudit(ctx, newJob.ID, true, current(newJob.ID).Revision, byAdminB("job.archived"))
		}},
		{"job.deleted", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			return b.DeleteJobWithAudit(ctx, newJob.ID, byAdminB("job.deleted"))
		}},
		{"incident.accepted", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			expected := &IncidentExpectation{Change: tenantHistoryChange()}
			_, err := b.AcceptIncidentWithExpectedOutboxAndAudit(ctx, f.jobB, "edge", tenantHistoryIncident, expected, nil, byAdminB("incident.accepted"))
			return err
		}},
		// The reset's event names tenant A's destination, which B cannot
		// reach, so its delivery is discarded and the discard is audited.
		{"baseline.reset", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			_, err := b.ResetRuntimeWithOutboxAndAudit(ctx, f.archivedB, "edge-archived", []string{managedNotificationKey(destinations.a, 1)}, byAdminB("baseline.reset"))
			return err
		}},
		{"notifications.pending_discarded", auditRecord{secondTenantID, AuditActorSystem}, func() error { return nil }},
		{"job.updated", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			record := current(f.jobB)
			record.Job.Targets = []string{"192.0.2.99"}
			_, _, _, err := b.UpdateJobWithEventsWithOutboxAndAudit(ctx, f.jobB, record.Revision, record.Job, record.Enabled, record.Archived, true, nil, byAdminB("job.updated"))
			return err
		}},
		{"scanner_profile.updated", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			entry := AuditEntry{Action: "scanner_profile.updated", Detail: profiles.b, ActorUserID: accountAdminA, TenantID: DefaultTenantID}
			_, err := b.UpdateScannerProfile(ctx, profiles.b, 2, "edge", "tenant-b", config.ScannerProfile{Engine: config.EngineNmap, Description: "tenant-b v3"}, "admin-b", entry)
			return err
		}},
		{"scanner_profile.created", auditRecord{secondTenantID, AuditActorUnit}, func() (err error) {
			newProfile, err = b.CreateScannerProfile(ctx, "edge-new", "tenant-b", config.ScannerProfile{Engine: config.EngineNmap}, "admin-b", byAdminB("scanner_profile.created"))
			return err
		}},
		{"scanner_profile.archived", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			return b.SetScannerProfileArchived(ctx, newProfile.ID, true, newProfile.Revision, "admin-b", byAdminB("scanner_profile.archived"))
		}},
		{"notifications.update_routing", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			return b.SetApplicationUpdateDestinations(ctx, []string{}, byAdminB("notifications.update_routing"))
		}},
		{"notifications.created", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			_, err := b.CreateManagedNotificationWithAudit(ctx, "", "pager", "generic", []byte("sealed pager"), []byte("nonce pager"), true, byAdminB("notifications.created"))
			return err
		}},
		{"notifications.updated", auditRecord{secondTenantID, AuditActorUnit}, func() (err error) {
			destination, err = b.UpdateManagedNotificationWithAudit(ctx, destinations.b, destination.Revision, "ops-b", destination.Provider, destination.Ciphertext, destination.Nonce, true, byAdminB("notifications.updated"))
			return err
		}},
		{"notifications.deleted", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			_, err := b.DeleteManagedNotificationWithAudit(ctx, destinations.b, destination.Revision, byAdminB("notifications.deleted"))
			return err
		}},
		{"public_dashboard.updated", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			return b.SavePublicDashboard(ctx, PublicDashboard{Title: "Tenant B"}, nil, byAdminB("public_dashboard.updated"))
		}},
		{"user.updated", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			return b.UpdateUser(ctx, operator, false, byAdminB("user.updated"))
		}},
		{"scan.run_requested", auditRecord{secondTenantID, AuditActorUnit}, func() error {
			return b.AuditEntry(ctx, byAdminB("scan.run_requested"))
		}},
	} {
		if err := check.run(); err != nil {
			t.Fatalf("tenant B's %s: %v", check.action, err)
		}
		if got := lastAudit(t, f.store, check.action); got != check.want {
			t.Errorf("tenant B's %s audit record = %+v, want %+v", check.action, got, check.want)
		}
	}
	if afterA := tenantRows(t, f.store, "security_audit", "tenant_id=?1", f.a); afterA != beforeA {
		t.Fatalf("tenant B's actions changed tenant A's audit:\n%s", strings.TrimPrefix(afterA, beforeA))
	}
	// Tenant A's own action is recorded in A.
	if _, err := f.store.Tenant(f.a).CreateJobWithEnabledAndAudit(ctx, testJob("edge-a-new"), true, AuditEntry{Action: "job.created", Detail: "edge-a-new"}); err != nil {
		t.Fatal(err)
	}
	if got, want := lastAudit(t, f.store, "job.created"), (auditRecord{DefaultTenantID, AuditActorSystem}); got != want {
		t.Fatalf("tenant A's job.created audit record = %+v, want %+v", got, want)
	}
}

// A host command may write an audit record to a database from before
// schema 52, whose accounts have no tenant yet. The record falls back to the
// default tenant, or the tenant the entry names, with the entry's actor kind,
// or unit for an entry with an actor and system without one.
func TestAuditEntryBeforeSchema52UsesTheDefaultTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "schema51.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{
		`CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL)`,
		`CREATE TABLE security_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', actor_user_id TEXT NOT NULL DEFAULT '', actor_username TEXT NOT NULL DEFAULT '', source_ip TEXT NOT NULL DEFAULT '', request_id TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, tenant_id TEXT DEFAULT '` + DefaultTenantID + `', actor_kind TEXT NOT NULL DEFAULT '')`,
		`INSERT INTO users(id,username,role) VALUES('` + accountAdminA + `','admin','administrator')`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if schema, err := auditSchemaOf(ctx, db); err != nil || schema != auditSchemaBefore52 {
		t.Fatalf("audit schema = %d, %v; want before schema 52", schema, err)
	}
	for _, check := range []struct {
		entry        AuditEntry
		tenant, kind string
	}{
		{AuditEntry{Action: "user.login", ActorUserID: accountAdminA}, DefaultTenantID, AuditActorUnit},
		{AuditEntry{Action: "notifications.pending_discarded"}, DefaultTenantID, AuditActorSystem},
		{AuditEntry{Action: "database.restore", ActorKind: AuditActorHost, TenantID: secondTenantID}, secondTenantID, AuditActorHost},
		{AuditEntry{Action: "platform_admin.setup_token_issued", ActorKind: AuditActorHost, TenantID: secondTenantID, platform: true}, "<null>", AuditActorHost},
	} {
		if err := insertAuditEntryExec(ctx, db, check.entry, time.Now().UTC()); err != nil {
			t.Fatalf("%s: %v", check.entry.Action, err)
		}
		var tenant, kind, category string
		if err := db.QueryRowContext(ctx, `SELECT COALESCE(tenant_id,'<null>'),actor_kind,category FROM security_audit WHERE action=?`, check.entry.Action).Scan(&tenant, &kind, &category); err != nil {
			t.Fatal(err)
		}
		if tenant != check.tenant || kind != check.kind || category != auditCategory(check.entry.Action) {
			t.Errorf("%s audit record = %s/%s/%s, want %s/%s/%s", check.entry.Action, tenant, kind, category, check.tenant, check.kind, auditCategory(check.entry.Action))
		}
	}
}

// A record written without a TenantStore belongs to the tenant it names, or
// else to the tenant of its actor, with the kind of its actor:
//
//   - a record without a tenant takes its actor's: the tenant of a tenant's
//     account, or none, the platform, for a platform administrator;
//   - a record without either belongs to the default tenant;
//   - the kind is the entry's, or unit for a tenant's account, platform for
//     a platform administrator, and system without an account.
//
// An unknown actor kind is refused, and every new record has a kind.
func TestAuditRecordsTheActingTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	const platformAdmin = "00000000-0000-0000-0000-00000000fc01"
	insertTenantUser(t, f.store, platformAdmin, nil, RolePlatformAdmin)
	first := countRows(t, f.store.DB, `SELECT COALESCE(MAX(id),0) FROM security_audit`)

	for _, check := range []struct {
		entry AuditEntry
		want  auditRecord
	}{
		{AuditEntry{Action: "user.logout", ActorUserID: accountAdminB}, auditRecord{secondTenantID, AuditActorUnit}},
		{AuditEntry{Action: "user.login", ActorUserID: accountOperatorA}, auditRecord{DefaultTenantID, AuditActorUnit}},
		{AuditEntry{Action: "admin.login", ActorUserID: platformAdmin}, auditRecord{"<null>", AuditActorPlatform}},
		{AuditEntry{Action: "auth.login_failed", ActorUserID: accountUnknown}, auditRecord{DefaultTenantID, AuditActorUnit}},
		{AuditEntry{Action: "notifications.pending_discarded"}, auditRecord{DefaultTenantID, AuditActorSystem}},
		{AuditEntry{Action: "database.backup", ActorUsername: "host-cli", ActorKind: AuditActorHost}, auditRecord{DefaultTenantID, AuditActorHost}},
		{AuditEntry{Action: "user.password_reset", TenantID: secondTenantID, ActorKind: AuditActorHost}, auditRecord{secondTenantID, AuditActorHost}},
		{AuditEntry{Action: "auth.rate_limited", TenantID: secondTenantID, ActorKind: AuditActorUnit}, auditRecord{secondTenantID, AuditActorUnit}},
	} {
		if err := f.store.AuditEntry(ctx, check.entry); err != nil {
			t.Fatalf("%+v: %v", check.entry, err)
		}
		if got := lastAudit(t, f.store, check.entry.Action); got != check.want {
			t.Errorf("%+v: audit record = %+v, want %+v", check.entry, got, check.want)
		}
	}

	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	if err := f.store.AuditEntry(ctx, AuditEntry{Action: "user.logout", ActorKind: "robot"}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("unknown actor kind = %v", err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("an unknown actor kind wrote %d records", got-audits)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE id>? AND actor_kind=''`, first); got != 0 {
		t.Fatalf("%d new records have no actor kind", got)
	}
}
