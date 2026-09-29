package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// The platform reads a unit's accounts as summaries: an account of another
// unit, a platform administrator, and an unknown ID are not found, and a
// deleted or unknown unit has no accounts. Revoking one account's sessions
// ends only that account's, and is recorded in its unit's audit as a
// platform action. The unit's capacity is read as its numbers.
func TestPlatformConsoleUnitAccounts(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	ps := f.store.Platform()

	accounts, err := ps.UnitAccounts(ctx, secondTenantID)
	if err != nil || !slices.Equal(usernames(accounts), []string{"admin-b", "operator-b"}) {
		t.Fatalf("unit B accounts = %v, %v", usernames(accounts), err)
	}
	for _, missing := range []string{accountUnknown, ""} {
		if _, err := ps.UnitAccounts(ctx, missing); !errors.Is(err, ErrNotFound) {
			t.Errorf("accounts of unit %q = %v, want ErrNotFound", missing, err)
		}
	}
	if account, err := ps.UnitAccount(ctx, secondTenantID, accountAdminB); err != nil || account.Username != "admin-b" || account.Role != RoleAdministrator {
		t.Fatalf("unit B administrator = %+v, %v", account, err)
	}
	for _, foreign := range []struct{ tenant, id string }{{secondTenantID, accountAdminA}, {secondTenantID, platformRoot}, {secondTenantID, accountUnknown}, {accountUnknown, accountAdminB}} {
		if _, err := ps.UnitAccount(ctx, foreign.tenant, foreign.id); !errors.Is(err, ErrNotFound) {
			t.Errorf("account %s of unit %s = %v, want ErrNotFound", foreign.id, foreign.tenant, err)
		}
	}

	sessions := func(id string) int {
		return countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, id)
	}
	for _, refused := range []struct {
		name, tenant, id string
		audit            AuditEntry
		want             error
	}{
		{"an account of another unit", secondTenantID, accountAdminA, platformAudit("user.sessions_revoked"), ErrNotFound},
		{"an unknown account", secondTenantID, accountUnknown, platformAudit("user.sessions_revoked"), ErrNotFound},
		{"by a unit's administrator", secondTenantID, accountOperatorB, accountAudit("user.sessions_revoked"), ErrAccountNotPermitted},
	} {
		if err := ps.RevokeUnitAccountSessions(ctx, refused.tenant, refused.id, refused.audit); !errors.Is(err, refused.want) {
			t.Errorf("revoke %s = %v, want %v", refused.name, err, refused.want)
		}
	}
	if sessions(accountAdminA) != 1 || sessions(accountOperatorB) != 1 {
		t.Fatal("a refused revocation ended a session")
	}
	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE tenant_id=? AND action='user.sessions_revoked' AND actor_kind=?`, secondTenantID, AuditActorPlatform)
	if err := ps.RevokeUnitAccountSessions(ctx, secondTenantID, accountOperatorB, platformAudit("user.sessions_revoked")); err != nil {
		t.Fatal(err)
	}
	if sessions(accountOperatorB) != 0 || sessions(accountAdminB) != 1 || sessions(accountAdminA) != 1 {
		t.Fatal("the revocation ended the wrong sessions")
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE tenant_id=? AND action='user.sessions_revoked' AND actor_kind=?`, secondTenantID, AuditActorPlatform); got != audits+1 {
		t.Fatalf("platform revocation records in unit B = %d, want %d", got, audits+1)
	}

	capacity, err := ps.TenantCapacity(ctx, secondTenantID)
	if err != nil || capacity.MaxConcurrentScans != nil {
		t.Fatalf("unit B capacity = %+v, %v", capacity, err)
	}
	slots := 1
	if err := ps.SetTenantCapacity(ctx, secondTenantID, TenantCapacity{MaxConcurrentScans: &slots}, CapacityLimits{MaxConcurrentScans: 2, MaxProbeCount: 10, MaxNaabuProbeCount: 10}, platformAudit("")); err != nil {
		t.Fatal(err)
	}
	if capacity, err := ps.TenantCapacity(ctx, secondTenantID); err != nil || capacity.MaxConcurrentScans == nil || *capacity.MaxConcurrentScans != 1 {
		t.Fatalf("capped unit B capacity = %+v, %v", capacity, err)
	}
	if _, err := f.store.DB.Exec(`UPDATE tenants SET state='deleted' WHERE id=?`, secondTenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := ps.TenantCapacity(ctx, secondTenantID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("capacity of a deleted unit = %v, want ErrNotFound", err)
	}
	if _, err := ps.UnitAccounts(ctx, secondTenantID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("accounts of a deleted unit = %v, want ErrNotFound", err)
	}
}

// A platform administrator invites another one, who stays pending and
// disabled until the invitation is redeemed, and enables or disables
// another platform administrator. It cannot change its own account there,
// a pending account cannot be enabled, a unit's account is not found, and
// disabling ends the account's sessions and revokes its links. Each change
// is recorded in platform scope.
func TestPlatformConsoleAdmins(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	ps := f.store.Platform()
	now := time.Now().UTC()

	admins, err := ps.PlatformAdmins(ctx)
	if err != nil || len(admins) != 1 || admins[0].ID != platformRoot {
		t.Fatalf("platform administrators = %+v, %v", admins, err)
	}
	for _, refused := range []struct {
		name, username, hash string
		expires              time.Time
		audit                AuditEntry
		want                 error
	}{
		{"by a unit's administrator", "invitee", "invite", now.Add(time.Hour), accountAudit(""), ErrAccountNotPermitted},
		{"a taken username", "admin-a", "invite", now.Add(time.Hour), platformAudit(""), ErrUsernameUnavailable},
		{"an invalid username", strings.Repeat("x", MaxUsernameBytes+1), "invite", now.Add(time.Hour), platformAudit(""), nil},
		{"without a token", "invitee", " ", now.Add(time.Hour), platformAudit(""), nil},
		{"with an expired token", "invitee", "invite", now, platformAudit(""), nil},
	} {
		_, err := ps.InvitePlatformAdmin(ctx, User{Username: refused.username}, refused.hash, now, refused.expires, refused.audit)
		if err == nil || (refused.want != nil && !errors.Is(err, refused.want)) {
			t.Errorf("invite %s = %v, want %v", refused.name, err, refused.want)
		}
	}
	invited, err := ps.InvitePlatformAdmin(ctx, User{Username: "Platform-Two"}, "invite-two", now, now.Add(time.Hour), platformAudit(""))
	if err != nil || invited.Username != "platform-two" || invited.DisplayName != "platform-two" || !invited.Pending || invited.Enabled || invited.Role != RolePlatformAdmin {
		t.Fatalf("invited platform administrator = %+v, %v", invited, err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM users WHERE id=? AND tenant_id IS NULL`, invited.ID); got != 1 {
		t.Fatal("the invited platform administrator has a tenant")
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE action=? AND tenant_id IS NULL AND actor_kind=?`, auditPlatformAdminInvited, AuditActorPlatform); got != 1 {
		t.Fatalf("invitation records = %d", got)
	}
	if _, err := ps.SetPlatformAdminEnabled(ctx, invited.ID, 0, true, platformAudit("")); !errors.Is(err, ErrAccountNotPermitted) {
		t.Fatalf("enable a pending platform administrator = %v", err)
	}
	if _, err := f.store.ActivateUser(ctx, "invite-two", "activated-hash", now, AuditEntry{Action: "user.activated"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES('session-two',?,?,?,?,'csrf')`, invited.ID, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`INSERT INTO user_invites(id_hash,user_id,issuer_user_id,created_at,expires_at) VALUES('issued-by-two',?,?,?,?)`, accountAdminB, invited.ID, now.Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	admins, err = ps.PlatformAdmins(ctx)
	if err != nil || len(admins) != 2 || !admins[1].Enabled || admins[1].Pending {
		t.Fatalf("platform administrators after the activation = %+v, %v", admins, err)
	}
	current := admins[1]

	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	for _, refused := range []struct {
		name, id string
		revision int64
		audit    AuditEntry
		want     error
	}{
		{"itself", platformRoot, 0, platformAudit(""), ErrAccountNotPermitted},
		{"by a unit's administrator", invited.ID, 0, accountAudit(""), ErrAccountNotPermitted},
		{"a unit's account", accountAdminA, 0, platformAudit(""), ErrNotFound},
		{"an unknown account", accountUnknown, 0, platformAudit(""), ErrNotFound},
		{"at a stale revision", invited.ID, current.Revision - 1, platformAudit(""), ErrConflict},
	} {
		if _, err := ps.SetPlatformAdminEnabled(ctx, refused.id, refused.revision, false, refused.audit); !errors.Is(err, refused.want) {
			t.Errorf("disable %s = %v, want %v", refused.name, err, refused.want)
		}
	}
	if unchanged, err := ps.SetPlatformAdminEnabled(ctx, invited.ID, current.Revision, true, platformAudit("")); err != nil || unchanged.Revision != current.Revision {
		t.Fatalf("enable an enabled platform administrator = %+v, %v", unchanged, err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("refused or idle changes wrote %d audit records", got-audits)
	}
	disabled, err := ps.SetPlatformAdminEnabled(ctx, invited.ID, current.Revision, false, platformAudit(""))
	if err != nil || disabled.Enabled || disabled.Revision != current.Revision+1 {
		t.Fatalf("disabled platform administrator = %+v, %v", disabled, err)
	}
	if countRows(t, f.store.DB, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, invited.ID) != 0 || countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites WHERE id_hash='issued-by-two' AND used_at IS NULL`) != 0 {
		t.Fatal("disabling kept the account's sessions or links")
	}
	if enabled, err := ps.SetPlatformAdminEnabled(ctx, invited.ID, 0, true, platformAudit("")); err != nil || !enabled.Enabled {
		t.Fatalf("enabled platform administrator = %+v, %v", enabled, err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE action=? AND tenant_id IS NULL AND actor_kind=?`, auditPlatformAdminUpdated, AuditActorPlatform); got != 2 {
		t.Fatalf("update records = %d, want 2", got)
	}
}

// A pending platform administrator has not redeemed its invitation, so it is
// neither enabled nor disabled: a request to disable it is refused with
// ErrAccountNotPermitted, like one to enable it, and changes nothing. Its
// invitation link stays usable until it is revoked, which is the way to stop
// it.
func TestPlatformConsoleRefusesToDisableAPendingAdmin(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	ps := f.store.Platform()
	now := time.Now().UTC()
	invited, err := ps.InvitePlatformAdmin(ctx, User{Username: "platform-two"}, "invite-two", now, now.Add(time.Hour), platformAudit(""))
	if err != nil {
		t.Fatal(err)
	}
	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	for _, revision := range []int64{0, invited.Revision} {
		if admin, err := ps.SetPlatformAdminEnabled(ctx, invited.ID, revision, false, platformAudit("")); !errors.Is(err, ErrAccountNotPermitted) {
			t.Errorf("disable a pending platform administrator at revision %d = %+v, %v; want ErrAccountNotPermitted", revision, admin, err)
		}
	}
	admins, err := ps.PlatformAdmins(ctx)
	if err != nil || len(admins) != 2 || admins[1].ID != invited.ID || !admins[1].Pending || admins[1].Enabled || admins[1].Revision != invited.Revision {
		t.Fatalf("platform administrators after the refused disable = %+v, %v", admins, err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("the refused disable wrote %d audit records", got-audits)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites WHERE id_hash='invite-two' AND used_at IS NULL`); got != 1 {
		t.Fatal("the refused disable used the invitation")
	}
}

// Revoking a pending platform administrator's invitation marks its unused
// links used, so none can activate the account, which stays pending and
// disabled, and records the revocation in platform scope. Only an enabled
// platform administrator revokes, and only a pending account's invitation:
// an account that redeemed its link, the actor's own included, is refused,
// and a unit's account is not found. A second revocation finds no link and
// records nothing.
func TestPlatformConsoleRevokesAPendingAdminInvitation(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	insertTenantUser(t, f.store, platformOther, nil, RolePlatformAdmin)
	ps := f.store.Platform()
	now := time.Now().UTC()
	invited, err := ps.InvitePlatformAdmin(ctx, User{Username: "platform-two"}, "invite-two", now, now.Add(time.Hour), platformAudit(""))
	if err != nil {
		t.Fatal(err)
	}
	usable := func() int {
		return countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites WHERE user_id=? AND used_at IS NULL`, invited.ID)
	}
	revocations := func() int {
		return countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE action=? AND tenant_id IS NULL AND actor_kind=?`, auditPlatformAdminActivationRevoked, AuditActorPlatform)
	}

	for _, refused := range []struct {
		name, id string
		audit    AuditEntry
		want     error
	}{
		{"by a unit's administrator", invited.ID, accountAudit(""), ErrAccountNotPermitted},
		{"by nobody", invited.ID, AuditEntry{}, ErrAccountNotPermitted},
		{"of an enabled platform administrator", platformOther, platformAudit(""), ErrAccountNotPermitted},
		{"of the actor's own account", platformRoot, platformAudit(""), ErrAccountNotPermitted},
		{"of a unit's account", accountAdminB, platformAudit(""), ErrNotFound},
		{"of an unknown account", accountUnknown, platformAudit(""), ErrNotFound},
	} {
		if revoked, err := ps.RevokePlatformAdminInvitation(ctx, refused.id, now, refused.audit); !errors.Is(err, refused.want) || revoked != 0 {
			t.Errorf("revoke %s = %d, %v; want %v", refused.name, revoked, err, refused.want)
		}
	}
	if usable() != 1 || revocations() != 0 || countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites WHERE used_at IS NULL AND user_id=?`, accountAdminB) != 0 {
		t.Fatal("a refused revocation changed a link or recorded a revocation")
	}

	if revoked, err := ps.RevokePlatformAdminInvitation(ctx, invited.ID, now, platformAudit("")); err != nil || revoked != 1 {
		t.Fatalf("revoke the invitation = %d, %v; want 1", revoked, err)
	}
	if usable() != 0 || revocations() != 1 {
		t.Fatalf("after the revocation the account has %d usable links and the platform audit %d revocations", usable(), revocations())
	}
	if _, err := f.store.ActivateUser(ctx, "invite-two", "activated-hash", now, AuditEntry{Action: "user.activated"}); err == nil {
		t.Fatal("the revoked invitation activated the account")
	}
	admins, err := ps.PlatformAdmins(ctx)
	if err != nil || len(admins) != 3 {
		t.Fatalf("platform administrators = %+v, %v", admins, err)
	}
	for _, admin := range admins {
		if admin.ID == invited.ID && (!admin.Pending || admin.Enabled) {
			t.Fatalf("the account of the revoked invitation = %+v, want it pending and disabled", admin)
		}
	}
	if revoked, err := ps.RevokePlatformAdminInvitation(ctx, invited.ID, now, platformAudit("")); err != nil || revoked != 0 || revocations() != 1 {
		t.Fatalf("revoke again = %d, %v, with %d revocations recorded; want 0 and 1", revoked, err, revocations())
	}

	// A link that expired is already unusable: revoking it finds nothing.
	expiring, err := ps.InvitePlatformAdmin(ctx, User{Username: "platform-three"}, "invite-three", now, now.Add(time.Minute), platformAudit(""))
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := ps.RevokePlatformAdminInvitation(ctx, expiring.ID, now.Add(2*time.Minute), platformAudit("")); err != nil || revoked != 0 || revocations() != 1 {
		t.Fatalf("revoke an expired invitation = %d, %v, with %d revocations recorded", revoked, err, revocations())
	}

	// The revocation is written with its record, or not at all.
	fresh, err := ps.InvitePlatformAdmin(ctx, User{Username: "platform-four"}, "invite-four", now, now.Add(time.Hour), platformAudit(""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`CREATE TRIGGER refuse_revocation_audit BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if revoked, err := ps.RevokePlatformAdminInvitation(ctx, fresh.ID, now, platformAudit("")); !errors.Is(err, ErrAuditUnavailable) || revoked != 0 {
		t.Fatalf("revoke without an audit record = %d, %v; want ErrAuditUnavailable", revoked, err)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM user_invites WHERE id_hash='invite-four' AND used_at IS NULL`); got != 1 {
		t.Fatal("an unrecorded revocation used the invitation")
	}
}

// The platform's destinations are the web-managed destinations without a
// tenant. The platform creates, updates and deletes only those: a unit's
// destination is not found, and its pending deliveries are never touched.
// A change that keeps the credentials moves the platform's pending
// deliveries to the new revision, and a credential change discards them.
// Deleting a destination drops it from the platform's update routing.
func TestPlatformConsoleNotifications(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	ps := f.store.Platform()
	ids := tenantFixtureNotifications

	if destination, err := ps.GetPlatformNotification(ctx, ids.platform); err != nil || destination.Name != "ops" || destination.TenantID != "" {
		t.Fatalf("platform destination = %+v, %v", destination, err)
	}
	for _, foreign := range []string{ids.a, ids.b, unknownNotificationID} {
		if _, err := ps.GetPlatformNotification(ctx, foreign); !errors.Is(err, ErrNotFound) {
			t.Errorf("platform read of %s = %v, want ErrNotFound", foreign, err)
		}
	}
	for _, refused := range []struct {
		name, id, title string
		sealed          []byte
		audit           AuditEntry
	}{
		{"without a name", "", "", []byte("sealed"), platformAudit("")},
		{"without credentials", "", "alerts", nil, platformAudit("")},
		{"by a unit's administrator", "", "alerts", []byte("sealed"), accountAudit("")},
		{"with a taken name", "", "ops", []byte("sealed"), platformAudit("")},
	} {
		if _, err := ps.CreatePlatformNotificationWithAudit(ctx, refused.id, refused.title, "generic", refused.sealed, []byte("nonce"), true, refused.audit); err == nil {
			t.Errorf("create %s succeeded", refused.name)
		}
	}
	created, err := ps.CreatePlatformNotificationWithAudit(ctx, "", "alerts", "generic", []byte("sealed alerts"), []byte("nonce alerts"), true, platformAudit(""))
	if err != nil || created.ID == "" || created.TenantID != "" || created.Revision != 1 {
		t.Fatalf("created platform destination = %+v, %v", created, err)
	}

	queue := func(destination string, tenant any) {
		t.Helper()
		if _, err := f.store.DB.Exec(`INSERT INTO outbox(destination,payload_json,attempts,next_at,tenant_id) VALUES(?,?,0,?,?)`, destination, []byte(`{}`), time.Now().UTC().Format(time.RFC3339Nano), tenant); err != nil {
			t.Fatal(err)
		}
	}
	queue("managed:"+created.ID+":1", nil)
	queue("managed:"+ids.b+":1", secondTenantID)
	pending := func(destination string) int {
		return countRows(t, f.store.DB, `SELECT COUNT(*) FROM outbox WHERE destination=? AND sent_at IS NULL`, destination)
	}
	for _, foreign := range []string{ids.a, ids.b, unknownNotificationID} {
		if _, err := ps.UpdatePlatformNotificationWithAudit(ctx, foreign, 1, "renamed", "generic", []byte("sealed"), []byte("nonce"), true, platformAudit("")); !errors.Is(err, ErrNotFound) {
			t.Errorf("platform update of %s = %v, want ErrNotFound", foreign, err)
		}
		if err := ps.DeletePlatformNotificationWithAudit(ctx, foreign, 1, platformAudit("")); !errors.Is(err, ErrNotFound) {
			t.Errorf("platform delete of %s = %v, want ErrNotFound", foreign, err)
		}
	}
	for _, refused := range []struct {
		name     string
		revision int64
		title    string
		sealed   []byte
		audit    AuditEntry
		want     error
	}{
		{"at a stale revision", 2, "renamed", []byte("sealed alerts"), platformAudit(""), ErrConflict},
		{"by a unit's administrator", 1, "renamed", []byte("sealed alerts"), accountAudit(""), ErrAccountNotPermitted},
		{"without a name", 1, "", []byte("sealed alerts"), platformAudit(""), nil},
		{"without credentials", 1, "renamed", nil, platformAudit(""), nil},
	} {
		_, err := ps.UpdatePlatformNotificationWithAudit(ctx, created.ID, refused.revision, refused.title, "generic", refused.sealed, []byte("nonce alerts"), true, refused.audit)
		if err == nil || (refused.want != nil && !errors.Is(err, refused.want)) {
			t.Errorf("update %s = %v, want %v", refused.name, err, refused.want)
		}
	}
	renamed, err := ps.UpdatePlatformNotificationWithAudit(ctx, created.ID, 1, "alerts renamed", "generic", []byte("sealed alerts"), []byte("nonce alerts"), false, platformAudit(""))
	if err != nil || renamed.Name != "alerts renamed" || renamed.Enabled || renamed.Revision != 2 {
		t.Fatalf("renamed platform destination = %+v, %v", renamed, err)
	}
	if pending("managed:"+created.ID+":1") != 0 || pending("managed:"+created.ID+":2") != 1 {
		t.Fatal("a rename did not move the pending delivery to the new revision")
	}
	if _, err := ps.UpdatePlatformNotificationWithAudit(ctx, created.ID, 2, "alerts renamed", "generic", []byte("new sealed alerts"), []byte("new nonce"), true, platformAudit("")); err != nil {
		t.Fatal(err)
	}
	if pending("managed:"+created.ID+":2") != 0 || pending("managed:"+ids.b+":1") != 1 {
		t.Fatal("a credential change kept the platform's delivery or discarded unit B's")
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE action='notifications.pending_discarded' AND tenant_id IS NULL AND actor_kind=?`, AuditActorPlatform); got != 1 {
		t.Fatalf("platform discard records = %d, want 1", got)
	}

	if err := ps.SetPlatformUpdateDestinations(ctx, []string{created.ID, ids.platform, created.ID}, accountAudit("")); !errors.Is(err, ErrAccountNotPermitted) {
		t.Fatalf("routing by a unit's administrator = %v", err)
	}
	if err := ps.SetPlatformUpdateDestinations(ctx, []string{created.ID, ids.platform, created.ID}, platformAudit("")); err != nil {
		t.Fatal(err)
	}
	state, err := ps.GetApplicationUpdateState(ctx)
	if want := []string{created.ID, ids.platform}; err != nil || !slices.Equal(state.UpdateNotificationDestinations, sortedCopy(want)) {
		t.Fatalf("platform routing = %v, %v", state.UpdateNotificationDestinations, err)
	}
	routingB, err := f.store.Tenant(f.b).ApplicationUpdateRouting(ctx)
	if err != nil || !slices.Equal(routingB.Destinations, []string{ids.b}) {
		t.Fatalf("unit B routing = %+v, %v", routingB, err)
	}
	queue("managed:"+created.ID+":3", nil)
	if err := ps.DeletePlatformNotificationWithAudit(ctx, created.ID, 2, platformAudit("")); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete = %v", err)
	}
	if err := ps.DeletePlatformNotificationWithAudit(ctx, created.ID, 3, accountAudit("")); !errors.Is(err, ErrAccountNotPermitted) {
		t.Fatalf("delete by a unit's administrator = %v", err)
	}
	if err := ps.DeletePlatformNotificationWithAudit(ctx, created.ID, 3, platformAudit("")); err != nil {
		t.Fatal(err)
	}
	if _, err := ps.GetPlatformNotification(ctx, created.ID); !errors.Is(err, ErrNotFound) || pending("managed:"+created.ID+":3") != 0 || pending("managed:"+ids.b+":1") != 1 {
		t.Fatalf("after the delete: read %v, pending %d, unit B pending %d", err, pending("managed:"+created.ID+":3"), pending("managed:"+ids.b+":1"))
	}
	if state, err := ps.GetApplicationUpdateState(ctx); err != nil || !slices.Equal(state.UpdateNotificationDestinations, []string{ids.platform}) {
		t.Fatalf("platform routing after the delete = %v, %v", state.UpdateNotificationDestinations, err)
	}
	if err := ps.DeletePlatformNotificationWithAudit(ctx, ids.platform, 1, platformAudit("")); err != nil {
		t.Fatal(err)
	}
	for action, want := range map[string]int{auditPlatformNotificationsCreated: 1, auditPlatformNotificationsUpdated: 2, auditPlatformNotificationsDeleted: 2, auditPlatformNotificationsUpdateRouting: 3} {
		if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE action=? AND tenant_id IS NULL AND actor_kind=?`, action, AuditActorPlatform); got != want {
			t.Errorf("%s records = %d, want %d", action, got, want)
		}
	}
	if _, err := f.store.DB.Exec(`DELETE FROM application_update_state`); err != nil {
		t.Fatal(err)
	}
	if err := ps.SetPlatformUpdateDestinations(ctx, nil, platformAudit("")); err != nil {
		t.Fatal(err)
	}
	if state, err := ps.GetApplicationUpdateState(ctx); err != nil || len(state.UpdateNotificationDestinations) != 0 || !state.UpdateNotificationDestinationsConfigured {
		t.Fatalf("platform routing on a new row = %+v, %v", state, err)
	}
}

// The platform's update routing selects only platform destinations. The
// store checks this in the transaction of the write, after the actor,
// whatever its caller checked: a unit's destination, a deployment
// destination, which is the default unit's, an unknown ID, and a platform
// destination deleted since the caller's check are refused alike, and the
// routing, the units' routing, and the platform audit stay as they were.
func TestPlatformUpdateRoutingSelectsOnlyPlatformDestinations(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	ps := f.store.Platform()
	ids := tenantFixtureNotifications
	if err := ps.SetPlatformUpdateDestinations(ctx, []string{ids.platform}, platformAudit("")); err != nil {
		t.Fatalf("the platform's own destination: %v", err)
	}
	routing := func() []string {
		t.Helper()
		state, err := ps.GetApplicationUpdateState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return state.UpdateNotificationDestinations
	}
	if got := routing(); !slices.Equal(got, []string{ids.platform}) {
		t.Fatalf("platform routing = %v", got)
	}
	audits := func() int {
		return countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE action=? AND tenant_id IS NULL`, auditPlatformNotificationsUpdateRouting)
	}
	units := func() [2]string {
		return [2]string{tenantNotificationDigest(t, f.store, f.a), tenantNotificationDigest(t, f.store, f.b)}
	}
	beforeAudits, beforeUnits := audits(), units()
	for _, selector := range []string{ids.a, ids.pausedA, ids.b, unknownNotificationID, "file:deployment"} {
		assertSelectionRefused(t, ps.SetPlatformUpdateDestinations(ctx, []string{ids.platform, selector}, platformAudit("")), selector)
	}
	if err := ps.SetPlatformUpdateDestinations(ctx, []string{ids.b}, accountAudit("")); !errors.Is(err, ErrAccountNotPermitted) {
		t.Errorf("routing by a unit's administrator = %v, want ErrAccountNotPermitted", err)
	}
	if got := routing(); !slices.Equal(got, []string{ids.platform}) || audits() != beforeAudits || units() != beforeUnits {
		t.Fatalf("a refused routing write changed the routing %v, the platform audit, or a unit", got)
	}

	// The caller checked the selection before this delete; the write after
	// it must not store the deleted destination.
	if err := ps.DeletePlatformNotificationWithAudit(ctx, ids.platform, 1, platformAudit("")); err != nil {
		t.Fatal(err)
	}
	assertSelectionRefused(t, ps.SetPlatformUpdateDestinations(ctx, []string{ids.platform}, platformAudit("")), ids.platform)
	if got := routing(); len(got) != 0 {
		t.Fatalf("platform routing after the refused write = %v", got)
	}
}

func sortedCopy(values []string) []string {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	return sorted
}
