package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"
)

// A sign-in's one-time factor is spent in the transaction that creates its
// session: a session that is not created leaves the TOTP time step and the
// recovery code unused, and a factor that another sign-in spent first is
// refused without a session. The checks before the session read the same
// state without changing it.
func TestSignInSessionSpendsItsFactorWithTheSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	user, err := defaultTenant(s).CreateUser(ctx, User{Username: "factor-user", Role: RoleViewer, PasswordHash: "current-hash", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("0123456789abcdef")
	sum := sha256.Sum256(append(append([]byte{}, salt...), "RECOVERYCODE"...))
	code := "v2$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + hex.EncodeToString(sum[:])
	if err := s.SaveRecoveryCodesForUser(ctx, user.ID, []string{code}); err != nil {
		t.Fatal(err)
	}
	sessionCount := func() int {
		t.Helper()
		var n int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, user.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	signIn := func(id string, factor SignInFactor, revision int64) error {
		return s.CreateSignInSession(ctx, SignInSession{UserID: user.ID, PasswordHash: "current-hash", Revision: revision, Factor: factor, IDHash: id, CSRF: "csrf", Created: now, Expires: now.Add(time.Hour), Audit: AuditEntry{Action: "user.login", Detail: "successful login", ActorUserID: user.ID}})
	}

	if available, err := s.TOTPStepAvailable(ctx, user.ID, 100); err != nil || !available {
		t.Fatalf("step 100 before any sign-in = %t, %v", available, err)
	}
	for _, check := range []struct {
		user string
		step int64
	}{{"", 100}, {user.ID, -1}} {
		if available, err := s.TOTPStepAvailable(ctx, check.user, check.step); err != nil || available {
			t.Fatalf("step %d of %q = %t, %v; want unavailable", check.step, check.user, available, err)
		}
	}
	for _, presented := range []string{"", "wrong-code"} {
		if match, err := s.MatchRecoveryCodeForUser(ctx, user.ID, presented); err != nil || match != "" {
			t.Fatalf("recovery code %q matched %q, %v", presented, match, err)
		}
	}
	match, err := s.MatchRecoveryCodeForUser(ctx, user.ID, " recovery code ")
	if err != nil || match != code {
		t.Fatalf("recovery code match = %q, %v; want the stored hash", match, err)
	}

	// A session refused for stale credentials, or failing to insert, spends
	// neither factor.
	if err := signIn("stale", SignInFactor{TOTPStep: 100, RecoveryCodeHash: match}, user.Revision+1); !errors.Is(err, ErrSessionCredentialsChanged) {
		t.Fatalf("sign-in with a stale revision = %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_login_audit BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := signIn("no-audit", SignInFactor{TOTPStep: 100, RecoveryCodeHash: match}, user.Revision); err == nil {
		t.Fatal("a sign-in without its audit record created a session")
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER fail_login_audit`); err != nil {
		t.Fatal(err)
	}
	if available, err := s.TOTPStepAvailable(ctx, user.ID, 100); err != nil || !available {
		t.Fatalf("step 100 after the failed sign-ins = %t, %v; want it unspent", available, err)
	}
	if again, err := s.MatchRecoveryCodeForUser(ctx, user.ID, "RECOVERYCODE"); err != nil || again != code {
		t.Fatalf("recovery code after the failed sign-ins = %q, %v; want it unused", again, err)
	}
	if got := sessionCount(); got != 0 {
		t.Fatalf("sessions after the failed sign-ins = %d, want none", got)
	}

	// The sign-in spends both factors with its session; each is refused
	// afterwards, without a session.
	if err := signIn("first", SignInFactor{TOTPStep: 100, RecoveryCodeHash: match}, user.Revision); err != nil {
		t.Fatal(err)
	}
	if available, err := s.TOTPStepAvailable(ctx, user.ID, 100); err != nil || available {
		t.Fatalf("step 100 after the sign-in = %t, %v; want it spent", available, err)
	}
	if available, err := s.TOTPStepAvailable(ctx, user.ID, 101); err != nil || !available {
		t.Fatalf("step 101 after the sign-in = %t, %v; want it available", available, err)
	}
	if err := signIn("replayed-step", SignInFactor{TOTPStep: 100}, user.Revision); !errors.Is(err, ErrTOTPReplay) {
		t.Fatalf("sign-in with a spent step = %v, want ErrTOTPReplay", err)
	}
	if err := signIn("used-code", SignInFactor{TOTPStep: NoTOTPStep, RecoveryCodeHash: match}, user.Revision); !errors.Is(err, ErrRecoveryCodeUsed) {
		t.Fatalf("sign-in with a used recovery code = %v, want ErrRecoveryCodeUsed", err)
	}
	if got := sessionCount(); got != 1 {
		t.Fatalf("sessions = %d, want the first sign-in's only", got)
	}
	if err := signIn("no-factor", NoSignInFactor, user.Revision); err != nil {
		t.Fatalf("sign-in without a factor = %v", err)
	}
	if err := s.CreateSignInSession(ctx, SignInSession{UserID: user.ID, PasswordHash: "current-hash", UpgradedPasswordHash: " ", Revision: user.Revision, Factor: NoSignInFactor, IDHash: "blank-upgrade", CSRF: "csrf", Created: now, Expires: now.Add(time.Hour)}); err == nil {
		t.Fatal("a blank upgraded password hash was accepted")
	}
}

// A sign-in session whose factor cannot be recorded is not created and
// leaves the factor as it was, and the checks before the session report a
// storage that cannot be read. The unconditional password-upgrade login
// primitive creates its session through the capped insert.
func TestSignInSessionStorageFailuresKeepTheFactor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	user, err := defaultTenant(s).CreateUser(ctx, User{Username: "factor-failures", Role: RoleViewer, PasswordHash: "current-hash", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRecoveryCodesForUser(ctx, user.ID, []string{"stored-code"}); err != nil {
		t.Fatal(err)
	}
	exec := func(statement string) {
		t.Helper()
		if _, err := s.DB.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	signIn := func(id string, factor SignInFactor) error {
		return s.CreateSignInSession(ctx, SignInSession{UserID: user.ID, PasswordHash: "current-hash", Revision: user.Revision, Factor: factor, IDHash: id, CSRF: "csrf", Created: now, Expires: now.Add(time.Hour)})
	}
	exec(`CREATE TRIGGER fail_replay_guard BEFORE INSERT ON totp_replay BEGIN SELECT RAISE(ABORT, 'replay guard unavailable'); END`)
	if err := signIn("step-failure", SignInFactor{TOTPStep: 7}); err == nil {
		t.Fatal("a session was created without recording its TOTP step")
	}
	exec(`DROP TRIGGER fail_replay_guard`)
	exec(`CREATE TRIGGER fail_recovery_use BEFORE UPDATE ON recovery_codes BEGIN SELECT RAISE(ABORT, 'recovery codes unavailable'); END`)
	if err := signIn("code-failure", SignInFactor{TOTPStep: NoTOTPStep, RecoveryCodeHash: "stored-code"}); err == nil {
		t.Fatal("a session was created without marking its recovery code used")
	}
	exec(`DROP TRIGGER fail_recovery_use`)
	var sessions, unused int
	if err := s.DB.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM sessions WHERE user_id=?1),(SELECT COUNT(*) FROM recovery_codes WHERE user_id=?1 AND used_at IS NULL)`, user.ID).Scan(&sessions, &unused); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || unused != 1 {
		t.Fatalf("after the failed sign-ins: sessions %d, unused recovery codes %d; want 0 and 1", sessions, unused)
	}
	if available, err := s.TOTPStepAvailable(ctx, user.ID, 7); err != nil || !available {
		t.Fatalf("step 7 after the failed sign-in = %t, %v; want it unspent", available, err)
	}

	exec(`ALTER TABLE totp_replay RENAME TO totp_replay_hidden`)
	if _, err := s.TOTPStepAvailable(ctx, user.ID, 7); err == nil {
		t.Fatal("an unreadable replay guard was reported as readable")
	}
	exec(`ALTER TABLE totp_replay_hidden RENAME TO totp_replay`)
	exec(`ALTER TABLE recovery_codes RENAME TO recovery_codes_hidden`)
	if _, err := s.MatchRecoveryCodeForUser(ctx, user.ID, "any-code"); err == nil {
		t.Fatal("unreadable recovery codes were reported as readable")
	}
	exec(`ALTER TABLE recovery_codes_hidden RENAME TO recovery_codes`)

	if err := s.CreateSessionForUserWithPasswordUpgrade(ctx, user.ID, "current-hash", "upgraded-hash", "upgraded-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "upgraded-session"); err != nil {
		t.Fatalf("session of the upgraded sign-in = %v", err)
	}
}

// The expired-session cleanup removes a session whose idle time ran out as
// well as one past its absolute expiry. A session used within the idle
// timeout stays, whatever its age.
func TestDeleteExpiredSessionsRemovesIdleSessions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, session := range []struct {
		id                string
		created, lastSeen time.Time
		expires           time.Time
	}{
		{"idle", now.Add(-48 * time.Hour), now.Add(-SessionIdleTimeout - time.Minute), now.Add(28 * 24 * time.Hour)},
		{"expired", now.Add(-31 * 24 * time.Hour), now.Add(-time.Hour), now.Add(-time.Minute)},
		{"recent", now.Add(-48 * time.Hour), now.Add(-SessionIdleTimeout + time.Minute), now.Add(28 * 24 * time.Hour)},
		{"new", now.Add(-time.Minute), now.Add(-time.Minute), now.Add(30 * 24 * time.Hour)},
	} {
		if err := s.CreateSession(ctx, session.id, "csrf-"+session.id, session.created, session.expires); err != nil {
			t.Fatal(err)
		}
		if err := s.TouchSession(ctx, session.id, session.lastSeen, session.expires); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := s.DeleteExpiredSessions(ctx, now)
	if err != nil || removed != 2 {
		t.Fatalf("removed sessions = %d, %v; want 2", removed, err)
	}
	for _, id := range []string{"idle", "expired"} {
		if _, err := s.GetSession(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("session %s = %v, want it removed", id, err)
		}
	}
	for _, id := range []string{"recent", "new"} {
		if _, err := s.GetSession(ctx, id); err != nil {
			t.Errorf("session %s was removed: %v", id, err)
		}
	}
}

// An account keeps at most MaxSessionsPerAccount sessions. Each new session
// removes the account's least recently used sessions beyond the cap, so the
// new session and the sessions in use stay; other accounts keep theirs.
func TestSessionsPerAccountAreCapped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	unit := defaultTenant(s)
	create := func(username string) User {
		t.Helper()
		user, err := unit.CreateUser(ctx, User{Username: username, Role: RoleViewer, PasswordHash: "unused-hash", Enabled: true}, AuditEntry{})
		if err != nil {
			t.Fatal(err)
		}
		return user
	}
	alice, bob := create("alice"), create("bob")
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	signIn := func(user User, id string, at time.Time) {
		t.Helper()
		if err := s.CreateSessionForUserWithAuditEntry(ctx, user.ID, id, "csrf", at, at.Add(30*24*time.Hour), AuditEntry{}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		signIn(bob, fmt.Sprintf("bob-%02d", i), start.Add(time.Duration(i)*time.Second))
	}
	for i := range MaxSessionsPerAccount {
		signIn(alice, fmt.Sprintf("alice-%02d", i), start.Add(time.Duration(i)*time.Second))
	}
	// The oldest session is in use again, so it is the most recently used.
	if err := s.TouchSession(ctx, "alice-00", start.Add(time.Minute), start.Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	count := func(user User) int {
		t.Helper()
		var n int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, user.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := count(alice); got != MaxSessionsPerAccount {
		t.Fatalf("alice's sessions at the cap = %d, want %d", got, MaxSessionsPerAccount)
	}
	// Two more sessions each remove the least recently used one.
	signIn(alice, "alice-new-1", start.Add(2*time.Minute))
	signIn(alice, "alice-new-2", start.Add(3*time.Minute))
	if got := count(alice); got != MaxSessionsPerAccount {
		t.Fatalf("alice's sessions after two more sign-ins = %d, want %d", got, MaxSessionsPerAccount)
	}
	for _, id := range []string{"alice-01", "alice-02"} {
		if _, err := s.GetSession(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("least recently used session %s = %v, want it removed", id, err)
		}
	}
	for _, id := range []string{"alice-00", "alice-03", "alice-new-1", "alice-new-2"} {
		if _, err := s.GetSession(ctx, id); err != nil {
			t.Errorf("session %s was removed: %v", id, err)
		}
	}
	if got := count(bob); got != 3 {
		t.Fatalf("bob's sessions = %d, want 3", got)
	}
}
