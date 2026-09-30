package auth

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// throttledAnswerBound is how long a refused sign-in may take in the tests
// below while the audit writer is busy. A refusal reads one account and
// checks the limiter in memory; the audit write that the busy writer holds
// back waits up to five seconds.
const throttledAnswerBound = 2 * time.Second

// Once a client has used its sign-in budget, a refused sign-in answers
// without waiting for the audit writer, for a username of any unit, of the
// platform, or of no account alike: whether the refusal is the first in its
// scope, and so writes an auth.rate_limited record, does not change how long
// the answer takes. The records are still written once the writer is free,
// one per scope.
func TestThrottledSignInDoesNotWaitForTheAuditWriter(t *testing.T) {
	ctx := context.Background()
	s, admin, _ := platformTestStore(t)
	addSecondUnit(t, s)
	scope, err := s.TenantScopeByID(ctx, platformTestTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tenant(scope).CreateUser(ctx, store.User{Username: "bravo-viewer", Role: store.RoleViewer, PasswordHash: cheapHash("unit b viewer password"), Enabled: true}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,enabled,created_at,updated_at) VALUES('00000000-0000-0000-0000-00000000fa05',NULL,'platform-root','platform-root',?,?,1,?,?)`, store.RolePlatformAdmin, cheapHash("platform administrator password"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	m := NewManager(s)
	const client = "203.0.113.90"
	from := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = client + ":4000"
		return r
	}
	for attempt := 0; attempt < authFailureThreshold; attempt++ {
		if _, _, err := m.LoginAs(ctx, from(), "guess-"+strconv.Itoa(attempt), "wrong password", "", ""); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("unknown username %d = %v, want invalid credentials", attempt, err)
		}
	}

	// A transaction holds the only writer connection, as a long write
	// elsewhere in the daemon does, so no audit record can be written.
	writer, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_ = writer.Rollback()
		}
	}
	defer release()
	for _, username := range []string{"nobody-anywhere", admin.Username, "bravo-viewer", "platform-root", "another-nobody", "unit-operator"} {
		started := time.Now()
		raw, _, err := m.LoginAs(ctx, from(), username, "wrong password", "", "")
		elapsed := time.Since(started)
		if raw != "" || !errors.Is(err, ErrRateLimited) || RetryAfterHeaderValue(err) != RetryAfterHeaderValue(ErrRateLimited) {
			t.Fatalf("throttled sign-in as %s = %q, %v; want the rate-limit error", username, raw, err)
		}
		if elapsed > throttledAnswerBound {
			t.Errorf("throttled sign-in as %s took %s while the audit writer was busy, want at most %s", username, elapsed.Round(time.Millisecond), throttledAnswerBound)
		}
	}
	release()

	// Once the writer is free, each scope has its one record.
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{store.DefaultTenantID: 1, platformTestTenantID: 1, "<null>": 1}
	if got := rateLimitRecordsPerScope(t, s, client); !maps.Equal(got, want) {
		t.Fatalf("rate-limit records per scope = %v, want %v", got, want)
	}
}

// A refused sign-in whose rate-limit record finds no free background write
// answers at once and writes no record; the scope's next refusal writes it.
func TestRateLimitRecordWithoutRoomIsWrittenByTheNextRefusal(t *testing.T) {
	ctx := context.Background()
	s, admin, _ := platformTestStore(t)
	m := NewManager(s)
	const client = "203.0.113.91"
	from := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = client + ":4000"
		return r
	}
	for attempt := 0; attempt < authFailureThreshold; attempt++ {
		if _, _, err := m.LoginAs(ctx, from(), admin.Username, "wrong password", "", ""); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("wrong password %d = %v, want invalid credentials", attempt, err)
		}
	}
	for range rateLimitRecordsPending {
		m.rateRecordSlots <- struct{}{}
	}
	if _, _, err := m.LoginAs(ctx, from(), admin.Username, "wrong password", "", ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("throttled sign-in = %v, want ErrRateLimited", err)
	}
	for range rateLimitRecordsPending {
		<-m.rateRecordSlots
	}
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rateLimitRecordsPerScope(t, s, client); len(got) != 0 {
		t.Fatalf("rate-limit records without room = %v, want none", got)
	}
	if _, _, err := m.LoginAs(ctx, from(), admin.Username, "wrong password", "", ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("throttled sign-in = %v, want ErrRateLimited", err)
	}
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := rateLimitRecordsPerScope(t, s, client), map[string]int{store.DefaultTenantID: 1}; !maps.Equal(got, want) {
		t.Fatalf("rate-limit records after the next refusal = %v, want %v", got, want)
	}
	// The wait ends with its context while a record waits for the writer.
	writer, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback() }()
	other := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	other.RemoteAddr = "203.0.113.92:4000"
	m.auditLoginRateLimit(ctx, "nobody-here", other)
	expired, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	if err := m.WaitForRateLimitRecords(expired); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait with a busy writer = %v, want the context's deadline", err)
	}
	_ = writer.Rollback()
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}
}

// rateLimitRecordsPerScope counts the auth.rate_limited records from the
// address per tenant, "<null>" for platform scope.
func rateLimitRecordsPerScope(t *testing.T, s *store.Store, address string) map[string]int {
	t.Helper()
	rows, err := s.DB.Query(`SELECT COALESCE(tenant_id,'<null>') FROM security_audit WHERE action='auth.rate_limited' AND source_ip=?`, address)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			t.Fatal(err)
		}
		counts[tenant]++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return counts
}

// factorFixturePassword is the password of the factor fixture's account.
const factorFixturePassword = "totp operator password"

// factorFixture is a store with an account that has TOTP and ten recovery
// codes, and a manager whose clock can run a change while a sign-in runs.
type factorFixture struct {
	s     *store.Store
	m     *Manager
	user  store.User
	codes []string
	now   time.Time
	// reads counts the clock reads of the current sign-in; during runs at
	// the read numbered at.
	reads, at int
	during    func()
	clients   int
}

func newFactorFixture(t *testing.T) *factorFixture {
	t.Helper()
	ctx := context.Background()
	s, _, _ := platformTestStore(t)
	unit := s.Tenant(store.DefaultTenantScope())
	// The account's password hash is older than the current policy, so a
	// sign-in upgrades it.
	user, err := unit.CreateUser(ctx, store.User{Username: "totp-operator", Role: store.RoleOperator, PasswordHash: cheapHash(factorFixturePassword), Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	plain, hashes, err := RecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	user.TOTPEnabled, user.TOTPSecret = true, "JBSWY3DPEHPK3PXP"
	if err := unit.SaveUserSecurity(ctx, user, hashes, true, false, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	f := &factorFixture{s: s, m: NewManager(s), user: user, codes: plain, now: time.Now().UTC(), at: 3}
	// A sign-in reads the clock for the client limits twice, then to check
	// the one-time code after the password, then for the session. The third
	// read is where a change made while the sign-in runs lands, unless the
	// test chooses another.
	f.m.Now = func() time.Time {
		f.reads++
		if f.reads == f.at && f.during != nil {
			during := f.during
			f.during = nil
			during()
		}
		return f.now
	}
	return f
}

// signIn signs the fixture's account in from a client of its own.
func (f *factorFixture) signIn(password, otp, recovery string) (string, error) {
	f.clients++
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	r.RemoteAddr = "192.0.2." + strconv.Itoa(f.clients) + ":1234"
	f.reads = 0
	raw, _, err := f.m.LoginAs(context.Background(), r, "totp-operator", password, otp, recovery)
	return raw, err
}

func (f *factorFixture) exec(t *testing.T, statement string, args ...any) {
	t.Helper()
	if _, err := f.s.DB.ExecContext(context.Background(), statement, args...); err != nil {
		t.Fatal(err)
	}
}

func (f *factorFixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.s.DB.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A sign-in that fails after its one-time factor was checked spends
// nothing: the TOTP time step stays unrecorded and the recovery code
// unused, and no auth.recovery_code_used record is written. That holds
// whether the session cannot be written because the security audit or the
// session storage is unavailable, the password-check queue refuses the
// upgrade of an older password hash, or the password changes during the
// sign-in. Once the cause is gone, the same factor signs in, once.
func TestFailedSignInSpendsNoOneTimeFactor(t *testing.T) {
	const password = factorFixturePassword
	for _, cause := range []struct {
		name string
		// fail arranges for the next sign-in to fail after its factor is
		// checked, and returns what undoes that and the password to sign in
		// with afterwards.
		fail    func(t *testing.T, f *factorFixture) (func(), string)
		wantErr func(error) bool
	}{
		{"the security audit is unavailable", func(t *testing.T, f *factorFixture) (func(), string) {
			f.exec(t, `CREATE TRIGGER fail_login_audit BEFORE INSERT ON security_audit WHEN NEW.action LIKE '%.login' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`)
			return func() { f.exec(t, `DROP TRIGGER fail_login_audit`) }, password
		}, func(err error) bool { return errors.Is(err, store.ErrAuditUnavailable) }},
		{"the session cannot be stored", func(t *testing.T, f *factorFixture) (func(), string) {
			f.exec(t, `CREATE TRIGGER fail_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'session storage unavailable'); END`)
			return func() { f.exec(t, `DROP TRIGGER fail_session`) }, password
		}, func(err error) bool { return err != nil && !errors.Is(err, ErrRateLimited) }},
		{"the password-check queue refuses the hash upgrade", func(t *testing.T, f *factorFixture) (func(), string) {
			f.during = func() {
				for range authArgon2MaxConcurrent {
					f.m.argon2Sem <- struct{}{}
				}
			}
			return func() {
				for range authArgon2MaxConcurrent {
					<-f.m.argon2Sem
				}
			}, password
		}, func(err error) bool { return errors.Is(err, ErrRateLimited) }},
		{"the password changes during the sign-in", func(t *testing.T, f *factorFixture) (func(), string) {
			const changed = "changed operator password"
			f.during = func() {
				f.exec(t, `UPDATE users SET password_hash=?,revision=revision+1 WHERE id=?`, cheapHash(changed), f.user.ID)
			}
			return func() {}, changed
		}, func(err error) bool { return err != nil && !errors.Is(err, ErrRateLimited) }},
	} {
		for _, factor := range []string{"TOTP code", "recovery code"} {
			t.Run(cause.name+", "+factor, func(t *testing.T) {
				f := newFactorFixture(t)
				step := f.now.Unix() / 30
				otp, recovery := totpCode(f.user.TOTPSecret, step), ""
				if factor == "recovery code" {
					otp, recovery = "", f.codes[0]
				}
				undo, retryPassword := cause.fail(t, f)
				raw, err := f.signIn(password, otp, recovery)
				if raw != "" || !cause.wantErr(err) {
					t.Fatalf("sign-in = %q, %v; want it to fail", raw, err)
				}
				undo()
				if got := f.count(t, `SELECT COUNT(*) FROM totp_replay WHERE user_id=? AND last_step>=?`, f.user.ID, step-1); got != 0 {
					t.Errorf("the failed sign-in recorded the TOTP time step")
				}
				if got := f.count(t, `SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL`, f.user.ID); got != len(f.codes) {
					t.Errorf("unused recovery codes after the failed sign-in = %d, want %d", got, len(f.codes))
				}
				if got := f.count(t, `SELECT COUNT(*) FROM security_audit WHERE action='auth.recovery_code_used'`); got != 0 {
					t.Errorf("the failed sign-in wrote %d auth.recovery_code_used records", got)
				}
				if raw, err := f.signIn(retryPassword, otp, recovery); err != nil || raw == "" {
					t.Fatalf("sign-in with the same %s afterwards = %q, %v", factor, raw, err)
				}
				f.checkSpentOnce(t, factor, step)
				// The factor is still accepted once.
				if raw, err := f.signIn(retryPassword, otp, recovery); err == nil || raw != "" {
					t.Fatalf("second sign-in with the same %s = %q, %v; want it refused", factor, raw, err)
				}
			})
		}
	}
}

// checkSpentOnce checks that one sign-in spent the factor: the recovery code
// is used, with one auth.recovery_code_used record, or the TOTP time step is
// recorded.
func (f *factorFixture) checkSpentOnce(t *testing.T, factor string, step int64) {
	t.Helper()
	if factor == "recovery code" {
		if got := f.count(t, `SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL`, f.user.ID); got != len(f.codes)-1 {
			t.Errorf("unused recovery codes after the sign-in = %d, want %d", got, len(f.codes)-1)
		}
		if got := f.count(t, `SELECT COUNT(*) FROM security_audit WHERE action='auth.recovery_code_used'`); got != 1 {
			t.Errorf("auth.recovery_code_used records after the sign-in = %d, want 1", got)
		}
		return
	}
	if got := f.count(t, `SELECT COUNT(*) FROM totp_replay WHERE user_id=? AND last_step=?`, f.user.ID, step); got != 1 {
		t.Errorf("the sign-in did not record the TOTP time step")
	}
}

// A sign-in whose factor another sign-in spends after it was checked, and
// before the session is created, gets the answer of a wrong code and costs
// the client's budget, without a session. A sign-in retried after a
// concurrent change that left the password valid, such as a display-name
// edit, spends its factor once, with the retried session; one retried after
// a TOTP re-enrolment needs a code of the new secret and spends nothing.
func TestSignInFactorRacesAreResolvedInTheSessionTransaction(t *testing.T) {
	for _, factor := range []string{"TOTP code", "recovery code"} {
		present := func(f *factorFixture) (string, string, int64) {
			step := f.now.Unix() / 30
			if factor == "recovery code" {
				return "", f.codes[0], step
			}
			return totpCode(f.user.TOTPSecret, step), "", step
		}
		t.Run("spent by another sign-in, "+factor, func(t *testing.T) {
			f := newFactorFixture(t)
			otp, recovery, step := present(f)
			// The fourth clock read comes after the factor check, for the
			// session.
			f.at = 4
			f.during = func() {
				ctx := context.Background()
				if factor == "recovery code" {
					if used, err := f.s.ConsumeRecoveryCodeTextForUser(ctx, f.user.ID, recovery, f.now); err != nil || !used {
						t.Errorf("spending the recovery code elsewhere = %t, %v", used, err)
					}
				} else if accepted, err := f.s.ConsumeTOTPStep(ctx, f.user.ID, step, f.now); err != nil || !accepted {
					t.Errorf("spending the step elsewhere = %t, %v", accepted, err)
				}
			}
			raw, err := f.signIn(factorFixturePassword, otp, recovery)
			if raw != "" || err == nil || err.Error() != "one-time code is required" {
				t.Fatalf("sign-in with a factor spent elsewhere = %q, %v; want the answer to a wrong code", raw, err)
			}
			if got := len(f.m.loginClientFails["login-client:login:192.0.2.1"]); got != 1 {
				t.Errorf("the client's sign-in budget counts %d failures, want 1", got)
			}
			if got := f.count(t, `SELECT COUNT(*) FROM security_audit WHERE action='auth.totp_failed'`); got != 1 {
				t.Errorf("auth.totp_failed records = %d, want 1", got)
			}
			if got := f.count(t, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, f.user.ID); got != 0 {
				t.Errorf("sessions = %d, want none", got)
			}
		})
		t.Run("retried after a display-name edit, "+factor, func(t *testing.T) {
			f := newFactorFixture(t)
			otp, recovery, step := present(f)
			f.during = func() {
				f.exec(t, `UPDATE users SET display_name='Renamed',revision=revision+1 WHERE id=?`, f.user.ID)
			}
			if raw, err := f.signIn(factorFixturePassword, otp, recovery); err != nil || raw == "" {
				t.Fatalf("sign-in retried after a display-name edit = %q, %v", raw, err)
			}
			f.checkSpentOnce(t, factor, step)
			if got := f.count(t, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, f.user.ID); got != 1 {
				t.Errorf("sessions = %d, want one", got)
			}
		})
		t.Run("retried after a TOTP re-enrolment, "+factor, func(t *testing.T) {
			f := newFactorFixture(t)
			otp, recovery, step := present(f)
			f.during = func() {
				ctx := context.Background()
				unit := f.s.Tenant(store.DefaultTenantScope())
				replaced, err := unit.GetUser(ctx, f.user.ID)
				if err != nil {
					t.Error(err)
					return
				}
				replaced.TOTPSecret = "KRUGS4ZANFZSAYJAOBZG65DPEBWW65DFEQ"
				_, hashes, err := RecoveryCodes()
				if err != nil {
					t.Error(err)
					return
				}
				if err := unit.SaveUserSecurity(ctx, replaced, hashes, true, false, store.AuditEntry{}); err != nil {
					t.Error(err)
				}
			}
			raw, err := f.signIn(factorFixturePassword, otp, recovery)
			if raw != "" || err == nil {
				t.Fatalf("sign-in retried after a TOTP re-enrolment = %q, %v; want it refused", raw, err)
			}
			if got := f.count(t, `SELECT COUNT(*) FROM totp_replay WHERE user_id=? AND last_step>=?`, f.user.ID, step-1); got != 0 {
				t.Errorf("the refused sign-in recorded the TOTP time step")
			}
			if got := f.count(t, `SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NOT NULL`, f.user.ID); got != 0 {
				t.Errorf("the refused sign-in used %d recovery codes", got)
			}
			if got := f.count(t, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, f.user.ID); got != 0 {
				t.Errorf("sessions = %d, want none", got)
			}
		})
	}
}

// An account keeps at most store.MaxSessionsPerAccount sessions. The
// sign-in that goes over the cap ends the account's least recently used
// session; a session that was used again stays, and so do the other
// sessions and the new one.
func TestSignInEndsTheLeastRecentlyUsedSessionOverTheCap(t *testing.T) {
	ctx := context.Background()
	s, _, operator := platformTestStore(t)
	m := NewManager(s)
	now := time.Now().UTC().Add(-time.Hour)
	m.Now = func() time.Time { return now }
	raws := make([]string, store.MaxSessionsPerAccount)
	for i := range raws {
		now = now.Add(time.Second)
		raws[i] = "existing-session-" + strconv.Itoa(i)
		if err := s.CreateSessionForUserWithAuditEntry(ctx, operator.ID, digest(raws[i]), "csrf", now, now.Add(SessionTTL), store.AuditEntry{}); err != nil {
			t.Fatal(err)
		}
	}
	request := func(raw string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
		r.RemoteAddr = "192.0.2.80:4000"
		if raw != "" {
			r.AddCookie(&http.Cookie{Name: SessionCookie, Value: raw})
		}
		return r
	}
	// The oldest session is used again.
	now = now.Add(time.Minute)
	if _, ok := m.Authenticate(ctx, request(raws[0])); !ok {
		t.Fatal("the oldest session does not authenticate")
	}
	now = now.Add(time.Second)
	raw, _, err := m.LoginAs(ctx, request(""), operator.Username, "unit operator password", "", "")
	if err != nil || raw == "" {
		t.Fatalf("sign-in over the cap = %q, %v", raw, err)
	}
	if _, ok := m.AuthenticateReadOnly(ctx, request(raws[1])); ok {
		t.Error("the least recently used session still authenticates after the sign-in over the cap")
	}
	for _, kept := range append([]string{raw, raws[0]}, raws[2:]...) {
		if _, ok := m.AuthenticateReadOnly(ctx, request(kept)); !ok {
			t.Errorf("session %s no longer authenticates", kept)
		}
	}
}

// tokenRedemption is an anonymous operation that redeems a one-time token:
// the first administrator's setup, an account's activation, or the platform
// setup. prepare returns a valid token on a fresh store.
type tokenRedemption struct {
	name    string
	prepare func(t *testing.T, m *Manager, now *time.Time) string
	redeem  func(m *Manager, r *http.Request, token string) error
}

func tokenRedemptions() []tokenRedemption {
	ctx := context.Background()
	setupToken := func(t *testing.T, m *Manager) string {
		t.Helper()
		token, err := m.EnsureSetupToken(ctx)
		if err != nil || token == "" {
			t.Fatalf("setup token = %q, %v", token, err)
		}
		return token
	}
	return []tokenRedemption{
		{"setup", func(t *testing.T, m *Manager, _ *time.Time) string {
			return setupToken(t, m)
		}, func(m *Manager, r *http.Request, token string) error {
			return m.SetupRequest(ctx, r, token, "administrator password")
		}},
		{"activation", func(t *testing.T, m *Manager, now *time.Time) string {
			t.Helper()
			unit := m.Store.Tenant(store.DefaultTenantScope())
			admin, err := unit.CreateUser(ctx, store.User{Username: "admin", Role: store.RoleAdministrator, PasswordHash: "unused-hash", Enabled: true}, store.AuditEntry{})
			if err != nil {
				t.Fatal(err)
			}
			plain, hash, err := NewOpaqueToken()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := unit.CreateUserWithInvite(ctx, store.User{Username: "invitee", Role: store.RoleViewer, PasswordHash: "!pending", Enabled: false}, hash, *now, now.Add(time.Hour), store.AuditEntry{ActorUserID: admin.ID}); err != nil {
				t.Fatal(err)
			}
			return plain
		}, func(m *Manager, r *http.Request, token string) error {
			_, err := m.ActivateRequest(ctx, r, token, "invitee account password")
			return err
		}},
		{"platform setup", func(t *testing.T, m *Manager, now *time.Time) string {
			t.Helper()
			if err := m.Setup(ctx, setupToken(t, m), "administrator password"); err != nil {
				t.Fatal(err)
			}
			*now = now.Add(2 * time.Minute)
			token, err := m.IssuePlatformSetupToken(ctx, false)
			if err != nil {
				t.Fatal(err)
			}
			return token
		}, func(m *Manager, r *http.Request, token string) error {
			_, err := m.PlatformSetupRequest(ctx, r, token, "root", "platform administrator password")
			return err
		}},
	}
}

// Through a shared loopback peer, the setups and activation get the
// cooldown that sign-in gets: after five wrong tokens every redemption
// through the peer waits two seconds, and no number of wrong tokens blocks
// the peer for five minutes. The valid token is redeemed once the cooldown
// ends.
func TestSharedLoopbackPeerCoolsDownTokenRedemptions(t *testing.T) {
	for _, operation := range tokenRedemptions() {
		for _, peer := range []string{"127.0.0.1:443", "[::1]:443"} {
			t.Run(operation.name+" from "+peer, func(t *testing.T) {
				s, err := store.Open(storetest.FreshPath(t))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				m := NewManager(s)
				now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
				m.Now = func() time.Time { return now }
				token := operation.prepare(t, m, &now)
				request := func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, "/api/v1/setup", nil)
					r.RemoteAddr = peer
					return r
				}
				for attempt := 0; attempt < authFailureThreshold; attempt++ {
					if err := operation.redeem(m, request(), "wrong-token-"+strconv.Itoa(attempt)); err == nil || errors.Is(err, ErrRateLimited) {
						t.Fatalf("wrong token %d = %v, want a failure", attempt, err)
					}
				}
				if err := operation.redeem(m, request(), "another-wrong-token"); !errors.Is(err, ErrRateLimited) || RetryAfterHeaderValue(err) != "2" {
					t.Errorf("redemption after %d wrong tokens = %v (Retry-After %s), want the 2-second cooldown", authFailureThreshold, err, RetryAfterHeaderValue(err))
				}
				for attempt := authFailureThreshold; attempt < authSourceFailureThreshold+authFailureThreshold; attempt++ {
					now = now.Add(authSharedLoopbackRetryDelay)
					if err := operation.redeem(m, request(), "wrong-token-"+strconv.Itoa(attempt)); err == nil || errors.Is(err, ErrRateLimited) {
						t.Fatalf("wrong token %d after the cooldown = %v, want a failure", attempt, err)
					}
				}
				if err := operation.redeem(m, request(), token); !errors.Is(err, ErrRateLimited) || RetryAfterHeaderValue(err) != "2" {
					t.Fatalf("redemption right after %d wrong tokens = %v (Retry-After %s), want the 2-second cooldown", authSourceFailureThreshold+authFailureThreshold, err, RetryAfterHeaderValue(err))
				}
				now = now.Add(authSharedLoopbackRetryDelay)
				if err := operation.redeem(m, request(), token); err != nil {
					t.Fatalf("redemption after the cooldown = %v", err)
				}
			})
		}
	}
}

// A client with its own address keeps the hard backstop for the setups and
// activation: after a hundred wrong tokens every redemption from it is
// refused for five minutes, with a five-minute Retry-After.
func TestDirectClientKeepsTheTokenBackstop(t *testing.T) {
	for _, operation := range tokenRedemptions() {
		t.Run(operation.name, func(t *testing.T) {
			s, err := store.Open(storetest.FreshPath(t))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			m := NewManager(s)
			now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
			m.Now = func() time.Time { return now }
			token := operation.prepare(t, m, &now)
			request := func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/v1/setup", nil)
				r.RemoteAddr = "198.51.100.45:443"
				return r
			}
			for attempt := 0; attempt < authSourceFailureThreshold; attempt++ {
				if err := operation.redeem(m, request(), "wrong-token-"+strconv.Itoa(attempt)); err == nil || errors.Is(err, ErrRateLimited) {
					t.Fatalf("wrong token %d = %v, want a failure", attempt, err)
				}
			}
			blockedAt := now
			for _, wait := range []time.Duration{0, authSharedLoopbackRetryDelay, authBlockDuration - time.Second} {
				now = blockedAt.Add(wait)
				if err := operation.redeem(m, request(), token); !errors.Is(err, ErrRateLimited) || RetryAfterHeaderValue(err) != "300" {
					t.Fatalf("redemption %s after %d wrong tokens = %v (Retry-After %s), want the five-minute block", wait, authSourceFailureThreshold, err, RetryAfterHeaderValue(err))
				}
			}
			now = blockedAt.Add(authBlockDuration)
			if err := operation.redeem(m, request(), token); err != nil {
				t.Fatalf("redemption after the block = %v", err)
			}
		})
	}
}

// A sign-in that finds TOTP enabled only when it retries, after the account
// changed during it, checks the code against the new secret and records its
// step with the session; without a valid code it is refused and records
// nothing.
func TestSignInRetryChecksTheCodeOfNewlyEnabledTOTP(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	for _, valid := range []bool{true, false} {
		ctx := context.Background()
		s, _, operator := platformTestStore(t)
		m := NewManager(s)
		now := time.Now().UTC()
		reads := 0
		// Without TOTP, the third clock read is the one for the session.
		m.Now = func() time.Time {
			reads++
			if reads == 3 {
				unit := s.Tenant(store.DefaultTenantScope())
				current, err := unit.GetUser(ctx, operator.ID)
				if err != nil {
					t.Fatal(err)
				}
				current.TOTPEnabled, current.TOTPSecret = true, secret
				if err := unit.SaveUserSecurity(ctx, current, nil, false, false, store.AuditEntry{}); err != nil {
					t.Fatal(err)
				}
			}
			return now
		}
		step := now.Unix() / 30
		code := totpCode(secret, step)
		if !valid {
			code = "000000"
			if totpCode(secret, step-1) == code || totpCode(secret, step) == code || totpCode(secret, step+1) == code {
				code = "111111"
			}
		}
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = "192.0.2.90:1234"
		raw, _, err := m.LoginAs(ctx, r, operator.Username, "unit operator password", code, "")
		var recorded int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM totp_replay WHERE user_id=? AND last_step>=?`, operator.ID, step-1).Scan(&recorded); err != nil {
			t.Fatal(err)
		}
		if valid && (err != nil || raw == "" || recorded != 1) {
			t.Fatalf("retried sign-in with the new secret's code = %q, %v; recorded steps %d", raw, err, recorded)
		}
		if !valid && (err == nil || raw != "" || recorded != 0) {
			t.Fatalf("retried sign-in with a wrong code = %q, %v; recorded steps %d", raw, err, recorded)
		}
	}
}

// A retried sign-in whose factor another sign-in spent between the two
// attempts gets the answer of a wrong code, without a session.
func TestSignInRetryWhoseFactorWasSpentIsRefused(t *testing.T) {
	for _, factor := range []string{"TOTP code", "recovery code"} {
		t.Run(factor, func(t *testing.T) {
			f := newFactorFixture(t)
			step := f.now.Unix() / 30
			otp, recovery := totpCode(f.user.TOTPSecret, step), ""
			if factor == "recovery code" {
				otp, recovery = "", f.codes[0]
			}
			// The fourth clock read is the one for the session: the account
			// changes, so the sign-in retries, and another sign-in spends the
			// factor first.
			f.at = 4
			f.during = func() {
				ctx := context.Background()
				f.exec(t, `UPDATE users SET display_name='Renamed',revision=revision+1 WHERE id=?`, f.user.ID)
				if recovery != "" {
					if used, err := f.s.ConsumeRecoveryCodeTextForUser(ctx, f.user.ID, recovery, f.now); err != nil || !used {
						t.Errorf("spending the recovery code elsewhere = %t, %v", used, err)
					}
				} else if accepted, err := f.s.ConsumeTOTPStep(ctx, f.user.ID, step, f.now); err != nil || !accepted {
					t.Errorf("spending the step elsewhere = %t, %v", accepted, err)
				}
			}
			raw, err := f.signIn(factorFixturePassword, otp, recovery)
			if raw != "" || err == nil || err.Error() != "one-time code is required" {
				t.Fatalf("retried sign-in with a spent factor = %q, %v; want the answer to a wrong code", raw, err)
			}
			if got := f.count(t, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, f.user.ID); got != 0 {
				t.Errorf("sessions = %d, want none", got)
			}
		})
	}
}

// A sign-in whose TOTP check cannot read the replay guard fails without a
// session and records nothing.
func TestSignInFailsWhenTheReplayGuardCannotBeRead(t *testing.T) {
	f := newFactorFixture(t)
	f.exec(t, `ALTER TABLE totp_replay RENAME TO totp_replay_hidden`)
	raw, err := f.signIn(factorFixturePassword, totpCode(f.user.TOTPSecret, f.now.Unix()/30), "")
	if raw != "" || err == nil || errors.Is(err, ErrRateLimited) {
		t.Fatalf("sign-in without a readable replay guard = %q, %v", raw, err)
	}
	f.exec(t, `ALTER TABLE totp_replay_hidden RENAME TO totp_replay`)
	if got := f.count(t, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, f.user.ID); got != 0 {
		t.Errorf("sessions = %d, want none", got)
	}
}

// NoteForwarding records a request whose directly connected peer is not a
// trusted proxy and sends a client-address forwarding header, whether the
// peer is loopback, as a proxy on the host is, or not, and asks for the
// warning at most once per interval. UntrustedProxy reports the latest such
// proxy for a day after its last request.
func TestNoteForwardingRecordsUntrustedProxies(t *testing.T) {
	var none *Manager
	if _, logNow := none.NoteForwarding(httptest.NewRequest(http.MethodGet, "/", nil)); logNow {
		t.Fatal("a nil manager asked for a warning")
	}
	if _, seen := none.UntrustedProxy(); seen {
		t.Fatal("a nil manager reported a proxy")
	}
	m := NewManager(nil)
	if err := m.SetTrustedProxies([]string{"10.0.0.9/32"}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 30, 9, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return now }
	request := func(remote, header, value string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil)
		r.RemoteAddr = remote
		if header != "" {
			r.Header.Set(header, value)
		}
		return r
	}
	if _, logNow := m.NoteForwarding(nil); logNow {
		t.Fatal("a nil request asked for a warning")
	}
	for _, r := range []*http.Request{
		request("10.0.0.5:4000", "", ""),
		request("10.0.0.5:4000", "X-Forwarded-For", " "),
		request("127.0.0.1:4000", "", ""),
		request("not-an-address", "X-Forwarded-For", "198.51.100.7"),
		request("10.0.0.9:4000", "X-Forwarded-For", "198.51.100.7"),
	} {
		if proxy, logNow := m.NoteForwarding(r); logNow || proxy.Peer != "" {
			t.Fatalf("request from %s with %v = %+v, %t; want it not recorded", r.RemoteAddr, r.Header, proxy, logNow)
		}
	}
	if proxy, seen := m.UntrustedProxy(); seen {
		t.Fatalf("untrusted proxy before one was seen = %+v", proxy)
	}
	proxy, logNow := m.NoteForwarding(request("10.0.0.5:4000", "X-Forwarded-For", "198.51.100.7"))
	if want := (UntrustedProxy{Peer: "10.0.0.5", Header: "X-Forwarded-For", LastSeenAt: now}); proxy != want || !logNow {
		t.Fatalf("first request from an untrusted proxy = %+v, %t; want %+v and a warning", proxy, logNow, want)
	}
	now = now.Add(time.Minute)
	proxy, logNow = m.NoteForwarding(request("[2001:db8::6]:4000", "Forwarded", "for=198.51.100.8"))
	if want := (UntrustedProxy{Peer: "2001:db8::6", Header: "Forwarded", LastSeenAt: now}); proxy != want || logNow {
		t.Fatalf("second untrusted proxy within the interval = %+v, %t; want %+v without a warning", proxy, logNow, want)
	}
	if seen, ok := m.UntrustedProxy(); !ok || seen != proxy {
		t.Fatalf("untrusted proxy = %+v, %t; want %+v", seen, ok, proxy)
	}
	now = now.Add(untrustedProxyLogInterval)
	if _, logNow := m.NoteForwarding(request("10.0.0.5:4000", "X-Forwarded-For", "198.51.100.7")); !logNow {
		t.Fatal("no warning once the interval passed")
	}
	now = now.Add(untrustedProxyNoticeTTL)
	if proxy, seen := m.UntrustedProxy(); seen {
		t.Fatalf("untrusted proxy a day after its last request = %+v", proxy)
	}
	// A proxy on the host that is not trusted connects from a loopback
	// address.
	proxy, _ = m.NoteForwarding(request("127.0.0.1:4000", "X-Forwarded-For", "198.51.100.7"))
	if want := (UntrustedProxy{Peer: "127.0.0.1", Header: "X-Forwarded-For", LastSeenAt: now}); proxy != want {
		t.Fatalf("request from an untrusted proxy on the host = %+v, want %+v", proxy, want)
	}
	proxy, _ = m.NoteForwarding(request("[::1]:4000", "Forwarded", "for=198.51.100.7"))
	if want := (UntrustedProxy{Peer: "::1", Header: "Forwarded", LastSeenAt: now}); proxy != want {
		t.Fatalf("request from an untrusted IPv6 proxy on the host = %+v, want %+v", proxy, want)
	}
}

// Behind a trusted proxy, the client address is the first address from the
// right of the forwarding chain that is not a trusted proxy. When the chain
// has entries to the left of that address, the address forwarded the
// request for another client: it is a proxy that EdgeWatch does not trust,
// such as a proxy on another host in front of the trusted proxy on the
// host. NoteForwarding records it with the header in use, and the client
// address stays the proxy's. A chain that ends at the client's own address,
// a chain of trusted proxies, a hop that cannot be read, and a header that
// EdgeWatch does not read are not recorded.
func TestNoteForwardingRecordsTheUntrustedProxyBehindATrustedOne(t *testing.T) {
	now := time.Date(2026, time.September, 30, 9, 0, 0, 0, time.UTC)
	for _, check := range []struct {
		name, forwarded, remote, header, value, client, proxy string
	}{
		{"an untrusted proxy in front of the host's proxy", "", "127.0.0.1:50000", "X-Forwarded-For", "198.51.100.7, 203.0.113.9", "203.0.113.9", "203.0.113.9"},
		{"an untrusted proxy in front of two trusted proxies", "", "127.0.0.1:50000", "X-Forwarded-For", "198.51.100.7, 203.0.113.9, 10.0.0.9", "203.0.113.9", "203.0.113.9"},
		{"an untrusted proxy that forwarded for an unreadable client", "", "127.0.0.1:50000", "X-Forwarded-For", "unknown, 203.0.113.9", "203.0.113.9", "203.0.113.9"},
		{"an untrusted proxy in a Forwarded chain", "forwarded", "[::1]:50000", "Forwarded", `for=198.51.100.7, for="[2001:db8::9]:443"`, "2001:db8::9", "2001:db8::9"},
		{"the client of the host's proxy", "", "127.0.0.1:50000", "X-Forwarded-For", "198.51.100.7", "198.51.100.7", ""},
		{"the client of two trusted proxies", "", "127.0.0.1:50000", "X-Forwarded-For", "198.51.100.7, 10.0.0.9", "198.51.100.7", ""},
		{"a chain of trusted proxies only", "", "127.0.0.1:50000", "X-Forwarded-For", "10.0.0.9", "10.0.0.9", ""},
		{"an unreadable hop", "", "127.0.0.1:50000", "X-Forwarded-For", "198.51.100.7, not-an-address", "127.0.0.1", ""},
		{"a header that EdgeWatch does not read", "", "127.0.0.1:50000", "Forwarded", "for=198.51.100.7, for=203.0.113.9", "127.0.0.1", ""},
		{"forwarded client addresses turned off", "none", "127.0.0.1:50000", "X-Forwarded-For", "198.51.100.7, 203.0.113.9", "127.0.0.1", ""},
	} {
		t.Run(check.name, func(t *testing.T) {
			m := NewManager(nil)
			m.Now = func() time.Time { return now }
			if err := m.SetTrustedProxies([]string{"127.0.0.1/32", "::1/128", "10.0.0.9/32"}); err != nil {
				t.Fatal(err)
			}
			if err := m.SetForwardedHeader(check.forwarded); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
			r.RemoteAddr = check.remote
			r.Header.Set(check.header, check.value)
			if got := m.ClientIP(r); got != check.client {
				t.Fatalf("client address = %q, want %q", got, check.client)
			}
			proxy, logNow := m.NoteForwarding(r)
			seen, reported := m.UntrustedProxy()
			if check.proxy == "" {
				if proxy.Peer != "" || logNow || reported {
					t.Fatalf("recorded %+v (warning %t, reported %t), want nothing", seen, logNow, reported)
				}
				return
			}
			want := UntrustedProxy{Peer: check.proxy, Header: check.header, LastSeenAt: now}
			if proxy != want || !logNow || !reported || seen != want {
				t.Fatalf("recorded %+v (warning %t), reported %+v (%t); want %+v with a warning", proxy, logNow, seen, reported, want)
			}
		})
	}
}

// A manager that was not made by NewManager still writes a refused
// sign-in's record in the background. A background write that fails writes
// nothing and leaves the refusal as it was. Stale suppression windows are
// dropped once the windows reach the limiter's ceiling.
func TestRateLimitRecordsInTheBackground(t *testing.T) {
	ctx := context.Background()
	s, _, _ := platformTestStore(t)
	from := func(address string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = address + ":4000"
		return r
	}
	m := &Manager{Store: s}
	m.auditLoginRateLimit(ctx, "nobody-here", from("203.0.113.93"))
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := rateLimitRecordsPerScope(t, s, "203.0.113.93"), map[string]int{"<null>": 1}; !maps.Equal(got, want) {
		t.Fatalf("records of a manager without NewManager = %v, want %v", got, want)
	}

	if _, err := s.DB.Exec(`CREATE TRIGGER fail_rate_limited BEFORE INSERT ON security_audit WHEN NEW.action='auth.rate_limited' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	m.auditLoginRateLimit(ctx, "nobody-here", from("203.0.113.94"))
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rateLimitRecordsPerScope(t, s, "203.0.113.94"); len(got) != 0 {
		t.Fatalf("records after a failed background write = %v, want none", got)
	}

	now := time.Now().UTC()
	m.Now = func() time.Time { return now }
	m.mu.Lock()
	for i := range authLimiterMaxEntries {
		m.rateAudit["stale-"+strconv.Itoa(i)] = now.Add(-authFailureWindow)
	}
	m.mu.Unlock()
	if !m.claimRateAudit("login:nobody-here", "", true, from("203.0.113.95")) {
		t.Fatal("a new window was not claimed")
	}
	m.mu.Lock()
	windows := len(m.rateAudit)
	m.mu.Unlock()
	if windows > 3 {
		t.Fatalf("suppression windows after the sweep = %d, want the stale ones dropped", windows)
	}
}
