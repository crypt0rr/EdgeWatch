package auth

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestRateLimitAuditCoalescesRotatingLoginIdentities(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Date(2026, 9, 13, 7, 0, 0, 0, time.UTC)
	m := NewManager(db)
	m.Now = func() time.Time { return now }
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "198.51.100.10:443"
	for i := 0; i < 100; i++ {
		m.auditRateLimit(ctx, "unknown-login:user-"+strconv.Itoa(i), request)
	}
	var rows int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='auth.rate_limited'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("rotating usernames created %d rate-limit audits, want one", rows)
	}

	otherSource := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	otherSource.RemoteAddr = "198.51.100.11:443"
	m.auditRateLimit(ctx, "login:admin", otherSource)
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='auth.rate_limited'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("distinct sources created %d rate-limit audits, want two", rows)
	}
}

// The record of a throttled sign-in belongs where the sign-in's failures
// do: in the unit of the account with the username, and in platform scope
// for a platform administrator or a username that no account has. The
// record of a throttled password or TOTP confirmation belongs to the
// confirming account's unit, or to platform scope for a platform
// administrator. Setup, and an activation token that no link has, name no
// account and stay in the default unit. Each case throttles its own client,
// whose address the record carries.
func TestRateLimitRecordsBelongToTheAccountsScope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, defaultAdmin, _ := platformTestStore(t)
	addSecondUnit(t, s)
	scope, err := s.TenantScopeByID(ctx, platformTestTenantID)
	if err != nil {
		t.Fatal(err)
	}
	const password = "unit b administrator password"
	adminB, err := storetest.CreateUser(ctx, s, scope, store.User{Username: "bravo-admin", Role: store.RoleAdministrator, PasswordHash: cheapHash(password), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	const rootID = "00000000-0000-0000-0000-00000000fa01"
	if _, err := s.DB.Exec(`INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,enabled,created_at,updated_at) VALUES(?,NULL,'platform-root','platform-root',?,?,1,?,?)`, rootID, store.RolePlatformAdmin, cheapHash("platform administrator password"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	m := NewManager(s)
	from := func(address string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = address + ":4000"
		return r
	}
	const platform = "<null>"
	for _, check := range []struct {
		name, address, subject, want string
		attempt                      func(*http.Request) error
	}{
		{"sign-in to a unit B account", "203.0.113.77", "login:bravo-admin", platformTestTenantID, func(r *http.Request) error {
			_, _, err := m.LoginAs(ctx, r, "bravo-admin", "wrong password", "", "")
			return err
		}},
		{"sign-in to a default unit account", "203.0.113.79", "login:" + defaultAdmin.Username, store.DefaultTenantID, func(r *http.Request) error {
			_, _, err := m.LoginAs(ctx, r, defaultAdmin.Username, "wrong password", "", "")
			return err
		}},
		{"sign-in to the platform administrator", "192.0.2.99", "login:platform-root", platform, func(r *http.Request) error {
			_, _, err := m.LoginAs(ctx, r, "platform-root", "wrong password", "", "")
			return err
		}},
		{"sign-in with an unknown username", "203.0.113.78", "login:nobody-anywhere", platform, func(r *http.Request) error {
			_, _, err := m.LoginAs(ctx, r, "nobody-anywhere", "wrong password", "", "")
			return err
		}},
		{"the platform administrator's password confirmation", "198.51.100.200", "password-confirmation", platform, func(r *http.Request) error {
			return m.ConfirmPasswordForUser(ctx, r, rootID, "wrong password")
		}},
		{"a unit B account's password confirmation", "198.51.100.201", "password-confirmation", platformTestTenantID, func(r *http.Request) error {
			return m.ConfirmPasswordForUser(ctx, r, adminB.ID, "wrong password")
		}},
		{"the platform administrator's TOTP confirmation", "198.51.100.202", "totp-confirmation", platform, func(r *http.Request) error {
			return m.ConfirmTOTPForUser(ctx, r, rootID, "000000", "")
		}},
		{"a unit B account's TOTP confirmation", "198.51.100.203", "totp-confirmation", platformTestTenantID, func(r *http.Request) error {
			return m.ConfirmTOTPForUser(ctx, r, adminB.ID, "000000", "")
		}},
		{"activation", "198.51.100.204", "activation", store.DefaultTenantID, func(r *http.Request) error {
			_, err := m.ActivateRequest(ctx, r, "not-a-token", "replacement password")
			return err
		}},
		{"setup", "198.51.100.205", "setup", store.DefaultTenantID, func(r *http.Request) error {
			return m.SetupRequest(ctx, r, "not-a-token", "replacement password")
		}},
	} {
		for attempt := 0; attempt < authFailureThreshold; attempt++ {
			if err := check.attempt(from(check.address)); err == nil || errors.Is(err, ErrRateLimited) {
				t.Fatalf("%s: attempt %d = %v, want a failure", check.name, attempt, err)
			}
		}
		if err := check.attempt(from(check.address)); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("%s: attempt over the budget = %v, want ErrRateLimited", check.name, err)
		}
		// A refused sign-in writes its record in the background.
		if err := m.WaitForRateLimitRecords(ctx); err != nil {
			t.Fatal(err)
		}
		records := rateLimitRecords(t, s, check.address)
		if want := []string{check.want + " " + check.subject + " " + store.AuditActorUnit}; !slices.Equal(records, want) {
			t.Errorf("%s: rate-limit records = %q, want %q", check.name, records, want)
		}
	}
	// Unit B's audit shows its own throttling, and the default unit's shows
	// neither unit B's nor the platform's.
	var inB, foreignInDefault int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action='auth.rate_limited' AND tenant_id=?`, platformTestTenantID).Scan(&inB); err != nil || inB != 3 {
		t.Fatalf("unit B's rate-limit records = %d, %v; want 3", inB, err)
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action='auth.rate_limited' AND tenant_id=? AND source_ip NOT IN ('203.0.113.79','198.51.100.204','198.51.100.205')`, store.DefaultTenantID).Scan(&foreignInDefault); err != nil || foreignInDefault != 0 {
		t.Fatalf("the default unit shows %d rate-limit records of other scopes, %v", foreignInDefault, err)
	}
}

// One client that is throttled on accounts of several scopes gets one
// rate-limit record per scope and operation: the record written for one
// unit's account does not suppress the record for another unit's account,
// or for a platform administrator, for the rest of the window. Unknown
// usernames all belong to platform scope, so a client that rotates through
// them still gets one platform record for sign-in.
func TestRateLimitRecordsFromOneClientReachEveryScope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, defaultAdmin, _ := platformTestStore(t)
	addSecondUnit(t, s)
	scope, err := s.TenantScopeByID(ctx, platformTestTenantID)
	if err != nil {
		t.Fatal(err)
	}
	adminB, err := storetest.CreateUser(ctx, s, scope, store.User{Username: "bravo-admin", Role: store.RoleAdministrator, PasswordHash: cheapHash("unit b administrator password"), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	const rootID = "00000000-0000-0000-0000-00000000fa03"
	if _, err := s.DB.Exec(`INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,enabled,created_at,updated_at) VALUES(?,NULL,'platform-root','platform-root',?,?,1,?,?)`, rootID, store.RolePlatformAdmin, cheapHash("platform administrator password"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	m := NewManager(s)
	const client = "203.0.113.60"
	from := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = client + ":4000"
		return r
	}
	signIn := func(username string) func() error {
		return func() error {
			_, _, err := m.LoginAs(ctx, from(), username, "wrong password", "", "")
			return err
		}
	}
	confirmPassword := func(userID string) func() error {
		return func() error { return m.ConfirmPasswordForUser(ctx, from(), userID, "wrong password") }
	}
	confirmTOTP := func(userID string) func() error {
		return func() error { return m.ConfirmTOTPForUser(ctx, from(), userID, "000000", "") }
	}
	// The client has one sign-in budget for every username. Once it is used,
	// the sign-in with each username is refused, and recorded in the
	// username's scope.
	for attempt := 0; attempt < authFailureThreshold; attempt++ {
		if err := signIn(defaultAdmin.Username)(); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("sign-in to the default unit's administrator: attempt %d = %v, want a failure", attempt, err)
		}
	}
	for _, username := range []string{defaultAdmin.Username, "bravo-admin", "platform-root", "nobody-anywhere"} {
		if err := signIn(username)(); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("sign-in as %s over the budget = %v, want ErrRateLimited", username, err)
		}
	}
	for _, check := range []struct {
		name    string
		attempt func() error
	}{
		{"password confirmation by the default unit's administrator", confirmPassword(defaultAdmin.ID)},
		{"password confirmation by unit B's administrator", confirmPassword(adminB.ID)},
		{"password confirmation by the platform administrator", confirmPassword(rootID)},
		{"TOTP confirmation by the default unit's administrator", confirmTOTP(defaultAdmin.ID)},
		{"TOTP confirmation by unit B's administrator", confirmTOTP(adminB.ID)},
		{"TOTP confirmation by the platform administrator", confirmTOTP(rootID)},
	} {
		for attempt := 0; attempt < authFailureThreshold; attempt++ {
			if err := check.attempt(); err == nil || errors.Is(err, ErrRateLimited) {
				t.Fatalf("%s: attempt %d = %v, want a failure", check.name, attempt, err)
			}
		}
		if err := check.attempt(); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("%s: attempt over the budget = %v, want ErrRateLimited", check.name, err)
		}
	}
	for i := 0; i < 100; i++ {
		if err := signIn("rotating-" + strconv.Itoa(i))(); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("rotating unknown username %d = %v, want ErrRateLimited", i, err)
		}
	}
	// A refused sign-in writes its record in the background.
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := s.DB.Query(`SELECT COALESCE(tenant_id,'<null>'),actor_username FROM security_audit WHERE action='auth.rate_limited' AND source_ip=?`, client)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]int{}
	for rows.Next() {
		var tenant, subject string
		if err := rows.Scan(&tenant, &subject); err != nil {
			t.Fatal(err)
		}
		got[tenant+" "+rateAuditEndpoint(subject)]++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{}
	for _, tenant := range []string{store.DefaultTenantID, platformTestTenantID, "<null>"} {
		for _, endpoint := range []string{"login", "password-confirmation", "totp-confirmation"} {
			want[tenant+" "+endpoint] = 1
		}
	}
	if !maps.Equal(got, want) {
		t.Fatalf("rate-limit records per scope and operation = %v, want %v", got, want)
	}
}

// rateLimitRecords returns the tenant, "<null>" for platform scope, the
// subject, and the actor kind of each rate-limit record from the address.
func rateLimitRecords(t *testing.T, s *store.Store, address string) []string {
	t.Helper()
	rows, err := s.DB.Query(`SELECT COALESCE(tenant_id,'<null>'),actor_username,actor_kind FROM security_audit WHERE action='auth.rate_limited' AND source_ip=? ORDER BY id`, address)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var records []string
	for rows.Next() {
		var tenant, subject, kind string
		if err := rows.Scan(&tenant, &subject, &kind); err != nil {
			t.Fatal(err)
		}
		records = append(records, tenant+" "+subject+" "+kind)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return records
}

func TestRateAuditEndpointGroupsLoginSubjectsOnly(t *testing.T) {
	t.Parallel()
	for subject, want := range map[string]string{
		"setup":                    "setup",
		"activation":               "activation",
		"password-confirmation":    "password-confirmation",
		"login:admin":              "login",
		"unknown-login:probe-user": "login",
		"custom":                   "custom",
	} {
		if got := rateAuditEndpoint(subject); got != want {
			t.Errorf("rateAuditEndpoint(%q) = %q, want %q", subject, got, want)
		}
	}
}
