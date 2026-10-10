package auth

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// The rate limits count an IPv6 client by its network of the configured
// prefix length, /64 by default, so a client cannot gain budgets by
// rotating the addresses of its own network. IPv4 addresses, loopback, and
// names that are no address stay as they are, and ClientIP, which audit
// records use, keeps the full address.
func TestRateLimitIdentityGroupsIPv6Networks(t *testing.T) {
	t.Parallel()
	m := NewManager(nil)
	identity := func(remote string) string {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = remote
		return m.RateLimitIdentity(r)
	}
	for remote, want := range map[string]string{
		"[2001:db8:1:2:3:4:5:6]:443": "2001:db8:1:2::/64",
		"[2001:db8:1:2::ffff]:443":   "2001:db8:1:2::/64",
		"[2001:db8:1:3::1]:443":      "2001:db8:1:3::/64",
		"[::1]:443":                  "::1",
		"198.51.100.7:443":           "198.51.100.7",
		"[::ffff:198.51.100.7]:443":  "198.51.100.7",
		"not-an-address:443":         "not-an-address",
	} {
		if got := identity(remote); got != want {
			t.Errorf("rate-limit identity of %s = %q, want %q", remote, got, want)
		}
	}
	for _, bits := range []int{0, 129, -1} {
		if err := m.SetIPv6RateLimitPrefix(bits); err == nil {
			t.Errorf("prefix length %d accepted", bits)
		}
	}
	if got := identity("[2001:db8:1:2:3:4:5:6]:443"); got != "2001:db8:1:2::/64" {
		t.Fatalf("identity after rejected prefixes = %q, want the default /64", got)
	}
	for bits, want := range map[int]string{128: "2001:db8:1:2:3:4:5:6", 56: "2001:db8:1::/56", 48: "2001:db8:1::/48"} {
		if err := m.SetIPv6RateLimitPrefix(bits); err != nil {
			t.Fatal(err)
		}
		if got := identity("[2001:db8:1:2:3:4:5:6]:443"); got != want {
			t.Errorf("identity with a /%d prefix = %q, want %q", bits, got, want)
		}
	}

	// Behind a trusted proxy, the forwarded client is grouped, and ClientIP
	// keeps its full address.
	m = NewManager(nil)
	if err := m.SetTrustedProxies([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:443"
	r.Header.Set("X-Forwarded-For", "2001:db8:9:9::42")
	if got := m.RateLimitIdentity(r); got != "2001:db8:9:9::/64" {
		t.Errorf("forwarded client identity = %q", got)
	}
	if got := m.ClientIP(r); got != "2001:db8:9:9::42" {
		t.Errorf("forwarded client address = %q", got)
	}
}

// The addresses of one IPv6 /64 share one sign-in budget: after five failed
// sign-ins from five of its addresses, a sixth address of the network is
// refused, while a client in another /64 and an IPv4 client are not. The
// audit records keep each full address.
func TestIPv6ClientsOfOneNetworkShareTheirSignInBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	s, _ := clientBudgetStore(t, now)
	m := NewManager(s)
	m.Now = func() time.Time { return now }
	from := func(address string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = "[" + address + "]:4000"
		return r
	}
	var failed []string
	for i := 1; i <= authFailureThreshold; i++ {
		address := fmt.Sprintf("2001:db8:1:2::%x", i)
		failed = append(failed, address)
		if raw, _, err := m.LoginAs(ctx, from(address), "unit-admin", "wrong password", "", ""); raw != "" || err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("failure %d from %s = %q, %v; want a failed sign-in", i, address, raw, err)
		}
	}
	const sixth = "2001:db8:1:2:ffff:ffff:ffff:ffff"
	if raw, _, err := m.LoginAs(ctx, from(sixth), "unit-operator", "unit-operator password", "", ""); raw != "" || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("sign-in from another address of the /64 = %q, %v; want ErrRateLimited", raw, err)
	}
	if raw, _, err := m.LoginAs(ctx, from("2001:db8:1:3::1"), "unit-operator", "unit-operator password", "", ""); err != nil || raw == "" {
		t.Fatalf("sign-in from another /64 = %q, %v", raw, err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	r.RemoteAddr = "198.51.100.44:4000"
	if raw, _, err := m.LoginAs(ctx, r, "unit-operator", "unit-operator password", "", ""); err != nil || raw == "" {
		t.Fatalf("sign-in from an IPv4 client = %q, %v", raw, err)
	}
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := s.DB.Query(`SELECT source_ip FROM security_audit WHERE action='auth.login_failed' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var recorded []string
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			t.Fatal(err)
		}
		recorded = append(recorded, address)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(recorded, failed) {
		t.Fatalf("failed sign-ins recorded from %v, want the full addresses %v", recorded, failed)
	}
	if got := rateLimitRecords(t, s, sixth); len(got) != 1 {
		t.Fatalf("rate-limit records from the sixth address = %v, want one with its full address", got)
	}

	// With a /128 prefix, each address has a budget of its own.
	m = NewManager(s)
	m.Now = func() time.Time { return now }
	if err := m.SetIPv6RateLimitPrefix(128); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= authFailureThreshold; i++ {
		if _, _, err := m.LoginAs(ctx, from(fmt.Sprintf("2001:db8:7:7::%x", i)), "unit-admin", "wrong password", "", ""); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("failure %d with a /128 prefix = %v", i, err)
		}
	}
	if raw, _, err := m.LoginAs(ctx, from("2001:db8:7:7::ff"), "unit-operator", "unit-operator password", "", ""); err != nil || raw == "" {
		t.Fatalf("sign-in from another address with a /128 prefix = %q, %v", raw, err)
	}
}

// The suppression windows of rate-limit records stay within the limiter's
// bound when refusals come from ever new sources, and the window just
// started is kept. The addresses of one IPv6 /64 share one window.
func TestRateAuditWindowsStayBoundedUnderRotatingSources(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	m := NewManager(nil)
	m.Now = func() time.Time { return now }
	from := func(remote string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = remote
		return r
	}
	var last *http.Request
	for i := 0; i < authLimiterMaxEntries+64; i++ {
		last = from(fmt.Sprintf("10.%d.%d.%d:443", i>>16&0xff, i>>8&0xff, i&0xff))
		if !m.claimRateAudit("login:probe", "", true, last) {
			t.Fatalf("refusal %d from a new source was not recorded", i+1)
		}
		m.mu.Lock()
		size := len(m.rateAudit)
		m.mu.Unlock()
		if size > authLimiterMaxEntries {
			t.Fatalf("after %d sources the rate-limit windows hold %d entries, want at most %d", i+1, size, authLimiterMaxEntries)
		}
	}
	if m.claimRateAudit("login:probe", "", true, last) {
		t.Fatal("the window just started was dropped")
	}
	if !m.claimRateAudit("login:probe", "", true, from("[2001:db8:4:4::1]:443")) {
		t.Fatal("the first refusal from an IPv6 network was not recorded")
	}
	if m.claimRateAudit("login:probe", "", true, from("[2001:db8:4:4::2]:443")) {
		t.Fatal("another address of the same /64 got a record of its own")
	}
}

// A username longer than any account can have, up to the request size
// limit, is never kept as a limiter key: every such name shares one small
// identity, while the sign-in still checks a password and counts against
// the client's budget as any unknown name does.
func TestOversizedUsernamesKeepLimiterKeysSmall(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	s, _ := clientBudgetStore(t, now)
	m := NewManager(s)
	m.Now = func() time.Time { return now }
	const client = "203.0.113.90:4000"
	from := func(remote string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = remote
		return r
	}
	huge := strings.Repeat("U", 1<<20)
	keySizes := func() []int {
		m.mu.Lock()
		defer m.mu.Unlock()
		var sizes []int
		keys := slices.Concat(slices.Collect(maps.Keys(m.accountFails)), slices.Collect(maps.Keys(m.accountBlocked)), slices.Collect(maps.Keys(m.accountInFlight)))
		for _, key := range keys {
			sizes = append(sizes, len(key))
		}
		return sizes
	}
	for i := 0; i < authFailureThreshold; i++ {
		raw, _, err := m.LoginAs(ctx, from(client), huge+strconv.Itoa(i), "wrong password", "", "")
		if raw != "" || err == nil || err.Error() != "invalid credentials" {
			t.Fatalf("sign-in %d with an oversized username = %q, %v", i+1, raw, err)
		}
		for _, size := range keySizes() {
			if size > 200 {
				t.Fatalf("after sign-in %d a limiter key has %d bytes", i+1, size)
			}
		}
	}
	if _, _, err := m.LoginAs(ctx, from(client), "unit-operator", "unit-operator password", "", ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("sign-in after %d oversized usernames = %v, want ErrRateLimited", authFailureThreshold, err)
	}
	// A reservation in flight has a small key too.
	source := m.sourceScopeFor(from("203.0.113.91:4000"), "login")
	account := loginAccount(normalizeLoginIdentity(huge))
	if !m.allowScoped(source, account) {
		t.Fatal("reservation refused")
	}
	for _, size := range keySizes() {
		if size > 200 {
			t.Fatalf("a reservation in flight has a key of %d bytes", size)
		}
	}
	m.releaseScoped(source, account)
	// A name that fits keeps its own readable key.
	for identity, want := range map[string]string{
		"unit-admin": "login:unit-admin",
		strings.Repeat("a", store.MaxUsernameBytes):   "login:" + strings.Repeat("a", store.MaxUsernameBytes),
		strings.Repeat("a", store.MaxUsernameBytes+1): "login:" + oversizedLoginIdentity,
	} {
		if got := loginAccount(identity); got != want {
			t.Errorf("loginAccount of a %d-byte name = %q, want %q", len(identity), got, want)
		}
	}
	// The failed sign-ins were recorded with the first 80 bytes of the name.
	var subject string
	if err := s.DB.QueryRow(`SELECT actor_username FROM security_audit WHERE action='auth.login_failed' LIMIT 1`).Scan(&subject); err != nil || subject != strings.Repeat("u", 80) {
		t.Fatalf("recorded username = %d bytes, %v; want the first 80", len(subject), err)
	}
}
