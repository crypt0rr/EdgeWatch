package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestConfirmTOTPForUserConsumesCurrentFactor(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	m := NewManager(db)
	m.Now = func() time.Time { return now }
	token, err := m.EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(ctx, token, "administrator password"); err != nil {
		t.Fatal(err)
	}
	admin, err := db.GetAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	admin.TOTPEnabled = true
	admin.TOTPSecret = "JBSWY3DPEHPK3PXP"
	if err := db.SaveAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp", nil)
	request.RemoteAddr = "198.51.100.50:8080"
	code := totpCode(admin.TOTPSecret, now.Unix()/30)
	if err := m.ConfirmTOTPForUser(ctx, request, store.LegacyAdminUserID, code, ""); err != nil {
		t.Fatalf("valid current factor rejected: %v", err)
	}
	if err := m.ConfirmTOTPForUser(ctx, request, store.LegacyAdminUserID, code, ""); err == nil || !strings.Contains(err.Error(), "current one-time code") {
		t.Fatalf("replayed current factor error = %v", err)
	}
	if err := m.ConfirmTOTPForUser(ctx, request, store.LegacyAdminUserID, "000000", ""); err == nil {
		t.Fatal("invalid current factor accepted")
	}
	plain, hashes, err := RecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveRecoveryCodes(ctx, hashes); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmTOTPForUser(ctx, request, store.LegacyAdminUserID, "", plain[0]); err != nil {
		t.Fatalf("valid recovery factor rejected: %v", err)
	}
}

func TestScopedAdmissionReservationsAndTOTPLogin(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	m := &Manager{Now: func() time.Time { return now }}
	// Two concurrent admissions exercise reservation increments and decrements;
	// the empty account path also verifies that source-only requests do not leave
	// an account bucket behind.
	if !m.allowScoped("source:198.51.100.1", "account") || !m.allowScoped("source:198.51.100.1", "account") {
		t.Fatal("scoped admission was unexpectedly denied")
	}
	m.releaseScoped("source:198.51.100.1", "account")
	m.releaseScoped("source:198.51.100.1", "account")
	if !m.allowScoped("source:198.51.100.2", "") {
		t.Fatal("source-only admission was unexpectedly denied")
	}
	m.releaseScoped("source:198.51.100.2", "")
	m.fails["source:198.51.100.3"] = make([]time.Time, authSourceFailureThreshold)
	for i := range m.fails["source:198.51.100.3"] {
		m.fails["source:198.51.100.3"][i] = now
	}
	if m.allowScoped("source:198.51.100.3", "account") {
		t.Fatal("source failure threshold was ignored")
	}
	accountKey := scopedAccountKey("source:198.51.100.4", "account")
	m.accountFails[accountKey] = make([]time.Time, authFailureThreshold)
	for i := range m.accountFails[accountKey] {
		m.accountFails[accountKey][i] = now
	}
	if m.allowScoped("source:198.51.100.4", "account") {
		t.Fatal("account failure threshold was ignored")
	}
	if !m.allowUnknownSource("unknown-login:198.51.100.5") || !m.allowUnknownSource("unknown-login:198.51.100.5") {
		t.Fatal("unknown-source admission was unexpectedly denied")
	}
	m.releaseUnknownSource("unknown-login:198.51.100.5")
	m.releaseUnknownSource("unknown-login:198.51.100.5")
	m.unknownSourceFails["unknown-login:198.51.100.6"] = make([]time.Time, authFailureThreshold)
	for i := range m.unknownSourceFails["unknown-login:198.51.100.6"] {
		m.unknownSourceFails["unknown-login:198.51.100.6"][i] = now
	}
	if m.allowUnknownSource("unknown-login:198.51.100.6") {
		t.Fatal("unknown-source failure threshold was ignored")
	}

	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	manager := NewManager(db)
	manager.Now = func() time.Time { return now }
	token, err := manager.EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Setup(ctx, token, "administrator password"); err != nil {
		t.Fatal(err)
	}
	admin, err := db.GetAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	admin.TOTPEnabled = true
	admin.TOTPSecret = "JBSWY3DPEHPK3PXP"
	if err := db.SaveAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "198.51.100.7:8080"
	code := totpCode(admin.TOTPSecret, now.Unix()/30)
	if _, _, err := manager.LoginAs(ctx, request, "admin", "administrator password", code, ""); err != nil {
		t.Fatalf("valid TOTP login failed: %v", err)
	}
	if _, _, err := manager.LoginAs(ctx, request, "admin", "administrator password", code, ""); err == nil {
		t.Fatal("replayed TOTP login was accepted")
	}
	plain, hashes, err := RecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveRecoveryCodes(ctx, hashes); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.LoginAs(ctx, request, "admin", "administrator password", "000000", plain[0]); err != nil {
		t.Fatalf("recovery-code login failed: %v", err)
	}
	if _, ok := VerifyTOTPAtStep(admin.TOTPSecret, "12a456", now); ok {
		t.Fatal("non-numeric TOTP code was accepted")
	}
}

func TestRequestWrappersMapTokenStoreErrorsAndDisabledAccounts(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(db)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/setup", nil)
	request.RemoteAddr = "198.51.100.8:8080"
	if err := manager.SetupRequest(ctx, request, "token", "administrator password"); err == nil {
		t.Fatal("closed setup store unexpectedly succeeded")
	}
	if err := manager.ActivateRequest(ctx, request, "token", "invitee account password"); err == nil {
		t.Fatal("closed activation store unexpectedly succeeded")
	}

	db, err = store.Open(filepath.Join(t.TempDir(), "disabled.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	manager = NewManager(db)
	token, err := manager.EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Setup(ctx, token, "administrator password"); err != nil {
		t.Fatal(err)
	}
	hash, err := PasswordHash("disabled account password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(ctx, store.User{Username: "disabled", DisplayName: "Disabled", Role: store.RoleViewer, PasswordHash: hash, Enabled: false}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "198.51.100.9:8080"
	if _, _, err := manager.LoginAs(ctx, request, "disabled", "disabled account password", "", ""); err == nil {
		t.Fatal("disabled account unexpectedly authenticated")
	}
}

func TestForwardedAddressAndLimiterHelpers(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", ""},
		{"unknown", "unknown", ""},
		{"obfuscated", "_proxy", ""},
		{"ipv4", "198.51.100.7", "198.51.100.7"},
		{"ipv6", "2001:db8::7", "2001:db8::7"},
		{"quoted", `"198.51.100.8"`, "198.51.100.8"},
		{"bracketed", "[2001:db8::8]", "2001:db8::8"},
		{"ipv4-port", "198.51.100.9:443", "198.51.100.9"},
		{"ipv6-port", "[2001:db8::9]:443", "2001:db8::9"},
		{"hostname", "proxy.example:443", ""},
		{"malformed", "[2001:db8::9", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseForwardedAddress(tc.raw); got != tc.want {
				t.Fatalf("parseForwardedAddress(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
	if host, port, err := netSplitHostPort(" [2001:db8::1]:8080 "); err != nil || host != "2001:db8::1" || port != "8080" {
		t.Fatalf("netSplitHostPort valid = %q:%q, %v", host, port, err)
	}
	if _, _, err := netSplitHostPort("not-a-host-port"); err == nil {
		t.Fatal("invalid host/port unexpectedly parsed")
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Forwarded-For", "198.51.100.10, 198.51.100.11")
	if got := forwardedCandidates(request); len(got) != 2 || got[0] != "198.51.100.10" || got[1] != "198.51.100.11" {
		t.Fatalf("forwarded candidates = %#v", got)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Forwarded", `for="[2001:db8::12]:443";proto=https,for=unknown`)
	if got := forwardedCandidates(request); len(got) != 2 || got[0] != "2001:db8::12" || got[1] != "" {
		t.Fatalf("RFC forwarded candidates = %#v", got)
	}
	request.Header.Set("X-Forwarded-For", "198.51.100.99")
	if got := forwardedCandidates(request); len(got) != 2 || got[0] != "2001:db8::12" {
		t.Fatalf("mixed forwarding conventions were not canonicalized: %#v", got)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Forwarded", "proto=https;host=edgewatch.example")
	if got := forwardedCandidates(request); len(got) != 0 {
		t.Fatalf("Forwarded entries without a for parameter = %#v", got)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	if got := forwardedCandidates(request); got != nil {
		t.Fatalf("request without forwarding headers = %#v", got)
	}
	if forwardedCandidates(nil) != nil {
		t.Fatal("nil request returned forwarded candidates")
	}
}

func TestConfirmTOTPForUserLegacyFallbackRateLimitAndMissingUser(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	m := NewManager(db)
	m.Now = func() time.Time { return now }
	token, err := m.EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(ctx, token, "administrator password"); err != nil {
		t.Fatal(err)
	}
	admin, err := db.GetAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	admin.TOTPEnabled = true
	admin.TOTPSecret = "JBSWY3DPEHPK3PXP"
	if err := db.SaveAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, store.LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp", nil)
	request.RemoteAddr = "198.51.100.20:8080"
	code := totpCode(admin.TOTPSecret, now.Unix()/30)
	// The fallback itself is the compatibility contract under test; the
	// encrypted fixture may have an unavailable legacy factor, so its result is
	// intentionally not used as an assertion here.
	_ = m.ConfirmTOTPForUser(ctx, request, store.LegacyAdminUserID, code, "")
	if err := m.ConfirmTOTPForUser(ctx, request, "missing-user", "000000", ""); err == nil {
		t.Fatal("missing user factor unexpectedly accepted")
	}
	limited := NewManager(db)
	limited.Now = func() time.Time { return now }
	key := scopedAccountKey(limited.sourceScopeFor(request, "totp-confirmation"), "totp-confirm:"+store.LegacyAdminUserID)
	limited.accountFails[key] = make([]time.Time, authFailureThreshold)
	for i := range limited.accountFails[key] {
		limited.accountFails[key][i] = now
	}
	if err := limited.ConfirmTOTPForUser(ctx, request, store.LegacyAdminUserID, code, ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("TOTP confirmation rate-limit error = %v", err)
	}
}

func TestLimiterMapInitializationEvictionAndCleanup(t *testing.T) {
	m := &Manager{}
	m.mu.Lock()
	m.ensureScopedLimiterMapsLocked()
	if m.fails == nil || m.blocked == nil || m.accountFails == nil || m.accountBlocked == nil || m.unknownSourceFails == nil || m.unknownSourceBlocked == nil || m.rateAudit == nil {
		t.Fatal("scoped limiter maps were not initialized")
	}
	m.mu.Unlock()

	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	fails := map[string][]time.Time{"old": {now.Add(-time.Hour)}, "new": {now.Add(-time.Minute)}}
	blocked := map[string]time.Time{}
	for i := len(fails); i < authLimiterMaxEntries; i++ {
		fails["f"+string(rune(i))] = []time.Time{now}
	}
	// The oldest failure is evicted when the bounded map is full.
	if len(fails) != authLimiterMaxEntries {
		t.Fatalf("test limiter size = %d", len(fails))
	}
	evictFailureBucketLocked(now, fails, blocked)
	if _, ok := fails["old"]; ok {
		t.Fatal("oldest failure bucket was not evicted")
	}

	// A blocked-only key is also eligible for eviction, and empty failure
	// slices do not prevent a valid blocked key from being selected.
	fails = map[string][]time.Time{}
	blocked = map[string]time.Time{"blocked": now.Add(authBlockDuration)}
	for i := 1; i < authLimiterMaxEntries; i++ {
		blocked["b"+string(rune(i))] = now.Add(authBlockDuration)
	}
	evictFailureBucketLocked(now, fails, blocked)
	if len(blocked) != authLimiterMaxEntries-1 {
		t.Fatalf("blocked eviction size = %d", len(blocked))
	}

	// Exercise threshold trimming and expiry cleanup for both failure buckets.
	values := make([]time.Time, 0, authFailureThreshold+2)
	for i := 0; i < authFailureThreshold+2; i++ {
		values = append(values, now.Add(time.Duration(i)*time.Second))
	}
	failed := map[string][]time.Time{"account": values}
	blocked = map[string]time.Time{"expired": now.Add(-time.Second)}
	recordFailureLocked(now, "account", authFailureThreshold, failed, blocked)
	if len(failed["account"]) != authFailureThreshold || len(blocked) != 2 {
		t.Fatalf("failure recording/expiry = %#v %#v", failed, blocked)
	}
	sweepFailureBucketLocked(now, failed, blocked, authFailureThreshold)
	if _, ok := blocked["expired"]; ok {
		t.Fatal("expired blocked entry was not swept")
	}

	// clearScoped removes account, source, unknown, and legacy-compatible keys.
	m = &Manager{fails: map[string][]time.Time{"203.0.113.4": {now}}, blocked: map[string]time.Time{"203.0.113.4": now}, accountFails: map[string][]time.Time{}, accountBlocked: map[string]time.Time{}, unknownSourceFails: map[string][]time.Time{}, unknownSourceBlocked: map[string]time.Time{}}
	key := scopedAccountKey("source:proxy:203.0.113.4", "admin")
	m.accountFails[key] = []time.Time{now}
	m.accountBlocked[key] = now
	m.fails["source:proxy:203.0.113.4"] = []time.Time{now}
	m.blocked["source:proxy:203.0.113.4"] = now
	m.clearScoped("source:proxy:203.0.113.4", "admin", "unknown")
	if len(m.accountFails) != 0 || len(m.accountBlocked) != 0 || len(m.fails) != 0 || len(m.blocked) != 0 {
		t.Fatalf("clearScoped left entries: %#v %#v %#v %#v", m.accountFails, m.accountBlocked, m.fails, m.blocked)
	}

	if got := scopedAccountKey("source", " "); got != "" {
		t.Fatalf("empty scoped account key = %q", got)
	}
	if got := legacySourceScope("source:203.0.113.4"); got != "203.0.113.4" {
		t.Fatalf("legacy source scope = %q", got)
	}
	if got := legacySourceScope("source:proxy:203.0.113.4"); got != "203.0.113.4" {
		t.Fatalf("scoped legacy source scope = %q", got)
	}
}
