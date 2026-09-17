package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
	if forwardedCandidates(nil) != nil {
		t.Fatal("nil request returned forwarded candidates")
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
