package web

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// A client that rotates well-formed slugs, each a page namespace of its
// own, is bounded by its budget for all public pages: once that is spent,
// every page, a real one included, answers it with 429 until the window
// passes. The flood adds no more buckets than the budget admitted, and it
// evicts no other client's bucket for the real page.
func TestPublicPageBudgetSpansEverySlug(t *testing.T) {
	t.Parallel()
	f := newPublicTenantFixture(t)
	now := time.Now().UTC()
	f.server.now = func() time.Time { return now }
	const neighbour, flooder = "198.51.100.120:1000", "198.51.100.121:1000"
	for _, client := range []string{neighbour, flooder} {
		if rec := f.getPublicPath("/api/public/v1/dashboard/other", client); rec.Code != http.StatusOK {
			t.Fatalf("real page for %s = %d: %s", client, rec.Code, rec.Body.String())
		}
	}
	refusedFrom := -1
	for i := 0; i < 5000; i++ {
		rec := f.getPublicPath(fmt.Sprintf("/api/public/v1/dashboard/nobody-%d", i), flooder)
		switch {
		case refusedFrom < 0 && rec.Code == http.StatusNotFound:
		case rec.Code == http.StatusTooManyRequests && rec.Header().Get("Retry-After") == "60" && strings.Contains(rec.Body.String(), `"rate_limited"`):
			if refusedFrom < 0 {
				refusedFrom = i
			}
		default:
			t.Fatalf("unknown slug %d = %d %v: %s", i, rec.Code, rec.Header(), rec.Body.String())
		}
	}
	// The real page took one request of the budget.
	if refusedFrom != publicPagesRequestLimit-1 {
		t.Fatalf("the first refused unknown slug was number %d, want %d", refusedFrom, publicPagesRequestLimit-1)
	}
	for _, path := range []string{"/api/public/v1/dashboard/other", "/api/public/v1/dashboard", "/api/public/v1/dashboard/nobody-0"} {
		if rec := f.getPublicPath(path, flooder); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("%s after the budget for all pages = %d: %s", path, rec.Code, rec.Body.String())
		}
	}
	f.server.publicMu.Lock()
	buckets := f.server.publicHits.len()
	neighbourBucket := f.server.publicHits.entries["public-dashboard/other:198.51.100.120"]
	f.server.publicMu.Unlock()
	// Each client's budget for all pages, the neighbour's page, and the
	// flooder's admitted pages.
	if want := 2 + 1 + publicPagesRequestLimit; buckets != want {
		t.Fatalf("buckets after the flood = %d, want %d", buckets, want)
	}
	if neighbourBucket == nil {
		t.Fatal("the flood evicted another client's bucket for the real page")
	}
	if rec := f.getPublicPath("/api/public/v1/dashboard/other", neighbour); rec.Code != http.StatusOK {
		t.Fatalf("real page for the other client after the flood = %d: %s", rec.Code, rec.Body.String())
	}
	now = now.Add(time.Minute)
	if rec := f.getPublicPath("/api/public/v1/dashboard/other", flooder); rec.Code != http.StatusOK {
		t.Fatalf("real page for the flooder a minute later = %d: %s", rec.Code, rec.Body.String())
	}
}

// The bucket store evicts its least recently used bucket in constant time,
// keeps a bucket that its client keeps using, drops the buckets that
// counted nothing in the window from the least recently used end, and
// counts each bucket's requests per second of a sliding minute.
func TestAnonymousBucketsEvictTheLeastRecentlyUsed(t *testing.T) {
	t.Parallel()
	const second = int64(1_800_000_000)
	var full anonymousBuckets
	for i := 0; i < anonymousBucketLimit; i++ {
		full.count(fmt.Sprintf("key-%d", i), second)
	}
	if full.get("key-0", second) == nil {
		t.Fatal("bucket missing before the bound was reached")
	}
	full.count("new", second)
	if full.len() != anonymousBucketLimit || full.entries["key-0"] == nil || full.entries["new"] == nil || full.entries["key-1"] != nil {
		t.Fatalf("over the bound: %d buckets, key-0 %t, new %t, key-1 %t; want the least recently used key-1 dropped", full.len(), full.entries["key-0"] != nil, full.entries["new"] != nil, full.entries["key-1"] != nil)
	}
	if full.get("missing", second) != nil {
		t.Fatal("a key without a bucket returned one")
	}

	var aging anonymousBuckets
	aging.count("old-1", second)
	aging.count("old-2", second)
	aging.count("fresh", second+30)
	aging.expire(second + anonymousWindowSeconds)
	if aging.len() != 1 || aging.entries["fresh"] == nil {
		t.Fatalf("after expiry %d buckets remain, fresh kept %t; want only fresh", aging.len(), aging.entries["fresh"] != nil)
	}

	var window anonymousBuckets
	for i := 0; i < 3; i++ {
		window.count("k", second)
	}
	window.count("k", second+30)
	window.count("k", second+30)
	for _, check := range []struct {
		at    int64
		total int
	}{{second + 30, 5}, {second + 59, 5}, {second + 60, 2}, {second + 89, 2}, {second + 90, 0}} {
		if got := window.get("k", check.at).total; got != check.total {
			t.Fatalf("requests in the window ending %ds after the first = %d, want %d", check.at-second, got, check.total)
		}
	}
	window.count("k", second+90)
	// A clock that goes back keeps the window where it is.
	if got := window.get("k", second+10).total; got != 1 {
		t.Fatalf("requests after the clock went back = %d, want 1", got)
	}
	if got := window.get("k", second+1000).total; got != 0 {
		t.Fatalf("requests after a long pause = %d, want 0", got)
	}
}

// The anonymous limits count an IPv6 client by its /64, as the sign-in
// limits do: another address of the same network shares the budget, while
// another network and an IPv4 client have their own. With a /128 prefix
// each address has its own.
func TestAnonymousLimitsGroupIPv6Networks(t *testing.T) {
	t.Parallel()
	server := &Server{Auth: auth.NewManager(nil)}
	from := func(remote string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/public/v1/dashboard", nil)
		r.RemoteAddr = remote
		return r
	}
	for i := 0; i < anonymousRequestLimit; i++ {
		if !server.allowAnonymousRequest(from(fmt.Sprintf("[2001:db8:5:6::%x]:1000", i+1)), publicDashboardRateLimit) {
			t.Fatalf("request %d refused", i+1)
		}
	}
	if server.allowAnonymousRequest(from("[2001:db8:5:6:ffff::1]:1000"), publicDashboardRateLimit) {
		t.Fatal("another address of the /64 was admitted after the network's budget")
	}
	for _, remote := range []string{"[2001:db8:5:7::1]:1000", "198.51.100.130:1000"} {
		if !server.allowAnonymousRequest(from(remote), publicDashboardRateLimit) {
			t.Fatalf("%s was refused", remote)
		}
	}
	if err := server.Auth.SetIPv6RateLimitPrefix(128); err != nil {
		t.Fatal(err)
	}
	if !server.allowAnonymousRequest(from("[2001:db8:5:6:ffff::2]:1000"), publicDashboardRateLimit) {
		t.Fatal("another address of the /64 was refused with a /128 prefix")
	}
	// Without an authentication manager the client address is used.
	bare := &Server{}
	if got := bare.rateLimitIdentity(from("[2001:db8:5:6::1]:1000")); got != "2001:db8:5:6::1" {
		t.Fatalf("identity without an authentication manager = %q", got)
	}
}

// NewServer applies web.ipv6_rate_limit_prefix to the rate limits. A prefix
// that configuration validation would reject is logged and leaves the
// default.
func TestServerAppliesTheIPv6RateLimitPrefix(t *testing.T) {
	t.Parallel()
	for prefix, want := range map[int]string{128: "2001:db8::1", 48: "2001:db8::/48", 0: "2001:db8::/64"} {
		db, err := store.Open(storetest.FreshPath(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080", IPv6RateLimitPrefix: &prefix}}
		a, err := app.New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		var logs bytes.Buffer
		server := NewServer(a, db, slog.New(slog.NewTextHandler(&logs, nil)))
		r := httptest.NewRequest(http.MethodGet, "/api/public/v1/dashboard", nil)
		r.RemoteAddr = "[2001:db8::1]:1000"
		if got := server.Auth.RateLimitIdentity(r); got != want {
			t.Errorf("identity with web.ipv6_rate_limit_prefix %d = %q, want %q", prefix, got, want)
		}
		if rejected := strings.Contains(logs.String(), "IPv6 rate-limit prefix configuration rejected"); rejected != (prefix == 0) {
			t.Errorf("prefix %d: rejection logged = %t", prefix, rejected)
		}
	}
}
