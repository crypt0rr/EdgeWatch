package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTrustedProxyConfigurationDefaultsToIgnoreHeaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("database: "+filepath.Join(dir, "edgewatch.db")+"\nretention: 24h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Web.TrustedProxies) != 0 {
		t.Fatalf("trusted proxies default = %#v", cfg.Web.TrustedProxies)
	}
	if cfg.Web.ForwardedHeader != "x-forwarded-for" {
		t.Fatalf("forwarded header default = %q, want x-forwarded-for", cfg.Web.ForwardedHeader)
	}
}

func TestForwardedHeaderConfigurationNormalizesExplicitPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	contents := "database: " + filepath.Join(dir, "edgewatch.db") + "\nretention: 24h\nweb:\n  forwarded_header: FORWARDED\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Web.ForwardedHeader != "forwarded" {
		t.Fatalf("forwarded header = %q, want normalized forwarded", cfg.Web.ForwardedHeader)
	}
}

func TestTrustedProxyConfigurationValidatesAddresses(t *testing.T) {
	base := Config{Version: 1, Database: "db", Retention: Duration(24 * 60 * 60 * 1e9), Scheduler: Scheduler{MaxConcurrent: 1}, Web: Web{Listen: "127.0.0.1:8080", TrustedProxies: []string{"127.0.0.1", "10.0.0.0/8"}}}
	if err := base.ValidateDeployment(); err != nil {
		t.Fatal(err)
	}
	base.Web.TrustedProxies = []string{"*"}
	if err := base.ValidateDeployment(); err == nil {
		t.Fatal("wildcard trusted proxy was accepted")
	}
	base.Web.TrustedProxies = []string{""}
	if err := base.ValidateDeployment(); err == nil {
		t.Fatal("empty trusted proxy was accepted")
	}
	base.Web.TrustedProxies = []string{"127.0.0.1/32"}
	for _, header := range []string{"x-forwarded-for", "forwarded", "none", " Forwarded "} {
		base.Web.ForwardedHeader = header
		if err := base.ValidateDeployment(); err != nil {
			t.Errorf("valid forwarded header %q rejected: %v", header, err)
		}
	}
	for _, header := range []string{"x-real-ip", "x-forwarded-for,forwarded", ""} {
		if header == "" {
			continue // Empty means the default after config decoding.
		}
		base.Web.ForwardedHeader = header
		if err := base.ValidateDeployment(); err == nil {
			t.Errorf("invalid forwarded header %q was accepted", header)
		}
	}
}

func TestAllowedHostConfigurationValidatesNamesAndPorts(t *testing.T) {
	base := Config{Version: 1, Database: "db", Retention: Duration(24 * 60 * 60 * 1e9), Scheduler: Scheduler{MaxConcurrent: 1}, Web: Web{Listen: "127.0.0.1:8080", AllowedHosts: []string{"console.example.test", "[2001:db8::10]:8443"}}}
	if err := base.ValidateDeployment(); err != nil {
		t.Fatal(err)
	}
	for _, hosts := range [][]string{{"https://console.example.test"}, {"bad host"}, {"console.example.test:0"}, {""}, {"[not-an-ip]:8443"}, {"console.example.test:bad"}, {"console.example.test:1"}, {":80"}, {"2001:db8:::10"}, {"-bad.example"}, {"bad-.example"}, {"bad..example"}, {strings.Repeat("a", 64) + ".example"}, {"bad_example"}} {
		base.Web.AllowedHosts = hosts
		err := base.ValidateDeployment()
		if hosts[0] == "console.example.test:1" {
			if err != nil {
				t.Fatalf("valid host with port rejected: %v", err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("invalid allowed host %v was accepted", hosts)
		}
	}
	base.Web.AllowedHosts = []string{"192.0.2.1"}
	if err := base.ValidateDeployment(); err != nil {
		t.Fatalf("valid IPv4 host rejected: %v", err)
	}
	tooLong := strings.Repeat("a", 254)
	base.Web.AllowedHosts = []string{tooLong}
	if err := base.ValidateDeployment(); err == nil {
		t.Fatal("overlong allowed host was accepted")
	}
}

func TestSourceURLConfiguration(t *testing.T) {
	base := Config{Version: 1, Database: "db", Retention: Duration(24 * time.Hour), Scheduler: Scheduler{MaxConcurrent: 1}, Web: Web{Listen: "127.0.0.1:8080"}}
	for _, source := range []string{"", "https://github.com/example/EdgeWatch/tree/custom-tag", "https://source.example.test/edgewatch.tar.gz"} {
		base.Web.SourceURL = source
		if err := base.ValidateDeployment(); err != nil {
			t.Errorf("source URL %q rejected: %v", source, err)
		}
	}
	for _, source := range []string{"http://example.test/source", "//example.test/source", "https://", "https://user:password@example.test/source", "https://example.test/source?token=secret", "https://example.test/source#fragment", " https://example.test/source", "javascript:alert(1)", "https://example.test/" + strings.Repeat("a", 2048)} {
		base.Web.SourceURL = source
		if err := base.ValidateDeployment(); err == nil {
			t.Errorf("source URL %q accepted", source)
		}
	}
}

func TestTargetExclusionConfigurationValidatesNetworks(t *testing.T) {
	base := Config{Version: 1, Database: "db", Retention: Duration(24 * 60 * 60 * 1e9), Scheduler: Scheduler{MaxConcurrent: 1}, Scanner: ScannerConfig{TargetExclusions: []string{"127.0.0.0/8"}}, Web: Web{Listen: "127.0.0.1:8080"}}
	if err := base.ValidateDeployment(); err != nil {
		t.Fatal(err)
	}
	base.Scanner.TargetExclusions = []string{"*"}
	if err := base.ValidateDeployment(); err == nil || !strings.Contains(err.Error(), "target_exclusions") {
		t.Fatalf("invalid scanner exclusion was accepted: %v", err)
	}
	base.Scanner.TargetExclusions = []string{"127.0.0.0/8", "127.0.0.0/8"}
	if err := base.ValidateDeployment(); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("duplicate scanner exclusion was accepted: %v", err)
	}
}

func TestTargetExclusionNetworkMatchingAndOverlap(t *testing.T) {
	_, left, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, contained, err := net.ParseCIDR("192.0.2.128/25")
	if err != nil {
		t.Fatal(err)
	}
	_, disjoint, err := net.ParseCIDR("198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if !networksOverlap(left, contained) || !networksOverlap(contained, left) || networksOverlap(left, disjoint) || networksOverlap(nil, left) {
		t.Fatal("network overlap classification is incorrect")
	}
	if got := matchingTargetExclusion(net.ParseIP("192.0.2.42"), []*net.IPNet{disjoint, left}); got != left.String() {
		t.Fatalf("matching exclusion = %q, want %q", got, left.String())
	}
	if got := matchingTargetExclusion(net.ParseIP("203.0.113.1"), []*net.IPNet{left}); got != "" {
		t.Fatalf("non-matching exclusion = %q", got)
	}
}

// web.ipv6_rate_limit_prefix defaults to /64 when it is omitted, and
// accepts a prefix length from /32 to /128; an explicit zero is rejected,
// not replaced by the default.
func TestIPv6RateLimitPrefixConfiguration(t *testing.T) {
	dir := t.TempDir()
	for contents, want := range map[string]int{
		"":                                     DefaultIPv6RateLimitPrefix,
		"web:\n  ipv6_rate_limit_prefix: 56\n": 56,
	} {
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte("database: "+filepath.Join(dir, "edgewatch.db")+"\nretention: 24h\n"+contents), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.Web.RateLimitIPv6Prefix(); got != want {
			t.Errorf("IPv6 rate-limit prefix from %q = %d, want %d", contents, got, want)
		}
	}
	base := Config{Version: 1, Database: "db", Retention: Duration(24 * time.Hour), Scheduler: Scheduler{MaxConcurrent: 1}, Web: Web{Listen: "127.0.0.1:8080"}}
	for _, prefix := range []int{MinIPv6RateLimitPrefix, 48, 64, 128} {
		base.Web.IPv6RateLimitPrefix = &prefix
		if err := base.ValidateDeployment(); err != nil {
			t.Errorf("prefix /%d rejected: %v", prefix, err)
		}
	}
	for _, prefix := range []int{0, MinIPv6RateLimitPrefix - 1, 129, -64} {
		base.Web.IPv6RateLimitPrefix = &prefix
		if err := base.ValidateDeployment(); err == nil || !strings.Contains(err.Error(), "web.ipv6_rate_limit_prefix") {
			t.Errorf("prefix %d accepted: %v", prefix, err)
		}
	}
}

// web.max_live_streams and web.max_live_streams_per_unit default to 256 and
// 64 when they are omitted, the per-unit limit to the deployment-wide one
// when that is lower; an explicit zero is rejected, not replaced by the
// default.
func TestLiveStreamLimitConfiguration(t *testing.T) {
	base := Config{Version: 1, Database: "db", Retention: Duration(24 * time.Hour), Scheduler: Scheduler{MaxConcurrent: 1}, Web: Web{Listen: "127.0.0.1:8080"}}
	limit := func(value int) *int { return &value }
	for _, check := range []struct {
		total, perUnit         *int
		wantTotal, wantPerUnit int
	}{
		{nil, nil, DefaultMaxLiveStreams, DefaultMaxLiveStreamsPerUnit},
		{limit(1024), nil, 1024, DefaultMaxLiveStreamsPerUnit},
		{limit(32), nil, 32, 32},
		{nil, limit(100), DefaultMaxLiveStreams, 100},
		{limit(MaxLiveStreamsLimit), limit(MaxLiveStreamsLimit), MaxLiveStreamsLimit, MaxLiveStreamsLimit},
		{limit(1), limit(1), 1, 1},
	} {
		base.Web.MaxLiveStreams, base.Web.MaxLiveStreamsPerUnit = check.total, check.perUnit
		if err := base.ValidateDeployment(); err != nil {
			t.Errorf("limits %d/%d rejected: %v", check.wantTotal, check.wantPerUnit, err)
		}
		if total, perUnit := base.Web.LiveStreamLimits(); total != check.wantTotal || perUnit != check.wantPerUnit {
			t.Errorf("limits = %d/%d, want %d/%d", total, perUnit, check.wantTotal, check.wantPerUnit)
		}
	}
	for _, check := range []struct {
		total, perUnit *int
		field          string
	}{
		{limit(0), nil, "web.max_live_streams "},
		{limit(-1), nil, "web.max_live_streams "},
		{limit(MaxLiveStreamsLimit + 1), nil, "web.max_live_streams "},
		{nil, limit(0), "web.max_live_streams_per_unit"},
		{nil, limit(-1), "web.max_live_streams_per_unit"},
		{nil, limit(DefaultMaxLiveStreams + 1), "web.max_live_streams_per_unit"},
		{limit(16), limit(17), "web.max_live_streams_per_unit"},
	} {
		base.Web.MaxLiveStreams, base.Web.MaxLiveStreamsPerUnit = check.total, check.perUnit
		if err := base.ValidateDeployment(); err == nil || !strings.Contains(err.Error(), check.field) {
			t.Errorf("limits %v/%v = %v, want a %s error", check.total, check.perUnit, err, check.field)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("database: "+filepath.Join(dir, "edgewatch.db")+"\nretention: 24h\nweb:\n  max_live_streams: 512\n  max_live_streams_per_unit: 32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if total, perUnit := cfg.Web.LiveStreamLimits(); total != 512 || perUnit != 32 {
		t.Fatalf("loaded limits = %d/%d", total, perUnit)
	}
}
