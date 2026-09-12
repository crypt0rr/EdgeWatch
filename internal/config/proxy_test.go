package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
