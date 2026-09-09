package config

import (
	"os"
	"path/filepath"
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
