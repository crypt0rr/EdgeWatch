package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBusinessUnitsFlagDefaultsOffAndParses(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want bool
	}{
		{name: "omitted", yaml: "", want: false},
		{name: "explicit false", yaml: "experimental:\n  business_units: false\n", want: false},
		{name: "explicit true", yaml: "experimental:\n  business_units: true\n", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("version: 1\ndatabase: ./data/edgewatch.db\n"+tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.BusinessUnitsEnabled(); got != tc.want {
				t.Fatalf("BusinessUnitsEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExperimentalSectionRejectsUnknownFeatures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ndatabase: ./data/edgewatch.db\nexperimental:\n  tenants: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "tenants") {
		t.Fatalf("unknown experimental feature was accepted: %v", err)
	}
}
