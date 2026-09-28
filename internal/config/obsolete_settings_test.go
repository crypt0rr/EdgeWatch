package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Business units are always on. A configuration written for their preview
// still starts: experimental.business_units is accepted whatever its value
// and reported as obsolete, and a configuration without it reports nothing.
func TestBusinessUnitsPreviewSettingIsAcceptedAsObsolete(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{name: "omitted", yaml: "", want: nil},
		{name: "empty section", yaml: "experimental: {}\n", want: nil},
		{name: "explicit false", yaml: "experimental:\n  business_units: false\n", want: []string{"experimental.business_units"}},
		{name: "explicit true", yaml: "experimental:\n  business_units: true\n", want: []string{"experimental.business_units"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("version: 1\ndatabase: ./data/edgewatch.db\n"+tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			for name, load := range map[string]func(string) (*Config, error){"Load": Load, "LoadForAdmin": LoadForAdmin} {
				cfg, err := load(path)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if got := cfg.ObsoleteSettings(); !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("%s ObsoleteSettings() = %v, want %v", name, got, tc.want)
				}
			}
		})
	}
}

// The preview's section accepts only its own key, as a boolean; anything
// else in it is rejected like every unknown or malformed setting.
func TestExperimentalSectionRejectsOtherKeys(t *testing.T) {
	for extra, want := range map[string]string{
		"experimental:\n  tenants: true\n":         "tenants",
		"experimental:\n  business_units: maybe\n": "maybe",
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte("version: 1\ndatabase: ./data/edgewatch.db\n"+extra), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%q was accepted or refused without naming %q: %v", extra, want, err)
		}
	}
}
