package web

import (
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
)

func TestScanChangeFormattingHelpers(t *testing.T) {
	if !sameStringMap(map[string]string{"a": "1"}, map[string]string{"a": "1"}) {
		t.Fatal("equal string maps were not recognized")
	}
	for _, tc := range []struct {
		a, b map[string]string
	}{
		{map[string]string{"a": "1"}, map[string]string{"a": "2"}},
		{map[string]string{"a": "1"}, map[string]string{"b": "1"}},
		{map[string]string{}, map[string]string{"a": "1"}},
	} {
		if sameStringMap(tc.a, tc.b) {
			t.Errorf("different maps were equal: %#v/%#v", tc.a, tc.b)
		}
	}
	if !sameStrings([]string{"udp", "tcp"}, []string{"tcp", "udp"}) || sameStrings([]string{"tcp"}, []string{"udp"}) {
		t.Fatal("string slice comparison is incorrect")
	}
	for _, tc := range []struct {
		protocol *config.Protocol
		want     string
	}{{nil, "disabled"}, {&config.Protocol{}, ""}, {&config.Protocol{Ports: "22"}, "22"}} {
		if got := protocolSummary(tc.protocol); got != tc.want {
			t.Errorf("protocol summary %#v = %q, want %q", tc.protocol, got, tc.want)
		}
	}
	for _, tc := range []struct {
		protocol *config.Protocol
		want     string
	}{{nil, "disabled"}, {&config.Protocol{}, "disabled"}, {&config.Protocol{NSEProfile: "banner"}, "banner"}} {
		if got := nseSummary(tc.protocol); got != tc.want {
			t.Errorf("NSE summary %#v = %q, want %q", tc.protocol, got, tc.want)
		}
	}
	for _, tc := range []struct {
		protocol *config.Protocol
		want     string
	}{{nil, "disabled"}, {&config.Protocol{}, "disabled"}, {&config.Protocol{Naabu: &config.NaabuOptions{ScanType: "connect", Verify: true}}, "connect (verify=true)"}} {
		if got := naabuSecuritySummary(tc.protocol); got != tc.want {
			t.Errorf("Naabu summary %#v = %q, want %q", tc.protocol, got, tc.want)
		}
	}
	if got := protocolSummary(&config.Protocol{Ports: "1-65535"}); got != "1-65535" {
		t.Fatal(got)
	}
}
