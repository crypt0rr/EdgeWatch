package config

import "testing"

func TestPortContainsUsesValidatedRanges(t *testing.T) {
	for _, test := range []struct {
		raw  string
		port int
		want bool
	}{
		{raw: "1,22,80-82,65535", port: 1, want: true},
		{raw: "1,22,80-82,65535", port: 81, want: true},
		{raw: "1,22,80-82,65535", port: 23, want: false},
		{raw: "1,22,80-82,65535", port: 0, want: false},
		{raw: "1,22,80-82,65535", port: 65536, want: false},
		{raw: "not-a-port", port: 1, want: false},
	} {
		if got := PortContains(test.raw, test.port); got != test.want {
			t.Errorf("PortContains(%q, %d) = %t, want %t", test.raw, test.port, got, test.want)
		}
	}
}
