package config

import (
	"strings"
	"testing"
)

func TestBuiltinScannerProfilesAndNormalization(t *testing.T) {
	nmap := BuiltinNmapProfile()
	if nmap.Engine != EngineNmap || nmap.Description == "" {
		t.Fatalf("built-in nmap profile = %#v", nmap)
	}
	naabu := BuiltinNaabuProfile()
	if naabu.Engine != EngineNaabuNmap || naabu.Naabu.ScanType != "connect" || naabu.Naabu.Rate != 1000 || naabu.Naabu.Verify != true {
		t.Fatalf("built-in naabu profile = %#v", naabu)
	}

	got := NormalizeScannerProfile(ScannerProfile{
		Engine:             EngineNaabuNmap,
		NSEProfile:         " ssl-cert ",
		OperatorAdjustable: []string{" rate ", "scan_type"},
		OperatorBounds:     map[string]NumericBound{" rate ": {Min: 1, Max: 1000}},
	})
	if got.Naabu.Rate != 1000 || got.Naabu.Workers != 25 || got.Naabu.Retries != 3 || !got.Naabu.Verify {
		t.Fatalf("Naabu defaults not materialized: %#v", got.Naabu)
	}
	if got.NSEProfile != "ssl-cert" || got.OperatorAdjustable[0] != "rate" || got.OperatorBounds["rate"].Max != 1000 {
		t.Fatalf("profile values not normalized: %#v", got)
	}
	if got.NmapArgs == nil || got.NaabuArgs == nil || got.EnrichmentArgs == nil {
		t.Fatalf("nil argument arrays were not materialized: %#v", got)
	}
}

func TestValidateOperatorBoundsAndNSEInputs(t *testing.T) {
	valid := map[string]NumericBound{
		"rate": {Min: 1, Max: 100000}, "workers": {Min: 1, Max: 1024},
		"retries": {Min: 0, Max: 10}, "timeout_ms": {Min: 100, Max: 60000},
		"warm_up_seconds": {Min: 0, Max: 60}, "address_batch_size": {Min: 1, Max: 256},
	}
	for field, bound := range valid {
		if err := validateOperatorBound(field, bound); err != nil {
			t.Errorf("valid %s bound rejected: %v", field, err)
		}
	}
	for _, tc := range []struct {
		field string
		bound NumericBound
	}{
		{"rate", NumericBound{Min: 10, Max: 1}},
		{"rate", NumericBound{Min: 0, Max: 1}},
		{"workers", NumericBound{Min: 1, Max: 2048}},
		{"unknown", NumericBound{Min: 1, Max: 2}},
	} {
		if err := validateOperatorBound(tc.field, tc.bound); err == nil {
			t.Errorf("invalid %s bound accepted: %#v", tc.field, tc.bound)
		}
	}

	for _, name := range []string{"banner", "dns-recursion", "http-headers", "http-title", "ssl-cert", "ssh-hostkey"} {
		if err := validateNSEName(name); err != nil {
			t.Errorf("approved NSE %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"", "not-installed", "../banner", "banner;id", "banner arg"} {
		if err := validateNSEName(name); err == nil {
			t.Errorf("invalid NSE %q accepted", name)
		}
	}
	if err := validateNSEArgs(map[string]string{"key_1": "value", "tls.version": "1.3"}); err != nil {
		t.Fatal(err)
	}
	for _, args := range []map[string]string{
		{"1key": "value"}, {"key": ""}, {"key": "@file"}, {"key": "a=b"}, {"key": "value/with/path"}, {"key name": "value"},
	} {
		if err := validateNSEArgs(args); err == nil {
			t.Errorf("unsafe NSE args accepted: %#v", args)
		}
	}
}

func TestScannerProfileValidationAndPreviewBranches(t *testing.T) {
	base := []string{PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput}
	if err := requirePlaceholders(base, "nmap", PlaceholderPorts, PlaceholderStructuredOutput); err != nil {
		t.Fatal(err)
	}
	if err := requirePlaceholders([]string{PlaceholderPorts, PlaceholderStructuredOutput}, "nmap", PlaceholderAddress); err == nil {
		t.Fatal("missing placeholder was accepted")
	}
	if err := requireAddressPlaceholder([]string{PlaceholderAddresses}, "nmap"); err != nil {
		t.Fatal(err)
	}
	if err := requireAddressPlaceholder([]string{}, "nmap"); err == nil {
		t.Fatal("missing address placeholder was accepted")
	}

	profile := ScannerProfile{
		Engine:         EngineNaabuNmap,
		Naabu:          BuiltinNaabuProfile().Naabu,
		NaabuArgs:      []string{PlaceholderTargetsFile, PlaceholderPorts, PlaceholderStructuredOutput, PlaceholderScanType, PlaceholderHostDiscovery, "-verbose"},
		NmapArgs:       []string{PlaceholderAddresses, PlaceholderAddressFamily, PlaceholderHostDiscovery, PlaceholderScanType, PlaceholderPorts, PlaceholderStructuredOutput, PlaceholderServiceDetection, PlaceholderNSE, "-v"},
		EnrichmentArgs: []string{PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput, "--host-timeout", "5m"},
		NSEProfile:     "http-title",
		NSEArgs:        map[string]string{"a": "b", "z": "last"},
	}
	previews, err := RenderScannerProfilePreview(profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(previews) != 3 || previews[0].Executable != "/usr/local/bin/naabu" || previews[1].Executable != "/usr/bin/nmap" || previews[2].Executable != "/usr/bin/nmap" {
		t.Fatalf("unexpected previews: %#v", previews)
	}
	joined := strings.Join(previews[1].Args, " ")
	for _, expected := range []string{"192.0.2.10", "2001:db8::10", "-4", "-Pn", "-sS", "-sV", "--script", "http-title", "a=example,z=example"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("custom preview missing %q: %v", expected, previews[1].Args)
		}
	}
	if !strings.Contains(strings.Join(previews[0].Args, " "), "-scan-type") || !strings.Contains(strings.Join(previews[2].Args, " "), "--host-timeout") {
		t.Fatalf("Naabu/enrichment preview missing expected args: %#v", previews)
	}

	for _, value := range []string{"", "--bad|flag", "${PATH}", "prefix{address}", "{unknown}"} {
		if err := validateArgTemplate([]string{value}, "nmap"); err == nil {
			t.Errorf("invalid template value %q accepted", value)
		}
	}
	if forbiddenPositionalLiteral("0.5s") || forbiddenPositionalLiteral("5m") {
		t.Fatal("duration scalar classification changed unexpectedly")
	}
}
