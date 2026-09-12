package config

import (
	"strings"
	"testing"
)

func TestValidateScannerProfileRejectsMissingManagedInputs(t *testing.T) {
	validNaabu := BuiltinNaabuProfile()
	validNaabu.NaabuArgs = []string{PlaceholderTargetsFile, PlaceholderPorts, PlaceholderStructuredOutput}
	validNmap := ScannerProfile{Engine: EngineNmap, NmapArgs: []string{PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput}}
	tests := []struct {
		name    string
		profile ScannerProfile
		want    string
	}{
		{name: "unknown engine", profile: ScannerProfile{Engine: "custom"}, want: "engine must be nmap or naabu_nmap"},
		{name: "naabu targets", profile: ScannerProfile{Engine: EngineNaabuNmap, Naabu: validNaabu.Naabu, NaabuArgs: []string{PlaceholderPorts, PlaceholderStructuredOutput}}, want: "targets_file"},
		{name: "naabu ports", profile: ScannerProfile{Engine: EngineNaabuNmap, Naabu: validNaabu.Naabu, NaabuArgs: []string{PlaceholderTargetsFile, PlaceholderStructuredOutput}}, want: "ports"},
		{name: "naabu output", profile: ScannerProfile{Engine: EngineNaabuNmap, Naabu: validNaabu.Naabu, NaabuArgs: []string{PlaceholderTargetsFile, PlaceholderPorts}}, want: "structured_output"},
		{name: "nmap address", profile: ScannerProfile{Engine: EngineNmap, NmapArgs: []string{PlaceholderPorts, PlaceholderStructuredOutput}}, want: "address"},
		{name: "enrichment address", profile: ScannerProfile{Engine: EngineNmap, EnrichmentArgs: []string{PlaceholderPorts, PlaceholderStructuredOutput}}, want: "address"},
		{name: "NSE args without profile", profile: ScannerProfile{Engine: EngineNmap, NSEArgs: map[string]string{"key": "value"}}, want: "nse_args requires"},
		{name: "unapproved NSE", profile: ScannerProfile{Engine: EngineNmap, NSEProfile: "default"}, want: "not installed or approved"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateScannerProfile(tt.profile); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
	if err := ValidateScannerProfile(validNmap); err != nil {
		t.Fatalf("valid Nmap profile rejected: %v", err)
	}
}

func TestValidateScannerProfileOperatorFieldRules(t *testing.T) {
	base := ScannerProfile{Engine: EngineNaabuNmap, Naabu: BuiltinNaabuProfile().Naabu}
	tests := []struct {
		name    string
		profile ScannerProfile
		want    string
	}{
		{name: "empty field", profile: ScannerProfile{Engine: base.Engine, OperatorAdjustable: []string{" "}}, want: "empty field"},
		{name: "duplicate field", profile: ScannerProfile{Engine: base.Engine, OperatorAdjustable: []string{"rate", "rate"}, OperatorBounds: map[string]NumericBound{"rate": {Min: 1, Max: 100}}}, want: "duplicate field"},
		{name: "missing bound", profile: ScannerProfile{Engine: base.Engine, OperatorAdjustable: []string{"rate"}}, want: "requires an operator bound"},
		{name: "typed bound", profile: ScannerProfile{Engine: base.Engine, OperatorAdjustable: []string{"verify"}, OperatorBounds: map[string]NumericBound{"verify": {Min: 0, Max: 1}}}, want: "does not accept a numeric bound"},
		{name: "unsupported field", profile: ScannerProfile{Engine: base.Engine, OperatorAdjustable: []string{"shell"}}, want: "is not supported"},
		{name: "orphan bound", profile: ScannerProfile{Engine: base.Engine, OperatorBounds: map[string]NumericBound{"rate": {Min: 1, Max: 10}}}, want: "not marked operator-adjustable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateScannerProfile(tt.profile); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}

	valid := base
	valid.OperatorAdjustable = []string{"rate", "scan_type", "verify"}
	valid.OperatorBounds = map[string]NumericBound{"rate": {Min: 100, Max: 10000}}
	if err := ValidateScannerProfile(valid); err != nil {
		t.Fatalf("typed and bounded operator fields rejected: %v", err)
	}
}

func TestScannerProfileArgumentClassificationAndBounds(t *testing.T) {
	for _, value := range []string{"-il", "-ox", "-p-", "-ss-extra", "-st-extra", "-su-extra", "-sv-extra", "-ir-target"} {
		if !forbiddenScannerFlag(value) {
			t.Errorf("managed flag family %q was not rejected", value)
		}
	}
	for _, value := range []string{"198.51.100.1:443", "192.0.2.0/24", "/tmp/output", "../nmap", "nmap", "sh", "-", "--"} {
		if !forbiddenPositionalLiteral(value) {
			t.Errorf("unsafe positional %q was accepted", value)
		}
	}
	for _, value := range []string{"100", "0.5s", "connect", "syn", "tcp", "false"} {
		if forbiddenPositionalLiteral(value) || !safeScannerScalar(value) {
			t.Errorf("safe scalar %q was classified as unsafe", value)
		}
	}
	if !forbiddenPositionalLiteral("target.example") || forbiddenPositionalLiteral("version-light") {
		t.Fatal("hostname and enum positional classification changed")
	}

	valid := []struct{ flag, operand string }{
		{"--scan-delay", "0s"}, {"--max-scan-delay", "1m"}, {"--initial-rtt-timeout", "1ms"}, {"--min-rtt-timeout", "1s"}, {"--max-rtt-timeout", "1m"},
	}
	for _, item := range valid {
		if err := validateScannerFlagOperand("nmap", item.flag, item.operand); err != nil {
			t.Errorf("valid %s %s rejected: %v", item.flag, item.operand, err)
		}
	}
	for _, item := range []struct{ flag, operand string }{{"--scan-delay", "61s"}, {"--max-scan-delay", "-1s"}, {"--initial-rtt-timeout", "0s"}, {"--max-rtt-timeout", "61s"}} {
		if err := validateScannerFlagOperand("nmap", item.flag, item.operand); err == nil {
			t.Errorf("out-of-range %s %s accepted", item.flag, item.operand)
		}
	}
	if err := validateScannerFlagOperand("naabu", "--unknown", "anything"); err != nil {
		t.Fatalf("Naabu scalar operand should remain unconstrained after flag validation: %v", err)
	}
}
