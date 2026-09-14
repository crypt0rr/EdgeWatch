package config

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNaabuAndSchedulerYAMLPresenceBranches(t *testing.T) {
	var options NaabuOptions
	if err := options.UnmarshalYAML(&yaml.Node{Kind: yaml.ScalarNode, Value: "connect"}); err == nil {
		t.Fatal("scalar Naabu options were accepted")
	}
	unknown := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode, Value: "unknown"}, {Kind: yaml.ScalarNode, Value: "true"}}}
	if err := options.UnmarshalYAML(unknown); err == nil || !strings.Contains(err.Error(), "field") {
		t.Fatalf("unknown Naabu option error = %v", err)
	}
	all := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "scan_type"}, {Kind: yaml.ScalarNode, Value: "syn"},
		{Kind: yaml.ScalarNode, Value: "rate"}, {Kind: yaml.ScalarNode, Value: "100"},
		{Kind: yaml.ScalarNode, Value: "workers"}, {Kind: yaml.ScalarNode, Value: "2"},
		{Kind: yaml.ScalarNode, Value: "retries"}, {Kind: yaml.ScalarNode, Value: "0"},
		{Kind: yaml.ScalarNode, Value: "timeout_ms"}, {Kind: yaml.ScalarNode, Value: "500"},
		{Kind: yaml.ScalarNode, Value: "warm_up_seconds"}, {Kind: yaml.ScalarNode, Value: "0"},
		{Kind: yaml.ScalarNode, Value: "verify"}, {Kind: yaml.ScalarNode, Value: "false"},
		{Kind: yaml.ScalarNode, Value: "address_batch_size"}, {Kind: yaml.ScalarNode, Value: "1"},
	}}
	if err := options.UnmarshalYAML(all); err != nil {
		t.Fatal(err)
	}
	if options.ScanType != "syn" || options.Rate != 100 || options.Workers != 2 || options.Retries != 0 || options.TimeoutMS != 500 || options.WarmUpSeconds != 0 || options.Verify || options.AddressBatchSize != 1 || !options.RateSet || !options.WorkersSet || !options.RetriesSet || !options.TimeoutMSSet || !options.WarmUpSecondsSet || !options.VerifySet || !options.AddressBatchSizeSet {
		t.Fatalf("decoded Naabu options = %#v", options)
	}

	var scheduler Scheduler
	if err := scheduler.UnmarshalYAML(&yaml.Node{Kind: yaml.SequenceNode}); err == nil {
		t.Fatal("sequence scheduler was accepted")
	}
	if err := scheduler.UnmarshalYAML(unknown); err == nil {
		t.Fatal("unknown scheduler field was accepted")
	}
	if err := scheduler.UnmarshalYAML(&yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "max_concurrent_scans"}, {Kind: yaml.ScalarNode, Value: "2"},
		{Kind: yaml.ScalarNode, Value: "max_probe_count"}, {Kind: yaml.ScalarNode, Value: "100"},
		{Kind: yaml.ScalarNode, Value: "max_naabu_probe_count"}, {Kind: yaml.ScalarNode, Value: "200"},
	}}); err != nil {
		t.Fatal(err)
	}
	if scheduler.MaxConcurrent != 2 || scheduler.MaxProbeCount != 100 || scheduler.MaxNaabuProbeCount != 200 || !scheduler.maxConcurrentSet || !scheduler.maxProbeCountSet || !scheduler.maxNaabuProbeCountSet {
		t.Fatalf("decoded scheduler = %#v", scheduler)
	}
}

func TestNaabuJSONPresenceAndValidationBranches(t *testing.T) {
	var options NaabuOptions
	if err := json.Unmarshal([]byte(`{"scan_type":"connect","rate":1,"workers":1,"retries":0,"timeout_ms":100,"warm_up_seconds":0,"verify":false,"address_batch_size":1}`), &options); err != nil {
		t.Fatal(err)
	}
	if !options.RateSet || !options.WorkersSet || !options.RetriesSet || !options.TimeoutMSSet || !options.WarmUpSecondsSet || !options.VerifySet || !options.AddressBatchSizeSet {
		t.Fatalf("JSON presence markers = %#v", options)
	}
	if err := json.Unmarshal([]byte(`{"unknown":true}`), &options); err == nil {
		t.Fatal("unknown JSON Naabu option was accepted")
	}
	if err := json.Unmarshal([]byte(`{"rate":`), &options); err == nil {
		t.Fatal("malformed JSON Naabu option was accepted")
	}

	base := BuiltinNaabuProfile().Naabu
	for _, tc := range []struct {
		name string
		edit func(*NaabuOptions)
	}{
		{"scan type", func(o *NaabuOptions) { o.ScanType = "" }},
		{"rate", func(o *NaabuOptions) { o.Rate = 0 }},
		{"workers", func(o *NaabuOptions) { o.Workers = 0 }},
		{"retries", func(o *NaabuOptions) { o.Retries = -1 }},
		{"timeout", func(o *NaabuOptions) { o.TimeoutMS = 99 }},
		{"warmup", func(o *NaabuOptions) { o.WarmUpSeconds = -1 }},
		{"batch", func(o *NaabuOptions) { o.AddressBatchSize = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := base
			tc.edit(&value)
			if err := ValidateNaabuOptions(value); err == nil {
				t.Fatal("invalid Naabu option was accepted")
			}
		})
	}
}

func TestScannerProfilePreviewAndArgumentFailureBranches(t *testing.T) {
	// The built-in profiles exercise the empty-array preview branches. Add a
	// script without arguments to cover the no-script-args path as well.
	profile := BuiltinNaabuProfile()
	profile.NSEProfile = "banner"
	previews, err := RenderScannerProfilePreview(profile)
	if err != nil || len(previews) != 2 {
		t.Fatalf("built-in preview = %#v, %v", previews, err)
	}
	if strings.Contains(strings.Join(previews[0].Args, " "), "--script-args") {
		t.Fatal("empty NSE arguments produced script arguments")
	}

	valid := []struct {
		name string
		args []string
	}{
		{"empty", []string{""}},
		{"nul", []string{"--verbose\x00"}},
		{"shell", []string{"--verbose|id"}},
		{"environment", []string{"--verbose", "${PATH}"}},
		{"missing operand", []string{"--host-timeout"}},
		{"unsafe operand", []string{"--host-timeout", "nmap"}},
		{"flag operand", []string{"--min-rate", "0"}},
		{"duplicate placeholder", []string{PlaceholderAddress, PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput}},
		{"embedded placeholder", []string{"prefix" + PlaceholderAddress}},
		{"unapproved flag", []string{"--script"}},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateArgTemplate(tc.args, "nmap"); err == nil {
				t.Fatalf("unsafe template accepted: %#v", tc.args)
			}
		})
	}
	for _, flag := range []string{"--min-rate", "--max-rate", "--max-retries", "--min-hostgroup", "--max-hostgroup", "--min-parallelism", "--max-parallelism"} {
		if err := validateScannerFlagOperand("nmap", flag, "999999"); err == nil {
			t.Fatalf("invalid numeric operand accepted for %s", flag)
		}
	}
	if err := validateScannerFlagOperand("nmap", "--host-timeout", "bad"); err == nil {
		t.Fatal("invalid duration operand accepted")
	}
}
