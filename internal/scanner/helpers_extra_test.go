package scanner

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestScannerHelperFunctionsNormalizeAndBoundValues(t *testing.T) {
	job := config.Job{TCP: &config.Protocol{Ports: "22", Mode: "connect"}, UDP: &config.Protocol{Ports: "53"}}
	if protocol, ok := protocolForJob(job, "tcp"); !ok || protocol.Mode != "connect" {
		t.Fatalf("TCP protocol = %#v, %v", protocol, ok)
	}
	if protocol, ok := protocolForJob(job, "udp"); !ok || protocol.Ports != "53" {
		t.Fatalf("UDP protocol = %#v, %v", protocol, ok)
	}
	if _, ok := protocolForJob(job, "icmp"); ok {
		t.Fatal("unsupported protocol was accepted")
	}

	hosts := map[string]model.HostObservation{"2001:db8::2": {Address: "2001:db8::2"}, "198.51.100.2": {Address: "198.51.100.2"}}
	if mapped := mapHosts(hosts); len(mapped) != 2 {
		t.Fatalf("mapped hosts = %#v", mapped)
	}
	if normalizeAddress(" 2001:0db8:0:0:0:0:0:1 ") != "2001:db8::1" || normalizeAddress("name") != "name" {
		t.Fatal("address normalization failed")
	}
	if scanType("udp", config.Protocol{Mode: "syn"}) != "udp" || scanType("tcp", config.Protocol{Mode: "connect"}) != "tcp connect" || scanType("tcp", config.Protocol{Mode: "syn"}) != "tcp syn" {
		t.Fatal("scan type selection failed")
	}
	if timingArg("conservative") != "-T2" || timingArg("fast") != "-T4" || timingArg("balanced") != "-T3" {
		t.Fatal("timing profile selection failed")
	}
	if got := sanitizeStderr("  warning  "); got != "warning" {
		t.Fatalf("sanitized stderr = %q", got)
	}
	if got := sanitizeStderr(strings.Repeat("x", 501)); len([]rune(got)) != 501 || !strings.HasSuffix(got, "…") {
		t.Fatalf("long stderr = %q", got)
	}
	if got := trimProgressOutput(strings.Repeat("x", 241)); len([]rune(got)) != 241 || !strings.HasSuffix(got, "…") {
		t.Fatalf("long progress output = %q", got)
	}
	for _, test := range []struct {
		line string
		want float64
		ok   bool
	}{
		{"About 42.5% done", .425, true},
		{"about -5% done", 0, true},
		{"about 150% done", 1, true},
		{"no percentage", 0, false},
		{"about nope% done", 0, false},
	} {
		got, ok := parseNmapProgress(test.line)
		if ok != test.ok || got != test.want {
			t.Errorf("parseNmapProgress(%q) = %v,%v, want %v,%v", test.line, got, ok, test.want, test.ok)
		}
	}

	var received Progress
	reportProgress(func(value Progress) { received = value }, Progress{Phase: "test"})
	if received.Phase != "test" {
		t.Fatal("progress callback was not invoked")
	}
	reportProgress(nil, Progress{Phase: "ignored"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(waitErrWithContext(ctx, errors.New("wait")), context.Canceled) {
		t.Fatal("context cancellation was not preferred")
	}
	if waitErrWithContext(context.Background(), errors.New("wait")).Error() != "wait" {
		t.Fatal("wait error was not preserved")
	}

	first, second := NewID(timeForScannerTest()), NewID(timeForScannerTest())
	if len(first) != 24 || len(second) != 24 || first == second {
		t.Fatalf("generated IDs = %q and %q", first, second)
	}
	if !net.ParseIP(normalizeAddress("192.0.2.1")).Equal(net.ParseIP("192.0.2.1")) || !reflect.DeepEqual(valueProtocol(job.TCP), *job.TCP) {
		t.Fatal("scanner helper normalization mismatch")
	}
}

func TestStateSummaryAggregation(t *testing.T) {
	var observation model.ProtocolObservation
	addStateSummary(&observation, "closed", "conn-refused", 2)
	addStateSummary(&observation, "closed", "conn-refused", 3)
	addStateSummary(&observation, "closed", "timeout", 1)
	addStateSummary(&observation, "filtered", "no-response", 1)
	addStateSummary(&observation, "ignored", "", 0)
	if len(observation.StateSummaries) != 2 || observation.StateSummaries[0].Count != 6 || len(observation.StateSummaries[0].Reasons) != 2 || observation.StateSummaries[0].Reasons[0].Count != 5 {
		t.Fatalf("state summaries = %#v", observation.StateSummaries)
	}
}

func timeForScannerTest() time.Time {
	return time.Unix(100, 0).UTC()
}
