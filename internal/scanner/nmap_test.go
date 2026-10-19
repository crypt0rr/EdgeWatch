package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

const sampleXML = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.7" extrainfo="Ubuntu" method="probed"><cpe>cpe:/a:openbsd:openssh:9.7</cpe></service></port><port protocol="tcp" portid="23"><state state="closed"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
const sampleXMLSinglePort = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.7" extrainfo="Ubuntu" method="probed"><cpe>cpe:/a:openbsd:openssh:9.7</cpe></service></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`

var nmapPortParseBenchmarkSink int64

func BenchmarkNmapPortScopeExpansionAcrossBatches(b *testing.B) {
	const expression = "1-65535"
	const batchCount = 16 // representative multi-address scan split into 16-host batches
	b.Run("once_per_scan", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ports, err := config.ParsePorts(expression)
			if err != nil {
				b.Fatal(err)
			}
			nmapPortParseBenchmarkSink = int64(batchCount * 16 * len(ports))
		}
	})
	b.Run("once_per_batch_regression", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var total int64
			for batch := 0; batch < batchCount; batch++ {
				ports, err := config.ParsePorts(expression)
				if err != nil {
					b.Fatal(err)
				}
				total += int64(16 * len(ports))
			}
			nmapPortParseBenchmarkSink = total
		}
	})
}

func TestWeightedProcessPercentClampsAndWeightsInvocations(t *testing.T) {
	cases := []struct {
		completed, total int64
		fraction         float64
		want             int
	}{
		{completed: 0, total: 0, fraction: 0.5, want: 0},
		{completed: 0, total: 4, fraction: -1, want: 0},
		{completed: 0, total: 4, fraction: 0.5, want: 12},
		{completed: 3, total: 4, fraction: 2, want: 100},
		{completed: 4, total: 4, fraction: 0, want: 100},
		{completed: -1, total: 4, fraction: 0.5, want: 12},
	}
	for _, test := range cases {
		if got := weightedProcessPercent(test.completed, test.total, test.fraction); got != test.want {
			t.Errorf("weightedProcessPercent(%d, %d, %v) = %d, want %d", test.completed, test.total, test.fraction, got, test.want)
		}
	}
	if got := weightedProcessPercent(1, 2, math.NaN()); got != 0 {
		t.Fatalf("weightedProcessPercent NaN = %d, want 0", got)
	}
}

func TestNmapHostAndUnitCollectionHelpers(t *testing.T) {
	hosts := map[string]model.HostObservation{
		"192.0.2.2": {Address: "192.0.2.2", Status: "down"},
		"192.0.2.1": {Address: "192.0.2.1", Status: "unreachable"},
		"192.0.2.3": {Address: "192.0.2.3", Status: "up"},
		"192.0.2.4": {Address: "192.0.2.2", Status: "timeout"},
		"192.0.2.5": {Address: "192.0.2.5", Status: "timedout"},
		"192.0.2.6": {Address: "192.0.2.6", Status: "timed-out"},
	}
	if got := incompleteHostAddresses(model.Snapshot{Hosts: mapsToHosts(hosts)}); !reflect.DeepEqual(got, []string{"192.0.2.1", "192.0.2.2", "192.0.2.5", "192.0.2.6"}) {
		t.Fatalf("incomplete host addresses = %#v", got)
	}
	if got := unreachableAddresses(hosts); !reflect.DeepEqual(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("unreachable addresses = %#v", got)
	}
	if got := dedupeStrings([]string{"a", "a", "b", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("deduped strings = %#v", got)
	}
	if dedupeStrings(nil) != nil || !reflect.DeepEqual(dedupeStrings([]string{"only"}), []string{"only"}) {
		t.Fatal("short dedupe inputs changed unexpectedly")
	}
	units := unitsFromMap(map[string]model.Unit{
		"z": {Target: "z", Protocol: "udp"},
		"a": {Target: "a", Protocol: "tcp"},
		"b": {Target: "a", Protocol: "udp"},
	})
	if len(units) != 3 || units[0].Target != "a" || units[0].Protocol != "tcp" || units[1].Protocol != "udp" {
		t.Fatalf("sorted units = %#v", units)
	}
	// The compatibility wrappers remain callable by integrations that do not
	// need detailed host evidence; an empty batch is a safe no-op.
	n := New("missing-nmap")
	if units, err := n.scanProtocolBatch(context.Background(), nil, "tcp", config.Protocol{Ports: "1", Mode: "connect"}, "balanced", true); err != nil || units != nil {
		t.Fatalf("empty compatibility batch = %#v, %v", units, err)
	}
}

func TestParseXML(t *testing.T) {
	r, err := parseXML([]byte(sampleXML), "tcp", true)
	if err != nil {
		t.Fatal(err)
	}
	p := r.Units["192.0.2.1"].Ports
	if len(p) != 1 || p[0].Port != 22 || p[0].Service == "" {
		t.Fatalf("unexpected ports %#v", p)
	}
}

func TestParseXMLCapturesHostEvidenceAndSummaries(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up" reason="arp-response" reason_ttl="64"/><address addr="198.51.100.10" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example Vendor"/><hostnames><hostname name="edge.example" type="user"/></hostnames><hostscript><script id="smb-os-discovery" output="OS: Example&#10;Computer name: edge"/></hostscript><times srtt="2500"/><ports><extraports state="closed" count="2"><extrareasons reason="conn-refused" count="2"/></extraports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="https" product="Example" version="1.2" extrainfo="TLS" method="probed" conf="9" tunnel="ssl" ostype="Linux" devicetype="general purpose"><cpe>cpe:/a:example:server:1.2</cpe></service></port><port protocol="tcp" portid="8443"><state state="open|filtered" reason="no-response"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	run, err := parseXMLWithConfig(data, "tcp", config.Protocol{Ports: "1-1000,8443", Mode: "syn", ServiceDetection: true})
	if err != nil {
		t.Fatal(err)
	}
	host := run.Hosts["198.51.100.10"]
	if host.StatusReason != "arp-response" || host.ReasonTTL != 64 || host.LatencyMS != 2.5 || host.Hostnames[0].Name != "edge.example" {
		t.Fatalf("host evidence missing: %#v", host)
	}
	if len(host.LinkAddresses) != 1 || host.LinkAddresses[0].Vendor != "Example Vendor" {
		t.Fatalf("link evidence missing: %#v", host.LinkAddresses)
	}
	protocol := host.Protocols[0]
	if protocol.ScannedPortCount != 1001 || len(protocol.Ports) != 2 || protocol.Ports[0].Reason != "syn-ack" || protocol.Ports[0].Service == nil || protocol.Ports[0].Service.Confidence != 9 {
		t.Fatalf("protocol evidence missing: %#v", protocol)
	}
	if len(protocol.StateSummaries) != 3 || protocol.StateSummaries[0].State != "closed" || protocol.StateSummaries[0].Reasons[0].Reason != "conn-refused" {
		t.Fatalf("state summaries missing: %#v", protocol.StateSummaries)
	}
	if len(protocol.NSEOutput) != 1 || protocol.NSEOutput[0] != "smb-os-discovery: OS: Example Computer name: edge" {
		t.Fatalf("host NSE evidence missing: %#v", protocol.NSEOutput)
	}
}

func TestParseXMLBoundsTargetControlledMetadata(t *testing.T) {
	huge := strings.Repeat("x", maxScannerMetadataBytes*4)
	var data strings.Builder
	data.WriteString(`<?xml version="1.0"?><nmaprun><host><status state="up" reason="`)
	data.WriteString(huge)
	data.WriteString(`"/><address addr="198.51.100.20" addrtype="ipv4"/>`)
	data.WriteString(`<hostnames>`)
	for i := 0; i < maxNmapHostnamesPerHost; i++ {
		fmt.Fprintf(&data, `<hostname name="%s-%d" type="%s"/>`, huge, i, huge)
	}
	data.WriteString(`</hostnames><address addr="`)
	data.WriteString(huge)
	data.WriteString(`" addrtype="mac" vendor="`)
	data.WriteString(huge)
	data.WriteString(`"/>`)
	for i := 0; i < maxNmapAddressesPerHost-2; i++ {
		fmt.Fprintf(&data, `<address addr="02:00:00:%02X:%02X:%02X" addrtype="mac" vendor="Example"/>`, i>>16, i>>8, i)
	}
	data.WriteString(`<ports><port protocol="tcp" portid="443"><state state="open" reason="`)
	data.WriteString(huge)
	data.WriteString(`"/><service name="`)
	data.WriteString(huge)
	data.WriteString(`" product="`)
	data.WriteString(huge)
	data.WriteString(`" version="`)
	data.WriteString(huge)
	data.WriteString(`" extrainfo="`)
	data.WriteString(huge)
	data.WriteString(`" method="probed" tunnel="`)
	data.WriteString(huge)
	data.WriteString(`" ostype="`)
	data.WriteString(huge)
	data.WriteString(`" devicetype="`)
	data.WriteString(huge)
	data.WriteString(`" conf="9">`)
	for i := 0; i < maxNmapCPEsPerService; i++ {
		fmt.Fprintf(&data, `<cpe>cpe:/a:example:%d:`, i)
		data.WriteString(huge)
		data.WriteString(`</cpe>`)
	}
	data.WriteString(`</service></port></ports><hostscript>`)
	for i := 0; i < maxScannerNSEOutputs+maxNmapMetadataRecordSlack; i++ {
		fmt.Fprintf(&data, `<script id="script-%d-`, i)
		data.WriteString(huge)
		data.WriteString(`" output="`)
		data.WriteString(huge)
		data.WriteString(`"/>`)
	}
	data.WriteString(`</hostscript></host><runstats><finished exit="success"/></runstats></nmaprun>`)

	run, err := parseXMLWithConfig([]byte(data.String()), "tcp", config.Protocol{Ports: "443", Mode: "connect", ServiceDetection: true})
	if err != nil {
		t.Fatal(err)
	}
	host := run.Hosts["198.51.100.20"]
	if len(host.Hostnames) > maxScannerHostnames || len(host.LinkAddresses) > maxScannerLinkAddresses || len(host.Hostnames) == 0 || len(host.LinkAddresses) == 0 {
		t.Fatalf("bounded host metadata counts = hostnames %d, links %d", len(host.Hostnames), len(host.LinkAddresses))
	}
	if len(host.StatusReason) > maxScannerMetadataBytes {
		t.Fatalf("host reason length = %d", len(host.StatusReason))
	}
	for _, hostname := range host.Hostnames {
		if len(hostname.Name) > maxScannerMetadataBytes || len(hostname.Type) > maxScannerMetadataBytes {
			t.Fatalf("hostname metadata escaped bound: %#v", hostname)
		}
	}
	for _, link := range host.LinkAddresses {
		if len(link.Address) > maxScannerMetadataBytes || len(link.Type) > maxScannerMetadataBytes || len(link.Vendor) > maxScannerMetadataBytes {
			t.Fatalf("link metadata escaped bound: %#v", link)
		}
	}
	if len(run.Units["198.51.100.20"].Ports) != 1 || len(run.Units["198.51.100.20"].Ports[0].Service) > maxScannerMetadataBytes {
		t.Fatalf("compact service fingerprint was not bounded: %#v", run.Units["198.51.100.20"].Ports)
	}
	protocol := host.Protocols[0]
	if len(protocol.NSEOutput) != maxScannerNSEOutputs {
		t.Fatalf("NSE output count = %d, want %d after raw slack", len(protocol.NSEOutput), maxScannerNSEOutputs)
	}
	for _, output := range protocol.NSEOutput {
		if len(output) > maxScannerMetadataBytes {
			t.Fatalf("NSE output length = %d", len(output))
		}
	}
	if len(protocol.Ports) != 1 || protocol.Ports[0].Service == nil {
		t.Fatalf("service evidence missing: %#v", protocol.Ports)
	}
	service := protocol.Ports[0].Service
	for _, value := range []string{service.Name, service.Product, service.Version, service.ExtraInfo, service.Method, service.Tunnel, service.OSType, service.DeviceType, protocol.Ports[0].Reason} {
		if len(value) > maxScannerMetadataBytes {
			t.Fatalf("service or port metadata length = %d", len(value))
		}
	}
	if len(service.CPEs) != maxScannerCPEs {
		t.Fatalf("CPE count = %d, want %d after raw slack", len(service.CPEs), maxScannerCPEs)
	}
	for _, cpe := range service.CPEs {
		if len(cpe) > maxScannerMetadataBytes {
			t.Fatalf("CPE length = %d", len(cpe))
		}
	}
	for _, summary := range protocol.StateSummaries {
		if len(summary.State) > maxScannerMetadataBytes || len(summary.Reasons) > maxScannerStateReasons {
			t.Fatalf("state summary escaped bounds: %#v", summary)
		}
		for _, reason := range summary.Reasons {
			if len(reason.Reason) > maxScannerMetadataBytes {
				t.Fatalf("state reason length = %d", len(reason.Reason))
			}
		}
	}
}

func TestParseXMLPreflightBoundsExpandedPortAllocation(t *testing.T) {
	data, portRecords := func() ([]byte, int) {
		const prefix = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports>`
		const suffix = `</ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
		portRecords := nmapPortRecordLimit(65535) + 1
		portXML := strings.Repeat(`<port protocol="tcp" portid="1"/>`, portRecords)
		commentBytes := maxNmapOutput - len(prefix) - len(portXML) - len(suffix) - len(`<!---->`)
		if commentBytes < 0 {
			t.Fatal("port fixture exceeds the existing XML byte limit")
		}
		var input strings.Builder
		input.Grow(maxNmapOutput)
		input.WriteString(prefix)
		input.WriteString(portXML)
		input.WriteString("<!--")
		input.WriteString(strings.Repeat("x", commentBytes))
		input.WriteString("-->")
		input.WriteString(suffix)
		data := []byte(input.String())
		if len(data) != maxNmapOutput {
			t.Fatalf("oversized fixture length = %d, want %d", len(data), maxNmapOutput)
		}
		return data, portRecords
	}()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	stats := nmapXMLParseStats{}
	_, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "1-65535"}, []string{"192.0.2.1"}, 65535, &stats)
	if err == nil || !strings.Contains(err.Error(), "port-record safety limit") {
		t.Fatalf("oversized port list error = %v, want bounded port-record failure", err)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 64<<20 {
		t.Fatalf("preflight allocated %d bytes for a %d-byte XML result; want under 64 MiB", allocated, len(data))
	}
	if stats.PortElements != portRecords || stats.MaterializedHosts != 0 || stats.MaterializedPortElements != 0 {
		t.Fatalf("preflight object counts = %#v; exceeded port records must fail before host materialization", stats)
	}
}

func TestParseXMLBoundsLargeNSEAndCPETextBeforeRetention(t *testing.T) {
	const scriptCount = 8
	data := func() []byte {
		const cpeCount = maxNmapCPEsPerService
		const scriptBytes = 256 << 10
		const cpeBytes = 320 << 10
		scriptOutput := strings.Repeat("s", scriptBytes)
		cpeValue := strings.Repeat("c", cpeBytes)
		var input strings.Builder
		input.Grow(15 << 20)
		input.WriteString(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><hostscript>`)
		for i := 0; i < scriptCount; i++ {
			input.WriteString(`<script id="script-`)
			fmt.Fprint(&input, i)
			input.WriteString(`" output="`)
			input.WriteString(scriptOutput)
			input.WriteString(`"/>`)
		}
		input.WriteString(`</hostscript><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" method="probed">`)
		for i := 0; i < cpeCount; i++ {
			input.WriteString(`<cpe>cpe:`)
			fmt.Fprintf(&input, "%02d:", i)
			input.WriteString(cpeValue)
			input.WriteString(`</cpe>`)
		}
		input.WriteString(`</service></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
		return []byte(input.String())
	}()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	stats := nmapXMLParseStats{}
	parsed, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443", ServiceDetection: true}, []string{"192.0.2.1"}, 1, &stats)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 128<<20 {
		t.Fatalf("bounded text parse allocated %d bytes for a %d-byte XML result", allocated, len(data))
	}
	protocol := parsed.Hosts["192.0.2.1"].Protocols[0]
	service := protocol.Ports[0].Service
	if stats.MaterializedHosts != 1 || stats.MaterializedPortElements != 1 || stats.MaterializedScriptElements != scriptCount || len(protocol.NSEOutput) != scriptCount || service == nil || len(service.CPEs) != maxScannerCPEs {
		t.Fatalf("selected metadata materialization = stats %#v, protocol %#v", stats, protocol)
	}
	for _, output := range protocol.NSEOutput {
		if len(output) > maxScannerMetadataBytes {
			t.Fatalf("NSE output escaped the existing truncation bound: %d bytes", len(output))
		}
	}
	for _, cpe := range service.CPEs {
		if len(cpe) > maxScannerMetadataBytes {
			t.Fatalf("CPE escaped the existing truncation bound: %d bytes", len(cpe))
		}
	}
}

type cancelAfterNmapTokens struct {
	context.Context
	stats *nmapXMLParseStats
	after int
}

func (ctx cancelAfterNmapTokens) Err() error {
	if ctx.stats.Tokens >= ctx.after {
		return context.Canceled
	}
	return ctx.Context.Err()
}

func TestParseXMLPreflightSkipsForeignHostsAndChecksCancellation(t *testing.T) {
	const selected = "192.0.2.1"
	var data strings.Builder
	data.WriteString(`<?xml version="1.0"?><nmaprun>`)
	for i := 0; i < 2_000; i++ {
		fmt.Fprintf(&data, `<host><status state="up"/><address addr="198.51.%d.%d" addrtype="ipv4"/><trace><hop ttl="1"/></trace><hostscript><script id="ignored-%d" output="foreign"/></hostscript></host>`, i/250, i%250+1, i)
	}
	data.WriteString(`<host><status state="up"/><address addr="` + selected + `" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports><hostscript><script id="selected-a" output="evidence"/><script id="selected-b" output="evidence"/></hostscript></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	stats := nmapXMLParseStats{}
	run, err := parseXMLWithPortCount(context.Background(), []byte(data.String()), "tcp", config.Protocol{Ports: "1-65535"}, []string{selected}, 65535, &stats)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Hosts) != 1 || run.Hosts[selected].Address != selected {
		t.Fatalf("materialized host set = %#v", run.Hosts)
	}
	if stats.HostElements != 2_001 || stats.SelectedHostSpans != 1 || stats.MaterializedHosts != 1 || stats.MaterializedPortElements != 1 || stats.SelectedScriptElements != 2 || stats.MaterializedScriptElements != 2 || stats.RetainedScriptSummaries != 2 {
		t.Fatalf("foreign host materialization counts = %#v", stats)
	}

	foreign := `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="198.51.100.1" addrtype="ipv4"/><trace>`
	for i := 0; i < 100; i++ {
		foreign += `<hop ttl="1"/>`
	}
	foreign += `</trace></host><runstats><finished exit="success"/></runstats></nmaprun>`
	cancelStats := nmapXMLParseStats{}
	cancelCtx := cancelAfterNmapTokens{Context: context.Background(), stats: &cancelStats, after: 12}
	_, err = parseXMLWithPortCount(cancelCtx, []byte(foreign), "tcp", config.Protocol{Ports: "443"}, []string{selected}, 1, &cancelStats)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("foreign subtree cancellation error = %v, want context.Canceled", err)
	}
	if cancelStats.HostElements != 1 || cancelStats.MaterializedHosts != 0 || cancelStats.SelectedHostSpans != 0 || cancelStats.Tokens < cancelCtx.after {
		t.Fatalf("cancellation did not occur while streaming a skipped host: %#v", cancelStats)
	}
}

type cancelAfterSelectedHostIndex struct {
	context.Context
	stats *nmapXMLParseStats
}

func (ctx cancelAfterSelectedHostIndex) Err() error {
	if ctx.stats.SelectedHostSpans > 0 {
		return context.Canceled
	}
	return ctx.Context.Err()
}

func TestParseXMLChecksCancellationBeforeHostMaterialization(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	stats := nmapXMLParseStats{}
	ctx := cancelAfterSelectedHostIndex{Context: context.Background(), stats: &stats}
	_, err := parseXMLWithPortCount(ctx, data, "tcp", config.Protocol{Ports: "443"}, []string{"192.0.2.1"}, 1, &stats)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation after preflight = %v, want context.Canceled", err)
	}
	if stats.SelectedHostSpans != 1 || stats.MaterializedHosts != 0 || stats.MaterializedPortElements != 0 {
		t.Fatalf("host was materialized after cancellation: %#v", stats)
	}
}

func TestParseXMLStreamsNSERecordsIntoBoundedSummaries(t *testing.T) {
	const address = "192.0.2.1"
	const scriptCount = 50_000
	var scripts strings.Builder
	scripts.Grow(scriptCount * len(`<script id="s" output="x"/>`))
	for i := 0; i < scriptCount; i++ {
		fmt.Fprintf(&scripts, `<script id="s%d" output="x"/>`, i)
	}
	data := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="` + address + `" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/>` + scripts.String() + `</port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	scripts.Reset()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	stats := nmapXMLParseStats{}
	parsed, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443"}, []string{address}, 1, &stats)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 96<<20 {
		t.Fatalf("streamed %d NSE records allocated %d bytes for %d bytes of XML", scriptCount, allocated, len(data))
	}
	if stats.SelectedScriptElements != scriptCount || stats.MaterializedScriptElements != scriptCount || stats.RetainedScriptSummaries != maxScannerNSEOutputs {
		t.Fatalf("NSE stream/materialization counts = %#v", stats)
	}
	if got := parsed.Hosts[address].Protocols[0].NSEOutput; len(got) != maxScannerNSEOutputs {
		t.Fatalf("NSE output retained %d summaries, want %d", len(got), maxScannerNSEOutputs)
	}
}

type cancelAfterContextErrors struct {
	context.Context
	calls int
	after int
}

func (ctx *cancelAfterContextErrors) Err() error {
	ctx.calls++
	if ctx.calls >= ctx.after {
		return context.Canceled
	}
	return ctx.Context.Err()
}

func TestNSECompactionChecksCancellationWithinLongField(t *testing.T) {
	ctx := &cancelAfterContextErrors{Context: context.Background(), after: 4}
	_, err := summarizeNSEOutputContext(ctx, "", strings.Repeat(" ", 1<<20))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("long NSE field cancellation = %v, want context.Canceled", err)
	}
}

func TestContextAwareScannerHelpersRejectNilContextBeforeNoop(t *testing.T) {
	var nilContext context.Context
	if _, _, err := foldedPositivePortsContext(nilContext, nmapExtraPorts{}, "tcp"); err == nil {
		t.Fatal("folded port helper accepted a nil context for empty scope")
	}
	values := make([]string, maxScannerNSEOutputs)
	if _, err := appendNSESummaryContext(nilContext, values, "", ""); err == nil {
		t.Fatal("NSE summary helper accepted a nil context after reaching its output cap")
	}
}

func TestNmapXMLTextBoundedChecksCancellationWithinLongField(t *testing.T) {
	ctx := &cancelAfterContextErrors{Context: context.Background(), after: 3}
	decoder := xml.NewDecoder(strings.NewReader(`<cpe>` + strings.Repeat("c", 1<<20) + `</cpe>`))
	if _, err := decoder.Token(); err != nil {
		t.Fatal(err)
	}
	_, err := readNmapXMLTextBounded(ctx, decoder)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("long XML text cancellation = %v, want context.Canceled", err)
	}
}

func TestFoldedPositivePortsChecksCancellationDuringExpansion(t *testing.T) {
	ctx := &cancelAfterContextErrors{Context: context.Background(), after: 4}
	extra := nmapExtraPorts{
		State: "open|filtered",
		Count: 65535,
		Reasons: []nmapExtraReason{{
			Reason: "no-response", Count: 65535, Protocol: "tcp", Ports: "1-65535",
		}},
	}
	_, _, err := foldedPositivePortsContext(ctx, extra, "tcp")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("folded port expansion cancellation = %v, want context.Canceled", err)
	}
}

func TestFoldedPositivePortsValidatesBeforeReturningResults(t *testing.T) {
	valid := nmapExtraPorts{
		State: "open|filtered",
		Count: 3,
		Reasons: []nmapExtraReason{
			{Reason: "no-response", Count: 2, Protocol: "UDP", Ports: "53, 123"},
			{Reason: "admin-prohibited", Count: 1, Ports: "500"},
		},
	}
	want := []foldedPort{{port: 53, reason: "no-response"}, {port: 123, reason: "no-response"}, {port: 500, reason: "admin-prohibited"}}
	ports, ok := foldedPositivePorts(valid, "udp")
	if !ok || !reflect.DeepEqual(ports, want) {
		t.Fatalf("compatibility expansion = %#v, %t; want %#v, true", ports, ok, want)
	}
	contextPorts, contextOK, err := foldedPositivePortsContext(context.Background(), valid, "udp")
	if err != nil || !contextOK || !reflect.DeepEqual(contextPorts, ports) {
		t.Fatalf("context expansion = %#v, %t, %v; want %#v, true, nil", contextPorts, contextOK, err, ports)
	}

	invalid := []struct {
		name  string
		extra nmapExtraPorts
	}{
		{name: "no reasons", extra: nmapExtraPorts{Count: 1}},
		{name: "wrong protocol", extra: nmapExtraPorts{Count: 1, Reasons: []nmapExtraReason{{Count: 1, Protocol: "tcp", Ports: "53"}}}},
		{name: "duplicate across reasons", extra: nmapExtraPorts{Count: 2, Reasons: []nmapExtraReason{{Count: 1, Ports: "53"}, {Count: 1, Ports: "53"}}}},
		{name: "malformed port", extra: nmapExtraPorts{Count: 1, Reasons: []nmapExtraReason{{Count: 1, Ports: "not-a-port"}}}},
		{name: "out-of-domain port", extra: nmapExtraPorts{Count: 1, Reasons: []nmapExtraReason{{Count: 1, Ports: "65536"}}}},
		{name: "listed count differs", extra: nmapExtraPorts{Count: 2, Reasons: []nmapExtraReason{{Count: 2, Ports: "53"}}}},
		{name: "reason count exceeds folded count", extra: nmapExtraPorts{Count: 1, Reasons: []nmapExtraReason{{Count: 2, Ports: "53-54"}}}},
		{name: "port list exceeds reason count", extra: nmapExtraPorts{Count: 1, Reasons: []nmapExtraReason{{Count: 1, Ports: "53,54"}}}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			got, valid := foldedPositivePorts(test.extra, "udp")
			if valid || len(got) != 0 {
				t.Fatalf("invalid folded list returned partial results %#v, valid=%t", got, valid)
			}
		})
	}

	callbackErr := errors.New("stop folded-port consumer")
	emitted := 0
	complete, err := walkFoldedPositivePortsContext(context.Background(), valid, "udp", func(foldedPort) error {
		emitted++
		return callbackErr
	})
	if complete || !errors.Is(err, callbackErr) || emitted != 1 {
		t.Fatalf("callback failure = complete %t, err %v, emitted %d; want false, callback error, one record", complete, err, emitted)
	}
}

func TestNmapPortBitsetGuardsThePortDomain(t *testing.T) {
	var ports nmapPortBitset
	ports.add(-1)
	ports.add(65536)
	if ports.contains(-1) || ports.contains(65536) {
		t.Fatal("out-of-domain ports appeared in the bitset")
	}
	// The parser rejects port zero before it reaches this storage helper.
	ports.add(65535)
	ports.add(1)
	if !ports.contains(1) || !ports.contains(65535) || ports.contains(0) || ports.contains(2) {
		t.Fatal("bitset did not preserve valid port endpoints and leave unset values clear")
	}
}

func TestParseXMLPreservesStateReasonSlackAndOutputCap(t *testing.T) {
	const address = "192.0.2.1"
	var ports strings.Builder
	for i := 0; i < maxScannerStateReasons+maxNmapMetadataRecordSlack; i++ {
		fmt.Fprintf(&ports, `<port protocol="tcp" portid="%d"><state state="open" reason="reason-%02d"/></port>`, i+1, i)
	}
	data := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="` + address + `" addrtype="ipv4"/><ports>` + ports.String() + `</ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	parsed, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "1-100"}, []string{address}, 100, nil)
	if err != nil {
		t.Fatalf("the established eight-reason allowance was rejected: %v", err)
	}
	protocol := parsed.Hosts[address].Protocols[0]
	if len(protocol.StateSummaries) != 1 || protocol.StateSummaries[0].Count != maxScannerStateReasons+maxNmapMetadataRecordSlack || len(protocol.StateSummaries[0].Reasons) != maxScannerStateReasons {
		t.Fatalf("reason slack and stored output cap = %#v", protocol.StateSummaries)
	}
}

func TestParseXMLRejectsTokenOverflowBeforeHostMaterialization(t *testing.T) {
	const address = "192.0.2.1"
	const hopCount = maxNmapXMLTokens/2 + 10
	var input strings.Builder
	input.Grow(hopCount * len(`<hop/>`))
	input.WriteString(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="` + address + `" addrtype="ipv4"/><trace>`)
	for i := 0; i < hopCount; i++ {
		input.WriteString(`<hop/>`)
	}
	input.WriteString(`</trace></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	data := []byte(input.String())
	input.Reset()
	if len(data) >= maxNmapOutput {
		t.Fatalf("token-overflow fixture unexpectedly reached the XML byte cap: %d bytes", len(data))
	}
	stats := nmapXMLParseStats{}
	_, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443"}, []string{address}, 1, &stats)
	if err == nil || !strings.Contains(err.Error(), "token safety limit") {
		t.Fatalf("token-overflow error = %v", err)
	}
	if stats.Tokens != maxNmapXMLTokens+1 || stats.MaterializedHosts != 0 || stats.MaterializedPortElements != 0 {
		t.Fatalf("token overflow was not rejected before materialization: %#v", stats)
	}
}

func TestParseXMLRejectsExcessAttributesBeforeHostMaterialization(t *testing.T) {
	var attrs strings.Builder
	for i := 0; i <= maxNmapXMLAttributes; i++ {
		fmt.Fprintf(&attrs, ` a%d="x"`, i)
	}
	data := []byte(`<?xml version="1.0"?><nmaprun` + attrs.String() + `><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	stats := nmapXMLParseStats{}
	_, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443"}, []string{"192.0.2.1"}, 1, &stats)
	if err == nil || !strings.Contains(err.Error(), "attribute safety limit") {
		t.Fatalf("attribute count error = %v, want bounded attribute failure", err)
	}
	if stats.MaterializedHosts != 0 || stats.SelectedHostSpans != 0 {
		t.Fatalf("excess attributes reached host materialization: %#v", stats)
	}
}

func TestParseXMLAttributeGuardBoundsLargeAttributeListAllocation(t *testing.T) {
	const attributeCount = 200_000
	const rootPrefix = `<?xml version="1.0"?><nmaprun`
	const longAttributePrefix = ` a-long="`
	const documentSuffix = `"><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`
	var attrs strings.Builder
	for index := 0; index < attributeCount; index++ {
		fmt.Fprintf(&attrs, ` a%d=""`, index)
	}
	var input strings.Builder
	input.Grow(maxNmapOutput)
	input.WriteString(rootPrefix)
	input.WriteString(attrs.String())
	input.WriteString(longAttributePrefix)
	longValueBytes := maxNmapOutput - len(rootPrefix) - attrs.Len() - len(longAttributePrefix) - len(documentSuffix)
	if longValueBytes < 0 {
		t.Fatal("attribute fixture exceeds the Nmap XML byte limit")
	}
	input.WriteString(strings.Repeat("x", longValueBytes))
	input.WriteString(documentSuffix)
	data := []byte(input.String())
	input.Reset()
	attrs.Reset()
	if len(data) != maxNmapOutput {
		t.Fatalf("attribute fixture length = %d, want %d", len(data), maxNmapOutput)
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	stats := nmapXMLParseStats{}
	_, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443"}, []string{"192.0.2.1"}, 1, &stats)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "attribute safety limit") {
		t.Fatalf("attribute overflow error = %v, want bounded pre-token failure", err)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 2<<20 {
		t.Fatalf("attribute guard allocated %d bytes before rejecting %d raw attributes", allocated, attributeCount)
	}
	if stats.Tokens > 1 || stats.MaterializedHosts != 0 || stats.SelectedHostSpans != 0 {
		t.Fatalf("attribute-overflow document produced XML tokens or hosts: %#v", stats)
	}
	runtime.KeepAlive(data)
}

func TestParseXMLRejectsInternalSubsetBeforeLargeAttributeAllocation(t *testing.T) {
	const attributeCount = 200_000
	const prefix = `<!DOCTYPE nmaprun [><nmaprun`
	const attribute = ` a="x"`
	const suffix = `></nmaprun>`
	var input strings.Builder
	input.Grow(len(prefix) + attributeCount*len(attribute) + len(suffix))
	input.WriteString(prefix)
	for range attributeCount {
		input.WriteString(attribute)
	}
	input.WriteString(suffix)
	data := []byte(input.String())
	input.Reset()
	if len(data) >= maxNmapOutput {
		t.Fatalf("internal-subset fixture unexpectedly reached the XML byte cap: %d bytes", len(data))
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	stats := nmapXMLParseStats{}
	_, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443"}, []string{"192.0.2.1"}, 1, &stats)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if !errors.Is(err, errNmapXMLInternalSubset) {
		t.Fatalf("internal-subset error = %v, want early unsupported-subset rejection (allocated %d bytes)", err, allocated)
	}
	if allocated > 2<<20 {
		t.Fatalf("internal-subset rejection allocated %d bytes for %d attributes", allocated, attributeCount)
	}
	if stats.Tokens != 0 || stats.MaterializedHosts != 0 || stats.SelectedHostSpans != 0 {
		t.Fatalf("internal-subset input reached XML tokenization/materialization: %#v", stats)
	}
	runtime.KeepAlive(data)
}

func TestNmapXMLDeclarationGuardIgnoresBracketDecoys(t *testing.T) {
	input := `<!DOCTYPE nmaprun SYSTEM "urn:example:[quoted]"><nmaprun a="ok"/>`
	guard := newNmapXMLAttributeLimitReader(context.Background(), strings.NewReader(input))
	got, err := io.ReadAll(guard)
	if err != nil {
		t.Fatalf("declaration decoy brackets were rejected: %v", err)
	}
	if string(got) != input {
		t.Fatalf("guard changed declaration bytes: %q", got)
	}
	if guard.attributeCount != 1 || guard.state != nmapXMLLexText {
		t.Fatalf("guard state after declaration and root tag = count %d, state %d; want count 1 and text", guard.attributeCount, guard.state)
	}
}

func TestParseXMLRejectsNestedDirectiveBeforeLargeAttributeAllocation(t *testing.T) {
	const attributeCount = 200_000
	const prefix = `<!DOCTYPE nmaprun <a>'<z q="'>`
	const attribute = ` a="x"`
	var input strings.Builder
	input.Grow(len(prefix) + attributeCount*len(attribute) + len(`><nmaprun/>`))
	input.WriteString(prefix)
	for range attributeCount {
		input.WriteString(attribute)
	}
	input.WriteString(`><nmaprun/>`)
	data := []byte(input.String())
	input.Reset()
	if len(data) >= maxNmapOutput {
		t.Fatalf("nested-directive fixture unexpectedly reached the XML byte cap: %d bytes", len(data))
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	stats := nmapXMLParseStats{}
	_, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443"}, []string{"192.0.2.1"}, 1, &stats)
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if !errors.Is(err, errNmapXMLInternalSubset) && !errors.Is(err, errNmapXMLAttributeLimit) {
		t.Fatalf("nested-directive error = %v, want early declaration or attribute rejection (allocated %d bytes)", err, allocated)
	}
	if allocated >= 2<<20 {
		t.Fatalf("nested-directive rejection allocated %d bytes for %d attributes", allocated, attributeCount)
	}
	if stats.Tokens != 0 {
		t.Fatalf("nested directive produced %d XML tokens before rejection", stats.Tokens)
	}
	runtime.KeepAlive(data)
}

func FuzzNmapXMLAttributeGuardMatchesRawToken(f *testing.F) {
	for _, seed := range []string{
		`<!DOCTYPE nmaprun><nmaprun a="x"/>`,
		`<nmaprun><!-- <fake a="x"> --><host/>`,
		`<!DOCTYPE nmaprun <nested>><nmaprun a="x"/>`,
		`<nmaprun a="unterminated`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		raw := []byte(input)
		guard := newNmapXMLAttributeLimitReader(context.Background(), bytes.NewReader(raw))
		guarded, guardErr := io.ReadAll(guard)
		if guardErr != nil {
			return // Unsupported or over-limit markup is intentionally rejected.
		}
		if !bytes.Equal(raw, guarded) {
			t.Fatal("attribute guard changed XML bytes")
		}
		readTokens := func(data []byte) ([]xml.Token, error) {
			decoder := xml.NewDecoder(bytes.NewReader(data))
			var tokens []xml.Token
			for {
				token, err := decoder.RawToken()
				if err != nil {
					return tokens, err
				}
				tokens = append(tokens, token)
			}
		}
		originalTokens, originalErr := readTokens(raw)
		guardedTokens, guardedErr := readTokens(guarded)
		if !reflect.DeepEqual(originalTokens, guardedTokens) || fmt.Sprint(originalErr) != fmt.Sprint(guardedErr) {
			t.Fatalf("guarded RawToken stream differs: original (%d, %v), guarded (%d, %v)", len(originalTokens), originalErr, len(guardedTokens), guardedErr)
		}
	})
}

func TestNmapXMLDeclarationGuardRejectsMalformedBangSubset(t *testing.T) {
	guard := newNmapXMLAttributeLimitReader(context.Background(), strings.NewReader(`<![conditional`))
	_, err := io.ReadAll(guard)
	if !errors.Is(err, errNmapXMLInternalSubset) {
		t.Fatalf("malformed declaration subset error = %v, want %v", err, errNmapXMLInternalSubset)
	}
}

type nmapXMLChunkReader struct {
	reader *bytes.Reader
	chunk  int
}

func (reader nmapXMLChunkReader) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.chunk {
		buffer = buffer[:reader.chunk]
	}
	return reader.reader.Read(buffer)
}

func TestNmapXMLAttributeGuardStopsBeforeExcessAttributeAcrossReads(t *testing.T) {
	var decoyAttrs strings.Builder
	for index := 0; index <= maxNmapXMLAttributes; index++ {
		fmt.Fprintf(&decoyAttrs, ` a%d="x"`, index)
	}
	var input strings.Builder
	input.WriteString(`<?xml version="1.0"?><?probe <ignored` + decoyAttrs.String() + `?><!DOCTYPE nmaprun><nmaprun`)
	for index := 0; index <= maxNmapXMLAttributes; index++ {
		fmt.Fprintf(&input, ` a%d="x"`, index)
	}
	input.WriteString(`></nmaprun>`)
	data := []byte(input.String())
	actualTag := strings.LastIndex(string(data), `<nmaprun`)
	guard := newNmapXMLAttributeLimitReader(context.Background(), nmapXMLChunkReader{reader: bytes.NewReader(data), chunk: 3})
	buffer := make([]byte, 3)
	var exposed []byte
	for {
		count, err := guard.Read(buffer)
		exposed = append(exposed, buffer[:count]...)
		if errors.Is(err, errNmapXMLAttributeLimit) {
			break
		}
		if err != nil {
			t.Fatalf("attribute guard read failed before the limit: %v", err)
		}
		if count == 0 {
			t.Fatal("attribute guard made no progress before the limit")
		}
	}
	firstExcessName := actualTag + strings.Index(string(data[actualTag:]), fmt.Sprintf("a%d=", maxNmapXMLAttributes))
	if firstExcessName < 0 || len(exposed) != firstExcessName {
		t.Fatalf("guard exposed %d bytes before rejecting attr %d at byte %d (actual tag offset %d)", len(exposed), maxNmapXMLAttributes+1, firstExcessName, actualTag)
	}
}

func TestParseXMLAttributeGuardSkipsNonTagMarkupAndQuotedValues(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><?probe <ignored a="1" b="2"?><!-- <ignored a="1" b="2"> --><!DOCTYPE nmaprun><nmaprun scanner="nmap" args="nmap -oX - 192.0.2.1" start="0" version="7.99" xmloutputversion="1.05"><scaninfo type="connect" protocol="tcp" numservices="1" services="443"/><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><trace><![CDATA[<ignored a="1" b="2">]]></trace></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	parsed, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443"}, []string{"192.0.2.1"}, 1, nil)
	if err != nil {
		t.Fatalf("valid Nmap DOCTYPE or markup decoy was rejected: %v", err)
	}
	if _, ok := parsed.Hosts["192.0.2.1"]; !ok {
		t.Fatalf("host after valid DTD and CDATA was not parsed: %#v", parsed.Hosts)
	}
}

func TestNmapXMLAttributeGuardStopsMalformedBareAttributesBeforeTokenization(t *testing.T) {
	var input strings.Builder
	input.WriteString(`<nmaprun`)
	for i := 0; i <= maxNmapXMLAttributes; i++ {
		fmt.Fprintf(&input, ` a%d`, i)
	}
	input.WriteString(`>`)
	data := []byte(input.String())
	guard := newNmapXMLAttributeLimitReader(context.Background(), bytes.NewReader(data))
	buffer := make([]byte, len(data))
	read, err := guard.Read(buffer)
	if !errors.Is(err, errNmapXMLAttributeLimit) || read >= len(data) {
		t.Fatalf("malformed bare attributes read %d/%d bytes with error %v, want bounded pre-token rejection", read, len(data), err)
	}
	read, repeatedErr := guard.Read(buffer)
	if read != 0 || !errors.Is(repeatedErr, errNmapXMLAttributeLimit) {
		t.Fatalf("repeat read after attribute limit = %d, %v; want 0 and the pending limit error", read, repeatedErr)
	}
	var nilContext context.Context
	zeroRead, zeroErr := newNmapXMLAttributeLimitReader(nilContext, bytes.NewReader(nil)).Read(nil)
	if zeroRead != 0 || zeroErr != nil {
		t.Fatalf("zero-length guard read = %d, %v; want 0, nil", zeroRead, zeroErr)
	}
	_, nilContextErr := newNmapXMLAttributeLimitReader(nilContext, bytes.NewReader(nil)).Read(buffer)
	if nilContextErr == nil {
		t.Fatal("attribute guard accepted a nil context for a nonempty read")
	}
}

func TestParseXMLRejectsMalformedSelectedRecordsWithoutReturningSnapshot(t *testing.T) {
	prefix := `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host><host>`
	suffix := `</host><runstats><finished exit="success"/></runstats></nmaprun>`
	cases := []struct {
		name                 string
		host                 string
		want                 string
		wantSelectedSpans    int
		wantMaterializedHost int
	}{
		{name: "port before address", host: `<status state="up"/><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports><address addr="192.0.2.1" addrtype="ipv4"/>`, want: "port records appeared before the host address"},
		{name: "missing port id", host: `<status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp"><state state="open"/></port></ports>`, want: "missing its port id"},
		{name: "invalid port id", host: `<status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="invalid"/></ports>`, want: "invalid nmap XML portid attribute"},
		{name: "out-of-range port id", host: `<status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="0"/></ports>`, want: "invalid port id 0"},
		{name: "missing folded count", host: `<status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><extraports state="closed"/></ports>`, want: "missing or negative extraports count"},
		{name: "negative folded count", host: `<status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><extraports state="closed" count="-1"/></ports>`, want: "missing or negative extraports count"},
		{name: "invalid state reason TTL", host: `<status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open" reason_ttl="bad"/></port></ports>`, want: "invalid nmap XML reason_ttl attribute"},
		{name: "invalid service confidence", host: `<status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service conf="unknown"/></port></ports>`, want: "invalid nmap XML conf attribute"},
		{name: "invalid host status reason TTL", host: `<status state="up" reason_ttl="bad"/><address addr="192.0.2.1" addrtype="ipv4"/>`, want: "invalid nmap XML reason_ttl attribute", wantSelectedSpans: 2, wantMaterializedHost: 1},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(prefix + test.host + suffix)
			stats := nmapXMLParseStats{}
			parsed, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "22"}, []string{"192.0.2.1", "192.0.2.2"}, 1, &stats)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("malformed Nmap result = %#v, %v; want error containing %q", parsed, err, test.want)
			}
			if parsed.Hosts != nil || parsed.Units != nil {
				t.Fatalf("malformed Nmap result returned a partial snapshot: %#v", parsed)
			}
			if stats.SelectedHostSpans != test.wantSelectedSpans || stats.MaterializedHosts != test.wantMaterializedHost {
				t.Fatalf("failed parse stats = %#v, want selected spans %d and materialized hosts %d", stats, test.wantSelectedSpans, test.wantMaterializedHost)
			}
		})
	}
}

func TestParseXMLRejectsUnexpectedDocumentElement(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><wrapper><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun></wrapper>`)
	_, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443"}, []string{"192.0.2.1"}, 1, nil)
	if err == nil || !strings.Contains(err.Error(), `unexpected document element "wrapper"`) {
		t.Fatalf("wrapped Nmap result error = %v, want fail-closed document-root error", err)
	}

	data = []byte(`<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/></runstats></nmaprun><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	_, err = parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443"}, []string{"192.0.2.1"}, 1, nil)
	if err == nil || !strings.Contains(err.Error(), "multiple document elements") {
		t.Fatalf("multiple Nmap roots error = %v, want fail-closed document structure error", err)
	}
}

func TestParseXMLCapsMaterializedHostsAtScannerBatchSize(t *testing.T) {
	var input strings.Builder
	input.WriteString(`<?xml version="1.0"?><nmaprun>`)
	for i := 1; i <= maxNmapXMLMaterializedHosts+1; i++ {
		fmt.Fprintf(&input, `<host><status state="up"/><address addr="198.51.100.%d" addrtype="ipv4"/></host>`, i)
	}
	input.WriteString(`<runstats><finished exit="success"/></runstats></nmaprun>`)
	stats := nmapXMLParseStats{}
	_, err := parseXMLWithPortCount(context.Background(), []byte(input.String()), "tcp", config.Protocol{Ports: "443"}, nil, 1, &stats)
	if err == nil || !strings.Contains(err.Error(), "materialized host safety limit") {
		t.Fatalf("materialized host count error = %v", err)
	}
	if stats.HostElements != maxNmapXMLMaterializedHosts || stats.MaterializedHosts != 0 {
		t.Fatalf("host batch limit was not enforced before materialization: %#v", stats)
	}
}

func TestParseXMLRejectsExcessRepeatedEvidenceBeforeMaterialization(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "service CPEs",
			body: func() string {
				var cpes strings.Builder
				for i := 0; i <= maxNmapCPEsPerService; i++ {
					cpes.WriteString(`<cpe>cpe:/a:example:service</cpe>`)
				}
				return `<ports><port protocol="tcp" portid="443"><state state="open"/><service method="table">` + cpes.String() + `</service></port></ports>`
			}(),
			want: "CPE safety limit",
		},
		{
			name: "state reasons",
			body: func() string {
				var ports strings.Builder
				for i := 0; i <= maxScannerStateReasons+maxNmapMetadataRecordSlack; i++ {
					fmt.Fprintf(&ports, `<port protocol="tcp" portid="%d"><state state="open" reason="r%d"/></port>`, i+1, i)
				}
				return `<ports>` + ports.String() + `</ports>`
			}(),
			want: "distinct reasons",
		},
		{
			name: "state summaries",
			body: func() string {
				var ports strings.Builder
				for i := 0; i < maxNmapStateSummaries; i++ {
					fmt.Fprintf(&ports, `<port protocol="tcp" portid="%d"><state state="custom-%d"/></port>`, i+1, i)
				}
				return `<ports>` + ports.String() + `</ports>`
			}(),
			want: "state-summary safety limit",
		},
		{
			name: "folded states",
			body: func() string {
				var states strings.Builder
				for i := 0; i <= maxNmapExtraPortsPerHost; i++ {
					fmt.Fprintf(&states, `<extraports state="closed" count="0" marker="%d"/>`, i)
				}
				return `<ports>` + states.String() + `</ports>`
			}(),
			want: "folded-state safety limit",
		},
		{
			name: "folded reasons",
			body: func() string {
				var reasons strings.Builder
				for i := 0; i <= maxNmapExtraReasonsPerRecord; i++ {
					fmt.Fprintf(&reasons, `<extrareasons reason="r%d" count="0"/>`, i)
				}
				return `<ports><extraports state="closed" count="0">` + reasons.String() + `</extraports></ports>`
			}(),
			want: "reason safety limit",
		},
		{
			name: "folded port list bytes",
			body: func() string {
				ports := strings.Repeat("1", maxNmapFoldedListBytes+1)
				return `<ports><extraports state="closed" count="0"><extrareasons reason="unknown" count="0" proto="tcp" ports="` + ports + `"/></extraports></ports>`
			}(),
			want: "folded port list exceeded",
		},
		{
			name: "hostnames",
			body: func() string {
				var names strings.Builder
				for i := 0; i <= maxNmapHostnamesPerHost; i++ {
					fmt.Fprintf(&names, `<hostname name="n%d" type="user"/>`, i)
				}
				return `<hostnames>` + names.String() + `</hostnames>`
			}(),
			want: "hostname safety limit",
		},
		{
			name: "addresses",
			body: func() string {
				var addresses strings.Builder
				for i := 0; i < maxNmapAddressesPerHost; i++ {
					fmt.Fprintf(&addresses, `<address addr="02:00:00:00:00:%02X" addrtype="mac"/>`, i)
				}
				return addresses.String()
			}(),
			want: "address safety limit",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>` + test.body + `</host><runstats><finished exit="success"/></runstats></nmaprun>`)
			stats := nmapXMLParseStats{}
			_, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "1-100"}, []string{"192.0.2.1"}, 100, &stats)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("safety error = %v, want substring %q", err, test.want)
			}
			if stats.MaterializedHosts != 0 || stats.MaterializedPortElements != 0 {
				t.Fatalf("unsafe records were materialized before rejection: %#v", stats)
			}
		})
	}
}

func TestNmapInvocationDeduplicatesSelectedAddressesBeforeParsing(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	invocations := filepath.Join(dir, "invocations")
	output := `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
	script := "#!/bin/sh\nxml_output=''\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-oX\" ]; then xml_output=\"$2\"; shift 2; else shift; fi\ndone\nprintf '%s' '" + output + "' > \"$xml_output\"\nprintf x >> '" + invocations + "'\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	targets := []resolvedTarget{
		{Name: "first.example", Addresses: []string{"192.0.2.1"}},
		{Name: "second.example", Addresses: []string{"192.0.2.1"}},
	}
	result, err := New(nmapPath).scanProtocolBatchDetailedProgress(context.Background(), targets, "tcp", config.Protocol{Ports: "443", Mode: "connect"}, "balanced", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(invocations)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || len(result.Units) != 1 || result.Units[0].Target != "192.0.2.1" {
		t.Fatalf("duplicate resolved address was not scanned once: calls=%q result=%#v", calls, result)
	}
}

func TestParseXMLDeduplicatesRepeatedPortsAndKeepsFullScope(t *testing.T) {
	const duplicateXML = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/></port><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
	duplicate, err := parseXMLWithPortCount(context.Background(), []byte(duplicateXML), "tcp", config.Protocol{Ports: "443"}, []string{"192.0.2.1", "192.0.2.1"}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	unit := duplicate.Units["192.0.2.1"]
	protocol := duplicate.Hosts["192.0.2.1"].Protocols[0]
	if len(unit.Ports) != 1 || len(protocol.Ports) != 1 || len(protocol.StateSummaries) != 1 || protocol.StateSummaries[0].Count != 1 {
		t.Fatalf("duplicate port result was not deduplicated: unit=%#v protocol=%#v", unit, protocol)
	}

	var full strings.Builder
	full.Grow(4 << 20)
	full.WriteString(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports>`)
	for port := 1; port <= 65535; port++ {
		fmt.Fprintf(&full, `<port protocol="tcp" portid="%d"><state state="closed"/></port>`, port)
	}
	for duplicate := 0; duplicate < nmapPortRecordLimit(65535)-65535; duplicate++ {
		full.WriteString(`<port protocol="tcp" portid="1"><state state="closed"/></port>`)
	}
	full.WriteString(`</ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	data := []byte(full.String())
	full = strings.Builder{}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	stats := nmapXMLParseStats{}
	wholeScope, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "1-65535"}, []string{"192.0.2.1"}, 65535, &stats)
	if err != nil {
		t.Fatalf("full 65,535-port response: %v", err)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	// TotalAlloc counts transient XML token allocations across both bounded
	// passes; a full-range scan legitimately visits tens of thousands of
	// records. The over-scope regression above caps allocation before
	// materialization. Here, the relevant bound is the retained output model.
	if after.HeapAlloc > before.HeapAlloc && after.HeapAlloc-before.HeapAlloc > 32<<20 {
		t.Fatalf("full-range parse retained %d bytes for %d port records", after.HeapAlloc-before.HeapAlloc, stats.MaterializedPortElements)
	}
	runtime.KeepAlive(data)
	if stats.MaterializedPortElements != nmapPortRecordLimit(65535) || wholeScope.Hosts["192.0.2.1"].Protocols[0].StateSummaries[0].Count != 65535 {
		t.Fatalf("full-scope output was truncated: stats=%#v summaries=%#v", stats, wholeScope.Hosts["192.0.2.1"].Protocols[0].StateSummaries)
	}
}

func foldedOpenFilteredHostXML(address string, count int) string {
	return fmt.Sprintf(`<host><status state="up"/><address addr="%s" addrtype="ipv4"/><ports><extraports state="open|filtered" count="%d"><extrareasons reason="no-response" count="%d" proto="tcp" ports="1-%d"/></extraports></ports></host>`, address, count, count, count)
}

func TestNmapXMLMaterializationBudgetCountsUniqueSelectedAddresses(t *testing.T) {
	const selected = "192.0.2.1"
	const fullRange = 65535
	selectedHost := foldedOpenFilteredHostXML(selected, fullRange)
	cases := []struct {
		name    string
		prefix  string
		suffix  string
		targets []string
		spans   int
	}{
		{
			name:    "sparse selected output only charges emitted address",
			prefix:  `<?xml version="1.0"?><nmaprun>` + selectedHost,
			suffix:  `<runstats><finished exit="success"/></runstats></nmaprun>`,
			targets: []string{selected, "192.0.2.2"},
			spans:   1,
		},
		{
			name:    "duplicate invocation target is one address slot",
			prefix:  `<?xml version="1.0"?><nmaprun>` + selectedHost,
			suffix:  `<runstats><finished exit="success"/></runstats></nmaprun>`,
			targets: []string{selected, selected},
			spans:   1,
		},
		{
			name:    "duplicate selected host record is decoded once",
			prefix:  `<?xml version="1.0"?><nmaprun>` + selectedHost,
			suffix:  selectedHost + `<runstats><finished exit="success"/></runstats></nmaprun>`,
			targets: []string{selected},
			spans:   1,
		},
		{
			name: "foreign hosts do not consume selected slots",
			prefix: func() string {
				var prefix strings.Builder
				prefix.WriteString(`<?xml version="1.0"?><nmaprun>`)
				for index := 0; index < 2000; index++ {
					fmt.Fprintf(&prefix, `<host><status state="up"/><address addr="198.51.%d.%d" addrtype="ipv4"/></host>`, index/254, index%254+1)
				}
				prefix.WriteString(selectedHost)
				return prefix.String()
			}(),
			suffix:  `<runstats><finished exit="success"/></runstats></nmaprun>`,
			targets: []string{selected},
			spans:   1,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(test.prefix + test.suffix)
			stats := nmapXMLParseStats{}
			parsed, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "1-65535"}, test.targets, fullRange, &stats)
			if err != nil {
				t.Fatalf("full-range selected result rejected: %v", err)
			}
			if stats.SelectedHostSpans != test.spans || stats.MaterializedHosts != test.spans {
				t.Fatalf("selected host spans/materialization = %d/%d, want %d: %#v", stats.SelectedHostSpans, stats.MaterializedHosts, test.spans, stats)
			}
			if got := len(parsed.Units[selected].Ports); got != fullRange {
				t.Fatalf("selected full-range positive ports = %d, want %d", got, fullRange)
			}
		})
	}
}

func TestNmapDuplicateRecordSlackDoesNotExpandPortScope(t *testing.T) {
	const address = "192.0.2.1"
	duplicateRecords := `<port protocol="tcp" portid="443"><state state="open"/></port>`
	var duplicates strings.Builder
	for i := 0; i < nmapPortRecordLimit(1); i++ {
		duplicates.WriteString(duplicateRecords)
	}
	accepted := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="` + address + `" addrtype="ipv4"/><ports>` + duplicates.String() + `</ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	stats := nmapXMLParseStats{}
	parsed, err := parseXMLWithPortCount(context.Background(), accepted, "tcp", config.Protocol{Ports: "443"}, []string{address}, 1, &stats)
	if err != nil {
		t.Fatalf("duplicate record slack response: %v", err)
	}
	if stats.MaterializedPortElements != nmapPortRecordLimit(1) || len(parsed.Units[address].Ports) != 1 || parsed.Hosts[address].Protocols[0].StateSummaries[0].Count != 1 {
		t.Fatalf("duplicate record slack changed the one-port scope: stats=%#v run=%#v", stats, parsed)
	}

	tooManyDistinct := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="` + address + `" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port><port protocol="tcp" portid="444"><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	if _, err := parseXMLWithPortCount(context.Background(), tooManyDistinct, "tcp", config.Protocol{Ports: "443"}, []string{address}, 1, nil); err == nil || !strings.Contains(err.Error(), "scan scope") {
		t.Fatalf("distinct ports beyond the configured scope = %v, want scan-scope error", err)
	}
}

func TestParseXMLPreservesNSESummaryTruncationAcrossMultipleScriptsPerPort(t *testing.T) {
	const address = "192.0.2.1"
	var scripts strings.Builder
	for script := 0; script < maxScannerNSEOutputs*3; script++ {
		fmt.Fprintf(&scripts, `<script id="script-%d" output="result-%d"/>`, script, script)
	}
	data := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="` + address + `" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/>` + scripts.String() + `</port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	stats := nmapXMLParseStats{}
	parsed, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443"}, []string{address}, 1, &stats)
	if err != nil {
		t.Fatalf("multiple NSE results for one scanned port: %v", err)
	}
	if got := parsed.Hosts[address].Protocols[0].NSEOutput; len(got) != maxScannerNSEOutputs {
		t.Fatalf("NSE summaries = %d, want the existing %d-item output cap", len(got), maxScannerNSEOutputs)
	}
	if stats.SelectedScriptElements != maxScannerNSEOutputs*3 || stats.MaterializedScriptElements != maxScannerNSEOutputs*3 || stats.RetainedScriptSummaries > maxScannerNSEOutputs {
		t.Fatalf("raw NSE stream and retained summaries = %#v", stats)
	}
}

func TestNSESummaryRetentionSkipsIgnoredPortRecords(t *testing.T) {
	const address = "192.0.2.1"
	data := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="` + address + `" addrtype="ipv4"/><ports>` +
		`<port protocol="udp" portid="443"><state state="open"/><script id="udp" output="ignored"/></port>` +
		`<port protocol="tcp" portid="443"><state state="closed"/><script id="closed" output="ignored"/></port>` +
		`<port protocol="tcp" portid="443"><state state="open"/><script id="duplicate" output="ignored"/></port>` +
		`<port protocol="tcp" portid="444"><state state="open"/><script id="kept" output="result"/></port>` +
		`</ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	parsed, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443,444"}, []string{address}, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Hosts[address].Protocols[0].NSEOutput; !reflect.DeepEqual(got, []string{"kept: result"}) {
		t.Fatalf("port NSE summaries included an ignored record or lost later evidence: %v", got)
	}
}

func TestParseXMLReservesTheCombinedNSESummaryCapForHostScripts(t *testing.T) {
	const address = "192.0.2.1"
	var portScripts strings.Builder
	for index := 0; index < maxScannerNSEOutputs; index++ {
		fmt.Fprintf(&portScripts, `<script id="port-%02d" output="result-%02d"/>`, index, index)
	}
	data := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="` + address + `" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/>` + portScripts.String() + `</port></ports><hostscript><script id="host-priority" output="preserve this summary"/></hostscript></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	parsed, err := parseXMLWithPortCount(context.Background(), data, "tcp", config.Protocol{Ports: "443"}, []string{address}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := parsed.Hosts[address].Protocols[0].NSEOutput
	if len(got) != maxScannerNSEOutputs {
		t.Fatalf("combined host and port NSE summaries = %d, want %d", len(got), maxScannerNSEOutputs)
	}
	if got[0] != "host-priority: preserve this summary" || got[len(got)-1] != "port-30: result-30" {
		t.Fatalf("NSE cap did not preserve host evidence before trimming one port summary: first=%q last=%q", got[0], got[len(got)-1])
	}
}

func TestAppendNSESummaryKeepsTheExistingOutputCap(t *testing.T) {
	values := make([]string, maxScannerNSEOutputs)
	for index := range values {
		values[index] = fmt.Sprintf("summary-%d", index)
	}
	want := slices.Clone(values)
	got, err := appendNSESummaryContext(context.Background(), values, "extra", "ignored after the summary cap")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("NSE output at cap = %#v, %v; want unchanged %#v", got, err, want)
	}
}

func TestBoundedScannerStringsKeepsSortedLimitWithBoundedAllocation(t *testing.T) {
	const inputCount = 100_000
	values := make([]string, inputCount)
	for index := range values {
		values[index] = fmt.Sprintf("cpe:%06d", inputCount-index)
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	bounded := boundedScannerStrings(values, maxScannerCPEs)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 1<<20 {
		t.Fatalf("bounded string selection allocated %d bytes for %d values", allocated, inputCount)
	}
	if len(bounded) != maxScannerCPEs || bounded[0] != "cpe:000001" || bounded[len(bounded)-1] != fmt.Sprintf("cpe:%06d", maxScannerCPEs) {
		t.Fatalf("sorted bounded CPE values = %v..%v (%d items)", bounded[0], bounded[len(bounded)-1], len(bounded))
	}
	runtime.KeepAlive(values)
	runtime.KeepAlive(bounded)
}

func TestMergeHostObservationKeepsIncompleteStatusRegardlessOfOrder(t *testing.T) {
	up := model.HostObservation{
		Address: "192.0.2.10", Status: "up", StatusReason: "arp-response",
		Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", ScannedPorts: "443"}},
	}
	omitted := model.HostObservation{
		Address: "192.0.2.10", Status: "unreachable", StatusReason: "nmap-omitted",
		Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "nmap-omitted", ScannedPorts: "443"}},
	}
	for _, test := range []struct {
		name          string
		first, second model.HostObservation
	}{
		{name: "up then omitted", first: up, second: omitted},
		{name: "omitted then up", first: omitted, second: up},
	} {
		t.Run(test.name, func(t *testing.T) {
			hosts := map[string]model.HostObservation{}
			mergeHostObservationMap(hosts, test.first.Address, test.first)
			mergeHostObservationMap(hosts, test.second.Address, test.second)
			got := hosts["192.0.2.10"]
			dedupeHostObservation(&got)
			if got.Status != "unreachable" || got.StatusReason != "nmap-omitted" {
				t.Fatalf("merged status = %q/%q, want unreachable/nmap-omitted", got.Status, got.StatusReason)
			}
			if len(got.Protocols) != 1 || got.Protocols[0].Status != "unreachable" || got.Protocols[0].StatusReason != "nmap-omitted" {
				t.Fatalf("merged TCP coverage = %#v, want sticky unreachable/nmap-omitted", got.Protocols)
			}
		})
	}
}

func TestMergeProtocolObservationKeepsNoResponseStickyRegardlessOfOrder(t *testing.T) {
	noResponse := model.HostObservation{
		Address: "192.0.2.12", Status: "unknown", StatusReason: "no-response",
		Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unknown", StatusReason: "no-response", ScannedPorts: "1-65535"}},
	}
	up := model.HostObservation{
		Address: "192.0.2.12", Status: "up", StatusReason: "syn-ack",
		Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", StatusReason: "syn-ack", ScannedPorts: "443"}},
	}
	for _, test := range []struct {
		name          string
		first, second model.HostObservation
	}{
		{name: "no-response then up", first: noResponse, second: up},
		{name: "up then no-response", first: up, second: noResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			hosts := map[string]model.HostObservation{}
			mergeHostObservationMap(hosts, test.first.Address, test.first)
			mergeHostObservationMap(hosts, test.second.Address, test.second)
			got := hosts["192.0.2.12"]
			dedupeHostObservation(&got)
			if len(got.Protocols) != 1 || got.Protocols[0].Status != "unknown" || got.Protocols[0].StatusReason != "no-response" {
				t.Fatalf("merged TCP coverage = %#v, want sticky unknown/no-response", got.Protocols)
			}
		})
	}
}

func TestMergeProtocolObservationAllowsCompletedNaabuCoverage(t *testing.T) {
	completed := model.HostObservation{
		Address: "192.0.2.13", Status: "unknown", StatusReason: "scan-complete",
		Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unknown", StatusReason: "scan-complete", ScannedPorts: "1-65535"}},
	}
	up := model.HostObservation{
		Address: "192.0.2.13", Status: "up", StatusReason: "syn-ack",
		Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", StatusReason: "syn-ack", ScannedPorts: "443"}},
	}
	hosts := map[string]model.HostObservation{}
	mergeHostObservationMap(hosts, completed.Address, completed)
	mergeHostObservationMap(hosts, up.Address, up)
	got := hosts[completed.Address]
	dedupeHostObservation(&got)
	if len(got.Protocols) != 1 || got.Protocols[0].Status != "up" || got.Protocols[0].StatusReason != "syn-ack" {
		t.Fatalf("completed Naabu coverage was not replaced by authoritative evidence: %#v", got.Protocols)
	}
}

func TestMergeHostObservationMarksAddressIncompleteAcrossProtocols(t *testing.T) {
	hosts := map[string]model.HostObservation{}
	mergeHostObservationMap(hosts, "192.0.2.11", model.HostObservation{
		Address: "192.0.2.11", Status: "up",
		Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", StatusReason: "syn-ack", ScannedPorts: "443"}},
	})
	mergeHostObservationMap(hosts, "192.0.2.11", model.HostObservation{
		Address: "192.0.2.11", Status: "unreachable", StatusReason: "nmap-host-timeout",
		Protocols: []model.ProtocolObservation{{Protocol: "udp", Status: "unreachable", StatusReason: "nmap-host-timeout", ScannedPorts: "53"}},
	})
	got := hosts["192.0.2.11"]
	dedupeHostObservation(&got)
	if got.Status != "unreachable" || got.StatusReason != "nmap-host-timeout" {
		t.Fatalf("cross-protocol status = %q/%q, want unreachable/nmap-host-timeout", got.Status, got.StatusReason)
	}
	if len(got.Protocols) != 2 {
		t.Fatalf("cross-protocol observations = %#v, want TCP and UDP", got.Protocols)
	}
	if got.Protocols[0].Protocol != "tcp" || got.Protocols[0].Status != "up" || got.Protocols[0].StatusReason != "syn-ack" {
		t.Fatalf("healthy TCP coverage was contaminated by UDP failure: %#v", got.Protocols[0])
	}
	if got.Protocols[1].Protocol != "udp" || got.Protocols[1].Status != "unreachable" || got.Protocols[1].StatusReason != "nmap-host-timeout" {
		t.Fatalf("UDP failure evidence was not retained: %#v", got.Protocols[1])
	}
}

func TestHostEvidenceDoesNotChangeSnapshotHash(t *testing.T) {
	base := model.Snapshot{Units: []model.Unit{{Target: "198.51.100.10", Protocol: "tcp", Addresses: []string{"198.51.100.10"}, Ports: []model.PortState{{Port: 443, State: "open"}}}}}
	withEvidence := base
	withEvidence.Hosts = []model.HostObservation{{Address: "198.51.100.10", StatusReason: "arp-response", LatencyMS: 1.2, Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "1-65535", Ports: []model.PortObservation{{Port: 443, State: "open", Reason: "syn-ack"}}}}}}
	if base.Hash() != withEvidence.Hash() {
		t.Fatal("host evidence changed the snapshot hash")
	}
}

func TestScanPreservesPerAddressEvidenceForDNS(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	output := `<?xml version="1.0"?><nmaprun><host><status state="up" reason="syn-ack"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/></port></ports></host><host><status state="up" reason="syn-ack"/><address addr="192.0.2.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open|filtered" reason="no-response"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s' '"+output+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	n.Resolver = fakeResolver{[]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}}
	job := config.NormalizeJob(config.Job{Name: "dns", Targets: []string{"edge.example"}, MaxExpandedHosts: 2, TCP: &config.Protocol{Ports: "22,443", Mode: "syn"}})
	snapshot, err := n.Scan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Hosts) != 2 || snapshot.Hosts[0].SourceTargets[0] != "edge.example" || snapshot.Hosts[0].DNSNames[0] != "edge.example" || snapshot.Hosts[0].Protocols[0].Ports[0].Port != 443 || snapshot.Hosts[1].Protocols[0].Ports[0].Port != 22 {
		t.Fatalf("unexpected DNS host evidence: %#v", snapshot.Hosts)
	}
	if len(snapshot.Units) != 1 || len(snapshot.Units[0].Ports) != 2 {
		t.Fatalf("unexpected DNS aggregate unit: %#v", snapshot.Units)
	}
}
func TestParseXMLRejectsMalformed(t *testing.T) {
	if _, err := parseXML([]byte("<nmaprun>"), "tcp", false); err == nil {
		t.Fatal("malformed XML accepted")
	}
}

func TestParseXMLRetainsTimedOutHost(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><nmaprun><host timedout="true"><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	run, err := parseXMLWithConfig(data, "tcp", config.Protocol{Ports: "443", Mode: "connect"})
	if err != nil {
		t.Fatalf("timed-out host discarded healthy evidence: %v", err)
	}
	host, ok := run.Hosts["192.0.2.10"]
	if !ok || host.Status != "unreachable" || host.StatusReason != "nmap-host-timeout" {
		t.Fatalf("timed-out host observation = %#v", host)
	}
	if len(host.Protocols) != 1 || host.Protocols[0].Status != "unreachable" || host.Protocols[0].StatusReason != "nmap-host-timeout" {
		t.Fatalf("timed-out protocol coverage = %#v, want unreachable/nmap-host-timeout", host.Protocols)
	}
}

type fakeResolver struct{ ips []net.IP }

func (f fakeResolver) LookupIP(context.Context, string, string) ([]net.IP, error) { return f.ips, nil }
func TestResolveHostnameAndCIDRLimit(t *testing.T) {
	n := New("nmap")
	n.Resolver = fakeResolver{[]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}}
	job := config.Job{Targets: []string{"Example.COM"}, MaxExpandedHosts: 2}
	got, err := n.resolve(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name != "example.com" || !reflect.DeepEqual(got[0].Addresses, []string{"192.0.2.1", "2001:db8::1"}) {
		t.Fatalf("unexpected %#v", got)
	}
	job = config.Job{Targets: []string{"192.0.2.0/30"}, MaxExpandedHosts: 3}
	if _, err := n.resolve(context.Background(), job); err == nil || !IsConfigurationError(err) {
		t.Fatalf("CIDR limit error = %v, want typed configuration failure", err)
	}
}

func TestResolveRejectsExcludedAddresses(t *testing.T) {
	n := New("nmap")
	if err := n.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"127.0.0.1", "169.254.169.254", "::1"} {
		if _, err := n.resolve(context.Background(), config.Job{Targets: []string{target}, MaxExpandedHosts: 4}); err == nil || !strings.Contains(err.Error(), "excluded") || !IsConfigurationError(err) {
			t.Fatalf("excluded target %q resolved without error: %v", target, err)
		}
	}
	n.Resolver = fakeResolver{[]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("127.0.0.1")}}
	if _, err := n.resolve(context.Background(), config.Job{Targets: []string{"edge.example"}, MaxExpandedHosts: 4}); err == nil || !strings.Contains(err.Error(), "resolved to excluded") || !IsConfigurationError(err) {
		t.Fatalf("DNS result containing excluded address was accepted: %v", err)
	}
	for _, address := range []string{"0.0.0.0", "::"} {
		n.Resolver = fakeResolver{[]net.IP{net.ParseIP(address)}}
		if _, err := n.resolve(context.Background(), config.Job{Targets: []string{"unspecified.example"}, MaxExpandedHosts: 1}); err == nil || !strings.Contains(err.Error(), "resolved to excluded") || !strings.Contains(err.Error(), "unspecified") {
			t.Fatalf("DNS result containing unspecified address %q was accepted: %v", address, err)
		}
	}
	if err := n.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	if _, err := n.resolve(context.Background(), config.Job{Targets: []string{"127.0.0.1"}, MaxExpandedHosts: 1}); err != nil {
		t.Fatalf("explicit empty exclusion override rejected target: %v", err)
	}
	for _, address := range []string{"0.0.0.0", "::"} {
		n.Resolver = fakeResolver{[]net.IP{net.ParseIP(address)}}
		if _, err := n.resolve(context.Background(), config.Job{Targets: []string{"override.example"}, MaxExpandedHosts: 1}); err == nil || !strings.Contains(err.Error(), "resolved to excluded") || !strings.Contains(err.Error(), "unspecified") {
			t.Fatalf("explicit empty exclusion override accepted unspecified address %q: %v", address, err)
		}
	}
}

func TestResolveTypesStaticExpansionAndEmptyDNSFailures(t *testing.T) {
	n := New("nmap")
	if _, err := n.resolve(context.Background(), config.Job{Targets: []string{"1.1.1.1", "8.8.8.8"}, MaxExpandedHosts: 1}); err == nil || !IsConfigurationError(err) {
		t.Fatalf("expanded IP target limit error = %v, want typed configuration failure", err)
	}

	if err := n.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	if _, err := n.resolve(context.Background(), config.Job{Targets: []string{"127.0.0.0/30"}, MaxExpandedHosts: 4}); err == nil || !IsConfigurationError(err) {
		t.Fatalf("CIDR containing excluded address error = %v, want typed configuration failure", err)
	}

	if err := n.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	n.Resolver = fakeResolver{}
	if _, err := n.resolve(context.Background(), config.Job{Targets: []string{"empty.example"}, MaxExpandedHosts: 1}); err == nil || !IsConfigurationError(err) {
		t.Fatalf("empty DNS response error = %v, want typed configuration failure", err)
	}

	n.Resolver = fakeResolver{ips: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}}
	if _, err := n.resolve(context.Background(), config.Job{Targets: []string{"many.example"}, MaxExpandedHosts: 1}); err == nil || !IsConfigurationError(err) {
		t.Fatalf("expanded DNS target limit error = %v, want typed configuration failure", err)
	}
}

func TestAggregatePrefersConfirmedOpen(t *testing.T) {
	target := resolvedTarget{Name: "example.com", Addresses: []string{"192.0.2.1", "192.0.2.2"}, Aggregate: true}
	parsed := map[string]model.Unit{"192.0.2.1": {Ports: []model.PortState{{Port: 53, State: "open|filtered"}}}, "192.0.2.2": {Ports: []model.PortState{{Port: 53, State: "open"}}}}
	got := aggregate(target, parsed, "udp")
	if got.Ports[0].State != "open" {
		t.Fatalf("got %s", got.Ports[0].State)
	}
}

func TestNmapArgsHostDiscovery(t *testing.T) {
	protocol := config.Protocol{Ports: "22", Mode: "syn"}
	addresses := []string{"192.0.2.1"}

	withAssumption := nmapArgs(4, "tcp", protocol, "balanced", true, addresses)
	if !slices.Contains(withAssumption, "-Pn") {
		t.Fatalf("assume_alive=true args: %v", withAssumption)
	}
	if !slices.Contains(withAssumption, "--reason") {
		t.Fatalf("nmap args omitted --reason: %v", withAssumption)
	}

	withDiscovery := nmapArgs(4, "tcp", protocol, "balanced", false, addresses)
	if slices.Contains(withDiscovery, "-Pn") {
		t.Fatalf("assume_alive=false args: %v", withDiscovery)
	}
	if countNmapVerbosity(withDiscovery) != 1 {
		t.Fatalf("assume_alive=false args must request explicit down hosts with one -v: %v", withDiscovery)
	}
	if countNmapVerbosity(withAssumption) != 0 {
		t.Fatalf("assume_alive=true must preserve the default command without -v: %v", withAssumption)
	}
}

func countNmapVerbosity(args []string) int {
	count := 0
	for _, argument := range args {
		if argument == "-v" || argument == "-vv" || argument == "-vvv" || argument == "--verbose" {
			count++
		}
	}
	return count
}

func TestNmapDiscoveryVerbosityAcrossProtocolsAndProfiles(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			pc := config.Protocol{Ports: "22,53", Mode: "connect"}
			for _, assumeAlive := range []bool{false, true} {
				args := nmapArgs(4, protocol, pc, "balanced", assumeAlive, []string{"192.0.2.9"})
				if got := countNmapVerbosity(args); got != map[bool]int{false: 1, true: 0}[assumeAlive] {
					t.Fatalf("assume_alive=%t verbosity count = %d, args=%v", assumeAlive, got, args)
				}
				if assumeAlive != slices.Contains(args, "-Pn") {
					t.Fatalf("assume_alive=%t -Pn mismatch: %v", assumeAlive, args)
				}
			}

			for _, explicit := range []string{"-v", "-vv", "-vvv", "--verbose"} {
				pc.NmapArgs = []string{explicit, config.PlaceholderPorts, config.PlaceholderStructuredOutput, config.PlaceholderAddresses}
				args := nmapArgs(4, protocol, pc, "balanced", false, []string{"192.0.2.9"})
				if got := countNmapVerbosity(args); got != 1 {
					t.Fatalf("custom %s template duplicated verbosity: %v", explicit, args)
				}
			}

			pc.NmapArgs = nil
			args := nmapArgsWithTemplateAndDiscovery(4, protocol, pc, "balanced", true, []string{"192.0.2.9"}, nil, false)
			if countNmapVerbosity(args) != 0 {
				t.Fatalf("Naabu enrichment must not infer host reachability from Nmap verbosity: %v", args)
			}
			if !slices.Contains(args, "-Pn") {
				t.Fatalf("Naabu enrichment must skip redundant Nmap host discovery: %v", args)
			}
		})
	}
}

func TestVerboseOutputForFullPortUnitFitsProgressBound(t *testing.T) {
	writer := &progressOutputWriter{limit: maxProgressOutput}
	// A maximum-length IPv6 address gives a conservative status-line size for
	// the largest supported Nmap work unit, including a fully open port range.
	line := []byte("Discovered open port 65535/tcp on 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\n")
	for probe := 0; probe < 65536; probe++ {
		if _, err := writer.Write(line); err != nil {
			t.Fatalf("verbose line %d write error: %v", probe, err)
		}
	}
	if writer.exceeded {
		t.Fatalf("verbosity diagnostics for a 65,536-probe unit exceeded the %d-byte bound (%d bytes)", maxProgressOutput, len(writer.String()))
	}
}

func TestScanUsesVerboseNmapXMLToRecordCompletedDownHostDiscovery(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	quietFixture := filepath.Join("testdata", "nmap-7.95-host-down-quiet.xml")
	verboseFixture := filepath.Join("testdata", "nmap-7.95-host-down-verbose.xml")
	script := "#!/bin/sh\nxml_output=''\nverbose=0\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    -oX) xml_output=\"$2\"; shift 2; continue ;;\n    -v|-vv|-vvv|--verbose) verbose=1 ;;\n  esac\n  shift\ndone\nif [ \"$verbose\" -eq 1 ]; then cp '" + verboseFixture + "' \"$xml_output\"; else cp '" + quietFixture + "' \"$xml_output\"; fi\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	assumeAlive := false
	job := config.NormalizeJob(config.Job{
		Name: "host-discovery-down", Targets: []string{"192.0.2.9"}, MaxExpandedHosts: 1,
		AssumeAlive: &assumeAlive, TCP: &config.Protocol{Ports: "22,80", Mode: "connect"}, UDP: &config.Protocol{Ports: "53"},
	})
	snapshot, err := New(nmapPath).Scan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Hosts) != 1 {
		t.Fatalf("host observations = %#v", snapshot.Hosts)
	}
	if len(snapshot.Hosts[0].Protocols) != 2 {
		t.Fatalf("TCP+UDP protocol evidence = %#v", snapshot.Hosts[0].Protocols)
	}
	for _, protocol := range snapshot.Hosts[0].Protocols {
		if protocol.Status != "unreachable" || protocol.StatusReason != "no-response" || protocol.DiscoveryState != "down" {
			t.Errorf("Nmap verbose down evidence for %s = %#v", protocol.Protocol, protocol)
		}
	}
}

func TestNmapProfilePlaceholdersRenderManagedArguments(t *testing.T) {
	pc := config.Protocol{Ports: "22,443", Mode: "connect", ServiceDetection: true, NmapArgs: []string{
		config.PlaceholderAddresses, config.PlaceholderPorts, config.PlaceholderStructuredOutput,
		config.PlaceholderHostDiscovery, config.PlaceholderScanType, config.PlaceholderServiceDetection,
	}}
	args := nmapArgs(4, "tcp", pc, "balanced", true, []string{"192.0.2.1", "192.0.2.2"})
	joined := strings.Join(args, " ")
	if strings.Contains(joined, config.PlaceholderAddresses) || strings.Contains(joined, config.PlaceholderPorts) {
		t.Fatalf("placeholder leaked into command: %v", args)
	}
	if strings.Count(joined, "-p") != 1 || strings.Count(joined, "22,443") != 1 || strings.Count(joined, "-oX") != 1 {
		t.Fatalf("managed arguments were not rendered exactly once: %v", args)
	}
	if !strings.Contains(joined, "192.0.2.1") || !strings.Contains(joined, "192.0.2.2") || !strings.Contains(joined, "-sT") || !strings.Contains(joined, "-sV") || !strings.Contains(joined, "-Pn") {
		t.Fatalf("profile placeholders were not rendered: %v", args)
	}
}

func TestNmapCustomProfileKeepsTypedDefaultsWhenPlaceholdersOmitted(t *testing.T) {
	pc := config.Protocol{Ports: "443", Mode: "syn", ServiceDetection: true, NmapArgs: []string{
		config.PlaceholderAddress, config.PlaceholderPorts, config.PlaceholderStructuredOutput, "--host-timeout", "5m",
	}}
	args := nmapArgs(6, "tcp", pc, "balanced", true, []string{"2001:db8::10"})
	joined := strings.Join(args, " ")
	for _, expected := range []string{"-Pn", "-6", "-sS", "-sV", "--version-light", "--host-timeout", "5m"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("custom Nmap profile omitted typed default %q: %v", expected, args)
		}
	}
	if strings.Contains(joined, config.PlaceholderAddress) || strings.Contains(joined, config.PlaceholderPorts) {
		t.Fatalf("placeholder leaked into custom Nmap command: %v", args)
	}
}

func TestScanProtocolRecordsOmittedHostWithoutDroppingBatch(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	output := `<?xml version="1.0"?><nmaprun><host><status state="up" reason="arp-response"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port></ports></host><host><status state="up" reason="arp-response"/><address addr="192.0.2.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
	script := "#!/bin/sh\nprintf '%s' '" + output + "'\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	target := resolvedTarget{Name: "batch", Addresses: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}}
	result, err := n.scanProtocolBatchDetailedProgress(context.Background(), []resolvedTarget{target}, "tcp", config.Protocol{Ports: "22,80", Mode: "syn"}, "balanced", false, nil)
	if err != nil {
		t.Fatalf("partial host response was rejected instead of returned as evidence: %v", err)
	}
	if len(result.Units) != 2 {
		t.Fatalf("units = %#v, want the two reported hosts only", result.Units)
	}
	missing, ok := result.Hosts["192.0.2.3"]
	if !ok || missing.Status != "unreachable" || missing.StatusReason != "nmap-omitted" {
		t.Fatalf("missing host observation = %#v", missing)
	}
	if len(missing.Protocols) != 1 || missing.Protocols[0].StateSummaries[0].State != "unreachable" {
		t.Fatalf("missing host scope evidence = %#v", missing.Protocols)
	}
}

func TestScanReturnsPartialSnapshotForReachableAndOmittedHosts(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	output := `<?xml version="1.0"?><nmaprun><host><status state="up" reason="syn-ack"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s' '"+output+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	job := config.NormalizeJob(config.Job{
		Name:             "partial",
		Targets:          []string{"192.0.2.1", "192.0.2.2"},
		MaxExpandedHosts: 2,
		TCP:              &config.Protocol{Ports: "443", Mode: "connect"},
	})
	snapshot, err := n.Scan(context.Background(), job)
	if err != nil {
		t.Fatalf("partial scan was rejected: %v", err)
	}
	if len(snapshot.Units) != 1 || snapshot.Units[0].Target != "192.0.2.1" {
		t.Fatalf("reachable unit was not retained: %#v", snapshot.Units)
	}
	if len(snapshot.Hosts) != 2 || snapshot.Hosts[1].Address != "192.0.2.2" || snapshot.Hosts[1].Status != "unreachable" {
		t.Fatalf("partial host observations = %#v", snapshot.Hosts)
	}
}

func TestScanProtocolFailsWhenEntireInvocationOmitsHosts(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	output := `<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/></runstats></nmaprun>`
	script := "#!/bin/sh\nprintf '%s' '" + output + "'\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	target := resolvedTarget{Name: "192.0.2.1", Addresses: []string{"192.0.2.1"}}
	_, err := n.scanProtocol(context.Background(), target, "tcp", config.Protocol{Ports: "22", Mode: "syn"}, "balanced", false)
	if err == nil || !strings.Contains(err.Error(), "omitted expected address") {
		t.Fatalf("expected empty invocation failure, got %v", err)
	}
}

// udpOpenFilteredXML renders Nmap 7.9x XML for one UDP host scanned on ports
// 20001-(20000+total). The first silent ports are open|filtered and the rest
// are closed. listed selects whether Nmap printed the open|filtered ports one
// by one (at most 25 by default, more with -v, -vv or -vvv) or folded them
// into <extraports>. portList controls the extrareasons port list that Nmap
// 7.80 and later attach to folded states.
func udpOpenFilteredXML(silent, total int, listed, portList bool) []byte {
	var ports strings.Builder
	extra := func(state, reason string, first, count int) {
		if count == 0 {
			return
		}
		list := ""
		if portList {
			list = fmt.Sprintf(` proto="udp" ports="%d-%d"`, first, first+count-1)
		}
		fmt.Fprintf(&ports, `<extraports state="%s" count="%d"><extrareasons reason="%s" count="%d"%s/></extraports>`, state, count, reason, count, list)
	}
	if listed {
		for port := 20001; port < 20001+silent; port++ {
			fmt.Fprintf(&ports, `<port protocol="udp" portid="%d"><state state="open|filtered" reason="no-response" reason_ttl="0"/><service name="unknown" method="table" conf="3"/></port>`, port)
		}
	} else {
		extra("open|filtered", "no-response", 20001, silent)
	}
	extra("closed", "port-unreach", 20001+silent, total-silent)
	return []byte(`<?xml version="1.0" encoding="UTF-8"?><nmaprun scanner="nmap" version="7.99" xmloutputversion="1.05"><scaninfo type="udp" protocol="udp"/><host><status state="up" reason="user-set" reason_ttl="0"/><address addr="192.0.2.10" addrtype="ipv4"/><ports>` + ports.String() + `</ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
}

func udpUnitPorts(t *testing.T, data []byte) (model.Unit, model.ProtocolObservation) {
	t.Helper()
	run, err := parseXMLWithConfig(data, "udp", config.Protocol{Ports: "20001-20040"})
	if err != nil {
		t.Fatal(err)
	}
	host, ok := run.Hosts["192.0.2.10"]
	if !ok || len(host.Protocols) != 1 {
		t.Fatalf("UDP host evidence = %#v", run.Hosts)
	}
	unit := run.Units["192.0.2.10"]
	(&model.Snapshot{Units: []model.Unit{unit}}).Normalize()
	return unit, host.Protocols[0]
}

// Nmap folds more than 25 open|filtered UDP ports into one <extraports>
// element at default verbosity. The folded ports are still observations and
// must reach the baseline exactly as if Nmap had listed them one by one.
func TestParseXMLRecordsFoldedUDPOpenFilteredPorts(t *testing.T) {
	folded, foldedProtocol := udpUnitPorts(t, udpOpenFilteredXML(26, 40, false, true))
	if len(folded.Ports) != 26 || folded.Ports[0].Port != 20001 || folded.Ports[25].Port != 20026 {
		t.Fatalf("folded open|filtered ports were dropped: %#v", folded.Ports)
	}
	for _, port := range folded.Ports {
		if port.State != "open|filtered" || len(port.Evidence) != 1 || port.Evidence[0] != "192.0.2.10" {
			t.Fatalf("folded port = %#v", port)
		}
	}
	if foldedProtocol.Status != "up" || len(foldedProtocol.Ports) != 26 || foldedProtocol.Ports[0].Reason != "no-response" {
		t.Fatalf("folded protocol evidence = %#v", foldedProtocol)
	}
	summaries := map[string]int{}
	for _, summary := range foldedProtocol.StateSummaries {
		summaries[summary.State] = summary.Count
	}
	if summaries["open|filtered"] != 26 || summaries["closed"] != 14 {
		t.Fatalf("folded ports were counted twice or not at all: %#v", foldedProtocol.StateSummaries)
	}

	// -v, -vv and -vvv make Nmap list the same ports individually. Profile
	// verbosity must not change what the comparison engine sees.
	listed, _ := udpUnitPorts(t, udpOpenFilteredXML(26, 40, true, true))
	if !reflect.DeepEqual(listed.Ports, folded.Ports) {
		t.Fatalf("listed and folded observations differ:\nlisted %#v\nfolded %#v", listed.Ports, folded.Ports)
	}

	// Crossing the 25-port display threshold must only report the ports that
	// actually changed: 24 silent ports are listed, 26 are folded.
	fewer, _ := udpUnitPorts(t, udpOpenFilteredXML(24, 40, false, true))
	fewerListed, _ := udpUnitPorts(t, udpOpenFilteredXML(24, 40, true, true))
	if !reflect.DeepEqual(fewer.Ports, fewerListed.Ports) || len(fewer.Ports) != 24 {
		t.Fatalf("24 silent ports = %#v", fewer.Ports)
	}
	if !reflect.DeepEqual(fewer.Ports, folded.Ports[:24]) {
		t.Fatalf("24-port and 26-port observations disagree beyond the two changed ports")
	}

	// Non-contiguous folded ports are listed as comma-separated ports and
	// ranges, possibly under several reasons.
	scattered := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="udp" portid="161"><state state="open" reason="udp-response"/></port><extraports state="open|filtered" count="4"><extrareasons reason="no-response" count="3" proto="udp" ports="53, 123-124"/><extrareasons reason="admin-prohibited" count="1" ports="500"/></extraports></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	unit, protocol := udpUnitPorts(t, scattered)
	var got []string
	for _, port := range unit.Ports {
		got = append(got, fmt.Sprintf("%d/%s", port.Port, port.State))
	}
	if want := []string{"53/open|filtered", "123/open|filtered", "124/open|filtered", "161/open", "500/open|filtered"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scattered folded ports = %v, want %v", got, want)
	}
	if protocol.Status != "up" || len(protocol.Ports) != 5 {
		t.Fatalf("scattered folded protocol = %#v", protocol)
	}
}

// XML without a usable folded port list (older Nmap releases, or a list that
// does not account for every folded port) cannot say which ports were
// open|filtered. The protocol must then be flagged as incomplete coverage so
// the engine neither adds nor removes the unlisted ports.
func TestParseXMLFlagsUnlistedFoldedOpenFilteredPorts(t *testing.T) {
	folded := string(udpOpenFilteredXML(26, 40, false, true))
	const reason = `<extrareasons reason="no-response" count="26" proto="udp" ports="20001-20026"/>`
	replace := func(old, replacement string) []byte {
		if !strings.Contains(folded, old) {
			t.Fatalf("fixture does not contain %q", old)
		}
		return []byte(strings.Replace(folded, old, replacement, 1))
	}
	for _, test := range []struct {
		name      string
		xml       []byte
		wantError bool
	}{
		{name: "no port list", xml: udpOpenFilteredXML(26, 40, false, false)},
		{name: "short port list", xml: replace(`ports="20001-20026"`, `ports="20001-20025"`)},
		{name: "long port list", xml: replace(`ports="20001-20026"`, `ports="1-65535"`)},
		{name: "other protocol", xml: replace(`proto="udp" ports="20001-20026"`, `proto="tcp" ports="20001-20026"`)},
		{name: "invalid port list", xml: replace(`ports="20001-20026"`, `ports="20001-x"`)},
		{name: "reversed range", xml: replace(`ports="20001-20026"`, `ports="20026-20001"`)},
		{name: "duplicate ports", xml: replace(reason, `<extrareasons reason="no-response" count="13" proto="udp" ports="20001-20013"/><extrareasons reason="no-response" count="13" proto="udp" ports="20001-20013"/>`)},
		{name: "reason counts exceed the folded count", xml: replace(reason, `<extrareasons reason="no-response" count="26" proto="udp" ports="20001-20026"/><extrareasons reason="no-response" count="1" proto="udp" ports="20027"/>`)},
		{name: "implausible count", xml: replace(`state="open|filtered" count="26"`, `state="open|filtered" count="70000"`), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.wantError {
				_, err := parseXMLWithConfig(test.xml, "udp", config.Protocol{Ports: "20001-20040"})
				if err == nil || !strings.Contains(err.Error(), "scan scope") {
					t.Fatalf("implausible folded count error = %v, want failed scan-scope validation", err)
				}
				return
			}
			unit, protocol := udpUnitPorts(t, test.xml)
			if len(unit.Ports) != 0 {
				t.Fatalf("unverifiable folded ports were recorded: %#v", unit.Ports)
			}
			if protocol.Status != "unknown" || protocol.StatusReason != nmapUnlistedOpenFilteredReason {
				t.Fatalf("unlisted open|filtered ports were silently dropped: status %q/%q", protocol.Status, protocol.StatusReason)
			}
		})
	}
}

func TestParseXMLRecordsDownHostAsUnreachable(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><nmaprun><host><status state="down" reason="no-response" reason_ttl="64"/><address addr="192.0.2.9" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	run, err := parseXMLWithConfig(data, "tcp", config.Protocol{Ports: "1-100", Mode: "connect"})
	if err != nil {
		t.Fatal(err)
	}
	host, ok := run.Hosts["192.0.2.9"]
	if !ok || host.Status != "unreachable" || host.StatusReason != "no-response" || host.ReasonTTL != 64 {
		t.Fatalf("down host observation = %#v", host)
	}
	if _, ok := run.Units["192.0.2.9"]; ok {
		t.Fatal("down host unexpectedly produced a comparison unit")
	}
	if len(host.Protocols) != 1 || host.Protocols[0].StateSummaries[0].State != "unreachable" {
		t.Fatalf("down host protocol evidence = %#v", host.Protocols)
	}
}

func TestScanMarksOnlyCompletedNmapHostDiscovery(t *testing.T) {
	downXML := `<?xml version="1.0"?><nmaprun><host><status state="down" reason="no-response"/><address addr="192.0.2.9" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`
	timeoutXML := `<?xml version="1.0"?><nmaprun><host timedout="true"><status state="up"/><address addr="192.0.2.9" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`
	upXML := `<?xml version="1.0"?><nmaprun><host><status state="up" reason="syn-ack"/><address addr="192.0.2.9" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`
	tests := []struct {
		name        string
		xml         string
		assumeAlive bool
		wantState   string
		wantReason  string
	}{
		{name: "explicit host discovery down", xml: downXML, wantState: "down", wantReason: "no-response"},
		{name: "timed out host", xml: timeoutXML, wantReason: "nmap-host-timeout"},
		{name: "assumed alive skips host discovery", xml: upXML, assumeAlive: true, wantReason: "syn-ack"},
		{name: "up host", xml: upXML, wantState: "up", wantReason: "syn-ack"},
		{name: "omitted host", xml: `<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/></runstats></nmaprun>`, wantReason: "nmap-omitted"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			nmapPath := filepath.Join(dir, "nmap")
			script := "#!/bin/sh\nprintf '%s' '" + test.xml + "'\n"
			if test.name == "explicit host discovery down" {
				omittedXML := `<?xml version="1.0"?><nmaprun><verbose level="0"/><runstats><finished exit="success"/><hosts up="0" down="1" total="1"/></runstats></nmaprun>`
				script = "#!/bin/sh\nverbose=0\nfor arg in \"$@\"; do case \"$arg\" in -v|-vv|-vvv|--verbose) verbose=1 ;; esac; done\nif [ \"$verbose\" -eq 1 ]; then printf '%s' '" + test.xml + "'; else printf '%s' '" + omittedXML + "'; fi\n"
			}
			if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			assumeAlive := test.assumeAlive
			job := config.NormalizeJob(config.Job{
				Name: "host-discovery", Targets: []string{"192.0.2.9"}, MaxExpandedHosts: 1,
				AssumeAlive: &assumeAlive, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
			})
			snapshot, err := New(nmapPath).Scan(context.Background(), job)
			if err != nil {
				t.Fatal(err)
			}
			if len(snapshot.Hosts) != 1 || snapshot.Hosts[0].Address != "192.0.2.9" {
				t.Fatalf("host observations = %#v", snapshot.Hosts)
			}
			host := snapshot.Hosts[0]
			if len(host.Protocols) != 1 {
				t.Fatalf("protocol observations = %#v", host.Protocols)
			}
			protocol := host.Protocols[0]
			if protocol.DiscoveryState != test.wantState {
				t.Errorf("discovery state = %q, want %q", protocol.DiscoveryState, test.wantState)
			}
			if protocol.StatusReason != test.wantReason {
				t.Errorf("status reason = %q, want %q", protocol.StatusReason, test.wantReason)
			}
		})
	}
}

func TestMergeDiscoveryStatesKeepsConflictsNonAuthoritative(t *testing.T) {
	for _, test := range []struct {
		name, first, second, third, want string
	}{
		{name: "same state", first: "up", second: "up", want: "up"},
		{name: "up then down", first: "up", second: "down", want: "conflict"},
		{name: "down then up", first: "down", second: "up", want: "conflict"},
		{name: "third fragment cannot clear conflict", first: "up", second: "down", third: "up", want: "conflict"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := mergeDiscoveryStates(test.first, test.second)
			if test.third != "" {
				got = mergeDiscoveryStates(got, test.third)
			}
			if got != test.want {
				t.Fatalf("merged discovery state = %q, want %q", got, test.want)
			}
		})
	}
}

func TestScanBatchesExpandedCIDRTargets(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	countPath := filepath.Join(dir, "invocations")
	var hosts strings.Builder
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&hosts, `<host><status state="up"/><address addr="192.0.2.%d" addrtype="ipv4"/></host>`, i)
	}
	output := `<?xml version="1.0"?><nmaprun>` + hosts.String() + `<runstats><finished exit="success"/></runstats></nmaprun>`
	script := "#!/bin/sh\nprintf x >> '" + countPath + "'\nprintf '%s' '" + output + "'\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	job := config.NormalizeJob(config.Job{
		Name: "cidr", Targets: []string{"192.0.2.0/30"}, MaxExpandedHosts: 4,
		TCP: &config.Protocol{Ports: "22", Mode: "syn"}, Timing: "balanced",
	})
	snapshot, err := n.Scan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	invocations, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(invocations) != 1 {
		t.Fatalf("nmap invocations = %d, want one batch: %q", len(invocations), invocations)
	}
	if len(snapshot.Units) != 4 {
		t.Fatalf("snapshot units = %d, want four expanded hosts: %#v", len(snapshot.Units), snapshot.Units)
	}
}

func TestDirectNmapScanBatchesFullRangeAndReportsMatchingInvocationTotals(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	countPath := filepath.Join(dir, "invocations")
	output := `<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/></runstats></nmaprun>`
	script := "#!/bin/sh\nprintf x >> '" + countPath + "'\nprintf '%s' '" + output + "'\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	job := config.NormalizeJob(config.Job{
		Name:             "direct-full-range",
		Targets:          []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
		MaxExpandedHosts: 3,
		TCP:              &config.Protocol{Ports: "1-65535", Mode: "syn"},
	})
	var updates []Progress
	if _, err := New(nmapPath).ScanWithProgress(context.Background(), job, func(progress Progress) { updates = append(updates, progress) }); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatalf("full-range Nmap invocations = %d, want 3 one-address batches: %q", len(calls), calls)
	}
	if len(updates) == 0 {
		t.Fatal("scan emitted no progress")
	}
	last := updates[len(updates)-1]
	if last.Phase != "complete" || last.TotalInvocations != 3 || last.CompletedInvocations != 3 || last.TotalProbes != 3*65535 || last.CompletedProbes != last.TotalProbes {
		t.Fatalf("progress totals do not match the adaptive batches: %#v", last)
	}
}

func TestScanWithProgressReportsBoundedWork(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s' '"+sampleXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	job := config.NormalizeJob(config.Job{
		Name: "progress", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Ports: "22-23", Mode: "syn"}, Timing: "balanced",
	})
	var updates []Progress
	if _, err := n.ScanWithProgress(context.Background(), job, func(progress Progress) { updates = append(updates, progress) }); err != nil {
		t.Fatal(err)
	}
	if len(updates) < 4 {
		t.Fatalf("progress updates = %#v, want resolving, scanning, invocation, complete", updates)
	}
	first, last := updates[0], updates[len(updates)-1]
	if first.Phase != "resolving" || last.Phase != "complete" {
		t.Fatalf("progress phases = %#v ... %#v", first, last)
	}
	if last.TotalProbes != 2 || last.CompletedProbes != 2 || last.TotalInvocations != 1 || last.CompletedInvocations != 1 {
		t.Fatalf("progress totals = %#v", last)
	}
}

func TestScanWithProgressReportsLiveProcessHeartbeatAndNmapOutput(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	script := "#!/bin/sh\necho 'About 42.0% done; ETC: 00:01' >&2\nsleep 2\nprintf '%s' '" + sampleXML + "'\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	job := config.NormalizeJob(config.Job{
		Name: "live-progress", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Ports: "22-23", Mode: "syn"}, Timing: "balanced",
	})
	var updates []Progress
	if _, err := n.ScanWithProgress(context.Background(), job, func(progress Progress) { updates = append(updates, progress) }); err != nil {
		t.Fatal(err)
	}
	foundLive, foundOutput, foundFraction, foundComplete := false, false, false, false
	for _, update := range updates {
		if update.ProcessAlive && update.Protocol == "tcp" {
			foundLive = true
		}
		if strings.Contains(update.LastOutput, "About 42.0%") {
			foundOutput = true
		}
		if update.ProcessAlive && update.ProcessProgressPercent > 0 {
			foundFraction = true
		}
		if update.Phase == "complete" && !update.ProcessAlive {
			foundComplete = true
		}
	}
	if !foundLive || !foundOutput || !foundFraction || !foundComplete {
		t.Fatalf("live progress updates missing: live=%v output=%v fraction=%v complete=%v updates=%#v", foundLive, foundOutput, foundFraction, foundComplete, updates)
	}
}

func TestScanWithProgressUsesTerminalStatusWithoutControllingTTY(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	script := "#!/bin/sh\nout=\"\"\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-oX\" ]; then out=\"$2\"; shift 2; else shift; fi\ndone\nif [ -t 1 ]; then\n  printf 'Scanning 192.0.2.1\\r\\n'\n  printf 'Connect Scan Timing: About 37.50%% done\\r\\n'\nfi\nprintf '%s' '" + sampleXMLSinglePort + "' > \"$out\"\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	job := config.NormalizeJob(config.Job{
		Name: "tty-progress", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Ports: "22", Mode: "connect"}, Timing: "balanced",
	})
	var updates []Progress
	if _, err := n.ScanWithProgress(context.Background(), job, func(progress Progress) { updates = append(updates, progress) }); err != nil {
		t.Fatal(err)
	}
	foundOutput, foundFraction := false, false
	for _, update := range updates {
		if strings.Contains(update.LastOutput, "Scanning 192.0.2.1") || strings.Contains(update.LastOutput, "About 37.50%") {
			foundOutput = true
		}
		if update.ProcessAlive && update.ProcessProgressPercent == 37 {
			foundFraction = true
		}
	}
	if !foundOutput || !foundFraction {
		t.Fatalf("terminal status progress missing: output=%v fraction=%v updates=%#v", foundOutput, foundFraction, updates)
	}
}

func TestScanWithProgressReportsXMLTaskProgress(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	prefix := `<?xml version="1.0"?><nmaprun><taskprogress task="Connect Scan" percent="37.50"/>`
	suffix := `<host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`
	script := "#!/bin/sh\nout=\"\"\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-oX\" ]; then out=\"$2\"; shift 2; else shift; fi\ndone\nprintf '%s' '" + prefix + "' > \"$out\"\nsleep 1\nprintf '%s' '" + suffix + "' >> \"$out\"\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	job := config.NormalizeJob(config.Job{
		Name: "xml-progress", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Ports: "22", Mode: "connect"}, Timing: "balanced",
	})
	var updates []Progress
	if _, err := n.ScanWithProgress(context.Background(), job, func(progress Progress) { updates = append(updates, progress) }); err != nil {
		t.Fatal(err)
	}
	foundFraction, foundOutput := false, false
	for _, update := range updates {
		if update.ProcessAlive && update.ProcessProgressPercent == 37 {
			foundFraction = true
		}
		if strings.Contains(update.LastOutput, "Nmap Connect Scan: 37.50% complete") {
			foundOutput = true
		}
	}
	if !foundFraction || !foundOutput {
		t.Fatalf("XML task progress missing: fraction=%v output=%v updates=%#v", foundFraction, foundOutput, updates)
	}
}

func TestNmapXMLProgressParserHandlesSplitRecords(t *testing.T) {
	parser := &nmapXMLProgressParser{}
	var got []struct {
		line     string
		fraction float64
	}
	emit := func(line string, fraction float64) {
		got = append(got, struct {
			line     string
			fraction float64
		}{line: line, fraction: fraction})
	}
	parser.feed([]byte(`<nmaprun><taskprogress task="Connect`), emit)
	parser.feed([]byte(` Scan" percent="125.0"/></nmaprun>`), emit)
	if len(got) != 1 || got[0].fraction != 1 || !strings.Contains(got[0].line, "100.00%") {
		t.Fatalf("split XML progress = %#v", got)
	}
}

func TestNmapXMLProgressParserScansMalformedRecordsLinearlyAndHonorsCancellation(t *testing.T) {
	const malformedRecord = `<taskprogress percent="37.5">`
	var input strings.Builder
	input.Grow(2 << 20)
	for input.Len() < 2<<20 {
		input.WriteString(malformedRecord)
	}
	data := []byte(input.String())
	input.Reset()
	parser := &nmapXMLProgressParser{}
	started := time.Now()
	parser.feed(data, nil)
	if elapsed := time.Since(started); elapsed >= time.Second {
		// Keep this a coarse guard for the old quadratic suffix scan; race
		// instrumentation and shared CI runners make a tight wall-clock bound
		// unreliable even when the parser scans linearly.
		t.Fatalf("2 MiB of malformed task progress took %s; want under 1 s", elapsed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	emitted := 0
	err := (&nmapXMLProgressParser{}).feedContext(ctx, bytes.Repeat([]byte(`<taskprogress task="scan" percent="1"/>`), 64<<10), func(string, float64) {
		emitted++
		cancel()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled progress feed = %v; want context.Canceled", err)
	}
	if emitted != 1 {
		t.Fatalf("cancelled progress feed emitted %d records; want it to stop after the callback cancels the context", emitted)
	}
}

func TestProgressOutputWriterScansOnlyNewBytes(t *testing.T) {
	writer := &progressOutputWriter{}
	data := []byte{'x'}
	started := time.Now()
	for range 256 << 10 {
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		// Race instrumentation adds substantial fixed overhead to each Write;
		// this bound still catches rescanning the full unterminated prefix.
		t.Fatalf("256 KiB of bytewise progress output took %s; want under 2 s", elapsed)
	}
}

func TestNmapXMLProgressParserAcceptsAttributeLimit(t *testing.T) {
	const extraAttributes = maxNmapXMLAttributes - 2
	var input strings.Builder
	input.Grow(len(`<taskprogress task="Connect Scan" percent="37.5"`) + extraAttributes*len(` extra="x"`) + len(`/>`))
	input.WriteString(`<taskprogress task="Connect Scan" percent="37.5"`)
	for range extraAttributes {
		input.WriteString(` extra="x"`)
	}
	input.WriteString(`/>`)

	parser := &nmapXMLProgressParser{}
	var got []struct {
		line     string
		fraction float64
	}
	parser.feed([]byte(input.String()), func(line string, fraction float64) {
		got = append(got, struct {
			line     string
			fraction float64
		}{line: line, fraction: fraction})
	})
	if len(got) != 1 || got[0].fraction != 0.375 || got[0].line != "Nmap Connect Scan: 37.50% complete" {
		t.Fatalf("taskprogress at the attribute limit = %#v", got)
	}
}

func TestNmapXMLProgressParserBoundsAttributeAllocation(t *testing.T) {
	const attributeCount = 200_000
	const attribute = ` a="x"`

	var input strings.Builder
	input.Grow(len(`<taskprogress task="Connect" percent="37.5"`) + attributeCount*len(attribute) + len(`/>`))
	input.WriteString(`<taskprogress task="Connect" percent="37.5"`)
	for range attributeCount {
		input.WriteString(attribute)
	}
	input.WriteString(`/><taskprogress task="Connect Scan" percent="37.5"/>`)
	data := []byte(input.String())

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	parser := &nmapXMLProgressParser{}
	var got []struct {
		line     string
		fraction float64
	}
	parser.feed(data, func(line string, fraction float64) {
		got = append(got, struct {
			line     string
			fraction float64
		}{line: line, fraction: fraction})
	})
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(data)
	allocated := after.TotalAlloc - before.TotalAlloc
	if len(got) != 1 || got[0].fraction != 0.375 || got[0].line != "Nmap Connect Scan: 37.50% complete" {
		t.Fatalf("over-limit progress was not discarded while later valid progress remained visible: %#v", got)
	}
	maxAllocation := uint64(len(data))*3 + 512<<10
	if allocated > maxAllocation {
		t.Fatalf("taskprogress attribute guard allocated %d bytes for %d raw attributes, limit %d", allocated, attributeCount, maxAllocation)
	}
}

func TestPollNmapXMLProgressHonorsOutputLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.xml")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(maxNmapOutput) + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pollNmapXMLProgress(path, &nmapXMLProgressParser{}, nil); !errors.Is(err, errNmapProgressOutputExceeded) {
		t.Fatalf("oversized progress file error = %v", err)
	}
}

func TestScannerStorageErrorClassifiesExhaustedTemporaryStorage(t *testing.T) {
	underlying := errors.New("write failed")
	err := scannerStorageError(underlying, "open output: no space left on device")
	if err == nil || !strings.Contains(err.Error(), "scanner temporary storage exhausted") || !errors.Is(err, underlying) {
		t.Fatalf("storage error = %v", err)
	}
}
