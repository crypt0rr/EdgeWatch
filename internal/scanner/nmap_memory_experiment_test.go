package scanner

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
)

func TestNmapXMLRejectsCompactFoldedScopeAboveWorkUnitSlotsBeforeDecode(t *testing.T) {
	const hostCount = 2
	targets := make([]string, hostCount)
	var input strings.Builder
	input.Grow(2 << 10)
	input.WriteString(`<?xml version="1.0"?><nmaprun>`)
	for index := range targets {
		targets[index] = fmt.Sprintf("198.51.100.%d", index+1)
		fmt.Fprintf(&input, `<host><status state="up"/><address addr="%s" addrtype="ipv4"/><ports><extraports state="open|filtered" count="65535"><extrareasons reason="no-response" count="65535" proto="udp" ports="1-65535"/></extraports></ports></host>`, targets[index])
	}
	input.WriteString(`<runstats><finished exit="success"/></runstats></nmaprun>`)
	data := []byte(input.String())
	stats := nmapXMLParseStats{}
	_, err := parseXMLWithPortCount(context.Background(), data, "udp", config.Protocol{Ports: "1-65535"}, targets, 65535, &stats)
	if err == nil || !strings.Contains(err.Error(), "materialized slot") {
		t.Fatalf("two-host full-range folded result error = %v, want materialization-slot rejection", err)
	}
	if stats.MaterializedHosts != 0 || stats.MaterializedPositivePorts != 0 || stats.SelectedHostSpans != 0 {
		t.Fatalf("over-budget XML was decoded before rejection: %#v", stats)
	}
	if len(data) > 1<<10 {
		t.Fatalf("compact rejection fixture grew to %d bytes", len(data))
	}
	t.Logf("compact folded over-budget shape rejected before decode: hosts=%d xml_bytes=%d requested_slots=%d stats=%#v", hostCount, len(data), hostCount*65535, stats)
	runtime.KeepAlive(data)
}

func TestNmapXMLMaterializesExactWorkUnitSlotBoundary(t *testing.T) {
	const hostCount = 2
	const portsPerHost = 32768
	targets := make([]string, hostCount)
	var input strings.Builder
	input.Grow(2 << 10)
	input.WriteString(`<?xml version="1.0"?><nmaprun>`)
	for index := range targets {
		targets[index] = fmt.Sprintf("198.51.100.%d", index+1)
		fmt.Fprintf(&input, `<host><status state="up"/><address addr="%s" addrtype="ipv4"/><ports><extraports state="open|filtered" count="%d"><extrareasons reason="no-response" count="%d" proto="udp" ports="1-%d"/></extraports></ports></host>`, targets[index], portsPerHost, portsPerHost, portsPerHost)
	}
	input.WriteString(`<runstats><finished exit="success"/></runstats></nmaprun>`)
	data := []byte(input.String())
	input.Reset()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	peakHeap := before.HeapAlloc
	stopSampling := make(chan struct{})
	samplingDone := make(chan struct{})
	go func() {
		defer close(samplingDone)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopSampling:
				return
			case <-ticker.C:
				var sample runtime.MemStats
				runtime.ReadMemStats(&sample)
				if sample.HeapAlloc > peakHeap {
					peakHeap = sample.HeapAlloc
				}
			}
		}
	}()
	stats := nmapXMLParseStats{}
	parsed, err := parseXMLWithPortCount(context.Background(), data, "udp", config.Protocol{Ports: "1-32768"}, targets, portsPerHost, &stats)
	close(stopSampling)
	<-samplingDone
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	for _, target := range targets {
		if got := len(parsed.Units[target].Ports); got != portsPerHost {
			t.Fatalf("folded positive ports for %s = %d; want %d", target, got, portsPerHost)
		}
		if got := len(parsed.Hosts[target].Protocols[0].Ports); got != portsPerHost {
			t.Fatalf("folded host observations for %s = %d; want %d", target, got, portsPerHost)
		}
	}
	if stats.MaterializedPositivePorts != int(maxNmapXMLMaterializedPortSlots) {
		t.Fatalf("materialized positive-port records = %d, want exact %d-slot boundary", stats.MaterializedPositivePorts, maxNmapXMLMaterializedPortSlots)
	}
	t.Logf("compact folded exact-boundary shape: hosts=%d xml_bytes=%d expanded_ports=%d total_alloc_delta=%d retained_heap_delta=%d sampled_peak_heap_delta=%d", hostCount, len(data), hostCount*portsPerHost, after.TotalAlloc-before.TotalAlloc, after.HeapAlloc-before.HeapAlloc, peakHeap-before.HeapAlloc)
	runtime.KeepAlive(data)
	runtime.KeepAlive(parsed)
}
