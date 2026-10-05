package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestManagedNmapHostDiscoveryLearnsMixedTCPAndUDPAndReportsDown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "host-state")
	if err := os.WriteFile(statePath, []byte("mixed\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	writeXML := func(name string, verbose bool, hosts ...string) string {
		t.Helper()
		var up, down int
		for _, host := range hosts {
			if strings.Contains(host, `state="up"`) {
				up++
			} else {
				down++
			}
		}
		path := filepath.Join(dir, name)
		verbosity := ""
		if verbose {
			verbosity = `<verbose level="1"/>`
		}
		document := `<?xml version="1.0"?><nmaprun>` + verbosity + strings.Join(hosts, "") +
			`<runstats><finished exit="success"/><hosts up="` + strconv.Itoa(up) + `" down="` + strconv.Itoa(down) + `" total="` + strconv.Itoa(len(hosts)) + `"/></runstats></nmaprun>`
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	upHost := func(protocol, port string) string {
		return `<host><status state="up" reason="syn-ack"/><address addr="192.0.2.8" addrtype="ipv4"/><ports><port protocol="` + protocol + `" portid="` + port + `"><state state="open" reason="syn-ack"/></port></ports></host>`
	}
	downHost := func(address string) string {
		return `<host><status state="down" reason="no-response" reason_ttl="0"/><address addr="` + address + `" addrtype="ipv4"/></host>`
	}

	fixtures := map[string]string{
		"tcp-mixed": writeXML("tcp-mixed.xml", true, upHost("tcp", "22"), downHost("192.0.2.9")),
		"udp-mixed": writeXML("udp-mixed.xml", true, upHost("udp", "53"), downHost("192.0.2.9")),
		"tcp-quiet": writeXML("tcp-quiet.xml", false, upHost("tcp", "22")),
		"udp-quiet": writeXML("udp-quiet.xml", false, upHost("udp", "53")),
		"tcp-down":  writeXML("tcp-down.xml", true, downHost("192.0.2.8"), downHost("192.0.2.9")),
		"udp-down":  writeXML("udp-down.xml", true, downHost("192.0.2.8"), downHost("192.0.2.9")),
	}
	for _, key := range []string{"tcp-quiet", "udp-quiet"} {
		contents, err := os.ReadFile(fixtures[key])
		if err != nil {
			t.Fatal(err)
		}
		// The quiet Nmap output omits the down <host> while runstats still
		// accounts for the address, matching Nmap 7.95 without -v.
		contents = []byte(strings.Replace(string(contents), `<hosts up="1" down="0" total="1"/>`, `<hosts up="1" down="1" total="2"/>`, 1))
		if err := os.WriteFile(fixtures[key], contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	nmapPath := filepath.Join(dir, "nmap")
	script := "#!/bin/sh\nxml_output=''\nprotocol=tcp\nverbose=0\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    -oX) xml_output=\"$2\"; shift 2; continue ;;\n    -sU) protocol=udp ;;\n    -v|-vv|-vvv|--verbose) verbose=1 ;;\n  esac\n  shift\ndone\nstate=$(cat '" + statePath + "')\nkey=\"$protocol-quiet\"\nif [ \"$verbose\" -eq 1 ]; then key=\"$protocol-mixed\"; fi\nif [ \"$state\" = down ]; then key=\"$protocol-down\"; fi\ncase \"$key\" in\n"
	// All fixture paths are generated under t.TempDir and are not
	// user-controlled.
	for _, protocol := range []string{"tcp", "udp"} {
		for _, mode := range []string{"quiet", "mixed", "down"} {
			key := protocol + "-" + mode
			script += key + ") cat '" + fixtures[key] + "' > \"$xml_output\" ;;\n"
		}
	}
	script += "esac\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{
		Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour),
		Scheduler: config.Scheduler{MaxConcurrent: 1}, Scanner: config.ScannerConfig{TargetExclusions: []string{}},
		Web: config.Web{Listen: "127.0.0.1:8080"},
	}
	application, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	productionScanner := scanner.New(nmapPath)
	if err := productionScanner.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	application.Scanner = productionScanner

	assumeAlive := false
	job := config.NormalizeJob(config.Job{
		Name: "mixed-host-discovery", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.8/31"}, MaxExpandedHosts: 2, AssumeAlive: &assumeAlive,
		TCP: &config.Protocol{Ports: "22", Mode: "connect"}, UDP: &config.Protocol{Ports: "53"},
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	})
	record, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}

	first, events, err := application.RunJobRecord(ctx, record)
	if err != nil || first.Status != "success" {
		t.Fatalf("mixed up/down TCP+UDP scan = %#v, events=%#v, err=%v", first, events, err)
	}
	if len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("mixed up/down scan events = %#v, want one baseline-complete", events)
	}
	state, err := defaultTenant(db).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || len(state.Baseline.HostStates) != 2 {
		t.Fatalf("mixed up/down baseline states = %#v", state.Baseline)
	}

	if err := os.WriteFile(statePath, []byte("down\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, events, err := application.RunJobRecord(ctx, record)
	if err != nil || second.Status != "success" {
		t.Fatalf("host-down TCP+UDP scan = %#v, events=%#v, err=%v", second, events, err)
	}
	if len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 {
		t.Fatalf("host-down scan events = %#v, want one host-state change", events)
	}
	change := events[0].Changes[0]
	if change.Kind != "host" || change.Target != "192.0.2.8" || change.Old != "up" || change.New != "down" {
		t.Fatalf("host-down change = %#v", change)
	}
}
