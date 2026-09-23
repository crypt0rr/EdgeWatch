package scanner

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
)

type failingResolver struct{ err error }

func (r failingResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return nil, r.err
}

func TestRunScannerVersionProbeKillsChildWhenOutputLimitExceeded(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "finished")
			redirect := ""
			if stream == "stderr" {
				redirect = " >&2"
			}
			script := "i=0\nwhile [ \"$i\" -lt 2 ]; do\n  printf '%65536s' x" + redirect + "\n  i=$((i + 1))\ndone\nsleep 1\ntouch " + marker + "\n"
			path := filepath.Join(t.TempDir(), "scanner")
			if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o700); err != nil {
				t.Fatal(err)
			}
			_, err := runScannerVersionProbe(context.Background(), path, "--version")
			if err == nil || !strings.Contains(err.Error(), "scanner version output exceeded") {
				t.Fatalf("oversized %s error = %v", stream, err)
			}
			if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
				t.Fatalf("version-probe child reached post-output marker (stat error %v)", statErr)
			}
		})
	}
}

func TestNmapTargetExclusionsAndVersions(t *testing.T) {
	n := New("missing-nmap")
	if err := n.SetTargetExclusions(nil); err != nil {
		t.Fatal(err)
	}
	if got := n.excludedNetwork(nil); got != "invalid-address" {
		t.Fatalf("nil exclusion reason = %q", got)
	}
	if got := n.excludedNetwork(net.ParseIP("0.0.0.0")); got != "unspecified" {
		t.Fatalf("unspecified exclusion reason = %q", got)
	}
	if err := n.SetTargetExclusions([]string{"192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	if got := n.excludedNetwork(net.ParseIP("192.0.2.5")); got != "192.0.2.0/24" {
		t.Fatalf("configured exclusion reason = %q", got)
	}
	if got := n.excludedNetwork(net.ParseIP("198.51.100.5")); got != "" {
		t.Fatalf("allowed address reason = %q", got)
	}
	if err := n.SetTargetExclusions([]string{"not-a-network"}); err == nil {
		t.Fatal("invalid target exclusion accepted")
	}

	dir := t.TempDir()
	versionPath := filepath.Join(dir, "naabu-version")
	if err := os.WriteFile(versionPath, []byte("#!/bin/sh\nprintf '%s\\n' '[INF] Current Version: 2.6.1'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n.NaabuPath = versionPath
	if got := n.NaabuVersion(context.Background()); got != "2.6.1" {
		t.Fatalf("marker Naabu version = %q", got)
	}
	fallbackPath := filepath.Join(dir, "naabu-fallback")
	if err := os.WriteFile(fallbackPath, []byte("#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then exit 1; fi\nprintf '%s\\n' 'naabu v2.6.2'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n.NaabuPath = fallbackPath
	if got := n.NaabuVersion(context.Background()); got != "2.6.2" {
		t.Fatalf("fallback Naabu version = %q", got)
	}
	badPath := filepath.Join(dir, "naabu-invalid")
	if err := os.WriteFile(badPath, []byte("#!/bin/sh\nprintf '%s\\n' 'banner only'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n.NaabuPath = badPath
	if got := n.NaabuVersion(context.Background()); got != "unknown" {
		t.Fatalf("invalid Naabu version = %q", got)
	}
	n.NaabuPath = filepath.Join(dir, "missing")
	if got := n.NaabuVersion(context.Background()); got != "unknown" {
		t.Fatalf("missing Naabu version = %q", got)
	}
	if got := n.Version(context.Background()); got != "unknown" {
		t.Fatalf("missing Nmap version = %q", got)
	}
}

func TestNmapOutputBoundariesAndProgressWriters(t *testing.T) {
	if got, err := nmapXMLOutputExceeded("missing.xml", 0); err != nil || got {
		t.Fatalf("zero limit output check = %v, %v", got, err)
	}
	if _, err := nmapXMLOutputExceeded("missing.xml", 1); err == nil {
		t.Fatal("missing XML output did not fail stat")
	}
	path := filepath.Join(t.TempDir(), "small.xml")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if exceeded, err := nmapXMLOutputExceeded(path, 3); err != nil || exceeded {
		t.Fatalf("exact XML output check = %v, %v", exceeded, err)
	}
	if exceeded, err := nmapXMLOutputExceeded(path, 2); err != nil || !exceeded {
		t.Fatalf("oversized XML output check = %v, %v", exceeded, err)
	}

	cmd := exec.Command("nmap", "--reason")
	if got, err := prepareNmapXMLOutput(cmd); err != nil || got != "" || cmd.Args[1] != "--reason" {
		t.Fatalf("command without XML output = %q, %v, %#v", got, err, cmd.Args)
	}
	cmd = exec.Command("nmap", "-oX", "-")
	path, err := prepareNmapXMLOutput(cmd)
	if err != nil || path == "" || cmd.Args[2] == "-" {
		t.Fatalf("command XML output rewrite = %q, %v, %#v", path, err, cmd.Args)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("prepared XML path missing: %v", err)
	}
	_ = os.Remove(path)

	var lines []string
	var exceeded atomic.Int32
	writer := &progressOutputWriter{limit: 12, emit: func(line string) { lines = append(lines, line) }, onExceeded: func() { exceeded.Add(1) }}
	if count, err := writer.Write([]byte("first\r\nsecond\rthird")); err != nil || count != len("first\r\nsecond\rthird") {
		t.Fatalf("progress write = %d, %v", count, err)
	}
	writer.Flush()
	_, _ = writer.Write([]byte("overflow"))
	_, _ = writer.Write([]byte("again"))
	if exceeded.Load() != 1 || !strings.Contains(writer.String(), "first") || len(lines) < 2 {
		t.Fatalf("bounded writer = lines=%#v output=%q exceeded=%d", lines, writer.String(), exceeded.Load())
	}
	if !reflect.DeepEqual(writer.Bytes(), []byte(writer.String())) {
		t.Fatal("Bytes and String disagree")
	}
	var noLimit progressOutputWriter
	_, _ = noLimit.Write([]byte("complete\n"))
	if noLimit.String() != "complete\n" {
		t.Fatalf("unbounded writer = %q", noLimit.String())
	}
}

func TestNmapProgressParserAndCappedFiles(t *testing.T) {
	parser := &nmapXMLProgressParser{}
	parser.feed([]byte(strings.Repeat("x", 100)), nil)
	parser.feed([]byte("<taskprogress percent=\"-1\"/>"), func(string, float64) {})
	parser.feed([]byte("<taskprogress percent=\"101\"/>"), func(string, float64) {})
	parser.feed([]byte("<taskprogress task=\" \" percent=\"50\"/>"), func(line string, fraction float64) {
		if !strings.Contains(line, "Nmap progress") || fraction != 0.5 {
			t.Errorf("blank task progress = %q, %v", line, fraction)
		}
	})
	parser.feed([]byte("<taskprogress bad='unterminated"), nil)
	parser.feed([]byte(strings.Repeat("y", 5000)), nil)

	path := filepath.Join(t.TempDir(), "read.xml")
	if err := os.WriteFile(path, []byte("small"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, exceeded, err := readCappedFile(path, 16)
	if err != nil || exceeded || string(data) != "small" {
		t.Fatalf("small capped read = %q, %v, %v", data, exceeded, err)
	}
	if _, _, err := readCappedFile("missing.xml", 16); err == nil {
		t.Fatal("missing capped file did not fail")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("z", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	data, exceeded, err = readCappedFile(path, 8)
	if err != nil || !exceeded || len(data) != 8 {
		t.Fatalf("oversized capped read = len %d, %v, %v", len(data), exceeded, err)
	}

	if err := pollNmapXMLProgress("missing.xml", &nmapXMLProgressParser{}, nil); err == nil {
		t.Fatal("missing progress file did not fail")
	}
	progressPath := filepath.Join(t.TempDir(), "progress.xml")
	if err := os.WriteFile(progressPath, []byte("<taskprogress task=\"scan\" percent=\"25\"/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &nmapXMLProgressParser{offset: 100}
	var output string
	if err := pollNmapXMLProgress(progressPath, p, func(line string, _ float64) { output = line }); err != nil {
		t.Fatal(err)
	}
	if output == "" || p.offset == 0 {
		t.Fatalf("progress poll did not reset/read file: output=%q offset=%d", output, p.offset)
	}
}

func TestNmapScanWithProgressResolutionAndCancellationFailures(t *testing.T) {
	n := New("missing-nmap")
	n.Resolver = failingResolver{err: errors.New("resolver unavailable")}
	job := config.NormalizeJob(config.Job{Name: "resolution", Targets: []string{"edge.example"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"}})
	if _, err := n.ScanWithProgress(context.Background(), job, nil); err == nil || !strings.Contains(err.Error(), "resolver unavailable") {
		t.Fatalf("resolution failure = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n.Resolver = fakeResolver{[]net.IP{net.ParseIP("192.0.2.1")}}
	if _, err := n.ScanWithProgress(ctx, job, nil); err == nil {
		t.Fatal("canceled scan unexpectedly succeeded")
	}
	if _, err := n.ScanWithProgress(context.Background(), config.Job{Targets: []string{"192.0.2.1"}}, nil); err != nil {
		t.Fatalf("job without protocols should be an empty success: %v", err)
	}
}

func TestNmapServiceAndNSESummaryHelpers(t *testing.T) {
	type serviceEvidence struct {
		Name       string   `xml:"name,attr"`
		Product    string   `xml:"product,attr"`
		Version    string   `xml:"version,attr"`
		Extra      string   `xml:"extrainfo,attr"`
		Method     string   `xml:"method,attr"`
		Confidence int      `xml:"conf,attr"`
		Tunnel     string   `xml:"tunnel,attr"`
		OSType     string   `xml:"ostype,attr"`
		DeviceType string   `xml:"devicetype,attr"`
		CPES       []string `xml:"cpe"`
	}
	if hasServiceEvidence(serviceEvidence{}) {
		t.Fatal("empty service reported as evidence")
	}
	if !hasServiceEvidence(serviceEvidence{Name: "ssh"}) {
		t.Fatal("named service missing evidence")
	}
	for _, test := range []struct{ id, output, want string }{
		{"", "", ""}, {"http", "", "http"}, {"", "hello\nworld", "hello world"}, {"http", "hello", "http: hello"},
	} {
		if got := summarizeNSEOutput(test.id, test.output); got != test.want {
			t.Errorf("summarizeNSEOutput(%q,%q) = %q, want %q", test.id, test.output, got, test.want)
		}
	}
	if got := summarizeNSEOutput("long", strings.Repeat("x", 600)); len(got) != maxScannerMetadataBytes || !strings.HasSuffix(got, "…") {
		t.Fatalf("long NSE summary length = %d (%q)", len(got), got)
	}
}
