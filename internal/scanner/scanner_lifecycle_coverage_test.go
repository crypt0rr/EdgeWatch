package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
)

func TestNaabuLifecycleFailurePreservesCauseWithoutLeakingIt(t *testing.T) {
	cause := errors.New("private /var/lib/edgewatch path with credential=do-not-report")
	wrapped := withNaabuLifecycleFailure(naabuLifecycleInputCleanup, cause)
	if !errors.Is(wrapped, cause) {
		t.Fatalf("lifecycle failure %v does not preserve its cause", wrapped)
	}
	if got, want := wrapped.Error(), "naabu target input cleanup failed"; got != want {
		t.Fatalf("lifecycle failure text = %q, want %q", got, want)
	}
	for _, forbidden := range []string{"/var/lib/edgewatch", "credential", "do-not-report"} {
		if strings.Contains(wrapped.Error(), forbidden) {
			t.Fatalf("lifecycle failure leaked %q: %v", forbidden, wrapped)
		}
	}
}

func TestNaabuInputCleanupFailureDoesNotPromoteDiscovery(t *testing.T) {
	naabu := writeNaabuFixture(t, `input=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-list" ]; then input="$2"; break; fi
  shift
done
[ -n "$input" ] || exit 41
rm -f "$input" || exit 42
mkdir "$input" || exit 43
printf residue > "$input/leftover"
printf '%s\\n' '{"ip":"192.0.2.1","port":443,"protocol":"tcp"}'
`)
	n := NewWithNaabu("missing-nmap", naabu)
	n.workDir = t.TempDir()
	options := testNaabuOptions()
	job := config.NormalizeJob(config.Job{
		Name: "input-cleanup", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{
			Engine: config.EngineNaabuNmap, Ports: "1-65535", Mode: "connect",
			Naabu: &options,
		},
	})
	targets := []resolvedTarget{{Name: "192.0.2.1", Addresses: []string{"192.0.2.1"}}}
	snapshot, err := n.scanNaabuDiscoveryResolved(context.Background(), job, targets, nil)
	if err == nil || !strings.Contains(err.Error(), "naabu target input cleanup failed") {
		t.Fatalf("discovery with failed input cleanup = %v, want lifecycle cleanup failure", err)
	}
	if IsConfigurationError(err) {
		t.Fatalf("input cleanup failure was classified as permanent configuration: %v", err)
	}
	if len(snapshot.Units) != 0 {
		t.Fatalf("failed discovery returned baseline units: %#v", snapshot.Units)
	}
	if len(snapshot.Hosts) != 1 || snapshot.Hosts[0].Address != "192.0.2.1" {
		t.Fatalf("failed discovery host evidence = %#v", snapshot.Hosts)
	}
	for _, host := range snapshot.Hosts {
		for _, protocol := range host.Protocols {
			if len(protocol.DiscoveredPorts) != 0 {
				t.Fatalf("cleanup-failed discovery retained positive ports: %#v", protocol.DiscoveredPorts)
			}
		}
	}

	entries, readErr := os.ReadDir(n.workDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var leftover string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "edgewatch-naabu-targets-") && entry.IsDir() {
			leftover = filepath.Join(n.workDir, entry.Name())
			break
		}
	}
	if leftover == "" {
		t.Fatalf("fixture did not leave the nonempty input directory in %s", n.workDir)
	}
	defer os.RemoveAll(leftover)
	if contents, readErr := os.ReadFile(filepath.Join(leftover, "leftover")); readErr != nil || string(contents) != "residue" {
		t.Fatalf("preserved failed-cleanup evidence = %q, %v", contents, readErr)
	}
}

func TestNmapXMLCleanupFailureIsReturned(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	writeScript(t, nmapPath, xmlOutputScript+`rm -f "$out" || exit 42
mkdir "$out" || exit 43
printf residue > "$out/leftover"
`)
	cmd := exec.Command(nmapPath, "-oX", "-", "192.0.2.1")
	_, _, err := runNmapInvocationWithProgressPollInterval(context.Background(), cmd, nil, dir, nil, nil, time.Hour, nil)
	if err == nil || !strings.Contains(err.Error(), "remove nmap XML output") {
		t.Fatalf("Nmap invocation with failed XML cleanup = %v, want cleanup error", err)
	}

	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var xmlPath string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "edgewatch-nmap-") && strings.HasSuffix(entry.Name(), ".xml") {
			xmlPath = filepath.Join(dir, entry.Name())
			break
		}
	}
	if xmlPath == "" {
		t.Fatal("fixture did not leave the failed-cleanup XML path")
	}
	defer os.RemoveAll(xmlPath)
	if info, statErr := os.Stat(xmlPath); statErr != nil || !info.IsDir() {
		t.Fatalf("failed-cleanup XML path info = %v, %v; want preserved nonempty directory", info, statErr)
	}
	if contents, readErr := os.ReadFile(filepath.Join(xmlPath, "leftover")); readErr != nil || string(contents) != "residue" {
		t.Fatalf("preserved XML cleanup evidence = %q, %v", contents, readErr)
	}
}

func TestNmapStartFailureRemovesPreparedXML(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing-nmap")
	cmd := exec.Command(missing, "-oX", "-", "192.0.2.1")
	_, _, err := runNmapInvocationWithProgressPollInterval(context.Background(), cmd, nil, dir, nil, nil, time.Hour, nil)
	if err == nil || !IsConfigurationError(err) {
		t.Fatalf("missing Nmap executable error = %v, want typed start failure", err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "edgewatch-nmap-") && strings.HasSuffix(entry.Name(), ".xml") {
			t.Fatalf("start failure left prepared XML path %q behind", entry.Name())
		}
	}
}

func TestNmapXMLPreparationFailureDoesNotStartScanner(t *testing.T) {
	dir := t.TempDir()
	outputDir := filepath.Join(dir, "missing-output-directory")
	started := filepath.Join(dir, "scanner-started")
	nmapPath := filepath.Join(dir, "nmap")
	writeScript(t, nmapPath, "#!/bin/sh\nprintf started > '"+started+"'\n")
	cmd := exec.Command(nmapPath, "-oX", "-", "192.0.2.1")
	_, _, err := runNmapInvocationWithProgressPollInterval(context.Background(), cmd, nil, outputDir, nil, nil, time.Hour, nil)
	if err == nil || !strings.Contains(err.Error(), "create nmap progress file") {
		t.Fatalf("Nmap with unavailable XML directory error = %v, want retryable preparation failure", err)
	}
	if IsConfigurationError(err) {
		t.Fatalf("XML preparation failure was classified as permanent configuration: %v", err)
	}
	if _, statErr := os.Stat(started); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Nmap started despite XML preparation failure: stat=%v", statErr)
	}
	if _, statErr := os.Stat(outputDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed XML preparation created the unavailable output directory: %v", statErr)
	}
}
