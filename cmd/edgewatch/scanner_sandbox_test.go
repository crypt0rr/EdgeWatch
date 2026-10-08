package main

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/sandbox"
)

func TestDaemonRefusesARequiredSandboxBeforeOpeningTheDatabase(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\nscanner:\n  sandbox: required\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A test process can never confine scanner processes, so a required
	// sandbox must stop the daemon before it creates or migrates anything.
	err := run([]string{"daemon", "--config", configPath})
	if !errors.Is(err, sandbox.ErrUnavailable) || !strings.Contains(err.Error(), "set scanner.sandbox to auto") {
		t.Fatalf("daemon with a required sandbox = %v, want ErrUnavailable", err)
	}
	if _, statErr := os.Stat(database); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("refused daemon left a database behind: %v", statErr)
	}
}

func TestScannerSandboxWarningsOnlyForUnconfinedRoot(t *testing.T) {
	t.Parallel()
	unavailable := sandbox.Status{Mode: sandbox.ModeAuto, State: sandbox.StateUnavailable, ProcessUID: 0, Reason: "the container does not grant KILL"}
	if got := scannerSandboxWarnings(unavailable); len(got) != 1 || got[0] != "scanner processes run unconfined as UID 0: the container does not grant KILL" {
		t.Fatalf("root warnings = %q", got)
	}
	notRoot := unavailable
	notRoot.ProcessUID = 1000
	for name, status := range map[string]sandbox.Status{
		"not root": notRoot,
		"enforced": {State: sandbox.StateEnforced, ProcessUID: sandbox.UID},
		"disabled": {State: sandbox.StateDisabled},
	} {
		if got := scannerSandboxWarnings(status); len(got) != 0 {
			t.Errorf("%s warnings = %q, want none", name, got)
		}
	}
}

func TestLogScannerSandboxNamesTheOutcome(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		status sandbox.Status
		want   string
	}{
		"enforced":         {status: sandbox.NewEnforced().Status(), want: `"level":"INFO","msg":"scanner processes are sandboxed","uid":65532`},
		"unavailable root": {status: sandbox.Status{State: sandbox.StateUnavailable, Reason: "no KILL"}, want: `"level":"WARN","msg":"scanner processes run unconfined as UID 0; see the container hardening guide","reason":"no KILL"`},
		"unavailable user": {status: sandbox.Status{State: sandbox.StateUnavailable, ProcessUID: 1000, Reason: "not root"}, want: `"level":"INFO","msg":"scanner processes run as the daemon's user","uid":1000`},
		"off":              {status: sandbox.Status{State: sandbox.StateDisabled}, want: `"msg":"scanner sandbox is off; scanner processes run unconfined"`},
	} {
		var output bytes.Buffer
		logScannerSandbox(slog.New(slog.NewJSONHandler(&output, nil)), test.status)
		if !strings.Contains(output.String(), test.want) {
			t.Errorf("%s log = %s, want %s", name, output.String(), test.want)
		}
	}
}
