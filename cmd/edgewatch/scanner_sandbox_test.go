package main

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
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

func TestDaemonRefusesARequiredLandlockBeforeOpeningTheDatabase(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\nscanner:\n  landlock: required\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A test binary never starts scanner processes through sandbox-exec.
	err := run([]string{"scan", "--config", configPath, "--job", "missing"})
	if !errors.Is(err, sandbox.ErrUnavailable) || !strings.Contains(err.Error(), "set scanner.landlock to auto") {
		t.Fatalf("scan with a required Landlock = %v, want ErrUnavailable", err)
	}
	if _, statErr := os.Stat(database); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("refused scan left a database behind: %v", statErr)
	}
}

func TestSandboxExecIsHandledBeforeFlagParsing(t *testing.T) {
	t.Parallel()
	// The scanner's own flags must reach sandbox-exec untouched; flag
	// parsing would reject them. Malformed arguments get its usage.
	err := run([]string{sandbox.ExecCommand, "--config", "x", "-oX", "-"})
	if err == nil || !strings.Contains(err.Error(), "usage: sandbox-exec --profile scanner|notifier --files N [--tmp] [--seccomp] -- PROGRAM") {
		t.Fatalf("sandbox-exec = %v, want its usage", err)
	}
}

func TestScannerSandboxOptionsProbeNmap(t *testing.T) {
	t.Parallel()
	options := scannerSandboxOptions(&config.Config{Scanner: config.ScannerConfig{Sandbox: "required", Landlock: "off"}}, "/opt/nmap")
	if options.Mode != "required" || options.Landlock != "off" || len(options.Probes) != 1 || strings.Join(options.Probes[0].Args, " ") != "/opt/nmap --version" || options.Probes[0].Self {
		t.Fatalf("sandbox options = %+v", options)
	}
}

func TestNotificationSandboxOptionsCheckTheChildTrust(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", "/run/secrets/corp-ca.pem")
	for mode, landlock := range map[string]string{"": sandbox.ModeAuto, "required": sandbox.ModeAuto, " OFF ": sandbox.ModeOff} {
		options := notificationSandboxOptions(&config.Config{Notifications: config.Notifications{Sandbox: mode}})
		if options.Profile != sandbox.Notifier || options.Mode != mode || options.Landlock != landlock {
			t.Fatalf("%q options = %+v", mode, options)
		}
		check := options.IdentityProbe
		if !check.Self || strings.Join(check.Args, " ") != "notify-check" || len(options.Probes) != 1 || options.Probes[0].Name != check.Name {
			t.Fatalf("%q probes = %+v, %+v", mode, check, options.Probes)
		}
		// The check runs in the child's environment, with its certificate
		// authority variables.
		if !slices.Contains(check.Env, "SSL_CERT_FILE=/run/secrets/corp-ca.pem") {
			t.Fatalf("%q probe environment = %q", mode, check.Env)
		}
	}
}

func TestNotifyCheckReadsTheCertificateAuthorities(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.pem")
	t.Setenv("SSL_CERT_FILE", missing)
	t.Setenv("SSL_CERT_DIR", "")
	// Go skips a missing file, so the child trusts what the daemon does.
	if err := run([]string{"notify-check"}); err != nil {
		t.Fatalf("notify-check with a missing file = %v", err)
	}
	directory := filepath.Join(t.TempDir(), "unreadable")
	if err := os.Mkdir(directory, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("UID 0 reads any directory")
	}
	t.Setenv("SSL_CERT_DIR", directory)
	if err := run([]string{"notify-check"}); err == nil || !strings.Contains(err.Error(), "read SSL_CERT_DIR") {
		t.Fatalf("notify-check with an unreadable directory = %v", err)
	}
}

func TestScannerSandboxWarningsOnlyForUnconfinedRoot(t *testing.T) {
	t.Parallel()
	unavailable := sandbox.Status{Mode: sandbox.ModeAuto, State: sandbox.StateUnavailable, ProcessUID: 0, Reason: "the container does not grant KILL"}
	if got := scannerSandboxWarnings(unavailable); len(got) != 1 || got[0] != "scanner processes run unconfined as UID 0: the container does not grant KILL" {
		t.Fatalf("root warnings = %q", got)
	}
	restricted := unavailable
	restricted.Landlock = sandbox.LandlockStatus{State: sandbox.StateEnforced, ABI: 6}
	if got := scannerSandboxWarnings(restricted); len(got) != 1 || got[0] != "scanner processes run as UID 0, restricted only by Landlock: the container does not grant KILL" {
		t.Fatalf("root warnings with Landlock = %q", got)
	}
	if got := notificationSandboxWarnings(unavailable); len(got) != 1 || got[0] != "the notification process runs unconfined as UID 0: the container does not grant KILL" {
		t.Fatalf("notification root warnings = %q", got)
	}
	if got := notificationSandboxWarnings(restricted); len(got) != 1 || got[0] != "the notification process runs as UID 0, restricted only by Landlock: the container does not grant KILL" {
		t.Fatalf("notification root warnings with Landlock = %q", got)
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

func TestLogNotificationSandboxNamesTheOutcome(t *testing.T) {
	t.Parallel()
	restricted := sandbox.LandlockStatus{State: sandbox.StateEnforced, ABI: 6}
	for name, test := range map[string]struct {
		status sandbox.Status
		want   string
	}{
		"enforced":                {status: sandbox.NewEnforcedFor(sandbox.Notifier).WithLandlock("/usr/local/bin/edgewatch", 6).Status(), want: `"level":"INFO","msg":"the notification process is sandboxed","uid":65531,"gid":65531,"landlock":"enforced","landlock_reason":"","seccomp":"unavailable"`},
		"root with Landlock only": {status: sandbox.Status{State: sandbox.StateUnavailable, Reason: "no KILL", Landlock: restricted}, want: `"level":"WARN","msg":"the notification process runs as UID 0, restricted only by Landlock; see the container hardening guide","reason":"no KILL"`},
		"unavailable root":        {status: sandbox.Status{State: sandbox.StateUnavailable, Reason: "no KILL"}, want: `"level":"WARN","msg":"the notification process runs unconfined as UID 0; see the container hardening guide","reason":"no KILL"`},
		"unavailable user":        {status: sandbox.Status{State: sandbox.StateUnavailable, ProcessUID: 1000, Reason: "not root", Landlock: restricted}, want: `"level":"INFO","msg":"the notification process runs as the daemon's user","uid":1000,"reason":"not root","landlock":"enforced"`},
		"off":                     {status: sandbox.Status{State: sandbox.StateDisabled}, want: `"msg":"notification sandbox is off; the notification process runs unconfined"`},
	} {
		var output bytes.Buffer
		logNotificationSandbox(slog.New(slog.NewJSONHandler(&output, nil)), test.status)
		if !strings.Contains(output.String(), test.want) {
			t.Errorf("%s log = %s, want %s", name, output.String(), test.want)
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
		"root with Landlock only": {
			status: sandbox.Status{State: sandbox.StateUnavailable, Reason: "no KILL", Landlock: sandbox.LandlockStatus{State: sandbox.StateEnforced, ABI: 6}},
			want:   `"level":"WARN","msg":"scanner processes run as UID 0, restricted only by Landlock; see the container hardening guide","reason":"no KILL"`,
		},
		"Landlock": {status: sandbox.NewEnforced().WithLandlock("/usr/local/bin/edgewatch", 6).WithSeccomp().Status(), want: `"level":"INFO","msg":"scanner processes are restricted with Landlock","abi":6,"seccomp":"enforced"`},
		"no Landlock": {
			status: sandbox.Status{State: sandbox.StateEnforced, Landlock: sandbox.LandlockStatus{State: sandbox.StateUnavailable, Reason: "old kernel"}},
			want:   `"level":"INFO","msg":"scanner processes start without Landlock","reason":"old kernel"`,
		},
		"Landlock off": {status: sandbox.NewEnforced().Status(), want: `"msg":"scanner.landlock is off; scanner processes start without Landlock"`},
	} {
		var output bytes.Buffer
		logScannerSandbox(slog.New(slog.NewJSONHandler(&output, nil)), test.status)
		if !strings.Contains(output.String(), test.want) {
			t.Errorf("%s log = %s, want %s", name, output.String(), test.want)
		}
	}
}
