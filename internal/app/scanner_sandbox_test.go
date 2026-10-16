package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestNewWithOptionsInstallsTheScannerSandbox(t *testing.T) {
	t.Parallel()
	newApp := func(options Options) *App {
		t.Helper()
		s, err := store.Open(storetest.FreshPath(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
		a, err := NewWithOptions(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)), options)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	confined := newApp(Options{Sandbox: sandbox.NewEnforced()})
	if got := confined.ScannerSandbox(); got.State != sandbox.StateEnforced || got.UID != 0 || got.GID != 0 || got.ProcessUID != nil || got.IdentityPool == nil || got.IdentityPool.State != sandbox.StateEnforced {
		t.Fatalf("sandboxed application status = %+v, want pool status without a stable UID", got)
	}
	if _, ok := confined.Scanner.(*scanner.Nmap); !ok {
		t.Fatalf("scanner = %T, want the Nmap scanner that received the policy", confined.Scanner)
	}
	if got := newApp(Options{}).ScannerSandbox(); got.State != sandbox.StateDisabled {
		t.Fatalf("application without a policy reports %+v, want disabled", got)
	}
	notifying := newApp(Options{NotificationSandbox: sandbox.NewEnforcedFor(sandbox.Notifier)})
	if got := notifying.NotificationSandbox(); got.State != sandbox.StateEnforced || got.UID != sandbox.NotifierUID {
		t.Fatalf("notification sandbox status = %+v", got)
	}
	if got := newApp(Options{}).NotificationSandbox(); got.State != sandbox.StateDisabled {
		t.Fatalf("application without a notification policy reports %+v, want disabled", got)
	}
}

func TestNewWithoutScannerPolicyDoesNotProbeScannerBinaries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeVersionProbe := func(name, output string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' '"+output+"'\nprintf x >> \"${0}.called\"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	nmapPath := writeVersionProbe("nmap", "Nmap version 99.1")
	naabuPath := writeVersionProbe("naabu", "[INF] Current Version: 99.2")
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	newTestApp := func(options Options) *App {
		t.Helper()
		s, err := store.Open(storetest.FreshPath(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		a, err := newApp(context.Background(), cfg, s, nmapPath, naabuPath, slog.New(slog.NewTextHandler(io.Discard, nil)), options)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	unconfined := newTestApp(Options{})
	if nmap, naabu := unconfined.ScannerVersions(); nmap != "unknown" || naabu != "unknown" {
		t.Fatalf("versions without scanner policy = %q/%q, want unknown/unknown", nmap, naabu)
	}
	for _, path := range []string{nmapPath, naabuPath} {
		if _, err := os.Stat(path + ".called"); !os.IsNotExist(err) {
			t.Fatalf("scanner version probe ran without a policy for %s (stat error %v)", path, err)
		}
	}

	helperLog := filepath.Join(dir, "sandbox-exec.called")
	helperPath := filepath.Join(dir, "sandbox-exec")
	helper := "#!/bin/sh\nprintf x >> \"${0}.called\"\nwhile [ \"$#\" -gt 0 ] && [ \"$1\" != \"--\" ]; do shift; done\n[ \"$#\" -gt 0 ] || exit 2\nshift\nexec \"$@\"\n"
	if err := os.WriteFile(helperPath, []byte(helper), 0o700); err != nil {
		t.Fatal(err)
	}
	policy := (*sandbox.Policy)(nil).WithLandlock(helperPath, 6)
	confined := newTestApp(Options{Sandbox: policy})
	if nmap, naabu := confined.ScannerVersions(); nmap != "Nmap version 99.1" || naabu != "99.2" {
		t.Fatalf("versions with configured scanner policy = %q/%q, want fixture versions", nmap, naabu)
	}
	for _, path := range []string{nmapPath, naabuPath} {
		if _, err := os.Stat(path + ".called"); err != nil {
			t.Fatalf("configured scanner policy did not run %s through the helper: %v", path, err)
		}
	}
	if _, err := os.Stat(helperLog); err != nil {
		t.Fatalf("configured scanner policy did not invoke its helper: %v", err)
	}
	if calls, err := os.ReadFile(helperLog); err != nil || strings.Count(string(calls), "x") != 2 {
		t.Fatalf("scanner helper calls = %q, err=%v; want exactly two probes", calls, err)
	}
}

func TestScannerVersionsUsesUnknownForMissingCachedValues(t *testing.T) {
	var nilApp *App
	if nmap, naabu := nilApp.ScannerVersions(); nmap != "unknown" || naabu != "unknown" {
		t.Fatalf("nil application versions = %q/%q, want unknown/unknown", nmap, naabu)
	}

	app := &App{nmapVersion: "  ", naabuVersion: "\t"}
	if nmap, naabu := app.ScannerVersions(); nmap != "unknown" || naabu != "unknown" {
		t.Fatalf("empty cached versions = %q/%q, want unknown/unknown", nmap, naabu)
	}
	app.nmapVersion, app.naabuVersion = " Nmap version 7.99 ", " 7.99 "
	if nmap, naabu := app.ScannerVersions(); nmap != "Nmap version 7.99" || naabu != "7.99" {
		t.Fatalf("cached versions were not trimmed: %q/%q", nmap, naabu)
	}
}
