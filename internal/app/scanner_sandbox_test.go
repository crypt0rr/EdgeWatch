package app

import (
	"io"
	"log/slog"
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
	if got := confined.ScannerSandbox(); got.State != sandbox.StateEnforced || got.UID != sandbox.UID {
		t.Fatalf("sandboxed application status = %+v", got)
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
