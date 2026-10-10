package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// pausingLogHandler holds the first log record with the message pause until
// release is closed, after it has closed reached. It holds the record before
// the wrapped handler writes it, so other records are written meanwhile.
type pausingLogHandler struct {
	slog.Handler
	pause            string
	reached, release chan struct{}
	once             *sync.Once
}

func (h pausingLogHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == h.pause {
		held := false
		h.once.Do(func() {
			close(h.reached)
			held = true
		})
		if held {
			<-h.release
		}
	}
	return h.Handler.Handle(ctx, record)
}

func (h pausingLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.Handler = h.Handler.WithAttrs(attrs)
	return h
}

func (h pausingLogHandler) WithGroup(name string) slog.Handler {
	h.Handler = h.Handler.WithGroup(name)
	return h
}

// freeLoopbackAddress returns a loopback address that nothing listens on.
func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

// getStartup sends a GET request to the daemon's listener.
func getStartup(t *testing.T, address, path, token string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "http://"+address+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return 0, err.Error()
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, strings.TrimSpace(string(body))
}

// The daemon opens its listener before it migrates the database. While the
// migration runs, GET /healthz answers 503 starting, /metrics reports the
// migration, and the console answers 503 starting; once the daemon has
// started, the same listener answers 200 ready and serves the console.
//
// The test is not parallel: it replaces commandContext, to stop the daemon,
// and wrapLogHandler, to hold the migration at its "database migration
// started" record, which the migration writes once it has recorded that it
// runs.
func TestDaemonAnswersHealthzWhileItMigrates(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "data", "edgewatch.db")
	address := freeLoopbackAddress(t)
	token := strings.Repeat("daemon-startup-token-", 2)
	tokenFile := filepath.Join(dir, "metrics.token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	contents := fmt.Sprintf("database: %s\nweb:\n  listen: %s\n  metrics:\n    enabled: true\n    token_file: %s\nupdates:\n  enabled: false\nenrichment:\n  rdap:\n    enabled: false\n", database, address, tokenFile)
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	reached, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseMigration := func() { releaseOnce.Do(func() { close(release) }) }
	previousContext, previousWrap := commandContext, wrapLogHandler
	commandContext = func() context.Context { return ctx }
	wrapLogHandler = func(handler slog.Handler) slog.Handler {
		return pausingLogHandler{Handler: handler, pause: "database migration started", reached: reached, release: release, once: &sync.Once{}}
	}
	done := make(chan error, 1)
	t.Cleanup(func() {
		releaseMigration()
		cancel()
		select {
		case <-done:
		case <-time.After(time.Minute):
			t.Error("the daemon did not stop")
		}
		commandContext, wrapLogHandler = previousContext, previousWrap
	})
	go func() { done <- run([]string{"daemon", "--config", configPath}) }()

	select {
	case <-reached:
	case err := <-done:
		done <- err
		t.Fatalf("the daemon stopped before it migrated: %v", err)
	case <-time.After(time.Minute):
		t.Fatal("the daemon did not start its migration")
	}
	if code, body := getStartup(t, address, "/healthz", ""); code != http.StatusServiceUnavailable || body != `{"status":"starting"}` {
		t.Errorf("GET /healthz while migrating = %d %s, want 503 starting", code, body)
	}
	if code, body := getStartup(t, address, "/api/v1/setup/status", ""); code != http.StatusServiceUnavailable || !strings.Contains(body, `"code":"starting"`) {
		t.Errorf("GET /api/v1/setup/status while migrating = %d %s, want 503 starting", code, body)
	}
	code, body := getStartup(t, address, "/metrics", token)
	if code != http.StatusOK || !strings.Contains(body, `edgewatch_migration_state{state="migrating"} 1`) || !strings.Contains(body, `edgewatch_health_status{status="starting"} 1`) {
		t.Errorf("GET /metrics while migrating = %d:\n%s", code, body)
	}

	releaseMigration()
	deadline := time.Now().Add(time.Minute)
	for {
		code, body := getStartup(t, address, "/healthz", "")
		if code == http.StatusOK && body == `{"status":"ready"}` {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET /healthz after the migration = %d %s, want 200 ready", code, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code, body := getStartup(t, address, "/api/v1/setup/status", ""); code != http.StatusOK {
		t.Errorf("GET /api/v1/setup/status after the start = %d %s", code, body)
	}
	cancel()
	select {
	case err := <-done:
		done <- err
		if err != nil {
			t.Errorf("daemon stopped with %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the daemon did not stop")
	}
}
