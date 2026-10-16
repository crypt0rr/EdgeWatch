package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func daemonMigrationFailure(t *testing.T, database string) (state, phase, lastError string) {
	t.Helper()
	reader, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := reader.DB.QueryRow(`SELECT state,phase,last_error FROM startup_state WHERE id=1`).Scan(&state, &phase, &lastError); err != nil {
		t.Fatal(err)
	}
	return state, phase, lastError
}

// A daemon interrupted during a schema upgrade must return at the last
// committed schema step, record the cancellation, and resume from that
// checkpoint on its next start. Pausing the migration's completed-step log
// lets the test cancel the real run daemon command after the checkpoint has
// committed but before the next step begins.
func TestDaemonCancellationDuringSchemaMigrationResumesFromCheckpoint(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "data", "edgewatch.db")
	if err := os.MkdirAll(filepath.Dir(database), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(database, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	targetVersion := sqliteUserVersion(t, database)
	const checkpoint = 60
	if targetVersion <= checkpoint+1 {
		t.Fatalf("fixture schema version %d cannot exercise migration after checkpoint %d", targetVersion, checkpoint)
	}
	setSQLiteUserVersion(t, database, checkpoint)
	configPath := writeDaemonLeaseConfig(t, dir, database)

	ctx, cancel := context.WithCancel(context.Background())
	reached, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseMigration := func() { releaseOnce.Do(func() { close(release) }) }
	previousContext, previousWrap := commandContext, wrapLogHandler
	commandContext = func() context.Context { return ctx }
	wrapLogHandler = func(slog.Handler) slog.Handler {
		return pausingLogHandler{Handler: slog.NewTextHandler(io.Discard, nil), pause: "database migration step completed", reached: reached, release: release, once: &sync.Once{}}
	}
	done := make(chan error, 1)
	finished, restored := false, false
	restoreHooks := func() {
		if restored {
			return
		}
		commandContext, wrapLogHandler = previousContext, previousWrap
		restored = true
	}
	t.Cleanup(func() {
		releaseMigration()
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Error("daemon did not stop after the migration test was released and canceled")
			}
		}
		restoreHooks()
	})
	go func() { done <- run([]string{"daemon", "--config", configPath}) }()
	select {
	case <-reached:
	case err := <-done:
		finished = true
		t.Fatalf("daemon stopped before the first migration checkpoint: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("daemon did not reach a completed schema migration step")
	}

	canceledAt := time.Now()
	cancel()
	releaseMigration()
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatalf("daemon run returned %v after command cancellation, want clean cancellation", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("daemon did not return promptly after migration cancellation")
	}
	if elapsed := time.Since(canceledAt); elapsed > 30*time.Second {
		t.Fatalf("daemon returned %s after cancellation, want under 30s", elapsed)
	}
	commandContext = previousContext
	wrapLogHandler = func(slog.Handler) slog.Handler { return slog.NewTextHandler(io.Discard, nil) }

	if got := sqliteUserVersion(t, database); got != checkpoint+1 {
		t.Fatalf("user_version after cancellation = %d, want last committed checkpoint %d (target %d)", got, checkpoint+1, targetVersion)
	}
	state, phase, lastError := daemonMigrationFailure(t, database)
	if state != "failed" || phase != "" || !strings.Contains(lastError, "context canceled") {
		t.Fatalf("startup_state after cancellation = state %q phase %q last_error %q, want failed, empty phase, and context canceled", state, phase, lastError)
	}

	// The configured listener is deliberately occupied, so a successful
	// migration reaches the normal listener error without leaving a daemon
	// running in this test process.
	err = run([]string{"daemon", "--config", configPath})
	if err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("second daemon start error = %v, want the occupied listener after resuming migration", err)
	}
	if got := sqliteUserVersion(t, database); got != targetVersion {
		t.Fatalf("user_version after resume = %d, want target schema %d", got, targetVersion)
	}
	state, phase, lastError = daemonMigrationFailure(t, database)
	if state != "ready" || phase != "" || lastError != "" {
		t.Fatalf("startup_state after resumed migration = state %q phase %q last_error %q, want ready with no error", state, phase, lastError)
	}
	restoreHooks()
}
