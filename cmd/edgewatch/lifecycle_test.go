package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestRunComponentReturnsFunctionError(t *testing.T) {
	t.Parallel()
	errCh := make(chan error, 1)
	want := errors.New("component stopped")
	runComponent(errCh, slog.New(slog.NewTextHandler(io.Discard, nil)), "test", func() error {
		return want
	})
	if err := <-errCh; !errors.Is(err, want) {
		t.Fatalf("component result = %v, want %v", err, want)
	}
}

func TestRunComponentConvertsPanicsToErrors(t *testing.T) {
	t.Parallel()
	errCh := make(chan error, 1)
	runComponent(errCh, nil, "test", func() error {
		panic("boom")
	})
	if err := <-errCh; err == nil || err.Error() != "test component panicked: boom" {
		t.Fatalf("panic result = %v", err)
	}
}

func TestContextWithSignalsCleanupStopsWatcher(t *testing.T) {
	t.Parallel()
	parent, cancel := context.WithCancel(context.Background())
	ctx, cleanup := contextWithSignals(parent)
	cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("context was not cancelled")
	}
	cleanup()
}

func TestTerminationSignalsIncludeAHangupUnlessIgnored(t *testing.T) {
	t.Parallel()
	hangup := false
	for _, received := range terminationSignals() {
		if received == syscall.SIGHUP {
			hangup = true
		}
	}
	if hangup == signal.Ignored(syscall.SIGHUP) {
		t.Fatalf("termination signals %v include a hangup = %v, while hangups are ignored = %v", terminationSignals(), hangup, signal.Ignored(syscall.SIGHUP))
	}
}
