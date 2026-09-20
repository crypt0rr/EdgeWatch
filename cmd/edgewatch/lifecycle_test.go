package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestRunComponentReturnsFunctionError(t *testing.T) {
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
	errCh := make(chan error, 1)
	runComponent(errCh, nil, "test", func() error {
		panic("boom")
	})
	if err := <-errCh; err == nil || err.Error() != "test component panicked: boom" {
		t.Fatalf("panic result = %v", err)
	}
}

func TestContextWithSignalsCleanupStopsWatcher(t *testing.T) {
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
