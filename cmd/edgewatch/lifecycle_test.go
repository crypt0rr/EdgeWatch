package main

import (
	"io"
	"log/slog"
	"testing"
)

func TestRunComponentConvertsPanicsToErrors(t *testing.T) {
	errCh := make(chan error, 1)
	runComponent(errCh, slog.New(slog.NewTextHandler(io.Discard, nil)), "test", func() error {
		panic("boom")
	})
	if err := <-errCh; err == nil || err.Error() != "test component panicked: boom" {
		t.Fatalf("panic result = %v", err)
	}
}
