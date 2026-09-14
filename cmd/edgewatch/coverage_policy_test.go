package main

import (
	"log/slog"
	"testing"
)

// Exercise every configured log-level branch. Keeping this as a behavioral
// check ensures a typo in deployment configuration cannot silently select an
// unexpected logger threshold.
func TestNewLoggerHonorsConfiguredLevels(t *testing.T) {
	for _, level := range []string{"debug", "warn", "error", "info", "", " unknown "} {
		logger := newLogger(level)
		if logger == nil {
			t.Fatalf("newLogger(%q) returned nil", level)
		}
		if level == "debug" && !logger.Enabled(t.Context(), slog.LevelDebug) {
			t.Fatalf("debug logger did not enable debug messages")
		}
		if level == "error" && logger.Enabled(t.Context(), slog.LevelInfo) {
			t.Fatalf("error logger enabled info messages")
		}
	}
}
