package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

// Exercise every configured log-level branch. Keeping this as a behavioral
// check ensures a typo in deployment configuration cannot silently select an
// unexpected logger threshold.
func TestNewLoggerHonorsConfiguredLevels(t *testing.T) {
	for _, level := range []string{"debug", "warn", "error", "info", "", " unknown "} {
		logger := newLogger(level, nil)
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

// A configured deployment timezone must control daemon log timestamps, while an
// omitted setting keeps the process timezone used before the option existed.
func TestNewLoggerFormatsTimestampsInDeploymentTimezone(t *testing.T) {
	// Kathmandu has a fixed +05:45 offset, so this cannot pass by accident on a
	// host whose process timezone already matches the configured zone.
	kathmandu, err := time.LoadLocation("Asia/Kathmandu")
	if err != nil {
		t.Fatal(err)
	}
	offset := func(value time.Time) int {
		_, seconds := value.Zone()
		return seconds
	}
	var output bytes.Buffer
	newLoggerTo(&output, "info", kathmandu).Info("timezone check", "at", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("log output is not JSON: %v: %s", err, output.String())
	}
	stamp, err := time.Parse(time.RFC3339Nano, record["time"].(string))
	if err != nil {
		t.Fatalf("log time %v: %v", record["time"], err)
	}
	if offset(stamp) != 5*3600+45*60 {
		t.Fatalf("log time %q does not use the configured timezone offset", record["time"])
	}
	// Only the record timestamp is rewritten; time-valued attributes keep the
	// value supplied by the caller.
	if record["at"] != "2026-01-02T03:04:05Z" {
		t.Fatalf("time attribute = %v, want the caller-supplied UTC value", record["at"])
	}

	output.Reset()
	newLoggerTo(&output, "info", nil).Info("process timezone")
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("log output is not JSON: %v: %s", err, output.String())
	}
	if stamp, err = time.Parse(time.RFC3339Nano, record["time"].(string)); err != nil {
		t.Fatalf("log time %v: %v", record["time"], err)
	}
	if offset(stamp) != offset(stamp.In(time.Local)) {
		t.Fatalf("log time %q does not keep the process timezone when none is configured", record["time"])
	}
}
