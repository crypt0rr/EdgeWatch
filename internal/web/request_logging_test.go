package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestLoggingRecordsCorrelationAndResponseMetrics(t *testing.T) {
	var output bytes.Buffer
	server := &Server{Log: slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	handler := server.requestLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if RequestID(r.Context()) == "" {
			t.Fatal("request context did not contain a request ID")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs?secret=not-logged", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d", recorder.Code)
	}
	requestID := recorder.Header().Get(requestIDHeader)
	if len(requestID) != 32 {
		t.Fatalf("request ID = %q, want 32 hex characters", requestID)
	}
	if strings.Contains(output.String(), "secret=not-logged") {
		t.Fatal("request query string was logged")
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("log lines = %d, want debug start and one completion line: %s", len(lines), output.String())
	}
	var completion map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &completion); err != nil {
		t.Fatal(err)
	}
	if completion["request_id"] != requestID || completion["client_ip"] != "192.0.2.10" || completion["method"] != http.MethodPost || completion["path"] != "/api/v1/jobs" || completion["status"] != float64(http.StatusCreated) || completion["bytes"] != float64(2) {
		t.Fatalf("completion record = %#v", completion)
	}
}

func TestRequestLoggingAddsCorrelationToErrorResponses(t *testing.T) {
	server := &Server{Log: slog.Default()}
	handler := server.requestLogging(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusBadRequest, "invalid", "invalid request", nil)
	}))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/error", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	handler.ServeHTTP(recorder, request)
	if recorder.Header().Get(requestIDHeader) == "" {
		t.Fatal("error response did not include request ID header")
	}
}

func TestRequestLoggingLevelControlsRoutineLines(t *testing.T) {
	for _, test := range []struct {
		name       string
		level      slog.Level
		wantLines  int
		wantStarts bool
	}{
		{name: "warn suppresses routine request logs", level: slog.LevelWarn, wantLines: 0},
		{name: "debug includes request start", level: slog.LevelDebug, wantLines: 2, wantStarts: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			server := &Server{Log: slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: test.level}))}
			handler := server.requestLogging(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))
			lines := strings.TrimSpace(output.String())
			if lines == "" {
				if test.wantLines != 0 {
					t.Fatalf("no logs, want %d", test.wantLines)
				}
				return
			}
			if got := len(strings.Split(lines, "\n")); got != test.wantLines {
				t.Fatalf("log lines = %d, want %d: %s", got, test.wantLines, lines)
			}
		})
	}
}

func TestRequestLoggingRecoversPanicIntoStructuredError(t *testing.T) {
	var output bytes.Buffer
	server := &Server{Log: slog.New(slog.NewJSONHandler(&output, nil))}
	handler := server.requestLogging(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(errors.New("boom")) }))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/panic", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("panic response status = %d", recorder.Code)
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output.String())), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["level"] != "ERROR" || entry["request_id"] != recorder.Header().Get(requestIDHeader) || entry["status"] != float64(http.StatusInternalServerError) {
		t.Fatalf("panic record = %#v", entry)
	}
}
