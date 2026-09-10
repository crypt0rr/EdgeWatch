package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"
)

const requestIDHeader = "X-Request-ID"

type requestIDContextKey struct{}

var requestIDFallbackCounter atomic.Uint64

// RequestID returns the correlation ID assigned by the web middleware. It is
// useful to handlers and future integrations that need to add the ID to an
// audit or downstream log entry without trusting a client-supplied header.
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	return value
}

func newRequestID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	// crypto/rand is expected to be available on supported hosts. A timestamp
	// fallback keeps the request observable if the OS entropy source is
	// temporarily unavailable, while preserving uniqueness for concurrent
	// requests through the monotonic clock component.
	return fmt.Sprintf("fallback-%x-%x", time.Now().UnixNano(), requestIDFallbackCounter.Add(1))
}

type requestLoggingWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (w *requestLoggingWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *requestLoggingWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	count, err := w.ResponseWriter.Write(data)
	w.bytes += int64(count)
	return count, err
}

// Flush keeps server-sent events working through the response wrapper. The
// concrete net/http writer used by the daemon supports flushing; the check
// still keeps the wrapper safe for unit-test writers and custom transports.
func (w *requestLoggingWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap lets http.ResponseController reach optional capabilities such as
// write-deadline control that are not declared directly by ResponseWriter.
func (w *requestLoggingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) requestLogging(next http.Handler) http.Handler {
	logger := s.Log
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := newRequestID()
		w.Header().Set(requestIDHeader, requestID)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
		started := time.Now()
		wrapped := &requestLoggingWriter{ResponseWriter: w, status: http.StatusOK}

		logger.DebugContext(ctx, "http request started", "request_id", requestID, "method", r.Method, "path", r.URL.Path)
		defer func(logCtx context.Context) {
			recovered := recover()
			if recovered != nil && !wrapped.wroteHeader {
				http.Error(wrapped, "internal server error", http.StatusInternalServerError)
			}
			attributes := []any{
				"request_id", requestID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.status,
				"bytes", wrapped.bytes,
				"duration_ms", time.Since(started).Seconds() * 1000,
			}
			if recovered != nil {
				attributes = append(attributes, "panic", fmt.Sprint(recovered), "stack", string(debug.Stack()))
				logger.ErrorContext(logCtx, "http request recovered panic", attributes...)
				return
			}
			logger.InfoContext(logCtx, "http request completed", attributes...)
		}(ctx)
		next.ServeHTTP(wrapped, r.WithContext(ctx))
	})
}
