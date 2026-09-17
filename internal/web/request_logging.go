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

	"github.com/crypt0rr/edgewatch/internal/store"
)

const (
	requestIDHeader         = "X-Request-ID"
	slowRequestLogThreshold = time.Second
)

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
		clientIP := s.clientIP(r)
		ctx = store.WithAuditContext(ctx, requestID, clientIP)
		started := time.Now()
		wrapped := &requestLoggingWriter{ResponseWriter: w, status: http.StatusOK}

		logger.DebugContext(ctx, "http request started", "request_id", requestID, "client_ip", clientIP, "method", r.Method, "path", r.URL.Path)
		defer func(logCtx context.Context) {
			recovered := recover()
			if recovered != nil && !wrapped.wroteHeader {
				// Never reflect a panic value to the client. Panic strings often
				// contain request data or provider credentials; the response is
				// deliberately generic and the structured log records only its type.
				http.Error(wrapped, "internal server error", http.StatusInternalServerError)
			} else if recovered != nil {
				// Once headers have reached the peer net/http cannot change the
				// status code. Ask it to close the connection so a partial response
				// is not reused as a successful keep-alive response. HTTP/1 writers
				// that support Hijack are closed immediately; other transports use
				// the connection-close response hint.
				wrapped.Header().Set("Connection", "close")
				if hijacker, ok := wrapped.ResponseWriter.(http.Hijacker); ok {
					if connection, _, hijackErr := hijacker.Hijack(); hijackErr == nil {
						_ = connection.Close()
					}
				}
			}
			duration := time.Since(started)
			attributes := []any{
				"request_id", requestID,
				"client_ip", clientIP,
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.status,
				"bytes", wrapped.bytes,
				"duration_ms", duration.Seconds() * 1000,
			}
			if recovered != nil {
				attributes = append(attributes, "panic_type", fmt.Sprintf("%T", recovered), "stack", string(debug.Stack()))
				logger.ErrorContext(logCtx, "http request recovered panic", attributes...)
				return
			}
			// Successful, fast requests are useful while diagnosing a request but
			// are too noisy for the normal information log level (the UI polls
			// several endpoints regularly). Keep failures and slow requests visible
			// at info so an idle console cannot hide operational problems.
			if wrapped.status >= http.StatusBadRequest || duration >= slowRequestLogThreshold {
				logger.InfoContext(logCtx, "http request completed", attributes...)
				return
			}
			logger.DebugContext(logCtx, "http request completed", attributes...)
		}(ctx)
		next.ServeHTTP(wrapped, r.WithContext(ctx))
	})
}
