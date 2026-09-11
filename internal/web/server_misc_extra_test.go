package web

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/webui"
)

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
	addr   net.Addr
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn, 1), closed: make(chan struct{}), addr: pipeAddr("edgewatch-test")}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return l.addr }

type deadlineTrackingWriter struct {
	header   http.Header
	body     bytes.Buffer
	deadline time.Time
	status   int
}

func (w *deadlineTrackingWriter) Header() http.Header { return w.header }

func (w *deadlineTrackingWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(data)
}

func (w *deadlineTrackingWriter) WriteHeader(status int) { w.status = status }
func (w *deadlineTrackingWriter) Flush()                 {}

func (w *deadlineTrackingWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

func TestServeListenerWriteDeadlineReleasesStalledReader(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	server.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	server.writeTimeout = 30 * time.Millisecond
	listener := newPipeListener()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	released := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1<<20))
		close(released)
	})
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.serveListener(ctx, listener, listener.Addr().String(), handler) }()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	listener.conns <- serverConn
	requestDone := make(chan struct{})
	go func() {
		_, _ = clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"))
		close(requestDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("stalled response did not honor the write deadline")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("request writer did not finish")
	}
	_ = clientConn.Close()
	_ = serverConn.Close()
	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("server returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not shut down after stalled response")
	}
}

func TestStreamClearsServerWriteDeadline(t *testing.T) {
	server, _, session := newUsersTestServer(t)
	writer := &deadlineTrackingWriter{header: make(http.Header)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil).WithContext(ctx)
	server.stream(writer, request, session)
	if !writer.deadline.IsZero() {
		t.Fatalf("SSE write deadline = %v, want cleared", writer.deadline)
	}
}

func waitForSSESubscribers(t *testing.T, server *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.mu.Lock()
		got := len(server.subscribers)
		server.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	server.mu.Lock()
	got := len(server.subscribers)
	server.mu.Unlock()
	t.Fatalf("SSE subscriber count = %d, want %d", got, want)
}

func startTestSSEStream(server *Server, session store.Session) (context.CancelFunc, <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil).WithContext(ctx)
	response := &deadlineTrackingWriter{header: make(http.Header)}
	done := make(chan struct{})
	go func() {
		server.stream(response, request, session)
		close(done)
	}()
	return cancel, done
}

func TestSSESubscriberLimits(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	server.sseMaxSubscribers = 2
	server.sseMaxSubscribersPerUser = 10
	cancelA, doneA := startTestSSEStream(server, store.Session{IDHash: "session-a", UserID: "user-a"})
	cancelB, doneB := startTestSSEStream(server, store.Session{IDHash: "session-b", UserID: "user-b"})
	waitForSSESubscribers(t, server, 2)
	limited := &deadlineTrackingWriter{header: make(http.Header)}
	limitedCtx, limitedCancel := context.WithCancel(context.Background())
	limitedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil).WithContext(limitedCtx)
	limitedDone := make(chan struct{})
	go func() {
		server.stream(limited, limitedRequest, store.Session{IDHash: "session-c", UserID: "user-c"})
		close(limitedDone)
	}()
	select {
	case <-limitedDone:
	case <-time.After(time.Second):
		limitedCancel()
		t.Fatal("global SSE limit did not refuse a new stream")
	}
	limitedCancel()
	if limited.status != http.StatusOK || limited.header.Get("Content-Type") != "text/event-stream" || limited.header.Get("Retry-After") != "5" || !bytes.Contains(limited.body.Bytes(), []byte(`"type":"stream_limit"`)) {
		t.Fatalf("global SSE limit response = status %d content-type %q retry-after %q body %q", limited.status, limited.header.Get("Content-Type"), limited.header.Get("Retry-After"), limited.body.String())
	}
	cancelA()
	cancelB()
	select {
	case <-doneA:
	case <-time.After(time.Second):
		t.Fatal("first SSE stream did not close")
	}
	select {
	case <-doneB:
	case <-time.After(time.Second):
		t.Fatal("second SSE stream did not close")
	}

	server.sseMaxSubscribers = 10
	server.sseMaxSubscribersPerUser = 2
	cancelOne, doneOne := startTestSSEStream(server, store.Session{IDHash: "same-session", UserID: "user"})
	cancelTwo, doneTwo := startTestSSEStream(server, store.Session{IDHash: "same-session", UserID: "user"})
	waitForSSESubscribers(t, server, 2)
	perSession := &deadlineTrackingWriter{header: make(http.Header)}
	perSessionCtx, perSessionCancel := context.WithCancel(context.Background())
	perSessionRequest := httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil).WithContext(perSessionCtx)
	perSessionDone := make(chan struct{})
	go func() {
		server.stream(perSession, perSessionRequest, store.Session{IDHash: "same-session", UserID: "user"})
		close(perSessionDone)
	}()
	select {
	case <-perSessionDone:
	case <-time.After(time.Second):
		perSessionCancel()
		t.Fatal("per-session SSE limit did not refuse a new stream")
	}
	perSessionCancel()
	if perSession.status != http.StatusOK || perSession.header.Get("Content-Type") != "text/event-stream" || perSession.header.Get("Retry-After") != "5" || !bytes.Contains(perSession.body.Bytes(), []byte(`"type":"stream_limit"`)) {
		t.Fatalf("per-session SSE limit response = status %d content-type %q retry-after %q body %q", perSession.status, perSession.header.Get("Content-Type"), perSession.header.Get("Retry-After"), perSession.body.String())
	}
	cancelOne()
	cancelTwo()
	select {
	case <-doneOne:
	case <-time.After(time.Second):
		t.Fatal("per-session first stream did not close")
	}
	select {
	case <-doneTwo:
	case <-time.After(time.Second):
		t.Fatal("per-session second stream did not close")
	}
}

func TestSSEStreamsCloseOnShutdownSignal(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	cancel, done := startTestSSEStream(server, store.Session{IDHash: "shutdown-session", UserID: "user"})
	defer cancel()
	waitForSSESubscribers(t, server, 1)
	server.signalShutdown()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SSE stream did not close after shutdown signal")
	}
	server.mu.Lock()
	remaining := len(server.subscribers)
	server.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("SSE subscribers after shutdown = %d, want 0", remaining)
	}
}

func TestServeListenerWaitsForGracefulShutdown(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	server.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.serveListener(ctx, listener, listener.Addr().String(), handler)
	}()
	clientDone := make(chan error, 1)
	go func() {
		response, requestErr := http.Get("http://" + listener.Addr().String())
		if requestErr == nil {
			response.Body.Close()
		}
		clientDone <- requestErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("slow handler did not start")
	}
	cancel()
	// The production server is shutting down, but the listener must remain
	// joined until the in-flight handler has drained.
	select {
	case err := <-serveDone:
		t.Fatalf("server returned before handler drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-clientDone:
		if err != nil {
			t.Fatalf("slow request failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow request did not finish")
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("graceful server shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not finish after the handler drained")
	}
}

func TestServerStaticSSEAndAuditHelpers(t *testing.T) {
	server, _, session := newUsersTestServer(t)
	server.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := server.ListenAndServe(context.Background(), "not-a-listener"); err == nil {
		t.Fatal("invalid listener address was accepted")
	}

	server.broadcast(map[string]any{"type": "first"})
	server.broadcast(map[string]any{"type": "second"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil).WithContext(ctx)
	request.Header.Set("Last-Event-ID", "1")
	streamResponse := httptest.NewRecorder()
	server.stream(streamResponse, request, session)
	if streamResponse.Code != http.StatusOK || streamResponse.Header().Get("Content-Type") != "text/event-stream" || !bytes.Contains(streamResponse.Body.Bytes(), []byte("second")) {
		t.Fatalf("stream response = %d %s %q", streamResponse.Code, streamResponse.Header().Get("Content-Type"), streamResponse.Body.String())
	}
	var message bytes.Buffer
	writeSSEMessage(&message, sseMessage{id: 7, payload: []byte(`{"type":"test"}`)})
	if message.String() != "id: 7\ndata: {\"type\":\"test\"}\n\n" {
		t.Fatalf("SSE message = %q", message.String())
	}

	assetResponse := httptest.NewRecorder()
	server.asset(assetResponse, httptest.NewRequest(http.MethodGet, "/assets/does-not-exist", nil))
	if assetResponse.Code != http.StatusNotFound {
		t.Fatalf("missing asset status = %d", assetResponse.Code)
	}
	directoryResponse := httptest.NewRecorder()
	server.asset(directoryResponse, httptest.NewRequest(http.MethodGet, "/assets/", nil))
	if directoryResponse.Code != http.StatusNotFound {
		t.Fatalf("asset directory status = %d, want 404", directoryResponse.Code)
	}
	entries, err := fs.ReadDir(webui.Files(), "dist/assets")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("embedded assets directory: %v", err)
	}
	if err == nil {
		if len(entries) == 0 {
			t.Fatal("embedded assets directory is empty")
		}
		knownName := ""
		for _, entry := range entries {
			if !entry.IsDir() && entry.Name() != ".gitkeep" {
				knownName = entry.Name()
				break
			}
		}
		if knownName == "" {
			t.Fatal("embedded assets directory has no build output")
		}
		knownAsset := httptest.NewRecorder()
		server.asset(knownAsset, httptest.NewRequest(http.MethodGet, "/assets/"+knownName, nil))
		if knownAsset.Code != http.StatusOK || knownAsset.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("known asset response = %d, cache-control=%q", knownAsset.Code, knownAsset.Header().Get("Cache-Control"))
		}
	}
	spaResponse := httptest.NewRecorder()
	server.spa(spaResponse, httptest.NewRequest(http.MethodGet, "/", nil))
	if spaResponse.Code != http.StatusOK || spaResponse.Header().Get("Cache-Control") != "no-cache" || !bytes.Contains(spaResponse.Body.Bytes(), []byte("EdgeWatch")) {
		t.Fatalf("SPA response = %d cache-control=%q %q", spaResponse.Code, spaResponse.Header().Get("Cache-Control"), spaResponse.Body.String())
	}
	apiResponse := httptest.NewRecorder()
	server.spa(apiResponse, httptest.NewRequest(http.MethodGet, "/api/v1/missing", nil))
	if apiResponse.Code != http.StatusNotFound {
		t.Fatalf("SPA API fallback status = %d", apiResponse.Code)
	}
	pathResponse := httptest.NewRecorder()
	server.spa(pathResponse, httptest.NewRequest(http.MethodGet, "/unknown-route", nil))
	if pathResponse.Code != http.StatusOK {
		t.Fatalf("SPA route status = %d", pathResponse.Code)
	}

	auditResponse := httptest.NewRecorder()
	if !server.requireAudit(context.Background(), auditResponse, "test.action", "safe detail") || auditResponse.Code != http.StatusOK {
		t.Fatalf("required audit response = %d", auditResponse.Code)
	}
	server.auditOptional(context.Background(), "test.optional", "safe detail")
	server.auditOptionalEntry(context.Background(), store.AuditEntry{Action: "test.optional.entry", Detail: "safe detail"})
}
