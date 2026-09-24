package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// startCookieSSEStream exercises the complete stream handler while keeping the
// response in memory. The cookie is important: stream() only performs its
// pre-write authorization re-check for a network-authenticated request.
func startCookieSSEStream(server *Server, raw string, session store.Session) (*deadlineTrackingWriter, context.CancelFunc, <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil).WithContext(ctx)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
	writer := &deadlineTrackingWriter{header: make(http.Header)}
	done := make(chan struct{})
	go func() {
		server.stream(writer, request, session)
		close(done)
	}()
	return writer, cancel, done
}

func waitForSSECacheEntries(t *testing.T, server *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.sseAuthMu.Lock()
		got := len(server.sseAuthCache)
		server.sseAuthMu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	server.sseAuthMu.Lock()
	got := len(server.sseAuthCache)
	server.sseAuthMu.Unlock()
	t.Fatalf("SSE authorization cache entries = %d, want %d", got, want)
}

func waitForSSEBody(t *testing.T, writer *deadlineTrackingWriter, want string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		writer.mu.Lock()
		body := writer.body.String()
		writer.mu.Unlock()
		if strings.Contains(body, want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	writer.mu.Lock()
	body := writer.body.String()
	writer.mu.Unlock()
	t.Fatalf("SSE body did not contain %q: %s", want, body)
}

func TestSSEAuthorizationCacheLifecycleThroughStreams(t *testing.T) {
	server, db, _ := newUsersTestServer(t)
	ctx := context.Background()
	raw, _, err := server.Auth.Login(ctx, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil), "administrator password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	authRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	authRequest.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
	session, ok := server.Auth.AuthenticateReadOnly(ctx, authRequest)
	if !ok {
		t.Fatal("login session was not authenticated")
	}

	// Keep the test fast without changing the production heartbeat or cache
	// constants. The clock is injected so advancing past the bound is
	// deterministic and does not require a long sleep.
	clockMu := sync.Mutex{}
	clock := time.Now().UTC()
	server.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}
	server.sseAuthTTL = time.Second
	advanceClock := func(d time.Duration) {
		clockMu.Lock()
		clock = clock.Add(d)
		clockMu.Unlock()
	}

	_, cancelA, doneA := startCookieSSEStream(server, raw, session)
	writerB, cancelB, doneB := startCookieSSEStream(server, raw, session)
	defer cancelB()
	waitForSSESubscribers(t, server, 2)
	waitForSSECacheEntries(t, server, 1)

	// Closing one stream must not invalidate the sibling's ability to receive
	// events, even though both streams share one authorization-cache key.
	cancelA()
	select {
	case <-doneA:
	case <-time.After(time.Second):
		t.Fatal("first SSE stream did not close")
	}
	waitForSSESubscribers(t, server, 1)
	server.broadcast(map[string]any{"type": "test", "token": "survivor"})
	waitForSSEBody(t, writerB, "survivor")

	if err := db.DeleteSession(ctx, session.IDHash); err != nil {
		t.Fatal(err)
	}
	advanceClock(2 * time.Second)
	server.broadcast(map[string]any{"type": "test", "token": "revoked"})
	select {
	case <-doneB:
	case <-time.After(time.Second):
		t.Fatal("revoked SSE stream did not close after the authorization bound")
	}
	writerB.mu.Lock()
	body := writerB.body.String()
	writerB.mu.Unlock()
	if strings.Contains(body, "revoked") {
		t.Fatalf("revoked SSE stream received an event: %s", body)
	}
	waitForSSECacheEntries(t, server, 0)
}

func TestSSEAnonymousStreamDoesNotSeedAuthorizationCache(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil).WithContext(ctx)
	writer := &deadlineTrackingWriter{header: make(http.Header)}
	done := make(chan struct{})
	go func() {
		server.stream(writer, request, store.Session{})
		close(done)
	}()
	waitForSSESubscribers(t, server, 1)
	waitForSSECacheEntries(t, server, 0)

	server.broadcast(map[string]any{"type": "test", "token": "anonymous-event"})
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("anonymous SSE stream did not close after authorization failed")
	}
	writer.mu.Lock()
	body := writer.body.String()
	writer.mu.Unlock()
	if bytes.Contains([]byte(body), []byte("anonymous-event")) {
		t.Fatalf("anonymous SSE stream received an event: %s", body)
	}
	waitForSSECacheEntries(t, server, 0)
	cancel()
}
