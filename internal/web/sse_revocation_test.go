package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func loginSSETestSession(t *testing.T, server *Server) (string, store.Session) {
	t.Helper()
	ctx := context.Background()
	raw, _, err := server.Auth.Login(ctx, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil), "administrator password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
	session, ok := server.Auth.AuthenticateReadOnly(ctx, request)
	if !ok {
		t.Fatal("login session was not authenticated")
	}
	return raw, session
}

func waitForSSEStreamClose(t *testing.T, done <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s SSE stream did not close promptly", name)
	}
}

func assertSSEStreamStillOpen(t *testing.T, done <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-done:
		t.Fatalf("%s SSE stream closed unexpectedly", name)
	default:
	}
}

func TestSSESessionRevocationCancelsOnlyMatchingStream(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	rawA, sessionA := loginSSETestSession(t, server)
	rawB, sessionB := loginSSETestSession(t, server)
	if sessionA.UserID != sessionB.UserID || sessionA.IDHash == sessionB.IDHash {
		t.Fatalf("test sessions are not independent browser sessions: A=%#v B=%#v", sessionA, sessionB)
	}
	_, cancelA, doneA := startCookieSSEStream(server, rawA, sessionA)
	writerB, cancelB, doneB := startCookieSSEStream(server, rawB, sessionB)
	defer cancelA()
	defer cancelB()
	waitForSSESubscribers(t, server, 2)
	waitForSSECacheEntries(t, server, 2)

	server.revokeSSESession(sessionA.IDHash)
	waitForSSEStreamClose(t, doneA, "revoked")
	assertSSEStreamStillOpen(t, doneB, "sibling")
	waitForSSESubscribers(t, server, 1)

	server.broadcast(map[string]any{"type": "test", "token": "sibling-survives"})
	waitForSSEBody(t, writerB, "sibling-survives")
	server.revokeSSEUser(sessionB.UserID)
	waitForSSEStreamClose(t, doneB, "user-wide revoked")
	waitForSSECacheEntries(t, server, 0)
}

func TestSSEUserRevocationCanPreserveCurrentSession(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	rawA, sessionA := loginSSETestSession(t, server)
	rawB, sessionB := loginSSETestSession(t, server)
	writerA, cancelA, doneA := startCookieSSEStream(server, rawA, sessionA)
	_, cancelB, doneB := startCookieSSEStream(server, rawB, sessionB)
	defer cancelA()
	defer cancelB()
	waitForSSESubscribers(t, server, 2)
	waitForSSECacheEntries(t, server, 2)

	server.revokeSSEUserExcept(sessionA.UserID, sessionA.IDHash)
	waitForSSEStreamClose(t, doneB, "non-preserved")
	assertSSEStreamStillOpen(t, doneA, "preserved")
	waitForSSESubscribers(t, server, 1)
	server.broadcast(map[string]any{"type": "test", "token": "preserved-survives"})
	waitForSSEBody(t, writerA, "preserved-survives")
	waitForSSECacheEntries(t, server, 1)
}

func TestLogoutCancelsOriginatingSSEStream(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	raw, session := loginSSETestSession(t, server)
	_, cancel, done := startCookieSSEStream(server, raw, session)
	defer cancel()
	waitForSSESubscribers(t, server, 1)

	logout := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logout.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
	response := httptest.NewRecorder()
	server.logout(response, logout, session)
	if response.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, body = %s", response.Code, response.Body.String())
	}
	waitForSSEStreamClose(t, done, "logged-out")
}
