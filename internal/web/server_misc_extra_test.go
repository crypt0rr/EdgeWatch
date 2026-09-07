package web

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestServerStaticSSEAndAuditHelpers(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
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
	server.stream(streamResponse, request)
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
	spaResponse := httptest.NewRecorder()
	server.spa(spaResponse, httptest.NewRequest(http.MethodGet, "/", nil))
	if spaResponse.Code != http.StatusOK || !bytes.Contains(spaResponse.Body.Bytes(), []byte("EdgeWatch")) {
		t.Fatalf("SPA response = %d %q", spaResponse.Code, spaResponse.Body.String())
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
