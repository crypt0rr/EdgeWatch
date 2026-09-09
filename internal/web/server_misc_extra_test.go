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
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/webui"
)

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
