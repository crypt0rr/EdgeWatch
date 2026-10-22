package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanSlotDemandHandlerWritesInternalErrorWhenStoreFails(t *testing.T) {
	t.Parallel()
	server, _ := newHealthServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/slot-demand", nil).WithContext(ctx)
	response := httptest.NewRecorder()

	server.scanSlotDemand(response, request, defaultTenantStore(server))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("slot demand response = %d %s, want 500", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "context canceled") {
		t.Fatalf("slot demand response disclosed storage error: %s", response.Body.String())
	}
}
