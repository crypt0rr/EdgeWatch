package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestJobPendingChangesAreSortedAndBoundToTheJob(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	record, err := defaultTenant(db).CreateJob(ctx, config.NormalizeJob(config.Job{
		Name:     "pending-changes",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.10"},
		TCP:      &config.Protocol{Ports: "22,443", Mode: "connect"},
		Timeout:  config.Duration(time.Minute),
		Timing:   "balanced",
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Pending = map[string]model.Pending{
			"service|z": {Change: model.Change{Kind: "service", Target: "192.0.2.20", Protocol: "tcp", Port: 443, Old: "https", New: "nginx", Severity: "info"}, Count: 1},
			"port|a":    {Change: model.Change{Kind: "port", Target: "192.0.2.10", Protocol: "tcp", Port: 22, Old: "not-open", New: "open", Severity: "critical"}, Count: 2},
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/pending-changes?limit=1&offset=0", nil)
	response := httptest.NewRecorder()
	server.jobRoute(response, request, admin, defaultTenantStore(server), record.ID+"/pending-changes")
	if response.Code != http.StatusOK {
		t.Fatalf("pending changes status = %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		JobID          string              `json:"job_id"`
		Job            string              `json:"job"`
		PendingChanges []pendingChangeView `json:"pending_changes"`
		Pagination     struct {
			Limit      int  `json:"limit"`
			Offset     int  `json:"offset"`
			Total      int  `json:"total"`
			HasMore    bool `json:"has_more"`
			NextOffset *int `json:"next_offset"`
		} `json:"pagination"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.JobID != record.ID || payload.Job != record.Job.Name || len(payload.PendingChanges) != 1 {
		t.Fatalf("pending change response = %#v", payload)
	}
	if got := payload.PendingChanges[0]; got.Change.Target != "192.0.2.10" || got.Change.Kind != "port" || got.Count != 2 {
		t.Fatalf("first pending change = %#v", got)
	}
	if payload.Pagination.Limit != 1 || payload.Pagination.Offset != 0 || payload.Pagination.Total != 2 || !payload.Pagination.HasMore || payload.Pagination.NextOffset == nil || *payload.Pagination.NextOffset != 1 {
		t.Fatalf("pending changes pagination = %#v", payload.Pagination)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/pending-changes?limit=1&offset=1", nil)
	response = httptest.NewRecorder()
	server.jobRoute(response, request, admin, defaultTenantStore(server), record.ID+"/pending-changes")
	if response.Code != http.StatusOK {
		t.Fatalf("second pending changes page status = %d: %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.PendingChanges) != 1 {
		t.Fatalf("second pending changes page = %#v", payload.PendingChanges)
	}
	if got := payload.PendingChanges[0]; got.Change.Target != "192.0.2.20" || got.Change.Kind != "service" || got.Count != 1 {
		t.Fatalf("second pending change = %#v", got)
	}
}

func TestJobPendingChangesWithoutRuntimeStateReturnsAnEmptyArray(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	record, err := defaultTenant(db).CreateJob(ctx, config.NormalizeJob(config.Job{
		Name:     "no-pending-changes",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.11"},
		TCP:      &config.Protocol{Ports: "22", Mode: "connect"},
		Timeout:  config.Duration(time.Minute),
		Timing:   "balanced",
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/pending-changes", nil)
	response := httptest.NewRecorder()
	server.jobRoute(response, request, admin, defaultTenantStore(server), record.ID+"/pending-changes")
	if response.Code != http.StatusOK {
		t.Fatalf("pending changes status = %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		PendingChanges []pendingChangeView `json:"pending_changes"`
		Pagination     struct {
			Total int `json:"total"`
		} `json:"pagination"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.PendingChanges == nil || len(payload.PendingChanges) != 0 || payload.Pagination.Total != 0 {
		t.Fatalf("empty pending changes = %#v, total = %d", payload.PendingChanges, payload.Pagination.Total)
	}
	permission, ok := authPermissionForRoute(http.MethodGet, "/jobs/{id}/pending-changes")
	if !ok || permission != auth.PermissionScansRead {
		t.Fatalf("pending changes route permission = %q, found = %v", permission, ok)
	}
}

func authPermissionForRoute(method, path string) (string, bool) {
	for _, route := range apiRoutes {
		if route.Method == method && route.Template == path {
			return route.Permission, true
		}
	}
	return "", false
}
