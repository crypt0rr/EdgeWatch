package web

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
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

func TestPendingChangeViewsSortTiesByProtocolPortKindAndKey(t *testing.T) {
	items := pendingChangeViews(map[string]model.Pending{
		"z":       {Change: model.Change{Target: "192.0.2.30", Protocol: "tcp", Port: 80, Kind: "port"}},
		"a":       {Change: model.Change{Target: "192.0.2.30", Protocol: "tcp", Port: 80, Kind: "port"}},
		"udp":     {Change: model.Change{Target: "192.0.2.30", Protocol: "udp", Port: 80, Kind: "port"}},
		"443":     {Change: model.Change{Target: "192.0.2.30", Protocol: "tcp", Port: 443, Kind: "port"}},
		"service": {Change: model.Change{Target: "192.0.2.30", Protocol: "tcp", Port: 80, Kind: "service"}},
	})
	want := []string{"a", "z", "service", "443", "udp"}
	if len(items) != len(want) {
		t.Fatalf("sorted pending changes = %#v", items)
	}
	for index, key := range want {
		if items[index].Key != key {
			t.Fatalf("sorted pending change %d = %q, want %q; all items: %#v", index, items[index].Key, key, items)
		}
	}
}

func TestJobPendingChangesReturnsSanitizedStoreFailure(t *testing.T) {
	server, db, _ := newUsersTestServer(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	server.Log = slog.New(slog.NewTextHandler(&logs, nil))
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/job-1/pending-changes", nil)
	server.jobPendingChanges(response, request, defaultTenantStore(server), store.JobRecord{ID: "job-1"})
	assertRedactedInternalError(t, "pending changes with a closed store", response, "", "database is closed", &logs)
}

func TestJobPendingChangesRejectsInvalidOffsets(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	for _, offset := range []string{"-1", "10000001"} {
		t.Run(offset, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/job-1/pending-changes?offset="+offset, nil)
			server.jobPendingChanges(response, request, defaultTenantStore(server), store.JobRecord{ID: "job-1"})
			apiErr := decodeAPIError(t, response)
			if response.Code != http.StatusBadRequest || apiErr.Error.Code != "invalid_pagination" {
				t.Fatalf("pending changes offset %q = %d %#v", offset, response.Code, apiErr.Error)
			}
		})
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
