package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestWriteBaselineConflictReturnsSafeCurrentMarker(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{Store: db}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/missing/baseline/reset", nil)
	rec := httptest.NewRecorder()
	server.writeBaselineConflict(rec, req, "missing")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"baseline_conflict"`) {
		t.Fatalf("baseline conflict response = %d %s", rec.Code, rec.Body.String())
	}
	job, err := db.CreateJob(context.Background(), config.NormalizeJob(config.Job{
		Name: "conflict-job", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.1"},
		TCP: &config.Protocol{Ports: "22", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	server.writeBaselineConflict(rec, req, job.ID)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"baseline_scan_id"`) {
		t.Fatalf("current baseline conflict response = %d %s", rec.Code, rec.Body.String())
	}
}

func TestRetrySSEReservationWithoutStoreIsSafe(t *testing.T) {
	(&Server{}).retrySSEReservation()
}
