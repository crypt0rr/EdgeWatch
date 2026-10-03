package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestApproveBaselineMapsStorageFailuresToInternalErrors(t *testing.T) {
	t.Run("approval transaction", func(t *testing.T) {
		server, db, admin, record, scan := baselineApprovalFixture(t)
		if _, err := db.DB.ExecContext(context.Background(), `CREATE TRIGGER reject_baseline_runtime_insert
			BEFORE INSERT ON job_runtime WHEN NEW.job_id='`+record.ID+`'
			BEGIN SELECT RAISE(ABORT,'baseline storage unavailable'); END`); err != nil {
			t.Fatal(err)
		}

		response := postBaselineApproval(server, admin, record.ID, scan.ID)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), `"code":"baseline_approval"`) {
			t.Fatalf("approval storage failure = %d: %s, want sanitized 500 baseline_approval", response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "baseline storage unavailable") {
			t.Fatalf("approval response disclosed storage error: %s", response.Body.String())
		}
	})

	t.Run("scan lookup", func(t *testing.T) {
		server, db, admin, record, scan := baselineApprovalFixture(t)
		if _, err := db.DB.ExecContext(context.Background(), `DROP TABLE scans`); err != nil {
			t.Fatal(err)
		}

		response := postBaselineApproval(server, admin, record.ID, scan.ID)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), `"code":"scan_read"`) {
			t.Fatalf("scan lookup storage failure = %d: %s, want sanitized 500 scan_read", response.Code, response.Body.String())
		}
	})
}

func TestApproveBaselineRejectsUnsuccessfulScanAsInvalidInput(t *testing.T) {
	server, _, admin, record, scan := baselineApprovalFixture(t)
	scan.ID = "baseline-storage-test-failed-scan"
	scan.Status = "failed"
	if err := server.Store.System().SaveScan(context.Background(), scan); err != nil {
		t.Fatal(err)
	}

	response := postBaselineApproval(server, admin, record.ID, scan.ID)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_scan"`) {
		t.Fatalf("failed scan approval = %d: %s, want 400 invalid_scan", response.Code, response.Body.String())
	}
}

func baselineApprovalFixture(t *testing.T) (*Server, *store.Store, store.Session, store.JobRecord, model.Scan) {
	t.Helper()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{
		Name: "baseline-error-test", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.77"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	})
	record, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{
		ID: "baseline-storage-test-scan", JobID: record.ID, JobRevision: record.Revision,
		Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "success",
		ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{},
	}
	if err := db.System().SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	return server, db, admin, record, scan
}

func postBaselineApproval(server *Server, admin store.Session, jobID, scanID string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+jobID+"/baseline/approve", strings.NewReader(`{"scan_id":"`+scanID+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.jobRoute(response, request, admin, defaultTenantStore(server), jobID+"/baseline/approve")
	return response
}
