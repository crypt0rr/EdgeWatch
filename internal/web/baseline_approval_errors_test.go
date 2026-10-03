package web

import (
	"context"
	"errors"
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

func TestApproveBaselineMapsEarlyStorageFailuresToInternalErrors(t *testing.T) {
	t.Run("runtime state", func(t *testing.T) {
		server, db, admin, record, scan := baselineApprovalFixture(t)
		if _, err := db.DB.ExecContext(context.Background(), `DROP TABLE job_runtime`); err != nil {
			t.Fatal(err)
		}

		response := postBaselineApproval(server, admin, record.ID, scan.ID)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), `"code":"store"`) {
			t.Fatalf("runtime state failure = %d: %s, want sanitized 500 store", response.Code, response.Body.String())
		}
	})

	t.Run("notification destinations", func(t *testing.T) {
		server, db, admin, record, scan := baselineApprovalFixture(t)
		if _, err := db.DB.ExecContext(context.Background(), `DROP TABLE managed_notifications`); err != nil {
			t.Fatal(err)
		}

		response := postBaselineApproval(server, admin, record.ID, scan.ID)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), `"code":"notification"`) {
			t.Fatalf("notification destination failure = %d: %s, want sanitized 500 notification", response.Code, response.Body.String())
		}
	})

	t.Run("missing scan", func(t *testing.T) {
		server, _, admin, record, _ := baselineApprovalFixture(t)
		response := postBaselineApproval(server, admin, record.ID, "missing-scan")
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_scan"`) {
			t.Fatalf("missing scan = %d: %s, want 400 invalid_scan", response.Code, response.Body.String())
		}
	})
}

func TestWriteBaselineApprovalErrorMapsMutationFailures(t *testing.T) {
	server, _, _, record, _ := baselineApprovalFixture(t)
	ts := defaultTenantStore(server)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/baseline/approve", nil)
	cases := []struct {
		name       string
		err        error
		statusCode int
		code       string
	}{
		{name: "active scan", err: store.ErrJobScanActive, statusCode: http.StatusConflict, code: "job_active"},
		{name: "conflict", err: store.ErrConflict, statusCode: http.StatusConflict, code: "baseline_conflict"},
		{name: "missing record", err: store.ErrNotFound, statusCode: http.StatusNotFound, code: "not_found"},
		{name: "invalid request", err: store.ErrValidation, statusCode: http.StatusBadRequest, code: "validation_failed"},
		{name: "storage failure", err: errors.New("database details must stay private"), statusCode: http.StatusInternalServerError, code: "baseline_approval"},
		{name: "audit unavailable", err: store.ErrAuditUnavailable, statusCode: http.StatusServiceUnavailable, code: "audit_unavailable"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.writeBaselineApprovalError(response, request, ts, record.ID, test.err)
			if response.Code != test.statusCode || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("mapped error = %d: %s, want %d %s", response.Code, response.Body.String(), test.statusCode, test.code)
			}
			if strings.Contains(response.Body.String(), "database details must stay private") {
				t.Fatalf("error response disclosed storage details: %s", response.Body.String())
			}
		})
	}
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
