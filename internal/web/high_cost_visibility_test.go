package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestOperatorScopeEditShowsTheClearedHighCostApproval(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	server.App.Config.Scheduler.MaxProbeCount = 100
	operator := admin
	operator.Role = store.RoleOperator
	job := config.NormalizeJob(config.Job{
		Name: "approved-broad", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Ports: "1-1000", Mode: "connect", Engine: config.EngineNmap}, AllowHighCost: true,
	})
	record, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	serve := func(session store.Session, method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/jobs/"+record.ID, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		server.jobRoute(rec, req, session, defaultTenantStore(server), record.ID)
		return rec
	}
	type response struct {
		Job struct {
			AllowHighCost bool `json:"allow_high_cost"`
		} `json:"job"`
		ScanBudget *struct {
			Exceeded         bool  `json:"exceeded"`
			EstimatedProbes  int64 `json:"estimated_probes"`
			Limit            int64 `json:"limit"`
			ApprovalWouldFit bool  `json:"approval_would_fit"`
		} `json:"scan_budget"`
		Cleared bool `json:"high_cost_approval_cleared"`
	}
	decode := func(rec *httptest.ResponseRecorder) response {
		t.Helper()
		var value response
		if err := json.Unmarshal(rec.Body.Bytes(), &value); err != nil {
			t.Fatalf("decode %s: %v", rec.Body.String(), err)
		}
		return value
	}

	approved := serve(admin, http.MethodGet, "")
	if got := decode(approved); approved.Code != http.StatusOK || got.ScanBudget == nil || got.ScanBudget.Exceeded {
		t.Fatalf("approved job = %d %s, want a budget that fits", approved.Code, approved.Body.String())
	}

	edit := fromConfig(record.Job)
	edit.Revision = record.Revision
	edit.TCP.Ports = "1-999"
	body, err := json.Marshal(edit)
	if err != nil {
		t.Fatal(err)
	}
	prompt := serve(operator, http.MethodPut, string(body))
	if prompt.Code != http.StatusConflict || !strings.Contains(prompt.Body.String(), "high-cost approval: cleared; an administrator must approve the new scope again (about 999 probes exceed the budget of 100") {
		t.Fatalf("operator scope edit = %d %s, want the cleared approval in the confirmation", prompt.Code, prompt.Body.String())
	}

	edit.ConfirmRebaseline = true
	body, err = json.Marshal(edit)
	if err != nil {
		t.Fatal(err)
	}
	saved := serve(operator, http.MethodPut, string(body))
	got := decode(saved)
	if saved.Code != http.StatusOK || !got.Cleared || got.Job.AllowHighCost {
		t.Fatalf("confirmed operator edit = %d %s, want the approval reported as cleared", saved.Code, saved.Body.String())
	}
	if got.ScanBudget == nil || !got.ScanBudget.Exceeded || got.ScanBudget.EstimatedProbes != 999 || got.ScanBudget.Limit != 100 || !got.ScanBudget.ApprovalWouldFit {
		t.Fatalf("budget after the edit = %+v", got.ScanBudget)
	}

	// A routine edit that keeps the scope keeps the approval and says nothing.
	reloaded, err := defaultTenant(db).GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Job.AllowHighCost {
		t.Fatal("the approval survived the operator's scope change")
	}
	routine := fromConfig(reloaded.Job)
	routine.Revision = reloaded.Revision
	routine.Schedule = "30 * * * *"
	body, err = json.Marshal(routine)
	if err != nil {
		t.Fatal(err)
	}
	if rec := serve(operator, http.MethodPut, string(body)); rec.Code != http.StatusOK || decode(rec).Cleared {
		t.Fatalf("routine edit = %d %s", rec.Code, rec.Body.String())
	}
}
