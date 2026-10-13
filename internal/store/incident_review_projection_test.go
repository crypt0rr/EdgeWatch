package store

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func saveReviewFixture(t *testing.T, s *Store, name string) (JobRecord, IncidentInboxItem) {
	t.Helper()
	ctx := context.Background()
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob(name))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	incident := model.Incident{
		Change: model.Change{Key: "review-projection", Kind: "port", Severity: "warning", Target: "projection.example", Protocol: "tcp", Port: 443, Old: "closed", New: "open"},
		ScanID: "projection-opened", OpenedAt: now, LastSeenAt: now,
	}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[incident.Change.Key] = incident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	return job, findIncidentInboxItem(t, tenant, ctx, job.ID, incident.Change.Key, now)
}

func assertIncidentReviewSideEffects(t *testing.T, s *Store, jobID string, want int) {
	t.Helper()
	for _, check := range []struct {
		table string
		query string
	}{
		{table: "incident_reviews", query: `SELECT COUNT(*) FROM incident_reviews WHERE job_id=?`},
		{table: "incident_review_history", query: `SELECT COUNT(*) FROM incident_review_history WHERE job_id=?`},
		{table: "security_audit", query: `SELECT COUNT(*) FROM security_audit WHERE action='incident.review.updated' AND detail LIKE ?`},
	} {
		arg := any(jobID)
		if check.table == "security_audit" {
			arg = jobID + ":%"
		}
		var got int
		if err := s.DB.QueryRowContext(context.Background(), check.query, arg).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s rows after rejected projection write = %d; want %d", check.table, got, want)
		}
	}
}

func TestSaveIncidentReviewFailsClosedForMissingOrStaleProjection(t *testing.T) {
	for _, test := range []struct {
		name             string
		mutate           func(*testing.T, *Store, JobRecord, IncidentInboxItem)
		wantErr          error
		wantErrSubstring string
	}{
		{
			name: "missing active projection row",
			mutate: func(t *testing.T, s *Store, job JobRecord, item IncidentInboxItem) {
				if _, err := s.DB.ExecContext(context.Background(), `DELETE FROM runtime_incidents WHERE job_id=? AND key=?`, job.ID, item.Incident.Change.Key); err != nil {
					t.Fatal(err)
				}
				// The canonical runtime still has the occurrence. A missing projection
				// must not trigger the expensive state decode as a fallback.
				state, err := defaultTenant(s).RuntimeState(context.Background(), job.ID)
				if err != nil || state.Incidents[item.Incident.Change.Key].Change.Key == "" {
					t.Fatalf("runtime source after projection deletion = %+v, %v; want the active occurrence retained", state.Incidents, err)
				}
			},
			wantErr: ErrIncidentNotFound,
		},
		{
			name: "stale incident JSON with old token",
			mutate: func(t *testing.T, s *Store, job JobRecord, item IncidentInboxItem) {
				stale := item.Incident
				stale.Change.Severity = "critical"
				raw, err := json.Marshal(stale)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.DB.ExecContext(context.Background(), `UPDATE runtime_incidents SET incident_json=? WHERE job_id=? AND key=?`, raw, job.ID, item.Incident.Change.Key); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrIncidentOccurrenceChanged,
		},
		{
			name: "malformed incident JSON",
			mutate: func(t *testing.T, s *Store, job JobRecord, item IncidentInboxItem) {
				if _, err := s.DB.ExecContext(context.Background(), `UPDATE runtime_incidents SET incident_json=? WHERE job_id=? AND key=?`, []byte("{broken"), job.ID, item.Incident.Change.Key); err != nil {
					t.Fatal(err)
				}
			},
			wantErrSubstring: "invalid character",
		},
		{
			name: "empty occurrence token",
			mutate: func(t *testing.T, s *Store, job JobRecord, item IncidentInboxItem) {
				if _, err := s.DB.ExecContext(context.Background(), `UPDATE runtime_incidents SET occurrence_token='' WHERE job_id=? AND key=?`, job.ID, item.Incident.Change.Key); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrIncidentOccurrenceChanged,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := openTestStore(t)
			job, item := saveReviewFixture(t, s, "review-projection-"+strings.ReplaceAll(test.name, " ", "-"))
			test.mutate(t, s, job, item)
			_, err := defaultTenant(s).SaveIncidentReview(context.Background(), job.ID, IncidentReviewWrite{
				Key: item.Incident.Change.Key, OccurrenceToken: item.OccurrenceToken, ExpectedRevision: 0, Status: "investigating",
			}, "reviewer", "Reviewer", AuditEntry{})
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("save error = %v; want %v", err, test.wantErr)
			}
			if test.wantErrSubstring != "" && (err == nil || !strings.Contains(err.Error(), test.wantErrSubstring)) {
				t.Fatalf("save error = %v; want substring %q", err, test.wantErrSubstring)
			}
			if test.wantErr == nil && test.wantErrSubstring == "" && err != nil {
				t.Fatalf("save error = %v; want success", err)
			}
			assertIncidentReviewSideEffects(t, s, job.ID, 0)
		})
	}
}

func TestIncidentReviewOccurrenceLookupUsesJobKeyIndexes(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, item := saveReviewFixture(t, s, "review-projection-query-plan")
	rows, err := s.DB.QueryContext(ctx, `EXPLAIN QUERY PLAN SELECT incidents.incident_json,incidents.occurrence_token
		FROM runtime_incidents AS incidents
		JOIN jobs AS owner ON owner.id=incidents.job_id AND owner.tenant_id=?
		JOIN job_runtime AS runtime ON runtime.job_id=incidents.job_id
		WHERE incidents.job_id=? AND incidents.key=?`, DefaultTenantScope().id, job.ID, item.Incident.Change.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	plan := strings.Join(details, " | ")
	if !strings.Contains(plan, "SEARCH incidents USING INDEX") || !strings.Contains(plan, "job_id=? AND key=?") {
		t.Fatalf("incident lookup plan = %q; want a primary-key search by job_id and key", plan)
	}
	if !strings.Contains(plan, "SEARCH runtime USING") || !strings.Contains(plan, "job_id=?") {
		t.Fatalf("runtime existence plan = %q; want a primary-key search by job_id", plan)
	}
	if !strings.Contains(plan, "SEARCH owner USING") || !strings.Contains(plan, "id=?") {
		t.Fatalf("owner plan = %q; want a tenant-qualified job primary-key search", plan)
	}
	t.Logf("incident occurrence lookup plan: %s", plan)
}

func TestSaveIncidentReviewDoesNotDecodeLargeBaseline(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("review-large-baseline"))
	if err != nil {
		t.Fatal(err)
	}
	incident := model.Incident{
		Change: model.Change{Key: "large-baseline-review", Kind: "host", Severity: "info", Target: "large.example", Old: "absent", New: "present"},
		ScanID: "large-baseline-scan", OpenedAt: time.Now().UTC(),
	}
	largeValue := strings.Repeat("b", 8<<20)
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: largeValue, Protocol: "tcp", Ports: "1-65535"}}}
		state.Incidents[incident.Change.Key] = incident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	var stateBytes int
	if err := s.DB.QueryRowContext(ctx, `SELECT length(state_json) FROM job_runtime WHERE job_id=?`, job.ID).Scan(&stateBytes); err != nil {
		t.Fatal(err)
	}
	if stateBytes < 8<<20 {
		t.Fatalf("stored runtime size = %d; want at least 8 MiB", stateBytes)
	}
	item := findIncidentInboxItem(t, tenant, ctx, job.ID, incident.Change.Key, time.Now().UTC())
	write := IncidentReviewWrite{Key: incident.Change.Key, OccurrenceToken: item.OccurrenceToken, Status: "investigating", Note: "small projection write"}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	if _, err := tenant.SaveIncidentReview(ctx, job.ID, write, "reviewer", "Reviewer", AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated >= 2<<20 {
		t.Fatalf("SaveIncidentReview allocated %d bytes while runtime JSON was %d bytes; want no multi-megabyte state decode", allocated, stateBytes)
	}
	t.Logf("8 MiB runtime SaveIncidentReview: state_json=%d bytes allocated=%d bytes elapsed=%s", stateBytes, allocated, elapsed)
}
