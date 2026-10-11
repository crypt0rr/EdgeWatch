package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestIncidentOccurrenceTokenIsStableAndVersioned(t *testing.T) {
	opened := time.Date(2026, 10, 10, 9, 30, 0, 0, time.FixedZone("test", 2*60*60))
	incident := model.Incident{Change: model.Change{Key: "port|host|tcp|443", Kind: "port", Severity: "critical", Target: "host", Protocol: "tcp", Port: 443, Old: "closed", New: "open"}, ScanID: "scan-1", OpenedAt: opened}
	first, err := incidentOccurrenceToken("tenant-a", "job-a", "map-key", incident)
	if err != nil {
		t.Fatal(err)
	}
	incident.LastSeenAt = opened.Add(time.Hour)
	incident.RecoveryCount = 3
	second, err := incidentOccurrenceToken("tenant-a", "job-a", "map-key", incident)
	if err != nil || first != second || len(first) != 67 || first[:3] != "v1:" {
		t.Fatalf("token after mutable observation fields = %q, %v; want stable v1 token %q", second, err, first)
	}
	incident.Change.New = "filtered"
	changed, err := incidentOccurrenceToken("tenant-a", "job-a", "map-key", incident)
	if err != nil || changed == first {
		t.Fatalf("token after exact change update = %q, %v; want a distinct token", changed, err)
	}
	legacy := model.Incident{Change: model.Change{Key: "legacy"}}
	legacyToken, err := incidentOccurrenceToken("tenant-a", "job-a", "legacy", legacy)
	if err != nil || legacyToken == "" {
		t.Fatalf("legacy occurrence token = %q, %v", legacyToken, err)
	}
	legacy.LastSeenAt = opened
	legacy.RecoveryCount = 4
	continuedLegacyToken, err := incidentOccurrenceToken("tenant-a", "job-a", "legacy", legacy)
	if err != nil || continuedLegacyToken != legacyToken {
		t.Fatalf("legacy token changed with observation-only fields: %q, %v; want %q", continuedLegacyToken, err, legacyToken)
	}
}

func TestIncidentObservationUncertaintyValidationClosesStatusAndReasonPairs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		value IncidentObservationUncertainty
		valid bool
	}{
		{name: "unknown without newer evidence", value: IncidentObservationUncertainty{Status: IncidentObservationUnknown, Reason: IncidentReasonNoNewerObservation}, valid: true},
		{name: "incomplete target timeout", value: IncidentObservationUncertainty{Status: IncidentObservationIncomplete, Reason: IncidentReasonTargetObservationIncomplete}, valid: true},
		{name: "unrecognized status", value: IncidentObservationUncertainty{Status: IncidentObservationStatus("healthy"), Reason: IncidentReasonNoNewerObservation}},
		{name: "down evidence cannot be unknown", value: IncidentObservationUncertainty{Status: IncidentObservationUnknown, Reason: IncidentReasonTargetHostDown}},
		{name: "lack of recovery evidence is not incomplete", value: IncidentObservationUncertainty{Status: IncidentObservationIncomplete, Reason: IncidentReasonLatestScanDoesNotEstablishRecovery}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.value.valid() != test.valid {
				t.Fatalf("uncertainty validity = %t; want %t", test.value.valid(), test.valid)
			}
		})
	}
}

func TestIncidentInboxFiltersBeforePaginationAndSavesBoundedReviews(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job, err := ts.CreateJob(ctx, testJob("inbox"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	incidents := map[string]model.Incident{
		"critical-old": {Change: model.Change{Key: "critical-old", Kind: "port", Severity: "critical", Target: "old.example", Protocol: "tcp", Port: 443}, ScanID: "scan-old", OpenedAt: now.Add(-2 * time.Hour), LastSeenAt: now},
		"critical-new": {Change: model.Change{Key: "critical-new", Kind: "service", Severity: "critical", Target: "new.example", Protocol: "tcp", Port: 80}, ScanID: "scan-new", OpenedAt: now.Add(-time.Hour), LastSeenAt: now},
		"warning":      {Change: model.Change{Key: "warning", Kind: "port", Severity: "warning", Target: "warning.example", Protocol: "tcp", Port: 22}, ScanID: "scan-warning", OpenedAt: now.Add(-3 * time.Hour), LastSeenAt: now},
		"unknown-time": {Change: model.Change{Key: "unknown-time", Kind: "port", Severity: "critical", Target: "legacy.example", Protocol: "tcp", Port: 25}},
	}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents = incidents
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	page, err := ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "all_active", Limit: 1, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 4 || page.ActiveCount != 4 || len(page.Items) != 1 || page.Items[0].Incident.Change.Key != "critical-old" || !page.HasMore || page.NextOffset == nil || *page.NextOffset != 1 {
		t.Fatalf("first priority page = %+v", page)
	}
	page, err = ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "all_active", Severity: "warning", Limit: 1, Now: now})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Incident.Change.Key != "warning" {
		t.Fatalf("filtered page = %+v, %v; want one warning", page, err)
	}
	legacy := findIncidentInboxItem(t, ts, ctx, job.ID, "unknown-time", now)
	if legacy.ObservationUncertainty.Status != "unknown" || legacy.ObservationUncertainty.Reason != "legacy_origin_unknown" || legacy.OpeningTimeKnown || legacy.OpeningScanAvailable {
		t.Fatalf("legacy evidence was not explicit and unknown: %+v", legacy)
	}
	item := findIncidentInboxItem(t, ts, ctx, job.ID, "critical-old", now)
	exact, err := ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "all_active", JobID: job.ID, OccurrenceToken: item.OccurrenceToken, Now: now})
	if err != nil || exact.Total != 1 || len(exact.Items) != 1 || exact.Items[0].OccurrenceToken != item.OccurrenceToken {
		t.Fatalf("bounded exact-occurrence refresh = %+v, %v", exact, err)
	}
	missing, err := ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "all_active", JobID: job.ID, OccurrenceToken: "unknown-token", Now: now})
	if err != nil || missing.Total != 0 || len(missing.Items) != 0 {
		t.Fatalf("unknown occurrence refresh = %+v, %v; want zero rows", missing, err)
	}
	if _, err := ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "all_active", OccurrenceToken: item.OccurrenceToken, Now: now}); !errors.Is(err, ErrIncidentReviewInvalid) {
		t.Fatalf("unbounded occurrence refresh without job ID = %v; want invalid filter", err)
	}
	due := now.Add(-time.Minute)
	write := IncidentReviewWrite{Key: item.Incident.Change.Key, OccurrenceToken: item.OccurrenceToken, ExpectedRevision: 0, Status: "investigating", Note: "operator note retained privately", FollowUpAt: &due}
	actorAudit := AuditEntry{ActorUserID: "reviewer-id", ActorUsername: "reviewer", SourceIP: "127.0.0.1"}
	review, err := ts.SaveIncidentReview(ctx, job.ID, write, "reviewer-id", "Reviewer Label", actorAudit)
	if err != nil || review.Revision != 1 || review.Status != "investigating" || review.ReviewerLabel == nil || *review.ReviewerLabel != "Reviewer Label" || review.FollowUpAt == nil {
		t.Fatalf("save initial review = %+v, %v", review, err)
	}
	page, err = ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "follow_up_due", Now: now})
	if err != nil || page.Total != 1 || page.Items[0].ViewStatus != "follow_up_due" || page.Items[0].Review.Note != write.Note {
		t.Fatalf("due review view = %+v, %v", page, err)
	}
	if _, err := ts.SaveIncidentReview(ctx, job.ID, write, "reviewer-id", "Reviewer Label", actorAudit); !errors.Is(err, ErrIncidentReviewRevisionConflict) {
		t.Fatalf("stale review revision = %v; want review revision conflict", err)
	}
	for revision := int64(1); revision < 23; revision++ {
		write.ExpectedRevision = revision
		write.Note = fmt.Sprintf("revision-%d", revision+1)
		write.FollowUpAt = nil
		if _, err := ts.SaveIncidentReview(ctx, job.ID, write, "reviewer-id", "Reviewer Label", actorAudit); err != nil {
			t.Fatalf("save revision %d: %v", revision+1, err)
		}
	}
	var currentRevision, historyRows int
	if err := s.DB.QueryRowContext(ctx, `SELECT revision FROM incident_reviews WHERE job_id=? AND occurrence_token=?`, job.ID, item.OccurrenceToken).Scan(&currentRevision); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_review_history WHERE job_id=? AND occurrence_token=?`, job.ID, item.OccurrenceToken).Scan(&historyRows); err != nil {
		t.Fatal(err)
	}
	if currentRevision != 23 || historyRows != incidentReviewHistoryLimit {
		t.Fatalf("review revision/history = %d/%d; want 23/%d", currentRevision, historyRows, incidentReviewHistoryLimit)
	}
	var auditDetail string
	if err := s.DB.QueryRowContext(ctx, `SELECT detail FROM security_audit WHERE action='incident.review.updated' ORDER BY id DESC LIMIT 1`).Scan(&auditDetail); err != nil {
		t.Fatal(err)
	}
	if auditDetail == "" || containsAny(auditDetail, write.Note, item.OccurrenceToken) {
		t.Fatalf("audit detail contains review content or token: %q", auditDetail)
	}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		delete(state.Incidents, "critical-old")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents["critical-old"] = model.Incident{Change: incidents["critical-old"].Change, ScanID: "scan-reopened", OpenedAt: now.Add(24 * time.Hour), LastSeenAt: now.Add(24 * time.Hour)}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	page, err = ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "needs_review", JobID: job.ID, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	var reopened *IncidentInboxItem
	for i := range page.Items {
		if page.Items[i].Incident.Change.Key == "critical-old" {
			reopened = &page.Items[i]
			break
		}
	}
	if reopened == nil || reopened.OccurrenceToken == item.OccurrenceToken || reopened.Review.Revision != 0 || reopened.Review.Status != "needs_review" {
		t.Fatalf("reopened occurrence inherited prior review: %+v", reopened)
	}
}

func TestIncidentInboxDefaultKindAndInvestigatingFilters(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job, err := ts.CreateJob(ctx, testJob("inbox-default-filters"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	incident := model.Incident{Change: model.Change{Key: "filter-port", Kind: "port", Severity: "warning", Target: "filter.example", Protocol: "tcp", Port: 443}, ScanID: "filter-scan", OpenedAt: now, LastSeenAt: now}
	otherKind := model.Incident{Change: model.Change{Key: "filter-service", Kind: "service", Severity: "critical", Target: "filter.example", Protocol: "tcp", Port: 443}, ScanID: "filter-service-scan", OpenedAt: now, LastSeenAt: now}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[incident.Change.Key] = incident
		state.Incidents[otherKind.Change.Key] = otherKind
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}

	// The kind filter applies before pagination: the higher-priority service
	// item is excluded before the single-row page is selected.
	defaultPage, err := ts.ListIncidentInbox(ctx, IncidentInboxFilter{Kind: "port", Limit: 1})
	if err != nil || defaultPage.Total != 1 || defaultPage.ActiveCount != 2 || len(defaultPage.Items) != 1 || defaultPage.Items[0].Incident.Change.Key != incident.Change.Key || defaultPage.Items[0].ViewStatus != "needs_review" {
		t.Fatalf("default kind-filtered page = %+v, %v", defaultPage, err)
	}
	if _, err := ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "recently_closed"}); !errors.Is(err, ErrIncidentReviewInvalid) {
		t.Fatalf("unknown view = %v; want invalid-filter error", err)
	}

	item := findIncidentInboxItem(t, ts, ctx, job.ID, incident.Change.Key, now)
	write := IncidentReviewWrite{Key: incident.Change.Key, OccurrenceToken: item.OccurrenceToken, Status: "investigating"}
	if _, err := ts.SaveIncidentReview(ctx, job.ID, write, "reviewer", "Reviewer", AuditEntry{}); err != nil {
		t.Fatalf("save investigating review without a due time: %v", err)
	}
	defaultView, err := ts.ListIncidentInbox(ctx, IncidentInboxFilter{Kind: "port", Now: now})
	if err != nil || defaultView.Total != 1 || len(defaultView.Items) != 1 || defaultView.Items[0].ViewStatus != "investigating" {
		t.Fatalf("omitted view did not include the investigating item from all_active: %+v, %v", defaultView, err)
	}
	needsReview, err := ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "needs_review", Kind: "port", Now: now})
	if err != nil || needsReview.Total != 0 || len(needsReview.Items) != 0 {
		t.Fatalf("explicit needs-review view included an investigating item: %+v, %v", needsReview, err)
	}
	page, err := ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "investigating", Kind: "port", Now: now})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ViewStatus != "investigating" {
		t.Fatalf("investigating view without due time = %+v, %v", page, err)
	}

	due := now.Add(24 * time.Hour)
	write.ExpectedRevision = 1
	write.FollowUpAt = &due
	if _, err := ts.SaveIncidentReview(ctx, job.ID, write, "reviewer", "Reviewer", AuditEntry{}); err != nil {
		t.Fatalf("save future follow-up: %v", err)
	}
	page, err = ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "investigating", Kind: "port", Now: now})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Review.FollowUpAt == nil || !page.Items[0].Review.FollowUpAt.Equal(due) {
		t.Fatalf("future follow-up remained in investigating view = %+v, %v", page, err)
	}
	pastDue := time.Now().UTC().Add(-time.Minute)
	write.ExpectedRevision = 2
	write.FollowUpAt = &pastDue
	if _, err := ts.SaveIncidentReview(ctx, job.ID, write, "reviewer", "Reviewer", AuditEntry{}); err != nil {
		t.Fatalf("save past-due follow-up: %v", err)
	}
	defaultNow, err := ts.ListIncidentInbox(ctx, IncidentInboxFilter{Kind: "port"})
	if err != nil || defaultNow.Total != 1 || len(defaultNow.Items) != 1 || defaultNow.Items[0].ViewStatus != "follow_up_due" {
		t.Fatalf("omitted timestamp did not use current time for past-due follow-up: %+v, %v", defaultNow, err)
	}
}

func TestIncidentInboxReturnsErrorForCorruptProjectionAfterEarlierValidRow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job, err := ts.CreateJob(ctx, testJob("inbox-corrupt-projection"))
	if err != nil {
		t.Fatal(err)
	}
	valid := model.Incident{Change: model.Change{Key: "valid-first", Kind: "host", Severity: "critical", Target: "valid.example", Old: "absent", New: "present"}}
	corrupt := model.Incident{Change: model.Change{Key: "corrupt-later", Kind: "host", Severity: "warning", Target: "corrupt.example", Old: "absent", New: "present"}}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[valid.Change.Key] = valid
		state.Incidents[corrupt.Change.Key] = corrupt
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE runtime_incidents SET incident_json=? WHERE job_id=? AND key=?`, `{broken`, job.ID, corrupt.Change.Key); err != nil {
		t.Fatal(err)
	}

	if page, err := ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "all_active"}); err == nil {
		t.Fatalf("corrupt projection returned page=%+v; want an error after the earlier valid row", page)
	}
}

func TestSaveIncidentReviewRejectsInvalidWritesWithoutPartialRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job, err := ts.CreateJob(ctx, testJob("inbox-invalid-writes"))
	if err != nil {
		t.Fatal(err)
	}
	incident := model.Incident{Change: model.Change{Key: "invalid-write", Kind: "host", Severity: "warning", Target: "invalid.example", Old: "absent", New: "present"}, ScanID: "invalid-write-scan", OpenedAt: time.Now().UTC(), LastSeenAt: time.Now().UTC()}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[incident.Change.Key] = incident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	item := findIncidentInboxItem(t, ts, ctx, job.ID, incident.Change.Key, time.Now().UTC())
	dueTooFar := time.Now().UTC().Add((incidentFollowUpMaxDays + 1) * 24 * time.Hour)
	dueNow := time.Now().UTC()
	valid := IncidentReviewWrite{Key: incident.Change.Key, OccurrenceToken: item.OccurrenceToken, Status: "investigating"}
	tests := []struct {
		name          string
		write         IncidentReviewWrite
		reviewerLabel string
	}{
		{name: "missing key", write: IncidentReviewWrite{OccurrenceToken: item.OccurrenceToken, Status: "investigating"}, reviewerLabel: "Reviewer"},
		{name: "negative revision", write: func() IncidentReviewWrite { value := valid; value.ExpectedRevision = -1; return value }(), reviewerLabel: "Reviewer"},
		{name: "unknown status", write: func() IncidentReviewWrite { value := valid; value.Status = "closed"; return value }(), reviewerLabel: "Reviewer"},
		{name: "invalid utf8 note", write: func() IncidentReviewWrite { value := valid; value.Note = string([]byte{0xff}); return value }(), reviewerLabel: "Reviewer"},
		{name: "oversize note", write: func() IncidentReviewWrite {
			value := valid
			value.Note = strings.Repeat("n", incidentReviewNoteMaxBytes+1)
			return value
		}(), reviewerLabel: "Reviewer"},
		{name: "blank reviewer label", write: valid, reviewerLabel: " \t "},
		{name: "needs review cannot carry a due time", write: func() IncidentReviewWrite {
			value := valid
			value.Status = "needs_review"
			value.FollowUpAt = &dueNow
			return value
		}(), reviewerLabel: "Reviewer"},
		{name: "follow-up is bounded to thirty days", write: func() IncidentReviewWrite { value := valid; value.FollowUpAt = &dueTooFar; return value }(), reviewerLabel: "Reviewer"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ts.SaveIncidentReview(ctx, job.ID, test.write, "reviewer", test.reviewerLabel, AuditEntry{}); !errors.Is(err, ErrIncidentReviewInvalid) {
				t.Fatalf("invalid review write error = %v; want ErrIncidentReviewInvalid", err)
			}
			for _, table := range []string{"incident_reviews", "incident_review_history", "security_audit"} {
				var count int
				query := `SELECT COUNT(*) FROM ` + table
				if table == "security_audit" {
					query += ` WHERE action='incident.review.updated'`
				}
				if err := s.DB.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 0 {
					t.Fatalf("%s rows after rejected write = %d, %v; want no partial write", table, count, err)
				}
			}
		})
	}

	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		delete(state.Incidents, incident.Change.Key)
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.SaveIncidentReview(ctx, job.ID, valid, "reviewer", "Reviewer", AuditEntry{}); !errors.Is(err, ErrIncidentNotFound) {
		t.Fatalf("write to recovered occurrence = %v; want ErrIncidentNotFound", err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM incident_reviews`) != 0 || countRows(t, s.DB, `SELECT COUNT(*) FROM incident_review_history`) != 0 {
		t.Fatal("review for a recovered occurrence left durable review rows")
	}
}

func TestIncidentInboxObservationUsesStrictlyNewerJobEvidence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job, err := ts.CreateJob(ctx, testJob("inbox-uncertainty"))
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := ts.CreateJob(ctx, testJob("inbox-unrelated"))
	if err != nil {
		t.Fatal(err)
	}
	lastSeen := time.Date(2026, 10, 11, 12, 0, 0, 500000000, time.UTC)
	incident := model.Incident{
		Change: model.Change{Key: "edge", Kind: "port-address", Severity: "critical", Target: "edge.example", Address: "192.0.2.44", Protocol: "tcp", Port: 443, Old: "closed", New: "open"},
		ScanID: "opening-incomplete", OpenedAt: lastSeen.Add(-time.Hour), LastSeenAt: lastSeen,
	}
	openingSnapshot := model.Snapshot{Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "443"}}}
	insertIncidentEvidenceScan(t, ctx, s, job, incident.ScanID, lastSeen, "incomplete", model.ScanComparisonNotCompared, openingSnapshot)
	insertIncidentEvidenceScan(t, ctx, s, job, "newer-down", lastSeen.Add(time.Nanosecond), "success", model.ScanComparisonCompared, model.Snapshot{
		Scopes:     []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "443"}},
		Hosts:      []model.HostObservation{{Address: "192.0.2.44", SourceTargets: []string{"edge.example"}, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", DiscoveryState: "down"}}}},
		HostStates: []model.HostState{{Address: "192.0.2.44", State: "down"}},
	})
	insertIncidentEvidenceScan(t, ctx, s, unrelated, "unrelated-latest", lastSeen.Add(time.Hour), "failed", model.ScanComparisonNotCompared, model.Snapshot{})
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[incident.Change.Key] = incident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	item := findIncidentInboxItem(t, ts, ctx, job.ID, incident.Change.Key, lastSeen.Add(time.Hour))
	uncertainty := item.ObservationUncertainty
	if !item.OpeningScanAvailable || uncertainty.Status != "incomplete" || uncertainty.Reason != "target_host_down" || uncertainty.ScanID != "newer-down" || uncertainty.ObservedAt == nil || !uncertainty.ObservedAt.Equal(lastSeen.Add(time.Nanosecond)) || uncertainty.ScanStatus != "success" || uncertainty.Comparison != model.ScanComparisonCompared {
		t.Fatalf("newer explicit down evidence = %+v, opening available=%t; want only strictly newer same-job evidence", uncertainty, item.OpeningScanAvailable)
	}

	// An incomplete origin scan at exactly LastSeenAt is not newer evidence.
	// Its later pruning changes only the opening-source availability flag.
	prunedJob, err := ts.CreateJob(ctx, testJob("inbox-pruned-origin"))
	if err != nil {
		t.Fatal(err)
	}
	prunedIncident := model.Incident{
		Change: model.Change{Key: "pruned-origin", Kind: "port", Severity: "warning", Target: "pruned.example", Protocol: "tcp", Port: 80},
		ScanID: "pruned-opening", OpenedAt: lastSeen.Add(-time.Minute), LastSeenAt: lastSeen,
	}
	insertIncidentEvidenceScan(t, ctx, s, prunedJob, prunedIncident.ScanID, lastSeen, "incomplete", model.ScanComparisonNotCompared, model.Snapshot{})
	if _, err := s.System().UpdateRuntime(ctx, prunedJob.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[prunedIncident.Change.Key] = prunedIncident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	beforePrune := findIncidentInboxItem(t, ts, ctx, prunedJob.ID, prunedIncident.Change.Key, lastSeen.Add(time.Hour))
	if !beforePrune.OpeningScanAvailable || beforePrune.ObservationUncertainty.Status != "unknown" || beforePrune.ObservationUncertainty.Reason != "no_newer_observation" || beforePrune.ObservationUncertainty.ScanID != "" {
		t.Fatalf("opening scan was misrepresented as a newer observation: %+v", beforePrune)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM scans WHERE id=?`, prunedIncident.ScanID); err != nil {
		t.Fatal(err)
	}
	afterPrune := findIncidentInboxItem(t, ts, ctx, prunedJob.ID, prunedIncident.Change.Key, lastSeen.Add(time.Hour))
	if afterPrune.OpeningScanAvailable || afterPrune.ObservationUncertainty.Status != "unknown" || afterPrune.ObservationUncertainty.Reason != "no_newer_observation" {
		t.Fatalf("pruning origin changed the distinct newer-observation state: %+v", afterPrune)
	}

	// Even a later scan from another job cannot be attached to this occurrence.
	if afterPrune.ObservationUncertainty.ScanID != "" {
		t.Fatalf("unrelated job scan was selected as occurrence evidence: %+v", afterPrune.ObservationUncertainty)
	}
}

func insertIncidentEvidenceScan(t *testing.T, ctx context.Context, s *Store, job JobRecord, id string, finished time.Time, status, comparison string, snapshot model.Snapshot) {
	t.Helper()
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	stamp := sqliteTimestamp(finished)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scans(id,job_id,job,started_at,finished_at,status,comparison,config_hash,snapshot_json,tenant_id)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, id, job.ID, job.Job.Name, stamp, stamp, status, comparison, job.Job.SecurityHash(), raw, job.TenantID); err != nil {
		t.Fatal(err)
	}
}

func TestIncidentInboxLatestScanSeekUsesHistoryIndex(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	defer s.Close()
	rows, err := s.DB.QueryContext(context.Background(), `EXPLAIN QUERY PLAN SELECT candidate.id FROM scans AS candidate
		WHERE candidate.job_id=? AND candidate.tenant_id=? AND candidate.finished_at>?
		ORDER BY candidate.finished_at DESC,candidate.id DESC LIMIT 1`, "job", "tenant", "2026-10-11T12:00:00.000000000Z")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail)
		plan.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), scansJobHistoryIndex) {
		t.Fatalf("newer observation seek does not use the bounded job history index: %s", plan.String())
	}
}

func TestIncidentObservationUncertaintyRequiresExplicitCoverageEvidence(t *testing.T) {
	t.Parallel()
	lastSeen := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	incident := model.Incident{Change: model.Change{
		Key: "edge", Kind: "port", Target: "edge.example", Address: "192.0.2.44", Protocol: "tcp", Port: 443,
	}, LastSeenAt: lastSeen}
	base := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "443"}},
		Hosts:  []model.HostObservation{{Address: "192.0.2.44", SourceTargets: []string{"edge.example"}, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}}},
	}
	down := base
	down.Hosts = []model.HostObservation{{Address: "192.0.2.44", SourceTargets: []string{"edge.example"}, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", DiscoveryState: "down"}}}}
	partial := base
	partial.Hosts = []model.HostObservation{{Address: "192.0.2.44", SourceTargets: []string{"edge.example"}, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "nmap-host-timeout", DiscoveryState: "up"}}}}
	siblingTimeout := base
	siblingTimeout.Hosts = []model.HostObservation{
		{Address: "192.0.2.44", SourceTargets: []string{"edge.example"}, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}},
		{Address: "192.0.2.45", SourceTargets: []string{"edge.example"}, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "nmap-host-timeout", DiscoveryState: "up"}}},
	}
	if reason := incidentCoverageUncertainty(incident.Change, siblingTimeout); reason != "" {
		t.Fatalf("sibling IP timeout affected address-specific finding: reason=%q; want complete evidence for %s", reason, incident.Change.Address)
	}
	siblingIncident := incident.Change
	siblingIncident.Address = "192.0.2.45"
	if reason := incidentCoverageUncertainty(siblingIncident, siblingTimeout); reason != "target_observation_incomplete" {
		t.Fatalf("matching IP timeout = %q; want target_observation_incomplete", reason)
	}
	downs := []model.HostState{{Address: "192.0.2.44", State: "down"}}
	uncertainReachability := func(reason string) model.Snapshot {
		value := base
		value.Hosts = []model.HostObservation{{
			Address: "192.0.2.44", SourceTargets: []string{"edge.example"}, Status: "unreachable", StatusReason: reason,
			Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: reason, DiscoveryState: "down"}},
		}}
		value.HostStates = downs
		return value
	}
	tests := []struct {
		name       string
		status     string
		comparison string
		snapshot   model.Snapshot
		wantStatus IncidentObservationStatus
		wantReason IncidentObservationReason
	}{
		{name: "failed scan", status: "failed", comparison: model.ScanComparisonNotCompared, snapshot: base, wantStatus: IncidentObservationIncomplete, wantReason: IncidentReasonLatestScanFailed},
		{name: "incomplete scan", status: "incomplete", comparison: model.ScanComparisonNotCompared, snapshot: base, wantStatus: IncidentObservationIncomplete, wantReason: IncidentReasonLatestScanIncomplete},
		{name: "not compared", status: "success", comparison: model.ScanComparisonNotCompared, snapshot: base, wantStatus: IncidentObservationIncomplete, wantReason: IncidentReasonLatestScanNotCompared},
		{name: "target resolution failure", status: "success", comparison: model.ScanComparisonCompared, snapshot: model.Snapshot{Scopes: base.Scopes, TargetFailures: []model.TargetCoverageFailure{{Target: "edge.example", Reason: "lookup-failed"}}}, wantStatus: IncidentObservationIncomplete, wantReason: IncidentReasonTargetResolutionFailed},
		{name: "explicit host down", status: "success", comparison: model.ScanComparisonCompared, snapshot: func() model.Snapshot { value := down; value.HostStates = downs; return value }(), wantStatus: IncidentObservationIncomplete, wantReason: IncidentReasonTargetHostDown},
		{name: "administrative rejection is reachability uncertainty", status: "success", comparison: model.ScanComparisonCompared, snapshot: uncertainReachability("admin-prohibited"), wantStatus: IncidentObservationIncomplete, wantReason: IncidentReasonTargetObservationIncomplete},
		{name: "host unreachable response is not host down", status: "success", comparison: model.ScanComparisonCompared, snapshot: uncertainReachability("host-unreach"), wantStatus: IncidentObservationIncomplete, wantReason: IncidentReasonTargetObservationIncomplete},
		{name: "network unreachable response is not host down", status: "success", comparison: model.ScanComparisonCompared, snapshot: uncertainReachability("net-unreach"), wantStatus: IncidentObservationIncomplete, wantReason: IncidentReasonTargetObservationIncomplete},
		{name: "compared scan with partial target observation", status: "success", comparison: model.ScanComparisonCompared, snapshot: partial, wantStatus: IncidentObservationIncomplete, wantReason: IncidentReasonTargetObservationIncomplete},
		{name: "target omitted", status: "success", comparison: model.ScanComparisonCompared, snapshot: model.Snapshot{Scopes: []model.Scope{{Target: "other.example", Protocol: "tcp", Ports: "443"}}}, wantStatus: IncidentObservationIncomplete, wantReason: IncidentReasonTargetUnobserved},
		{name: "protocol omitted", status: "success", comparison: model.ScanComparisonCompared, snapshot: model.Snapshot{Scopes: []model.Scope{{Target: "edge.example", Protocol: "udp", Ports: "53"}}}, wantStatus: IncidentObservationIncomplete, wantReason: IncidentReasonProtocolUnobserved},
		{name: "legacy shape", status: "success", comparison: model.ScanComparisonCompared, snapshot: model.Snapshot{}, wantStatus: IncidentObservationUnknown, wantReason: IncidentReasonLatestScanUnclassifiable},
		{name: "covered but not recovery evidence", status: "success", comparison: model.ScanComparisonCompared, snapshot: base, wantStatus: IncidentObservationUnknown, wantReason: IncidentReasonLatestScanDoesNotEstablishRecovery},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			uncertainty := incidentObservationUncertainty(incident, "later-scan", sqliteTimestamp(lastSeen.Add(time.Second)), test.status, test.comparison, raw)
			if !uncertainty.valid() {
				t.Fatalf("uncertainty has an unrecognized enum value: %+v", uncertainty)
			}
			if uncertainty.Status != test.wantStatus || uncertainty.Reason != test.wantReason || uncertainty.ScanID != "later-scan" || uncertainty.ObservedAt == nil || !uncertainty.ObservedAt.Equal(lastSeen.Add(time.Second)) {
				t.Fatalf("uncertainty = %+v; want status=%s reason=%s with later scan metadata", uncertainty, test.wantStatus, test.wantReason)
			}
		})
	}
	for _, test := range []struct {
		name       string
		scanID     string
		finishedAt string
		wantReason IncidentObservationReason
	}{
		{name: "no newer scan", wantReason: IncidentReasonNoNewerObservation},
		{name: "same instant", scanID: "same-scan", finishedAt: sqliteTimestamp(lastSeen), wantReason: IncidentReasonNoNewerObservation},
		{name: "older scan", scanID: "older-scan", finishedAt: sqliteTimestamp(lastSeen.Add(-time.Nanosecond)), wantReason: IncidentReasonNoNewerObservation},
	} {
		t.Run(test.name, func(t *testing.T) {
			uncertainty := incidentObservationUncertainty(incident, test.scanID, test.finishedAt, "incomplete", model.ScanComparisonNotCompared, []byte(`{}`))
			if !uncertainty.valid() {
				t.Fatalf("uncertainty has an unrecognized enum value: %+v", uncertainty)
			}
			if uncertainty.Status != "unknown" || uncertainty.Reason != test.wantReason || uncertainty.ScanID != "" {
				t.Fatalf("non-newer evidence affected uncertainty: %+v", uncertainty)
			}
		})
	}
}

func TestIncidentCoverageUncertaintyClassifiesHostAndOmissionEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		change   model.Change
		snapshot model.Snapshot
		want     IncidentObservationReason
	}{
		{
			name:   "host evidence matches DNS name and reports down",
			change: model.Change{Key: "host-down", Kind: "host", Target: "host.example"},
			snapshot: model.Snapshot{
				Scopes: []model.Scope{{Target: "host.example", Protocol: "tcp"}},
				Hosts:  []model.HostObservation{{Address: "192.0.2.80", DNSNames: []string{"HOST.EXAMPLE."}, Status: "down"}},
			},
			want: IncidentReasonTargetHostDown,
		},
		{
			name:   "host evidence matches source target and host-state down",
			change: model.Change{Key: "host-state-down", Kind: "host", Target: "host.example"},
			snapshot: model.Snapshot{
				Scopes:     []model.Scope{{Target: "host.example", Protocol: "tcp"}},
				Hosts:      []model.HostObservation{{Address: "192.0.2.81", SourceTargets: []string{"HOST.EXAMPLE."}, Status: "up"}},
				HostStates: []model.HostState{{Address: "192.0.2.81", State: "down"}},
			},
			want: IncidentReasonTargetHostDown,
		},
		{
			name:   "hostname protocol evidence uses source target matching",
			change: model.Change{Key: "port-source", Kind: "port", Target: "host.example", Protocol: "tcp", Port: 443},
			snapshot: model.Snapshot{
				Scopes: []model.Scope{{Target: "host.example", Protocol: "tcp", Ports: "443"}},
				Hosts:  []model.HostObservation{{Address: "192.0.2.82", SourceTargets: []string{"host.example"}, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}}},
			},
		},
		{
			name:   "host omitted protocol is not treated as positive coverage",
			change: model.Change{Key: "port-omitted", Kind: "port", Target: "host.example", Protocol: "tcp", Port: 443},
			snapshot: model.Snapshot{
				Scopes: []model.Scope{{Target: "host.example", Protocol: "tcp", Ports: "443"}},
				Hosts:  []model.HostObservation{{Address: "192.0.2.83", DNSNames: []string{"host.example"}, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unknown", StatusReason: "nmap-omitted"}}}},
			},
			want: IncidentReasonProtocolUnobserved,
		},
		{
			name:   "address resolution failure is attributed to that endpoint",
			change: model.Change{Key: "port-resolution", Kind: "port-address", Target: "host.example", Address: "192.0.2.84", Protocol: "tcp", Port: 443},
			snapshot: model.Snapshot{
				Scopes:         []model.Scope{{Target: "host.example", Protocol: "tcp", Ports: "443"}},
				TargetFailures: []model.TargetCoverageFailure{{Target: "192.0.2.84", Reason: "resolution-failed"}},
			},
			want: IncidentReasonTargetResolutionFailed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := incidentCoverageUncertainty(test.change, test.snapshot); got != test.want {
				t.Fatalf("coverage uncertainty = %q; want %q", got, test.want)
			}
		})
	}
}

func findIncidentInboxItem(t *testing.T, ts *TenantStore, ctx context.Context, jobID, key string, now time.Time) IncidentInboxItem {
	t.Helper()
	page, err := ts.ListIncidentInbox(ctx, IncidentInboxFilter{View: "all_active", JobID: jobID, Limit: 100, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if item.Incident.Change.Key == key {
			return item
		}
	}
	t.Fatalf("incident %s not found in inbox", key)
	return IncidentInboxItem{}
}

func TestIncidentReviewFollowsTheOccurrenceThroughObservationAndSuppression(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job, err := ts.CreateJob(ctx, testJob("inbox-lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	incident := model.Incident{
		Change: model.Change{Key: "lifecycle", Kind: "port", Severity: "critical", Target: "lifecycle.example", Protocol: "tcp", Port: 443, Old: "closed", New: "open"},
		ScanID: "scan-opening", OpenedAt: now, LastSeenAt: now,
	}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents["lifecycle"] = incident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	opened := findIncidentInboxItem(t, ts, ctx, job.ID, "lifecycle", now)
	write := IncidentReviewWrite{Key: "lifecycle", OccurrenceToken: opened.OccurrenceToken, ExpectedRevision: 0, Status: "investigating", Note: "follow the same occurrence"}
	if _, err := ts.SaveIncidentReview(ctx, job.ID, write, "reviewer", "Reviewer", AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	incident.LastSeenAt = now.Add(time.Hour)
	incident.RecoveryCount = 2
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents["lifecycle"] = incident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	continued := findIncidentInboxItem(t, ts, ctx, job.ID, "lifecycle", now.Add(time.Hour))
	if continued.OccurrenceToken != opened.OccurrenceToken || continued.Review.Revision != 1 || continued.Review.Note != write.Note {
		t.Fatalf("same occurrence lost its review after a newer observation: %+v", continued)
	}

	// A change to any exact finding evidence gives the active row a new token,
	// and the old token cannot be used to attach its review to that row.
	incident.Change.New = "filtered"
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents["lifecycle"] = incident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	changed := findIncidentInboxItem(t, ts, ctx, job.ID, "lifecycle", now.Add(time.Hour))
	if changed.OccurrenceToken == opened.OccurrenceToken || changed.Review.Revision != 0 {
		t.Fatalf("changed evidence inherited prior review: %+v", changed)
	}
	write.ExpectedRevision = 1
	if _, err := ts.SaveIncidentReview(ctx, job.ID, write, "reviewer", "Reviewer", AuditEntry{}); !errors.Is(err, ErrIncidentOccurrenceChanged) {
		t.Fatalf("save with stale occurrence token = %v; want occurrence changed", err)
	}

	// Suppression closes the reviewed occurrence. When the same finding is
	// observed again with a new origin, it begins as a new review.
	if _, err := ts.SaveIncidentReview(ctx, job.ID, IncidentReviewWrite{
		Key: "lifecycle", OccurrenceToken: changed.OccurrenceToken, ExpectedRevision: 0, Status: "investigating", Note: "suppressed occurrence",
	}, "reviewer", "Reviewer", AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.SuppressIncidentWithAudit(ctx, job.ID, job.Job.Name, "lifecycle", AuditEntry{Action: "incident.suppressed"}); err != nil {
		t.Fatal(err)
	}
	reopenedOrigin := incident
	reopenedOrigin.ScanID = "scan-after-suppression"
	reopenedOrigin.OpenedAt = now.Add(2 * time.Hour)
	reopenedOrigin.LastSeenAt = reopenedOrigin.OpenedAt
	reopenedOrigin.RecoveryCount = 0
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		delete(state.Suppressed, "lifecycle")
		delete(state.SuppressedChanges, "lifecycle")
		state.Incidents["lifecycle"] = reopenedOrigin
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	reopened := findIncidentInboxItem(t, ts, ctx, job.ID, "lifecycle", now.Add(2*time.Hour))
	if reopened.OccurrenceToken == changed.OccurrenceToken || reopened.Review.Revision != 0 || reopened.Review.Status != "needs_review" || reopened.OpeningTimeKnown != true {
		t.Fatalf("suppression reopen inherited prior review or origin: %+v", reopened)
	}
}

func TestIncidentReviewSerializesCompetingWritersAndScanFinalization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job, err := ts.CreateJob(ctx, testJob("inbox-writers"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	incident := model.Incident{Change: model.Change{Key: "writer", Kind: "port", Severity: "warning", Target: "writer.example", Protocol: "tcp", Port: 443, Old: "closed", New: "open"}, ScanID: "scan-writer", OpenedAt: now, LastSeenAt: now}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents["writer"] = incident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	item := findIncidentInboxItem(t, ts, ctx, job.ID, "writer", now)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, note := range []string{"writer one", "writer two"} {
		note := note
		go func() {
			<-start
			_, err := ts.SaveIncidentReview(ctx, job.ID, IncidentReviewWrite{
				Key: "writer", OccurrenceToken: item.OccurrenceToken, ExpectedRevision: 0, Status: "investigating", Note: note,
			}, "reviewer", "Reviewer", AuditEntry{})
			results <- err
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrIncidentReviewRevisionConflict):
			conflicts++
		default:
			t.Fatalf("competing review write error = %v; want one success and one revision conflict", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("competing review writes produced %d successes and %d conflicts", successes, conflicts)
	}

	// Race an optimistic review save against the scan-finalization path. The
	// finalization changes the occurrence origin; either it wins and rejects
	// the stale token, or the review commits first and is closed by the new
	// occurrence projection. In neither order can the new occurrence inherit
	// the old review.
	finalizing := model.Incident{Change: model.Change{Key: "finalizing", Kind: "host", Severity: "info", Target: "finalizing.example", Old: "absent", New: "present"}, ScanID: "scan-before-finalize", OpenedAt: now, LastSeenAt: now}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents["finalizing"] = finalizing
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	before := findIncidentInboxItem(t, ts, ctx, job.ID, "finalizing", now)
	reviewStart := make(chan struct{})
	finalizeStart := make(chan struct{})
	reviewResult := make(chan error, 1)
	finalizeResult := make(chan error, 1)
	go func() {
		<-reviewStart
		_, err := ts.SaveIncidentReview(ctx, job.ID, IncidentReviewWrite{
			Key: "finalizing", OccurrenceToken: before.OccurrenceToken, ExpectedRevision: 0, Status: "investigating", Note: "scan race",
		}, "reviewer", "Reviewer", AuditEntry{})
		reviewResult <- err
	}()
	go func() {
		<-finalizeStart
		_, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
			current := state.Incidents["finalizing"]
			current.ScanID = "scan-finalized"
			current.OpenedAt = now.Add(time.Minute)
			current.LastSeenAt = current.OpenedAt
			state.Incidents["finalizing"] = current
			return nil, nil
		})
		finalizeResult <- err
	}()
	close(reviewStart)
	close(finalizeStart)
	reviewErr := <-reviewResult
	finalizeErr := <-finalizeResult
	if finalizeErr != nil {
		t.Fatalf("scan finalization racing with review = %v", finalizeErr)
	}
	if reviewErr != nil && !errors.Is(reviewErr, ErrIncidentOccurrenceChanged) {
		t.Fatalf("review racing with scan finalization = %v; want success or occurrence conflict", reviewErr)
	}
	after := findIncidentInboxItem(t, ts, ctx, job.ID, "finalizing", now.Add(time.Minute))
	if after.OccurrenceToken == before.OccurrenceToken || after.Review.Revision != 0 || after.Review.Status != "needs_review" {
		t.Fatalf("new scan occurrence inherited a racing review: %+v", after)
	}
}

func TestIncidentReviewRetentionDeletesClosedRowsAndHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job, err := ts.CreateJob(ctx, testJob("inbox-retention"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	incident := model.Incident{Change: model.Change{Key: "retained", Kind: "port", Severity: "info", Target: "retained.example", Protocol: "tcp", Port: 80}, ScanID: "scan-retained", OpenedAt: now, LastSeenAt: now}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents["retained"] = incident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	token, err := incidentOccurrenceToken(DefaultTenantID, job.ID, "retained", incident)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.SaveIncidentReview(ctx, job.ID, IncidentReviewWrite{Key: "retained", OccurrenceToken: token, Status: "investigating", Note: "retained note"}, "reviewer", "Reviewer", AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if deleted, err := s.System().deleteIncidentReviewRetentionBatches(cancelled, sqliteTimestamp(now.Add(24*time.Hour))); !errors.Is(err, context.Canceled) || deleted != 0 {
		t.Fatalf("cancelled active-review retention = deleted %d, err %v; want cancellation before deletion", deleted, err)
	}
	if deleted, err := s.System().deleteIncidentReviewRetentionBatches(ctx, sqliteTimestamp(now.Add(24*time.Hour))); err != nil || deleted != 0 {
		t.Fatalf("active-review retention = deleted %d, err %v; want active review preserved", deleted, err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM incident_reviews WHERE job_id=?`, job.ID); got != 1 {
		t.Fatalf("active review rows after retention = %d; want 1", got)
	}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		delete(state.Incidents, "retained")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	cutoff := now.Add(24 * time.Hour)
	stats, err := s.System().PruneWithStats(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if stats.IncidentReviews != 1 || stats.Total() < 1 {
		t.Fatalf("retention stats = %+v", stats)
	}
	for _, table := range []string{"incident_reviews", "incident_review_history"} {
		var count int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&count); err != nil || count != 0 {
			t.Errorf("%s rows after closed review retention = %d, %v", table, count, err)
		}
	}
}

func TestMigration68BackfillsActiveOccurrenceProjection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	job, err := defaultTenant(s).CreateJob(ctx, testJob("migration-68"))
	if err != nil {
		t.Fatal(err)
	}
	incident := model.Incident{Change: model.Change{Key: "migrated", Kind: "port", Severity: "critical", Target: "migration.example", Protocol: "tcp", Port: 443}, ScanID: "schema-67-scan", OpenedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), LastSeenAt: time.Date(2026, 10, 1, 0, 0, 0, 500000000, time.UTC)}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents["migrated"] = incident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	path := s.Path
	for _, statement := range []string{
		`DROP INDEX runtime_incidents_inbox_occurrence`, `DROP INDEX runtime_incidents_inbox_order`, `ALTER TABLE runtime_incidents DROP COLUMN occurrence_token`,
		`ALTER TABLE runtime_incidents DROP COLUMN severity`, `ALTER TABLE runtime_incidents DROP COLUMN kind`, `ALTER TABLE runtime_incidents DROP COLUMN opened_at_sort`, `ALTER TABLE runtime_incidents DROP COLUMN last_seen_at_sort`,
		`DROP INDEX incident_reviews_closed_retention`, `DROP TABLE incident_review_history`, `DROP TABLE incident_reviews`, `PRAGMA user_version=67`,
	} {
		if _, err := s.DB.ExecContext(ctx, statement); err != nil {
			t.Fatalf("prepare schema 67 fixture: %s: %v", statement, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade schema 67 fixture: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	want, err := incidentOccurrenceToken(DefaultTenantID, job.ID, "migrated", incident)
	if err != nil {
		t.Fatal(err)
	}
	var token, severity, kind, opened, lastSeen string
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT occurrence_token,severity,kind,opened_at_sort,last_seen_at_sort FROM runtime_incidents WHERE job_id=? AND key='migrated'`, job.ID).Scan(&token, &severity, &kind, &opened, &lastSeen); err != nil {
		t.Fatal(err)
	}
	if token != want || severity != "critical" || kind != "port" || opened != sqliteTimestamp(incident.OpenedAt) || lastSeen != sqliteTimestamp(incident.LastSeenAt) {
		t.Fatalf("backfilled occurrence projection = %q %q %q %q %q; want %q critical port %q %q", token, severity, kind, opened, lastSeen, want, sqliteTimestamp(incident.OpenedAt), sqliteTimestamp(incident.LastSeenAt))
	}
	var violations int
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_foreign_key_list('incident_reviews') WHERE "table"='scans'`).Scan(&violations); err != nil || violations != 0 {
		t.Fatalf("incident reviews reference scans: count=%d err=%v", violations, err)
	}
	if got := countRows(t, upgraded.DB, `PRAGMA user_version`); got != schemaVersion {
		t.Fatalf("upgraded schema version = %d, want %d", got, schemaVersion)
	}
}

func TestIncidentInboxProjectionBackfillResumesAfterCommittedBatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	job, err := defaultTenant(s).CreateJob(ctx, testJob("inbox-backfill-resume"))
	if err != nil {
		t.Fatal(err)
	}
	opened := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	incidents := make(map[string]model.Incident, incidentInboxBackfillBatchSize+1)
	for index := 0; index <= incidentInboxBackfillBatchSize; index++ {
		key := fmt.Sprintf("backfill-%03d", index)
		incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "port", Severity: "warning", Target: "backfill.example", Protocol: "tcp", Port: 443}, ScanID: "backfill-scan", OpenedAt: opened}
	}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents = incidents
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE runtime_incidents SET occurrence_token='',severity='',kind='',opened_at_sort='',last_seen_at_sort='' WHERE job_id=?`, job.ID); err != nil {
		t.Fatal(err)
	}
	interrupted, cancel := context.WithCancel(ctx)
	firstProgress := []int64{}
	err = backfillIncidentInboxProjection(interrupted, s.DB, func(processed int64) {
		firstProgress = append(firstProgress, processed)
		if processed == incidentInboxBackfillBatchSize {
			cancel()
		}
	})
	cancel()
	if !errors.Is(err, context.Canceled) || len(firstProgress) != 1 || firstProgress[0] != incidentInboxBackfillBatchSize {
		t.Fatalf("interrupted backfill = %v, progress %v; want cancellation after one committed batch", err, firstProgress)
	}
	var remaining int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM runtime_incidents WHERE job_id=? AND occurrence_token=''`, job.ID).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("unprocessed rows after interrupted backfill = %d, %v; want one", remaining, err)
	}
	resumedProgress := []int64{}
	if err := backfillIncidentInboxProjection(ctx, s.DB, func(processed int64) { resumedProgress = append(resumedProgress, processed) }); err != nil {
		t.Fatalf("resume backfill: %v", err)
	}
	if len(resumedProgress) != 1 || resumedProgress[0] != 1 {
		t.Fatalf("resumed backfill progress = %v; want one remaining row", resumedProgress)
	}
	var processed, empty int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*),SUM(CASE WHEN occurrence_token='' THEN 1 ELSE 0 END) FROM runtime_incidents WHERE job_id=?`, job.ID).Scan(&processed, &empty); err != nil || processed != incidentInboxBackfillBatchSize+1 || empty != 0 {
		t.Fatalf("backfilled projection counts = %d total, %d empty, %v", processed, empty, err)
	}
	var repeatedProgress []int64
	if err := backfillIncidentInboxProjection(ctx, s.DB, func(processed int64) { repeatedProgress = append(repeatedProgress, processed) }); err != nil || len(repeatedProgress) != 0 {
		t.Fatalf("completed backfill rerun progress = %v, %v; want an idempotent no-op", repeatedProgress, err)
	}
}

func TestIncidentInboxProjectionBackfillRejectsMalformedJSONAndRollsBackPartialBatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	job, err := defaultTenant(s).CreateJob(ctx, testJob("inbox-backfill-rollback"))
	if err != nil {
		t.Fatal(err)
	}
	incidents := []model.Incident{
		{Change: model.Change{Key: "a-retry", Kind: "port", Severity: "critical", Target: "retry.example", Protocol: "tcp", Port: 443}, ScanID: "retry-scan-a", OpenedAt: time.Now().UTC()},
		{Change: model.Change{Key: "z-retry", Kind: "port", Severity: "warning", Target: "retry.example", Protocol: "tcp", Port: 80}, ScanID: "retry-scan-z", OpenedAt: time.Now().UTC()},
	}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		for _, incident := range incidents {
			state.Incidents[incident.Change.Key] = incident
		}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE runtime_incidents SET occurrence_token='',severity='',kind='',opened_at_sort='',last_seen_at_sort='' WHERE job_id=?`, job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE runtime_incidents SET incident_json=? WHERE job_id=? AND key='z-retry'`, `{broken`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := backfillIncidentInboxProjection(ctx, s.DB, nil); err == nil {
		t.Fatal("backfill accepted malformed active-incident JSON")
	}
	var token, severity string
	if err := s.DB.QueryRowContext(ctx, `SELECT occurrence_token,severity FROM runtime_incidents WHERE job_id=? AND key='a-retry'`, job.ID).Scan(&token, &severity); err != nil {
		t.Fatal(err)
	}
	if token != "" || severity != "" {
		t.Fatalf("malformed batch changed an earlier projection row: token=%q severity=%q", token, severity)
	}

	raw, err := json.Marshal(incidents[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE runtime_incidents SET incident_json=? WHERE job_id=? AND key='z-retry'`, raw, job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_second_inbox_projection_update BEFORE UPDATE OF occurrence_token ON runtime_incidents WHEN OLD.key='z-retry' BEGIN SELECT RAISE(ABORT,'injected projection update failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := backfillIncidentInboxProjection(ctx, s.DB, nil); err == nil {
		t.Fatal("backfill succeeded after the injected second-row update failure")
	}
	var updated int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM runtime_incidents WHERE job_id=? AND occurrence_token<>''`, job.ID).Scan(&updated); err != nil {
		t.Fatal(err)
	}
	if updated != 0 {
		t.Fatalf("failed batch left %d projection rows updated; want transaction rollback", updated)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER fail_second_inbox_projection_update`); err != nil {
		t.Fatal(err)
	}
	if err := backfillIncidentInboxProjection(ctx, s.DB, nil); err != nil {
		t.Fatalf("retry backfill after correcting source and removing injected failure: %v", err)
	}
	for _, incident := range incidents {
		want, err := incidentOccurrenceToken(DefaultTenantID, job.ID, incident.Change.Key, incident)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRowContext(ctx, `SELECT occurrence_token,severity FROM runtime_incidents WHERE job_id=? AND key=?`, job.ID, incident.Change.Key).Scan(&token, &severity); err != nil {
			t.Fatal(err)
		}
		if token != want || severity != incident.Change.Severity {
			t.Errorf("retried backfill row %s = token %q severity %q; want token %q and severity %q", incident.Change.Key, token, severity, want, incident.Change.Severity)
		}
	}
}

func TestIncidentReviewsSurviveBackupAndRestore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job, err := ts.CreateJob(ctx, testJob("inbox-restore"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	incident := model.Incident{Change: model.Change{Key: "restored-review", Kind: "service", Severity: "warning", Target: "restore.example", Protocol: "tcp", Port: 443, Old: "unknown", New: "https"}, ScanID: "restore-review-scan", OpenedAt: now, LastSeenAt: now}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[incident.Change.Key] = incident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	item := findIncidentInboxItem(t, ts, ctx, job.ID, incident.Change.Key, now)
	if _, err := ts.SaveIncidentReview(ctx, job.ID, IncidentReviewWrite{
		Key: incident.Change.Key, OccurrenceToken: item.OccurrenceToken, ExpectedRevision: 0, Status: "investigating", Note: "restored private note",
	}, "reviewer", "Restore Reviewer", AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	var backup string
	backup, err = s.Backup(ctx, filepath.Join(t.TempDir(), "inbox-backup.db"))
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "restored-inbox.db")
	if _, err := Restore(ctx, backup, destination, RestoreOptions{}); err != nil {
		t.Fatalf("restore review backup: %v", err)
	}
	restored, err := OpenReadOnlyExisting(destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	page, err := restored.Tenant(DefaultTenantScope()).ListIncidentInbox(ctx, IncidentInboxFilter{View: "all_active", JobID: job.ID, Limit: 10, Now: now})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].OccurrenceToken != item.OccurrenceToken || page.Items[0].Review.Revision != 1 || page.Items[0].Review.Note != "restored private note" || page.Items[0].Review.ReviewerLabel == nil || *page.Items[0].Review.ReviewerLabel != "Restore Reviewer" {
		t.Fatalf("restored incident review = %+v, %v", page, err)
	}
	var history int
	if err := restored.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_review_history WHERE job_id=? AND occurrence_token=?`, job.ID, item.OccurrenceToken).Scan(&history); err != nil || history != 1 {
		t.Fatalf("restored review history count = %d, %v; want one", history, err)
	}
}

func containsAny(s string, values ...string) bool {
	for _, value := range values {
		if value != "" && strings.Contains(s, value) {
			return true
		}
	}
	return false
}
