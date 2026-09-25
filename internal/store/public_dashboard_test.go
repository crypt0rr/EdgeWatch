package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestPublicDashboardRoundTripNormalizesAndDeduplicatesHosts(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	jobIDs := map[string]string{}
	for _, name := range []string{"job-a", "job-b"} {
		job := config.NormalizeJob(config.Job{Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "22", Mode: "syn"}})
		record, err := s.CreateJob(ctx, job)
		if err != nil {
			t.Fatal(err)
		}
		jobIDs[name] = record.ID
	}
	err := s.SavePublicDashboard(ctx, PublicDashboard{Enabled: true, Title: "  Network status  ", Introduction: "  selected hosts  "}, []PublicDashboardHost{
		{JobID: jobIDs["job-b"], Address: " 2001:0db8::1 "},
		{JobID: jobIDs["job-a"], Address: "192.0.2.1"},
		{JobID: jobIDs["job-a"], Address: " 192.0.2.1 "},
	}, AuditEntry{Action: "public_dashboard.updated", Detail: "test", ActorUsername: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	dashboard, err := s.GetPublicDashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !dashboard.Enabled || dashboard.Title != "Network status" || dashboard.Introduction != "selected hosts" || dashboard.UpdatedAt.IsZero() {
		t.Fatalf("dashboard = %#v", dashboard)
	}
	if len(dashboard.Hosts) != 2 {
		t.Fatalf("normalized host allow-list = %#v", dashboard.Hosts)
	}
	seen := map[string]string{}
	for _, host := range dashboard.Hosts {
		seen[host.JobID] = host.Address
	}
	if seen[jobIDs["job-a"]] != "192.0.2.1" || seen[jobIDs["job-b"]] != "2001:db8::1" {
		t.Fatalf("normalized host allow-list = %#v", dashboard.Hosts)
	}
	var auditCount int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action=?`, "public_dashboard.updated").Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("audit rows = %d, want 1", auditCount)
	}

	// Invalid input must roll back both the dashboard text and the host set.
	if err := s.SavePublicDashboard(ctx, PublicDashboard{Enabled: false, Title: "replacement"}, []PublicDashboardHost{{JobID: jobIDs["job-a"], Address: "not-an-ip"}}, AuditEntry{}); err == nil {
		t.Fatal("invalid host was accepted")
	}
	after, err := s.GetPublicDashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Title != dashboard.Title || len(after.Hosts) != len(dashboard.Hosts) {
		t.Fatalf("invalid save was not rolled back: %#v", after)
	}
	if err := s.SavePublicDashboard(ctx, PublicDashboard{Title: "x", Introduction: strings.Repeat("i", 501)}, nil, AuditEntry{}); err == nil {
		t.Fatal("overlong introduction was accepted")
	}
	if err := s.SavePublicDashboard(ctx, PublicDashboard{Title: strings.Repeat("🙂", 120), Introduction: strings.Repeat("é", 500)}, nil, AuditEntry{}); err != nil {
		t.Fatalf("unicode text at the character limit was rejected: %v", err)
	}
	if err := s.SavePublicDashboard(ctx, PublicDashboard{Title: strings.Repeat("🙂", 121)}, nil, AuditEntry{}); err == nil {
		t.Fatal("unicode title beyond the character limit was accepted")
	}
	if err := s.SavePublicDashboard(ctx, PublicDashboard{Title: "x"}, []PublicDashboardHost{{Address: "192.0.2.1"}}, AuditEntry{}); err == nil {
		t.Fatal("host without job was accepted")
	}

}

func TestPublicDashboardNotFoundAndLatestSuccessfulHostScope(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM public_dashboard WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPublicDashboard(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing dashboard error = %v", err)
	}

	jobConfig := config.NormalizeJob(config.Job{Name: "host-scope", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.0/30"}, TCP: &config.Protocol{Ports: "22", Mode: "syn"}})
	job, err := s.CreateJob(ctx, jobConfig)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := model.Scan{ID: "scope-old", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now.Add(-time.Minute), FinishedAt: now.Add(-time.Minute), Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.7", Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "22", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 22, State: "open"}}}}}}}}
	latest := model.Scan{ID: "scope-latest", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", NmapVersion: "7.99", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.7", Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "22,443", ScannedPortCount: 2, Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}}}}
	failed := model.Scan{ID: "scope-failed", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now.Add(time.Minute), FinishedAt: now.Add(time.Minute), Status: "failed", Snapshot: latest.Snapshot}
	for _, scan := range []model.Scan{old, latest, failed} {
		if err := s.SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	host, summary, err := s.GetLatestSuccessfulJobHost(ctx, job.ID, "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if host.ScanID != latest.ID || host.DataQuality != "detailed" || host.Host.Protocols[0].Ports[0].Port != 443 || summary.ID != latest.ID {
		t.Fatalf("latest scoped host = %#v, summary = %#v", host, summary)
	}
	if _, _, err := s.GetLatestSuccessfulJobHost(ctx, "another-job", "198.51.100.7"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-job lookup error = %v", err)
	}
	if _, _, err := s.GetLatestSuccessfulJobHost(ctx, job.ID, "198.51.100.8"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing-address lookup error = %v", err)
	}
	if _, _, err := s.GetLatestSuccessfulJobHost(ctx, job.ID, "not-an-ip"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid-address lookup error = %v", err)
	}
}

func TestLatestSuccessfulJobHostsResolvesSelectionsInOneSet(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	jobA, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "batch-a", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.1"}, TCP: &config.Protocol{Ports: "22", Mode: "syn"}}))
	if err != nil {
		t.Fatal(err)
	}
	jobB, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "batch-b", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"2001:db8::1"}, TCP: &config.Protocol{Ports: "443", Mode: "syn"}}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, scan := range []model.Scan{
		{ID: "batch-a-scan", JobID: jobA.ID, JobRevision: jobA.Revision, Job: jobA.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.1", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 22, State: "open"}}}}}}}},
		{ID: "batch-b-scan", JobID: jobB.ID, JobRevision: jobB.Revision, Job: jobB.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "2001:db8::1", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}}}},
	} {
		if err := s.SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	results, err := s.GetLatestSuccessfulJobHosts(ctx, []PublicDashboardHost{{JobID: jobA.ID, Address: "198.51.100.1"}, {JobID: jobB.ID, Address: "2001:0db8::1"}, {JobID: "missing", Address: "198.51.100.1"}})
	if err != nil || len(results) != 2 {
		t.Fatalf("batch latest hosts = %#v, %v", results, err)
	}
	if results[0].Summary.ID == "" || results[1].Summary.ID == "" {
		t.Fatalf("batch summaries missing: %#v", results)
	}
}

func TestLatestSuccessfulJobHostsUsesProjectionBeforeHistoryFallback(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	jobA, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "same-address-a", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.44"}, TCP: &config.Protocol{Ports: "22", Mode: "connect"}}))
	if err != nil {
		t.Fatal(err)
	}
	jobB, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "same-address-b", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.44"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"}}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, scan := range []model.Scan{
		{ID: "same-address-a-scan", JobID: jobA.ID, JobRevision: jobA.Revision, Job: jobA.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.44", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 22, State: "open"}}}}}}}},
		{ID: "same-address-b-scan", JobID: jobB.ID, JobRevision: jobB.Revision, Job: jobB.Job.Name, StartedAt: now.Add(time.Second), FinishedAt: now.Add(time.Second), Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.44", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}}}},
	} {
		if err := s.SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}

	// The address-keyed projection now points at job B. Job A must still be
	// resolved exactly through the bounded history fallback rather than being
	// given job B's observation.
	results, err := s.GetLatestSuccessfulJobHosts(ctx, []PublicDashboardHost{{JobID: jobA.ID, Address: "198.51.100.44"}, {JobID: jobB.ID, Address: "198.51.100.44"}})
	if err != nil || len(results) != 2 {
		t.Fatalf("same-address lookup = %#v, %v", results, err)
	}
	for _, result := range results {
		if result.Selection.JobID == jobA.ID && result.Summary.ID != "same-address-a-scan" {
			t.Fatalf("job A crossed into projection row: %#v", result)
		}
		if result.Selection.JobID == jobB.ID && result.Summary.ID != "same-address-b-scan" {
			t.Fatalf("job B did not use projection row: %#v", result)
		}
	}

	// Removing the source host row does not invalidate the maintained
	// projection. This guards the fast path from silently falling back to
	// decoding/ranking retained history for every normal selection.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM scan_hosts WHERE scan_id=?`, "same-address-b-scan"); err != nil {
		t.Fatal(err)
	}
	results, err = s.GetLatestSuccessfulJobHosts(ctx, []PublicDashboardHost{{JobID: jobB.ID, Address: "198.51.100.44"}})
	if err != nil || len(results) != 1 || results[0].Summary.ID != "same-address-b-scan" {
		t.Fatalf("projection-only lookup = %#v, %v", results, err)
	}
}

func TestLatestSuccessfulJobHostsHistoryQueryScopesSelectionBeforeLookup(t *testing.T) {
	s := openTestStore(t)
	query, args := latestSuccessfulJobHostsHistoryQuery([]PublicDashboardHost{{JobID: "job", Address: "198.51.100.10"}})
	rows, err := s.DB.QueryContext(context.Background(), `EXPLAIN QUERY PLAN `+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	joined := strings.ToLower(strings.Join(details, " "))
	if !strings.Contains(joined, "correlated scalar subquery") {
		t.Fatalf("history lookup did not use a per-selection lookup: %v", details)
	}
	if strings.Contains(query, "row_number") {
		t.Fatal("history lookup still materializes a window over all matching rows")
	}
}

func TestPublicDashboardDefaultsBlankTitle(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.SavePublicDashboard(ctx, PublicDashboard{Title: "   "}, nil, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	dashboard, err := s.GetPublicDashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if dashboard.Title != "EdgeWatch public status" || dashboard.Hosts == nil {
		t.Fatalf("default dashboard = %#v", dashboard)
	}
}

func TestSavePublicDashboardIfCurrentRejectsAStaleToken(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	loaded, err := s.GetPublicDashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SavePublicDashboardIfCurrent(ctx, loaded.UpdatedAt, PublicDashboard{Enabled: true, Title: "Status", Introduction: "v1"}, nil, AuditEntry{Action: "public_dashboard.updated"}); err != nil {
		t.Fatal(err)
	}
	published, err := s.GetPublicDashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !published.UpdatedAt.After(loaded.UpdatedAt) {
		t.Fatalf("save did not advance updated_at: %s -> %s", loaded.UpdatedAt, published.UpdatedAt)
	}
	err = s.SavePublicDashboardIfCurrent(ctx, loaded.UpdatedAt, PublicDashboard{Enabled: false, Title: "Stale"}, nil, AuditEntry{Action: "public_dashboard.updated"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save error = %v, want ErrConflict", err)
	}
	current, err := s.GetPublicDashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Enabled || current.Title != "Status" || !current.UpdatedAt.Equal(published.UpdatedAt) {
		t.Fatalf("stale save changed the dashboard: %#v", current)
	}
	var audits int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='public_dashboard.updated'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit rows = %d (%v), want only the accepted save", audits, err)
	}

	// Saves within one clock tick, or after the clock stepped back, still
	// advance the token, so a stale editor cannot match a newer save.
	future := time.Now().UTC().Add(time.Hour)
	if _, err := s.DB.ExecContext(ctx, `UPDATE public_dashboard SET updated_at=? WHERE id=1`, future.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePublicDashboardIfCurrent(ctx, future, PublicDashboard{Enabled: true, Title: "After clock step"}, nil, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	stepped, err := s.GetPublicDashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !stepped.UpdatedAt.After(future) {
		t.Fatalf("updated_at after a clock step = %s, want later than %s", stepped.UpdatedAt, future)
	}
	if err := s.SavePublicDashboardIfCurrent(ctx, future, PublicDashboard{Title: "Stale again"}, nil, AuditEntry{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("save with the pre-step token = %v, want ErrConflict", err)
	}
}

func TestListLegacyPublicScansExcludesIndexedSnapshots(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "legacy-public", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.1"}, TCP: &config.Protocol{Ports: "80", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	indexed := model.Scan{
		ID: "public-indexed", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name,
		StartedAt: now.Add(-time.Minute), FinishedAt: now.Add(-time.Minute), Status: "success",
		Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.1", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 80, State: "open"}}}}}}},
	}
	legacy := model.Scan{
		ID: "public-legacy", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name,
		StartedAt: now, FinishedAt: now, Status: "success",
		Snapshot: model.Snapshot{Units: []model.Unit{{Target: "198.51.100.1", Protocol: "tcp", Addresses: []string{"198.51.100.1"}, Ports: []model.PortState{{Port: 80, State: "open"}}}}},
	}
	if err := s.SaveScan(ctx, indexed); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveScan(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListLegacyPublicScans(ctx, job.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != legacy.ID {
		t.Fatalf("legacy public rows = %#v", rows)
	}
}
