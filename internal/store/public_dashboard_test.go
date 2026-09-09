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
