package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// otherTenantRows renders every row of a tenant that the host commands could
// read or change: its jobs, scans, runtime state, incidents, events,
// deliveries, destinations, and audit records.
func otherTenantRows(t *testing.T, database, tenantID string) string {
	t.Helper()
	reader, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var rows []string
	for _, query := range []string{
		`SELECT group_concat(id||':'||revision||':'||updated_at, ',') FROM (SELECT id,revision,updated_at FROM jobs WHERE tenant_id=? ORDER BY id)`,
		`SELECT group_concat(id||':'||status, ',') FROM (SELECT id,status FROM scans WHERE tenant_id=? ORDER BY id)`,
		`SELECT group_concat(quote(r.state_json)||r.updated_at, ',') FROM job_runtime AS r JOIN jobs AS j ON j.id=r.job_id AND j.tenant_id=?`,
		`SELECT group_concat(i.key, ',') FROM runtime_incidents AS i JOIN jobs AS j ON j.id=i.job_id AND j.tenant_id=?`,
		`SELECT COUNT(*) FROM events WHERE tenant_id=?`,
		`SELECT COUNT(*)||':'||COUNT(sent_at)||':'||group_concat(terminal_at, ',') FROM outbox WHERE tenant_id=?`,
		`SELECT group_concat(id||':'||revision, ',') FROM managed_notifications WHERE tenant_id=?`,
		`SELECT COUNT(*) FROM security_audit WHERE tenant_id=?`,
	} {
		var value sql.NullString
		if err := reader.DB.QueryRow(query, tenantID).Scan(&value); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		rows = append(rows, value.String)
	}
	return strings.Join(rows, "\n")
}

const otherTenantID = "00000000-0000-0000-0000-000000000200"

// seedTwoTenants gives the default tenant a job named edge with one scan,
// and creates a second tenant in SQL, because no product API creates one
// yet. The second tenant has an enabled destination, which rawURL names,
// and its own job named edge with a scan, a baseline, an incident, an
// event, and a failed delivery, plus a job named only-other. It returns the
// default tenant's job.
func seedTwoTenants(t *testing.T, database, rawURL string) store.JobRecord {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, otherTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	scope, err := s.TenantScopeByID(ctx, otherTenantID)
	if err != nil {
		t.Fatal(err)
	}
	own, other := s.Tenant(store.DefaultTenantScope()), s.Tenant(scope)
	// The other tenant's destination exists before its jobs, so their
	// alerts follow it; the default tenant has no destination.
	notifier, err := notify.New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := notifier.Tenant(other).CreateManagedWithAudit(ctx, "Other operations", rawURL, true, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	job := managedCLIJob("edge")
	ownJob, err := own.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	otherJob, err := other.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.CreateJob(ctx, managedCLIJob("only-other")); err != nil {
		t.Fatal(err)
	}
	snapshot := model.Snapshot{Units: []model.Unit{{Target: "192.0.2.10", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}}
	for _, scan := range []model.Scan{
		{ID: "scan-default", JobID: ownJob.ID, JobRevision: ownJob.Revision},
		{ID: "scan-other", JobID: otherJob.ID, JobRevision: otherJob.Revision},
	} {
		scan.Job, scan.StartedAt, scan.FinishedAt, scan.Status, scan.ConfigHash, scan.Snapshot = job.Name, now.Add(-time.Minute), now, "success", job.SecurityHash(), snapshot
		if err := s.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	key := "port|192.0.2.10|tcp|1"
	if _, err := s.System().UpdateRuntimeWithOutbox(ctx, otherJob.ID, []string{"other-destination"}, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &snapshot
		state.BaselineScanID, state.BaselineConfigHash = "scan-other", job.SecurityHash()
		if state.Incidents == nil {
			state.Incidents = map[string]model.Incident{}
		}
		state.Incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "port", Target: "192.0.2.10", Protocol: "tcp", Port: 1, Old: "closed", New: "open", Severity: "critical"}, ScanID: "scan-other", OpenedAt: now, LastSeenAt: now}
		return []model.Event{{Type: "change", JobID: otherJob.ID, Job: job.Name, ScanID: "scan-other", Message: "other tenant change", CreatedAt: now}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET terminal_at=? WHERE tenant_id=?`, stamp, otherTenantID); err != nil {
		t.Fatal(err)
	}
	return ownJob
}

// Host commands act on the default tenant's data. They neither show nor
// change the second tenant's jobs, scans, baselines, deliveries, or
// destinations, even for its job of the same name, and they alert and audit
// only in the default tenant.
func TestHostCommandsActOnlyOnTheDefaultTenant(t *testing.T) {
	ctx := context.Background()
	database := storetest.FreshPath(t)
	dir := filepath.Dir(database)
	rawURL, calls := importStartupWebhook(t)
	ownJob := seedTwoTenants(t, database, rawURL)
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cli := func(args ...string) (string, error) {
		t.Helper()
		stdout, _, err := captureCLIOutput(t, func() error {
			return run(append(args, "--config", configPath, "--output", "json"))
		})
		return stdout, err
	}
	before := otherTenantRows(t, database, otherTenantID)

	// status lists only the default tenant's job, with its own scan and no
	// baseline, incident, or failed delivery of the other tenant.
	out, err := cli("status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var rows []struct {
		Name             string `json:"name"`
		BaselineScanID   string `json:"baseline_scan_id"`
		ActiveIncidents  int    `json:"active_incidents"`
		LastScanID       string `json:"last_scan_id"`
		FailedDeliveries int    `json:"failed_deliveries"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("status output %q: %v", out, err)
	}
	if len(rows) != 1 || rows[0].Name != "edge" || rows[0].LastScanID != "scan-default" || rows[0].BaselineScanID != "" || rows[0].ActiveIncidents != 0 || rows[0].FailedDeliveries != 0 {
		t.Fatalf("status rows = %+v, want only the default tenant's job", rows)
	}
	if _, err := cli("status", "--job", "only-other"); err == nil || !strings.Contains(err.Error(), `unknown job "only-other"`) {
		t.Fatalf("status of the other tenant's job = %v", err)
	}

	// history returns only the default tenant's scans and events, with or
	// without the shared job name.
	for _, filter := range [][]string{nil, {"--job", "edge"}} {
		out, err := cli(append([]string{"history"}, filter...)...)
		if err != nil {
			t.Fatalf("history %v: %v", filter, err)
		}
		var history struct {
			Scans  []model.Scan  `json:"scans"`
			Events []model.Event `json:"events"`
		}
		if err := json.Unmarshal([]byte(out), &history); err != nil {
			t.Fatalf("history output %q: %v", out, err)
		}
		if len(history.Scans) != 1 || history.Scans[0].ID != "scan-default" || history.Scans[0].JobID != ownJob.ID || len(history.Events) != 0 {
			t.Fatalf("history %v = %+v, want only the default tenant's scan", filter, history)
		}
	}

	// baseline export includes only the default tenant's job, and the other
	// tenant's job is not found by name.
	for i, filter := range [][]string{nil, {"--job", "edge"}} {
		path := filepath.Join(dir, fmt.Sprintf("export-%d.json", i))
		if _, err := cli(append([]string{"baseline", "export", "--out", path}, filter...)...); err != nil {
			t.Fatalf("baseline export %v: %v", filter, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var export store.BaselineExport
		if err := json.Unmarshal(raw, &export); err != nil {
			t.Fatal(err)
		}
		if len(export.Jobs) != 1 || export.Jobs[0].JobID != ownJob.ID || export.Jobs[0].BaselineScanID != "" || export.Jobs[0].Baseline != nil {
			t.Fatalf("baseline export %v = %s, want only the default tenant's job", filter, raw)
		}
	}
	if _, err := cli("baseline", "export", "--job", "only-other", "--out", filepath.Join(dir, "export-other.json")); err == nil {
		t.Fatal("baseline export found the other tenant's job")
	}

	// baseline approve does not accept the other tenant's scan for the
	// default tenant's job; approve and reset change only the default
	// tenant's baseline.
	if _, err := cli("baseline", "approve", "--job", "edge", "--scan-id", "scan-other"); err == nil {
		t.Fatal("baseline approve accepted the other tenant's scan")
	}
	if _, err := cli("baseline", "approve", "--job", "edge", "--scan-id", "scan-default"); err != nil {
		t.Fatalf("baseline approve: %v", err)
	}
	if _, err := cli("baseline", "reset", "--job", "edge"); err != nil {
		t.Fatalf("baseline reset: %v", err)
	}
	if _, err := cli("baseline", "reset", "--job", "only-other"); err == nil || !strings.Contains(err.Error(), "unknown managed job") {
		t.Fatalf("baseline reset of the other tenant's job = %v", err)
	}

	// scan runs the default tenant's job of the shared name and does not
	// find the other tenant's job.
	nmap := writeFakeNmap(t, dir, false)
	if _, err := cli("scan", "--job", "only-other", "--nmap", nmap); err == nil || !strings.Contains(err.Error(), "unknown managed job") {
		t.Fatalf("scan of the other tenant's job = %v", err)
	}
	out, err = cli("scan", "--job", "edge", "--nmap", nmap)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var scanned struct {
		Scan model.Scan `json:"scan"`
	}
	if err := json.Unmarshal([]byte(out), &scanned); err != nil || scanned.Scan.JobID != ownJob.ID || scanned.Scan.Status != "success" {
		t.Fatalf("scan output = %s, %v; want a successful scan of the default tenant's job", out, err)
	}

	// notify test tests only the default tenant's destinations, of which
	// there are none.
	out, err = cli("notify", "test")
	if err != nil {
		t.Fatalf("notify test: %v", err)
	}
	var summary map[string]int
	if err := json.Unmarshal([]byte(out), &summary); err != nil || summary["tested"] != 0 || summary["locked"] != 0 {
		t.Fatalf("notify test summary = %s, %v; want nothing tested", out, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("the other tenant's destination received %d messages", calls.Load())
	}

	if after := otherTenantRows(t, database, otherTenantID); after != before {
		t.Fatalf("host commands changed the other tenant's data:\nbefore\n%s\nafter\n%s", before, after)
	}
	reader, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var actions []string
	auditRows, err := reader.DB.QueryContext(ctx, `SELECT action FROM security_audit WHERE actor_username='host-cli' AND actor_kind='host' AND tenant_id=? ORDER BY id`, store.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer auditRows.Close()
	for auditRows.Next() {
		var action string
		if err := auditRows.Scan(&action); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, action)
	}
	if err := auditRows.Err(); err != nil {
		t.Fatal(err)
	}
	if want := "baseline.approved,baseline.reset,scan.run_requested,notifications.test"; strings.Join(actions, ",") != want {
		t.Fatalf("host audit actions in the default tenant = %v, want %s", actions, want)
	}
}
