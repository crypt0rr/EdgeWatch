package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

const defaultTenantLiteral = "'" + DefaultTenantID + "'"

// largeSnapshotHosts is the number of hosts in a largeSnapshotScan.
const largeSnapshotHosts = 48

// largeSnapshotScan is a successful scan whose snapshot is large enough to
// spill into overflow pages.
func largeSnapshotScan(id, jobID, job string, finished time.Time) model.Scan {
	hosts := make([]model.HostObservation, 0, largeSnapshotHosts)
	for i := range largeSnapshotHosts {
		hosts = append(hosts, model.HostObservation{
			Address:       fmt.Sprintf("192.0.2.%d", 10+i),
			AddressFamily: "IPv4",
			SourceTargets: []string{job + ".example"},
			DNSNames:      []string{strings.Repeat(fmt.Sprintf("host-%02d-", i), 60) + ".example"},
		})
	}
	return model.Scan{
		ID: id, JobID: jobID, Job: job, StartedAt: finished.Add(-time.Minute), FinishedAt: finished,
		Status: "success", ConfigHash: "config-" + job, Snapshot: model.Snapshot{Hosts: hosts},
		Changes: []model.Change{{Key: "change-" + id, Kind: "port-opened", Target: job, New: strings.Repeat("d", 512)}},
	}
}

// columnSnapshot renders the rows of table with the given columns, each with
// its rowid.
func columnSnapshot(t *testing.T, db *sql.DB, table string, columns []string) string {
	t.Helper()
	var out strings.Builder
	query := `SELECT rowid,"` + strings.Join(columns, `","`) + `" FROM ` + table + ` ORDER BY rowid`
	if err := snapshotRows(db, query, &out); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return out.String()
}

// queryStrings returns the first column of every row of query, with NULL
// as "<null>".
func queryStrings(t *testing.T, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value sql.NullString
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		if !value.Valid {
			value.String = "<null>"
		}
		values = append(values, value.String)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return values
}

// indexKeys lists the key columns of index with their sort order.
func indexKeys(t *testing.T, db *sql.DB, index string) string {
	t.Helper()
	var keys sql.NullString
	if err := db.QueryRow(`SELECT group_concat(k,',') FROM (SELECT name || CASE WHEN "desc" THEN ' DESC' ELSE '' END AS k FROM pragma_index_xinfo(?) WHERE key=1 ORDER BY seqno)`, index).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	return keys.String
}

// queryPlan returns the EXPLAIN QUERY PLAN details of query.
func queryPlan(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	rows, err := db.Query(`EXPLAIN QUERY PLAN `+query, args...)
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
	return strings.Join(details, "; ")
}

// insertJobRows creates bare default-tenant jobs rows for fixtures that save
// scans of made-up job IDs. From schema 53 a scan with a job ID must belong
// to the tenant of an existing job.
func insertJobRows(t *testing.T, s *Store, ids ...string) {
	t.Helper()
	stamp := sqliteTimestamp(time.Now())
	for _, id := range ids {
		if _, err := s.DB.Exec(`INSERT INTO jobs(id,tenant_id,name,definition_json,created_at,updated_at) VALUES(?,?,?,'{}',?,?)`, id, DefaultTenantID, id, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
}

// insertSecondTenantJob copies the job source into the second tenant under
// the same name, with its revisions and silence state, because no product
// API creates a job in another tenant yet.
func insertSecondTenantJob(t *testing.T, s *Store, source, id string) {
	t.Helper()
	for _, statement := range []string{
		`INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) SELECT ?1,'` + secondTenantID + `',name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs WHERE id=?2`,
		`INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) SELECT ?1,revision,definition_json,security_hash,created_at FROM job_revisions WHERE job_id=?2`,
		`INSERT INTO job_silence_state(job_id,eligible_at,updated_at) SELECT ?1,eligible_at,updated_at FROM job_silence_state WHERE job_id=?2`,
	} {
		if _, err := s.DB.Exec(statement, id, source); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

func setTenantState(t *testing.T, s *Store, tenant, state string) {
	t.Helper()
	if _, err := s.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, state, tenant); err != nil {
		t.Fatal(err)
	}
}

// The guard triggers refuse a row whose tenant does not follow its job or
// dashboard, a tenant that is being deleted, and a changed tenant.
func TestSchema53GuardTriggers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	insertSecondTenant(t, s)
	jobA, err := defaultTenant(s).CreateJob(ctx, testJob("edge"))
	if err != nil {
		t.Fatal(err)
	}
	const jobB = "00000000-0000-0000-0000-000000000b01"
	insertSecondTenantJob(t, s, jobA.ID, jobB)
	stamp := sqliteTimestamp(time.Now())
	var tenantNone any
	sequence := 0
	scan := func(jobID any, tenant ...any) func() error {
		return func() error {
			sequence++
			columns, values := "id,job_id,job,started_at,finished_at,status,config_hash,snapshot_json", "?,?,'edge',?,?,'success','hash','{}'"
			args := []any{fmt.Sprintf("guard-scan-%d", sequence), jobID, stamp, stamp}
			if len(tenant) == 1 {
				columns, values, args = columns+",tenant_id", values+",?", append(args, tenant[0])
			}
			_, err := s.DB.Exec(`INSERT INTO scans(`+columns+`) VALUES(`+values+`)`, args...)
			return err
		}
	}
	event := func(jobID any, tenant ...any) func() error {
		return func() error {
			columns, values := "type,job,job_id,payload_json,created_at", "'guard','edge',?,'{}',?"
			args := []any{jobID, stamp}
			if len(tenant) == 1 {
				columns, values, args = columns+",tenant_id", values+",?", append(args, tenant[0])
			}
			_, err := s.DB.Exec(`INSERT INTO events(`+columns+`) VALUES(`+values+`)`, args...)
			return err
		}
	}
	const (
		scanJob      = "scans.tenant_id must be the tenant of the scan's job"
		scanState    = "scans.tenant_id must name an active or disabled tenant"
		eventJob     = "events.tenant_id must be the tenant of the event's job"
		eventState   = "events.tenant_id must name an active or disabled tenant"
		hostTenant   = "a public dashboard host must belong to a job of the dashboard's tenant"
		unknownJob   = "00000000-0000-0000-0000-00000000dead"
		unknownOwner = "00000000-0000-0000-0000-000000000999"
	)
	type guardCase struct {
		name    string
		write   func() error
		wantErr string
	}
	run := func(label string, cases []guardCase) {
		t.Helper()
		for _, tc := range cases {
			err := tc.write()
			if tc.wantErr == "" && err != nil {
				t.Errorf("%s: %s: %v, want success", label, tc.name, err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("%s: %s: %v, want %q", label, tc.name, err, tc.wantErr)
			}
		}
	}

	run("active tenants", []guardCase{
		{"scan in its job's tenant", scan(jobA.ID, DefaultTenantID), ""},
		{"scan of a default-tenant job by the column default", scan(jobA.ID), ""},
		{"scan of a second-tenant job", scan(jobB, secondTenantID), ""},
		{"scan in another tenant than its job", scan(jobA.ID, secondTenantID), scanJob},
		// The column default is the default tenant, and the trigger refuses
		// it for a job of another tenant.
		{"scan of a second-tenant job by the column default", scan(jobB), scanJob},
		{"scan without a tenant", scan(jobA.ID, tenantNone), scanJob},
		{"scan of an unknown job", scan(unknownJob, DefaultTenantID), scanJob},
		{"legacy scan with a NULL job ID", scan(tenantNone), ""},
		{"legacy scan with an empty job ID", scan("", DefaultTenantID), ""},
		{"legacy scan in the second tenant", scan("", secondTenantID), scanJob},
		{"legacy scan in an unknown tenant", scan("", unknownOwner), scanJob},

		{"event in its job's tenant", event(jobA.ID, DefaultTenantID), ""},
		{"event of a default-tenant job by the column default", event(jobA.ID), ""},
		{"event of a second-tenant job", event(jobB, secondTenantID), ""},
		{"event in another tenant than its job", event(jobA.ID, secondTenantID), eventJob},
		{"event of a second-tenant job by the column default", event(jobB), eventJob},
		{"job event without a tenant", event(jobA.ID, tenantNone), eventJob},
		{"event of an unknown job", event(unknownJob, DefaultTenantID), eventJob},
		{"platform event", event("", tenantNone), ""},
		{"platform event with a NULL job ID", event(tenantNone, tenantNone), ""},
		{"event without a job in the second tenant", event("", secondTenantID), ""},
		{"event without a job in an unknown tenant", event("", unknownOwner), eventState},
	})

	// A disabled tenant keeps its history growing; a tenant that is being
	// deleted, or is deleted, takes no new rows.
	for _, tc := range []struct {
		state   string
		allowed bool
	}{{"disabled", true}, {"deleting", false}, {"deleted", false}} {
		setTenantState(t, s, secondTenantID, tc.state)
		scanErr, eventErr := scanState, eventState
		if tc.allowed {
			scanErr, eventErr = "", ""
		}
		run("second tenant "+tc.state, []guardCase{
			{"scan", scan(jobB, secondTenantID), scanErr},
			{"job event", event(jobB, secondTenantID), eventErr},
			{"event without a job", event("", secondTenantID), eventErr},
			{"platform event", event("", tenantNone), ""},
			{"default tenant scan", scan(jobA.ID, DefaultTenantID), ""},
		})
	}
	setTenantState(t, s, secondTenantID, "active")

	// The tenant of a history row, a job and a dashboard cannot change,
	// even to the same value. Other columns stay writable.
	if err := defaultTenant(s).SavePublicDashboard(ctx, PublicDashboard{}, nil, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		statement string
		wantErr   string
	}{
		{`UPDATE scans SET tenant_id=tenant_id WHERE job_id='` + jobA.ID + `'`, "scans.tenant_id cannot be changed"},
		{`UPDATE scans SET tenant_id='` + secondTenantID + `' WHERE job_id='` + jobA.ID + `'`, "scans.tenant_id cannot be changed"},
		{`UPDATE events SET tenant_id=NULL WHERE job_id='` + jobA.ID + `'`, "events.tenant_id cannot be changed"},
		{`UPDATE jobs SET tenant_id='` + secondTenantID + `' WHERE id='` + jobA.ID + `'`, "jobs.tenant_id cannot be changed"},
		{`UPDATE public_dashboards SET tenant_id='` + secondTenantID + `'`, "public_dashboards.tenant_id cannot be changed"},
		{`UPDATE scans SET status='failed' WHERE job_id='` + jobA.ID + `'`, ""},
		{`UPDATE events SET created_at=created_at WHERE job_id='` + jobA.ID + `'`, ""},
		{`UPDATE jobs SET name='renamed' WHERE id='` + jobA.ID + `'`, ""},
	} {
		_, err := s.DB.Exec(tc.statement)
		if tc.wantErr == "" && err != nil {
			t.Errorf("%s: %v", tc.statement, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: %v, want %q", tc.statement, err, tc.wantErr)
		}
	}

	// A published host belongs to a job of the dashboard's tenant.
	var defaultDashboard int64
	if err := s.DB.QueryRow(`SELECT id FROM public_dashboards WHERE tenant_id=?`, DefaultTenantID).Scan(&defaultDashboard); err != nil {
		t.Fatal(err)
	}
	var secondDashboard int64
	if err := s.DB.QueryRow(`INSERT INTO public_dashboards(tenant_id,updated_at) VALUES(?,?) RETURNING id`, secondTenantID, stamp).Scan(&secondDashboard); err != nil {
		t.Fatal(err)
	}
	host := func(dashboard int64, jobID, address string) func() error {
		return func() error {
			_, err := s.DB.Exec(`INSERT INTO public_dashboard_hosts(dashboard_id,job_id,address,created_at) VALUES(?,?,?,?)`, dashboard, jobID, address, stamp)
			return err
		}
	}
	update := func(statement string) func() error {
		return func() error {
			_, err := s.DB.Exec(statement)
			return err
		}
	}
	run("public dashboard hosts", []guardCase{
		{"host of a job in the dashboard's tenant", host(defaultDashboard, jobA.ID, "192.0.2.10"), ""},
		{"host of a second-tenant job in the second dashboard", host(secondDashboard, jobB, "192.0.2.10"), ""},
		{"host of a second-tenant job", host(defaultDashboard, jobB, "192.0.2.11"), hostTenant},
		{"host of a default-tenant job in the second dashboard", host(secondDashboard, jobA.ID, "192.0.2.11"), hostTenant},
		{"host of an unknown dashboard", host(999, jobA.ID, "192.0.2.12"), hostTenant},
		{"move a host to a job of another tenant", update(`UPDATE public_dashboard_hosts SET job_id='` + jobB + `' WHERE job_id='` + jobA.ID + `'`), hostTenant},
		{"move a host to the dashboard of another tenant", update(fmt.Sprintf(`UPDATE public_dashboard_hosts SET dashboard_id=%d WHERE job_id='%s'`, secondDashboard, jobA.ID)), hostTenant},
		{"change the address of a host", update(`UPDATE public_dashboard_hosts SET address='192.0.2.20' WHERE job_id='` + jobA.ID + `'`), ""},
	})
	// The store refuses such a host itself, as a host of an unknown job,
	// before the trigger would.
	if err := defaultTenant(s).SavePublicDashboard(ctx, PublicDashboard{Enabled: true}, []PublicDashboardHost{{JobID: jobB, Address: "192.0.2.10"}}, AuditEntry{}); !errors.Is(err, ErrValidation) || err.Error() != errPublicDashboardHostJob.Error() {
		t.Fatalf("publish a host of another tenant's job = %v, want %q", err, errPublicDashboardHostJob)
	}
}

// tenantOf returns the tenant_id of the one row that query selects, or
// "<null>".
func tenantOf(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	tenants := queryStrings(t, db, query, args...)
	if len(tenants) != 1 {
		t.Fatalf("%s selects %d rows %v, want one", query, len(tenants), tenants)
	}
	return tenants[0]
}

// Every writer of scans, events and outbox names the tenant, derived from
// the job, or none for a platform event, in the write transaction.
func TestSchema53WritersAttributeTheirTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	insertSecondTenant(t, s)
	jobA, err := defaultTenant(s).CreateJob(ctx, testJob("edge"))
	if err != nil {
		t.Fatal(err)
	}
	const jobB = "00000000-0000-0000-0000-000000000b01"
	insertSecondTenantJob(t, s, jobA.ID, jobB)
	now := time.Now().UTC()
	const platform = "<null>"

	// Scans follow their job; a legacy scan without a job ID belongs to the
	// default tenant; a scan of an unknown job is refused.
	for id, jobID := range map[string]string{"scan-a": jobA.ID, "scan-b": jobB, "scan-legacy": ""} {
		if err := s.System().SaveScan(ctx, largeSnapshotScan(id, jobID, "edge", now)); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	if err := s.System().SaveScan(ctx, largeSnapshotScan("scan-unknown", "00000000-0000-0000-0000-00000000dead", "edge", now)); err == nil || !strings.Contains(err.Error(), "scans.tenant_id must be the tenant of the scan's job") {
		t.Fatalf("save a scan of an unknown job = %v", err)
	}
	for id, want := range map[string]string{"scan-a": DefaultTenantID, "scan-b": secondTenantID, "scan-legacy": DefaultTenantID} {
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM scans WHERE id=?`, id); got != want {
			t.Fatalf("%s tenant = %s, want %s", id, got, want)
		}
	}

	// Runtime, silence and job events, with the deliveries queued for them.
	for jobID, want := range map[string]string{jobA.ID: DefaultTenantID, jobB: secondTenantID} {
		destination := "reset-" + want
		if _, err := s.Tenant(TenantScope{id: want}).ResetRuntimeWithOutbox(ctx, jobID, "edge", []string{destination}); err != nil {
			t.Fatal(err)
		}
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM events WHERE type='baseline-reset' AND job_id=?`, jobID); got != want {
			t.Fatalf("runtime event tenant = %s, want %s", got, want)
		}
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM outbox WHERE destination=?`, destination); got != want {
			t.Fatalf("runtime delivery tenant = %s, want %s", got, want)
		}
		destination = "silence-" + want
		// Two days after the last successful scan.
		if _, created, err := s.System().RecordJobSilenceAlert(ctx, jobID, "edge", now.Add(-24*time.Hour), now.Add(48*time.Hour), time.Hour, []string{destination}); err != nil || !created {
			t.Fatalf("silence alert = %v, %v", created, err)
		}
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM events WHERE type='job-silent' AND job_id=?`, jobID); got != want {
			t.Fatalf("silence event tenant = %s, want %s", got, want)
		}
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM outbox WHERE destination=?`, destination); got != want {
			t.Fatalf("silence delivery tenant = %s, want %s", got, want)
		}
	}
	job := testJob("edge")
	job.Targets = []string{"192.0.2.20"}
	if _, _, events, err := defaultTenant(s).UpdateJobWithEventsWithOutbox(ctx, jobA.ID, jobA.Revision, job, true, false, true, []string{"job-update"}); err != nil || len(events) != 1 {
		t.Fatalf("scope change events = %v, %v", events, err)
	}
	if got := tenantOf(t, s.DB, `SELECT tenant_id FROM outbox WHERE destination='job-update'`); got != DefaultTenantID {
		t.Fatalf("job update delivery tenant = %s", got)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='baseline-reset' AND job_id=? AND tenant_id=?`, jobA.ID, DefaultTenantID); got != 2 {
		t.Fatalf("default-tenant reset events = %d, want 2", got)
	}

	// An update alert has the platform's copy, without a tenant, and a copy
	// for each tenant it is routed to. The deliveries of a copy belong to
	// its owner.
	if _, err := s.Platform().RecordInstalledVersion(ctx, "1.0.0", "", false, nil); err != nil {
		t.Fatal(err)
	}
	routes := []UpdateAlertRoute{{}, {TenantID: DefaultTenantID, Destinations: []string{"updates"}}, {TenantID: secondTenantID}}
	if events, err := s.Platform().RecordInstalledVersion(ctx, "1.1.0", "https://example.invalid/1.1.0", true, routes); err != nil || len(events) != 3 {
		t.Fatalf("upgrade alert = %v, %v", events, err)
	}
	if events, err := s.Platform().RecordReleaseCheck(ctx, "1.1.0", "1.2.0", "https://example.invalid/1.2.0", "EdgeWatch 1.2.0", "", "etag", true, routes); err != nil || len(events) != 3 {
		t.Fatalf("update available alert = %v, %v", events, err)
	}
	for _, eventType := range []string{"application-updated", "application-update-available"} {
		if got := queryStrings(t, s.DB, `SELECT tenant_id FROM events WHERE type=? ORDER BY tenant_id`, eventType); !slices.Equal(got, []string{platform, DefaultTenantID, secondTenantID}) {
			t.Fatalf("%s event tenants = %v, want the platform, then each tenant", eventType, got)
		}
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE destination='updates' AND tenant_id=?`, DefaultTenantID); got != 2 {
		t.Fatalf("default tenant update deliveries = %d, want 2", got)
	}

	// A config.yaml job's events and deliveries belong to the default
	// tenant; a delivery queued directly follows its event.
	if _, err := s.System().UpdateState(ctx, "legacy", func(*model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "legacy-change", Job: "legacy", CreatedAt: now}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := tenantOf(t, s.DB, `SELECT tenant_id FROM events WHERE type='legacy-change'`); got != DefaultTenantID {
		t.Fatalf("legacy event tenant = %s", got)
	}
	for destination, event := range map[string]model.Event{
		"queued-legacy":   {Type: "legacy-change", Job: "legacy", CreatedAt: now},
		"queued-job-b":    {Type: "change", JobID: jobB, Job: "edge", CreatedAt: now},
		"queued-platform": {Type: "notice", Message: "platform", CreatedAt: now},
	} {
		if err := s.System().QueueEvent(ctx, destination, event); err != nil {
			t.Fatal(err)
		}
	}
	for destination, want := range map[string]string{"queued-legacy": DefaultTenantID, "queued-job-b": secondTenantID, "queued-platform": platform} {
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM outbox WHERE destination=?`, destination); got != want {
			t.Fatalf("%s delivery tenant = %s, want %s", destination, got, want)
		}
	}

	// A dropped delivery's event belongs to the delivery's tenant.
	for _, destination := range []string{"queued-job-b", "queued-platform"} {
		for attempt := 0; attempt < deliveryMaxAttempts; attempt++ {
			if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE destination=?`, sqliteTimestamp(time.Now().Add(-time.Minute)), destination); err != nil {
				t.Fatal(err)
			}
			due, err := s.System().ClaimDueDeliveriesExcluding(ctx, 1, "terminal-owner", excludeAllBut(t, s, destination))
			if err != nil || len(due) != 1 || due[0].Destination != destination {
				t.Fatalf("claim %s attempt %d = %#v, %v", destination, attempt, due, err)
			}
			if err := s.System().DeliveryResultClaim(ctx, due[0].ID, due[0].ClaimToken, errors.New("provider failed")); err != nil {
				t.Fatal(err)
			}
		}
	}
	terminal := queryStrings(t, s.DB, `SELECT tenant_id FROM events WHERE type='notification-delivery-terminal' ORDER BY id`)
	if !slices.Equal(terminal, []string{secondTenantID, platform}) {
		t.Fatalf("terminal delivery event tenants = %v", terminal)
	}

	// A tenant that is being deleted takes no new history, and the write
	// that would add it fails as a whole.
	setTenantState(t, s, secondTenantID, "deleting")
	if err := s.System().SaveScan(ctx, largeSnapshotScan("scan-deleting", jobB, "edge", now)); err == nil || !strings.Contains(err.Error(), "must name an active or disabled tenant") {
		t.Fatalf("save a scan of a deleting tenant = %v", err)
	}
	if _, err := s.Tenant(TenantScope{id: secondTenantID}).ResetRuntimeWithOutbox(ctx, jobB, "edge", []string{"reset-deleting"}); err == nil || !strings.Contains(err.Error(), "must name an active or disabled tenant") {
		t.Fatalf("reset a job of a deleting tenant = %v", err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE destination='reset-deleting'`); got != 0 {
		t.Fatalf("deliveries of a refused event = %d", got)
	}
}

// excludeAllBut returns every pending destination except keep, so a claim
// takes only keep's delivery.
func excludeAllBut(t *testing.T, s *Store, keep string) []string {
	t.Helper()
	return queryStrings(t, s.DB, `SELECT DISTINCT destination FROM outbox WHERE destination<>?`, keep)
}

// A quarantined delivery keeps the tenant of its outbox row.
func TestRestoreQuarantineKeepsTheDeliveryTenant(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		// staged turns the source into the staged schema.
		staged []string
		want   map[string]string
	}{
		{
			name: "backup",
			want: map[string]string{"queued-job-a": DefaultTenantID, "queued-job-b": secondTenantID, "queued-platform": "<null>"},
		},
		{
			// The quarantine table is created by the restore, in its
			// schema-35 shape, and gains the tenant column.
			name:   "backup without a quarantine table",
			staged: []string{"DROP TABLE restore_quarantined_deliveries"},
			want:   map[string]string{"queued-job-a": DefaultTenantID, "queued-job-b": secondTenantID, "queued-platform": "<null>"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			source := filepath.Join(dir, "source.db")
			destination := filepath.Join(dir, "destination.db")
			s, err := Open(source)
			if err != nil {
				t.Fatal(err)
			}
			insertSecondTenant(t, s)
			jobA, err := defaultTenant(s).CreateJob(ctx, testJob("edge"))
			if err != nil {
				t.Fatal(err)
			}
			const jobB = "00000000-0000-0000-0000-000000000b01"
			insertSecondTenantJob(t, s, jobA.ID, jobB)
			for destination, event := range map[string]model.Event{
				"queued-job-a":    {Type: "change", JobID: jobA.ID, Job: "edge"},
				"queued-job-b":    {Type: "change", JobID: jobB, Job: "edge"},
				"queued-platform": {Type: "notice", Message: "platform"},
			} {
				if err := s.System().QueueEvent(ctx, destination, event); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			execFixtureStatements(t, source, tc.staged)
			createRestoreFixture(t, destination, "destination")

			result, err := Restore(ctx, source, destination, RestoreOptions{})
			if err != nil {
				t.Fatalf("restore: %v", err)
			}
			if result.PendingDeliveriesAffected != 3 {
				t.Fatalf("restore result = %#v", result)
			}
			restored, err := Open(destination)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			if got := countRows(t, restored.DB, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL`); got != 0 {
				t.Fatalf("pending deliveries after the restore = %d", got)
			}
			for destination, want := range tc.want {
				if got := tenantOf(t, restored.DB, `SELECT tenant_id FROM restore_quarantined_deliveries WHERE destination=? AND restore_epoch=?`, destination, result.RestoreEpoch); got != want {
					t.Fatalf("%s quarantine tenant = %s, want %s", destination, got, want)
				}
			}
			if got := tableColumns(t, restored.DB, "restore_quarantined_deliveries"); got[len(got)-1] != "tenant_id TEXT notnull=0 default="+defaultTenantLiteral+" pk=0" {
				t.Fatalf("quarantine columns = %v", got)
			}
		})
	}
}
