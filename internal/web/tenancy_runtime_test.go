package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// tenantBaselineRows renders the baseline data of one job: its runtime
// state and metadata, incidents and baseline hosts, and the events,
// deliveries and audit records that name it.
func tenantBaselineRows(t *testing.T, db *sql.DB, jobID string) string {
	t.Helper()
	var rows []string
	for _, query := range []string{
		`SELECT quote(state_json)||updated_at FROM job_runtime WHERE job_id=?`,
		`SELECT baseline_scan_id||baseline_modified||COALESCE(baseline_epoch,'')||updated_at FROM job_runtime_meta WHERE job_id=?`,
		`SELECT group_concat(key) FROM runtime_incidents WHERE job_id=?`,
		`SELECT group_concat(address) FROM baseline_hosts WHERE job_id=?`,
		`SELECT COUNT(*) FROM events WHERE job_id=?`,
		`SELECT COUNT(*) FROM outbox WHERE tenant_id=(SELECT tenant_id FROM jobs WHERE id=?)`,
		`SELECT COUNT(*) FROM security_audit WHERE detail LIKE '%'||?||'%'`,
	} {
		var value sql.NullString
		if err := db.QueryRow(query, jobID).Scan(&value); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		rows = append(rows, value.String)
	}
	return strings.Join(rows, "\n")
}

// The baseline routes use the session's tenant. Both tenants have a job
// named "edge" whose modified baseline holds the same address with the same
// incident key; only a DNS name tells the tenants apart. The second tenant's
// administrator reads, resets and approves only its own baseline: on the
// first tenant's job every baseline route answers as for an unknown job,
// byte for byte, and changes nothing. That includes the RDAP route of a
// baseline host, which does not load the job first. The cases share one
// server, because opening a database is the slow part.
func TestBaselineRoutesUseTheSessionTenant(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{Name: "edge", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"}})
	jobA, err := defaultTenantStore(server).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	const otherTenantID = "00000000-0000-0000-0000-000000000200"
	const jobB = "00000000-0000-0000-0000-000000000b01"
	const unknownJob = "00000000-0000-0000-0000-00000000dead"
	const address = "192.0.2.10"
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	for _, statement := range []string{
		`INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES('` + otherTenantID + `','Other','other','` + stamp + `','` + stamp + `')`,
		`INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) SELECT '` + jobB + `','` + otherTenantID + `',name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs WHERE id='` + jobA.ID + `'`,
		`INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) SELECT '` + jobB + `',revision,definition_json,security_hash,created_at FROM job_revisions WHERE job_id='` + jobA.ID + `'`,
	} {
		if _, err := db.DB.ExecContext(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	key := "port|" + address + "|tcp|443"
	change := model.Change{Key: key, Kind: "port", Target: address, Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}
	for jobID, marker := range map[string]string{jobA.ID: "tenant-a", jobB: "tenant-b"} {
		hosts := []model.HostObservation{{Address: address, AddressFamily: "IPv4", DNSNames: []string{marker + ".example"}, Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "443", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}}
		scan := model.Scan{ID: "scan-" + marker, JobID: jobID, Job: "edge", StartedAt: now.Add(-time.Minute), FinishedAt: now, Status: "success", ConfigHash: job.SecurityHash(), Snapshot: model.Snapshot{Hosts: hosts}}
		if err := db.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
		if _, err := db.System().UpdateRuntime(ctx, jobID, func(state *model.JobState) ([]model.Event, error) {
			state.Baseline = &model.Snapshot{Hosts: hosts}
			state.BaselineScanID, state.BaselineConfigHash, state.BaselineModified = scan.ID, job.SecurityHash(), true
			state.Incidents[key] = model.Incident{Change: change, ScanID: scan.ID, OpenedAt: now, LastSeenAt: now}
			return nil, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	other, err := defaultTenant(db).CreateUser(ctx, store.User{Username: "other-admin", DisplayName: "Other", Role: store.RoleAdministrator, PasswordHash: "unused-hash", Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE users SET tenant_id=? WHERE id=?`, otherTenantID, other.ID); err != nil {
		t.Fatal(err)
	}
	cookies := map[string]string{}
	for name, userID := range map[string]string{"a": admin.UserID, "b": other.ID} {
		raw := "tenant-runtime-" + name
		if err := db.CreateSessionForUserWithAudit(ctx, userID, digest(raw), "csrf-"+name, now, now.Add(time.Hour), "", ""); err != nil {
			t.Fatal(err)
		}
		cookies[name] = raw
	}
	call := func(account, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "edgewatch_session", Value: cookies[account]})
		req.Header.Set("X-CSRF-Token", "csrf-"+account)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		server.api(rec, req)
		return rec
	}

	// Every baseline route on tenant A's job, from tenant B, gets the
	// response of an unknown job, and tenant A's baseline is unchanged.
	beforeA := tenantBaselineRows(t, db.DB, jobA.ID)
	for _, route := range []struct{ method, path, body string }{
		{http.MethodGet, "/baseline", ""},
		{http.MethodGet, "/baseline/hosts", ""},
		{http.MethodGet, "/baseline/hosts?q=tenant-a", ""},
		{http.MethodGet, "/baseline/hosts/" + address, ""},
		{http.MethodGet, "/baseline/hosts/" + address + "/rdap", ""},
		{http.MethodPost, "/baseline/reset", `{}`},
		{http.MethodPost, "/baseline/approve", `{"scan_id":"scan-tenant-a"}`},
	} {
		unknown := call("b", route.method, "/api/v1/jobs/"+unknownJob+route.path, route.body)
		foreign := call("b", route.method, "/api/v1/jobs/"+jobA.ID+route.path, route.body)
		if foreign.Code != http.StatusNotFound || foreign.Code != unknown.Code || foreign.Body.String() != unknown.Body.String() {
			t.Errorf("%s %s on tenant A's job from tenant B = %d %s; unknown job = %d %s", route.method, route.path, foreign.Code, foreign.Body.String(), unknown.Code, unknown.Body.String())
		}
	}
	if after := tenantBaselineRows(t, db.DB, jobA.ID); after != beforeA {
		t.Fatalf("tenant B's requests changed tenant A's baseline:\nbefore\n%s\nafter\n%s", beforeA, after)
	}

	// Each tenant reads only its own baseline hosts and job summaries, also
	// when it searches for the other tenant's marker or the shared address.
	own := map[string]string{"a": "tenant-a", "b": "tenant-b"}
	ownJob := map[string]string{"a": jobA.ID, "b": jobB}
	for account, other := range map[string]string{"a": "b", "b": "a"} {
		base := "/api/v1/jobs/" + ownJob[account]
		for _, path := range []string{base + "/baseline", base + "/baseline/hosts", base + "/baseline/hosts?q=" + address, base + "/baseline/hosts/" + address, "/api/v1/jobs"} {
			rec := call(account, http.MethodGet, path, "")
			body := rec.Body.String()
			if rec.Code != http.StatusOK || strings.Contains(body, own[other]) || strings.Contains(body, ownJob[other]) || !strings.Contains(body, ownJob[account]) {
				t.Errorf("tenant %s: GET %s = %d: %s", account, path, rec.Code, body)
			}
			if strings.Contains(path, "/hosts") && !strings.Contains(body, own[account]+".example") {
				t.Errorf("tenant %s: GET %s lacks its own host: %s", account, path, body)
			}
		}
		rec := call(account, http.MethodGet, base+"/baseline/hosts?q="+own[other], "")
		var hosts struct {
			Hosts      []json.RawMessage `json:"hosts"`
			Pagination struct {
				Total int `json:"total"`
			} `json:"pagination"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &hosts) != nil || len(hosts.Hosts) != 0 || hosts.Pagination.Total != 0 {
			t.Errorf("tenant %s: search for the other tenant's host = %d: %s", account, rec.Code, rec.Body.String())
		}
	}
	if rec := call("b", http.MethodGet, "/api/v1/jobs/"+jobB+"/baseline/hosts/"+address+"/rdap", ""); rec.Code != http.StatusOK {
		t.Fatalf("tenant B's own baseline host RDAP = %d: %s", rec.Code, rec.Body.String())
	}

	// Tenant B cannot approve tenant A's scan for its own job, and its own
	// approval and reset leave tenant A's baseline unchanged.
	unknown := call("b", http.MethodPost, "/api/v1/jobs/"+jobB+"/baseline/approve", `{"scan_id":"missing-scan"}`)
	foreign := call("b", http.MethodPost, "/api/v1/jobs/"+jobB+"/baseline/approve", `{"scan_id":"scan-tenant-a"}`)
	if foreign.Code == http.StatusOK || foreign.Code != unknown.Code || foreign.Body.String() != unknown.Body.String() {
		t.Fatalf("tenant B approved tenant A's scan = %d %s; an unknown scan = %d %s", foreign.Code, foreign.Body.String(), unknown.Code, unknown.Body.String())
	}
	if rec := call("b", http.MethodPost, "/api/v1/jobs/"+jobB+"/baseline/approve", `{"scan_id":"scan-tenant-b"}`); rec.Code != http.StatusOK {
		t.Fatalf("tenant B's own approval = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("b", http.MethodPost, "/api/v1/jobs/"+jobB+"/baseline/reset", `{}`); rec.Code != http.StatusOK {
		t.Fatalf("tenant B's own reset = %d: %s", rec.Code, rec.Body.String())
	}
	if after := tenantBaselineRows(t, db.DB, jobA.ID); after != beforeA {
		t.Fatalf("tenant B's own writes changed tenant A's baseline:\nbefore\n%s\nafter\n%s", beforeA, after)
	}
	stateB, err := db.Tenant(store.DefaultTenantScope()).RuntimeState(ctx, jobB)
	if err != nil || stateB.Baseline != nil {
		t.Fatalf("the default tenant read tenant B's state: %+v, %v", stateB, err)
	}
	if rec := call("b", http.MethodGet, "/api/v1/jobs/"+jobB+"/baseline", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"snapshot":null`) {
		t.Fatalf("tenant B's baseline after its reset = %d: %s", rec.Code, rec.Body.String())
	}
}
