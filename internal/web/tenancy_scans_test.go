package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The scan routes and the host inventory read through the store that the
// API router resolved from the session. Two tenants' jobs scanned the same
// address. An account of the second tenant gets exactly the response for an
// unknown scan when it names the first tenant's scan, on every /scans/{id}
// route and under its own job, and its host inventory and search show only
// its own scan's host.
func TestScanRoutesUseTheSessionTenant(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{Name: "tenant-scan-job", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"}})
	recordA, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	const (
		otherTenantID = "00000000-0000-0000-0000-000000000200"
		jobB          = "00000000-0000-0000-0000-000000000b01"
		address       = "192.0.2.10"
	)
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, []any{otherTenantID, stamp, stamp}},
		// Tenant B's job is a copy of tenant A's, with the same name.
		{`INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) SELECT ?,?,name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs WHERE id=?`, []any{jobB, otherTenantID, recordA.ID}},
	} {
		if _, err := db.DB.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for scanID, jobID := range map[string]string{"scan-tenant-a": recordA.ID, "scan-tenant-b": jobB} {
		host := model.HostObservation{Address: address, AddressFamily: "IPv4", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "443", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}
		scan := model.Scan{ID: scanID, JobID: jobID, Job: job.Name, StartedAt: now.Add(-time.Minute), FinishedAt: now, Status: "success", ConfigHash: job.SecurityHash(), Snapshot: model.Snapshot{Hosts: []model.HostObservation{host}}}
		if err := db.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	other, err := defaultTenant(db).CreateUser(ctx, store.User{Username: "other-scan-admin", DisplayName: "Other", Role: store.RoleAdministrator, PasswordHash: "unused-hash", Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE users SET tenant_id=? WHERE id=?`, otherTenantID, other.ID); err != nil {
		t.Fatal(err)
	}
	cookies := map[string]string{}
	for name, userID := range map[string]string{"own": admin.UserID, "other": other.ID} {
		raw := "tenant-scan-route-" + name
		if err := db.CreateSessionForUserWithAudit(ctx, userID, digest(raw), "csrf-"+name, now, now.Add(time.Hour), "", ""); err != nil {
			t.Fatal(err)
		}
		cookies[name] = raw
	}
	get := func(account, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(&http.Cookie{Name: "edgewatch_session", Value: cookies[account]})
		rec := httptest.NewRecorder()
		server.api(rec, req)
		return rec
	}

	// Each route names the scan at {scan}. Routes that tenant A can read
	// with its own scan show that the scan exists.
	for _, route := range []struct {
		path     string
		readable bool
	}{
		{"/api/v1/scans/{scan}", true},
		{"/api/v1/scans/{scan}/summary", true},
		{"/api/v1/scans/{scan}/hosts", true},
		{"/api/v1/scans/{scan}/hosts/" + address, true},
		{"/api/v1/scans/{scan}/hosts/" + address + "/rdap", false},
		{"/api/v1/jobs/" + jobB + "/scans/{scan}", false},
		{"/api/v1/jobs/" + jobB + "/scans/{scan}/hosts", false},
		{"/api/v1/jobs/" + jobB + "/scans/{scan}/hosts/" + address, false},
	} {
		unknown := get("other", strings.Replace(route.path, "{scan}", "unknown-scan", 1))
		foreign := get("other", strings.Replace(route.path, "{scan}", "scan-tenant-a", 1))
		if unknown.Code != http.StatusNotFound || foreign.Code != unknown.Code || foreign.Body.String() != unknown.Body.String() {
			t.Errorf("tenant B: GET %s with tenant A's scan = %d %s; an unknown scan = %d %s", route.path, foreign.Code, foreign.Body.String(), unknown.Code, unknown.Body.String())
		}
		if !route.readable {
			continue
		}
		if rec := get("own", strings.Replace(route.path, "{scan}", "scan-tenant-a", 1)); rec.Code != http.StatusOK {
			t.Errorf("tenant A: GET %s = %d: %s", route.path, rec.Code, rec.Body.String())
		}
	}
	if rec := get("other", "/api/v1/scans/scan-tenant-b/hosts/"+address); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"scan-tenant-b"`) {
		t.Errorf("tenant B: own scan host = %d: %s", rec.Code, rec.Body.String())
	}

	inventory := func(account, query string) []string {
		t.Helper()
		rec := get(account, "/api/v1/hosts"+query)
		var body struct {
			Hosts []struct {
				Address string `json:"address"`
				JobID   string `json:"job_id"`
				ScanID  string `json:"scan_id"`
			} `json:"hosts"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			t.Fatalf("%s: GET /hosts%s = %d: %s", account, query, rec.Code, rec.Body.String())
		}
		hosts := make([]string, 0, len(body.Hosts))
		for _, host := range body.Hosts {
			hosts = append(hosts, host.ScanID+"@"+host.JobID+"/"+host.Address)
		}
		sort.Strings(hosts)
		return hosts
	}
	for account, want := range map[string]string{"own": "scan-tenant-a@" + recordA.ID + "/" + address, "other": "scan-tenant-b@" + jobB + "/" + address} {
		for _, query := range []string{"", "?q=" + address, "?q=19", "?protocol=tcp&has_open_ports=true"} {
			if got := inventory(account, query); len(got) != 1 || got[0] != want {
				t.Errorf("%s: host inventory%s = %v, want [%s]", account, query, got, want)
			}
		}
	}

	// A scan from before the host index holds only units, and the inventory
	// reads its snapshot. Each tenant's inventory merges its own such scans
	// and never the other tenant's.
	for scanID, legacy := range map[string]struct{ job, address string }{"legacy-tenant-a": {recordA.ID, "192.0.2.20"}, "legacy-tenant-b": {jobB, "192.0.2.30"}} {
		scan := model.Scan{ID: scanID, JobID: legacy.job, Job: job.Name, StartedAt: now.Add(-2 * time.Minute), FinishedAt: now.Add(-time.Minute), Status: "success", ConfigHash: job.SecurityHash(),
			Snapshot: model.Snapshot{Units: []model.Unit{{Target: legacy.address, Addresses: []string{legacy.address}, Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}}}}
		if err := db.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	for account, want := range map[string][]string{
		"own":   {"legacy-tenant-a@" + recordA.ID + "/192.0.2.20", "scan-tenant-a@" + recordA.ID + "/" + address},
		"other": {"legacy-tenant-b@" + jobB + "/192.0.2.30", "scan-tenant-b@" + jobB + "/" + address},
	} {
		if got := inventory(account, ""); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: host inventory with legacy scans = %v, want %v", account, got, want)
		}
	}
}
