package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The scanner profile routes and the job profile selection resolve profiles
// through the session's tenant. An administrator of another tenant sees the
// built-in profiles and their own, never the first tenant's custom profile:
// reading, updating or archiving it, or pinning it to a job, fails exactly
// as an unknown profile does, and the job list does not reveal its newer
// revision. The built-in profiles stay selectable in every tenant.
func TestScannerProfileRoutesUseTheSessionTenant(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	own := defaultTenantStore(server)
	nmap := config.ScannerProfile{Engine: config.EngineNmap}
	profileA, err := own.CreateScannerProfile(ctx, "Tenant profile", "", nmap, "admin")
	if err != nil {
		t.Fatal(err)
	}
	pinnedA := config.NormalizeJob(config.Job{Name: "pinned", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "1", Mode: "connect", ProfileID: profileA.ID}})
	if err := server.applySelectedScannerProfile(ctx, own, &pinnedA, false, false); err != nil {
		t.Fatal(err)
	}
	jobA, err := own.CreateJob(ctx, pinnedA)
	if err != nil {
		t.Fatal(err)
	}
	// The job keeps revision 1 while the profile moves on to revision 2.
	if _, err := own.UpdateScannerProfile(ctx, profileA.ID, 1, "Tenant profile", "revised", nmap, "admin"); err != nil {
		t.Fatal(err)
	}

	// The other tenant has an administrator with the same password, a
	// profile with the same name, and a copy of the pinned job. No product
	// API pins another tenant's profile, so the copy is made in SQL.
	const otherTenantID = "00000000-0000-0000-0000-000000000200"
	const jobB = "00000000-0000-0000-0000-000000000b01"
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	other, err := defaultTenant(db).CreateUser(ctx, store.User{Username: "other-admin", DisplayName: "Other", Role: store.RoleAdministrator, PasswordHash: "unused-hash", Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, []any{otherTenantID, stamp, stamp}},
		{`UPDATE users SET tenant_id=?,password_hash=(SELECT password_hash FROM users WHERE id=?) WHERE id=?`, []any{otherTenantID, admin.UserID, other.ID}},
		{`INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) SELECT ?1,?3,name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs WHERE id=?2`, []any{jobB, jobA.ID, otherTenantID}},
		{`INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) SELECT ?1,revision,definition_json,security_hash,created_at FROM job_revisions WHERE job_id=?2`, []any{jobB, jobA.ID}},
		{`INSERT INTO job_silence_state(job_id,eligible_at,updated_at) SELECT ?1,eligible_at,updated_at FROM job_silence_state WHERE job_id=?2`, []any{jobB, jobA.ID}},
	} {
		if _, err := db.DB.ExecContext(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("%s: %v", statement.sql, err)
		}
	}
	scopeB, err := db.TenantScopeByID(ctx, otherTenantID)
	if err != nil {
		t.Fatal(err)
	}
	profileB, err := db.Tenant(scopeB).CreateScannerProfile(ctx, "Tenant profile", "", nmap, "other-admin")
	if err != nil {
		t.Fatal(err)
	}
	cookies := map[string]string{}
	for name, userID := range map[string]string{"own": admin.UserID, "other": other.ID} {
		raw := "tenant-profile-" + name
		if err := db.CreateSessionForUserWithAudit(ctx, userID, digest(raw), "csrf-"+name, now, now.Add(time.Hour), "", ""); err != nil {
			t.Fatal(err)
		}
		cookies[name] = raw
	}
	call := func(account, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "edgewatch_session", Value: cookies[account]})
		req.Header.Set("X-CSRF-Token", "csrf-"+account)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.api(rec, req)
		return rec
	}
	// sameAsUnknown sends the request for the first tenant's profile and for
	// an unknown one as the other tenant, and requires identical answers.
	const unknown = "00000000-0000-0000-0000-00000000dead"
	sameAsUnknown := func(method, path, body string, status int) {
		t.Helper()
		leaked := call("other", method, strings.ReplaceAll(path, "{id}", profileA.ID), strings.ReplaceAll(body, "{id}", profileA.ID))
		missing := call("other", method, strings.ReplaceAll(path, "{id}", unknown), strings.ReplaceAll(body, "{id}", unknown))
		if leaked.Code != status || leaked.Code != missing.Code || leaked.Body.String() != missing.Body.String() {
			t.Errorf("other tenant: %s %s = %d %s; unknown profile = %d %s; want %d for both", method, path, leaked.Code, leaked.Body.String(), missing.Code, missing.Body.String(), status)
		}
	}

	profiles := "/api/v1/scanner-profiles"
	for account, want := range map[string][]string{"own": {profileA.ID}, "other": {profileB.ID}} {
		rec := call(account, http.MethodGet, profiles+"?include_archived=true", "")
		var list struct {
			Profiles []struct {
				ID string `json:"id"`
			} `json:"profiles"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil {
			t.Fatalf("%s tenant: profile list = %d: %s", account, rec.Code, rec.Body.String())
		}
		var got []string
		for _, profile := range list.Profiles {
			got = append(got, profile.ID)
		}
		sort.Strings(got)
		want = append(want, store.BuiltinNmapProfileID, store.BuiltinNaabuProfileID)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s tenant: profiles = %v, want %v", account, got, want)
		}
	}
	for _, id := range []string{profileB.ID, store.BuiltinNaabuProfileID} {
		if rec := call("other", http.MethodGet, profiles+"/"+id, ""); rec.Code != http.StatusOK {
			t.Errorf("other tenant: GET profile %s = %d: %s", id, rec.Code, rec.Body.String())
		}
	}
	sameAsUnknown(http.MethodGet, profiles+"/{id}", "", http.StatusNotFound)
	sameAsUnknown(http.MethodGet, profiles+"/{id}/revisions", "", http.StatusNotFound)
	sameAsUnknown(http.MethodPut, profiles+"/{id}", `{"name":"stolen","engine":"nmap","password":"administrator password","revision":2}`, http.StatusNotFound)
	sameAsUnknown(http.MethodDelete, profiles+"/{id}", `{"password":"administrator password","revision":2}`, http.StatusNotFound)
	if current, err := own.GetScannerProfile(ctx, profileA.ID); err != nil || current.Name != "Tenant profile" || current.Revision != 2 || current.Archived {
		t.Fatalf("the first tenant's profile changed: %+v, %v", current, err)
	}

	// The job list flags a newer revision of the pinned profile only in the
	// profile's own tenant.
	type jobView struct {
		ID  string `json:"id"`
		Job struct {
			TCP struct {
				ProfileID       string `json:"profile_id"`
				ProfileRevision int64  `json:"profile_revision"`
				UpdateAvailable bool   `json:"profile_update_available"`
				LatestRevision  int64  `json:"profile_latest_revision"`
			} `json:"tcp"`
		} `json:"job"`
	}
	for account, want := range map[string]struct {
		id       string
		revision int64
	}{"own": {jobA.ID, 2}, "other": {jobB, 0}} {
		var list struct {
			Jobs []jobView `json:"jobs"`
		}
		rec := call(account, http.MethodGet, "/api/v1/jobs", "")
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Jobs) != 1 {
			t.Fatalf("%s tenant: job list = %d: %s", account, rec.Code, rec.Body.String())
		}
		var single jobView
		rec = call(account, http.MethodGet, "/api/v1/jobs/"+want.id, "")
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &single) != nil {
			t.Fatalf("%s tenant: job = %d: %s", account, rec.Code, rec.Body.String())
		}
		for _, view := range []jobView{list.Jobs[0], single} {
			tcp := view.Job.TCP
			if view.ID != want.id || tcp.ProfileID != profileA.ID || tcp.ProfileRevision != 1 || tcp.UpdateAvailable != (want.revision > 0) || tcp.LatestRevision != want.revision {
				t.Errorf("%s tenant: job = %+v, want the latest profile revision %d", account, view, want.revision)
			}
		}
	}

	// The other tenant cannot pin the first tenant's profile to a new job,
	// or keep it on its copy of the pinned job; either is refused as an
	// unknown profile. The built-in profiles and its own can be pinned.
	newJob := func(name, profileID string) string {
		return fmt.Sprintf(`{"name":%q,"schedule":"0 * * * *","timezone":"UTC","targets":["192.0.2.20"],"tcp":{"ports":"1","mode":"connect","profile_id":%q}}`, name, profileID)
	}
	update := fromConfig(pinnedA)
	update.Revision = 1
	update.TCP.ProfileID = "{id}"
	updateBody, err := json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	sameAsUnknown(http.MethodPost, "/api/v1/jobs", newJob("pinned-elsewhere", "{id}"), http.StatusBadRequest)
	sameAsUnknown(http.MethodPut, "/api/v1/jobs/"+jobB, string(updateBody), http.StatusBadRequest)
	if rec := call("other", http.MethodPost, "/api/v1/jobs", newJob("pinned-elsewhere", unknown)); !strings.Contains(rec.Body.String(), "selected scanner profile was not found") {
		t.Fatalf("an unknown profile is refused with %d: %s", rec.Code, rec.Body.String())
	}
	for name, profileID := range map[string]string{"pinned-builtin": store.BuiltinNmapProfileID, "pinned-own": profileB.ID} {
		rec := call("other", http.MethodPost, "/api/v1/jobs", newJob(name, profileID))
		var created jobView
		if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &created) != nil || created.Job.TCP.ProfileID != profileID || created.Job.TCP.ProfileRevision != 1 {
			t.Fatalf("other tenant: create a job pinned to %s = %d: %s", profileID, rec.Code, rec.Body.String())
		}
	}
	update.TCP.ProfileID = store.BuiltinNmapProfileID
	updateBody, err = json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	if rec := call("other", http.MethodPut, "/api/v1/jobs/"+jobB, string(updateBody)); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), store.BuiltinNmapProfileID) {
		t.Fatalf("other tenant: pin a built-in profile to its job = %d: %s", rec.Code, rec.Body.String())
	}
}
