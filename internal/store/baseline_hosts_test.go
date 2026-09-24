package store

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestBaselineHostProjectionPaginatesAcceptedOverlay(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	snapshot := model.Snapshot{Hosts: []model.HostObservation{
		{Address: "198.51.100.2", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 443, State: "open", Service: &model.ServiceObservation{Product: "nginx"}}}}}},
		{Address: "198.51.100.1", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 22, State: "open"}}}}},
	}}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES('overlay-job','overlay','{}',1,0,1,'now','now')`); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceBaselineHostProjection(ctx, "overlay-job", snapshot); err != nil {
		t.Fatal(err)
	}
	open := true
	page, err := s.ListBaselineHostsPage(ctx, "overlay-job", "198.51.100.1", "tcp", &open, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].Host.Address != "198.51.100.1" {
		t.Fatalf("baseline page = %#v", page)
	}
	page, err = s.ListBaselineHostsPage(ctx, "overlay-job", "nginx", "tcp", &open, 10, 0)
	if err != nil || page.Total != 1 || page.Items[0].Host.Address != "198.51.100.2" {
		t.Fatalf("baseline service search = %#v, %v", page, err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET name='renamed-overlay' WHERE id='overlay-job'`); err != nil {
		t.Fatal(err)
	}
	page, err = s.ListBaselineHostsPage(ctx, "overlay-job", "renamed-overlay", "", nil, 10, 0)
	if err != nil || page.Total != 2 {
		t.Fatalf("baseline current job-name search = %#v, %v", page, err)
	}
	page, err = s.ListBaselineHostsPage(ctx, "overlay-job", "overlay-job", "", nil, 10, 0)
	if err != nil || page.Total != 0 {
		t.Fatalf("stale baseline job-name search = %#v, %v", page, err)
	}
	if _, err := s.GetBaselineHost(ctx, "overlay-job", "198.51.100.2"); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStateSummaryUsesProjectionCounts(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES('summary-job','summary','{}',1,0,1,'now','now')`); err != nil {
		t.Fatal(err)
	}
	state := []byte(`{"baseline":{"hosts":[{"address":"198.51.100.1"}]},"baseline_scan_id":"scan-1","baseline_config_hash":"hash","candidate_count":2,"candidate_attempts":3,"incidents":{"one":{}},"pending":{"two":{}}}`)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, "summary-job", state, "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scans(id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json) VALUES('scan-1','summary','now','now','success','','Nmap','hash','{}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scan_hosts(scan_id,address,host_json) VALUES('scan-1','198.51.100.1','{}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "summary-job", 1, "scan-1", "hash", 0, 1, 2, 3, 0, 1, "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO runtime_incidents(job_id,key,incident_json) VALUES(?,?,?)`, "summary-job", "one", `{}`); err != nil {
		t.Fatal(err)
	}
	summary, err := s.RuntimeStateSummary(ctx, "summary-job")
	if err != nil {
		t.Fatal(err)
	}
	if !summary.HasBaseline || summary.BaselineHostCount != 1 || summary.IncidentCount != 1 || summary.PendingCount != 1 || summary.CandidateCount != 2 || summary.CandidateAttempts != 3 {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestRuntimeStateSummaryUsesBaselineProjectionCounts(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES('projected-summary','projected-summary','{}',1,0,1,'now','now')`); err != nil {
		t.Fatal(err)
	}
	state := []byte(`{"baseline":{"hosts":[{"address":"198.51.100.20"}]},"baseline_scan_id":"projected-baseline"}`)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, "projected-summary", state, "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "projected-summary", 1, "projected-baseline", "", 0, 1, 0, 0, 0, 0, "now"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceBaselineHostProjection(ctx, "projected-summary", model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.20"}, {Address: "198.51.100.21"}}}); err != nil {
		t.Fatal(err)
	}

	summary, err := s.RuntimeStateSummary(ctx, "projected-summary")
	if err != nil {
		t.Fatal(err)
	}
	if summary.BaselineHostCount != 2 {
		t.Fatalf("projected summary = %#v", summary)
	}
}

func TestRuntimeStateSummaryFallsBackToLegacyUnitsWithMetadata(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES('unit-metadata-summary','unit-metadata-summary','{}',1,0,1,'now','now')`); err != nil {
		t.Fatal(err)
	}
	state := []byte(`{"baseline":{"units":[{"addresses":["198.51.100.30","198.51.100.31"]}]}}`)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, "unit-metadata-summary", state, "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "unit-metadata-summary", 1, "", "", 0, 1, 0, 0, 0, 0, "now"); err != nil {
		t.Fatal(err)
	}

	summary, err := s.RuntimeStateSummary(ctx, "unit-metadata-summary")
	if err != nil {
		t.Fatal(err)
	}
	if summary.BaselineHostCount != 2 {
		t.Fatalf("unit metadata summary = %#v", summary)
	}
}

func TestRuntimeStateSummaryHandlesMetadataWithoutLegacyBaseline(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	for _, jobID := range []string{"metadata-no-runtime", "metadata-no-baseline"} {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES(?,?,?,1,0,1,'now','now')`, jobID, jobID, `{}`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, jobID, 1, "", "", 0, 0, 0, 0, 0, 0, "now"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, "metadata-no-baseline", []byte(`{"candidate_count":1}`), "now"); err != nil {
		t.Fatal(err)
	}

	for _, jobID := range []string{"metadata-no-runtime", "metadata-no-baseline"} {
		summary, err := s.RuntimeStateSummary(ctx, jobID)
		if err != nil {
			t.Fatal(err)
		}
		if summary.HasBaseline || summary.BaselineHostCount != 0 {
			t.Fatalf("metadata-only summary for %s = %#v", jobID, summary)
		}
	}
}

func TestRuntimeStateSummaryPreservesLegacyHostsOnMetadataFastPath(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES('legacy-metadata-summary','legacy-metadata-summary','{}',1,0,1,'now','now')`); err != nil {
		t.Fatal(err)
	}
	state := []byte(`{"baseline":{"hosts":[{"address":"198.51.100.10"},{"address":"198.51.100.11"}]},"baseline_scan_id":"legacy-baseline","baseline_config_hash":"hash"}`)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, "legacy-metadata-summary", state, "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "legacy-metadata-summary", 1, "legacy-baseline", "hash", 0, 1, 0, 0, 0, 0, "now"); err != nil {
		t.Fatal(err)
	}

	summary, err := s.RuntimeStateSummary(ctx, "legacy-metadata-summary")
	if err != nil {
		t.Fatal(err)
	}
	if !summary.HasBaseline || summary.BaselineHostCount != 2 {
		t.Fatalf("legacy metadata summary = %#v", summary)
	}
}

func TestRuntimeStateSummaryCountsLegacyUnitAddresses(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES('legacy-summary-job','legacy-summary','{}',1,0,1,'now','now')`); err != nil {
		t.Fatal(err)
	}
	state := []byte(`{"baseline":{"units":[{"target":"dns.example","protocol":"tcp","addresses":["198.51.100.1","198.51.100.2"]}]},"candidate_count":1}`)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, "legacy-summary-job", state, "now"); err != nil {
		t.Fatal(err)
	}
	summary, err := s.RuntimeStateSummary(ctx, "legacy-summary-job")
	if err != nil {
		t.Fatal(err)
	}
	if !summary.HasBaseline || summary.BaselineHostCount != 2 {
		t.Fatalf("legacy summary = %#v", summary)
	}
}

func TestRuntimeStateSummariesMatchSingleJobSummariesAndArchiveScope(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	insertScan := func(id string, addresses ...string) {
		t.Helper()
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO scans(id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json) VALUES(?,?, 'now','now','success','','Nmap','hash','{}')`, id, id); err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			if _, err := s.DB.ExecContext(ctx, `INSERT INTO scan_hosts(scan_id,address,host_json) VALUES(?,?,'{}')`, id, address); err != nil {
				t.Fatal(err)
			}
		}
	}
	insertJob := func(id string, archived bool) {
		t.Helper()
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES(?,?, '{}',1,?,1,'now','now')`, id, id, boolInt(archived)); err != nil {
			t.Fatal(err)
		}
	}
	insertRuntime := func(id, state string) {
		t.Helper()
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, id, []byte(state), "now"); err != nil {
			t.Fatal(err)
		}
	}

	insertJob("legacy-hosts", false)
	insertRuntime("legacy-hosts", `{"baseline":{"hosts":[{"address":"198.51.100.1"},{"address":"198.51.100.2"}]},"candidate_count":2,"candidate_attempts":3,"incomplete_candidate_attempts":1,"incidents":{"one":{}},"pending":{"two":{}}}`)
	insertJob("legacy-units", false)
	insertRuntime("legacy-units", `{"baseline":{"units":[{"addresses":["198.51.100.3","198.51.100.4"]},{"addresses":["198.51.100.4"]}]},"baseline_scan_id":"","baseline_config_hash":"legacy","candidate_count":1}`)
	insertJob("projected", false)
	insertRuntime("projected", `{"baseline":{"hosts":[{"address":"198.51.100.5"}]},"baseline_scan_id":"","baseline_config_hash":"current"}`)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "projected", 1, "", "current", 0, 1, 4, 5, 1, 2, "now"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceBaselineHostProjection(ctx, "projected", model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.5"}, {Address: "198.51.100.6"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO runtime_incidents(job_id,key,incident_json) VALUES(?,?,?)`, "projected", "incident", `{}`); err != nil {
		t.Fatal(err)
	}
	insertScan("metadata-source-scan", "198.51.100.40")
	insertJob("metadata-source", false)
	insertRuntime("metadata-source", `{"baseline":{"hosts":[]},"baseline_scan_id":"metadata-source-scan"}`)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "metadata-source", 1, "metadata-source-scan", "hash", 0, 1, 0, 0, 0, 0, "now"); err != nil {
		t.Fatal(err)
	}
	insertJob("legacy-modified", false)
	insertRuntime("legacy-modified", `{"baseline":{"hosts":[{"address":"198.51.100.41"}]},"baseline_modified":true}`)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO baseline_hosts(job_id,address,host_json) VALUES(?,?,?)`, "legacy-modified", "198.51.100.41", `{}`); err != nil {
		t.Fatal(err)
	}
	insertJob("empty", false)
	insertJob("archived", true)
	insertRuntime("archived", `{"baseline":{"hosts":[{"address":"198.51.100.7"}]}}`)
	insertJob("projected-invalid-runtime", false)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, "projected-invalid-runtime", `{invalid`, "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "projected-invalid-runtime", 1, "", "", 0, 0, 0, 0, 0, 0, "2"); err != nil {
		t.Fatal(err)
	}
	insertScan("json-source", "198.51.100.30")
	insertScan("stale-metadata-source", "198.51.100.31", "198.51.100.32")
	insertJob("metadata-empty-source", false)
	insertRuntime("metadata-empty-source", `{"baseline":{"hosts":[]},"baseline_scan_id":"json-source"}`)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "metadata-empty-source", 1, "", "", 0, 0, 0, 0, 0, 0, "now"); err != nil {
		t.Fatal(err)
	}
	insertJob("stale-metadata-source", false)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, "stale-metadata-source", `{"baseline":{"units":[{"addresses":["198.51.100.30"]}]},"baseline_scan_id":"json-source"}`, "2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "stale-metadata-source", 1, "stale-metadata-source", "", 0, 0, 0, 0, 0, 0, "1"); err != nil {
		t.Fatal(err)
	}
	const seededJobCount = 128
	seededIDs := make([]string, 0, seededJobCount)
	for index := 0; index < seededJobCount; index++ {
		id := fmt.Sprintf("seeded-%03d", index)
		insertJob(id, false)
		seededIDs = append(seededIDs, id)
	}

	for _, includeArchived := range []bool{false, true} {
		got, err := s.RuntimeStateSummaries(ctx, includeArchived)
		if err != nil {
			t.Fatalf("RuntimeStateSummaries(includeArchived=%t): %v", includeArchived, err)
		}
		wantIDs := []string{"legacy-hosts", "legacy-units", "projected", "metadata-source", "legacy-modified", "empty", "projected-invalid-runtime", "metadata-empty-source", "stale-metadata-source"}
		wantIDs = append(wantIDs, seededIDs...)
		if includeArchived {
			wantIDs = append(wantIDs, "archived")
		}
		if len(got) != len(wantIDs) {
			t.Fatalf("summary count with includeArchived=%t = %d, want %d (%#v)", includeArchived, len(got), len(wantIDs), got)
		}
		for _, id := range wantIDs {
			want, err := s.RuntimeStateSummary(ctx, id)
			if err != nil {
				t.Fatalf("RuntimeStateSummary(%q): %v", id, err)
			}
			if !reflect.DeepEqual(got[id], want) {
				t.Errorf("batched summary for %q = %#v, want %#v", id, got[id], want)
			}
		}
		if !includeArchived {
			if _, ok := got["archived"]; ok {
				t.Fatal("archived job appeared in default summary list")
			}
		}
	}
}

func TestRuntimeStateSummariesReportsInvalidLegacyRuntimeJSON(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES('invalid-json','invalid-json','{}',1,0,1,'now','now')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES('invalid-json','{invalid','2')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,updated_at) VALUES('invalid-json',1,'1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RuntimeStateSummaries(ctx, false); err == nil {
		t.Fatal("expected invalid stale runtime JSON to fail the batch summary")
	}
}

func TestRuntimeStateSummariesReportsQueryAndScanErrors(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		s := openTestStore(t)
		ctx := context.Background()
		if _, err := s.DB.ExecContext(ctx, `DROP TABLE job_runtime_meta`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RuntimeStateSummaries(ctx, false); err == nil {
			t.Fatal("expected missing runtime metadata table to fail")
		}
	})
	t.Run("scan", func(t *testing.T) {
		s := openTestStore(t)
		ctx := context.Background()
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES('bad-count','bad-count','{}',1,0,1,'now','now')`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,candidate_count,updated_at) VALUES('bad-count',1,'not-a-number','now')`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RuntimeStateSummaries(ctx, false); err == nil {
			t.Fatal("expected invalid runtime metadata integer to fail scanning")
		}
	})
}

func TestLegacyRuntimeHostCountFallsBackToZero(t *testing.T) {
	if got := legacyRuntimeHostCount(sql.NullInt64{}, sql.NullInt64{}); got != 0 {
		t.Fatalf("empty legacy host counts = %d, want 0", got)
	}
}
