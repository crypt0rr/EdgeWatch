package store

import (
	"context"
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
