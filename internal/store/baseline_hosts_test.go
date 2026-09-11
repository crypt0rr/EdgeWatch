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
		{Address: "198.51.100.2", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 443, State: "open"}}}}},
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
	summary, err := s.RuntimeStateSummary(ctx, "summary-job")
	if err != nil {
		t.Fatal(err)
	}
	if !summary.HasBaseline || summary.BaselineHostCount != 1 || summary.IncidentCount != 1 || summary.PendingCount != 1 || summary.CandidateCount != 2 || summary.CandidateAttempts != 3 {
		t.Fatalf("summary = %#v", summary)
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
