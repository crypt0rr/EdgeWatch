package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestMigration70ExtendsScansIdentityIndex(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	job, err := defaultTenant(s).CreateJob(ctx, testJob("migration-70"))
	if err != nil {
		t.Fatal(err)
	}
	finished := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	snapshot := model.Snapshot{Scopes: []model.Scope{{Target: "migration.example", Protocol: "tcp", Ports: "443"}}}
	insertIncidentEvidenceScan(t, ctx, s, job, "schema-69-scan", finished, "success", model.ScanComparisonCompared, snapshot)
	var before string
	if err := s.DB.QueryRowContext(ctx, `SELECT snapshot_json FROM scans WHERE id=?`, "schema-69-scan").Scan(&before); err != nil {
		t.Fatal(err)
	}
	path := s.Path
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	execFixtureStatements(t, path, []string{
		`DROP INDEX scans_identity`,
		`CREATE INDEX scans_identity ON scans(id,tenant_id,job_id,status,finished_at,job)`,
		`PRAGMA user_version=69`,
	})

	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade from schema 69: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != 70 {
		t.Fatalf("schema version = %d, want 70", version)
	}
	if got := indexKeys(t, upgraded.DB, scansIdentityIndex); got != schema70ScanIndexes[scansIdentityIndex] {
		t.Fatalf("%s keys = %q, want %q", scansIdentityIndex, got, schema70ScanIndexes[scansIdentityIndex])
	}
	var after, comparison string
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT snapshot_json,comparison FROM scans WHERE id=?`, "schema-69-scan").Scan(&after, &comparison); err != nil {
		t.Fatal(err)
	}
	if after != before || comparison != model.ScanComparisonCompared {
		t.Fatalf("migration changed scan evidence: snapshot same=%t comparison=%q", after == before, comparison)
	}
	plan := strings.Join(explainPlan(t, upgraded.DB, `SELECT id,tenant_id,job_id,status,finished_at,comparison FROM scans INDEXED BY scans_identity WHERE id=? AND tenant_id=? AND job_id=?`, "schema-69-scan", job.TenantID, job.ID), " | ")
	if !strings.Contains(plan, "USING COVERING INDEX scans_identity") {
		t.Fatalf("scan metadata lookup is not covered by scans_identity: %s", plan)
	}
	if err := runMigration(ctx, upgraded.DB, 70, migration70Statements(), false); err == nil || err.Error() != fmt.Sprintf("schema migration 70: the database is at schema %d, not 69; another process is migrating it", schemaVersion) {
		t.Fatalf("repeated schema 70 migration = %v, want moved-marker refusal", err)
	}
}
