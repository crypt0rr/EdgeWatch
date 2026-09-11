package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestUsageAndPrintValue(t *testing.T) {
	if err := usage(); err == nil || !strings.Contains(err.Error(), "invalid or missing command") {
		t.Fatalf("usage error = %v", err)
	}

	if err := printValue("text", "hello"); err != nil {
		t.Fatalf("text value: %v", err)
	}
	if err := printValue("text", map[string]string{"status": "ok"}); err != nil {
		t.Fatalf("default value: %v", err)
	}
	if err := printValue("json", map[string]string{"status": "ok"}); err != nil {
		t.Fatalf("json value: %v", err)
	}
	// Both output modes marshal structured values, so an unsupported value must
	// be returned to the caller instead of being silently discarded.
	if err := printValue("json", make(chan int)); err == nil {
		t.Fatal("unsupported JSON value did not fail")
	}
	if err := printValue("text", make(chan int)); err == nil {
		t.Fatal("unsupported default value did not fail")
	}
}

func TestNormalizedConfigIncludesDeploymentAndLegacyJobMetadata(t *testing.T) {
	cfg := &config.Config{
		Version:       1,
		Database:      "/var/lib/edgewatch/edgewatch.db",
		Web:           config.Web{Listen: "127.0.0.1:8080"},
		Scheduler:     config.Scheduler{MaxConcurrent: 2, MaxProbeCount: 500},
		Retention:     config.Duration(48 * time.Hour),
		Jobs:          []config.Job{{Name: "legacy", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.4"}}},
		Notifications: config.Notifications{URLs: []string{"generic://example.invalid"}},
	}
	value := normalizedConfig(cfg)
	if value["valid"] != true || value["version"] != 1 || value["database"] != cfg.Database || value["web_listen"] != cfg.Web.Listen {
		t.Fatalf("deployment metadata = %#v", value)
	}
	if value["max_probe_count"] != int64(500) || value["rdap_enabled"] != true || value["legacy_jobs_inactive"] != true || value["notification_destinations"] != 1 {
		t.Fatalf("normalized metadata = %#v", value)
	}
	jobs, ok := value["jobs"].([]map[string]any)
	if !ok || len(jobs) != 1 || jobs[0]["name"] != "legacy" || jobs[0]["security_hash"] == "" {
		t.Fatalf("normalized jobs = %#v", value["jobs"])
	}
}

func TestRunVersionHelpAndConfigValidation(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("version: %v", err)
	}
	if err := run([]string{"help"}); err == nil {
		t.Fatal("help unexpectedly succeeded")
	}
	if err := run(nil); err == nil {
		t.Fatal("empty command unexpectedly succeeded")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	contents := "database: " + filepath.Join(dir, "edgewatch.db") + "\n"
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"config", "validate", "--config", configPath}); err != nil {
		t.Fatalf("config validate: %v", err)
	}
	if err := run([]string{"config", "unknown", "--config", configPath}); err == nil {
		t.Fatal("unknown config action unexpectedly succeeded")
	}
}

func TestHealthDoesNotConstructScannerApplication(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireLease(context.Background(), "health-test"); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "scanner-invoked")
	script := filepath.Join(dir, "scanner")
	contents := "#!/bin/sh\necho invoked > " + marker + "\n"
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"health", "--config", configPath, "--nmap", script}); err != nil {
		t.Fatalf("health: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("health invoked scanner constructor: stat=%v", err)
	}
}

func TestRunStatusReportsUnknownManagedJob(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	contents := "database: " + database + "\n"
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	err = run([]string{"status", "--config", configPath, "--job", "missing"})
	if err == nil || !strings.Contains(err.Error(), `unknown job "missing"`) {
		t.Fatalf("status error = %v", err)
	}
}

func TestStatusFallsBackToUTCForInvalidTimezone(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Jobs: []config.Job{{Name: "invalid-zone", Schedule: "0 * * * *", Timezone: "Not/AZone"}}}
	if err := status(context.Background(), s, cfg, "", "json"); err != nil {
		t.Fatalf("status returned an error for an invalid timezone: %v", err)
	}
}

func TestRunStatusHistoryAndBaselineForManagedJob(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	job := config.NormalizeJob(config.Job{
		Name: "managed", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"},
		TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced",
	})
	record, err := s.CreateJob(ctx, job)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{ID: "managed-scan", JobID: record.ID, JobRevision: record.Revision, Job: job.Name, StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: job.SecurityHash(), Snapshot: model.Snapshot{Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}}}
	if err := s.SaveScan(ctx, scan); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	contents := "database: " + database + "\njobs:\n  - name: legacy\n    schedule: \"0 * * * *\"\n    timezone: UTC\n    targets: [127.0.0.2]\n    tcp:\n      ports: \"1\"\n      mode: connect\n"
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"status", "--config", configPath, "--output", "json"}); err != nil {
		t.Fatalf("managed status: %v", err)
	}
	if err := run([]string{"status", "--config", configPath, "--job", "managed"}); err != nil {
		t.Fatalf("filtered managed status: %v", err)
	}
	if err := run([]string{"history", "--config", configPath, "--job", "managed", "--limit", "2"}); err != nil {
		t.Fatalf("managed history: %v", err)
	}
	if err := run([]string{"baseline", "reset", "--config", configPath, "--job", "managed"}); err != nil {
		t.Fatalf("baseline reset: %v", err)
	}
	if err := run([]string{"baseline", "approve", "--config", configPath, "--job", "managed", "--scan-id", scan.ID}); err != nil {
		t.Fatalf("baseline approval: %v", err)
	}
	s, err = store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var audits int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action IN ('baseline.reset','baseline.approved') AND actor_username='host-cli'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 2 {
		t.Fatalf("CLI baseline audit rows = %d, want two", audits)
	}
}

func TestRunBackupVerifyAndBaselineExport(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "--config", configPath, "--output", "json"}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	outputDir := filepath.Join(dir, "backups")
	if err := os.Mkdir(outputDir, 0o750); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(outputDir, "edgewatch.db")
	if err := run([]string{"backup", "--config", configPath, "--out", backupPath, "--output", "json"}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if info, err := os.Stat(backupPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup file = %v, %v", info, err)
	}
	exportPath := filepath.Join(outputDir, "baseline.json")
	if err := run([]string{"baseline", "export", "--config", configPath, "--out", exportPath, "--output", "json"}); err != nil {
		t.Fatalf("baseline export: %v", err)
	}
	contents, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	var exported map[string]any
	if err := json.Unmarshal(contents, &exported); err != nil {
		t.Fatalf("decode baseline export: %v", err)
	}
	if exported["format_version"] != float64(store.BaselineExportVersion) {
		t.Fatalf("baseline export = %#v", exported)
	}
}

func TestRunRestoreDryRunAndReplacement(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	source := filepath.Join(dir, "source.db")
	createCLIStoreFixture(t, source, "source")
	createCLIStoreFixture(t, database, "destination")
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"restore", "--config", configPath, "--from", source, "--dry-run", "--output", "json"}); err != nil {
		t.Fatalf("restore dry-run: %v", err)
	}
	if err := os.WriteFile(database+"-wal", []byte("stale WAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"restore", "--config", configPath, "--from", source, "--output", "json"}); !errors.Is(err, store.ErrRestoreSidecars) {
		t.Fatalf("restore with stale sidecar error = %v, want ErrRestoreSidecars", err)
	}
	if err := os.Remove(database + "-wal"); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"restore", "--config", configPath, "--from", source, "--output", "json"}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	s, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var value string
	if err := s.DB.QueryRowContext(context.Background(), `SELECT value FROM cli_restore_fixture`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "source" {
		t.Fatalf("restored CLI value = %q, want source", value)
	}
}

func createCLIStoreFixture(t *testing.T, path, value string) {
	t.Helper()
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TABLE cli_restore_fixture (value TEXT NOT NULL); INSERT INTO cli_restore_fixture(value) VALUES (?)`, value); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAdminActionRequiresExplicitSetupTokenConfirmation(t *testing.T) {
	err := adminActionForUser(context.Background(), "setup-token", nil, "", "admin", false)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("setup-token confirmation error = %v", err)
	}
	if err := adminActionForUser(context.Background(), "reissue-setup-token", nil, "", "admin", false); err == nil {
		t.Fatal("reissue setup token without force unexpectedly succeeded")
	}
}
