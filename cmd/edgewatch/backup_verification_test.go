package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// sealedBackup writes a backup of a deployment that holds one web-managed
// destination and one TOTP seed, sealed with the keys beside its database,
// and returns the backup and that directory.
func sealedBackup(t *testing.T) (backup, keyDir string) {
	t.Helper()
	ctx := context.Background()
	database := storetest.FreshPath(t)
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	notifier, err := notify.New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := notifier.Tenant(s.Tenant(store.DefaultTenantScope())).CreateManagedWithAudit(ctx, "Ops", "generic://127.0.0.1:9/ops?disabletls=yes", true, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, store.Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "hash", TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	backup, err = s.Backup(ctx, filepath.Join(t.TempDir(), "backup.db"))
	if err != nil {
		t.Fatal(err)
	}
	return backup, filepath.Dir(database)
}

// writeRandomKey writes a new random key to path.
func writeRandomKey(t *testing.T, path string) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyKey(t *testing.T, from, to string) {
	t.Helper()
	raw, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// keyDeployment is a stopped deployment whose database and keys are another
// deployment's than the backup's.
func keyDeployment(t *testing.T) (database, configPath string) {
	t.Helper()
	database = storetest.FreshPath(t)
	dir := filepath.Dir(database)
	writeRandomKey(t, filepath.Join(dir, "notification.key"))
	writeRandomKey(t, filepath.Join(dir, "auth.key"))
	configPath = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return database, configPath
}

type keyCheckReport struct {
	Safe     bool                   `json:"safe"`
	Valid    bool                   `json:"valid"`
	Refusal  string                 `json:"refusal"`
	Error    string                 `json:"error"`
	KeyCheck *store.RestoreKeyCheck `json:"key_check"`
}

func decodeKeyCheckReport(t *testing.T, stdout string) keyCheckReport {
	t.Helper()
	var report keyCheckReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("output %q is not one JSON document: %v", stdout, err)
	}
	if strings.Contains(stdout, "generic://") || strings.Contains(stdout, "JBSWY3DPEHPK3PXP") {
		t.Fatalf("the output leaked a secret: %s", stdout)
	}
	return report
}

// A backup sealed with other keys than the configured ones would lock its
// destinations and TOTP seeds. The dry run reports how many, by count only,
// and exits non-zero; the restore refuses it and leaves the database as it
// was, unless --allow-key-mismatch accepts the locked secrets. With the
// backup's keys in place, configured or beside the database, both succeed.
func TestRunRestoreChecksTheBackupAgainstTheConfiguredKeys(t *testing.T) {
	backup, keyDir := sealedBackup(t)
	database, configPath := keyDeployment(t)
	dir := filepath.Dir(database)
	locked := store.RestoreKeyCheck{Destinations: 1, DestinationsLocked: 1, TOTPSecrets: 1, TOTPUnreadable: 1}
	before := snapshotCLIFile(t, database)

	stdout, _, err := captureCLIOutput(t, func() error {
		return run([]string{"restore", "--config", configPath, "--from", backup, "--dry-run", "--output", "json"})
	})
	if !errors.Is(err, store.ErrRestoreKeyMismatch) || !strings.Contains(err.Error(), "--allow-key-mismatch") {
		t.Fatalf("dry run with other keys = %v", err)
	}
	report := decodeKeyCheckReport(t, stdout)
	if report.Safe || report.KeyCheck == nil || *report.KeyCheck != locked || !strings.Contains(report.Refusal, "cannot open 1 of 1 web-managed destinations") {
		t.Fatalf("dry run report = %+v", report)
	}
	if err := run([]string{"restore", "--config", configPath, "--from", backup, "--output", "json"}); !errors.Is(err, store.ErrRestoreKeyMismatch) {
		t.Fatalf("restore with other keys = %v", err)
	}
	assertCLIFileUnchanged(t, database, before)

	// The backup's keys, configured explicitly, open everything.
	configured := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(configured, 0o700); err != nil {
		t.Fatal(err)
	}
	copyKey(t, filepath.Join(keyDir, "notification.key"), filepath.Join(configured, "notification.key"))
	copyKey(t, filepath.Join(keyDir, "auth.key"), filepath.Join(configured, "auth.key"))
	explicit := filepath.Join(dir, "explicit.yaml")
	if err := os.WriteFile(explicit, []byte("database: "+database+"\nnotifications:\n  encryption_key_file: "+filepath.Join(configured, "notification.key")+"\nweb:\n  auth_key_file: "+filepath.Join(configured, "auth.key")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err = captureCLIOutput(t, func() error {
		return run([]string{"restore", "--config", explicit, "--from", backup, "--dry-run", "--output", "json"})
	})
	if err != nil {
		t.Fatalf("dry run with the backup's configured keys: %v", err)
	}
	if report := decodeKeyCheckReport(t, stdout); !report.Safe || report.KeyCheck == nil || *report.KeyCheck != (store.RestoreKeyCheck{Destinations: 1, TOTPSecrets: 1}) {
		t.Fatalf("dry run report with the backup's keys = %+v", report)
	}

	// The override restores the backup with its secrets locked and reports
	// the counts.
	stdout, _, err = captureCLIOutput(t, func() error {
		return run([]string{"restore", "--config", configPath, "--from", backup, "--allow-key-mismatch", "--output", "json"})
	})
	if err != nil {
		t.Fatalf("restore with --allow-key-mismatch: %v", err)
	}
	if report := decodeKeyCheckReport(t, stdout); report.KeyCheck == nil || *report.KeyCheck != locked {
		t.Fatalf("restore report = %+v", report)
	}

	// With the backup's keys beside the database, the restore needs no
	// override.
	copyKey(t, filepath.Join(keyDir, "notification.key"), filepath.Join(dir, "notification.key"))
	copyKey(t, filepath.Join(keyDir, "auth.key"), filepath.Join(dir, "auth.key"))
	stdout, _, err = captureCLIOutput(t, func() error {
		return run([]string{"restore", "--config", configPath, "--from", backup, "--output", "json"})
	})
	if err != nil {
		t.Fatalf("restore with the backup's keys: %v", err)
	}
	if report := decodeKeyCheckReport(t, stdout); report.KeyCheck == nil || report.KeyCheck.Mismatch() {
		t.Fatalf("restore report with the backup's keys = %+v", report)
	}
}

// verify --from checks a backup file while the daemon runs: it never opens
// the configured database or its lease, and leaves the backup byte for byte
// as it was. It reports the checks as one JSON document and exits non-zero
// when one fails: a truncated file, a newer schema, or keys that cannot open
// the backup's secrets.
func TestRunVerifyFromChecksABackupFileWhileTheDaemonRuns(t *testing.T) {
	backup, keyDir := sealedBackup(t)
	database, configPath := keyDeployment(t)
	dir := filepath.Dir(database)
	live, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.System().AcquireDaemonLease(context.Background(), "verify-from-test"); err != nil {
		live.Close()
		t.Fatal(err)
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	beforeDatabase := snapshotCLIFile(t, database)
	beforeBackup := snapshotCLIFile(t, backup)
	verify := func(t *testing.T, args ...string) (keyCheckReport, string, error) {
		t.Helper()
		stdout, _, err := captureCLIOutput(t, func() error {
			return run(append([]string{"verify", "--config", configPath, "--output", "json"}, args...))
		})
		return decodeKeyCheckReport(t, stdout), stdout, err
	}

	// Another deployment's keys cannot open the backup's secrets.
	report, _, err := verify(t, "--from", backup)
	if !errors.Is(err, store.ErrRestoreKeyMismatch) || report.Valid || report.KeyCheck == nil || report.KeyCheck.DestinationsLocked != 1 || report.KeyCheck.TOTPUnreadable != 1 {
		t.Fatalf("verify with other keys = %+v, %v", report, err)
	}
	if report, _, err := verify(t, "--from", backup, "--allow-key-mismatch"); err != nil || !report.Valid || report.KeyCheck.DestinationsLocked != 1 {
		t.Fatalf("verify with the mismatch allowed = %+v, %v", report, err)
	}
	copyKey(t, filepath.Join(keyDir, "notification.key"), filepath.Join(dir, "notification.key"))
	copyKey(t, filepath.Join(keyDir, "auth.key"), filepath.Join(dir, "auth.key"))
	report, stdout, err := verify(t, "--from", backup)
	if err != nil || !report.Valid || report.KeyCheck == nil || report.KeyCheck.Mismatch() {
		t.Fatalf("verify of a good backup while the daemon runs = %+v, %v", report, err)
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatal(err)
	}
	if document["schema_supported"] != true || document["edgewatch_schema"] != true || document["integrity_check"] != "ok" || document["source_path"] != backup {
		t.Fatalf("verify report = %s", stdout)
	}
	assertCLIFileUnchanged(t, database, beforeDatabase)
	assertCLIFileUnchanged(t, backup, beforeBackup)
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(backup + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("verify created %s next to the backup (%v)", suffix, err)
		}
	}
	lease, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	status, err := lease.System().DaemonLeaseStatus(context.Background())
	lease.Close()
	if err != nil || !status.Active || status.Owner != "verify-from-test" {
		t.Fatalf("daemon lease after verify = %+v, %v", status, err)
	}

	raw, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(t.TempDir(), "truncated.db")
	if err := os.WriteFile(truncated, raw[:len(raw)/3], 0o600); err != nil {
		t.Fatal(err)
	}
	if report, _, err := verify(t, "--from", truncated); err == nil || report.Valid || report.Error == "" {
		t.Fatalf("verify of a truncated backup = %+v, %v", report, err)
	}
	newer := filepath.Join(t.TempDir(), "newer.db")
	if err := os.WriteFile(newer, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", newer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 999`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, stdout, err = verify(t, "--from", newer)
	if err == nil || !strings.Contains(err.Error(), "unsupported schema version: 999") {
		t.Fatalf("verify of a newer backup = %v", err)
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil || document["schema_supported"] != false || document["schema_version"] != float64(999) || document["valid"] != false {
		t.Fatalf("verify report of a newer backup = %s, %v", stdout, err)
	}
	if _, _, err := verify(t, "--from", database); err == nil || !strings.Contains(err.Error(), "run verify without --from") {
		t.Fatalf("verify --from the configured database = %v", err)
	}
	if err := run([]string{"verify", "--config", configPath, "--allow-key-mismatch"}); err == nil || !strings.Contains(err.Error(), "only with --from") {
		t.Fatalf("verify --allow-key-mismatch without --from = %v", err)
	}
}

// The backup command prints the checks its new file passed, quick_check by
// default and integrity_check with --full-check, and the options apply only
// to the commands that use them.
func TestRunBackupReportsItsChecksAndTheNewOptionsApplyWhereTheyBelong(t *testing.T) {
	database := storetest.FreshPath(t)
	dir := filepath.Dir(database)
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args  []string
		check string
	}{
		{check: "quick_check"},
		{args: []string{"--full-check"}, check: "integrity_check"},
	} {
		output := filepath.Join(dir, tc.check+".db")
		stdout, _, err := captureCLIOutput(t, func() error {
			return run(append([]string{"backup", "--config", configPath, "--out", output, "--output", "json"}, tc.args...))
		})
		if err != nil {
			t.Fatalf("backup %v: %v", tc.args, err)
		}
		var result store.BackupResult
		if err := json.Unmarshal([]byte(stdout), &result); err != nil {
			t.Fatal(err)
		}
		if result.Path != output || result.Bytes <= 0 || result.SchemaVersion < 1 || result.Check != tc.check || result.IntegrityCheck != "ok" || result.ForeignKeyViolations != 0 {
			t.Fatalf("backup %v result = %+v", tc.args, result)
		}
	}
	for _, args := range [][]string{
		{"restore", "--from", database, "--full-check"},
		{"verify", "--full-check"},
		{"backup", "--out", filepath.Join(dir, "x.db"), "--allow-key-mismatch"},
		{"health", "--from", database},
	} {
		if err := run(append(args, "--config", configPath)); err == nil || !strings.Contains(err.Error(), "does not apply to "+args[0]) {
			t.Errorf("%v error = %v, want a refused option", args, err)
		}
	}
	for cmd, want := range map[string][]string{
		"verify":  {"--from", "--allow-key-mismatch"},
		"backup":  {"--full-check"},
		"restore": {"--allow-key-mismatch"},
	} {
		stdout, _, err := captureCLIOutput(t, func() error { return run([]string{cmd, "--help"}) })
		if err != nil {
			t.Fatal(err)
		}
		for _, option := range want {
			if !strings.Contains(stdout, "  "+option+"\t") {
				t.Errorf("%s --help does not list %s: %s", cmd, option, stdout)
			}
		}
	}
}

// health reports the outcome of the scheduled backups that the daemon
// recorded, and a failed backup as a warning that keeps the daemon healthy.
// config validate prints the backup settings.
func TestRunHealthReportsTheScheduledBackups(t *testing.T) {
	database := storetest.FreshPath(t)
	dir := filepath.Dir(database)
	backups := filepath.Join(dir, "backups")
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\nbackup:\n  directory: "+backups+"\n  keep: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	live, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.System().AcquireDaemonLease(context.Background(), "health-backup-test"); err != nil {
		live.Close()
		t.Fatal(err)
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	type healthDocument struct {
		Status   string   `json:"status"`
		Warnings []string `json:"warnings"`
		Backups  *struct {
			Directory             string `json:"directory"`
			Schedule              string `json:"schedule"`
			Keep                  int    `json:"keep"`
			LastBackup            string `json:"last_backup"`
			LastSuccessAgeSeconds *int64 `json:"last_success_age_seconds"`
			LastError             string `json:"last_error"`
			ConsecutiveFailures   int    `json:"consecutive_failures"`
		} `json:"backups"`
	}
	health := func(t *testing.T) healthDocument {
		t.Helper()
		stdout, _, err := captureCLIOutput(t, func() error {
			return run([]string{"health", "--config", configPath, "--output", "json"})
		})
		if err != nil {
			t.Fatalf("health: %v", err)
		}
		var document healthDocument
		if err := json.Unmarshal([]byte(stdout), &document); err != nil {
			t.Fatalf("health output %q: %v", stdout, err)
		}
		return document
	}
	document := health(t)
	if document.Status != "ready" || document.Backups == nil || document.Backups.Directory != backups || document.Backups.Schedule != "0 3 * * *" || document.Backups.Keep != 3 || document.Backups.LastSuccessAgeSeconds != nil || len(document.Warnings) != 0 {
		t.Fatalf("health before the first backup = %+v", document)
	}

	status := map[string]any{
		"directory": backups, "schedule": "0 3 * * *", "keep": 3,
		"last_success_at": time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano), "last_backup": "edgewatch-scheduled-20261001T030000Z.db",
		"last_failure_at": time.Now().UTC().Format(time.RFC3339Nano), "last_error": "output directory: disk full", "consecutive_failures": 1,
	}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backup-status.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	document = health(t)
	if document.Status != "ready" || document.Backups.LastBackup != "edgewatch-scheduled-20261001T030000Z.db" || document.Backups.LastSuccessAgeSeconds == nil || *document.Backups.LastSuccessAgeSeconds < 3500 || document.Backups.ConsecutiveFailures != 1 {
		t.Fatalf("health after a failed backup = %+v", document)
	}
	if len(document.Warnings) != 1 || !strings.Contains(document.Warnings[0], "the scheduled backup failed 1 time(s)") || !strings.Contains(document.Warnings[0], "disk full") {
		t.Fatalf("health warnings = %v", document.Warnings)
	}
	if err := os.WriteFile(filepath.Join(dir, "backup-status.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if document := health(t); len(document.Warnings) != 1 || !strings.Contains(document.Warnings[0], "read scheduled backup status") || document.Backups == nil {
		t.Fatalf("health with an unreadable status = %+v", document)
	}

	stdout, _, err := captureCLIOutput(t, func() error {
		return run([]string{"config", "validate", "--config", configPath, "--output", "json"})
	})
	if err != nil {
		t.Fatalf("config validate: %v", err)
	}
	var normalized struct {
		Backup map[string]any `json:"backup"`
	}
	if err := json.Unmarshal([]byte(stdout), &normalized); err != nil || normalized.Backup["directory"] != backups || normalized.Backup["keep"] != float64(3) || normalized.Backup["schedule"] != "0 3 * * *" {
		t.Fatalf("config validate backup = %s, %v", stdout, err)
	}
}
