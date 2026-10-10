package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadBackupConfig(t *testing.T, section string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("database: "+filepath.Join(dir, "edgewatch.db")+"\n"+section), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

// Scheduled backups are off by default. A directory turns them on with a
// daily schedule and a week of backups unless the schedule and the number
// kept are set.
func TestBackupDefaultsTurnScheduledBackupsOnOnlyWithADirectory(t *testing.T) {
	t.Parallel()
	cfg, err := loadBackupConfig(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Backup.Enabled() || cfg.Backup != (Backup{}) {
		t.Fatalf("default backup settings = %+v", cfg.Backup)
	}
	cfg, err = loadBackupConfig(t, "backup:\n  directory: \" /var/lib/edgewatch/backups/ \"\n")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Backup.Enabled() || cfg.Backup != (Backup{Directory: "/var/lib/edgewatch/backups", Schedule: DefaultBackupSchedule, Keep: DefaultBackupKeep}) {
		t.Fatalf("backup settings with a directory = %+v", cfg.Backup)
	}
	cfg, err = loadBackupConfig(t, "backup:\n  directory: /backups\n  schedule: \"30 */6 * * *\"\n  keep: 28\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Backup != (Backup{Directory: "/backups", Schedule: "30 */6 * * *", Keep: 28}) {
		t.Fatalf("explicit backup settings = %+v", cfg.Backup)
	}
	if _, err := loadBackupConfig(t, "backup:\n  directory: /backups\n  retention: 7\n"); err == nil {
		t.Fatal("an unknown backup setting was accepted")
	}
}

func TestBackupValidationRefusesUnusableSettings(t *testing.T) {
	t.Parallel()
	for section, want := range map[string]string{
		"backup:\n  schedule: \"0 3 * * *\"\n":                          "require backup.directory",
		"backup:\n  keep: 3\n":                                          "require backup.directory",
		"backup:\n  directory: backups\n":                               "must be an absolute path",
		"backup:\n  directory: /\n":                                     "must not be the root directory",
		"backup:\n  directory: /backups\n  schedule: x\n":               "five-field cron expression",
		"backup:\n  directory: /backups\n  schedule: \"0 0 3 * * *\"\n": "five-field cron expression",
		"backup:\n  directory: /backups\n  keep: -1\n":                  "between 1 and 1000",
		"backup:\n  directory: /backups\n  keep: 1001\n":                "between 1 and 1000",
	} {
		if _, err := loadBackupConfig(t, section); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error = %v, want %q", section, err, want)
		}
	}
	// A configuration built in code is validated the same way.
	if err := (Backup{Schedule: " "}).validate(); err != nil {
		t.Fatalf("blank schedule without a directory: %v", err)
	}
	if _, err := ParseBackupSchedule(DefaultBackupSchedule); err != nil {
		t.Fatalf("default schedule: %v", err)
	}
}
