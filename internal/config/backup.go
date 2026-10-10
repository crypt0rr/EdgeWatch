package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// Defaults and bounds of the scheduled backups.
const (
	// DefaultBackupSchedule takes one backup a day at 03:00.
	DefaultBackupSchedule = "0 3 * * *"
	// DefaultBackupKeep keeps a week of daily backups.
	DefaultBackupKeep = 7
	// MaxBackupKeep bounds the backups that the daemon keeps.
	MaxBackupKeep = 1000
)

// Backup configures the backups that the daemon takes on a schedule. They are
// off unless Directory is set. Each backup is checked as the backup command
// checks its output before it is published, and the daemon keeps the newest
// Keep of the backups that it wrote there, removing older ones. Files that
// the daemon did not write are never removed.
type Backup struct {
	// Directory receives the backups. It must be an absolute path to an
	// existing directory; the daemon does not create it.
	Directory string `yaml:"directory"`
	// Schedule is a five-field cron expression, in the deployment timezone
	// when one is set and UTC otherwise, that fires. A TZ= or CRON_TZ=
	// prefix is refused, as in a job's schedule. It defaults to
	// DefaultBackupSchedule.
	Schedule string `yaml:"schedule"`
	// Keep is the number of scheduled backups kept, from 1 to MaxBackupKeep.
	// It defaults to DefaultBackupKeep.
	Keep int `yaml:"keep"`
}

// Enabled reports whether the daemon takes scheduled backups.
func (b Backup) Enabled() bool { return b.Directory != "" }

// applyBackupDefaults fills in the schedule and the number of backups kept
// when a directory is set. Without a directory, the other settings stay as
// written, so validation can refuse them.
func applyBackupDefaults(b *Backup) {
	b.Directory = strings.TrimSpace(b.Directory)
	b.Schedule = strings.TrimSpace(b.Schedule)
	if b.Directory == "" {
		return
	}
	b.Directory = filepath.Clean(b.Directory)
	if b.Schedule == "" {
		b.Schedule = DefaultBackupSchedule
	}
	if b.Keep == 0 {
		b.Keep = DefaultBackupKeep
	}
}

// ParseBackupSchedule parses a backup.schedule cron expression.
func ParseBackupSchedule(spec string) (cron.Schedule, error) {
	return cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse(spec)
}

// validate checks the backup settings. The schedule is checked in location,
// the deployment timezone, or UTC when it is nil.
func (b Backup) validate(location *time.Location) error {
	if !b.Enabled() {
		if strings.TrimSpace(b.Schedule) != "" || b.Keep != 0 {
			return errors.New("backup.schedule and backup.keep require backup.directory")
		}
		return nil
	}
	if !filepath.IsAbs(b.Directory) {
		return fmt.Errorf("backup.directory must be an absolute path: %q", b.Directory)
	}
	if b.Directory == string(filepath.Separator) {
		return errors.New("backup.directory must not be the root directory")
	}
	// A prefix would override the deployment timezone that the schedule is
	// documented to follow, so it is refused as in a job's schedule.
	schedule := strings.TrimSpace(b.Schedule)
	if strings.HasPrefix(schedule, "TZ=") || strings.HasPrefix(schedule, "CRON_TZ=") {
		return errors.New("backup.schedule must contain five cron fields; set the deployment timezone in timezone")
	}
	parsed, err := ParseBackupSchedule(schedule)
	if err != nil {
		return fmt.Errorf("backup.schedule must be a five-field cron expression: %w", err)
	}
	if location == nil {
		location = time.UTC
	}
	// A schedule such as February 30 parses but never fires: the daemon
	// would have no next backup to wait for.
	if parsed.Next(time.Now().UTC().In(location)).IsZero() {
		return errors.New("backup.schedule never fires")
	}
	if b.Keep < 1 || b.Keep > MaxBackupKeep {
		return fmt.Errorf("backup.keep must be between 1 and %d", MaxBackupKeep)
	}
	return nil
}
