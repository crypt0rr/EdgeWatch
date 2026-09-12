package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/web"
	"github.com/robfig/cron/v3"
)

var version = "dev"

// exitProcess is a variable so lifecycle tests can exercise the second-signal
// path without terminating the test binary.
var exitProcess = os.Exit

// Final scan persistence is allowed up to five minutes for a large host
// inventory. Keep the component join deadline above that bound so a graceful
// container stop can finish the transaction before Docker sends SIGKILL.
const daemonShutdownTimeout = 6 * time.Minute

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "edgewatch:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	cmd := args[0]
	action := ""
	rest := args[1:]
	if cmd == "config" || cmd == "baseline" || cmd == "notify" || cmd == "admin" {
		if len(rest) == 0 {
			return usage()
		}
		action, rest = rest[0], rest[1:]
	}
	if cmd == "version" {
		fmt.Println("EdgeWatch", version)
		return nil
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	configPath := fs.String("config", "/etc/edgewatch/config.yaml", "configuration file")
	output := fs.String("output", "text", "text or json")
	outPath := fs.String("out", "", "output file for backup or baseline export")
	fromPath := fs.String("from", "", "source database file for restore")
	allowSidecarReplay := fs.Bool("allow-sidecar-replay", false, "allow existing SQLite sidecars during an intentional crash-recovery restore")
	allowActiveDaemon := fs.Bool("allow-active-daemon", false, "allow restore when the destination daemon heartbeat is still active (emergency recovery only)")
	dryRun := fs.Bool("dry-run", false, "inspect a restore without replacing the destination")
	jobName := fs.String("job", "", "job name")
	scanID := fs.String("scan-id", "", "scan ID")
	limit := fs.Int("limit", 50, "history limit")
	nmapPath := fs.String("nmap", "/usr/bin/nmap", "Nmap executable (fixed runtime binary; override only for local tests)")
	passwordFile := fs.String("password-file", "", "file containing a new administrator password")
	username := fs.String("username", "admin", "username for administrator recovery actions")
	force := fs.Bool("force", false, "confirm replacement of the current setup token")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if cmd == "help" {
		return usage()
	}
	loadConfig := config.Load
	if cmd == "admin" || cmd == "backup" || cmd == "verify" || cmd == "health" || cmd == "status" || cmd == "history" || cmd == "restore" || (cmd == "baseline" && action == "export") {
		// Host recovery must not depend on monitor-only configuration such as
		// Shoutrrr destinations, encryption keys, listener settings, or legacy
		// YAML job semantics.
		loadConfig = config.LoadForAdmin
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if cmd == "config" {
		if action != "validate" {
			return errors.New("expected: config validate")
		}
		return printValue(*output, normalizedConfig(cfg))
	}
	if cmd == "restore" {
		if *fromPath == "" {
			return errors.New("--from is required")
		}
		if *dryRun && *allowSidecarReplay {
			return errors.New("--allow-sidecar-replay cannot be combined with --dry-run")
		}
		preflight, err := store.PreflightRestore(context.Background(), *fromPath, cfg.Database)
		if err != nil {
			return err
		}
		if *dryRun {
			return printValue(*output, preflight)
		}
		result, err := store.Restore(context.Background(), *fromPath, cfg.Database, store.RestoreOptions{AllowSidecarReplay: *allowSidecarReplay, AllowActiveDaemon: *allowActiveDaemon})
		if err != nil {
			// Do not open the destination to audit a refused restore: doing so
			// could itself cause SQLite to inspect, checkpoint, or remove the
			// very sidecar that made the restore unsafe.
			return err
		}
		auditHostCommand(context.Background(), cfg.Database, nil, false, store.AuditEntry{Action: "database.restore", Detail: hostAuditDetail("source", *fromPath, err)})
		return printValue(*output, result)
	}
	// Keep the daemon as the sole migration/repair owner. Read-only health and
	// diagnostic commands must never create a database or mutate schema state,
	// while backup needs a writable connection for VACUUM INTO without running
	// migrations in parallel with the daemon.
	readOnlyCommand := cmd == "health" || cmd == "status" || cmd == "history" || cmd == "verify" || (cmd == "baseline" && action == "export")
	// Initialize the configured logger before opening the writable store so
	// migration and resumable-backfill progress uses the same structured output
	// as the rest of the daemon.
	logger := newLogger(cfg.LogLevel())
	var openStore func(string) (*store.Store, error)
	switch {
	case readOnlyCommand:
		openStore = store.OpenReadOnlyExisting
	case cmd == "backup":
		openStore = store.OpenExisting
	default:
		openStore = func(path string) (*store.Store, error) {
			return store.OpenWithLogger(path, logger)
		}
	}
	s, err := openStore(cfg.Database)
	if err != nil {
		return err
	}
	defer s.Close()
	if cmd == "admin" {
		return adminActionForUser(context.Background(), action, s, *passwordFile, *username, *force)
	}
	var application *app.App
	needApplication := cmd == "daemon" || cmd == "scan" || cmd == "notify" || (cmd == "baseline" && action != "export")
	if needApplication {
		application, err = app.New(cfg, s, *nmapPath, logger)
		if err != nil {
			return err
		}
		application.Version = version
	}
	ctx, stop := contextWithSignals(context.Background())
	defer stop()
	switch cmd {
	case "daemon":
		return runDaemon(ctx, application, cfg.Web.Listen, s, logger)
	case "scan":
		if *jobName == "" {
			return errors.New("--job is required")
		}
		record, err := s.GetJobByName(ctx, *jobName)
		if err != nil {
			return fmt.Errorf("unknown managed job %q; YAML jobs are inactive and must be recreated in the web console", *jobName)
		}
		scan, events, err := application.RunJobRecord(ctx, record)
		if printErr := printValue(*output, map[string]any{"scan": scan, "events": events}); printErr != nil {
			return printErr
		}
		return err
	case "status":
		return status(ctx, s, cfg, *jobName, *output)
	case "history":
		scans, err := s.ListScans(ctx, *jobName, *limit)
		if err != nil {
			return err
		}
		events, err := s.ListEvents(ctx, *jobName, *limit)
		if err != nil {
			return err
		}
		return printValue(*output, map[string]any{"scans": scans, "events": events})
	case "baseline":
		if action == "export" {
			err := exportBaseline(ctx, s, *jobName, *outPath, *output)
			auditHostCommand(ctx, cfg.Database, s, false, store.AuditEntry{Action: "baseline.export", Detail: hostAuditDetail("output", *outPath, err)})
			return err
		}
		return baseline(ctx, action, s, application, *jobName, *scanID, *output)
	case "notify":
		if action != "test" {
			return errors.New("expected: notify test")
		}
		err := application.Notifier.Test()
		auditHostCommand(ctx, cfg.Database, s, true, store.AuditEntry{Action: "notifications.test", Detail: hostAuditDetail("operation", "global", err)})
		return err
	case "backup":
		if *outPath == "" {
			return errors.New("--out is required")
		}
		err := backup(ctx, s, *outPath, *output)
		auditHostCommand(ctx, cfg.Database, s, true, store.AuditEntry{Action: "database.backup", Detail: hostAuditDetail("output", *outPath, err)})
		return err
	case "verify":
		err := verify(ctx, s, *output)
		auditHostCommand(ctx, cfg.Database, s, false, store.AuditEntry{Action: "database.verify", Detail: hostAuditDetail("operation", "database", err)})
		return err
	case "health":
		health, err := s.HealthStatus(ctx)
		if err != nil {
			return err
		}
		return printValue(*output, health)
	default:
		return usage()
	}
}

func usage() error {
	fmt.Fprintln(os.Stderr, `Usage: edgewatch <command> [options]
	Commands: daemon, config validate, scan, status, history, baseline approve|reset|export, backup, restore, verify, notify test, admin setup-token|reset-password|disable-totp, health, version
	Admin recovery actions accept --username (default admin) and require host access.`)
	return errors.New("invalid or missing command")
}

func newLogger(level string) *slog.Logger {
	var minimum slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		minimum = slog.LevelDebug
	case "warn":
		minimum = slog.LevelWarn
	case "error":
		minimum = slog.LevelError
	default:
		minimum = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: minimum}))
}

func adminAction(ctx context.Context, action string, s *store.Store, passwordFile string, confirmations ...bool) error {
	return adminActionForUser(ctx, action, s, passwordFile, "admin", confirmations...)
}

func adminActionForUser(ctx context.Context, action string, s *store.Store, passwordFile, username string, confirmations ...bool) error {
	force := len(confirmations) > 0 && confirmations[0]
	if action == "setup-token" || action == "reissue-setup-token" {
		if !force {
			return errors.New("reissuing the setup token replaces the current token; pass --force to confirm")
		}
		token, err := auth.NewManager(s).ReissueSetupToken(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "EdgeWatch setup token (valid for 15 minutes):", token)
		return nil
	}
	username = strings.TrimSpace(username)
	if username == "" {
		username = "admin"
	}
	user, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("user %q is not configured", username)
	}
	switch action {
	case "reset-password":
		if passwordFile == "" {
			return errors.New("--password-file is required")
		}
		raw, err := os.ReadFile(passwordFile)
		if err != nil {
			return err
		}
		password := string(raw)
		password = strings.TrimRight(password, "\r\n")
		hash, err := auth.PasswordHash(password)
		if err != nil {
			return err
		}
		user.PasswordHash, user.UpdatedAt = hash, time.Now().UTC()
		if user.ID == store.LegacyAdminUserID {
			admin, adminErr := s.GetAdmin(ctx)
			if adminErr != nil {
				return adminErr
			}
			admin.PasswordHash, admin.UpdatedAt = hash, user.UpdatedAt
			return s.SaveAdminSecurityWithAudit(ctx, admin, nil, false, true, store.AuditEntry{Action: "admin.password_reset", Detail: "password reset from host CLI", ActorUsername: "host-cli"})
		}
		return s.SaveUserSecurity(ctx, user, nil, false, true, store.AuditEntry{Action: "user.password_reset", Detail: "password reset from host CLI", ActorUsername: "host-cli"})
	case "disable-totp":
		user.TOTPEnabled, user.TOTPSecret, user.UpdatedAt = false, "", time.Now().UTC()
		if user.ID == store.LegacyAdminUserID {
			admin, adminErr := s.GetAdmin(ctx)
			if adminErr != nil {
				return adminErr
			}
			admin.TOTPEnabled, admin.TOTPSecret, admin.UpdatedAt = false, "", user.UpdatedAt
			return s.SaveAdminSecurityWithAudit(ctx, admin, []string{}, true, true, store.AuditEntry{Action: "admin.totp_disabled", Detail: "TOTP disabled from host CLI", ActorUsername: "host-cli"})
		}
		return s.SaveUserSecurity(ctx, user, []string{}, true, true, store.AuditEntry{Action: "user.totp_disabled", Detail: "TOTP disabled from host CLI", ActorUsername: "host-cli"})
	default:
		return errors.New("expected: admin reset-password|disable-totp")
	}
}

func runDaemon(ctx context.Context, application *app.App, listen string, s *store.Store, logger *slog.Logger) error {
	runCtx, _ := application.BeginRun(ctx)
	server := web.NewServer(application, s, logger)
	errCh := make(chan error, 2)
	go runComponent(errCh, logger, "daemon", func() error { return application.Daemon(runCtx) })
	go runComponent(errCh, logger, "web", func() error { return server.ListenAndServe(runCtx, listen) })
	first := <-errCh
	// One component returning (including an HTTP bind or daemon lease error)
	// must stop the other component before the database is closed by run(). A
	// bounded join prevents a scanner that ignores cancellation from keeping a
	// container alive indefinitely; a second OS signal can still force-exit.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), daemonShutdownTimeout)
	defer cancel()
	stopDone := make(chan struct{})
	go func() {
		application.StopRun()
		close(stopDone)
	}()
	select {
	case <-stopDone:
	case <-shutdownCtx.Done():
		logger.Error("daemon shutdown timed out", "timeout", daemonShutdownTimeout, "first_error", first)
		return shutdownCtx.Err()
	}
	var second error
	select {
	case second = <-errCh:
	case <-shutdownCtx.Done():
		logger.Error("component shutdown timed out", "timeout", daemonShutdownTimeout, "first_error", first)
		return shutdownCtx.Err()
	}
	if first != nil {
		return first
	}
	return second
}

func runComponent(errCh chan<- error, logger *slog.Logger, name string, fn func() error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if logger == nil {
				logger = slog.Default()
			}
			logger.Error("component goroutine panic recovered", "component", name, "panic", recovered, "stack", string(debug.Stack()))
			errCh <- fmt.Errorf("%s component panicked: %v", name, recovered)
		}
	}()
	errCh <- fn()
}

// contextWithSignals cancels on the first termination signal and reserves a
// second signal for an immediate process exit. The watcher is explicitly
// stoppable so commands that finish without a signal do not leak a goroutine.
func contextWithSignals(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	stop := make(chan struct{})
	watcherDone := make(chan struct{})
	var stopOnce sync.Once
	go func() {
		defer close(watcherDone)
		select {
		case <-parent.Done():
			return
		case <-stop:
			return
		case <-signals:
			cancel()
		}
		select {
		case <-signals:
			exitProcess(1)
		case <-parent.Done():
		case <-stop:
		}
	}()
	cleanup := func() {
		stopOnce.Do(func() { close(stop) })
		signal.Stop(signals)
		cancel()
		<-watcherDone
	}
	return ctx, cleanup
}
func printValue(format string, v any) error {
	if format == "json" {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	switch x := v.(type) {
	case string:
		fmt.Println(x)
	default:
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	}
	return nil
}

func normalizedConfig(cfg *config.Config) map[string]any {
	jobs := make([]map[string]any, 0, len(cfg.Jobs))
	for _, j := range cfg.Jobs {
		jobs = append(jobs, map[string]any{"name": j.Name, "schedule": j.Schedule, "timezone": j.Timezone, "targets": j.Targets, "security_hash": j.SecurityHash()})
	}
	return map[string]any{"valid": true, "version": cfg.Version, "database": cfg.Database, "web_listen": cfg.Web.Listen, "log_level": cfg.LogLevel(), "max_probe_count": cfg.Scheduler.MaxProbeCount, "max_naabu_probe_count": cfg.Scheduler.MaxNaabuProbeCount, "target_exclusions": append([]string(nil), cfg.Scanner.TargetExclusions...), "rdap_enabled": cfg.RDAPEnabled(), "updates_enabled": cfg.UpdatesEnabled(), "jobs": jobs, "legacy_jobs_inactive": len(jobs) > 0, "notification_destinations": len(cfg.Notifications.URLs)}
}

func status(ctx context.Context, s *store.Store, cfg *config.Config, filter, output string) error {
	type row struct {
		Name                string `json:"name"`
		Schedule            string `json:"schedule"`
		Timezone            string `json:"timezone"`
		BaselineScanID      string `json:"baseline_scan_id,omitempty"`
		BaselineProgress    string `json:"baseline_progress"`
		ActiveIncidents     int    `json:"active_incidents"`
		ConsecutiveFailures int    `json:"consecutive_failures"`
		LastScanID          string `json:"last_scan_id,omitempty"`
		LastScanStatus      string `json:"last_scan_status,omitempty"`
		LastScanFinished    string `json:"last_scan_finished,omitempty"`
		NextRun             string `json:"next_run"`
		FailedDeliveries    int    `json:"failed_deliveries"`
	}
	var rows []row
	failedDeliveries, err := s.FailedDeliveries(ctx)
	if err != nil {
		return err
	}
	managed, err := s.ListJobs(ctx, true)
	if err != nil {
		return err
	}
	managedNames := map[string]bool{}
	for _, record := range managed {
		managedNames[record.Job.Name] = true
		if filter != "" && record.Job.Name != filter {
			continue
		}
		state, err := s.RuntimeState(ctx, record.ID)
		if err != nil {
			return err
		}
		progress := "complete"
		if state.Baseline == nil {
			progress = fmt.Sprintf("%d/%d", state.CandidateCount, record.Job.Baseline.Samples)
		} else if state.BaselineConfigHash != record.Job.SecurityHash() {
			progress = fmt.Sprintf("updating %d/%d", state.CandidateCount, record.Job.Baseline.Samples)
		}
		entry := row{Name: record.Job.Name, Schedule: record.Job.Schedule, Timezone: record.Job.Timezone, BaselineScanID: state.BaselineScanID, BaselineProgress: progress, ActiveIncidents: len(state.Incidents), ConsecutiveFailures: state.ConsecutiveFailures, FailedDeliveries: failedDeliveries}
		if scans, listErr := s.ListJobScans(ctx, record.ID, 1); listErr != nil {
			return listErr
		} else if len(scans) == 1 {
			entry.LastScanID, entry.LastScanStatus = scans[0].ID, scans[0].Status
			entry.LastScanFinished = scans[0].FinishedAt.Format(time.RFC3339)
		}
		location := statusLocation(record.Job.Timezone)
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		if schedule, parseErr := parser.Parse(record.Job.Schedule); parseErr == nil {
			entry.NextRun = schedule.Next(time.Now().In(location)).Format(time.RFC3339)
		}
		rows = append(rows, entry)
	}
	for _, j := range cfg.Jobs {
		if managedNames[j.Name] {
			continue
		}
		if filter != "" && j.Name != filter {
			continue
		}
		state, err := s.State(ctx, j.Name)
		if err != nil {
			return err
		}
		progress := "complete"
		if state.Baseline == nil {
			progress = fmt.Sprintf("%d/%d", state.CandidateCount, j.Baseline.Samples)
		} else if state.BaselineConfigHash != j.SecurityHash() {
			progress = fmt.Sprintf("updating %d/%d", state.CandidateCount, j.Baseline.Samples)
		}
		entry := row{Name: j.Name, Schedule: j.Schedule, Timezone: j.Timezone, BaselineScanID: state.BaselineScanID, BaselineProgress: progress, ActiveIncidents: len(state.Incidents), ConsecutiveFailures: state.ConsecutiveFailures, FailedDeliveries: failedDeliveries}
		if scans, listErr := s.ListScans(ctx, j.Name, 1); listErr != nil {
			return listErr
		} else if len(scans) == 1 {
			entry.LastScanID = scans[0].ID
			entry.LastScanStatus = scans[0].Status
			entry.LastScanFinished = scans[0].FinishedAt.Format(time.RFC3339)
		}
		location := statusLocation(j.Timezone)
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		if schedule, parseErr := parser.Parse(j.Schedule); parseErr == nil {
			entry.NextRun = schedule.Next(time.Now().In(location)).Format(time.RFC3339)
		}
		rows = append(rows, entry)
	}
	if filter != "" && len(rows) == 0 {
		return fmt.Errorf("unknown job %q", filter)
	}
	return printValue(output, rows)
}

func statusLocation(timezone string) *time.Location {
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return time.UTC
	}
	return location
}

func baseline(ctx context.Context, action string, s *store.Store, a *app.App, job, scanID, output string) error {
	if job == "" {
		return errors.New("--job is required")
	}
	if record, managedErr := s.GetJobByName(ctx, job); managedErr == nil {
		var events []model.Event
		var err error
		var destinations []string
		destinations, err = a.Notifier.QueueDestinationsForJob(ctx, record.Job)
		if err != nil {
			return err
		}
		switch action {
		case "approve":
			if scanID == "" {
				return errors.New("--scan-id is required")
			}
			scan, getErr := s.GetScan(ctx, scanID)
			if getErr != nil {
				return getErr
			}
			if scan.JobID != record.ID || scan.ConfigHash != record.Job.SecurityHash() {
				return errors.New("scan does not match the current managed job")
			}
			events, err = s.ApproveRuntimeWithOutboxAndAudit(ctx, record.ID, record.Job.Name, scan, destinations, store.AuditEntry{
				Action:        "baseline.approved",
				Detail:        record.ID + ":" + scan.ID,
				ActorUserID:   store.LegacyAdminUserID,
				ActorUsername: "host-cli",
			})
		case "reset":
			events, err = s.ResetRuntimeWithOutboxAndAudit(ctx, record.ID, record.Job.Name, destinations, store.AuditEntry{
				Action:        "baseline.reset",
				Detail:        record.ID,
				ActorUserID:   store.LegacyAdminUserID,
				ActorUsername: "host-cli",
			})
		default:
			return errors.New("expected: baseline approve|reset")
		}
		if err != nil {
			return err
		}
		a.WakeDelivery()
		return printValue(output, events)
	}
	return fmt.Errorf("unknown managed job %q; YAML jobs are inactive and must be recreated in the web console", job)
}
