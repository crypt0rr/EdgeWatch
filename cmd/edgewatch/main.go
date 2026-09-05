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
	"strings"
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
	jobName := fs.String("job", "", "job name")
	scanID := fs.String("scan-id", "", "scan ID")
	limit := fs.Int("limit", 50, "history limit")
	nmapPath := fs.String("nmap", "nmap", "Nmap executable")
	passwordFile := fs.String("password-file", "", "file containing a new administrator password")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if cmd == "help" {
		return usage()
	}
	loadConfig := config.Load
	if cmd == "admin" {
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
	s, err := store.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer s.Close()
	if cmd == "admin" {
		return adminAction(context.Background(), action, s, *passwordFile)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	application, err := app.New(cfg, s, *nmapPath, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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
		return baseline(ctx, action, s, application, *jobName, *scanID, *output)
	case "notify":
		if action != "test" {
			return errors.New("expected: notify test")
		}
		return application.Notifier.Test()
	case "health":
		return s.Healthy(ctx)
	default:
		return usage()
	}
}

func usage() error {
	fmt.Fprintln(os.Stderr, `Usage: edgewatch <command> [options]
	Commands: daemon, config validate, scan, status, history, baseline approve|reset, notify test, admin reset-password|disable-totp, health, version`)
	return errors.New("invalid or missing command")
}

func adminAction(ctx context.Context, action string, s *store.Store, passwordFile string) error {
	admin, err := s.GetAdmin(ctx)
	if err != nil {
		return errors.New("administrator is not configured")
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
		admin.PasswordHash, admin.UpdatedAt = hash, time.Now().UTC()
		return s.SaveAdminSecurity(ctx, admin, nil, false, true, "admin.password_reset", "password reset from host CLI")
	case "disable-totp":
		admin.TOTPEnabled, admin.TOTPSecret, admin.UpdatedAt = false, "", time.Now().UTC()
		return s.SaveAdminSecurity(ctx, admin, []string{}, true, true, "admin.totp_disabled", "TOTP disabled from host CLI")
	default:
		return errors.New("expected: admin reset-password|disable-totp")
	}
}

func runDaemon(ctx context.Context, application *app.App, listen string, s *store.Store, logger *slog.Logger) error {
	runCtx, _ := application.BeginRun(ctx)
	server := web.NewServer(application, s, logger)
	errCh := make(chan error, 2)
	go func() { errCh <- application.Daemon(runCtx) }()
	go func() { errCh <- server.ListenAndServe(runCtx, listen) }()
	first := <-errCh
	// One component returning (including an HTTP bind or daemon lease error)
	// must stop the other component before the database is closed by run().
	application.StopRun()
	second := <-errCh
	if first != nil {
		return first
	}
	return second
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
	return map[string]any{"valid": true, "version": cfg.Version, "database": cfg.Database, "web_listen": cfg.Web.Listen, "max_probe_count": cfg.Scheduler.MaxProbeCount, "rdap_enabled": cfg.RDAPEnabled(), "jobs": jobs, "legacy_jobs_inactive": len(jobs) > 0, "notification_destinations": len(cfg.Notifications.URLs)}
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
		location, _ := time.LoadLocation(record.Job.Timezone)
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
		location, _ := time.LoadLocation(j.Timezone)
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

func baseline(ctx context.Context, action string, s *store.Store, a *app.App, job, scanID, output string) error {
	if job == "" {
		return errors.New("--job is required")
	}
	if record, managedErr := s.GetJobByName(ctx, job); managedErr == nil {
		var events []model.Event
		var err error
		var destinations []string
		destinations, err = a.Notifier.QueueDestinations(ctx)
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
			events, err = s.ApproveRuntimeWithOutbox(ctx, record.ID, record.Job.Name, scan, destinations)
		case "reset":
			events, err = s.ResetRuntimeWithOutbox(ctx, record.ID, record.Job.Name, destinations)
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
