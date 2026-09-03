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
	"syscall"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
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
	if cmd == "config" || cmd == "baseline" || cmd == "notify" {
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
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if cmd == "help" {
		return usage()
	}
	cfg, err := config.Load(*configPath)
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
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	application, err := app.New(cfg, s, *nmapPath, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cmd {
	case "daemon":
		return application.Daemon(ctx)
	case "scan":
		if *jobName == "" {
			return errors.New("--job is required")
		}
		job, err := application.Job(*jobName)
		if err != nil {
			return err
		}
		scan, events, err := application.RunJob(ctx, job)
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
Commands: daemon, config validate, scan, status, history, baseline approve|reset, notify test, health, version`)
	return errors.New("invalid or missing command")
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
	return map[string]any{"valid": true, "version": cfg.Version, "database": cfg.Database, "jobs": jobs, "notification_destinations": len(cfg.Notifications.URLs)}
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
	for _, j := range cfg.Jobs {
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
	if _, err := a.Job(job); err != nil {
		return err
	}
	var events []model.Event
	var err error
	switch action {
	case "approve":
		if scanID == "" {
			return errors.New("--scan-id is required")
		}
		scan, getErr := s.GetScan(ctx, scanID)
		if getErr != nil {
			return getErr
		}
		jobConfig, getErr := a.Job(job)
		if getErr != nil {
			return getErr
		}
		if scan.ConfigHash != jobConfig.SecurityHash() {
			return errors.New("scan does not match the current security-relevant job configuration")
		}
		events, err = s.Approve(ctx, job, scan)
	case "reset":
		events, err = s.ResetBaseline(ctx, job)
	default:
		return errors.New("expected: baseline approve|reset")
	}
	if err != nil {
		return err
	}
	if err = a.Notifier.Queue(ctx, events); err != nil {
		return err
	}
	return printValue(output, events)
}
