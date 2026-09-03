package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/robfig/cron/v3"
)

type App struct {
	Config       *config.Config
	Store        *store.Store
	Scanner      Scanner
	Engine       *engine.Engine
	Notifier     *notify.Notifier
	Logger       *slog.Logger
	active       sync.Map
	wg           sync.WaitGroup
	sem          chan struct{}
	nmapVersion  string
	scheduleMu   sync.Mutex
	cron         *cron.Cron
	entries      map[string]cron.EntryID
	scheduleWake chan struct{}
	eventMu      sync.RWMutex
	eventHandler func(model.Event)
}

// Scanner is the small boundary used by the application. Production uses
// Nmap; tests and future scan engines can provide deterministic implementations
// without changing scheduling or baseline behavior.
type Scanner interface {
	Scan(context.Context, config.Job) (model.Snapshot, error)
	Version(context.Context) string
}

func New(cfg *config.Config, s *store.Store, nmapPath string, logger *slog.Logger) (*App, error) {
	n, err := notify.New(s, cfg.Notifications.URLs)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	sc := scanner.New(nmapPath)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return &App{Config: cfg, Store: s, Scanner: sc, Engine: &engine.Engine{Store: s}, Notifier: n, Logger: logger, sem: make(chan struct{}, cfg.Scheduler.MaxConcurrent), nmapVersion: sc.Version(ctx), entries: map[string]cron.EntryID{}, scheduleWake: make(chan struct{}, 1)}, nil
}

func (a *App) Job(name string) (config.Job, error) {
	for _, j := range a.Config.Jobs {
		if j.Name == name {
			return j, nil
		}
	}
	return config.Job{}, fmt.Errorf("unknown job %q", name)
}

func (a *App) RunJob(ctx context.Context, job config.Job) (model.Scan, []model.Event, error) {
	return a.runJob(ctx, job, "", 0, false)
}

// RunJobRecord executes a web-managed job revision. The record is passed by
// value so a concurrent edit cannot change the configuration of an in-flight
// scan.
func (a *App) RunJobRecord(ctx context.Context, record store.JobRecord) (model.Scan, []model.Event, error) {
	if record.Archived {
		return model.Scan{}, nil, errors.New("archived jobs cannot run")
	}
	return a.runJob(ctx, record.Job, record.ID, record.Revision, true)
}

func (a *App) runJob(ctx context.Context, job config.Job, jobID string, revision int64, managed bool) (model.Scan, []model.Event, error) {
	key := job.Name
	if managed {
		key = jobID
	}
	if _, loaded := a.active.LoadOrStore(key, true); loaded {
		return model.Scan{}, nil, scanner.ErrBusy
	}
	defer a.active.Delete(key)
	select {
	case a.sem <- struct{}{}:
		defer func() { <-a.sem }()
	case <-ctx.Done():
		return model.Scan{}, nil, ctx.Err()
	}
	started := time.Now().UTC()
	scan := model.Scan{ID: scanner.NewID(started), JobID: jobID, JobRevision: revision, Job: job.Name, StartedAt: started, ConfigHash: job.SecurityHash(), NmapVersion: a.nmapVersion}
	leaseKey := job.Name
	if managed {
		leaseKey = jobID
	}
	var leaseErr error
	if managed {
		leaseErr = a.Store.AcquireJobLeaseForRevision(ctx, leaseKey, scan.ID, revision, started.Add(job.Timeout.Value()+time.Minute))
	} else {
		leaseErr = a.Store.AcquireJobLease(ctx, leaseKey, scan.ID, started.Add(job.Timeout.Value()+time.Minute))
	}
	if err := leaseErr; err != nil {
		if errors.Is(err, store.ErrJobBusy) {
			return model.Scan{}, nil, scanner.ErrBusy
		}
		return model.Scan{}, nil, err
	}
	// Publish lifecycle updates to the web console without persisting them as
	// alert events. This keeps SSE subscribers responsive even when a scan has
	// no baseline or incident event to emit.
	a.emitEvents([]model.Event{{Type: "scan.started", JobID: jobID, Job: job.Name, ScanID: scan.ID, Message: "Scan started", CreatedAt: started}})
	defer func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer releaseCancel()
		_ = a.Store.ReleaseJobLease(releaseCtx, leaseKey, scan.ID)
	}()
	scanCtx, cancel := context.WithTimeout(ctx, job.Timeout.Value())
	defer cancel()
	snapshot, scanErr := a.Scanner.Scan(scanCtx, job)
	scan.FinishedAt = time.Now().UTC()
	scan.Snapshot = snapshot
	if scanErr != nil {
		scan.Status = "failed"
		scan.Error = scanErr.Error()
	} else {
		scan.Status = "success"
	}
	persistCtx, persistCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer persistCancel()
	if err := a.Store.SaveScan(persistCtx, scan); err != nil {
		return scan, nil, err
	}
	completionEvent := model.Event{Type: "scan.completed", JobID: jobID, Job: job.Name, ScanID: scan.ID, Message: "Scan " + scan.Status, CreatedAt: scan.FinishedAt}
	var events []model.Event
	var err error
	if scanErr != nil {
		if managed {
			events, err = a.Engine.FailureForJob(persistCtx, jobID, job.Name, scan)
		} else {
			events, err = a.Engine.Failure(persistCtx, job.Name, scan)
		}
	} else {
		if managed {
			events, err = a.Engine.SuccessForJob(persistCtx, jobID, job, scan)
		} else {
			events, err = a.Engine.Success(persistCtx, job, scan)
		}
	}
	if managed && errors.Is(err, store.ErrJobRevisionChanged) {
		// Keep the scan in immutable history, but do not let a result from a
		// superseded security scope seed or mutate the current baseline. A
		// lifecycle-only revision retains the same hash and is still accepted.
		a.Logger.Info("scan completed for superseded security scope; runtime state unchanged", "job", job.Name, "scan_id", scan.ID)
		events, err = nil, nil
	}
	if err != nil {
		a.emitEvents([]model.Event{completionEvent})
		return scan, nil, err
	}
	if err = a.Notifier.Queue(persistCtx, events); err != nil {
		a.emitEvents(events)
		a.emitEvents([]model.Event{completionEvent})
		return scan, events, err
	}
	a.emitEvents(events)
	a.emitEvents([]model.Event{completionEvent})
	if err := a.Notifier.Drain(persistCtx); err != nil {
		a.Logger.Warn("notification delivery deferred for retry", "job", job.Name)
	}
	if scanErr != nil {
		return scan, events, scanErr
	}
	return scan, events, nil
}

func (a *App) Daemon(ctx context.Context) error {
	if len(a.Config.Jobs) > 0 {
		a.Logger.Warn("legacy YAML jobs detected; they are inactive in web-managed mode and must be recreated in the console", "jobs", len(a.Config.Jobs))
	}
	owner := fmt.Sprintf("%s-%d", hostname(), os.Getpid())
	if err := a.Store.AcquireLease(ctx, owner); err != nil {
		return err
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.Store.ReleaseLease(releaseCtx, owner)
	}()
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	c := cron.New(cron.WithParser(parser))
	a.scheduleMu.Lock()
	a.cron = c
	a.scheduleMu.Unlock()
	if err := a.reconcileSchedules(ctx, true); err != nil {
		return err
	}
	c.Start()
	heartbeat := time.NewTicker(30 * time.Second)
	deliver := time.NewTicker(30 * time.Second)
	prune := time.NewTicker(24 * time.Hour)
	defer heartbeat.Stop()
	defer deliver.Stop()
	defer prune.Stop()
	_ = a.Notifier.Drain(ctx)
	if n, err := a.Store.Prune(ctx, time.Now().Add(-a.Config.Retention.Value())); err != nil {
		a.Logger.Error("startup history pruning failed", "error", err)
	} else if n > 0 {
		a.Logger.Info("startup history pruned", "scans", n)
	}
	for {
		select {
		case <-ctx.Done():
			a.scheduleMu.Lock()
			a.cron = nil
			a.scheduleMu.Unlock()
			stopped := c.Stop()
			<-stopped.Done()
			a.wg.Wait()
			return nil
		case <-heartbeat.C:
			if err := a.Store.Heartbeat(ctx, owner); err != nil {
				return err
			}
		case <-deliver.C:
			if err := a.Notifier.Drain(ctx); err != nil {
				a.Logger.Warn("notification delivery failed")
			}
		case <-prune.C:
			if n, err := a.Store.Prune(ctx, time.Now().Add(-a.Config.Retention.Value())); err != nil {
				a.Logger.Error("history pruning failed", "error", err)
			} else {
				a.Logger.Info("history pruned", "scans", n)
			}
		case <-a.scheduleWake:
			if err := a.reconcileSchedules(ctx, false); err != nil {
				a.Logger.Error("job schedule reconciliation failed", "error", err)
			}
		}
	}
}

func (a *App) startScheduled(ctx context.Context, job config.Job) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.runScheduled(ctx, job)
	}()
}

func (a *App) startManagedScheduled(ctx context.Context, id string) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		record, err := a.Store.GetJob(ctx, id)
		if err != nil || record.Archived || !record.Enabled {
			return
		}
		scan, events, runErr := a.RunJobRecord(ctx, record)
		if errors.Is(runErr, scanner.ErrBusy) {
			a.Logger.Warn("scheduled run skipped because job is active", "job", record.Job.Name)
			return
		}
		if runErr != nil {
			a.Logger.Error("scan failed", "job", record.Job.Name, "scan_id", scan.ID, "error", runErr)
			return
		}
		a.Logger.Info("scan complete", "job", record.Job.Name, "scan_id", scan.ID, "events", len(events))
	}()
}

// RefreshSchedules wakes the running daemon. Changes made while the daemon is
// stopped are picked up at the next startup.
func (a *App) RefreshSchedules() {
	select {
	case a.scheduleWake <- struct{}{}:
	default:
	}
}

// SetEventHandler registers an optional live-update sink (the web console uses
// this for SSE). It is deliberately a callback so the scanner and application
// packages remain independent of HTTP.
func (a *App) SetEventHandler(handler func(model.Event)) {
	a.eventMu.Lock()
	a.eventHandler = handler
	a.eventMu.Unlock()
}

func (a *App) emitEvents(events []model.Event) {
	a.eventMu.RLock()
	handler := a.eventHandler
	a.eventMu.RUnlock()
	if handler == nil {
		return
	}
	for _, event := range events {
		handler(event)
	}
}

func (a *App) reconcileSchedules(ctx context.Context, runOnStart bool) error {
	a.scheduleMu.Lock()
	c := a.cron
	a.scheduleMu.Unlock()
	if c == nil {
		return nil
	}
	jobs, err := a.Store.ListJobs(ctx, true)
	if err != nil {
		return err
	}
	desired := map[string]store.JobRecord{}
	for _, record := range jobs {
		if !record.Archived && record.Enabled {
			desired[record.ID] = record
		}
	}
	a.scheduleMu.Lock()
	defer a.scheduleMu.Unlock()
	for id, entry := range a.entries {
		if _, ok := desired[id]; !ok {
			c.Remove(entry)
			delete(a.entries, id)
		}
	}
	for id, record := range desired {
		if old, ok := a.entries[id]; ok {
			c.Remove(old)
			delete(a.entries, id)
		}
		spec := "CRON_TZ=" + record.Job.Timezone + " " + record.Job.Schedule
		jobID := id
		entry, err := c.AddFunc(spec, func() { a.startManagedScheduled(ctx, jobID) })
		if err != nil {
			return fmt.Errorf("job %s: %w", record.Job.Name, err)
		}
		a.entries[id] = entry
		if runOnStart && record.Job.RunsOnStart() {
			a.startManagedScheduled(ctx, id)
		}
	}
	return nil
}

func (a *App) runScheduled(ctx context.Context, job config.Job) {
	scan, events, err := a.RunJob(ctx, job)
	if errors.Is(err, scanner.ErrBusy) {
		a.Logger.Warn("scheduled run skipped because job is active", "job", job.Name)
		return
	}
	if err != nil {
		a.Logger.Error("scan failed", "job", job.Name, "scan_id", scan.ID, "error", err)
		return
	}
	a.Logger.Info("scan complete", "job", job.Name, "scan_id", scan.ID, "events", len(events))
}
func hostname() string {
	v, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return v
}

func JSON(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }
