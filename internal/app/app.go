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
	Config      *config.Config
	Store       *store.Store
	Scanner     *scanner.Nmap
	Engine      *engine.Engine
	Notifier    *notify.Notifier
	Logger      *slog.Logger
	active      sync.Map
	wg          sync.WaitGroup
	sem         chan struct{}
	nmapVersion string
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
	return &App{Config: cfg, Store: s, Scanner: sc, Engine: &engine.Engine{Store: s}, Notifier: n, Logger: logger, sem: make(chan struct{}, cfg.Scheduler.MaxConcurrent), nmapVersion: sc.Version(ctx)}, nil
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
	if _, loaded := a.active.LoadOrStore(job.Name, true); loaded {
		return model.Scan{}, nil, scanner.ErrBusy
	}
	defer a.active.Delete(job.Name)
	select {
	case a.sem <- struct{}{}:
		defer func() { <-a.sem }()
	case <-ctx.Done():
		return model.Scan{}, nil, ctx.Err()
	}
	started := time.Now().UTC()
	scan := model.Scan{ID: scanner.NewID(started), Job: job.Name, StartedAt: started, ConfigHash: job.SecurityHash(), NmapVersion: a.nmapVersion}
	if err := a.Store.AcquireJobLease(ctx, job.Name, scan.ID, started.Add(job.Timeout.Value()+time.Minute)); err != nil {
		if errors.Is(err, store.ErrJobBusy) {
			return model.Scan{}, nil, scanner.ErrBusy
		}
		return model.Scan{}, nil, err
	}
	defer func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer releaseCancel()
		_ = a.Store.ReleaseJobLease(releaseCtx, job.Name, scan.ID)
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
	var events []model.Event
	var err error
	if scanErr != nil {
		events, err = a.Engine.Failure(persistCtx, job.Name, scan)
	} else {
		events, err = a.Engine.Success(persistCtx, job, scan)
	}
	if err != nil {
		return scan, nil, err
	}
	if err = a.Notifier.Queue(persistCtx, events); err != nil {
		return scan, events, err
	}
	if err := a.Notifier.Drain(persistCtx); err != nil {
		a.Logger.Warn("notification delivery deferred for retry", "job", job.Name, "error", err)
	}
	if scanErr != nil {
		return scan, events, scanErr
	}
	return scan, events, nil
}

func (a *App) Daemon(ctx context.Context) error {
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
	for _, job := range a.Config.Jobs {
		j := job
		spec := "CRON_TZ=" + j.Timezone + " " + j.Schedule
		if _, err := c.AddFunc(spec, func() { a.startScheduled(ctx, j) }); err != nil {
			return err
		}
		if j.RunsOnStart() {
			a.startScheduled(ctx, j)
		}
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
				a.Logger.Warn("notification delivery failed", "error", err)
			}
		case <-prune.C:
			if n, err := a.Store.Prune(ctx, time.Now().Add(-a.Config.Retention.Value())); err != nil {
				a.Logger.Error("history pruning failed", "error", err)
			} else {
				a.Logger.Info("history pruned", "scans", n)
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
