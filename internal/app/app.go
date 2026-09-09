package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/updatecheck"
	"github.com/robfig/cron/v3"
)

type App struct {
	// Version is the build version shown by the web console and CLI. It is
	// populated by the command package when the process starts and defaults to
	// "dev" for library and test users.
	Version           string
	Config            *config.Config
	Store             *store.Store
	Scanner           Scanner
	Engine            *engine.Engine
	Notifier          *notify.Notifier
	Logger            *slog.Logger
	active            sync.Map
	running           sync.Map
	wg                sync.WaitGroup
	runMu             sync.Mutex
	runCtx            context.Context
	runCancel         context.CancelFunc
	runAccepting      bool
	runStarted        bool
	sem               chan struct{}
	nmapVersion       string
	naabuVersion      string
	scheduleMu        sync.Mutex
	cron              *cron.Cron
	entries           map[string]cron.EntryID
	scheduleSpecs     map[string]string
	scheduleWake      chan struct{}
	eventMu           sync.RWMutex
	eventHandler      func(model.Event)
	deliveryWake      chan struct{}
	heartbeatInterval time.Duration
	ReleaseChecker    ReleaseChecker
	UpdateInterval    time.Duration
}

type activeRun struct {
	mu     sync.RWMutex
	scan   model.ActiveScan
	cancel context.CancelFunc
}

// ErrShuttingDown is returned when a new asynchronous managed scan cannot be
// accepted because the daemon is stopping.
var ErrShuttingDown = errors.New("application is shutting down")

// ErrScanWorkBudget is returned before a lease is acquired when a job's
// estimated probe count exceeds the deployment guard and the job has not
// explicitly opted into high-cost work.
var ErrScanWorkBudget = errors.New("estimated scan work exceeds the configured probe budget")

// ErrScanCycleStalled tells scheduled callers that an operator must intervene
// before another attempt is started. Manual runs are allowed to retry the
// checkpointed cycle explicitly.
var ErrScanCycleStalled = errors.New("scan cycle is stalled; manual retry required")

const (
	scanPersistenceTimeoutFloor   = 10 * time.Second
	scanPersistenceTimeoutPerHost = 25 * time.Millisecond
	scanPersistenceTimeoutMax     = 5 * time.Minute
)

// scanPersistenceTimeout gives the final database transaction enough time to
// serialize detailed host evidence without allowing a pathological result to
// block shutdown forever. The previous fixed ten-second budget was adequate
// for small jobs but could cancel a large successful scan midway through its
// SaveScan transaction.
func scanPersistenceTimeout(hostCount int) time.Duration {
	if hostCount <= 0 {
		return scanPersistenceTimeoutFloor
	}
	maxAdditional := (scanPersistenceTimeoutMax - scanPersistenceTimeoutFloor) / scanPersistenceTimeoutPerHost
	if int64(hostCount) >= int64(maxAdditional) {
		return scanPersistenceTimeoutMax
	}
	return scanPersistenceTimeoutFloor + time.Duration(hostCount)*scanPersistenceTimeoutPerHost
}

type ScanWorkBudgetError struct {
	Estimate config.WorkEstimate
	Budget   int64
}

func (e *ScanWorkBudgetError) Error() string {
	return fmt.Sprintf("%v: estimated %d probes exceeds budget %d", ErrScanWorkBudget, e.Estimate.Probes, e.Budget)
}

func (e *ScanWorkBudgetError) Unwrap() error { return ErrScanWorkBudget }

func (a *App) CheckScanWorkBudget(job config.Job) (config.WorkEstimate, error) {
	estimate, err := config.EstimateJobWork(job)
	if err != nil {
		return estimate, err
	}
	if job.AllowHighCost {
		return estimate, nil
	}
	budget := a.Config.Scheduler.MaxProbeCount
	if budget <= 0 {
		budget = config.DefaultMaxProbeCount
	}
	if estimate.Probes > budget {
		return estimate, &ScanWorkBudgetError{Estimate: estimate, Budget: budget}
	}
	return estimate, nil
}

// Scanner is the small boundary used by the application. Production uses
// Nmap; tests and future scan engines can provide deterministic implementations
// without changing scheduling or baseline behavior.
type Scanner interface {
	Scan(context.Context, config.Job) (model.Snapshot, error)
	Version(context.Context) string
}

// ReleaseChecker is the small boundary used by the daemon. Keeping the
// network client behind this interface makes cadence and failure behavior
// deterministic in application tests.
type ReleaseChecker interface {
	Check(context.Context, string) (updatecheck.Result, error)
}

// ProgressScanner is optional so deterministic test scanners and future
// integrations can keep the small Scanner contract. Production Nmap exposes
// bounded progress and responds to cancellation through the context.
type ProgressScanner interface {
	Scanner
	ScanWithProgress(context.Context, config.Job, scanner.ProgressReporter) (model.Snapshot, error)
}

func New(cfg *config.Config, s *store.Store, nmapPath string, logger *slog.Logger) (*App, error) {
	return NewWithScannerPaths(cfg, s, nmapPath, "/usr/local/bin/naabu", logger)
}

// NewWithScannerPaths is the production constructor used when the daemon
// needs to locate both fixed scanner binaries. New remains the compatibility
// entry point for tests and embedded callers that only know about Nmap.
func NewWithScannerPaths(cfg *config.Config, s *store.Store, nmapPath, naabuPath string, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Web.AuthKeyFile != "" {
		s.SetAuthKeyPath(cfg.Web.AuthKeyFile)
	}
	var n *notify.Notifier
	var err error
	if cfg.Notifications.EncryptionKeyFile != "" {
		// An explicitly configured path is operator-managed. It must already
		// contain a valid key; the notifier only generates the default key next
		// to the database when no override is configured.
		n, err = notify.NewWithKeyFile(s, cfg.Notifications.URLs, cfg.Notifications.EncryptionKeyFile)
	} else {
		n, err = notify.New(s, cfg.Notifications.URLs)
	}
	if err != nil {
		return nil, err
	}
	// Jobs created before per-job routing was introduced have a nil selection
	// and historically followed every globally enabled destination. Materialize
	// that snapshot at startup so a destination added later cannot silently
	// become enabled for those jobs. Explicit selections, including an empty
	// silent selection, are left untouched.
	materialized, err := s.MaterializeLegacyNotificationSelections(context.Background(), n.LegacySelection())
	if err != nil {
		return nil, fmt.Errorf("freeze legacy notification selections: %w", err)
	}
	if materialized > 0 {
		logger.Info("froze legacy notification selections", "jobs", materialized)
	}
	if len(cfg.Jobs) > 0 {
		legacyNames := make([]string, 0, len(cfg.Jobs))
		for _, job := range cfg.Jobs {
			legacyNames = append(legacyNames, job.Name)
		}
		logger.Warn("legacy YAML jobs are inactive; recreate them in the web console", "jobs", legacyNames)
	}
	sc := scanner.NewWithNaabu(nmapPath, naabuPath)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return &App{Version: "dev", Config: cfg, Store: s, Scanner: sc, Engine: &engine.Engine{Store: s}, Notifier: n, Logger: logger, ReleaseChecker: updatecheck.NewClient(), UpdateInterval: updatecheck.CheckInterval, sem: make(chan struct{}, cfg.Scheduler.MaxConcurrent), nmapVersion: sc.Version(ctx), naabuVersion: sc.NaabuVersion(ctx), entries: map[string]cron.EntryID{}, scheduleSpecs: map[string]string{}, scheduleWake: make(chan struct{}, 1), deliveryWake: make(chan struct{}, 1), heartbeatInterval: 30 * time.Second}, nil
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
	return a.runJob(ctx, job, "", 0, false, false)
}

// RunJobRecord executes a web-managed job revision. The record is passed by
// value so a concurrent edit cannot change the configuration of an in-flight
// scan.
func (a *App) RunJobRecord(ctx context.Context, record store.JobRecord) (model.Scan, []model.Event, error) {
	return a.runJobRecord(ctx, record, true)
}

// runJobRecord executes a web-managed job with an explicit trigger mode. A
// manual trigger may retry a stalled resumable cycle; scheduled triggers stop
// at the stalled state until an operator either runs it manually or discards
// the saved progress.
func (a *App) runJobRecord(ctx context.Context, record store.JobRecord, manual bool) (model.Scan, []model.Event, error) {
	if record.Archived {
		return model.Scan{}, nil, errors.New("archived jobs cannot run")
	}
	return a.runJob(ctx, record.Job, record.ID, record.Revision, true, manual)
}

// BeginRun binds the application's asynchronous work to parent. The returned
// context is shared by the daemon, scheduler, web-triggered scans, and
// shutdown path. The boolean reports whether this call created the binding;
// callers that own a standalone daemon invocation should call StopRun when it
// returns. A web test may start a fallback context before the daemon starts;
// the real binding replaces and cancels that fallback.
func (a *App) BeginRun(parent context.Context) (context.Context, bool) {
	if parent == nil {
		parent = context.Background()
	}
	a.runMu.Lock()
	if a.runStarted && a.runAccepting && a.runCtx != nil {
		ctx := a.runCtx
		a.runMu.Unlock()
		return ctx, false
	}
	if a.runCancel != nil && !a.runStarted {
		a.runCancel()
	}
	ctx, cancel := context.WithCancel(parent)
	a.runCtx, a.runCancel, a.runAccepting, a.runStarted = ctx, cancel, true, true
	a.runMu.Unlock()
	return ctx, true
}

// StopRun prevents new asynchronous work, cancels the shared run context, and
// waits until every tracked scheduled or manual run has returned. It is safe
// for multiple owners to call while shutdown races with a daemon error.
func (a *App) StopRun() {
	a.runMu.Lock()
	cancel := a.runCancel
	a.runAccepting = false
	a.runCancel = nil
	a.runCtx = nil
	a.runMu.Unlock()
	if cancel != nil {
		cancel()
	}
	a.wg.Wait()
}

// StartManagedRun accepts a web-triggered managed scan and tracks it in the
// same wait group as scheduled work. The callback runs after the scan has
// reached a terminal state (or could not be started).
func (a *App) StartManagedRun(id string, done func(model.Scan, []model.Event, error)) error {
	a.runMu.Lock()
	if !a.runAccepting {
		if a.runStarted {
			a.runMu.Unlock()
			return ErrShuttingDown
		}
		// Keep direct httptest/embedded-server users functional before a daemon
		// binds the lifecycle to its signal context. BeginRun replaces this
		// fallback if the real daemon starts later.
		a.runCtx, a.runCancel = context.WithCancel(context.Background())
		a.runAccepting = true
	}
	ctx := a.runCtx
	a.wg.Add(1)
	a.runMu.Unlock()
	go func() {
		defer a.wg.Done()
		latest, err := a.Store.GetJob(ctx, id)
		if err != nil {
			if done != nil {
				done(model.Scan{}, nil, err)
			}
			return
		}
		if latest.Archived {
			if done != nil {
				done(model.Scan{}, nil, errors.New("archived jobs cannot run"))
			}
			return
		}
		scan, events, runErr := a.RunJobRecord(ctx, latest)
		if done != nil {
			done(scan, events, runErr)
		}
	}()
	return nil
}

func (a *App) runJob(ctx context.Context, job config.Job, jobID string, revision int64, managed, manual bool) (model.Scan, []model.Event, error) {
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
	estimate, err := a.CheckScanWorkBudget(job)
	if err != nil {
		return model.Scan{}, nil, err
	}
	if managed && !manual {
		if cycle, cycleErr := a.Store.GetActiveScanCycle(ctx, jobID); cycleErr == nil && cycle.Status == "stalled" {
			return model.Scan{}, nil, ErrScanCycleStalled
		}
	}
	started := time.Now().UTC()
	engineName := config.EngineNmap
	profileID, profileRevision := "", int64(0)
	if job.TCP != nil {
		if job.TCP.Engine != "" {
			engineName = job.TCP.Engine
		}
		profileID, profileRevision = job.TCP.ProfileID, job.TCP.ProfileRevision
	}
	scan := model.Scan{ID: scanner.NewID(started), JobID: jobID, JobRevision: revision, Job: job.Name, StartedAt: started, ConfigHash: job.SecurityHash(), NmapVersion: a.nmapVersion, ScannerEngine: engineName, ScannerProfileID: profileID, ScannerProfileRevision: profileRevision}
	if engineName == config.EngineNaabuNmap {
		scan.NaabuVersion = a.naabuVersion
	}
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
	scanCtx, cancel := context.WithTimeout(ctx, job.Timeout.Value())
	run := &activeRun{scan: model.ActiveScan{ID: scan.ID, JobID: jobID, Job: job.Name, JobRevision: revision, StartedAt: started, EstimatedProbes: estimate.Probes, NmapInvocations: estimate.NmapInvocations, EstimatedSeconds: estimate.EstimatedSeconds, TotalProbes: estimate.Probes, TotalInvocations: estimate.NmapInvocations, Phase: "starting", Scanner: engineName, ScannerProfileID: profileID, ScannerProfileRevision: profileRevision}, cancel: cancel}
	a.running.Store(scan.ID, run)
	defer func() {
		cancel()
		a.running.Delete(scan.ID)
	}()
	// Legacy nil selections are frozen at scan start as well as when they are
	// persisted. This closes the race where a new endpoint is added while an
	// older scan is running: that scan must not deliver its completion events to
	// an endpoint that did not exist when the scan began. Stable selectors are
	// resolved again at finalization so managed credential rotations still use
	// the current revision.
	var legacyNotificationSelection []string
	legacySelectionCaptured := false
	if managed && job.NotificationDestinations == nil {
		if reloadErr := a.Notifier.Reload(ctx); reloadErr != nil {
			a.Logger.Warn("legacy notification selection snapshot failed", "job", job.Name, "error", reloadErr)
		} else {
			legacyNotificationSelection = a.Notifier.LegacySelection()
			legacySelectionCaptured = true
		}
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
	var snapshot model.Snapshot
	var scanErr error
	resumableRun := false
	// The scanner planner owns both ordinary Nmap units and Naabu pipeline
	// batches. Naabu units checkpoint a pinned address batch after discovery and
	// enrichment, so a paused cycle can resume without replaying completed
	// batches or bypassing the discovery phase.
	useResumable := managed
	if useResumable {
		if resumableScanner, ok := a.Scanner.(scanner.ResumableScanner); ok {
			var handled bool
			handled, snapshot, scanErr = a.runResumableAttempt(ctx, scanCtx, job, jobID, &scan, run, resumableScanner, manual)
			resumableRun = handled
			if errors.Is(scanErr, ErrScanCycleStalled) {
				// A scheduled trigger that races with a newly stalled cycle must
				// not create a synthetic failed scan or notification. The cycle's
				// original stall attempt already recorded the actionable alert.
				return model.Scan{}, nil, scanErr
			}
		}
	}
	if !resumableRun {
		if progressScanner, ok := a.Scanner.(ProgressScanner); ok {
			snapshot, scanErr = progressScanner.ScanWithProgress(scanCtx, job, func(progress scanner.Progress) {
				a.updateActiveProgress(scan.ID, progress)
			})
		} else {
			snapshot, scanErr = a.Scanner.Scan(scanCtx, job)
		}
	}
	// Scanner progress carries phase timing for the optional Naabu pipeline.
	// Capture it before the active run is removed by the deferred cleanup so
	// the immutable scan record remains useful after completion.
	if current := run.snapshot(); current.DiscoveryDurationMS > 0 || current.EnrichmentDurationMS > 0 {
		scan.DiscoveryDurationMS = current.DiscoveryDurationMS
		scan.EnrichmentDurationMS = current.EnrichmentDurationMS
	}
	scan.FinishedAt = time.Now().UTC()
	scan.Snapshot = snapshot
	if scan.ScannerEngine == config.EngineNaabuNmap {
		scan.DiscoveryPorts, scan.ConfirmedPorts = scannerDiscoveryStats(snapshot)
	}
	if scanErr != nil {
		if !resumableRun {
			if errors.Is(scanCtx.Err(), context.Canceled) {
				scan.Status = "canceled"
				scan.Error = "scan canceled"
			} else if errors.Is(scanCtx.Err(), context.DeadlineExceeded) || errors.Is(scanErr, context.DeadlineExceeded) {
				scan.Status = "timed_out"
				scan.Error = "scan timed out"
			} else {
				scan.Status = "failed"
				scan.Error = scanErr.Error()
			}
		}
	} else if !resumableRun {
		scan.Status = "success"
	}
	a.updateActivePhase(scan.ID, "finalizing")
	persistTimeout := scanPersistenceTimeout(len(scan.Snapshot.Hosts))
	if a.Logger != nil {
		a.Logger.Debug("persisting scan result", "scan_id", scan.ID, "hosts", len(scan.Snapshot.Hosts), "timeout", persistTimeout)
	}
	persistCtx, persistCancel := context.WithTimeout(context.Background(), persistTimeout)
	defer persistCancel()
	completionEvent := model.Event{Type: "scan.completed", JobID: jobID, Job: job.Name, ScanID: scan.ID, Message: "Scan " + scan.Status, CreatedAt: scan.FinishedAt}
	var destinations []string
	if managed {
		var destinationErr error
		if legacySelectionCaptured {
			destinations, destinationErr = a.Notifier.QueueDestinationsForSelection(persistCtx, legacyNotificationSelection)
		} else {
			destinations, destinationErr = a.Notifier.QueueDestinationsForJob(persistCtx, job)
		}
		if destinationErr != nil {
			// Preserve the completed scan even when notification configuration
			// cannot be read. Runtime state is deliberately left unchanged,
			// matching the pre-transaction behavior.
			if saveErr := a.Store.SaveScan(persistCtx, scan); saveErr != nil {
				return scan, nil, saveErr
			}
			return scan, nil, destinationErr
		}
	}
	var events []model.Event
	var finalizeErr error
	if managed {
		events, finalizeErr = a.Engine.FinalizeManagedScan(persistCtx, jobID, job, &scan, destinations)
	} else {
		if err := a.Store.SaveScan(persistCtx, scan); err != nil {
			return scan, nil, err
		}
		if scan.Status != "success" {
			events, finalizeErr = a.Engine.Failure(persistCtx, job.Name, scan)
		} else {
			events, finalizeErr = a.Engine.Success(persistCtx, job, scan)
		}
	}
	if managed && errors.Is(finalizeErr, store.ErrJobRevisionChanged) {
		// Keep the scan in immutable history, but do not let a result from a
		// superseded security scope seed or mutate the current baseline. A
		// lifecycle-only revision retains the same hash and is still accepted.
		a.Logger.Info("scan completed for superseded security scope; runtime state unchanged", "job", job.Name, "scan_id", scan.ID)
		events, finalizeErr = nil, nil
	}
	if finalizeErr != nil {
		a.emitEvents([]model.Event{completionEvent})
		return scan, nil, finalizeErr
	}
	a.emitEvents(events)
	a.emitEvents([]model.Event{completionEvent})
	if !managed {
		if err := a.Notifier.Queue(persistCtx, events); err != nil {
			return scan, events, err
		}
	}
	a.wakeDelivery()
	if scanErr != nil {
		return scan, events, scanErr
	}
	return scan, events, nil
}

// ActiveScans returns a stable snapshot of scans that are currently executing.
// A scan only enters this set after its database lease is acquired, so a
// queued or rejected request is not reported as running.
func (a *App) ActiveScans() []model.ActiveScan {
	var scans []model.ActiveScan
	a.running.Range(func(_, value any) bool {
		if run, ok := value.(*activeRun); ok {
			scans = append(scans, run.snapshot())
		}
		return true
	})
	sort.Slice(scans, func(i, j int) bool {
		if scans[i].StartedAt.Equal(scans[j].StartedAt) {
			return scans[i].ID < scans[j].ID
		}
		return scans[i].StartedAt.Before(scans[j].StartedAt)
	})
	return scans
}

// CancelScan requests cancellation of an active scan. The scanner owns the
// process context and will persist a canceled terminal record without
// mutating baseline or incident state.
func (a *App) CancelScan(id string) error {
	value, ok := a.running.Load(id)
	if !ok {
		return store.ErrNotFound
	}
	run, ok := value.(*activeRun)
	if !ok {
		return store.ErrNotFound
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.cancel == nil {
		return store.ErrNotFound
	}
	run.cancel()
	run.scan.Phase = "cancelling"
	return nil
}

func (a *App) updateActiveProgress(id string, progress scanner.Progress) {
	value, ok := a.running.Load(id)
	if !ok {
		return
	}
	run, ok := value.(*activeRun)
	if !ok {
		return
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	if progress.TotalProbes > 0 {
		run.scan.TotalProbes = progress.TotalProbes
	}
	if progress.TotalInvocations > 0 {
		run.scan.TotalInvocations = progress.TotalInvocations
	}
	run.scan.CompletedProbes = progress.CompletedProbes
	run.scan.CompletedInvocations = progress.CompletedInvocations
	run.scan.ProgressPercent = progressPercent(progress)
	if progress.Protocol != "" {
		run.scan.Protocol = progress.Protocol
	}
	if progress.CurrentInvocation > 0 {
		run.scan.CurrentInvocation = progress.CurrentInvocation
	}
	if progress.DiscoveryPortsFound > run.scan.DiscoveryPortsFound {
		run.scan.DiscoveryPortsFound = progress.DiscoveryPortsFound
	}
	if progress.DiscoveryAddresses > run.scan.DiscoveryAddresses {
		run.scan.DiscoveryAddresses = progress.DiscoveryAddresses
	}
	if progress.DiscoveryDurationMS > run.scan.DiscoveryDurationMS {
		run.scan.DiscoveryDurationMS = progress.DiscoveryDurationMS
	}
	if progress.EnrichmentDurationMS > run.scan.EnrichmentDurationMS {
		run.scan.EnrichmentDurationMS = progress.EnrichmentDurationMS
	}
	if progress.TotalBatches > 0 {
		run.scan.TotalBatches = progress.TotalBatches
	}
	if progress.ProcessAlive || progress.ProcessProgressPercent > 0 {
		run.scan.ProcessProgressPercent = progress.ProcessProgressPercent
	}
	if progress.ElapsedSeconds > run.scan.ElapsedSeconds {
		run.scan.ElapsedSeconds = progress.ElapsedSeconds
	}
	if progress.LastOutput != "" {
		run.scan.LastOutput = progress.LastOutput
	}
	run.scan.ProcessAlive = progress.ProcessAlive
	if progress.Phase != "" {
		run.scan.Phase = progress.Phase
	}
}

func (a *App) updateActivePhase(id, phase string) {
	value, ok := a.running.Load(id)
	if !ok {
		return
	}
	run, ok := value.(*activeRun)
	if !ok {
		return
	}
	run.mu.Lock()
	run.scan.Phase = phase
	run.scan.ProcessAlive = false
	run.mu.Unlock()
}

func (r *activeRun) snapshot() model.ActiveScan {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snapshot := r.scan
	if !snapshot.StartedAt.IsZero() {
		elapsed := int64(time.Since(snapshot.StartedAt).Seconds())
		if elapsed > snapshot.ElapsedSeconds {
			snapshot.ElapsedSeconds = elapsed
		}
	}
	return snapshot
}

func progressPercent(progress scanner.Progress) int {
	total, completed := progress.TotalProbes, progress.CompletedProbes
	if total <= 0 {
		total, completed = progress.TotalInvocations, progress.CompletedInvocations
	}
	if total <= 0 {
		return 0
	}
	percent := int(completed * 100 / total)
	if percent < 0 {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}

func scannerDiscoveryStats(snapshot model.Snapshot) (discovered, confirmed int) {
	seenDiscovered := map[string]struct{}{}
	seenConfirmed := map[string]struct{}{}
	for _, host := range snapshot.Hosts {
		for _, protocol := range host.Protocols {
			if protocol.Protocol != "tcp" {
				continue
			}
			for _, port := range protocol.DiscoveredPorts {
				seenDiscovered[host.Address+"/tcp/"+fmt.Sprint(port.Port)] = struct{}{}
			}
			for _, port := range protocol.Ports {
				if port.State == "open" || port.State == "open|filtered" {
					seenConfirmed[host.Address+"/tcp/"+fmt.Sprint(port.Port)] = struct{}{}
				}
			}
		}
	}
	return len(seenDiscovered), len(seenConfirmed)
}

func (a *App) Daemon(ctx context.Context) error {
	boundCtx, owned := a.BeginRun(ctx)
	// Keep daemon-owned work on a child context so an internal error can stop
	// cron callbacks and the delivery worker before Daemon returns to its
	// supervisor. The application run context is cancelled by StopRun after
	// both daemon and HTTP goroutines have been joined.
	daemonCtx, daemonCancel := context.WithCancel(boundCtx)
	ctx = daemonCtx
	defer daemonCancel()
	if owned {
		defer a.StopRun()
	}
	if len(a.Config.Jobs) > 0 {
		a.Logger.Warn("legacy YAML jobs detected; they are inactive in web-managed mode and must be recreated in the console", "jobs", len(a.Config.Jobs))
	}
	owner := fmt.Sprintf("%s-%d", hostname(), os.Getpid())
	if err := a.Store.AcquireLease(ctx, owner); err != nil {
		return err
	}
	if released, err := a.Store.ReleaseDeliveryClaims(ctx); err != nil {
		a.Logger.Error("startup notification claim cleanup failed", "error", err)
	} else if released > 0 {
		a.Logger.Info("startup notification claims released", "claims", released)
	}
	if released, err := a.Store.ReleaseAllJobLeases(ctx); err != nil {
		a.Logger.Error("startup job lease cleanup failed", "error", err)
	} else if released > 0 {
		a.Logger.Info("startup job leases released", "leases", released)
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
		// Keep healthy jobs running even when one persisted row is malformed;
		// the reconciliation retry ticker below will install it once repaired.
		a.Logger.Error("initial job schedule reconciliation failed", "error", err)
	}
	c.Start()
	heartbeatEvery := a.heartbeatInterval
	if heartbeatEvery <= 0 {
		heartbeatEvery = 30 * time.Second
	}
	heartbeat := time.NewTicker(heartbeatEvery)
	prune := time.NewTicker(24 * time.Hour)
	scheduleRetry := time.NewTicker(30 * time.Second)
	updateInterval := a.UpdateInterval
	if updateInterval <= 0 {
		updateInterval = updatecheck.CheckInterval
	}
	updates := time.NewTicker(updateInterval)
	defer heartbeat.Stop()
	defer prune.Stop()
	defer scheduleRetry.Stop()
	defer updates.Stop()
	workerCtx, workerCancel := context.WithCancel(ctx)
	deliveryDone := a.startDeliveryWorker(workerCtx)
	defer func() {
		// Cancel before joining. This ordering is required on heartbeat/lease
		// errors, where the parent context may still be live. Cancelling the
		// daemon context also releases any scheduled scan that c.Stop waits on.
		daemonCancel()
		workerCancel()
		a.scheduleMu.Lock()
		if a.cron == c {
			a.cron = nil
		}
		a.scheduleMu.Unlock()
		stopped := c.Stop()
		<-stopped.Done()
		<-deliveryDone
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if released, err := a.Store.ReleaseDeliveryClaims(releaseCtx); err != nil {
			a.Logger.Error("shutdown notification claim cleanup failed", "error", err)
		} else if released > 0 {
			a.Logger.Info("shutdown notification claims released", "claims", released)
		}
	}()
	a.wakeDelivery()
	if removed, err := a.Store.DeleteExpiredSessions(ctx, time.Now().UTC()); err != nil {
		a.Logger.Error("startup expired-session cleanup failed", "error", err)
	} else if removed > 0 {
		a.Logger.Info("startup expired sessions pruned", "sessions", removed)
	}
	if stats, err := a.Store.PruneWithStats(ctx, time.Now().Add(-a.Config.Retention.Value())); err != nil {
		a.Logger.Error("startup history pruning failed", "error", err)
	} else if stats.Total() > 0 {
		a.Logger.Info("startup history pruned", "rows", stats.Total(), "scans", stats.Scans, "events", stats.Events, "sent_outbox", stats.SentOutbox, "failed_outbox", stats.FailedOutbox, "revisions", stats.Revisions, "cycles", stats.Cycles)
	}
	if expired, err := a.Store.ExpireScanCycles(ctx, time.Now().UTC()); err != nil {
		a.Logger.Error("startup scan-cycle expiry failed", "error", err)
	} else if expired > 0 {
		a.Logger.Info("expired scan cycles", "cycles", expired)
	}
	// Run the update check once at startup, then on the fixed three-hour
	// cadence. Version tracking remains active even when outbound checks are
	// disabled so a later deployment can still report a real upgrade.
	a.runUpdateCheck(ctx)
	missedHeartbeats := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeat.C:
			if err := a.Store.Heartbeat(ctx, owner); err != nil {
				if errors.Is(err, store.ErrLeaseLost) {
					return err
				}
				missedHeartbeats++
				a.Logger.Error("daemon lease heartbeat failed", "error", err, "consecutive", missedHeartbeats)
				if missedHeartbeats >= 3 {
					return err
				}
				continue
			}
			missedHeartbeats = 0
		case <-prune.C:
			if removed, err := a.Store.DeleteExpiredSessions(ctx, time.Now().UTC()); err != nil {
				a.Logger.Error("expired-session cleanup failed", "error", err)
			} else if removed > 0 {
				a.Logger.Info("expired sessions pruned", "sessions", removed)
			}
			if stats, err := a.Store.PruneWithStats(ctx, time.Now().Add(-a.Config.Retention.Value())); err != nil {
				a.Logger.Error("history pruning failed", "error", err)
			} else {
				a.Logger.Info("history pruned", "rows", stats.Total(), "scans", stats.Scans, "events", stats.Events, "sent_outbox", stats.SentOutbox, "failed_outbox", stats.FailedOutbox, "revisions", stats.Revisions, "cycles", stats.Cycles)
			}
			if expired, err := a.Store.ExpireScanCycles(ctx, time.Now().UTC()); err != nil {
				a.Logger.Error("scan-cycle expiry failed", "error", err)
			} else if expired > 0 {
				a.Logger.Info("expired scan cycles", "cycles", expired)
			}
		case <-a.scheduleWake:
			if err := a.reconcileSchedules(ctx, false); err != nil {
				a.Logger.Error("job schedule reconciliation failed", "error", err)
			}
		case <-scheduleRetry.C:
			if err := a.reconcileSchedules(ctx, false); err != nil {
				a.Logger.Error("job schedule reconciliation retry failed", "error", err)
			}
		case <-updates.C:
			a.runUpdateCheck(ctx)
		}
	}
}

func (a *App) updateDestinations(ctx context.Context) []string {
	if a.Notifier == nil {
		return nil
	}
	destinations, err := a.Notifier.QueueDestinations(ctx)
	if err != nil {
		logger := a.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Warn("application update notification destinations unavailable", "error", err)
		return nil
	}
	return destinations
}

func (a *App) emitUpdateStatus() {
	a.emitEvents([]model.Event{{Type: "application.update_status", Message: "Application update status changed", CreatedAt: time.Now().UTC()}})
}

// runUpdateCheck records the current build and performs one bounded release
// lookup. All notification-producing state transitions are committed by the
// store before their corresponding events are emitted to SSE subscribers.
func (a *App) runUpdateCheck(ctx context.Context) {
	if a.Store == nil {
		return
	}
	logger := a.Logger
	if logger == nil {
		logger = slog.Default()
	}
	current := updatecheck.NormalizeVersion(a.Version)
	if current != "" {
		state, err := a.Store.GetApplicationUpdateState(ctx)
		if err != nil {
			logger.Warn("application version state unavailable", "error", err)
		} else {
			versionComparison := updatecheck.CompareVersions(current, state.InstalledVersion)
			notifyUpgrade := state.InstalledVersion != "" && versionComparison > 0
			if state.InstalledVersion != "" && versionComparison < 0 {
				logger.Warn("application version rollback detected", "previous_version", state.InstalledVersion, "current_version", current)
			}
			releaseURL := ""
			if state.LatestVersion == current {
				releaseURL = state.ReleaseURL
			}
			if releaseURL == "" {
				releaseURL = updatecheck.ReleasePageURL(current)
			}
			var destinations []string
			if notifyUpgrade {
				destinations = a.updateDestinations(ctx)
			}
			events, recordErr := a.Store.RecordInstalledVersion(ctx, current, releaseURL, notifyUpgrade, destinations)
			if recordErr != nil {
				logger.Warn("application version state update failed", "error", recordErr)
			} else if len(events) > 0 {
				a.emitEvents(events)
				a.wakeDelivery()
			}
		}
	}
	if a.Config == nil || !a.Config.UpdatesEnabled() || current == "" {
		return
	}
	checker := a.ReleaseChecker
	if checker == nil {
		return
	}
	state, err := a.Store.GetApplicationUpdateState(ctx)
	if err != nil {
		logger.Warn("application release state unavailable", "error", err)
		return
	}
	result, checkErr := checker.Check(ctx, state.ETag)
	if checkErr != nil {
		if err := a.Store.RecordReleaseCheckFailure(ctx, checkErr.Error()); err != nil {
			logger.Warn("application release failure state could not be saved", "error", err)
		}
		logger.Warn("application release check failed", "error", checkErr)
		a.emitUpdateStatus()
		return
	}
	if result.NotModified {
		if err := a.Store.RecordReleaseNotModified(ctx, result.ETag); err != nil {
			logger.Warn("application release check timestamp could not be saved", "error", err)
		}
		a.emitUpdateStatus()
		return
	}
	newer := updatecheck.CompareVersions(result.Release.Version, current) > 0
	release := result.Release
	if release.URL == "" {
		release.URL = updatecheck.ReleasePageURL(release.Version)
	}
	var destinations []string
	if newer {
		destinations = a.updateDestinations(ctx)
	}
	events, recordErr := a.Store.RecordReleaseCheck(ctx, current, release.Version, release.URL, release.Name, release.PublishedAt, result.ETag, newer, destinations)
	if recordErr != nil {
		logger.Warn("application release state update failed", "error", recordErr)
		return
	}
	if len(events) > 0 {
		a.emitEvents(events)
		a.wakeDelivery()
	}
	a.emitUpdateStatus()
}

func (a *App) startScheduled(ctx context.Context, job config.Job) {
	a.startTracked(func() {
		a.runScheduled(ctx, job)
	})
}

func (a *App) startManagedScheduled(ctx context.Context, id string) {
	a.startTracked(func() {
		record, err := a.Store.GetJob(ctx, id)
		if err != nil || record.Archived || !record.Enabled {
			return
		}
		scan, events, runErr := a.runJobRecord(ctx, record, false)
		if errors.Is(runErr, scanner.ErrBusy) {
			a.Logger.Warn("scheduled run skipped because job is active", "job", record.Job.Name)
			return
		}
		if errors.Is(runErr, ErrScanCycleStalled) {
			a.Logger.Warn("scheduled run skipped because resumable cycle is stalled; manual retry required", "job", record.Job.Name)
			return
		}
		if runErr != nil {
			a.Logger.Error("scan failed", "job", record.Job.Name, "scan_id", scan.ID, "error", runErr)
			return
		}
		a.Logger.Info("scan complete", "job", record.Job.Name, "scan_id", scan.ID, "events", len(events))
	})
}

func (a *App) startTracked(fn func()) bool {
	a.runMu.Lock()
	if !a.runAccepting {
		a.runMu.Unlock()
		return false
	}
	a.wg.Add(1)
	a.runMu.Unlock()
	go func() {
		defer a.wg.Done()
		fn()
	}()
	return true
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
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	specs := make(map[string]string, len(desired))
	invalid := map[string]error{}
	for id, record := range desired {
		spec := "CRON_TZ=" + record.Job.Timezone + " " + record.Job.Schedule
		parsed, err := parser.Parse(spec)
		if err != nil {
			invalid[id] = fmt.Errorf("job %s: %w", record.Job.Name, err)
			continue
		}
		if parsed.Next(time.Now().UTC()).IsZero() {
			invalid[id] = fmt.Errorf("job %s: schedule never fires", record.Job.Name)
			continue
		}
		specs[id] = spec
	}
	a.scheduleMu.Lock()
	if a.entries == nil {
		a.entries = map[string]cron.EntryID{}
	}
	if a.scheduleSpecs == nil {
		a.scheduleSpecs = map[string]string{}
	}
	// Add replacements before removing their old entries. All desired specs
	// were parsed above, so an AddFunc failure can be rolled back without
	// leaving an otherwise healthy job unscheduled.
	type pendingEntry struct {
		id     string
		entry  cron.EntryID
		old    cron.EntryID
		hadOld bool
	}
	pending := make([]pendingEntry, 0, len(specs))
	for id, spec := range specs {
		old, exists := a.entries[id]
		if exists && a.scheduleSpecs[id] == spec {
			continue
		}
		jobID := id
		entry, err := c.AddFunc(spec, func() { a.startManagedScheduled(ctx, jobID) })
		if err != nil {
			for _, added := range pending {
				c.Remove(added.entry)
			}
			a.scheduleMu.Unlock()
			return fmt.Errorf("job %s: %w", desired[id].Job.Name, err)
		}
		pending = append(pending, pendingEntry{id: id, entry: entry, old: old, hadOld: exists})
	}
	for id, old := range a.entries {
		if _, isInvalid := invalid[id]; isInvalid {
			// Preserve a last-known-good entry until the bad persisted row is
			// repaired. New invalid jobs simply remain unscheduled.
			continue
		}
		if _, exists := specs[id]; !exists {
			c.Remove(old)
			delete(a.entries, id)
			delete(a.scheduleSpecs, id)
		}
	}
	startOnCreate := make([]string, 0, len(pending))
	for _, next := range pending {
		if next.hadOld {
			c.Remove(next.old)
		}
		a.entries[next.id] = next.entry
		a.scheduleSpecs[next.id] = specs[next.id]
		if runOnStart && !next.hadOld && desired[next.id].Job.RunsOnStart() {
			startOnCreate = append(startOnCreate, next.id)
		}
	}
	// Preserve the spec cache for entries that were created by an older
	// process/version and did not need replacement during this pass.
	for id, spec := range specs {
		if _, ok := a.scheduleSpecs[id]; !ok {
			a.scheduleSpecs[id] = spec
		}
	}
	a.scheduleMu.Unlock()
	for _, id := range startOnCreate {
		a.startManagedScheduled(ctx, id)
	}
	if len(invalid) > 0 {
		errList := make([]error, 0, len(invalid))
		for _, err := range invalid {
			errList = append(errList, err)
		}
		return errors.Join(errList...)
	}
	return nil
}

// wakeDelivery coalesces notifications for the daemon-owned delivery worker.
// Keeping delivery outside the scheduler loop means a slow provider cannot
// stop heartbeats or delay schedule reconciliation.
func (a *App) wakeDelivery() {
	if a.deliveryWake == nil {
		return
	}
	select {
	case a.deliveryWake <- struct{}{}:
	default:
	}
}

// WakeDelivery asks the daemon-owned delivery worker to process newly queued
// notification intent promptly. It is safe for callers used by the web API
// when the daemon is not running; the periodic worker remains the fallback.
func (a *App) WakeDelivery() {
	a.wakeDelivery()
}

func (a *App) startDeliveryWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		drain := func() {
			passCtx, cancel := context.WithTimeout(ctx, 70*time.Second)
			defer cancel()
			if err := a.Notifier.Drain(passCtx); err != nil && !errors.Is(err, context.Canceled) {
				a.Logger.Warn("notification delivery deferred for retry", "error", err)
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-a.deliveryWake:
				drain()
			case <-ticker.C:
				drain()
			}
		}
	}()
	return done
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
