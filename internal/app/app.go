package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/updatecheck"
	"github.com/robfig/cron/v3"
)

type App struct {
	// Version is the build version shown by the web console and CLI. It is
	// populated by the command package when the process starts and defaults to
	// "dev" for library and test users.
	Version  string
	Config   *config.Config
	Store    *store.Store
	Scanner  Scanner
	Engine   *engine.Engine
	Notifier *notify.Notifier
	Logger   *slog.Logger
	// sandbox is the policy the scanner's processes start with.
	sandbox *sandbox.Policy
	active  sync.Map
	// managedReservations closes the window between an HTTP manual-run request
	// and the goroutine reaching runJob. Scheduled work checks this map too, so
	// a queued manual run receives the slot deterministically instead of two
	// requests both returning 202 and one being dropped later.
	managedReservations sync.Map
	running             sync.Map
	queuedRuns          sync.Map
	wg                  sync.WaitGroup
	runMu               sync.Mutex
	runCtx              context.Context
	runCancel           context.CancelFunc
	runAccepting        bool
	runStarted          bool
	slots               *slotPool
	nmapVersion         string
	naabuVersion        string
	daemonOwnerMu       sync.RWMutex
	daemonOwner         string
	scheduleMu          sync.Mutex
	cron                *cron.Cron
	entries             map[string]cron.EntryID
	scheduleSpecs       map[string]string
	scheduleWake        chan struct{}
	eventMu             sync.RWMutex
	eventHandler        func(model.Event)
	unitPausedHandler   func(tenantID string) // see SetUnitPausedHandler; eventMu guards it
	deliveryWake        chan struct{}
	heartbeatInterval   time.Duration
	ReleaseChecker      ReleaseChecker
	UpdateInterval      time.Duration
	clock               func() time.Time
	// pruneHistory overrides the system retention pass in deterministic tests.
	pruneHistory func(context.Context, time.Time) (store.PruneStats, error)
	// persistenceBudget overrides the size-based scan-finalization work budget
	// in deterministic tests. Production leaves it nil and uses
	// scanPersistenceTimeout.
	persistenceBudget func(hostCount int) time.Duration
	// units tracks the business units that this process paused, and wakes
	// the purge of deleted ones; see units.go.
	units unitLifecycle
}

type activeRun struct {
	mu     sync.RWMutex
	scan   model.ActiveScan
	cancel context.CancelFunc
	// tenant is the ID of the run's tenant, set by registerRun.
	tenant string
	// finalizing is set once the result is being saved. A cancellation can
	// no longer change the outcome then.
	finalizing bool
}

// interruptedByShutdown reports whether scanCtx ended because the run
// context ctx ended, as it does when the daemon stops or loses its lease,
// rather than because someone asked to cancel this scan.
func (r *activeRun) interruptedByShutdown(ctx, scanCtx context.Context) bool {
	if !errors.Is(scanCtx.Err(), context.Canceled) || ctx.Err() == nil {
		return false
	}
	if r == nil {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return !r.scan.CancelRequested
}

// ScanInterruptedMessage is the error of a scan that stopped because
// EdgeWatch stopped while it ran.
const ScanInterruptedMessage = "scan interrupted because EdgeWatch stopped"

type cronSlogLogger struct{ logger *slog.Logger }

func (l cronSlogLogger) Info(msg string, keysAndValues ...interface{}) {
	if l.logger != nil {
		l.logger.Info(msg, keysAndValues...)
	}
}

func (l cronSlogLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	if l.logger == nil {
		return
	}
	args := make([]any, 0, len(keysAndValues)+2)
	args = append(args, "error", err)
	args = append(args, keysAndValues...)
	l.logger.Error(msg, args...)
}

// ErrShuttingDown is returned when a new asynchronous managed scan cannot be
// accepted because the daemon is stopping.
var ErrShuttingDown = errors.New("application is shutting down")

// ErrScanFinalizing is returned by CancelScan once a scan is saving its
// result, when cancelling it would no longer change the outcome.
var ErrScanFinalizing = errors.New("scan is saving its result and can no longer be canceled")

// ErrScanWorkBudget is returned before a lease is acquired when a job's
// estimated probe count exceeds the deployment guard and the job has not
// explicitly opted into high-cost work.
var ErrScanWorkBudget = errors.New("estimated scan work exceeds the configured probe budget")

// ErrScanCycleStalled tells scheduled callers that an operator must intervene
// before another attempt is started. Transient unit failures are retried a
// bounded number of times while a cycle remains paused; this state is reserved
// for permanent failures or an exhausted retry budget. Manual runs are allowed
// to retry the checkpointed cycle explicitly.
var ErrScanCycleStalled = errors.New("scan cycle is stalled; manual retry required")

// ErrQueuedRunSkipped reports that a managed run did not start because its job
// was archived, or paused for a scheduled run, while the run waited for a scan
// slot.
var ErrQueuedRunSkipped = errors.New("queued run skipped")

// ErrQueuedRunCanceled is returned by a run whose wait for a scan slot was
// canceled with CancelQueuedRun.
var ErrQueuedRunCanceled = errors.New("queued run was canceled")

// ErrRunNotQueued is returned by CancelQueuedRun when the job has no run
// waiting for a scan slot, for example because it has already started.
var ErrRunNotQueued = errors.New("job has no queued run")

// queuedRun is a run waiting for a scan slot. cancel ends its wait. started
// and canceled are guarded by mu, so a cancellation either ends the wait or
// is refused because the run has already taken its slot.
type queuedRun struct {
	mu       sync.Mutex
	run      model.QueuedRun
	cancel   context.CancelCauseFunc
	started  bool
	canceled bool
}

// start marks the run as having taken its slot. It reports false when the
// run was canceled first.
func (q *queuedRun) start() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.canceled {
		return false
	}
	q.started = true
	return true
}

const (
	scanPersistenceTimeoutFloor      = 10 * time.Second
	scanPersistenceTimeoutPerHost    = 25 * time.Millisecond
	scanPersistenceTimeoutMax        = 5 * time.Minute
	scanPersistenceWriterWaitTimeout = 5 * time.Minute
)

// scanPersistenceTimeout gives the finalization transaction enough work time
// to serialize detailed host evidence after it obtains SQLite's writer. The
// separate writer-wait bound ensures that contention does not consume this
// size-based budget. The previous fixed ten-second budget could cancel a
// large successful scan midway through its SaveScan transaction.
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

// resolvedPlanProbeTotals derives the actual work represented by a pinned
// scanner plan. Unlike the preflight estimate, this count is based on the
// resolved addresses and concrete work units, so DNS expansion cannot bypass
// the deployment safety rails. A plan's declared total is treated as a
// conservative lower bound only when it exceeds the unit sum; the difference
// is charged to Nmap because it is the less permissive budget.
func resolvedPlanProbeTotals(plan scanner.WorkPlan) (discovery, nmapProbes int64) {
	var unitTotal int64
	for _, unit := range plan.Units {
		probes := unit.Probes
		if probes < 0 {
			probes = 0
		}
		unitTotal = saturatingProbeAdd(unitTotal, probes)
		if unit.Phase == "discovery" {
			discovery = saturatingProbeAdd(discovery, probes)
		} else {
			nmapProbes = saturatingProbeAdd(nmapProbes, probes)
		}
	}
	if len(plan.Units) == 0 {
		// Custom resumable scanners may provide only a declared total. Treat it
		// as Nmap work so a missing phase cannot make a plan appear free.
		return 0, maxNonNegative(plan.TotalProbes)
	}
	if declared := maxNonNegative(plan.TotalProbes); declared > unitTotal {
		nmapProbes = saturatingProbeAdd(nmapProbes, declared-unitTotal)
	}
	return discovery, nmapProbes
}

func maxNonNegative(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func saturatingProbeAdd(a, b int64) int64 {
	if b <= 0 || a >= math.MaxInt64-b {
		if b > 0 {
			return math.MaxInt64
		}
		return a
	}
	return a + b
}

// checkResolvedProbeBudget checks resolved work against budget, the probe
// budget of the job's tenant.
func checkResolvedProbeBudget(budget probeBudget, job config.Job, discovery, nmapProbes int64) error {
	discovery = maxNonNegative(discovery)
	nmapProbes = maxNonNegative(nmapProbes)
	total := saturatingProbeAdd(discovery, nmapProbes)
	estimate := config.WorkEstimate{Probes: total, NaabuProbes: discovery, NmapProbes: nmapProbes}
	// The absolute ceiling applies to each engine and to the combined run. A
	// high-cost opt-in can raise the budgets, never above this hard limit.
	if discovery > config.MaxProbeCountLimit || nmapProbes > config.MaxProbeCountLimit || total > config.MaxProbeCountLimit {
		return &ScanWorkBudgetError{Estimate: estimate, Budget: config.MaxProbeCountLimit}
	}
	nmapBudget, naabuBudget := budget.limits(job)
	if discovery > naabuBudget {
		return &ScanWorkBudgetError{Estimate: estimate, Budget: naabuBudget}
	}
	if nmapProbes > nmapBudget {
		return &ScanWorkBudgetError{Estimate: estimate, Budget: nmapBudget}
	}
	return nil
}

// CheckScanWorkBudget estimates a job's work and checks it against the probe
// budget of the tenant of ts. A failure to read that budget wraps
// ErrProbeBudgetUnavailable.
func (a *App) CheckScanWorkBudget(ctx context.Context, ts *store.TenantStore, job config.Job) (config.WorkEstimate, error) {
	estimate, err := config.EstimateJobWork(job)
	if err != nil {
		return estimate, err
	}
	budget, err := a.tenantProbeBudget(ctx, ts)
	if err != nil {
		return estimate, err
	}
	return estimate, checkEstimatedProbeBudget(budget, job, estimate)
}

// checkEstimatedProbeBudget checks a job's estimated work against budget.
func checkEstimatedProbeBudget(budget probeBudget, job config.Job, estimate config.WorkEstimate) error {
	// A Naabu pipeline always performs a full-range discovery pass. Keep its
	// discovery budget separate from Nmap work (including UDP) so selecting the
	// faster discovery engine cannot weaken the Nmap safety rail for the same
	// job.
	effectiveJob := config.NormalizeJob(job)
	// allow_high_cost is an explicit opt-in to the tenant's high-cost
	// ceiling, never permission to schedule an unbounded scan. Keep this
	// check first so even administrators cannot exceed the hard ceiling.
	if estimate.Probes > config.MaxProbeCountLimit {
		return &ScanWorkBudgetError{Estimate: estimate, Budget: config.MaxProbeCountLimit}
	}
	nmapBudget, naabuBudget := budget.limits(job)
	if effectiveJob.TCP != nil && effectiveJob.TCP.Engine == config.EngineNaabuNmap && estimate.NaabuProbes > naabuBudget {
		return &ScanWorkBudgetError{Estimate: estimate, Budget: naabuBudget}
	}
	if estimate.NmapProbes > nmapBudget {
		return &ScanWorkBudgetError{Estimate: estimate, Budget: nmapBudget}
	}
	return nil
}

// CheckScanCycleProbeBudget applies the same safety rails to durable work
// totals before the next process starts. For Naabu cycles this covers the
// data-dependent Nmap enrichment phase; for ordinary Nmap/UDP cycles it also
// keeps resolved DNS/CIDR work within the same budgets. ts is the store of
// the tenant that owns the cycle's job, and its probe budget applies.
func (a *App) CheckScanCycleProbeBudget(ctx context.Context, ts *store.TenantStore, cycle store.ScanCycleRecord, job config.Job) error {
	discovery, nmapProbes, err := ts.ScanCycleProbeTotals(ctx, cycle.ID)
	if err != nil {
		return err
	}
	budget, err := a.tenantProbeBudget(ctx, ts)
	if err != nil {
		return err
	}
	return checkResolvedProbeBudget(budget, job, discovery, nmapProbes)
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

// BudgetedProgressScanner can validate data-dependent work immediately before
// a scanner launches it. The direct path resolves DNS again, so the hook
// checks the resolved work of every engine; Naabu also discovers the TCP port
// set first, so the hook accounts for the subsequent Nmap enrichment. It is
// optional so the small Scanner contract used by test and plugin
// implementations does not change.
type BudgetedProgressScanner interface {
	ProgressScanner
	ScanWithProgressBudget(context.Context, config.Job, scanner.ProgressReporter, func(discoveryProbes, nmapProbes int64) error) (model.Snapshot, error)
}

func New(cfg *config.Config, s *store.Store, nmapPath string, logger *slog.Logger) (*App, error) {
	return NewWithScannerPaths(cfg, s, nmapPath, "/usr/local/bin/naabu", logger)
}

// Options selects startup work that only the daemon performs.
type Options struct {
	// ImportNotificationURLs imports the notification URLs in config.yaml as
	// encrypted web-managed destinations before the notifier loads its
	// destinations. Host commands leave it unset, so they never import.
	ImportNotificationURLs bool
	// Sandbox confines the scanner's Nmap and Naabu processes. Nil starts
	// them unconfined.
	Sandbox *sandbox.Policy
}

// ScannerSandbox reports how the scanner's Nmap and Naabu processes start.
func (a *App) ScannerSandbox() sandbox.Status {
	return a.sandbox.Status()
}

// NewWithOptions is New with daemon-only startup work selected by options.
func NewWithOptions(cfg *config.Config, s *store.Store, nmapPath string, logger *slog.Logger, options Options) (*App, error) {
	return newApp(cfg, s, nmapPath, "/usr/local/bin/naabu", logger, options)
}

// NewWithScannerPaths is the production constructor used when the daemon
// needs to locate both fixed scanner binaries. New remains the compatibility
// entry point for tests and embedded callers that only know about Nmap.
func NewWithScannerPaths(cfg *config.Config, s *store.Store, nmapPath, naabuPath string, logger *slog.Logger) (*App, error) {
	return newApp(cfg, s, nmapPath, naabuPath, logger, Options{})
}

func newApp(cfg *config.Config, s *store.Store, nmapPath, naabuPath string, logger *slog.Logger, options Options) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Web.AuthKeyFile != "" {
		s.SetAuthKeyPath(cfg.Web.AuthKeyFile)
		if err := store.ValidateAuthKeyFile(cfg.Web.AuthKeyFile); err != nil {
			return nil, fmt.Errorf("validate authentication key file: %w", err)
		}
	}
	var n *notify.Notifier
	var err error
	if cfg.Notifications.EncryptionKeyFile != "" {
		if err := notify.ValidateKeyFile(cfg.Notifications.EncryptionKeyFile); err != nil {
			return nil, fmt.Errorf("validate notification encryption key file: %w", err)
		}
	}
	if options.ImportNotificationURLs {
		// The import runs before the notifier loads, so imported URLs are
		// never registered as deployment destinations or queued for delivery.
		if err := importConfiguredNotifications(context.Background(), cfg, s, logger); err != nil {
			return nil, err
		}
	}
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
	// silent selection, are left untouched. Those jobs predate tenants, so
	// they belong to the default tenant, and only its jobs are frozen here.
	// Adding a destination to any tenant freezes that tenant's nil
	// selections first, so another tenant's jobs are left as they are.
	materialized, err := materializeLegacyNotificationSelections(context.Background(), s, n)
	if err != nil {
		return nil, fmt.Errorf("freeze legacy notification selections: %w", err)
	}
	if materialized > 0 {
		logger.Info("froze legacy notification selections", "jobs", materialized)
	}
	reportMissingNotificationDestinations(context.Background(), s, n, logger)
	if len(cfg.Jobs) > 0 {
		legacyNames := make([]string, 0, len(cfg.Jobs))
		for _, job := range cfg.Jobs {
			legacyNames = append(legacyNames, job.Name)
		}
		logger.Warn("legacy YAML jobs are inactive; recreate them in the web console", "jobs", legacyNames)
	}
	if obsolete := cfg.ObsoleteSettings(); len(obsolete) > 0 {
		logger.Warn("config.yaml sets obsolete settings that are ignored; business units are always on, so remove the experimental section", "settings", obsolete)
	}
	sc := scanner.NewWithNaabu(nmapPath, naabuPath)
	sc.SetSandbox(options.Sandbox)
	if err := sc.SetTargetExclusions(cfg.Scanner.TargetExclusions); err != nil {
		return nil, fmt.Errorf("configure scanner target exclusions: %w", err)
	}
	if err := s.SetTargetExclusions(cfg.Scanner.TargetExclusions); err != nil {
		return nil, fmt.Errorf("configure store target exclusions: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return &App{Version: "dev", Config: cfg, Store: s, Scanner: sc, Engine: &engine.Engine{Store: s}, Notifier: n, Logger: logger, sandbox: options.Sandbox, ReleaseChecker: updatecheck.NewClient(), UpdateInterval: updatecheck.CheckInterval, slots: newSlotPool(cfg.Scheduler.MaxConcurrent, nil), nmapVersion: sc.Version(ctx), naabuVersion: sc.NaabuVersion(ctx), entries: map[string]cron.EntryID{}, scheduleSpecs: map[string]string{}, scheduleWake: make(chan struct{}, 1), deliveryWake: make(chan struct{}, 1), heartbeatInterval: 30 * time.Second, clock: time.Now}, nil
}

// importConfiguredNotifications imports the notification URLs in config.yaml
// once and records the outcome for the health command and the console. Only
// an invalid URL, which is invalid configuration, stops startup. When the
// import fails, nothing is imported and the configured URLs keep delivering
// as deployment destinations. Logs name counts and destination IDs only.
func importConfiguredNotifications(ctx context.Context, cfg *config.Config, s *store.Store, logger *slog.Logger) error {
	result, err := notify.ImportConfiguredURLs(ctx, s, cfg.Notifications.URLs, cfg.Notifications.EncryptionKeyFile)
	state := store.NotificationConfigImport{Status: store.NotificationConfigImportNone, ConfiguredURLs: result.Configured, ImportedURLs: result.ImportedURLs()}
	var importErr *notify.ConfigImportError
	switch {
	case errors.As(err, &importErr):
		logger.Error("notification URLs in config.yaml could not be imported; they are still delivered from config.yaml", "error_code", importErr.Code, "error", importErr.Err, "configured_urls", result.Configured)
		state.Status, state.ErrorCode = store.NotificationConfigImportFailed, importErr.Code
	case err != nil:
		return err
	case result.Configured > 0:
		state.Status = store.NotificationConfigImportImported
	}
	if len(result.Imported) > 0 {
		ids := make([]string, 0, len(result.Imported))
		for _, imported := range result.Imported {
			ids = append(ids, imported.ID)
		}
		logger.Info("imported notification URLs from config.yaml as web-managed destinations", "imported", len(ids), "destination_ids", ids, "jobs_rerouted", len(result.ChangedJobs), "update_routing_changed", result.UpdateRoutingChanged, "pending_deliveries_moved", result.MovedDeliveries, "duplicate_deliveries_merged", result.MergedDeliveries)
	}
	if result.ImportedURLs() > 0 {
		logger.Warn("notification URLs in config.yaml were imported as web-managed destinations and are no longer used; remove notifications.urls and notifications.urls_file from config.yaml, a later release refuses to start while they are set", "configured_urls", result.Configured, "imported_urls", result.ImportedURLs())
	}
	if recordErr := s.System().RecordNotificationConfigImport(ctx, state); recordErr != nil {
		logger.Warn("notification import state could not be recorded for the health command", "error", recordErr)
	}
	return nil
}

// materializeLegacyNotificationSelections freezes the nil notification
// selection of the default tenant's jobs to the destinations that selection
// follows in that tenant, and returns how many jobs it changed.
func materializeLegacyNotificationSelections(ctx context.Context, s *store.Store, n *notify.Notifier) (int, error) {
	ts := s.Tenant(store.DefaultTenantScope())
	selection, err := n.Tenant(ts).LegacySelection(ctx)
	if err != nil {
		return 0, err
	}
	return ts.MaterializeLegacyNotificationSelections(ctx, selection)
}

// reportMissingNotificationDestinations warns about saved routing that no
// longer resolves. A deployment destination's ID follows its exact URL, so
// changing a URL in config.yaml creates a new destination. Jobs that selected
// the old one keep a selector that no longer delivers anywhere. Each job's
// selection is checked against its own tenant's destinations. The warning
// names jobs only: selectors can be legacy URL digests and are not logged. A
// failed check is logged and never blocks startup.
func reportMissingNotificationDestinations(ctx context.Context, s *store.Store, n *notify.Notifier, logger *slog.Logger) {
	scopes, err := s.System().TenantScopes(ctx)
	if err != nil {
		logger.Warn("notification routing check failed", "error", err)
		return
	}
	var names, ids []string
	for _, scope := range scopes {
		ts := s.Tenant(scope)
		jobs, err := ts.ListJobs(ctx, false)
		if err != nil {
			logger.Warn("notification routing check failed", "error", err)
			return
		}
		notifier := n.Tenant(ts)
		for _, record := range jobs {
			_, missing, err := notifier.CanonicalSelection(ctx, record.Job.NotificationDestinations)
			if err != nil {
				logger.Warn("notification routing check failed", "error", err)
				return
			}
			if len(missing) > 0 {
				names = append(names, record.Job.Name)
				ids = append(ids, record.ID)
			}
		}
	}
	if len(names) > 0 {
		logger.Warn("jobs route notifications to destinations that no longer exist; edit each job in the web console to select a current destination", "jobs", names, "job_ids", ids)
	}
}

// RunJobRecord executes a web-managed job revision. The record is passed by
// value so a concurrent edit cannot change the configuration of an in-flight
// scan. If the job is edited while the run waits for a scan slot, the run
// starts with the edited revision instead; see queuedManagedJob.
func (a *App) RunJobRecord(ctx context.Context, record store.JobRecord) (model.Scan, []model.Event, error) {
	return a.runJobRecord(ctx, record, true)
}

// runJobRecord executes a web-managed job with an explicit trigger mode. A
// manual trigger may retry a stalled resumable cycle; scheduled triggers stop
// at the stalled state until an operator either runs it manually or discards
// the saved progress. The run takes its tenant from the record once and
// reads the job's data, cycles and destinations in that tenant only.
func (a *App) runJobRecord(ctx context.Context, record store.JobRecord, manual bool) (model.Scan, []model.Event, error) {
	return a.runJobRecordWithCompletion(ctx, record, manual, true)
}

func (a *App) runJobRecordWithCompletion(ctx context.Context, record store.JobRecord, manual, publishLifecycleCompletion bool) (model.Scan, []model.Event, error) {
	if record.Archived {
		return model.Scan{}, nil, errors.New("archived jobs cannot run")
	}
	scope, err := a.Store.TenantScopeByID(ctx, record.TenantID)
	if err != nil {
		return model.Scan{}, nil, err
	}
	var accepted bool
	scan, events, runErr := a.runJobWithQueueMarker(ctx, scope, record.Job, record.ID, record.Revision, manual, publishLifecycleCompletion, &accepted)
	if accepted && publishLifecycleCompletion && scan.ID == "" && runErr != nil {
		a.emitScanSkipped(scope, record.ID, record.Job.Name, scanSkipReason(runErr))
	}
	return scan, events, runErr
}

func scanSkipReason(err error) string {
	switch {
	case errors.Is(err, scanner.ErrBusy), errors.Is(err, store.ErrJobBusy):
		return "busy"
	case strings.Contains(strings.ToLower(err.Error()), "archived jobs cannot run"):
		return "archived"
	case errors.Is(err, ErrQueuedRunSkipped):
		if strings.Contains(strings.ToLower(err.Error()), "archived") {
			return "archived"
		}
		if strings.Contains(strings.ToLower(err.Error()), "paused") {
			return "paused"
		}
		return "could_not_start"
	case errors.Is(err, ErrQueuedRunCanceled):
		return "canceled"
	case errors.Is(err, ErrScanWorkBudget):
		return "budget"
	case errors.Is(err, store.ErrTenantNotActive):
		return "unit_paused"
	case errors.Is(err, context.Canceled), errors.Is(err, ErrShuttingDown):
		return "shutting_down"
	case errors.Is(err, ErrScanCycleStalled):
		return "cycle_stalled"
	case errors.Is(err, store.ErrNotFound):
		return "job_unavailable"
	default:
		return "could_not_start"
	}
}

func (a *App) emitScanSkipped(scope store.TenantScope, jobID, job, reason string) {
	a.emitTenantEvents(scope, []model.Event{{
		Type: "scan.skipped", JobID: jobID, Job: job,
		Message: "Accepted scan did not start", Reason: reason, CreatedAt: time.Now().UTC(),
	}})
}

// queuedManagedJob returns the job definition a managed run starts with once
// it holds a scan slot. A queued run holds no job lease, so an operator can
// edit the job while the run waits. The run then uses the current revision
// rather than failing the lease's revision check and disappearing. A job that
// was archived, or paused for a scheduled run, is skipped with
// ErrQueuedRunSkipped. The lease still checks the returned revision, so a
// definition that changes again before the scan starts never runs. ts is the
// store of the job's tenant.
func (a *App) queuedManagedJob(ctx context.Context, ts *store.TenantStore, job config.Job, jobID string, revision int64, manual bool) (config.Job, int64, error) {
	current, err := ts.GetJob(ctx, jobID)
	if err != nil {
		return job, revision, err
	}
	if current.Revision == revision {
		return job, revision, nil
	}
	if current.Archived {
		return job, revision, fmt.Errorf("%w: job was archived while the run waited for a scan slot", ErrQueuedRunSkipped)
	}
	if !manual && !current.Enabled {
		return job, revision, fmt.Errorf("%w: job was paused while the run waited for a scan slot", ErrQueuedRunSkipped)
	}
	return current.Job, current.Revision, nil
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

func (a *App) setDaemonOwner(owner string) {
	a.daemonOwnerMu.Lock()
	a.daemonOwner = owner
	a.daemonOwnerMu.Unlock()
}

func (a *App) clearDaemonOwner(owner string) {
	a.daemonOwnerMu.Lock()
	if a.daemonOwner == owner {
		a.daemonOwner = ""
	}
	a.daemonOwnerMu.Unlock()
}

func (a *App) currentDaemonOwner() string {
	a.daemonOwnerMu.RLock()
	defer a.daemonOwnerMu.RUnlock()
	return a.daemonOwner
}

func daemonProcessOwner() string {
	return fmt.Sprintf("%s-%d-%s", hostname(), os.Getpid(), scanner.NewID(time.Now().UTC()))
}

// recoverBackgroundPanic keeps a defect in one daemon-owned goroutine from
// taking down the scanner and web console together. The full stack is retained
// in structured logs so recovery is observable and actionable.
func (a *App) recoverBackgroundPanic(name string) {
	if recovered := recover(); recovered != nil {
		logger := a.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("background goroutine panic recovered", "goroutine", name, "panic", recovered, "stack", string(debug.Stack()))
	}
}

// StartManagedRun accepts a web-triggered managed scan and tracks it in the
// same wait group as scheduled work. The callback runs after the scan has
// reached a terminal state (or could not be started) and the job's run
// reservation is released, so the callback may start the next run. ts is the
// store of the requesting tenant: a job of another tenant is not found.
func (a *App) StartManagedRun(ts *store.TenantStore, id string, done func(model.Scan, []model.Event, error)) error {
	reservation := scanner.NewID(time.Now().UTC())
	if _, loaded := a.managedReservations.LoadOrStore(id, reservation); loaded {
		return scanner.ErrBusy
	}
	if _, active := a.active.Load(id); active {
		a.managedReservations.Delete(id)
		return scanner.ErrBusy
	}
	a.runMu.Lock()
	if !a.runAccepting {
		if a.runStarted {
			a.runMu.Unlock()
			a.managedReservations.Delete(id)
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
		// Each release compares the stored value, so this goroutine can never
		// remove a reservation that a newer run made after the early release
		// below. The deferred release covers a panic before that point.
		defer a.managedReservations.CompareAndDelete(id, reservation)
		defer a.recoverBackgroundPanic("managed-scan")
		finish := func(scan model.Scan, events []model.Event, err error) {
			// The run has returned, so it no longer holds the job lease.
			// Release the reservation before done: the web callback broadcasts
			// scan.completed, and the console then lets the operator start the
			// next run at once.
			a.managedReservations.CompareAndDelete(id, reservation)
			if scan.ID == "" && err != nil {
				if scope, scopeErr := ts.Scope(); scopeErr == nil {
					a.emitScanSkipped(scope, id, scan.Job, scanSkipReason(err))
				}
			}
			if done != nil {
				done(scan, events, err)
			}
		}
		latest, err := ts.GetJob(ctx, id)
		if err != nil {
			finish(model.Scan{}, nil, err)
			return
		}
		if latest.Archived {
			finish(model.Scan{Job: latest.Job.Name}, nil, errors.New("archived jobs cannot run"))
			return
		}
		// The web callback publishes the terminal event after the run's active
		// entry and reservation have both been released. Suppress runJob's
		// lifecycle completion for this path so subscribers receive one event
		// and can immediately start another run.
		finish(a.runJobRecordWithCompletion(ctx, latest, true, false))
	}()
	return nil
}

// runJob runs one scan of a job of the tenant of scope. It reads the job,
// its cycles and its notification destinations through that tenant's store,
// and writes leases, cycles and results through the system store. The
// tenant's ID keys its scan slot.
func (a *App) runJob(ctx context.Context, scope store.TenantScope, job config.Job, jobID string, revision int64, manual, publishLifecycleCompletion bool) (model.Scan, []model.Event, error) {
	return a.runJobWithQueueMarker(ctx, scope, job, jobID, revision, manual, publishLifecycleCompletion, nil)
}

func (a *App) runJobWithQueueMarker(ctx context.Context, scope store.TenantScope, job config.Job, jobID string, revision int64, manual, publishLifecycleCompletion bool, accepted *bool) (model.Scan, []model.Event, error) {
	key := jobID
	if !manual {
		if _, reserved := a.managedReservations.Load(key); reserved {
			return model.Scan{}, nil, scanner.ErrBusy
		}
	}
	if _, loaded := a.active.LoadOrStore(key, true); loaded {
		return model.Scan{}, nil, scanner.ErrBusy
	}
	defer a.active.Delete(key)
	if accepted != nil {
		*accepted = true
	}
	trigger := "scheduled"
	if manual {
		trigger = "manual"
	}
	// The wait has its own context, so CancelQueuedRun can end it without
	// touching the run context the scan itself will use.
	waitCtx, cancelWait := context.WithCancelCause(ctx)
	defer cancelWait(nil)
	queued := &queuedRun{run: model.QueuedRun{JobID: jobID, Job: job.Name, QueuedAt: time.Now().UTC(), Trigger: trigger, TenantID: scope.ID()}, cancel: cancelWait}
	queuedInPool := false
	releaseSlot, slotErr := a.slots.AcquireWithQueued(waitCtx, scope.ID(), func() {
		a.queuedRuns.Store(jobID, queued)
		queuedInPool = true
	})
	if slotErr != nil {
		if queuedInPool {
			a.queuedRuns.CompareAndDelete(jobID, queued)
		}
		if errors.Is(context.Cause(waitCtx), ErrQueuedRunCanceled) {
			return model.Scan{}, nil, ErrQueuedRunCanceled
		}
		return model.Scan{}, nil, slotErr
	}
	if queuedInPool {
		defer a.queuedRuns.CompareAndDelete(jobID, queued)
	}
	defer releaseSlot()
	if !queued.start() {
		// The cancellation arrived as the slot was granted.
		return model.Scan{}, nil, ErrQueuedRunCanceled
	}
	ts, system := a.Store.Tenant(scope), a.Store.System()
	var queuedErr error
	if job, revision, queuedErr = a.queuedManagedJob(ctx, ts, job, jobID, revision, manual); queuedErr != nil {
		return model.Scan{}, nil, queuedErr
	}
	estimate, err := config.EstimateJobWork(job)
	if err != nil {
		return model.Scan{}, nil, err
	}
	// The run reads its tenant's probe budget once. The estimate, the
	// resolved plan and the direct scanner's own check all use it; the
	// resumable path checks each attempt against the current budget.
	budget, err := a.tenantProbeBudget(ctx, ts)
	if err != nil {
		return model.Scan{}, nil, err
	}
	if err := checkEstimatedProbeBudget(budget, job, estimate); err != nil {
		return model.Scan{}, nil, err
	}
	if !manual {
		if cycle, cycleErr := ts.GetActiveScanCycle(ctx, jobID); cycleErr == nil && cycle.Status == "stalled" && !cycleResumeWindowElapsed(cycle, time.Now().UTC()) {
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
	leaseKey := jobID
	leaseOwner := scan.ID
	if daemonOwner := a.currentDaemonOwner(); daemonOwner != "" {
		leaseOwner = "daemon/" + daemonOwner + "/" + scan.ID
	}
	// The lease also refuses a job whose tenant is not active, so a paused
	// tenant starts no scan, whether scheduled or manual.
	if err := system.AcquireJobLeaseForRevision(ctx, leaseKey, leaseOwner, revision, started.Add(job.Timeout.Value()+time.Minute)); err != nil {
		if errors.Is(err, store.ErrJobBusy) {
			return model.Scan{}, nil, scanner.ErrBusy
		}
		return model.Scan{}, nil, err
	}
	leaseReleased := false
	scanCtx, cancel := context.WithTimeout(ctx, job.Timeout.Value())
	run := &activeRun{scan: model.ActiveScan{ID: scan.ID, JobID: jobID, Job: job.Name, JobRevision: revision, StartedAt: started, EstimatedProbes: estimate.Probes, NmapInvocations: estimate.NmapInvocations, EstimatedSeconds: estimate.EstimatedSeconds, TotalProbes: estimate.Probes, TotalInvocations: estimate.NmapInvocations, Phase: "starting", Scanner: engineName, ScannerProfileID: profileID, ScannerProfileRevision: profileRevision}, cancel: cancel}
	a.registerRun(scope.ID(), scan.ID, run)
	// The active entry is now visible, so remove the queue marker only after
	// the queued-to-running handoff is observable through ActiveScans.
	a.queuedRuns.Delete(jobID)
	defer func() {
		cancel()
		a.running.Delete(scan.ID)
	}()
	// Legacy nil selections are frozen at scan start as well as when they are
	// persisted. This closes the race where a new endpoint is added while an
	// older scan is running: that scan must not deliver its completion events to
	// an endpoint that did not exist when the scan began. Stable selectors are
	// resolved again at finalization so managed credential rotations still use
	// the current revision. Both follow the destinations of the job's tenant,
	// so a nil selection never reaches another tenant's destinations.
	var legacyNotificationSelection []string
	legacySelectionCaptured := false
	if job.NotificationDestinations == nil {
		if selection, selectionErr := a.Notifier.Tenant(ts).LegacySelection(ctx); selectionErr != nil {
			a.Logger.Warn("legacy notification selection snapshot failed", "job", job.Name, "error", selectionErr)
		} else {
			legacyNotificationSelection = selection
			legacySelectionCaptured = true
		}
	}
	var scanErr error
	completionEvent := model.Event{Type: "scan.completed", JobID: jobID, Job: job.Name, ScanID: scan.ID}
	completionPublished := false
	lifecycleExitMessage := ""
	publishCompletion := func(message string) {
		if completionPublished {
			return
		}
		completionPublished = true
		if !publishLifecycleCompletion {
			return
		}
		completionEvent.Message = message
		completionEvent.CreatedAt = scan.FinishedAt
		if completionEvent.CreatedAt.IsZero() {
			completionEvent.CreatedAt = time.Now().UTC()
		}
		a.emitTenantEvents(scope, []model.Event{completionEvent})
	}
	// Publish lifecycle updates to the web console without persisting them as
	// alert events. This keeps SSE subscribers responsive even when a scan has
	// no baseline or incident event to emit.
	a.emitTenantEvents(scope, []model.Event{{Type: "scan.started", JobID: jobID, Job: job.Name, ScanID: scan.ID, Message: "Scan started", CreatedAt: started}})
	defer func() {
		if completionPublished {
			return
		}
		if lifecycleExitMessage == "" {
			switch {
			case errors.Is(scanErr, ErrScanCycleStalled):
				lifecycleExitMessage = "Scan attempt stopped because its resumable cycle is stalled"
			case scanErr != nil:
				lifecycleExitMessage = "Scan attempt stopped before finalization"
			default:
				lifecycleExitMessage = "Scan attempt ended before finalization"
			}
		}
		publishCompletion(lifecycleExitMessage)
	}()
	defer func() {
		if leaseReleased {
			return
		}
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), scanPersistenceWriterWaitTimeout)
		defer releaseCancel()
		if err := system.ReleaseJobLease(releaseCtx, leaseKey, leaseOwner); err != nil && a.Logger != nil {
			a.Logger.Warn("scan lease fallback release failed", "job", job.Name, "scan_id", scan.ID, "error", err)
		}
	}()
	var snapshot model.Snapshot
	resumableRun := false
	// The scanner planner owns both ordinary Nmap units and Naabu pipeline
	// batches. Naabu units checkpoint a pinned address batch after discovery and
	// enrichment, so a paused cycle can resume without replaying completed
	// batches or bypassing the discovery phase.
	if resumableScanner, ok := a.Scanner.(scanner.ResumableScanner); ok {
		var handled bool
		handled, snapshot, scanErr = a.runResumableAttempt(ctx, scanCtx, ts, job, jobID, &scan, run, resumableScanner, manual)
		resumableRun = handled
		if errors.Is(scanErr, ErrScanCycleStalled) {
			// A scheduled trigger that races with a newly stalled cycle must
			// not create a synthetic failed scan or notification. The cycle's
			// original stall attempt already recorded the actionable alert.
			lifecycleExitMessage = "Scan attempt stopped because its resumable cycle became stalled"
			return model.Scan{}, nil, scanErr
		}
	}
	if !resumableRun {
		if scanErr == nil {
			// The direct scanner path resolves DNS again. A budgeted scanner
			// checks the work of that resolution before it starts, so a DNS
			// answer that grew since the plan cannot bypass the probe budget.
			if budgetedScanner, ok := a.Scanner.(BudgetedProgressScanner); ok {
				snapshot, scanErr = budgetedScanner.ScanWithProgressBudget(scanCtx, job, func(progress scanner.Progress) {
					a.updateActiveProgress(scan.ID, progress)
				}, func(discoveryProbes, nmapProbes int64) error {
					return checkResolvedProbeBudget(budget, job, discoveryProbes, nmapProbes)
				})
			} else if progressScanner, ok := a.Scanner.(ProgressScanner); ok {
				snapshot, scanErr = progressScanner.ScanWithProgress(scanCtx, job, func(progress scanner.Progress) {
					a.updateActiveProgress(scan.ID, progress)
				})
			} else {
				snapshot, scanErr = a.Scanner.Scan(scanCtx, job)
			}
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
				if run.interruptedByShutdown(ctx, scanCtx) {
					scan.Error = ScanInterruptedMessage
					scan.Interrupted = true
				}
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
	if scanErr == nil {
		// Preserve reachable evidence from a partial discovery pass while making
		// the terminal result explicit. The engine will compare only complete
		// target scopes and will not advance a baseline from this scan.
		engine.MarkIncompleteScan(&scan)
	}
	a.beginActiveFinalization(scan.ID)
	persistTimeout := scanPersistenceTimeout(len(scan.Snapshot.Hosts))
	if a.persistenceBudget != nil {
		persistTimeout = a.persistenceBudget(len(scan.Snapshot.Hosts))
	}
	if a.Logger != nil {
		a.Logger.Debug("persisting scan result", "scan_id", scan.ID, "hosts", len(scan.Snapshot.Hosts), "timeout", persistTimeout)
	}
	// The result is persisted even when the run was canceled, so the
	// persistence context keeps ctx's values but not its cancellation.
	persistCtx := context.WithoutCancel(ctx)
	destinationCtx, destinationCancel := context.WithTimeout(persistCtx, scanPersistenceWriterWaitTimeout)
	var destinations []string
	var destinationErr error
	notifier := a.Notifier.Tenant(ts)
	if legacySelectionCaptured {
		destinations, destinationErr = notifier.QueueDestinationsForSelection(destinationCtx, legacyNotificationSelection)
	} else {
		destinations, destinationErr = notifier.QueueDestinationsForJob(destinationCtx, job)
	}
	destinationCancel()
	if destinationErr != nil {
		// Preserve the completed scan even when notification configuration
		// cannot be read. Runtime state is deliberately left unchanged,
		// matching the pre-transaction behavior, so the scan is recorded as
		// not compared.
		scan.Comparison = model.ScanComparisonNotCompared
		saveCtx, saveCancel := context.WithTimeout(persistCtx, scanPersistenceWriterWaitTimeout+persistTimeout)
		defer saveCancel()
		if saveErr := system.SaveScan(saveCtx, scan); saveErr != nil {
			lifecycleExitMessage = "Scan attempt could not be finalized because its result could not be saved"
			return scan, nil, saveErr
		}
		lifecycleExitMessage = "Scan attempt could not be finalized because notification destinations were unavailable"
		return scan, nil, destinationErr
	}
	// Renew and release the lease inside the finalization transaction. Its
	// writer wait has a separate bound; the size-based work deadline begins only
	// after SQLite grants this transaction the writer lock.
	finalizeOptions := store.ManagedScanFinalizationOptions{
		WriterWaitTimeout: scanPersistenceWriterWaitTimeout,
		WorkTimeout:       persistTimeout,
		LeaseOwner:        leaseOwner,
		LeaseUntil:        time.Now().UTC().Add(scanPersistenceWriterWaitTimeout + persistTimeout + time.Minute),
	}
	events, finalizeErr := a.Engine.FinalizeManagedScanWithOptions(persistCtx, jobID, job, &scan, destinations, finalizeOptions)
	if errors.Is(finalizeErr, store.ErrJobRevisionChanged) {
		// Keep the scan in immutable history, but do not let a result from a
		// superseded security scope seed or mutate the current baseline. A
		// lifecycle-only revision retains the same hash and is still accepted.
		a.Logger.Info("scan completed for superseded security scope; runtime state unchanged", "job", job.Name, "scan_id", scan.ID)
		events, finalizeErr = nil, nil
		leaseReleased = true
	}
	if errors.Is(finalizeErr, store.ErrTenantNotActive) {
		// The job's business unit was paused while the scan ran, whether this
		// process cancelled the scan or another one, such as a host command,
		// ran it. The store recorded the scan as the pause cancelled it and
		// changed no baseline, incident or alert, so there are no events.
		leaseReleased = true
		a.Logger.Info("scan finished after its business unit was paused; runtime state unchanged", "job", job.Name, "scan_id", scan.ID, "status", scan.Status)
		publishCompletion("Scan " + scan.Status)
		return scan, nil, errors.Join(finalizeErr, scanErr)
	}
	if errors.Is(finalizeErr, store.ErrCycleNotResumable) {
		// The store retained this result as immutable history but deliberately
		// skipped runtime comparison because the cycle was discarded or expired.
		leaseReleased = true
		publishCompletion("Scan " + scan.Status)
		return scan, nil, finalizeErr
	}
	if finalizeErr != nil {
		if a.Logger != nil {
			a.Logger.Error("scan result finalization failed", "job", job.Name, "scan_id", scan.ID, "error", finalizeErr)
		}
		failureScan := scan
		failureScan.Status = "failed"
		failureScan.Error = "scan result could not be finalized; inspect the EdgeWatch server log"
		failureScan.Snapshot = model.Snapshot{
			Scopes:         append([]model.Scope(nil), scan.Snapshot.Scopes...),
			TargetFailures: append([]model.TargetCoverageFailure(nil), scan.Snapshot.TargetFailures...),
		}
		failureScan.Changes = nil
		failureOptions := finalizeOptions
		if failureOptions.WorkTimeout < scanPersistenceTimeoutFloor {
			failureOptions.WorkTimeout = scanPersistenceTimeoutFloor
		}
		failureOptions.LeaseUntil = time.Now().UTC().Add(scanPersistenceWriterWaitTimeout + persistTimeout + time.Minute)
		failureEvents, failureErr := a.Engine.FinalizeManagedScanWithOptions(persistCtx, jobID, job, &failureScan, destinations, failureOptions)
		scan = failureScan
		if failureErr == nil {
			leaseReleased = true
			events = failureEvents
			a.emitTenantEvents(scope, events)
			a.wakeDelivery()
		} else if a.Logger != nil {
			a.Logger.Error("failed to persist scan finalization failure", "job", job.Name, "scan_id", scan.ID, "error", failureErr)
		}
		lifecycleExitMessage = "Scan failed because its result could not be finalized"
		publishCompletion(lifecycleExitMessage)
		return scan, events, errors.Join(finalizeErr, failureErr)
	}
	leaseReleased = true
	a.emitTenantEvents(scope, events)
	publishCompletion("Scan " + scan.Status)
	a.wakeDelivery()
	if scanErr != nil {
		return scan, events, scanErr
	}
	return scan, events, nil
}

// ActiveScans returns a stable snapshot of the scans of the tenant of scope
// that are currently executing. A scan only enters this set after its
// database lease is acquired, so a queued or rejected request is not
// reported as running. Another tenant's scans are never listed, and a scope
// without a tenant lists none.
func (a *App) ActiveScans(scope store.TenantScope) []model.ActiveScan {
	var scans []model.ActiveScan
	a.running.Range(func(_, value any) bool {
		if run, ok := value.(*activeRun); ok && run.inTenant(scope) {
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

// QueuedRuns returns accepted runs that have not yet registered as active
// scans. Results are isolated to the tenant scope and sorted by acceptance
// time so callers can present a stable queue.
func (a *App) QueuedRuns(scope store.TenantScope) []model.QueuedRun {
	var queued []model.QueuedRun
	a.queuedRuns.Range(func(_, value any) bool {
		if entry, ok := value.(*queuedRun); ok && entry.run.TenantID == scope.ID() {
			queued = append(queued, entry.run)
		}
		return true
	})
	sort.Slice(queued, func(i, j int) bool {
		if queued[i].QueuedAt.Equal(queued[j].QueuedAt) {
			return queued[i].JobID < queued[j].JobID
		}
		return queued[i].QueuedAt.Before(queued[j].QueuedAt)
	})
	return queued
}

// CancelQueuedRun ends the wait of the job's run that is queued for a scan
// slot in the tenant of scope. The run then never starts and is reported as
// skipped. A job of another tenant, or one without a queued run, is
// ErrRunNotQueued, exactly as a run that has already taken its slot.
func (a *App) CancelQueuedRun(scope store.TenantScope, jobID string) error {
	value, ok := a.queuedRuns.Load(jobID)
	if !ok {
		return ErrRunNotQueued
	}
	entry, ok := value.(*queuedRun)
	if !ok || !scope.Valid() || entry.run.TenantID != scope.ID() {
		return ErrRunNotQueued
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.started {
		return ErrRunNotQueued
	}
	entry.canceled = true
	entry.cancel(ErrQueuedRunCanceled)
	return nil
}

// CancelScan requests cancellation of an active scan of the tenant of scope.
// The scanner owns the process context and will persist a canceled terminal
// record without mutating baseline or incident state. Another tenant's scan
// is store.ErrNotFound, exactly as an unknown one, and keeps running.
func (a *App) CancelScan(scope store.TenantScope, id string) error {
	value, ok := a.running.Load(id)
	if !ok {
		return store.ErrNotFound
	}
	run, ok := value.(*activeRun)
	if !ok || !run.inTenant(scope) {
		return store.ErrNotFound
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.cancel == nil {
		return store.ErrNotFound
	}
	if run.finalizing {
		return ErrScanFinalizing
	}
	run.requestCancelLocked()
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
	if progress.TotalProbes > run.scan.TotalProbes {
		run.scan.TotalProbes = progress.TotalProbes
	}
	if progress.TotalInvocations > run.scan.TotalInvocations {
		run.scan.TotalInvocations = progress.TotalInvocations
	}
	// Discovery, enrichment, and UDP can publish different totals as work is
	// discovered. Keep the persisted operator-facing counters monotonic even
	// when a later phase reports a local (or newly-expanded) zero-based value.
	// A scan may still increase its total after this point; the percentage is a
	// high-water mark so the progress bar never jumps backwards on a phase
	// transition.
	if progress.CompletedProbes > run.scan.CompletedProbes {
		run.scan.CompletedProbes = progress.CompletedProbes
	}
	if progress.CompletedInvocations > run.scan.CompletedInvocations {
		run.scan.CompletedInvocations = progress.CompletedInvocations
	}
	percentProgress := scanner.Progress{
		CompletedProbes:      run.scan.CompletedProbes,
		TotalProbes:          run.scan.TotalProbes,
		CompletedInvocations: run.scan.CompletedInvocations,
		TotalInvocations:     run.scan.TotalInvocations,
	}
	if percent := progressPercent(percentProgress); percent > run.scan.ProgressPercent {
		run.scan.ProgressPercent = percent
	}
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

// beginActiveFinalization reports the finalizing phase and refuses later
// cancellation requests, which could no longer change the result.
func (a *App) beginActiveFinalization(id string) {
	value, ok := a.running.Load(id)
	if !ok {
		return
	}
	run, ok := value.(*activeRun)
	if !ok {
		return
	}
	run.mu.Lock()
	run.scan.Phase = "finalizing"
	run.scan.ProcessAlive = false
	run.finalizing = true
	run.mu.Unlock()
}

// inTenant reports whether the run belongs to the tenant of scope. A scope
// without a tenant matches no run. registerRun sets the run's tenant before
// the run can be found, and it never changes.
func (r *activeRun) inTenant(scope store.TenantScope) bool {
	return scope.Valid() && r.tenant == scope.ID()
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
	owner := daemonProcessOwner()
	system := a.Store.System()
	if owned {
		defer func() {
			a.StopRun()
			a.clearDaemonOwner(owner)
		}()
	}
	if len(a.Config.Jobs) > 0 {
		a.Logger.Warn("legacy YAML jobs detected; they are inactive in web-managed mode and must be recreated in the console", "jobs", len(a.Config.Jobs))
	}
	reclaimed, err := system.AcquireDaemonLease(ctx, owner)
	if err != nil {
		return err
	}
	a.setDaemonOwner(owner)
	if reclaimed > 0 {
		a.Logger.Info("reclaimed job leases from previous daemon", "leases", reclaimed)
	}
	if released, err := system.ReleaseDeliveryClaims(ctx); err != nil {
		a.Logger.Error("startup notification claim cleanup failed", "error", err)
	} else if released > 0 {
		a.Logger.Info("startup notification claims released", "claims", released)
	}
	if released, err := system.ReclaimExpiredJobLeases(ctx, time.Now().UTC()); err != nil {
		a.Logger.Error("startup job lease cleanup failed", "error", err)
	} else if released > 0 {
		a.Logger.Info("startup expired job leases reclaimed", "leases", released)
	}
	defer func() {
		// Release the daemon lease only after all tracked scans have stopped.
		// Otherwise another process can acquire the lease while an in-flight
		// scan still owns the old daemon's resources and writes state.
		// StopRun is required even when this Daemon call joined an existing
		// application lifecycle. In production runDaemon binds the lifecycle
		// before starting Daemon, so owned is false; waiting on the wait group
		// directly would leave web-triggered scans on the shared run context and
		// could block shutdown forever after a lease or heartbeat failure.
		a.StopRun()
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = system.ReleaseLease(releaseCtx, owner)
	}()
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	cronLogger := cronSlogLogger{logger: a.Logger}
	c := cron.New(cron.WithParser(parser), cron.WithLogger(cronLogger), cron.WithChain(cron.Recover(cronLogger)))
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
	scheduleRetry := time.NewTicker(30 * time.Second)
	updateInterval := a.UpdateInterval
	if updateInterval <= 0 {
		updateInterval = updatecheck.CheckInterval
	}
	updates := time.NewTicker(updateInterval)
	defer heartbeat.Stop()
	defer scheduleRetry.Stop()
	defer updates.Stop()
	workerCtx, workerCancel := context.WithCancel(ctx)
	deliveryDone := a.startDeliveryWorker(workerCtx)
	purgeDone := a.startUnitPurgeWorker(workerCtx)
	maintenanceDone := a.startMaintenanceWorker(workerCtx, system)
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
		<-purgeDone
		<-maintenanceDone
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if released, err := system.ReleaseDeliveryClaims(releaseCtx); err != nil {
			a.Logger.Error("shutdown notification claim cleanup failed", "error", err)
		} else if released > 0 {
			a.Logger.Info("shutdown notification claims released", "claims", released)
		}
	}()
	a.wakeDelivery()
	// Check managed jobs once during startup as well as on each heartbeat. This
	// surfaces a daemon that came back after a missed schedule without waiting
	// for the next cron tick.
	a.checkJobSilence(ctx, a.nowUTC())
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
			if err := system.Heartbeat(ctx, owner); err != nil {
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
			a.checkJobSilenceBounded(ctx, a.nowUTC())
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

// updateAlertRoutes resolves where an update alert goes. The update check is
// platform-wide, and its alert is fanned out: the platform's copy follows
// the platform's update routing to platform destinations, and each active
// tenant's copy follows that tenant's update routing to its own
// destinations. A tenant whose routing cannot be resolved still gets its
// copy, without destinations, as the platform's copy does when the platform
// routing cannot be read. The platform's route comes first. When the active
// tenants cannot be listed, it returns an error instead: the caller then
// leaves the alert unannounced, so that the next update check records every
// copy, because an alert announced with the platform's copy alone would
// never reach the tenants.
func (a *App) updateAlertRoutes(ctx context.Context) ([]store.UpdateAlertRoute, error) {
	if a.Store == nil {
		return nil, nil
	}
	logger := a.Logger
	if logger == nil {
		logger = slog.Default()
	}
	platform := store.UpdateAlertRoute{}
	if a.Notifier != nil {
		if state, err := a.Store.Platform().GetApplicationUpdateState(ctx); err != nil {
			logger.Warn("platform update notification routing unavailable", "error", err)
		} else if platform.Destinations, err = a.Notifier.PlatformUpdateDestinations(ctx, state.UpdateNotificationDestinations); err != nil {
			logger.Warn("platform update notification destinations unavailable", "error", err)
		}
	}
	scopes, err := a.Store.System().ActiveTenantScopes(ctx)
	if err != nil {
		return nil, fmt.Errorf("business units unavailable for the update alert: %w", err)
	}
	routes := []store.UpdateAlertRoute{platform}
	for _, scope := range scopes {
		route := store.UpdateAlertRoute{TenantID: scope.ID()}
		route.Destinations = a.tenantUpdateDestinations(ctx, logger, a.Store.Tenant(scope))
		routes = append(routes, route)
	}
	return routes, nil
}

// tenantUpdateDestinations resolves a tenant's update routing to the queue
// keys of its destinations, or nil when it cannot.
func (a *App) tenantUpdateDestinations(ctx context.Context, logger *slog.Logger, ts *store.TenantStore) []string {
	if a.Notifier == nil {
		return nil
	}
	routing, err := ts.ApplicationUpdateRouting(ctx)
	if err != nil {
		logger.Warn("application update notification routing unavailable", "error", err)
		return nil
	}
	// Routing that was never configured has nil destinations, which keeps the
	// original behavior of sending update events to every enabled destination
	// of the tenant until an administrator saves a selection. A saved empty
	// selection silences them, and a new business unit starts with one, so
	// it gets no update alerts until its administrators select destinations.
	destinations, err := a.Notifier.Tenant(ts).QueueDestinationsForSelection(ctx, routing.Destinations)
	if err != nil {
		logger.Warn("application update notification destinations unavailable", "error", err)
		return nil
	}
	return destinations
}

// emitUpdateAlert publishes every copy of an update alert that the store
// recorded as a live update. The platform's copy has no tenant and reaches
// the platform's streams; each business unit's copy names its unit and
// reaches only that unit's streams, so each console sees its own copy once.
func (a *App) emitUpdateAlert(events []model.Event) {
	a.emitEvents(events)
	a.wakeDelivery()
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
		state, err := a.Store.Platform().GetApplicationUpdateState(ctx)
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
			var routes []store.UpdateAlertRoute
			var routesErr error
			if notifyUpgrade {
				routes, routesErr = a.updateAlertRoutes(ctx)
			}
			if routesErr != nil {
				// Keep the previous installed version, so the next check
				// still sees the upgrade and records every copy of its alert.
				logger.Warn("application upgrade alert postponed to the next update check", "error", routesErr)
			} else if events, recordErr := a.Store.Platform().RecordInstalledVersion(ctx, current, releaseURL, notifyUpgrade, routes); recordErr != nil {
				logger.Warn("application version state update failed", "error", recordErr)
			} else if len(events) > 0 {
				a.emitUpdateAlert(events)
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
	state, err := a.Store.Platform().GetApplicationUpdateState(ctx)
	if err != nil {
		logger.Warn("application release state unavailable", "error", err)
		return
	}
	result, checkErr := checker.Check(ctx, state.ETag)
	if checkErr != nil {
		if err := a.Store.Platform().RecordReleaseCheckFailure(ctx, checkErr.Error()); err != nil {
			logger.Warn("application release failure state could not be saved", "error", err)
		}
		logger.Warn("application release check failed", "error", checkErr)
		a.emitUpdateStatus()
		return
	}
	if result.NotModified {
		if err := a.Store.Platform().RecordReleaseNotModified(ctx, result.ETag); err != nil {
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
	var routes []store.UpdateAlertRoute
	announce, etag := newer, result.ETag
	if newer {
		var routesErr error
		if routes, routesErr = a.updateAlertRoutes(ctx); routesErr != nil {
			// Store the release unannounced and without its ETag, so the next
			// check gets the release again instead of NotModified and records
			// every copy of its alert.
			logger.Warn("application update alert postponed to the next update check", "error", routesErr)
			announce, etag = false, ""
		}
	}
	events, recordErr := a.Store.Platform().RecordReleaseCheck(ctx, current, release.Version, release.URL, release.Name, release.PublishedAt, etag, announce, routes)
	if recordErr != nil {
		logger.Warn("application release state update failed", "error", recordErr)
		return
	}
	if len(events) > 0 {
		a.emitUpdateAlert(events)
	}
	a.emitUpdateStatus()
}

// startManagedScheduled starts a scheduled run of the job with the given ID
// in the tenant of scope.
func (a *App) startManagedScheduled(ctx context.Context, scope store.TenantScope, id string) {
	a.startTracked(func() {
		record, err := a.Store.Tenant(scope).GetJob(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				a.Logger.Warn("scheduled job no longer exists", "job_id", id)
			} else {
				a.Logger.Error("scheduled job lookup failed", "job_id", id, "error", err)
			}
			return
		}
		if record.Archived || !record.Enabled {
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
		if errors.Is(runErr, ErrQueuedRunSkipped) || errors.Is(runErr, ErrQueuedRunCanceled) {
			a.Logger.Info("scheduled run skipped", "job", record.Job.Name, "reason", runErr)
			return
		}
		if errors.Is(runErr, store.ErrTenantNotActive) {
			// The tenant was paused after the schedule was reconciled. The next
			// reconciliation removes its jobs until the tenant is active again.
			a.Logger.Info("scheduled run skipped because the job's tenant is not active", "job", record.Job.Name)
			return
		}
		var budgetErr *ScanWorkBudgetError
		if scan.ID == "" && errors.As(runErr, &budgetErr) {
			a.recordScheduledBudgetSkip(ctx, scope, record, budgetErr)
			return
		}
		if runErr != nil {
			a.Logger.Error("scan failed", "job", record.Job.Name, "scan_id", scan.ID, "error", runErr)
			return
		}
		a.Logger.Info("scan complete", "job", record.Job.Name, "scan_id", scan.ID, "events", len(events))
	})
}

// recordScheduledBudgetSkip reports a scheduled run that its probe budget
// stopped before a scan record existed. A manual run reports the refusal to
// the person who started it; nobody sees a scheduled one, so it becomes an
// activity event delivered to the job's destinations. It is reported once for
// each scope and budget, until a scan of the job runs again.
func (a *App) recordScheduledBudgetSkip(ctx context.Context, scope store.TenantScope, record store.JobRecord, budgetErr *ScanWorkBudgetError) {
	a.Logger.Warn("scheduled run skipped because it exceeds the probe budget", "job", record.Job.Name, "estimated_probes", budgetErr.Estimate.Probes, "budget", budgetErr.Budget)
	var destinations []string
	if a.Notifier != nil {
		var err error
		destinations, err = a.Notifier.Tenant(a.Store.Tenant(scope)).QueueDestinationsForJob(ctx, record.Job)
		if err != nil {
			// Like the silence watchdog, record nothing rather than an alert
			// without its deliveries; the next scheduled run tries again.
			a.Logger.Warn("budget skip notification destinations unavailable", "job", record.Job.Name, "error", err)
			return
		}
	}
	hash := record.Job.SecurityHash()
	key := fmt.Sprintf("%s|%d", hash, budgetErr.Budget)
	message := fmt.Sprintf("Scheduled scan skipped: about %d probes exceed the probe budget of %d. An administrator must approve high-cost scans for this job, or its scope must be reduced.", budgetErr.Estimate.Probes, budgetErr.Budget)
	if record.Job.AllowHighCost {
		message = fmt.Sprintf("Scheduled scan skipped: about %d probes exceed the high-cost limit of %d. Reduce the job's scope.", budgetErr.Estimate.Probes, budgetErr.Budget)
	}
	events, err := a.Store.System().UpdateRuntimeForScanWithOutbox(ctx, record.ID, hash, destinations, func(state *model.JobState) ([]model.Event, error) {
		if state.BudgetSkipAlertKey == key {
			return nil, nil
		}
		state.BudgetSkipAlertKey = key
		return []model.Event{{Type: model.EventScanBudgetExceeded, JobID: record.ID, Job: record.Job.Name, Message: message, CreatedAt: time.Now().UTC()}}, nil
	})
	if err != nil {
		a.Logger.Warn("budget skip could not be recorded", "job", record.Job.Name, "error", err)
		return
	}
	if len(events) > 0 {
		a.emitTenantEvents(scope, events)
		a.wakeDelivery()
	}
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
		defer a.recoverBackgroundPanic("scheduled-run")
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

// emitTenantEvents publishes the events of a tenant's work, such as a scan
// of one of its jobs, as live updates for that tenant only. Each event is
// tagged with the tenant, because a job's event always belongs to the job's
// tenant. The caller's events are not changed.
func (a *App) emitTenantEvents(scope store.TenantScope, events []model.Event) {
	tagged := make([]model.Event, len(events))
	for i, event := range events {
		event.TenantID = scope.ID()
		tagged[i] = event
	}
	a.emitEvents(tagged)
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
	// Reload the tenants' slot caps first, so a job that runs on start
	// already queues under them. A failed read keeps the caps in place.
	if err := a.refreshSlotCaps(ctx); err != nil && a.Logger != nil {
		a.Logger.Warn("tenant slot caps could not be refreshed", "error", err)
	}
	// Every active tenant's jobs are scheduled. A paused tenant's jobs are
	// left out, so their entries are removed below and return when the
	// tenant is active again. Job IDs are unique across tenants.
	scopes, err := a.Store.System().ActiveTenantScopes(ctx)
	if err != nil {
		return err
	}
	desired := map[string]store.JobRecord{}
	desiredScopes := map[string]store.TenantScope{}
	for _, scope := range scopes {
		jobs, err := a.Store.Tenant(scope).ListJobs(ctx, true)
		if err != nil {
			return err
		}
		for _, record := range jobs {
			if !record.Archived && record.Enabled {
				desired[record.ID] = record
				desiredScopes[record.ID] = scope
			}
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
		jobID, scope := id, desiredScopes[id]
		entry, err := c.AddFunc(spec, func() { a.startManagedScheduled(ctx, scope, jobID) })
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
		a.startManagedScheduled(ctx, desiredScopes[id], id)
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

// deliveryPassWindow bounds how long one delivery pass claims and dispatches
// notifications. Sends that have already started are not bounded by it.
const deliveryPassWindow = 90 * time.Second

func (a *App) startDeliveryWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer a.recoverBackgroundPanic("notification-delivery-worker")
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		drain := func() {
			defer a.recoverBackgroundPanic("notification-delivery")
			// The pass window only stops the pass from claiming and dispatching
			// more deliveries, so a provider outage cannot monopolize the worker;
			// the next wake or tick drains the rest. A send that has already
			// started finishes under the daemon context and its own provider
			// timeout, so a slow but healthy provider is never killed by the
			// window and charged an indeterminate 30-minute deferral. Shutdown
			// still cancels in-flight sends.
			if err := a.Notifier.DrainWithin(ctx, deliveryPassWindow); err != nil && !errors.Is(err, context.Canceled) {
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

func hostname() string {
	v, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return v
}

func JSON(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }
