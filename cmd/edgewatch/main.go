package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/sandbox"
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
	// Every EdgeWatch process can hold a key, a destination URL, or scan
	// data, so none dumps core and none can be read by a debugger of its own
	// identity.
	if err := sandbox.HardenProcess(); err != nil {
		fmt.Fprintln(os.Stderr, "edgewatch: warning:", err)
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "edgewatch:", err)
		os.Exit(exitStatus(err))
	}
}

// exitStatus is the exit status of a command that failed with err. The
// notification child reports the class of a failed send with its status;
// every other failure exits with 1.
func exitStatus(err error) int {
	var childErr *notify.ChildExitError
	if errors.As(err, &childErr) {
		return childErr.ExitCode()
	}
	return 1
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	// Scanner processes restricted with Landlock start through this hidden
	// command. Its arguments are the scanner's, so it bypasses flag parsing.
	if args[0] == sandbox.ExecCommand {
		return sandbox.Exec(args[1:])
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Println(usageText)
		return nil
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
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	configPath := fs.String("config", "/etc/edgewatch/config.yaml", "configuration file")
	output := fs.String("output", "text", "text or json")
	outPath := fs.String("out", "", "output file for backup or baseline export")
	fromPath := fs.String("from", "", "source database file for restore")
	allowSidecarReplay := fs.Bool("allow-sidecar-replay", false, "allow existing SQLite sidecars during an intentional crash-recovery restore")
	allowActiveDaemon := fs.Bool("allow-active-daemon", false, "allow restore when the destination daemon heartbeat is still active (emergency recovery only)")
	allowUnreadableDestination := fs.Bool("allow-unreadable-destination", false, "allow restore over a destination that cannot be inspected after EdgeWatch has been stopped")
	pendingDeliveries := fs.String("pending-deliveries", string(store.PendingDeliveriesQuarantine), "restore pending notification policy: quarantine, discard, or preserve")
	dryRun := fs.Bool("dry-run", false, "inspect a restore without replacing the destination")
	jobName := fs.String("job", "", "job name")
	scanID := fs.String("scan-id", "", "scan ID")
	limit := fs.Int("limit", 50, "history limit")
	nmapPath := fs.String("nmap", "/usr/bin/nmap", "Nmap executable (fixed runtime binary; override only for local tests)")
	passwordFile := fs.String("password-file", "", "file containing a new administrator password")
	username := fs.String("username", "admin", "username for administrator recovery actions")
	force := fs.Bool("force", false, "confirm replacement of the current setup token")
	tenantFlag := fs.String("tenant", "", "slug of the business unit a host command acts on")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printCommandHelp(os.Stdout, fs, cmd, action)
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q; flags must precede operands", fs.Arg(0))
	}
	tenantSlug, err := checkTenantFlag(fs, cmd, action, *tenantFlag)
	if err != nil {
		return err
	}
	if err := validateCommandFlags(fs, cmd, action); err != nil {
		return err
	}
	if cmd == "history" && (*limit < 1 || *limit > 1000) {
		return errors.New("--limit must be between 1 and 1000")
	}
	if cmd == "version" {
		fmt.Println("EdgeWatch", version)
		return nil
	}
	if cmd == "notify-send" {
		return notify.RunSendChild(os.Stdin)
	}
	if cmd == "notify-check" {
		return notify.CheckChildTrust()
	}
	if cmd == "config" {
		if action != "validate" {
			return errors.New("expected: config validate")
		}
		return validateConfig(*configPath, *output)
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
	if cmd == "daemon" {
		// Refuse an unusable key file or notification URL before the
		// database is opened, so a refused start never migrates it.
		if err := validateStartupConfig(cfg); err != nil {
			return err
		}
	}
	// The daemon and the scan command start scanner processes. A required
	// sandbox refuses them, before the database is opened, when the runtime
	// cannot confine those processes.
	var scannerSandbox *sandbox.Policy
	if cmd == "daemon" || cmd == "scan" {
		scannerSandbox = sandbox.Detect(scannerSandboxOptions(cfg, *nmapPath))
		if err := scannerSandbox.Require(); err != nil {
			return err
		}
	}
	// The daemon and the notify test command start notification processes,
	// in the same way.
	var notificationSandbox *sandbox.Policy
	if cmd == "daemon" || (cmd == "notify" && action == "test") {
		notificationSandbox = sandbox.Detect(notificationSandboxOptions(cfg))
		if err := notificationSandbox.Require(); err != nil {
			return err
		}
		notify.SetSandbox(notificationSandbox)
	}
	ctx, stop := contextWithSignals(context.Background())
	defer stop()
	if cmd == "restore" {
		if *fromPath == "" {
			return errors.New("--from is required")
		}
		policy, policyErr := store.ParsePendingDeliveryPolicy(*pendingDeliveries)
		if policyErr != nil {
			return policyErr
		}
		if *dryRun && *allowSidecarReplay {
			return errors.New("--allow-sidecar-replay cannot be combined with --dry-run")
		}
		options := store.RestoreOptions{AllowSidecarReplay: *allowSidecarReplay, AllowActiveDaemon: *allowActiveDaemon, AllowUnreadableDestination: *allowUnreadableDestination, PendingDeliveries: policy}
		if *dryRun {
			// The dry run goes through the same refusal checks as the restore
			// below. It prints its report either way and exits non-zero when the
			// restore would be refused, so scripts can rely on the exit status.
			report, refusal := store.DryRunRestore(ctx, *fromPath, cfg.Database, options)
			if err := printValue(*output, report); err != nil {
				return err
			}
			if refusal != nil {
				return fmt.Errorf("restore dry run: %w", refusal)
			}
			return nil
		}
		result, err := store.Restore(ctx, *fromPath, cfg.Database, options)
		if err != nil {
			// Do not open the destination to audit a refused restore: doing so
			// could itself cause SQLite to inspect, checkpoint, or remove the
			// very sidecar that made the restore unsafe.
			return err
		}
		auditHostCommandOnExisting(context.Background(), cfg.Database, store.AuditEntry{Action: "database.restore", Detail: hostAuditDetail("source", *fromPath, err)})
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
	logger := newLoggerTo(commandLogWriter(cmd), cfg.LogLevel(), deploymentLocation(cfg))
	// health, verify, and backup work on the whole database, of the current
	// schema or of an older one, so that a restored older backup can be
	// verified and backed up before the daemon upgrades it. The other
	// commands act on business units or accounts, whose rows the migrations
	// reshape: they refuse a database that the daemon has not upgraded yet.
	var openStore func(string) (*store.Store, error)
	switch {
	case cmd == "health" || cmd == "verify":
		openStore = store.OpenReadOnlyExisting
	case readOnlyCommand:
		openStore = store.OpenReadOnlyExistingUpgraded
	case cmd == "backup":
		openStore = store.OpenExisting
	case cmd == "daemon":
		// The daemon is the sole owner of schema migrations and startup
		// reconciliation. All other commands open the already-migrated database
		// without touching startup_state, avoiding health-signal changes and
		// writer contention while a healthy daemon is running.
		openStore = func(path string) (*store.Store, error) {
			// Refuse before migrating when another daemon's lease is live, so
			// a second daemon never upgrades the schema or rewrites
			// startup_state under a running one. If the lease cannot be read
			// here, startup continues and App.Daemon still refuses to take a
			// live lease after the migration.
			if err := store.CheckDaemonLeaseBeforeStartup(context.Background(), path); err != nil {
				if errors.Is(err, store.ErrDaemonLeaseBusy) {
					return nil, err
				}
				logger.Warn("could not check the daemon lease before migration", "error", err)
			}
			return store.OpenWithLogger(path, logger)
		}
	default:
		openStore = store.OpenExistingUpgraded
	}
	s, err := openStore(cfg.Database)
	if errors.Is(err, store.ErrSchemaUpgradePending) {
		return fmt.Errorf("%w; start the daemon once to upgrade it, then run this command again", err)
	}
	if err != nil {
		return err
	}
	defer s.Close()
	// Install the operator-managed authentication key before any command reads
	// or seals TOTP secrets. The daemon's compatibility migration and the host
	// recovery commands run before app.New, which otherwise applies this path;
	// without it they would use, or auto-create, a default key beside the
	// database that the configured key cannot open. The daemon validated the
	// configured key before it opened the database.
	s.SetAuthKeyPath(cfg.Web.AuthKeyFile)
	if cmd == "daemon" {
		if err := s.MigrateAdminCompatibility(context.Background()); err != nil {
			return fmt.Errorf("migrate administrator compatibility state: %w", err)
		}
	}
	if cmd == "admin" {
		if action == "platform-setup-token" {
			return platformSetupToken(context.Background(), s, *force, os.Stdout)
		}
		options := adminRecoveryOptions{force: *force, out: os.Stdout}
		if tenantSlug != "" {
			unit, _, err := hostUnit(context.Background(), s, tenantSlug)
			if err != nil {
				return err
			}
			options.unit = &unit
		}
		return adminRecovery(context.Background(), action, s, *passwordFile, *username, options)
	}
	// scan, status, history, baseline, and notify test act on the jobs,
	// scans, baselines, and destinations of the business unit that --tenant
	// names, or of the default unit without it, and the unit's state limits
	// them alike either way. The daemon, backup, verify, and health work on
	// the whole database, and admin recovery above works in the unit of the
	// account it changes.
	var unit store.Tenant
	var tenant *store.TenantStore
	if acceptsTenant(cmd, action) {
		if unit, tenant, err = hostUnitStore(context.Background(), s, tenantSlug, cmd, action); err != nil {
			return err
		}
	}
	var application *app.App
	needApplication := cmd == "daemon" || cmd == "scan" || cmd == "notify" || (cmd == "baseline" && action != "export")
	if needApplication {
		// Only the daemon imports notification URLs from config.yaml, after
		// the migrations above and before its notifier and delivery worker
		// start. Host commands keep using the configured URLs until then.
		application, err = app.NewWithOptions(cfg, s, *nmapPath, logger, app.Options{ImportNotificationURLs: cmd == "daemon", Sandbox: scannerSandbox, NotificationSandbox: notificationSandbox})
		if err != nil {
			return err
		}
		application.Version = version
		if scannerSandbox != nil {
			logScannerSandbox(logger, scannerSandbox.Status())
		}
		if notificationSandbox != nil {
			logNotificationSandbox(logger, notificationSandbox.Status())
		}
	}
	switch cmd {
	case "daemon":
		return runDaemon(ctx, application, cfg.Web.Listen, s, logger)
	case "scan":
		if *jobName == "" {
			return errors.New("--job is required")
		}
		record, err := tenant.GetJobByName(ctx, *jobName)
		if err != nil {
			return fmt.Errorf("unknown managed job %q; YAML jobs are inactive and must be recreated in the web console", *jobName)
		}
		scan, events, err := application.RunJobRecord(ctx, record)
		if errors.Is(err, store.ErrTenantNotActive) {
			err = hostScanPausedError(unit, scan, err)
		}
		auditHostCommand(ctx, tenant, store.AuditEntry{Action: "scan.run_requested", Detail: scanAuditDetail(record.ID, scan.Status, err)})
		if printErr := printValue(*output, map[string]any{"scan": scan, "events": events}); printErr != nil {
			return printErr
		}
		return err
	case "status":
		return status(ctx, tenant, unit.State, cfg, *jobName, *output)
	case "history":
		scans, events, err := listHistory(ctx, tenant, *jobName, *limit)
		if err != nil {
			return err
		}
		// Print empty lists, not null, for a unit without history, as the
		// web API does.
		if scans == nil {
			scans = []model.Scan{}
		}
		if events == nil {
			events = []model.Event{}
		}
		return printValue(*output, map[string]any{"scans": scans, "events": events})
	case "baseline":
		if action == "export" {
			// Baseline export is deliberately read-only. Persisting an audit row
			// here would violate the command's no-side-effects contract.
			return exportBaseline(ctx, tenant, *jobName, *outPath, *output)
		}
		return baseline(ctx, action, tenant, application, *jobName, *scanID, *output)
	case "notify":
		if action != "test" {
			return errors.New("expected: notify test")
		}
		// A locked web-managed destination fails the test, so restoring the
		// wrong notification key is not reported as a successful check. The
		// test messages go to the unit's destinations only, but the key is
		// one for the deployment: every unit's and the platform's enabled
		// destinations must open with it, whichever unit --tenant selects.
		summary, err := application.Notifier.Tenant(tenant).TestSummary(ctx)
		deploymentLocked, keyErr := application.Notifier.LockedDestinations(ctx)
		err = errors.Join(err, keyErr)
		auditHostCommand(ctx, tenant, store.AuditEntry{Action: "notifications.test", Detail: hostAuditDetail("operation", "global", err)})
		if printErr := printValue(*output, notifyTestResult{TestSummary: summary, DeploymentLocked: deploymentLocked}); printErr != nil {
			return errors.Join(err, printErr)
		}
		return err
	case "backup":
		if *outPath == "" {
			return errors.New("--out is required")
		}
		err := backup(ctx, s, *outPath, *output)
		auditHostCommand(ctx, s, store.AuditEntry{Action: "database.backup", Detail: hostAuditDetail("output", *outPath, err)})
		return err
	case "verify":
		err := verify(ctx, s, *output)
		return err
	case "health":
		health, err := s.System().HealthStatus(ctx)
		// The sandbox is detected for this container, which grants the
		// health command the daemon's capabilities and configuration.
		scannerSandbox := sandbox.Detect(scannerSandboxOptions(cfg, *nmapPath)).Status()
		notificationSandbox := sandbox.Detect(notificationSandboxOptions(cfg)).Status()
		health.Warnings = append(health.Warnings, scannerSandboxWarnings(scannerSandbox)...)
		health.Warnings = append(health.Warnings, notificationSandboxWarnings(notificationSandbox)...)
		if err != nil {
			if *output == "json" {
				// Keep stdout parseable for monitoring: report the failure
				// as a document, then exit non-zero with the reason on stderr.
				if printErr := printValue(*output, unhealthyStatus{HealthStatus: health, ScannerSandbox: scannerSandbox, NotificationSandbox: notificationSandbox, Status: "unhealthy", Error: err.Error()}); printErr != nil {
					return printErr
				}
			}
			return err
		}
		return printValue(*output, healthReport{HealthStatus: health, ScannerSandbox: scannerSandbox, NotificationSandbox: notificationSandbox})
	default:
		return usage()
	}
}

const usageText = `Usage: edgewatch <command> [options]
Commands: daemon, config validate, scan, status, history, baseline approve|reset|export, backup, restore, verify, notify test, admin setup-token|reissue-setup-token|platform-setup-token|reset-password|disable-totp, health, version, help
Run edgewatch <command> --help for the options of one command.
Admin recovery actions accept --username (default admin) and require host access.
scan, status, history, baseline, and notify test accept --tenant SLUG to act on that business unit instead of the default one, and admin reset-password and disable-totp accept it to stop unless the account belongs to that unit.`

// usage reports a missing or unknown command on stderr.
func usage() error {
	fmt.Fprintln(os.Stderr, usageText)
	return errors.New("invalid or missing command")
}

// printCommandHelp lists the options that the command accepts, with their
// defaults, in the order of the shared flag set.
func printCommandHelp(w io.Writer, fs *flag.FlagSet, cmd, action string) {
	key := commandFlagKey(cmd, action)
	allowed, known := commandFlagAllowlist[key]
	if !known {
		fmt.Fprintln(w, usageText)
		return
	}
	fmt.Fprintf(w, "Usage: edgewatch %s [options]\n", key)
	if len(allowed) == 0 {
		fmt.Fprintln(w, "This command has no options.")
		return
	}
	fmt.Fprintln(w, "Options:")
	fs.VisitAll(func(f *flag.Flag) {
		if _, ok := allowed[f.Name]; !ok {
			return
		}
		line := fmt.Sprintf("  --%s\t%s", f.Name, f.Usage)
		if f.DefValue != "" && f.DefValue != "false" {
			line += fmt.Sprintf(" (default %s)", f.DefValue)
		}
		fmt.Fprintln(w, line)
	})
}

func newLogger(level string, location *time.Location) *slog.Logger {
	return newLoggerTo(os.Stdout, level, location)
}

// commandLogWriter keeps the daemon's structured log on stdout, where
// container runtimes collect it. Every other command prints its result on
// stdout, so its log goes to stderr and --output json stays one document.
func commandLogWriter(cmd string) io.Writer {
	if cmd == "daemon" {
		return os.Stdout
	}
	return os.Stderr
}

// newLoggerTo builds the structured JSON logger. A configured deployment
// timezone rewrites the record timestamp so daemon logs follow config.yaml
// instead of the process timezone, which is UTC in the container image.
func newLoggerTo(w io.Writer, level string, location *time.Location) *slog.Logger {
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
	options := &slog.HandlerOptions{Level: minimum}
	if location != nil {
		options.ReplaceAttr = func(groups []string, attr slog.Attr) slog.Attr {
			if len(groups) == 0 && attr.Key == slog.TimeKey && attr.Value.Kind() == slog.KindTime {
				attr.Value = slog.TimeValue(attr.Value.Time().In(location))
			}
			return attr
		}
	}
	return slog.New(slog.NewJSONHandler(w, options))
}

// deploymentLocation resolves config.timezone for host-side output. Recovery
// commands load configuration without deployment validation, so an invalid
// zone there keeps the previous formatting instead of blocking recovery.
func deploymentLocation(cfg *config.Config) *time.Location {
	if cfg == nil {
		return nil
	}
	location, err := cfg.Location()
	if err != nil {
		return nil
	}
	return location
}

// accountRecovery saves an account's security state for the host recovery
// commands: a tenant's store, or the platform's store of one platform
// administrator.
type accountRecovery interface {
	SaveUserSecurity(ctx context.Context, u store.User, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit store.AuditEntry) error
}

// platformSetupToken prints a one-time token, valid for 15 minutes, that
// creates a platform administrator. It is refused once an enabled platform
// administrator exists and before the first administrator setup. An unused
// token that is still valid is replaced only with --force.
func platformSetupToken(ctx context.Context, s *store.Store, force bool, out io.Writer) error {
	token, err := auth.NewManager(s).IssuePlatformSetupToken(ctx, force)
	if errors.Is(err, store.ErrSetupTokenOutstanding) {
		return fmt.Errorf("%w; a new platform setup token replaces it, pass --force to confirm", err)
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "EdgeWatch platform setup token (valid for 15 minutes):", token)
	return nil
}

func adminAction(ctx context.Context, action string, s *store.Store, passwordFile string, confirmations ...bool) error {
	return adminActionForUser(ctx, action, s, passwordFile, "admin", confirmations...)
}

func adminActionForUser(ctx context.Context, action string, s *store.Store, passwordFile, username string, confirmations ...bool) error {
	force := len(confirmations) > 0 && confirmations[0]
	return adminRecovery(ctx, action, s, passwordFile, username, adminRecoveryOptions{force: force})
}

// adminRecoveryOptions are the options of a host recovery command.
type adminRecoveryOptions struct {
	// force confirms the replacement of the current setup token.
	force bool
	// unit, when set, is the business unit that --tenant named, which the
	// account must belong to: the command changes nothing for an account of
	// another unit or of the platform.
	unit *store.Tenant
	// out, when set, receives the account, its unit (or the platform) and
	// its role before the command acts.
	out io.Writer
}

// adminRecovery runs a host recovery command on the account with the
// username, which is unique across every business unit and the platform.
func adminRecovery(ctx context.Context, action string, s *store.Store, passwordFile, username string, options adminRecoveryOptions) error {
	force := options.force
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
	// An account is "not configured" only when it does not exist. Any other
	// failure, such as an invalid username or a database error, is reported
	// as it is.
	user, err := s.GetUserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("user %q is not configured", username)
	}
	if err != nil {
		return fmt.Errorf("look up user %q: %w", username, err)
	}
	// The host may recover an account of any tenant. The change goes through
	// the store of the account's own tenant, as the console's would. A
	// platform administrator has no tenant; the host is its break-glass
	// path, through the platform's store bound to that one account.
	var accounts accountRecovery
	if user.Role == store.RolePlatformAdmin {
		accounts = s.Platform().Account(user.ID)
	} else {
		// An account of a deleted unit no longer exists either.
		scope, err := s.TenantScopeByID(ctx, user.TenantID)
		if errors.Is(err, store.ErrNoTenantScope) {
			return fmt.Errorf("user %q is not configured", username)
		}
		if err != nil {
			return fmt.Errorf("look up the business unit of user %q: %w", username, err)
		}
		accounts = s.Tenant(scope)
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
		where, err := confirmAccountUnit(ctx, s, user, options)
		if err != nil {
			return err
		}
		detail := recoveryAuditDetail("password", "reset", user, where)
		user.PasswordHash, user.UpdatedAt = hash, time.Now().UTC()
		if user.ID == store.LegacyAdminUserID {
			admin, adminErr := s.GetAdmin(ctx)
			if adminErr != nil {
				return adminErr
			}
			admin.PasswordHash, admin.UpdatedAt = hash, user.UpdatedAt
			return s.SaveAdminSecurityWithAudit(ctx, admin, nil, false, true, store.AuditEntry{Action: "admin.password_reset", Detail: detail, ActorUsername: hostCLIActor, ActorKind: store.AuditActorHost})
		}
		return accounts.SaveUserSecurity(ctx, user, nil, false, true, store.AuditEntry{Action: "user.password_reset", Detail: detail, ActorUsername: hostCLIActor, ActorKind: store.AuditActorHost})
	case "disable-totp":
		where, err := confirmAccountUnit(ctx, s, user, options)
		if err != nil {
			return err
		}
		detail := recoveryAuditDetail("TOTP", "disabled", user, where)
		user.TOTPEnabled, user.TOTPSecret, user.UpdatedAt = false, "", time.Now().UTC()
		if user.ID == store.LegacyAdminUserID {
			admin, adminErr := s.GetAdmin(ctx)
			if adminErr != nil {
				return adminErr
			}
			admin.TOTPEnabled, admin.TOTPSecret, admin.UpdatedAt = false, "", user.UpdatedAt
			return s.SaveAdminSecurityWithAudit(ctx, admin, []string{}, true, true, store.AuditEntry{Action: "admin.totp_disabled", Detail: detail, ActorUsername: hostCLIActor, ActorKind: store.AuditActorHost})
		}
		return accounts.SaveUserSecurity(ctx, user, []string{}, true, true, store.AuditEntry{Action: "user.totp_disabled", Detail: detail, ActorUsername: hostCLIActor, ActorKind: store.AuditActorHost})
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

// notifyTestResult is what notify test prints: the counts of the test of the
// selected unit's destinations, and DeploymentLocked, the number of enabled
// web-managed destinations of every unit and of the platform that the
// notification key cannot open. It carries counts only, never a URL.
type notifyTestResult struct {
	notify.TestSummary
	DeploymentLocked int `json:"deployment_locked"`
}

// unhealthyStatus is the health document printed when the daemon is not
// healthy. Its status field replaces the embedded one.
type unhealthyStatus struct {
	store.HealthStatus
	ScannerSandbox      sandbox.Status `json:"scanner_sandbox"`
	NotificationSandbox sandbox.Status `json:"notification_sandbox"`
	Status              string         `json:"status"`
	Error               string         `json:"error"`
}

// healthReport is the health command's document: the daemon's health and how
// scanner and notification processes start in this container.
type healthReport struct {
	store.HealthStatus
	ScannerSandbox      sandbox.Status `json:"scanner_sandbox"`
	NotificationSandbox sandbox.Status `json:"notification_sandbox"`
}

// scannerSandboxOptions describes the configured sandbox and the scanner
// command whose start with Landlock the sandbox confirms. Nmap loads shared
// libraries, so its start shows whether the restriction allows the dynamic
// loader and the libraries' paths. Naabu is a static binary below /usr, which
// the restriction always allows, and its version command takes half a
// second, too long for every health check.
func scannerSandboxOptions(cfg *config.Config, nmapPath string) sandbox.Options {
	return sandbox.Options{
		Mode:     cfg.Scanner.Sandbox,
		Landlock: cfg.Scanner.Landlock,
		Probes:   []sandbox.Probe{{Args: []string{nmapPath, "--version"}}},
	}
}

// notificationSandboxOptions describes the configured notification sandbox.
// One setting selects both confinements: required needs the identity, and
// Landlock applies unless the setting is off. Both probes run the
// notify-check command in the notification process's own environment, so a
// certificate authority that SSL_CERT_FILE or SSL_CERT_DIR names and the
// confined process could not read keeps it unconfined instead of failing its
// deliveries.
func notificationSandboxOptions(cfg *config.Config) sandbox.Options {
	landlock := sandbox.ModeAuto
	if strings.EqualFold(strings.TrimSpace(cfg.Notifications.Sandbox), sandbox.ModeOff) {
		landlock = sandbox.ModeOff
	}
	check := sandbox.Probe{Name: "the notification process", Self: true, Args: []string{"notify-check"}, Env: notify.ChildEnvironment()}
	return sandbox.Options{
		Profile:       sandbox.Notifier,
		Mode:          cfg.Notifications.Sandbox,
		Landlock:      landlock,
		IdentityProbe: check,
		Probes:        []sandbox.Probe{check},
	}
}

// scannerSandboxWarnings reports a sandbox that auto mode could not enforce
// while scanner processes run as UID 0. A daemon that runs as another user
// starts scanner processes as that user, which the sandbox would not improve
// on.
func scannerSandboxWarnings(status sandbox.Status) []string {
	return unconfinedRootWarnings("scanner processes run", status)
}

// notificationSandboxWarnings reports a notification sandbox that auto mode
// could not enforce while the notification process runs as UID 0.
func notificationSandboxWarnings(status sandbox.Status) []string {
	return unconfinedRootWarnings("the notification process runs", status)
}

func unconfinedRootWarnings(subject string, status sandbox.Status) []string {
	if status.State != sandbox.StateUnavailable || status.ProcessUID != 0 {
		return nil
	}
	if status.Landlock.State == sandbox.StateEnforced {
		return []string{subject + " as UID 0, restricted only by Landlock: " + status.Reason}
	}
	return []string{subject + " unconfined as UID 0: " + status.Reason}
}

// logScannerSandbox records how scanner processes start.
func logScannerSandbox(logger *slog.Logger, status sandbox.Status) {
	switch {
	case status.State == sandbox.StateEnforced:
		logger.Info("scanner processes are sandboxed", "uid", status.UID, "gid", status.GID, "capabilities", status.Capabilities, "no_new_privileges", status.NoNewPrivileges)
	case status.State == sandbox.StateUnavailable && status.ProcessUID == 0 && status.Landlock.State == sandbox.StateEnforced:
		logger.Warn("scanner processes run as UID 0, restricted only by Landlock; see the container hardening guide", "reason", status.Reason)
	case status.State == sandbox.StateUnavailable && status.ProcessUID == 0:
		logger.Warn("scanner processes run unconfined as UID 0; see the container hardening guide", "reason", status.Reason)
	case status.State == sandbox.StateUnavailable:
		logger.Info("scanner processes run as the daemon's user", "uid", status.ProcessUID, "reason", status.Reason)
	default:
		logger.Info("scanner sandbox is off; scanner processes run unconfined", "uid", status.ProcessUID)
	}
	switch {
	case status.Landlock.State == sandbox.StateEnforced:
		logger.Info("scanner processes are restricted with Landlock", "abi", status.Landlock.ABI, "seccomp", status.Seccomp.State, "seccomp_reason", status.Seccomp.Reason)
	case status.Landlock.State == sandbox.StateUnavailable:
		logger.Info("scanner processes start without Landlock", "reason", status.Landlock.Reason)
	case status.State != sandbox.StateDisabled:
		logger.Info("scanner.landlock is off; scanner processes start without Landlock")
	}
}

// logNotificationSandbox records how the notification process starts.
func logNotificationSandbox(logger *slog.Logger, status sandbox.Status) {
	switch {
	case status.State == sandbox.StateEnforced:
		logger.Info("the notification process is sandboxed", "uid", status.UID, "gid", status.GID, "landlock", status.Landlock.State, "landlock_reason", status.Landlock.Reason, "seccomp", status.Seccomp.State)
	case status.State == sandbox.StateUnavailable && status.ProcessUID == 0 && status.Landlock.State == sandbox.StateEnforced:
		logger.Warn("the notification process runs as UID 0, restricted only by Landlock; see the container hardening guide", "reason", status.Reason)
	case status.State == sandbox.StateUnavailable && status.ProcessUID == 0:
		logger.Warn("the notification process runs unconfined as UID 0; see the container hardening guide", "reason", status.Reason)
	case status.State == sandbox.StateUnavailable:
		logger.Info("the notification process runs as the daemon's user", "uid", status.ProcessUID, "reason", status.Reason, "landlock", status.Landlock.State)
	default:
		logger.Info("notification sandbox is off; the notification process runs unconfined", "uid", status.ProcessUID)
	}
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

// validateStartupConfig checks the configured key files and the notification
// URLs from config.yaml as the daemon's startup does, with no database: the
// daemon runs it before it opens and migrates the database, and config
// validate runs it after config.Load. The URL error names only a digest
// prefix. app.New keeps its own checks for embedded callers.
func validateStartupConfig(cfg *config.Config) error {
	if cfg.Web.AuthKeyFile != "" {
		if err := store.ValidateAuthKeyFile(cfg.Web.AuthKeyFile); err != nil {
			return fmt.Errorf("validate authentication key file (web.auth_key_file): %w", err)
		}
	}
	if cfg.Notifications.EncryptionKeyFile != "" {
		if err := notify.ValidateKeyFile(cfg.Notifications.EncryptionKeyFile); err != nil {
			return fmt.Errorf("validate notification encryption key file (notifications.encryption_key_file): %w", err)
		}
	}
	if err := notify.ValidateConfiguredURLs(cfg.Notifications.URLs); err != nil {
		return fmt.Errorf("%w in notifications.urls or notifications.urls_file", err)
	}
	return nil
}

// validateConfig is config validate. It prints the normalized configuration
// with "valid": true when the daemon would accept it, and otherwise
// "valid": false with the reason, and then fails.
func validateConfig(path, output string) error {
	cfg, err := config.Load(path)
	if err == nil {
		err = validateStartupConfig(cfg)
	}
	if err != nil {
		// A boolean and a string always encode.
		_ = printValue(output, map[string]any{"valid": false, "error": err.Error()})
		return err
	}
	return printValue(output, normalizedConfig(cfg))
}

func normalizedConfig(cfg *config.Config) map[string]any {
	jobs := make([]map[string]any, 0, len(cfg.Jobs))
	for _, j := range cfg.Jobs {
		jobs = append(jobs, map[string]any{"name": j.Name, "schedule": j.Schedule, "timezone": j.Timezone, "targets": j.Targets, "security_hash": j.SecurityHash()})
	}
	return map[string]any{"valid": true, "version": cfg.Version, "database": cfg.Database, "timezone": cfg.Timezone, "web_listen": cfg.Web.Listen, "log_level": cfg.LogLevel(), "max_probe_count": cfg.Scheduler.MaxProbeCount, "max_naabu_probe_count": cfg.Scheduler.MaxNaabuProbeCount, "target_exclusions": append([]string(nil), cfg.Scanner.TargetExclusions...), "rdap_enabled": cfg.RDAPEnabled(), "updates_enabled": cfg.UpdatesEnabled(), "jobs": jobs, "legacy_jobs_inactive": len(jobs) > 0, "notification_destinations": len(cfg.Notifications.URLs)}
}

// status reports the managed jobs of the tenant of ts, whose state is
// unitState, followed by the inactive legacy YAML jobs that no managed job
// of that tenant replaces.
func status(ctx context.Context, ts *store.TenantStore, unitState string, cfg *config.Config, filter, output string) error {
	type row struct {
		Name string `json:"name"`
		// State is scheduled, paused, archived, unit_disabled (an enabled job
		// of a disabled business unit), or legacy (an inactive YAML job).
		// Only scheduled jobs run on their schedule and have a NextRun.
		State               string `json:"state"`
		Schedule            string `json:"schedule"`
		Timezone            string `json:"timezone"`
		BaselineScanID      string `json:"baseline_scan_id,omitempty"`
		BaselineProgress    string `json:"baseline_progress"`
		ActiveIncidents     int    `json:"active_incidents"`
		ConsecutiveFailures int    `json:"consecutive_failures"`
		LastScanID          string `json:"last_scan_id,omitempty"`
		LastScanStatus      string `json:"last_scan_status,omitempty"`
		LastScanFinished    string `json:"last_scan_finished,omitempty"`
		NextRun             string `json:"next_run,omitempty"`
		FailedDeliveries    int    `json:"failed_deliveries"`
	}
	// A unit without jobs prints an empty list, not null.
	rows := []row{}
	display := deploymentLocation(cfg)
	failedDeliveries, err := ts.FailedDeliveries(ctx)
	if err != nil {
		return err
	}
	managed, err := ts.ListJobs(ctx, true)
	if err != nil {
		return err
	}
	managedNames := map[string]bool{}
	for _, record := range managed {
		managedNames[record.Job.Name] = true
		if filter != "" && record.Job.Name != filter {
			continue
		}
		state, err := ts.RuntimeState(ctx, record.ID)
		if err != nil {
			return err
		}
		progress := "complete"
		if state.Baseline == nil {
			progress = fmt.Sprintf("%d/%d", state.CandidateCount, record.Job.Baseline.Samples)
		} else if state.BaselineConfigHash != record.Job.SecurityHash() {
			progress = fmt.Sprintf("updating %d/%d", state.CandidateCount, record.Job.Baseline.Samples)
		}
		entry := row{Name: record.Job.Name, State: managedJobState(record, unitState), Schedule: record.Job.Schedule, Timezone: record.Job.Timezone, BaselineScanID: state.BaselineScanID, BaselineProgress: progress, ActiveIncidents: len(state.Incidents), ConsecutiveFailures: state.ConsecutiveFailures, FailedDeliveries: failedDeliveries}
		if scans, listErr := ts.ListJobScans(ctx, record.ID, 1); listErr != nil {
			return listErr
		} else if len(scans) == 1 {
			entry.LastScanID, entry.LastScanStatus = scans[0].ID, scans[0].Status
			entry.LastScanFinished = statusTime(scans[0].FinishedAt, display)
		}
		// The daemon schedules only the enabled, non-archived managed jobs of
		// an active unit.
		if entry.State == jobStateScheduled {
			location := statusLocation(record.Job.Timezone)
			parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
			if schedule, parseErr := parser.Parse(record.Job.Schedule); parseErr == nil {
				entry.NextRun = statusTime(schedule.Next(time.Now().In(location)), display)
			}
		}
		rows = append(rows, entry)
	}
	// Inactive YAML jobs predate business units and belong to the default
	// unit, so another unit's status lists none.
	legacyJobs := cfg.Jobs
	if scope, err := ts.Scope(); err != nil || scope != store.DefaultTenantScope() {
		legacyJobs = nil
	}
	for _, j := range legacyJobs {
		if managedNames[j.Name] {
			continue
		}
		if filter != "" && j.Name != filter {
			continue
		}
		state, err := ts.State(ctx, j.Name)
		if err != nil {
			return err
		}
		progress := "complete"
		if state.Baseline == nil {
			progress = fmt.Sprintf("%d/%d", state.CandidateCount, j.Baseline.Samples)
		} else if state.BaselineConfigHash != j.SecurityHash() {
			progress = fmt.Sprintf("updating %d/%d", state.CandidateCount, j.Baseline.Samples)
		}
		// Legacy YAML jobs are inactive: the daemon never schedules them, so
		// they have no next run.
		entry := row{Name: j.Name, State: jobStateLegacy, Schedule: j.Schedule, Timezone: j.Timezone, BaselineScanID: state.BaselineScanID, BaselineProgress: progress, ActiveIncidents: len(state.Incidents), ConsecutiveFailures: state.ConsecutiveFailures, FailedDeliveries: failedDeliveries}
		if scans, listErr := ts.ListScans(ctx, j.Name, 1); listErr != nil {
			return listErr
		} else if len(scans) == 1 {
			entry.LastScanID = scans[0].ID
			entry.LastScanStatus = scans[0].Status
			entry.LastScanFinished = statusTime(scans[0].FinishedAt, display)
		}
		rows = append(rows, entry)
	}
	if filter != "" && len(rows) == 0 {
		return fmt.Errorf("unknown job %q", filter)
	}
	return printValue(output, rows)
}

// Job states reported by the status command. They match the console's job
// labels, plus unit_disabled for the enabled jobs of a disabled business
// unit and legacy for inactive YAML definitions.
const (
	jobStateScheduled    = "scheduled"
	jobStatePaused       = "paused"
	jobStateArchived     = "archived"
	jobStateUnitDisabled = "unit_disabled"
	jobStateLegacy       = "legacy"
)

// managedJobState mirrors the scheduler: archived jobs never run, paused
// (disabled) jobs run only on demand, and the other jobs of a unit whose
// state is unitState run on their schedule only while the unit is active.
func managedJobState(record store.JobRecord, unitState string) string {
	switch {
	case record.Archived:
		return jobStateArchived
	case !record.Enabled:
		return jobStatePaused
	case unitState != store.TenantStateActive:
		return jobStateUnitDisabled
	default:
		return jobStateScheduled
	}
}

// statusTime renders CLI status times in the configured deployment timezone.
// Without one, it keeps the previous stored or schedule-local offset.
func statusTime(value time.Time, display *time.Location) string {
	if display != nil {
		value = value.In(display)
	}
	return value.Format(time.RFC3339)
}

func statusLocation(timezone string) *time.Location {
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return time.UTC
	}
	return location
}

// baseline approves or resets the baseline of a managed job of the tenant of
// ts, and routes the resulting alerts to that tenant's destinations.
func baseline(ctx context.Context, action string, ts *store.TenantStore, a *app.App, job, scanID, output string) error {
	if job == "" {
		return errors.New("--job is required")
	}
	if record, managedErr := ts.GetJobByName(ctx, job); managedErr == nil {
		var events []model.Event
		var err error
		var destinations []string
		destinations, err = a.Notifier.Tenant(ts).QueueDestinationsForJob(ctx, record.Job)
		if err != nil {
			return err
		}
		switch action {
		case "approve":
			if scanID == "" {
				return errors.New("--scan-id is required")
			}
			scan, getErr := ts.GetScan(ctx, scanID)
			if getErr != nil {
				return getErr
			}
			if scan.JobID != record.ID || scan.ConfigHash != record.Job.SecurityHash() {
				return errors.New("scan does not match the current managed job")
			}
			events, err = ts.ApproveRuntimeWithOutboxAndAudit(ctx, record.ID, record.Job.Name, scan, destinations, store.AuditEntry{
				Action:        "baseline.approved",
				Detail:        record.ID + ":" + scan.ID,
				ActorUserID:   hostActorUserID(ts),
				ActorUsername: "host-cli",
				ActorKind:     store.AuditActorHost,
			})
		case "reset":
			events, err = ts.ResetRuntimeWithOutboxAndAudit(ctx, record.ID, record.Job.Name, destinations, store.AuditEntry{
				Action:        "baseline.reset",
				Detail:        record.ID,
				ActorUserID:   hostActorUserID(ts),
				ActorUsername: "host-cli",
				ActorKind:     store.AuditActorHost,
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
