package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/config"
	"modernc.org/sqlite"
)

type Store struct {
	DB *sql.DB
	// ReadDB is a separate read-only pool for history-heavy console queries.
	// Mutations and migration work stay on DB, while WAL lets these reads make
	// progress during a scan commit or pruning transaction. It is nil for
	// in-memory databases, where a second connection would not share state.
	ReadDB      *sql.DB
	Path        string
	authKeyPath string
	authAutoKey bool
	// queryOnly records a read-only inspection store so Close can remove only
	// empty SQLite sidecars that this connection created, and only when no
	// other connection has the database open. Existing companions are
	// deliberately left untouched because they may contain live or foreign
	// state that restore must inspect.
	queryOnly     bool
	artifactPath  string
	probeSidecars map[string]bool
	// releaseOpen removes this store from the process-wide registry of open
	// databases once its connections are closed.
	releaseOpen func()
	// targetExclusions is configured once during daemon startup. A nil slice
	// means the caller did not provide deployment policy (kept for embedded
	// library compatibility); a non-nil empty slice is an explicit allow-all
	// override.
	targetExclusions []string
}

type rowQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

var ErrJobBusy = errors.New("job is already running")
var ErrLeaseLost = errors.New("daemon lease lost")

// sqlitePragmaConnector applies connection-scoped SQLite settings whenever
// database/sql opens a physical connection. database/sql can discard a
// connection after a cancelled query, so issuing these PRAGMAs once through
// db.Exec is not sufficient: a replacement connection would silently revert
// to SQLite's defaults.
type sqlitePragmaConnector struct {
	driver.Connector
	queryOnly bool
}

func (c sqlitePragmaConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	execer, ok := conn.(driver.ExecerContext)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("SQLite driver does not support connection setup")
	}
	statements := []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA temp_store=FILE"}
	if c.queryOnly {
		statements = append(statements, "PRAGMA query_only=ON")
	}
	for _, statement := range statements {
		if _, err := execer.ExecContext(ctx, statement, nil); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func Open(path string) (*Store, error) {
	return openWithOptions(path, openOptions{create: true, migrate: true, configureWAL: true})
}

// OpenWithLogger opens a writable store and routes migration/startup progress
// through the supplied logger. Open remains the compatibility helper for
// library callers that do not have an application logger yet.
func OpenWithLogger(path string, logger *slog.Logger) (*Store, error) {
	return openWithOptions(path, openOptions{create: true, migrate: true, configureWAL: true, logger: logger})
}

// OpenExisting opens an existing database without running migrations or
// repair/backfill work. It is intended for host-side data commands such as
// backup, where opening the source must not mutate schema state or compete
// with the daemon's migration path.
func OpenExisting(path string) (*Store, error) {
	return openWithOptions(path, openOptions{requireExisting: true})
}

// OpenExistingContext is the context-aware variant used by long-running data
// commands. The regular OpenExisting helper is retained for library callers
// that do not have a request context.
func OpenExistingContext(ctx context.Context, path string) (*Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return openWithOptionsContext(ctx, path, openOptions{requireExisting: true})
}

// OpenReadOnlyExisting opens an existing database using SQLite's query-only
// mode. It never changes database content, journal mode, repairs permissions,
// or runs migrations, making it safe for health, verification, and export
// reads. SQLite may still initialize transient WAL/SHM coordination files
// while attaching to a live database; Store.Close removes only empty
// companions created by this inspection connection, and leaves them when
// another connection has the database open.
func OpenReadOnlyExisting(path string) (*Store, error) {
	return openWithOptions(path, openOptions{requireExisting: true, queryOnly: true})
}

// OpenReadOnlyExistingContext is the context-aware variant used by
// long-running host-side checks. It never changes database content, journal
// mode, permissions, or schema. SQLite may initialize transient coordination
// sidecars while opening a live WAL database. Store.Close removes only empty
// companions created by this inspection connection, and leaves them when
// another connection has the database open.
func OpenReadOnlyExistingContext(ctx context.Context, path string) (*Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return openWithOptionsContext(ctx, path, openOptions{requireExisting: true, queryOnly: true})
}

type openOptions struct {
	create          bool
	requireExisting bool
	migrate         bool
	configureWAL    bool
	queryOnly       bool
	logger          *slog.Logger
}

func openWithOptions(path string, options openOptions) (*Store, error) {
	return openWithOptionsContext(context.Background(), path, options)
}

func openWithOptionsContext(ctx context.Context, path string, options openOptions) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is empty")
	}
	dsn := path
	memoryDatabase := isSQLiteMemoryPath(path)
	artifactPath := path
	var probeSidecars map[string]bool
	if !memoryDatabase {
		var err error
		artifactPath, err = sqliteArtifactPath(path)
		if err != nil {
			return nil, err
		}
		if options.requireExisting {
			info, statErr := os.Stat(artifactPath)
			if errors.Is(statErr, os.ErrNotExist) {
				return nil, fmt.Errorf("database not found: %s", artifactPath)
			}
			if statErr != nil {
				return nil, statErr
			}
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("database path is not a regular file: %s", artifactPath)
			}
			if err := validatePrivateSQLiteArtifacts(artifactPath); err != nil {
				return nil, err
			}
		} else {
			if !options.create {
				return nil, fmt.Errorf("database not found: %s", artifactPath)
			}
			if err := os.MkdirAll(filepath.Dir(artifactPath), 0o750); err != nil {
				return nil, fmt.Errorf("create EdgeWatch database directory %q: %w", filepath.Dir(artifactPath), err)
			}
			if err := os.MkdirAll(filepath.Join(filepath.Dir(artifactPath), "tmp"), 0o750); err != nil {
				return nil, fmt.Errorf("create EdgeWatch temporary directory %q: %w", filepath.Join(filepath.Dir(artifactPath), "tmp"), err)
			}
			if err := ensurePrivateSQLiteFile(artifactPath); err != nil {
				return nil, fmt.Errorf("prepare EdgeWatch database %q: %w", artifactPath, err)
			}
			// Refuse unsafe pre-existing sidecars before SQLite can open or update
			// them. SQLite may follow a WAL/SHM symlink during connection setup, so
			// checking only after the first pragma would leave a small write window.
			if err := enforcePrivateSQLiteArtifacts(artifactPath); err != nil {
				return nil, fmt.Errorf("secure EdgeWatch database artifacts %q: %w", artifactPath, err)
			}
		}
		// Query-only commands must open SQLite in read-only mode before any
		// connection setup runs. PRAGMA query_only is still applied by the
		// connector as a defence in depth, but it cannot prevent SQLite from
		// creating a journal or sidecar while opening a writable DSN.
		if options.queryOnly {
			dsn = readOnlySQLiteDSN(artifactPath)
		}
	}
	var releaseOpen func()
	opened := false
	if !memoryDatabase {
		// Register before SQLite opens the file, so a read-only probe closing
		// in this process never tests for other connections by opening and
		// closing its own descriptor while this store holds SQLite locks.
		releaseOpen = openDatabases.register(artifactPath)
		defer func() {
			if !opened {
				releaseOpen()
			}
		}()
	}
	if options.queryOnly && !memoryDatabase {
		// Capture the companion files before SQLite opens the live-safe
		// read-only connection; it may initialize an empty WAL/SHM pair.
		probeSidecars = snapshotSQLiteSidecars(artifactPath)
	}
	connector, err := sqlite.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(sqlitePragmaConnector{Connector: connector, queryOnly: options.queryOnly})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if !options.migrate && !options.queryOnly {
		// Write-capable host commands open without migrating. Refuse a schema
		// from a newer release before anything writes, as the daemon does.
		var version int
		if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			db.Close()
			return nil, err
		}
		if version > schemaVersion {
			db.Close()
			return nil, newerSchemaError(version)
		}
	}
	if options.migrate && !options.queryOnly {
		// New databases must select incremental auto-vacuum before WAL mode or
		// any application table is created. Existing databases are intentionally
		// left unchanged: converting a populated file requires a one-time
		// operator-controlled VACUUM and must not happen during startup.
		var applicationTables int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&applicationTables); err != nil {
			db.Close()
			return nil, err
		}
		if applicationTables == 0 {
			if _, err := db.ExecContext(ctx, "PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
				db.Close()
				return nil, err
			}
		}
	}
	// Read the result of the journal-mode pragma instead of assuming that the
	// requested mode was accepted. SQLite may silently retain a different mode
	// on filesystems that do not support WAL. In that case the writer remains the
	// sole reader as well; opening a separate pool would advertise concurrency
	// guarantees that the storage backend cannot provide.
	walEnabled := memoryDatabase
	if !memoryDatabase && !options.queryOnly {
		journalPragma := "PRAGMA journal_mode"
		if options.configureWAL {
			journalPragma = "PRAGMA journal_mode=WAL"
		}
		var journalMode string
		if err := db.QueryRowContext(ctx, journalPragma).Scan(&journalMode); err != nil {
			db.Close()
			return nil, fmt.Errorf("verify SQLite journal mode: %w", err)
		}
		walEnabled = strings.EqualFold(strings.TrimSpace(journalMode), "wal")
		if !walEnabled {
			logger := options.logger
			if logger == nil {
				logger = slog.Default()
			}
			logger.Warn("SQLite WAL is unavailable; using the writer connection for reads", "journal_mode", strings.TrimSpace(journalMode), "remediation", "move the database to a filesystem that supports SQLite WAL for concurrent history reads")
		}
	}
	pragmas := []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, err
		}
		if !memoryDatabase && !options.queryOnly {
			if err := enforcePrivateSQLiteArtifacts(artifactPath); err != nil {
				db.Close()
				return nil, fmt.Errorf("secure EdgeWatch database artifacts %q: %w", artifactPath, err)
			}
		}
	}
	if options.migrate {
		if err := migrateContextWithLogger(ctx, db, options.logger); err != nil {
			db.Close()
			return nil, err
		}
	}
	if options.queryOnly {
		if !memoryDatabase {
			if err := validatePrivateSQLiteArtifacts(artifactPath); err != nil {
				db.Close()
				return nil, err
			}
		}
		store := &Store{DB: db, Path: dsn, authKeyPath: defaultAuthKeyPath(artifactPath), authAutoKey: true, queryOnly: true, releaseOpen: releaseOpen}
		if !memoryDatabase {
			store.artifactPath = artifactPath
			store.probeSidecars = probeSidecars
		}
		opened = true
		return store, nil
	}
	var readDB *sql.DB
	if !memoryDatabase && walEnabled {
		readConnector, connectorErr := sqlite.NewConnector(dsn)
		if connectorErr != nil {
			db.Close()
			return nil, connectorErr
		}
		readDB = sql.OpenDB(sqlitePragmaConnector{Connector: readConnector, queryOnly: true})
		readDB.SetMaxOpenConns(4)
		readDB.SetMaxIdleConns(4)
		// Opening one connection here validates the path and query-only pragma;
		// the connector reapplies it whenever database/sql creates another one.
		if _, err := readDB.Exec("PRAGMA query_only=ON"); err != nil {
			readDB.Close()
			db.Close()
			return nil, err
		}
	}
	if !memoryDatabase {
		if err := enforcePrivateSQLiteArtifacts(artifactPath); err != nil {
			if readDB != nil {
				readDB.Close()
			}
			db.Close()
			return nil, fmt.Errorf("secure EdgeWatch database artifacts %q: %w", artifactPath, err)
		}
	}
	opened = true
	store := &Store{DB: db, ReadDB: readDB, Path: dsn, authKeyPath: defaultAuthKeyPath(artifactPath), authAutoKey: true, releaseOpen: releaseOpen}
	if !memoryDatabase {
		store.artifactPath = artifactPath
	}
	return store, nil
}

// FilePath returns the on-disk SQLite database file, with any file: URI
// syntax and connection options removed, or an empty string for an in-memory
// database. Files kept beside the database, such as default encryption keys,
// must be derived from this path: Path holds the DSN, which may be a URI.
func (s *Store) FilePath() string {
	if s == nil {
		return ""
	}
	return s.artifactPath
}

// DatabaseFilePath returns the on-disk SQLite database file named by an
// accepted DSN, a plain path or a file: URI, with connection options removed.
// It returns an empty path for an in-memory database.
func DatabaseFilePath(dsn string) (string, error) {
	if isSQLiteMemoryPath(dsn) {
		return "", nil
	}
	return sqliteArtifactPath(dsn)
}

// readOnlySQLiteDSN builds a live-safe file URI with SQLite's mode=ro flag from
// the already validated artifact path. Do not add immutable=1 here: an
// inspection command may open while the daemon is running, and SQLite must be
// able to observe WAL frames committed after this connection was created.
// mode=ro prevents this reader from changing database content while still
// allowing SQLite's normal WAL coordination to provide a current view. The
// driver may initialize transient coordination sidecars even in read-only
// mode; those are not durable application state.
func readOnlySQLiteDSN(artifactPath string) string {
	return (&url.URL{Scheme: "file", Path: artifactPath, RawQuery: "mode=ro"}).String()
}

// SetTargetExclusions installs the deployment-wide scanner target policy. It
// must be called before jobs are created or updated. The values are copied so
// later configuration mutations cannot weaken the policy in use.
func (s *Store) SetTargetExclusions(exclusions []string) error {
	if exclusions == nil {
		s.targetExclusions = nil
		return nil
	}
	if _, err := config.ParseTargetExclusions(exclusions); err != nil {
		return err
	}
	s.targetExclusions = append([]string(nil), exclusions...)
	if len(exclusions) == 0 {
		// append to a nil slice preserves nil, which has a distinct meaning from
		// an explicitly empty policy.
		s.targetExclusions = []string{}
	}
	return nil
}

// validateManagedJob classifies every rejection as a ValidationError so the
// web layer can tell caller-correctable input apart from storage failures.
func (s *Store) validateManagedJob(job config.Job) error {
	if s.targetExclusions == nil {
		return NewValidationError(config.ValidateJob(job))
	}
	return NewValidationError(config.ValidateJobWithTargetExclusions(job, s.targetExclusions))
}

// sqliteArtifactPath resolves the on-disk filename represented by an accepted
// SQLite DSN. modernc.org/sqlite treats everything after the first '?' as
// connection options for both URI and plain-path DSNs, so artifact checks must
// strip that query before touching the filesystem. The database driver still
// receives the original DSN so its options remain effective.
func sqliteArtifactPath(path string) (string, error) {
	if !strings.HasPrefix(path, "file:") {
		if index := strings.IndexByte(path, '?'); index >= 0 {
			path = path[:index]
		}
		if path == "" {
			return "", errors.New("database path is empty")
		}
		return filepath.Clean(path), nil
	}
	withoutScheme := strings.TrimPrefix(path, "file:")
	if index := strings.IndexByte(withoutScheme, '?'); index >= 0 {
		withoutScheme = withoutScheme[:index]
	}
	if withoutScheme == "" || strings.HasPrefix(withoutScheme, ":memory:") {
		return "", errors.New("filesystem SQLite URI must include a database path")
	}
	// A URI authority is only safe for the local host. SQLite treats a URI
	// with another authority as a VFS-specific path that EdgeWatch cannot
	// reliably permission-check.
	if strings.HasPrefix(withoutScheme, "//") {
		u, err := url.Parse("file:" + withoutScheme)
		if err != nil {
			return "", fmt.Errorf("invalid SQLite database URI: %w", err)
		}
		if u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
			return "", errors.New("SQLite database URI must refer to the local host")
		}
		// url.Parse has already percent-decoded u.Path. Unescaping it again
		// would turn a literal %2F in a filename into a path separator.
		withoutScheme = u.Path
	}
	decoded := withoutScheme
	if !strings.HasPrefix(withoutScheme, "//") {
		var err error
		decoded, err = url.PathUnescape(withoutScheme)
		if err != nil {
			return "", fmt.Errorf("invalid SQLite database URI path: %w", err)
		}
	}
	if decoded == "" {
		return "", errors.New("filesystem SQLite URI must include a database path")
	}
	return filepath.Clean(decoded), nil
}

func isSQLiteMemoryPath(path string) bool {
	if path == ":memory:" || strings.HasPrefix(path, "file::memory:") {
		return true
	}
	if !strings.HasPrefix(path, "file:") {
		// The driver strips query options from plain paths before opening them,
		// therefore :memory:?cache=shared is still an in-memory DSN.
		if index := strings.IndexByte(path, '?'); index >= 0 {
			return path[:index] == ":memory:"
		}
		return false
	}
	queryIndex := strings.IndexByte(path, '?')
	if queryIndex < 0 {
		return false
	}
	for _, parameter := range strings.Split(path[queryIndex+1:], "&") {
		key, value, ok := strings.Cut(parameter, "=")
		if ok && key == "mode" && value == "memory" {
			return true
		}
	}
	return false
}

// ensurePrivateSQLiteFile creates the database before the SQLite driver sees
// it and repairs an existing file to owner-only permissions. This makes the
// sensitive database deterministic even when the container umask is 022.
func ensurePrivateSQLiteFile(path string) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("database path must not be a symbolic link: %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	closeErr := file.Close()
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(path, 0o600)
}

// enforcePrivateSQLiteArtifacts repairs permissions on SQLite's database and
// any sidecar files currently present. SQLite creates WAL/SHM lazily, so this
// is called after connection setup and migrations as well as before opening.
func enforcePrivateSQLiteArtifacts(path string) error {
	for _, candidate := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("database artifact must not be a symbolic link: %s", candidate)
		}
		if err := os.Chmod(candidate, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// validatePrivateSQLiteArtifacts verifies that the database and any existing
// SQLite sidecars are regular, non-symlink files. Unlike
// enforcePrivateSQLiteArtifacts it never changes permissions, which keeps
// read-only commands genuinely read-only.
func validatePrivateSQLiteArtifacts(path string) error {
	for _, candidate := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("database artifact must not be a symbolic link: %s", candidate)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("database artifact is not a regular file: %s", candidate)
		}
	}
	return nil
}

// SetAuthKeyPath selects an operator-managed authentication key. An explicit
// path is never generated automatically; the default key beside the database
// is generated lazily only when TOTP is first enabled.
func (s *Store) SetAuthKeyPath(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	s.authKeyPath = strings.TrimSpace(path)
	s.authAutoKey = false
}
func (s *Store) Close() error {
	var closeErr error
	if s.ReadDB == nil || s.ReadDB == s.DB {
		closeErr = s.DB.Close()
	} else {
		closeErr = errors.Join(s.ReadDB.Close(), s.DB.Close())
	}
	if s.releaseOpen != nil {
		s.releaseOpen()
	}
	if s.queryOnly && s.artifactPath != "" {
		// The read-only DSN is intentionally live-safe and may cause SQLite to
		// create an empty WAL/SHM pair. Remove only companions that were absent
		// before this probe, only while the WAL is empty, and only while no
		// other connection has the database open; never hide existing or
		// non-empty recovery evidence or another connection's files.
		cleanupSQLiteProbeSidecars(s.artifactPath, s.probeSidecars)
	}
	return closeErr
}

func (s *Store) reader() *sql.DB {
	if s.ReadDB != nil {
		return s.ReadDB
	}
	return s.DB
}

func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func nullInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

var (
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("resource was modified by another request")
	ErrRebaselineRequired = errors.New("security-relevant job changes require rebaseline confirmation")
	ErrJobScanActive      = errors.New("job has an active scan")
	ErrLastAdministrator  = errors.New("at least one enabled administrator is required")
	ErrIncidentNotFound   = errors.New("incident not found")
	// ErrIncidentConflict indicates that an incident changed after the
	// operator loaded it. Callers should refresh the incident list before
	// attempting the action again.
	ErrIncidentConflict          = errors.New("incident changed since it was loaded")
	ErrBaselineNotReady          = errors.New("baseline is not ready")
	ErrUnsupportedIncidentChange = errors.New("unsupported incident change")
	// ErrJobRevisionChanged is returned when a scan was queued with an older
	// immutable job revision. The caller must reload the job before starting it.
	ErrJobRevisionChanged = errors.New("job revision changed before scan started")
	// ErrValidation classifies errors caused by caller-supplied input that
	// fails a validation rule. API handlers map only this class to field-level
	// 400 responses; any other write failure is an internal error whose
	// storage detail must not reach clients.
	ErrValidation = errors.New("validation failed")
)

// ValidationError marks a caller-correctable input error. It keeps the
// validator's message unchanged, because API clients use that text as the
// field-level detail, while errors.Is(err, ErrValidation) reports true.
type ValidationError struct {
	Err error
}

func (e *ValidationError) Error() string { return e.Err.Error() }

func (e *ValidationError) Unwrap() error { return e.Err }

func (e *ValidationError) Is(target error) bool { return target == ErrValidation }

// NewValidationError wraps err as a ValidationError. A nil error stays nil so
// validators can be wrapped directly at a return statement.
func NewValidationError(err error) error {
	if err == nil {
		return nil
	}
	return &ValidationError{Err: err}
}
