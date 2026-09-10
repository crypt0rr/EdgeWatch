package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
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
	statements := []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"}
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
	if path == "" {
		return nil, errors.New("database path is empty")
	}
	dsn := path
	memoryDatabase := isSQLiteMemoryPath(path)
	artifactPath := path
	if !memoryDatabase {
		var err error
		artifactPath, err = sqliteArtifactPath(path)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(artifactPath), 0o750); err != nil {
			return nil, err
		}
		if err := ensurePrivateSQLiteFile(artifactPath); err != nil {
			return nil, err
		}
		// Refuse unsafe pre-existing sidecars before SQLite can open or update
		// them. SQLite may follow a WAL/SHM symlink during connection setup, so
		// checking only after the first pragma would leave a small write window.
		if err := enforcePrivateSQLiteArtifacts(artifactPath); err != nil {
			return nil, err
		}
	}
	connector, err := sqlite.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(sqlitePragmaConnector{Connector: connector})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	for _, pragma := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, err
		}
		if !memoryDatabase {
			if err := enforcePrivateSQLiteArtifacts(artifactPath); err != nil {
				db.Close()
				return nil, err
			}
		}
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	var readDB *sql.DB
	if !memoryDatabase {
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
			db.Close()
			return nil, err
		}
	}
	return &Store{DB: db, ReadDB: readDB, Path: dsn, authKeyPath: defaultAuthKeyPath(artifactPath), authAutoKey: true}, nil
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

func (s *Store) validateManagedJob(job config.Job) error {
	if s.targetExclusions == nil {
		return config.ValidateJob(job)
	}
	return config.ValidateJobWithTargetExclusions(job, s.targetExclusions)
}

// sqliteArtifactPath resolves the on-disk filename represented by a SQLite
// file: URI. The database driver receives the original URI (so query options
// such as mode=rwc remain effective), while permission checks must operate on
// the decoded filename rather than a literal string containing '?mode=…'.
func sqliteArtifactPath(path string) (string, error) {
	if !strings.HasPrefix(path, "file:") {
		return path, nil
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
		if u.Host != "" && u.Host != "localhost" {
			return "", errors.New("SQLite database URI must refer to the local host")
		}
		withoutScheme = u.Path
	}
	decoded, err := url.PathUnescape(withoutScheme)
	if err != nil {
		return "", fmt.Errorf("invalid SQLite database URI path: %w", err)
	}
	if decoded == "" {
		return "", errors.New("filesystem SQLite URI must include a database path")
	}
	return decoded, nil
}

func isSQLiteMemoryPath(path string) bool {
	if path == ":memory:" || strings.HasPrefix(path, "file::memory:") {
		return true
	}
	if !strings.HasPrefix(path, "file:") {
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
	if s.ReadDB == nil || s.ReadDB == s.DB {
		return s.DB.Close()
	}
	return errors.Join(s.ReadDB.Close(), s.DB.Close())
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
	ErrNotFound                  = errors.New("not found")
	ErrConflict                  = errors.New("resource was modified by another request")
	ErrRebaselineRequired        = errors.New("security-relevant job changes require rebaseline confirmation")
	ErrJobScanActive             = errors.New("job has an active scan")
	ErrLastAdministrator         = errors.New("at least one enabled administrator is required")
	ErrIncidentNotFound          = errors.New("incident not found")
	ErrBaselineNotReady          = errors.New("baseline is not ready")
	ErrUnsupportedIncidentChange = errors.New("unsupported incident change")
	// ErrJobRevisionChanged is returned when a scan was queued with an older
	// immutable job revision. The caller must reload the job before starting it.
	ErrJobRevisionChanged = errors.New("job revision changed before scan started")
)
