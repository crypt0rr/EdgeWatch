package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// While the daemon starts, the answer is starting unless the database
// reports a stalled migration, a failed one, or a schema that it does not
// open.
func TestStartupHealthStatus(t *testing.T) {
	t.Parallel()
	failure := errors.New("failure")
	for _, test := range []struct {
		health store.HealthStatus
		err    error
		want   string
	}{
		{store.HealthStatus{}, store.ErrStartupNotRecorded, healthStarting},
		{store.HealthStatus{Status: "starting"}, nil, healthStarting},
		{store.HealthStatus{Status: "ready"}, nil, healthStarting},
		{store.HealthStatus{Status: "ready"}, errors.New("daemon heartbeat is stale"), healthStarting},
		{store.HealthStatus{Status: "starting"}, errors.New("database migration heartbeat is stale"), healthUnhealthy},
		{store.HealthStatus{Status: "failed"}, failure, healthUnhealthy},
		{store.HealthStatus{}, store.ErrSchemaBelowUpgradeFloor, healthUnhealthy},
		{store.HealthStatus{}, failure, healthUnhealthy},
	} {
		if got := startupHealthStatus(test.health, test.err); got != test.want {
			t.Errorf("startupHealthStatus(%+v, %v) = %s, want %s", test.health, test.err, got, test.want)
		}
	}
	if _, err := (&Server{}).loadHealth(context.Background()); err == nil {
		t.Error("a server without a store or a startup database read a health")
	}
}

// startupFixture is a database whose migration a test controls, served by
// the startup server on a listener of its own.
type startupFixture struct {
	db      *store.Store
	token   string
	address string
	startup *StartupListener
}

func newStartupFixture(t *testing.T) *startupFixture {
	t.Helper()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	token := strings.Repeat("startup-metrics-token-", 2)
	tokenFile := filepath.Join(t.TempDir(), "metrics.token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := newStartupServer(config.Web{Metrics: config.WebMetrics{Enabled: true, TokenFile: tokenFile}}, db.Path, "v0.36.0", logger)
	f := &startupFixture{db: db, token: token, address: listener.Addr().String()}
	f.startup = serveStartup(listener, f.address, server)
	t.Cleanup(func() { _ = f.startup.Close() })
	return f
}

// get sends a request to the listener and returns its status and body.
func (f *startupFixture) get(t *testing.T, path, token string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "http://"+f.address+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}

// While the daemon migrates, the listener answers /healthz with starting
// from the database's startup state, /metrics with the build, the health,
// and the migration, and every other path with 503 starting. Once the
// console's server takes the listener over, the same listener serves the
// console and /healthz answers ready.
func TestStartupServerAnswersWhileTheDaemonMigrates(t *testing.T) {
	t.Parallel()
	f := newStartupFixture(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := f.db.DB.Exec(`UPDATE startup_state SET state='migrating',phase='host-search:scan_hosts',started_at=?,updated_at=?,progress=1,total=4 WHERE id=1`, now, now); err != nil {
		t.Fatal(err)
	}
	if code, body := f.get(t, "/healthz", ""); code != http.StatusServiceUnavailable || strings.TrimSpace(body) != `{"status":"starting"}` {
		t.Errorf("GET /healthz while migrating = %d %s", code, body)
	}
	for _, path := range []string{"/", "/api/v1/setup/status", "/api/public/v1/dashboard", "/assets/index.js"} {
		if code, body := f.get(t, path, ""); code != http.StatusServiceUnavailable || !strings.Contains(body, `"code":"starting"`) {
			t.Errorf("GET %s while migrating = %d %s", path, code, body)
		}
	}
	if code, _ := f.get(t, "/metrics", ""); code != http.StatusUnauthorized {
		t.Errorf("GET /metrics without the token while migrating = %d", code)
	}
	code, body := f.get(t, "/metrics", f.token)
	if code != http.StatusOK {
		t.Fatalf("GET /metrics while migrating = %d %s", code, body)
	}
	for _, want := range []string{
		`edgewatch_build_info{version="v0.36.0"} 1`,
		`edgewatch_health_status{status="starting"} 1`,
		`edgewatch_migration_state{state="migrating"} 1`,
		`edgewatch_migration_phase_info{phase="host-search:scan_hosts"} 1`,
		`edgewatch_migration_progress_ratio 0.25`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics while migrating lack %q:\n%s", want, body)
		}
	}
	for _, absent := range []string{"edgewatch_scan_slots_capacity", "edgewatch_database_bytes", "edgewatch_update_check_status", "edgewatch_daemon_heartbeat_age_seconds"} {
		if strings.Contains(body, absent) {
			t.Errorf("metrics while migrating report %s:\n%s", absent, body)
		}
	}

	// The migration finishes, the console's server takes the listener
	// over, and the daemon takes its lease.
	if _, err := f.db.DB.Exec(`UPDATE startup_state SET state='ready',phase='',progress=0,total=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	console := NewServer(nil, f.db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- console.ServeStartupListener(ctx, f.startup) }()
	if _, err := f.db.System().AcquireDaemonLease(context.Background(), "startup-test"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		code, body := f.get(t, "/healthz", "")
		if code == http.StatusOK && strings.TrimSpace(body) == `{"status":"ready"}` {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET /healthz after the takeover = %d %s, want 200 ready", code, body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code, body := f.get(t, "/api/v1/setup/status", ""); code != http.StatusOK {
		t.Errorf("GET /api/v1/setup/status after the takeover = %d %s", code, body)
	}
	cancel()
	if err := <-served; err != nil {
		t.Errorf("console server = %v", err)
	}
	if err := f.startup.Close(); err != nil {
		t.Errorf("Close after the takeover = %v", err)
	}
	if conn, err := net.DialTimeout("tcp", f.address, time.Second); err == nil {
		_ = conn.Close()
		t.Error("the listener still accepts after the console's server stopped")
	}
}

// The startup server answers unhealthy for a stalled or failed migration,
// and starting for a finished one whose daemon has not taken its lease.
func TestStartupServerReportsAFailedOrStalledMigration(t *testing.T) {
	t.Parallel()
	stale := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	for _, test := range []struct {
		name, state, updated string
		code                 int
		want                 string
	}{
		{"failed", "failed", stale, http.StatusServiceUnavailable, healthUnhealthy},
		{"stalled", "migrating", stale, http.StatusServiceUnavailable, healthUnhealthy},
		{"finished", "ready", stale, http.StatusServiceUnavailable, healthStarting},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newStartupFixture(t)
			if _, err := f.db.DB.Exec(`UPDATE startup_state SET state=?,updated_at=?,last_error='boom' WHERE id=1`, test.state, test.updated); err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.DB.Exec(`DELETE FROM daemon_lease`); err != nil {
				t.Fatal(err)
			}
			if code, body := f.get(t, "/healthz", ""); code != test.code || strings.TrimSpace(body) != `{"status":"`+test.want+`"}` {
				t.Errorf("GET /healthz = %d %s, want %d %s", code, body, test.code, test.want)
			}
		})
	}
}

// A start that fails before the console's server takes the listener over
// closes it, and the listener cannot be taken over after that.
func TestStartupListenerCloseBeforeTheTakeover(t *testing.T) {
	t.Parallel()
	f := newStartupFixture(t)
	if code, _ := f.get(t, "/healthz", ""); code != http.StatusServiceUnavailable {
		t.Errorf("GET /healthz before the migration = %d", code)
	}
	if err := f.startup.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.startup.Close(); err != nil {
		t.Errorf("second Close = %v", err)
	}
	if conn, err := net.DialTimeout("tcp", f.address, time.Second); err == nil {
		_ = conn.Close()
		t.Error("the closed listener still accepts")
	}
	console := NewServer(nil, f.db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := console.ServeStartupListener(context.Background(), f.startup); !errors.Is(err, net.ErrClosed) {
		t.Errorf("takeover of a closed listener = %v, want net.ErrClosed", err)
	}
	var none *StartupListener
	if err := none.Close(); err != nil {
		t.Errorf("Close of no listener = %v", err)
	}
}

// ListenForStartup opens only a loopback address, as ListenAndServe does.
func TestListenForStartupChecksTheAddress(t *testing.T) {
	t.Parallel()
	if _, err := ListenForStartup(config.Web{Listen: "192.0.2.1:8080"}, filepath.Join(t.TempDir(), "edgewatch.db"), "", nil); err == nil {
		t.Fatal("a non-loopback listener was opened")
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	startup, err := ListenForStartup(config.Web{Listen: address}, filepath.Join(t.TempDir(), "edgewatch.db"), "", nil)
	if err != nil {
		t.Fatalf("ListenForStartup(%s) = %v", address, err)
	}
	defer func() { _ = startup.Close() }()
	if _, err := ListenForStartup(config.Web{Listen: address}, filepath.Join(t.TempDir(), "edgewatch.db"), "", nil); err == nil {
		t.Error("a second listener opened the same address")
	}
	response, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://" + address + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	// No database exists yet: the daemon has not created it.
	if response.StatusCode != http.StatusServiceUnavailable || strings.TrimSpace(string(body)) != `{"status":"starting"}` {
		t.Errorf("GET /healthz before the database exists = %d %s", response.StatusCode, body)
	}
}

// A view of the handoff refuses to accept once it or the handoff is
// closed, and reports the listener's address.
func TestListenerHandoffViews(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handoff := newListenerHandoff(listener)
	first := handoff.view(false)
	if first.Addr().String() != listener.Addr().String() {
		t.Errorf("view address = %s, want %s", first.Addr(), listener.Addr())
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept of a closed view = %v", err)
	}
	second := handoff.view(true)
	accepted := make(chan error, 1)
	go func() {
		conn, err := second.Accept()
		if err == nil {
			_ = conn.Close()
		}
		accepted <- err
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := <-accepted; err != nil {
		t.Errorf("Accept after the first view closed = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := handoff.view(false).Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after the listener closed = %v", err)
	}
}
