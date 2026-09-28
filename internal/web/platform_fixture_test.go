package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
	"github.com/google/uuid"
)

// platformFixturePassword is the password of every fixture account. The
// accounts store it with cheapPasswordHash, so confirming it is fast.
const platformFixturePassword = "fixture account password"

// The actors of the platform fixture.
const (
	actorAdminA    = "unit A administrator"
	actorOperatorA = "unit A operator"
	actorViewerA   = "unit A viewer"
	actorAdminB    = "unit B administrator"
	actorPlatform  = "platform administrator"
)

// platformActors lists the actors in a fixed order.
var platformActors = []string{actorAdminA, actorOperatorA, actorViewerA, actorAdminB, actorPlatform}

// platformFixture is a server with two units. Unit A is the default unit, with an administrator, an operator and
// a viewer. Unit B, created through the application like any unit, has an
// administrator and a viewer. Both units have a job named "shared-job" that
// scans 192.0.2.10; unit B also has "bravo-job", which scans 198.51.100.77
// and has a scan, and a scanner profile, a notification destination, and
// audit records. Everything that names unit B contains "bravo", so a
// response can be searched for it. Every account is signed in, and the
// administrators have enrolled TOTP, as more than one unit requires.
type platformFixture struct {
	server   *Server
	db       *store.Store
	unitB    string
	a, b     *store.TenantStore
	users    map[string]store.User
	sessions map[string]routeMatrixSession
	// Unit B's resources, by kind.
	jobB, sharedJobB, scanB, profileB, destinationB, viewerB string
	// Unit A's resources, by kind.
	jobA, scanA, profileA, destinationA string
	// The platform administrator's second account and the platform's
	// destination.
	secondPlatformAdmin string
}

// platformFixtureAddress is the address that unit B's own job scans.
const platformFixtureAddress = "198.51.100.77"

func newPlatformFixture(t *testing.T) *platformFixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rdap := false
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 2}, Web: config.Web{Listen: "127.0.0.1:8080"}, Enrichment: config.Enrichment{RDAP: config.RDAP{Enabled: &rdap}}}
	application, err := app.New(cfg, db, "missing-nmap", logger)
	if err != nil {
		t.Fatal(err)
	}
	f := &platformFixture{server: NewServer(application, db, logger), db: db, users: map[string]store.User{}, sessions: map[string]routeMatrixSession{}}
	f.a = defaultTenant(db)
	hash := cheapPasswordHash(platformFixturePassword)
	create := func(ts *store.TenantStore, actor, username, role string) store.User {
		t.Helper()
		user, err := ts.CreateUser(ctx, store.User{Username: username, DisplayName: username, Role: role, PasswordHash: hash, Enabled: true}, store.AuditEntry{})
		if err != nil {
			t.Fatal(err)
		}
		f.users[actor] = user
		return user
	}
	create(f.a, actorAdminA, "alpha-admin", store.RoleAdministrator)
	create(f.a, actorOperatorA, "alpha-operator", store.RoleOperator)
	create(f.a, actorViewerA, "alpha-viewer", store.RoleViewer)
	f.users[actorPlatform] = insertPlatformAdmin(t, db, "platform-root", hash, true)
	f.secondPlatformAdmin = insertPlatformAdmin(t, db, "platform-second", hash, true).ID

	unit, err := application.CreateUnit(ctx, "Bravo Unit", "bravo", store.AuditEntry{ActorUserID: f.users[actorPlatform].ID, ActorUsername: "platform-root"})
	if err != nil {
		t.Fatal(err)
	}
	f.unitB = unit.ID
	scope, err := db.TenantScopeByID(ctx, f.unitB)
	if err != nil {
		t.Fatal(err)
	}
	f.b = db.Tenant(scope)
	create(f.b, actorAdminB, "bravo-admin", store.RoleAdministrator)
	f.viewerB = create(f.b, "unit B viewer", "bravo-viewer", store.RoleViewer).ID

	newJob := func(ts *store.TenantStore, name, target string) string {
		t.Helper()
		record, err := ts.CreateJob(ctx, config.NormalizeJob(config.Job{Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{target}, TCP: &config.Protocol{Ports: "8443", Mode: "connect"}}))
		if err != nil {
			t.Fatal(err)
		}
		return record.ID
	}
	f.jobA = newJob(f.a, "shared-job", "192.0.2.10")
	f.sharedJobB = newJob(f.b, "shared-job", "192.0.2.10")
	f.jobB = newJob(f.b, "bravo-job", platformFixtureAddress)
	now := time.Now().UTC()
	saveScan := func(jobID, name, address string) string {
		t.Helper()
		host := model.HostObservation{Address: address, AddressFamily: "IPv4", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "8443", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 8443, State: "open"}}}}}
		scan := model.Scan{ID: "scan-" + name, JobID: jobID, Job: name, StartedAt: now.Add(-time.Minute), FinishedAt: now, Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{host}}}
		if err := db.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
		return scan.ID
	}
	f.scanA = saveScan(f.jobA, "shared-job", "192.0.2.10")
	f.scanB = saveScan(f.jobB, "bravo-job", platformFixtureAddress)
	newProfile := func(ts *store.TenantStore, name string) string {
		t.Helper()
		profile, err := ts.CreateScannerProfile(ctx, name, "", config.ScannerProfile{Engine: config.EngineNmap}, "fixture")
		if err != nil {
			t.Fatal(err)
		}
		return profile.ID
	}
	f.profileA = newProfile(f.a, "alpha-profile")
	f.profileB = newProfile(f.b, "bravo-profile")
	newDestination := func(ts *store.TenantStore, name string) string {
		t.Helper()
		destination, err := application.Notifier.Tenant(ts).CreateManagedWithAudit(ctx, name, "generic://localhost/"+name+"?disabletls=yes", true, store.AuditEntry{})
		if err != nil {
			t.Fatal(err)
		}
		return destination.ID
	}
	f.destinationA = newDestination(f.a, "alpha-destination")
	f.destinationB = newDestination(f.b, "bravo-destination")
	for _, entry := range []store.AuditEntry{
		{Action: "job.created", Detail: "bravo-data-audit", ActorUserID: f.users[actorAdminB].ID, ActorUsername: "bravo-admin", SourceIP: "203.0.113.20"},
		{Action: "user.created", Detail: "bravo-account-audit", ActorUserID: f.users[actorAdminB].ID, ActorUsername: "bravo-admin", SourceIP: "203.0.113.20"},
	} {
		if err := f.b.AuditEntry(ctx, entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.a.AuditEntry(ctx, store.AuditEntry{Action: "job.created", Detail: "alpha-data-audit", ActorUserID: f.users[actorAdminA].ID, ActorUsername: "alpha-admin"}); err != nil {
		t.Fatal(err)
	}

	enrollAdministratorsInTOTP(t, db)
	for _, actor := range platformActors {
		f.sessions[actor] = f.signIn(t, actor)
	}
	return f
}

// insertPlatformAdmin adds a platform administrator with the password hash,
// without a setup token, which allows only one.
func insertPlatformAdmin(t *testing.T, db *store.Store, username, hash string, enabled bool) store.User {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	id := uuid.NewString()
	enabledValue := 0
	if enabled {
		enabledValue = 1
	}
	if _, err := db.DB.Exec(`INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at,revision) VALUES(?,NULL,?,?,?,?,'',0,?,?,?,'',1)`, id, username, username, store.RolePlatformAdmin, hash, enabledValue, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	user, err := db.GetAccount(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return user
}

// signIn creates a session for the actor's account and authenticates it,
// so the session carries what the gate checks.
func (f *platformFixture) signIn(t *testing.T, actor string) routeMatrixSession {
	t.Helper()
	ctx := context.Background()
	user := f.users[actor]
	now := time.Now().UTC()
	raw, csrf := "platform-fixture-"+digest(actor + now.String())[:24], "csrf-"+digest(actor)[:16]
	if err := f.db.CreateSessionForUserWithAudit(ctx, user.ID, digest(raw), csrf, now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	probe := httptest.NewRequest(http.MethodGet, consoleAPIBase+"/auth/session", nil)
	probe.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
	session, ok := f.server.Auth.AuthenticateReadOnly(ctx, probe)
	if !ok || session.TOTPEnrollmentRequired {
		t.Fatalf("session of %s = %+v, authenticated %t", actor, session, ok)
	}
	return routeMatrixSession{role: user.Role, raw: raw, session: session}
}

// call sends a JSON request through the API router as the actor.
func (f *platformFixture) call(t *testing.T, actor, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return callAPI(t, f.server, f.sessions[actor], method, path, body)
}

// confirmBody returns a JSON body that confirms the fixture password, with the
// extra fields.
func confirmBody(fields string) string {
	if fields == "" {
		return `{"password":"` + platformFixturePassword + `"}`
	}
	return `{"password":"` + platformFixturePassword + `",` + fields + `}`
}
