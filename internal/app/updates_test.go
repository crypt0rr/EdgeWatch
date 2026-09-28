package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
	"github.com/crypt0rr/edgewatch/internal/updatecheck"
)

type fakeReleaseChecker struct {
	result updatecheck.Result
	err    error
	calls  int
}

type closingReleaseChecker struct {
	store  *store.Store
	result updatecheck.Result
	err    error
}

func (c *closingReleaseChecker) Check(context.Context, string) (updatecheck.Result, error) {
	_ = c.store.Close()
	return c.result, c.err
}

func (f *fakeReleaseChecker) Check(context.Context, string) (updatecheck.Result, error) {
	f.calls++
	return f.result, f.err
}

// routedDestinations returns the destinations of every route of an update
// alert, or nil when no route has one.
func routedDestinations(routes []store.UpdateAlertRoute) []string {
	var destinations []string
	for _, route := range routes {
		destinations = append(destinations, route.Destinations...)
	}
	return destinations
}

func TestRunUpdateCheckTracksAndDeduplicatesReleases(t *testing.T) {
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Version = "v1.0.0"
	checker := &fakeReleaseChecker{result: updatecheck.Result{Release: updatecheck.Release{Version: "v1.0.0", URL: updatecheck.ReleasePageURL("v1.0.0")}}}
	a.ReleaseChecker = checker
	ctx := context.Background()
	a.runUpdateCheck(ctx)
	state, err := db.Platform().GetApplicationUpdateState(ctx)
	if err != nil || state.InstalledVersion != "v1.0.0" {
		t.Fatalf("initial version state=%#v err=%v", state, err)
	}
	checker.result.Release.Version = "v1.1.0"
	checker.result.Release.URL = updatecheck.ReleasePageURL("v1.1.0")
	a.runUpdateCheck(ctx)
	a.runUpdateCheck(ctx)
	events, err := defaultTenant(db).ListEvents(ctx, "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "application-update-available" {
		t.Fatalf("available events=%#v", events)
	}
	a.Version = "v1.1.0"
	a.runUpdateCheck(ctx)
	a.runUpdateCheck(ctx)
	events, err = defaultTenant(db).ListEvents(ctx, "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Type != "application-updated" || events[1].Type != "application-update-available" {
		t.Fatalf("version transition events=%#v", events)
	}
	if checker.calls != 5 {
		t.Fatalf("release checks=%d, want five immediate checks", checker.calls)
	}
}

func TestRunUpdateCheckPreservesReleaseOnFailureAndHonorsDisable(t *testing.T) {
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	enabled := false
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Updates: config.Updates{Enabled: &enabled}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Version = "v1.0.0"
	checker := &fakeReleaseChecker{err: errors.New("offline")}
	a.ReleaseChecker = checker
	a.runUpdateCheck(context.Background())
	state, err := db.Platform().GetApplicationUpdateState(context.Background())
	if err != nil || state.CheckStatus != "unknown" || checker.calls != 0 {
		t.Fatalf("disabled update state=%#v calls=%d err=%v", state, checker.calls, err)
	}
}

func TestRunUpdateCheckCoversFailureNotModifiedRollbackAndRouting(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Version = "v2.0.0"
	checker := &fakeReleaseChecker{err: errors.New("temporary GitHub outage")}
	a.ReleaseChecker = checker
	a.runUpdateCheck(ctx)
	state, err := db.Platform().GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.CheckStatus != "failed" || state.LastError == "" {
		t.Fatalf("failed check state = %#v", state)
	}

	checker.err = nil
	checker.result = updatecheck.Result{NotModified: true, ETag: "etag-2"}
	a.runUpdateCheck(ctx)
	state, err = db.Platform().GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.CheckStatus != "ok" || state.ETag != "etag-2" {
		t.Fatalf("not-modified state = %#v", state)
	}

	// A newer release with no upstream URL exercises the safe repository URL
	// fallback and the legacy all-destinations routing path.
	checker.result = updatecheck.Result{Release: updatecheck.Release{Version: "v3.0.0"}, ETag: "etag-3"}
	a.runUpdateCheck(ctx)
	state, err = db.Platform().GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.LatestVersion != "v3.0.0" || state.ReleaseURL != updatecheck.ReleasePageURL("v3.0.0") || state.AnnouncedAvailableVersion != "v3.0.0" {
		t.Fatalf("new release state = %#v", state)
	}

	// Materialize an explicit empty selection and verify the configured routing
	// branch remains silent while still updating the cached release.
	if err := defaultTenant(db).SetApplicationUpdateDestinations(ctx, []string{}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	checker.result.Release.Version = "v4.0.0"
	checker.result.Release.URL = ""
	a.runUpdateCheck(ctx)
	state, err = db.Platform().GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	routing, err := defaultTenant(db).ApplicationUpdateRouting(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !routing.Configured || len(routing.Destinations) != 0 || state.LatestVersion != "v4.0.0" {
		t.Fatalf("explicit routing state = %#v, release state = %#v", routing, state)
	}

	// A rollback is recorded without an upgrade event and clears the previous
	// announcement marker so a later reinstall can be announced again.
	a.Version = "v1.0.0"
	a.ReleaseChecker = nil
	a.runUpdateCheck(ctx)
	state, err = db.Platform().GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.InstalledVersion != "v1.0.0" || state.AnnouncedUpgradeVersion != "" {
		t.Fatalf("rollback state = %#v", state)
	}

	// Empty/development builds and missing dependencies are intentionally quiet.
	a.Version = "dev"
	a.runUpdateCheck(ctx)
	a.Store = nil
	a.runUpdateCheck(ctx)
}

func TestRunUpdateCheckCoversPersistenceFailureBranches(t *testing.T) {
	ctx := context.Background()
	newApp := func(t *testing.T) (*App, *store.Store) {
		t.Helper()
		db, err := store.Open(storetest.FreshPath(t))
		if err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}}
		a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		a.Version = "v1.0.0"
		return a, db
	}

	// A closed store exercises both state-unavailable branches and the nil
	// logger fallback used while reporting the failure.
	a, db := newApp(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	a.Logger = nil
	a.runUpdateCheck(ctx)
	if routes, err := a.updateAlertRoutes(ctx); err == nil || routes != nil {
		t.Fatalf("closed store returned update alert routes %+v, %v; want an error", routes, err)
	}

	// Readable update routing with destinations that cannot be read
	// exercises the second routing failure branch. The notifier reads the
	// default tenant's destinations through that tenant's store.
	a, db = newApp(t)
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications RENAME TO managed_notifications_unavailable`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	a.Logger = nil
	if routes, err := a.updateAlertRoutes(ctx); err != nil || routedDestinations(routes) != nil {
		t.Fatalf("unavailable notifier returned update alert routes %+v, %v; want routes without destinations", routes, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// A checker can fail after the state read. The failure marker itself may
	// also be unavailable (for example during shutdown), which is logged but
	// must not panic or emit a duplicate notification.
	a, db = newApp(t)
	a.ReleaseChecker = &closingReleaseChecker{store: db, err: errors.New("offline")}
	a.runUpdateCheck(ctx)

	// The same shutdown boundary is handled for a 304 response.
	a, db = newApp(t)
	a.ReleaseChecker = &closingReleaseChecker{store: db, result: updatecheck.Result{NotModified: true, ETag: "etag"}}
	a.runUpdateCheck(ctx)

	// And for a successful response whose persistence transaction cannot be
	// committed. This keeps release state durable-or-unchanged.
	a, db = newApp(t)
	a.ReleaseChecker = &closingReleaseChecker{store: db, result: updatecheck.Result{Release: updatecheck.Release{Version: "v2.0.0"}}}
	a.runUpdateCheck(ctx)

	// A nil deployment configuration still records the installed build but
	// intentionally skips external checks.
	a, db = newApp(t)
	a.Config = nil
	a.ReleaseChecker = &fakeReleaseChecker{result: updatecheck.Result{Release: updatecheck.Release{Version: "v2.0.0"}}}
	a.runUpdateCheck(ctx)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}
