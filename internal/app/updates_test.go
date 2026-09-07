package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/updatecheck"
)

type fakeReleaseChecker struct {
	result updatecheck.Result
	err    error
	calls  int
}

func (f *fakeReleaseChecker) Check(context.Context, string) (updatecheck.Result, error) {
	f.calls++
	return f.result, f.err
}

func TestRunUpdateCheckTracksAndDeduplicatesReleases(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
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
	state, err := db.GetApplicationUpdateState(ctx)
	if err != nil || state.InstalledVersion != "v1.0.0" {
		t.Fatalf("initial version state=%#v err=%v", state, err)
	}
	checker.result.Release.Version = "v1.1.0"
	checker.result.Release.URL = updatecheck.ReleasePageURL("v1.1.0")
	a.runUpdateCheck(ctx)
	a.runUpdateCheck(ctx)
	events, err := db.ListEvents(ctx, "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "application-update-available" {
		t.Fatalf("available events=%#v", events)
	}
	a.Version = "v1.1.0"
	a.runUpdateCheck(ctx)
	a.runUpdateCheck(ctx)
	events, err = db.ListEvents(ctx, "", 20)
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
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
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
	state, err := db.GetApplicationUpdateState(context.Background())
	if err != nil || state.CheckStatus != "unknown" || checker.calls != 0 {
		t.Fatalf("disabled update state=%#v calls=%d err=%v", state, checker.calls, err)
	}
}
