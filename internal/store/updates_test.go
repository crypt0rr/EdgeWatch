package store

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
)

func TestApplicationUpdateStateAndNotificationDeduplication(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if state, err := s.GetApplicationUpdateState(ctx); err != nil || state.CheckStatus != "unknown" {
		t.Fatalf("initial update state = %#v, err=%v", state, err)
	}
	if events, err := s.RecordInstalledVersion(ctx, "v1.0.0", "", false, nil); err != nil || len(events) != 0 {
		t.Fatalf("first version seed events=%#v err=%v", events, err)
	}
	if events, err := s.RecordReleaseCheck(ctx, "v1.0.0", "v1.1.0", "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.1.0", "1.1", "2026-09-07T12:00:00Z", `"etag"`, true, []string{"file:test"}); err != nil || len(events) != 1 {
		t.Fatalf("new release events=%#v err=%v", events, err)
	}
	if events, err := s.RecordReleaseCheck(ctx, "v1.0.0", "v1.1.0", "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.1.0", "1.1", "2026-09-07T12:00:00Z", `"etag"`, true, []string{"file:test"}); err != nil || len(events) != 0 {
		t.Fatalf("duplicate release events=%#v err=%v", events, err)
	}
	var deliveries int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox").Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 {
		t.Fatalf("outbox deliveries=%d, want one available-release notification", deliveries)
	}
	state, err := s.GetApplicationUpdateState(ctx)
	if err != nil || state.LatestVersion != "v1.1.0" || state.AnnouncedAvailableVersion != "v1.1.0" {
		t.Fatalf("release state=%#v err=%v", state, err)
	}
	if events, err := s.RecordInstalledVersion(ctx, "v1.1.0", state.ReleaseURL, true, []string{"file:test"}); err != nil || len(events) != 1 {
		t.Fatalf("upgrade events=%#v err=%v", events, err)
	}
	if events, err := s.RecordInstalledVersion(ctx, "v1.1.0", state.ReleaseURL, true, []string{"file:test"}); err != nil || len(events) != 0 {
		t.Fatalf("duplicate upgrade events=%#v err=%v", events, err)
	}
	if events, err := s.RecordInstalledVersion(ctx, "v1.0.0", state.ReleaseURL, false, nil); err != nil || len(events) != 0 {
		t.Fatalf("rollback events=%#v err=%v", events, err)
	}
	if events, err := s.RecordInstalledVersion(ctx, "v1.1.0", state.ReleaseURL, true, []string{"file:test"}); err != nil || len(events) != 1 {
		t.Fatalf("re-upgrade events=%#v err=%v", events, err)
	}
	if err := s.RecordReleaseCheckFailure(ctx, "temporary upstream failure"); err != nil {
		t.Fatal(err)
	}
	state, err = s.GetApplicationUpdateState(ctx)
	if err != nil || state.LatestVersion != "v1.1.0" || state.CheckStatus != "failed" || state.LastError != "temporary upstream failure" {
		t.Fatalf("failure state=%#v err=%v", state, err)
	}
}

func TestApplicationUpdateNotificationDestinationsAreExplicitAndNormalized(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	state, err := s.GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.UpdateNotificationDestinationsConfigured || state.UpdateNotificationDestinations != nil {
		t.Fatalf("new state unexpectedly has explicit routing: %#v", state)
	}
	if err := s.SetApplicationUpdateDestinations(ctx, []string{" managed:b ", "managed:a", "managed:b", ""}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	state, err = s.GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"managed:a", "managed:b"}
	if !state.UpdateNotificationDestinationsConfigured || !reflect.DeepEqual(state.UpdateNotificationDestinations, want) {
		t.Fatalf("normalized routing = %#v, want %#v (configured=%t)", state.UpdateNotificationDestinations, want, state.UpdateNotificationDestinationsConfigured)
	}
	if err := s.SetApplicationUpdateDestinations(ctx, []string{}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	state, err = s.GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !state.UpdateNotificationDestinationsConfigured || state.UpdateNotificationDestinations == nil || len(state.UpdateNotificationDestinations) != 0 {
		t.Fatalf("explicit empty routing = %#v (configured=%t)", state.UpdateNotificationDestinations, state.UpdateNotificationDestinationsConfigured)
	}
}
