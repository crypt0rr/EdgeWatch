package store

import (
	"context"
	"testing"
)

func TestEnsureDeploymentNotificationIDsIsStableAndSkipsBlankHashes(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	empty, err := s.EnsureDeploymentNotificationIDs(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty input returned %v", empty)
	}

	first, err := s.EnsureDeploymentNotificationIDs(ctx, []string{"  legacy-a  ", "", "   ", "legacy-b", "legacy-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first["legacy-a"] == "" || first["legacy-b"] == "" {
		t.Fatalf("unexpected first mapping: %#v", first)
	}
	if first["legacy-a"] == first["legacy-b"] {
		t.Fatal("different legacy hashes received the same opaque ID")
	}

	second, err := s.EnsureDeploymentNotificationIDs(ctx, []string{"legacy-a", "legacy-b"})
	if err != nil {
		t.Fatal(err)
	}
	if second["legacy-a"] != first["legacy-a"] || second["legacy-b"] != first["legacy-b"] {
		t.Fatalf("mapping was not stable: first=%#v second=%#v", first, second)
	}
	var rows int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM deployment_notification_ids`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("stored mapping rows = %d, want 2", rows)
	}
}

func TestEnsureDeploymentNotificationIDsReturnsProjectionErrors(t *testing.T) {
	s := openTestStore(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.EnsureDeploymentNotificationIDs(canceled, []string{"cancelled"}); err == nil {
		t.Fatal("canceled transaction unexpectedly succeeded")
	}
	if _, err := s.DB.Exec(`DROP TABLE deployment_notification_ids`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureDeploymentNotificationIDs(context.Background(), []string{"missing-table"}); err == nil {
		t.Fatal("missing projection unexpectedly succeeded")
	}
}
