package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func importStartupWebhook(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return "generic://" + parsed.Host + "/hooks/startup-secret-token?disabletls=yes&template=json", &calls
}

func writeImportStartupConfig(t *testing.T, dir, database, listen, rawURL string) string {
	t.Helper()
	configPath := filepath.Join(dir, "config.yaml")
	contents := fmt.Sprintf("database: %s\nweb:\n  listen: %s\nupdates:\n  enabled: false\nenrichment:\n  rdap:\n    enabled: false\nnotifications:\n  urls:\n    - %q\n", database, listen, rawURL)
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

// Host commands keep delivering to the configured URLs before the daemon has
// imported them; they never import the URLs themselves.
func TestNotifyTestBeforeImportUsesConfiguredURLs(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "data", "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	rawURL, calls := importStartupWebhook(t)
	configPath := writeImportStartupConfig(t, dir, database, "127.0.0.1:8080", rawURL)
	stdout, _, err := captureCLIOutput(t, func() error {
		return run([]string{"notify", "test", "--config", configPath, "--output", "json"})
	})
	if err != nil {
		t.Fatalf("notify test before import: %v", err)
	}
	if !strings.Contains(stdout, `"tested": 1`) || calls.Load() != 1 {
		t.Fatalf("notify test before import = %s with %d sends, want one configured URL tested", stdout, calls.Load())
	}
	reader, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	records, err := reader.ListManagedNotifications(context.Background())
	if err != nil || len(records) != 0 {
		t.Fatalf("notify test imported destinations: %d, %v", len(records), err)
	}
}

// The daemon imports the configured URL after migrating and before its
// notifier starts. Afterwards `edgewatch health` asks the operator to remove
// the URL from config.yaml, and host commands use the imported destination.
func TestDaemonStartImportsConfiguredNotificationURLs(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "data", "edgewatch.db")
	rawURL, calls := importStartupWebhook(t)

	// A previous start registered the URL as a deployment destination that a
	// job selects.
	seed, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := notify.New(seed, []string{rawURL})
	if err != nil {
		seed.Close()
		t.Fatal(err)
	}
	selection := previous.LegacySelection()
	if len(selection) != 1 || !strings.HasPrefix(selection[0], "file:") {
		seed.Close()
		t.Fatalf("previous deployment selection = %v", selection)
	}
	job := managedCLIJob("imported-routing")
	job.NotificationDestinations = selection
	record, err := seed.CreateJob(ctx, job)
	if err != nil {
		seed.Close()
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}

	configPath := writeImportStartupConfig(t, dir, database, occupiedLoopbackAddress(t), rawURL)
	stdout, _, err := captureCLIOutput(t, func() error {
		return run([]string{"daemon", "--config", configPath})
	})
	if err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("daemon did not get past startup to the listener: %v", err)
	}
	if !strings.Contains(stdout, "imported notification URLs from config.yaml") || !strings.Contains(stdout, "remove notifications.urls and notifications.urls_file from config.yaml") {
		t.Fatalf("daemon log lacks the import summary or warning:\n%s", stdout)
	}
	if strings.Contains(stdout, "startup-secret-token") || strings.Contains(stdout, "generic://") {
		t.Fatalf("daemon log exposes the notification URL:\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "notification.key")); err != nil {
		t.Fatalf("the import did not create the default notification key: %v", err)
	}

	s, err := store.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	records, err := s.ListManagedNotifications(ctx)
	if err != nil || len(records) != 1 || records[0].Name != "Deployment destination" {
		s.Close()
		t.Fatalf("imported destinations = %#v, %v", records, err)
	}
	stored, err := s.GetJob(ctx, record.ID)
	if err != nil || !slices.Equal(stored.Job.NotificationDestinations, []string{records[0].ID}) {
		s.Close()
		t.Fatalf("job routing after the daemon import = %v, %v", stored.Job.NotificationDestinations, err)
	}
	// The daemon released its lease on exit; stand in for a running daemon so
	// the health command reaches its warnings.
	if _, err := s.AcquireDaemonLease(ctx, "running-daemon"); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	healthOut, _, err := captureCLIOutput(t, func() error {
		return run([]string{"health", "--config", configPath, "--output", "json"})
	})
	if err != nil {
		t.Fatalf("health after import: %v", err)
	}
	var health store.HealthStatus
	if err := json.Unmarshal([]byte(healthOut), &health); err != nil {
		t.Fatalf("health output %q: %v", healthOut, err)
	}
	if health.Status != "ready" || !slices.Equal(health.Warnings, []string{"notification URLs in config.yaml were imported; remove them from config.yaml"}) {
		t.Fatalf("health after import = %#v", health)
	}

	// Host commands now use the imported destination, once, and never the
	// configured URL as a second deployment destination.
	testOut, _, err := captureCLIOutput(t, func() error {
		return run([]string{"notify", "test", "--config", configPath, "--output", "json"})
	})
	if err != nil {
		t.Fatalf("notify test after import: %v", err)
	}
	if !strings.Contains(testOut, `"tested": 1`) || calls.Load() != 1 {
		t.Fatalf("notify test after import = %s with %d sends, want the imported destination tested once", testOut, calls.Load())
	}
}
