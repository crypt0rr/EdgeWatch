package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// importWebhook is a local Shoutrrr generic endpoint that counts deliveries.
// The token in its path stands in for a credential that must never leak.
func importWebhook(t *testing.T, token string) (string, *atomic.Int32) {
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
	return "generic://" + parsed.Host + "/hooks/" + token + "?disabletls=yes&template=json", &calls
}

func urlDigest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// writeImportConfig writes a config.yaml that lists one URL inline and the
// others in a protected URL file, and loads it as the daemon does.
func writeImportConfig(t *testing.T, dir, database string, inline string, fileURLs ...string) *config.Config {
	t.Helper()
	urlsFile := filepath.Join(dir, "notification-urls.txt")
	if err := os.WriteFile(urlsFile, []byte("# deployment URLs\n"+strings.Join(fileURLs, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	contents := fmt.Sprintf("database: %s\nweb:\n  listen: 127.0.0.1:8080\nupdates:\n  enabled: false\nenrichment:\n  rdap:\n    enabled: false\nnotifications:\n  urls_file: %s\n  urls:\n    - %q\n", database, urlsFile, inline)
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func importLogger() (*slog.Logger, *bytes.Buffer) {
	var logs bytes.Buffer
	return slog.New(slog.NewJSONHandler(&logs, nil)), &logs
}

func countRows(t *testing.T, s *store.Store, query string, args ...any) int {
	t.Helper()
	var count int
	if err := s.DB.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func pendingOutbox(t *testing.T, s *store.Store) map[string]int {
	t.Helper()
	rows, err := s.DB.Query(`SELECT destination,COUNT(*) FROM outbox WHERE sent_at IS NULL AND terminal_at='' GROUP BY destination`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var destination string
		var count int
		if err := rows.Scan(&destination, &count); err != nil {
			t.Fatal(err)
		}
		out[destination] = count
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func auditLog(t *testing.T, s *store.Store) string {
	t.Helper()
	rows, err := s.DB.Query(`SELECT action||' '||detail FROM security_audit`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var audit strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		audit.WriteString(line + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return audit.String()
}

func assertNoSecrets(t *testing.T, where, text string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatalf("%s exposes %q:\n%s", where, secret, text)
		}
	}
}

// downgradeToSchema49 removes the schema-50 import state, as a database
// written by the previous release has it.
func downgradeToSchema49(t *testing.T, database string) {
	t.Helper()
	raw, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, statement := range []string{
		`ALTER TABLE deployment_notification_ids DROP COLUMN managed_notification_id`,
		`ALTER TABLE deployment_notification_ids DROP COLUMN imported_at`,
		`DROP TABLE notification_config_import`,
		`PRAGMA user_version=49`,
	} {
		if _, err := raw.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// The first daemon start of the new release imports the notification URLs of
// a populated schema-49 installation. Every reference to the deployment
// destinations moves to the imported ones, queued alerts are still delivered,
// and a second start imports nothing.
func TestMigration50ImportsConfiguredNotificationURLsFromSchema49Fixture(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "data", "edgewatch.db")
	inline, inlineCalls := importWebhook(t, "inline-secret-token")
	fromFile, fileCalls := importWebhook(t, "file-secret-token")
	opsURL, _ := importWebhook(t, "ops-secret-token")
	digestInline, digestFile := urlDigest(inline), urlDigest(fromFile)

	// The previous release: both URLs are deployment destinations with opaque
	// IDs, next to one web-managed destination.
	fixture, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := notify.New(fixture, []string{inline, fromFile})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := previous.CreateManaged(ctx, "Ops", opsURL, true)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := fixture.EnsureDeploymentNotificationIDs(ctx, []string{digestInline, digestFile})
	if err != nil {
		t.Fatal(err)
	}
	opaqueInline, opaqueFile := ids[digestInline], ids[digestFile]
	create := func(name string, selection []string) store.JobRecord {
		t.Helper()
		job := routingTestJob(name)
		job.NotificationDestinations = selection
		record, createErr := fixture.CreateJob(ctx, job)
		if createErr != nil {
			t.Fatal(createErr)
		}
		return record
	}
	shared := create("fixture-shared", []string{"file:" + opaqueInline, ops.ID})
	legacyDigest := create("fixture-legacy-digest", []string{"file:" + digestFile})
	allDestinations := create("fixture-all", nil)
	silent := create("fixture-silent", []string{})
	if err := fixture.SetApplicationUpdateDestinations(ctx, []string{"file:" + opaqueInline, "file:" + digestFile}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	event := func(label string) model.Event {
		return model.Event{Type: "scan_failed", Job: "fixture-" + label, Message: "queued before upgrade", CreatedAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	}
	for _, queued := range []struct{ destination, label string }{
		{opaqueInline, "inline"},
		{digestInline, "inline"}, // the same alert under the legacy alias
		{digestFile, "legacy-file"},
		{opaqueFile, "file"},
	} {
		if err := fixture.QueueEvent(ctx, queued.destination, event(queued.label)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.DB.ExecContext(ctx, `UPDATE notification_delivery_health SET terminal_failures=2,last_error_code='delivery_failed' WHERE destination_identity=?`, opaqueInline); err != nil {
		t.Fatal(err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	downgradeToSchema49(t, database)

	cfg := writeImportConfig(t, dir, database, inline, fromFile)
	upgraded, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	logger, logs := importLogger()
	application, err := NewWithOptions(cfg, upgraded, "missing-nmap", logger, Options{ImportNotificationURLs: true})
	if err != nil {
		t.Fatal(err)
	}

	// One encrypted, enabled web-managed destination per configured URL.
	var importedInline, importedFile string
	for digest, target := range map[string]*string{digestInline: &importedInline, digestFile: &importedFile} {
		if err := upgraded.DB.QueryRowContext(ctx, `SELECT managed_notification_id FROM deployment_notification_ids WHERE legacy_hash=? AND imported_at<>''`, digest).Scan(target); err != nil {
			t.Fatalf("configured URL was not recorded as imported: %v", err)
		}
	}
	if importedInline == importedFile || importedInline == "" {
		t.Fatalf("imported destination IDs = %q and %q, want one per URL", importedInline, importedFile)
	}
	records, err := upgraded.ListManagedNotifications(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("managed destinations after import = %d, want Ops plus two imported", len(records))
	}
	for _, record := range records {
		assertNoSecrets(t, "stored ciphertext", string(record.Ciphertext), "secret-token", "127.0.0.1")
	}
	views := application.Notifier.DestinationsContext(ctx)
	names := map[string]string{}
	for _, view := range views {
		if view.Source != "web" || view.Locked || view.ReadOnly || !view.Enabled {
			t.Fatalf("destination after import = %#v, want only editable web-managed destinations", view)
		}
		names[view.ID] = view.Name
	}
	if names[importedInline] != "Deployment destination" || names[importedFile] != "Deployment destination 2" {
		t.Fatalf("imported destination names = %v", names)
	}

	// Job routing, update routing, pending alerts, and delivery health.
	for _, check := range []struct {
		before store.JobRecord
		want   []string
		bumps  int64
	}{
		{shared, sortedIDs(importedInline, ops.ID), 1},
		{legacyDigest, []string{importedFile}, 1},
		{silent, []string{}, 0},
	} {
		stored, err := upgraded.GetJob(ctx, check.before.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Revision != check.before.Revision+check.bumps || stored.Job.NotificationDestinations == nil || !slices.Equal(stored.Job.NotificationDestinations, check.want) {
			t.Fatalf("job %s = revision %d selection %v, want revision %d selection %v", check.before.Job.Name, stored.Revision, stored.Job.NotificationDestinations, check.before.Revision+check.bumps, check.want)
		}
	}
	// The import leaves the nil "all enabled destinations" selection alone;
	// the existing startup freeze then pins it to the destinations that now
	// exist, which are the imported ones instead of the deployment ones.
	stored, err := upgraded.GetJob(ctx, allDestinations.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := sortedIDs(importedInline, importedFile, ops.ID); !slices.Equal(stored.Job.NotificationDestinations, want) {
		t.Fatalf("all-destinations job selection = %v, want %v", stored.Job.NotificationDestinations, want)
	}
	if n := countRows(t, upgraded, `SELECT COUNT(*) FROM security_audit WHERE action='job.notification_destination_replaced' AND detail LIKE ?`, "%"+allDestinations.ID+"%"); n != 0 {
		t.Fatalf("the import rewrote the nil selection (%d audit rows)", n)
	}
	state, err := upgraded.GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := sortedIDs(importedInline, importedFile); !slices.Equal(state.UpdateNotificationDestinations, want) {
		t.Fatalf("update routing = %v, want %v", state.UpdateNotificationDestinations, want)
	}
	pending := pendingOutbox(t, upgraded)
	if pending["managed:"+importedInline+":1"] != 1 || pending["managed:"+importedFile+":1"] != 2 || len(pending) != 2 {
		t.Fatalf("pending deliveries = %v, want the legacy-digest duplicate merged and every row re-addressed", pending)
	}
	health, err := upgraded.ListDeliveryHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range []string{opaqueInline, opaqueFile, digestInline, digestFile} {
		if _, ok := health[identity]; ok {
			t.Fatalf("deployment delivery health identity survived the import")
		}
	}
	if item := health["managed:"+importedInline]; item.TerminalFailures != 2 || item.Pending != 1 {
		t.Fatalf("imported delivery health = %#v", item)
	}

	// Redacted audit and logs.
	if n := countRows(t, upgraded, `SELECT COUNT(*) FROM security_audit WHERE action='notifications.config_imported'`); n != 1 {
		t.Fatalf("import audit rows = %d, want 1", n)
	}
	assertNoSecrets(t, "security audit", auditLog(t, upgraded), "secret-token", "127.0.0.1", digestInline, digestFile)
	assertNoSecrets(t, "daemon log", logs.String(), "secret-token", "127.0.0.1", digestInline, digestFile, "generic://")
	if !strings.Contains(logs.String(), "imported notification URLs from config.yaml") || !strings.Contains(logs.String(), "remove notifications.urls and notifications.urls_file from config.yaml") {
		t.Fatalf("daemon log lacks the import summary or the removal warning:\n%s", logs.String())
	}

	// The health command reports the leftover configuration.
	if _, err := upgraded.AcquireDaemonLease(ctx, "import-test"); err != nil {
		t.Fatal(err)
	}
	status, err := upgraded.HealthStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(status.Warnings, []string{"notification URLs in config.yaml were imported; remove them from config.yaml"}) {
		t.Fatalf("health warnings = %v", status.Warnings)
	}
	if got := application.Notifier.StatusContext(ctx)["config_import"]; got != "imported" {
		t.Fatalf("console notification status config_import = %v, want imported", got)
	}

	// Queued alerts reach the same endpoints through the imported destinations.
	if err := application.Notifier.Drain(ctx); err != nil {
		t.Fatalf("drain after import: %v", err)
	}
	if inlineCalls.Load() != 1 || fileCalls.Load() != 2 {
		t.Fatalf("delivered queued alerts = inline %d, file %d; want 1 and 2", inlineCalls.Load(), fileCalls.Load())
	}

	// A second start imports nothing and warns again.
	jobRevisions := countRows(t, upgraded, `SELECT COUNT(*) FROM job_revisions`)
	audits := countRows(t, upgraded, `SELECT COUNT(*) FROM security_audit`)
	secondLogger, secondLogs := importLogger()
	restarted, err := NewWithOptions(cfg, upgraded, "missing-nmap", secondLogger, Options{ImportNotificationURLs: true})
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, upgraded, `SELECT COUNT(*) FROM managed_notifications`); n != 3 {
		t.Fatalf("managed destinations after a second start = %d, want 3", n)
	}
	if countRows(t, upgraded, `SELECT COUNT(*) FROM job_revisions`) != jobRevisions || countRows(t, upgraded, `SELECT COUNT(*) FROM security_audit`) != audits {
		t.Fatal("a second start rewrote jobs or wrote audit rows")
	}
	if strings.Contains(secondLogs.String(), "imported notification URLs from config.yaml") || !strings.Contains(secondLogs.String(), "remove notifications.urls and notifications.urls_file from config.yaml") {
		t.Fatalf("second start log = %s", secondLogs.String())
	}
	if deployment := restarted.Notifier.StatusContext(ctx)["deployment"]; deployment != 0 {
		t.Fatalf("a second start registered %v deployment destinations", deployment)
	}
}

func sortedIDs(values ...string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return out
}

// When the import fails, nothing is imported and the daemon still starts and
// delivers through the configured URLs. The failure is logged without the
// URL, and the health command and the console report it.
func TestDaemonImportFailureKeepsDeliveringFromConfig(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "data", "edgewatch.db")
	configured, calls := importWebhook(t, "config-secret-token")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	existing, err := notify.New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := existing.CreateManaged(ctx, "Locked", "generic://127.0.0.1:9/locked?disabletls=yes", true); err != nil {
		t.Fatal(err)
	}
	// The default key is lost while an encrypted destination exists, so the
	// key cannot be recreated and the import cannot encrypt anything.
	if err := os.Remove(filepath.Join(dir, "data", "notification.key")); err != nil {
		t.Fatal(err)
	}
	cfg := writeImportConfig(t, dir, database, configured)
	logger, logs := importLogger()
	application, err := NewWithOptions(cfg, s, "missing-nmap", logger, Options{ImportNotificationURLs: true})
	if err != nil {
		t.Fatalf("daemon did not start after a failed import: %v", err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM managed_notifications`); n != 1 {
		t.Fatalf("managed destinations after a failed import = %d, want only the existing one", n)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM deployment_notification_ids WHERE imported_at<>''`); n != 0 {
		t.Fatalf("%d URLs were recorded as imported by a failed import", n)
	}
	if !strings.Contains(logs.String(), `"error_code":"key_unavailable"`) || !strings.Contains(logs.String(), "could not be imported") {
		t.Fatalf("failed import log = %s", logs.String())
	}
	assertNoSecrets(t, "daemon log", logs.String(), "config-secret-token", "127.0.0.1", urlDigest(configured), "generic://")
	if _, err := s.AcquireDaemonLease(ctx, "import-failure-test"); err != nil {
		t.Fatal(err)
	}
	status, err := s.HealthStatus(ctx)
	if err != nil {
		t.Fatalf("a failed import made the daemon unhealthy: %v", err)
	}
	if !slices.Equal(status.Warnings, []string{"notification URLs in config.yaml could not be imported (key_unavailable); they are still delivered from config.yaml"}) {
		t.Fatalf("health warnings = %v", status.Warnings)
	}
	notificationStatus := application.Notifier.StatusContext(ctx)
	if notificationStatus["config_import"] != "failed" || notificationStatus["deployment"] != 1 {
		t.Fatalf("notification status after a failed import = %#v", notificationStatus)
	}
	if err := application.Notifier.Queue(ctx, []model.Event{{Type: "scan_failed", Job: "after-failed-import", CreatedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	if err := application.Notifier.Drain(ctx); err != nil {
		t.Logf("drain deferred the locked destination: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("configured URL deliveries after a failed import = %d, want 1", got)
	}
}

// Host commands build the application without the import. Before the daemon
// imports, they keep the configured URLs as deployment destinations.
func TestHostCommandsDoNotImportNotificationURLs(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "data", "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := writeImportConfig(t, dir, database, "generic://127.0.0.1:9/host-command?disabletls=yes")
	application, err := New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM managed_notifications`); n != 0 {
		t.Fatalf("a host command imported %d destinations", n)
	}
	if deployment := application.Notifier.StatusContext(ctx)["deployment"]; deployment != 1 {
		t.Fatalf("deployment destinations for a host command = %v, want 1", deployment)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "notification.key")); !os.IsNotExist(err) {
		t.Fatalf("a host command created the notification key: %v", err)
	}
	if state, err := s.NotificationConfigImportState(ctx); err != nil || state.Status != store.NotificationConfigImportNone {
		t.Fatalf("a host command recorded import state %#v, %v", state, err)
	}
}

// Invalid configuration still stops the daemon before anything is imported.
func TestDaemonImportRejectsInvalidConfiguration(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	logger, logs := importLogger()
	cfg := routingTestConfig(database, "unknown-service://invalid-secret-token@example.invalid/path")
	if _, err := NewWithOptions(cfg, s, "missing-nmap", logger, Options{ImportNotificationURLs: true}); err == nil || !strings.Contains(err.Error(), "invalid Shoutrrr destination") || strings.Contains(err.Error(), "invalid-secret-token") {
		t.Fatalf("invalid URL startup error = %v", err)
	}
	missingKey := routingTestConfig(database, "generic://127.0.0.1:9/valid?disabletls=yes")
	missingKey.Notifications.EncryptionKeyFile = filepath.Join(dir, "missing.key")
	if _, err := NewWithOptions(missingKey, s, "missing-nmap", logger, Options{ImportNotificationURLs: true}); err == nil || !strings.Contains(err.Error(), "validate notification encryption key file") {
		t.Fatalf("missing configured key startup error = %v", err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM managed_notifications`); n != 0 {
		t.Fatalf("invalid configuration imported %d destinations", n)
	}
	assertNoSecrets(t, "daemon log", logs.String(), "invalid-secret-token")
}

// Without configured URLs the daemon records that nothing is configured and
// reports no warning.
func TestDaemonImportWithoutConfiguredURLs(t *testing.T) {
	ctx := context.Background()
	database := filepath.Join(t.TempDir(), "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	logger, logs := importLogger()
	if _, err := NewWithOptions(routingTestConfig(database), s, "missing-nmap", logger, Options{ImportNotificationURLs: true}); err != nil {
		t.Fatal(err)
	}
	state, err := s.NotificationConfigImportState(ctx)
	if err != nil || state.Status != store.NotificationConfigImportNone || state.UpdatedAt.IsZero() {
		t.Fatalf("import state without URLs = %#v, %v", state, err)
	}
	if strings.Contains(logs.String(), "notification URLs in config.yaml") {
		t.Fatalf("startup without URLs logged an import message: %s", logs.String())
	}
}
