package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func testURLDigest(label string) string {
	sum := sha256.Sum256([]byte("generic://127.0.0.1:9/" + label))
	return hex.EncodeToString(sum[:])
}

func testImport(digest, id string) DeploymentNotificationImport {
	return DeploymentNotificationImport{LegacyHash: digest, ID: id, Name: "Deployment destination", Provider: "generic", Ciphertext: []byte("sealed-" + id), Nonce: []byte("nonce-" + id)}
}

func pendingDestinations(t *testing.T, s *Store) map[string]int {
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

func auditDetails(t *testing.T, s *Store, action string) []string {
	t.Helper()
	rows, err := s.DB.Query(`SELECT detail FROM security_audit WHERE action=? ORDER BY id`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		out = append(out, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func testImportEvent(label string) model.Event {
	return model.Event{Type: "scan_failed", Job: "import-" + label, ScanID: "scan-" + label, CreatedAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
}

// A configured URL becomes a web-managed destination, and every reference to
// its deployment destination moves to it in the same transaction. The fixture
// covers a URL with an opaque ID and a URL known only by its legacy digest,
// which is how a database upgraded from before opaque IDs still names it.
func TestImportDeploymentNotificationsRewritesEveryReference(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	digestA, digestB := testURLDigest("a"), testURLDigest("b")
	ids, err := s.EnsureDeploymentNotificationIDs(ctx, []string{digestA})
	if err != nil {
		t.Fatal(err)
	}
	opaqueA := ids[digestA]
	ops, err := s.CreateManagedNotification(ctx, "ops-destination", "Ops", "generic", []byte{1}, []byte{2}, true)
	if err != nil {
		t.Fatal(err)
	}
	create := func(name string, selection []string) JobRecord {
		t.Helper()
		job := testJob(name)
		job.NotificationDestinations = selection
		record, createErr := s.CreateJob(ctx, job)
		if createErr != nil {
			t.Fatal(createErr)
		}
		return record
	}
	shared := create("shared", []string{"file:" + opaqueA, ops.ID})
	legacyDigest := create("legacy-digest", []string{"file:" + digestB})
	bothSpellings := create("both-spellings", []string{"file:" + opaqueA, "file:" + digestA})
	// A job that selects two imported URLs gets one new revision.
	twoImports := create("two-imports", []string{"file:" + opaqueA, "file:" + digestB})
	allDestinations := create("all-destinations", nil)
	silent := create("silent", []string{})
	unrelated := create("unrelated", []string{ops.ID})
	archived := create("archived", []string{"file:" + opaqueA})
	if err := s.SetJobArchived(ctx, archived.ID, true); err != nil {
		t.Fatal(err)
	}
	archived, err = s.GetJob(ctx, archived.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetApplicationUpdateDestinations(ctx, []string{"file:" + opaqueA, "file:" + digestB, ops.ID}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}

	// Pending deliveries under the opaque ID and the legacy digest alias. The
	// same payload under both spellings collides once both are re-addressed.
	for _, queued := range []struct {
		destination string
		event       string
	}{{opaqueA, "shared"}, {digestA, "legacy-only"}, {digestB, "digest-b"}, {opaqueA, "sent"}, {opaqueA, "terminal"}, {ops.ID, "unrelated"}} {
		if err := s.QueueEvent(ctx, queued.destination, testImportEvent(queued.event)); err != nil {
			t.Fatal(err)
		}
	}
	early := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)
	var keeperID int64
	if err := s.DB.QueryRowContext(ctx, `SELECT id FROM outbox WHERE destination=? AND CAST(payload_json AS TEXT) LIKE '%import-shared%'`, opaqueA).Scan(&keeperID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET attempts=3,deferrals=2,next_at=? WHERE id=?`, late.Format(time.RFC3339Nano), keeperID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,attempts,deferrals,next_at) SELECT ?,payload_json,1,4,? FROM outbox WHERE id=?`, digestA, sqliteTimestamp(early), keeperID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET sent_at=? WHERE CAST(payload_json AS TEXT) LIKE '%import-sent%'`, late.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET terminal_at=? WHERE CAST(payload_json AS TEXT) LIKE '%import-terminal%'`, late.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	// Health recorded under both spellings of A is merged into one identity.
	for _, health := range []struct {
		identity, success, failure, code, updated string
		terminal                                  int
	}{
		{identity: opaqueA, failure: early.Format(time.RFC3339Nano), code: "delivery_failed", terminal: 1, updated: early.Format(time.RFC3339Nano)},
		{identity: digestA, success: late.Format(time.RFC3339Nano), terminal: 2, updated: late.Format(time.RFC3339Nano)},
	} {
		if _, err := s.DB.ExecContext(ctx, `UPDATE notification_delivery_health SET terminal_failures=?,last_success_at=?,last_failure_at=?,last_terminal_at=?,last_error_code=?,last_error_fingerprint=?,updated_at=? WHERE destination_identity=?`, health.terminal, health.success, health.failure, health.failure, health.code, health.code, health.updated, health.identity); err != nil {
			t.Fatal(err)
		}
	}

	result, err := s.ImportDeploymentNotifications(ctx, []DeploymentNotificationImport{testImport(digestA, "imported-a"), testImport(digestB, "imported-b")})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 2 || result.Skipped != 0 {
		t.Fatalf("import result = %#v, want two new destinations", result)
	}
	if result.Imported[0].ID != "imported-a" || result.Imported[0].DeploymentID != opaqueA || result.Imported[0].Name != "Deployment destination" {
		t.Fatalf("first imported destination = %#v", result.Imported[0])
	}
	if result.Imported[1].ID != "imported-b" || result.Imported[1].Name != "Deployment destination 2" || result.Imported[1].DeploymentID == "" || result.Imported[1].DeploymentID == digestB {
		t.Fatalf("second imported destination = %#v, want a unique name and a fresh opaque ID", result.Imported[1])
	}
	if result.MovedDeliveries != 3 || result.MergedDeliveries != 1 || !result.UpdateRoutingChanged {
		t.Fatalf("import moved %d and merged %d deliveries, routing changed %t; want 3, 1, true", result.MovedDeliveries, result.MergedDeliveries, result.UpdateRoutingChanged)
	}
	wantChanged := []string{shared.ID, legacyDigest.ID, bothSpellings.ID, twoImports.ID, archived.ID}
	slices.Sort(wantChanged)
	gotChanged := slices.Clone(result.ChangedJobs)
	slices.Sort(gotChanged)
	if !slices.Equal(gotChanged, wantChanged) {
		t.Fatalf("changed jobs = %v, want %v", gotChanged, wantChanged)
	}

	for _, id := range []string{"imported-a", "imported-b"} {
		var enabled int
		var revision, credentialRevision int64
		var provider string
		var ciphertext []byte
		if err := s.DB.QueryRowContext(ctx, `SELECT enabled,revision,credential_revision,provider,ciphertext FROM managed_notifications WHERE id=?`, id).Scan(&enabled, &revision, &credentialRevision, &provider, &ciphertext); err != nil {
			t.Fatalf("imported destination %s: %v", id, err)
		}
		if enabled != 1 || revision != 1 || credentialRevision != 1 || provider != "generic" || string(ciphertext) != "sealed-"+id {
			t.Fatalf("imported destination %s = enabled %d revision %d/%d provider %q", id, enabled, revision, credentialRevision, provider)
		}
	}
	for digest, want := range map[string]string{digestA: "imported-a", digestB: "imported-b"} {
		var managedID, importedAt string
		if err := s.DB.QueryRowContext(ctx, `SELECT managed_notification_id,imported_at FROM deployment_notification_ids WHERE legacy_hash=?`, digest).Scan(&managedID, &importedAt); err != nil {
			t.Fatal(err)
		}
		if managedID != want || importedAt == "" {
			t.Fatalf("deployment mapping for %s = %q at %q, want %q", want, managedID, importedAt, want)
		}
	}

	wantSelections := map[string][]string{
		shared.ID:        sortedSelection("imported-a", ops.ID),
		legacyDigest.ID:  {"imported-b"},
		bothSpellings.ID: {"imported-a"},
		archived.ID:      {"imported-a"},
		twoImports.ID:    {"imported-a", "imported-b"},
	}
	for _, before := range []JobRecord{shared, legacyDigest, bothSpellings, twoImports, archived} {
		stored, err := s.GetJob(ctx, before.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Revision != before.Revision+1 || !slices.Equal(stored.Job.NotificationDestinations, wantSelections[before.ID]) {
			t.Fatalf("job %s = revision %d selection %v, want revision %d selection %v", before.Job.Name, stored.Revision, stored.Job.NotificationDestinations, before.Revision+1, wantSelections[before.ID])
		}
		if stored.Archived != before.Archived || stored.Job.SecurityHash() != before.Job.SecurityHash() {
			t.Fatalf("job %s lifecycle or scope changed", before.Job.Name)
		}
		var revisionJSON, securityHash string
		if err := s.DB.QueryRowContext(ctx, `SELECT definition_json,security_hash FROM job_revisions WHERE job_id=? AND revision=?`, stored.ID, stored.Revision).Scan(&revisionJSON, &securityHash); err != nil {
			t.Fatalf("job %s revision %d was not recorded: %v", before.Job.Name, stored.Revision, err)
		}
		if strings.Contains(revisionJSON, "file:") || securityHash != before.Job.SecurityHash() {
			t.Fatalf("job %s revision still selects a deployment destination or changed scope: %s", before.Job.Name, revisionJSON)
		}
	}
	for _, before := range []JobRecord{allDestinations, silent, unrelated} {
		stored, err := s.GetJob(ctx, before.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Revision != before.Revision || (stored.Job.NotificationDestinations == nil) != (before.Job.NotificationDestinations == nil) || !slices.Equal(stored.Job.NotificationDestinations, before.Job.NotificationDestinations) {
			t.Fatalf("unaffected job %s changed: revision %d selection %#v", before.Job.Name, stored.Revision, stored.Job.NotificationDestinations)
		}
	}

	state, err := s.GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := sortedSelection("imported-a", "imported-b", ops.ID); !state.UpdateNotificationDestinationsConfigured || !slices.Equal(state.UpdateNotificationDestinations, want) {
		t.Fatalf("update routing = %v, want %v", state.UpdateNotificationDestinations, want)
	}

	pending := pendingDestinations(t, s)
	if pending["managed:imported-a:1"] != 2 || pending["managed:imported-b:1"] != 1 || pending[opaqueA] != 0 || pending[digestA] != 0 || pending[digestB] != 0 || pending[ops.ID] != 1 {
		t.Fatalf("pending deliveries after import = %v", pending)
	}
	var attempts, deferrals int
	var nextAt string
	if err := s.DB.QueryRowContext(ctx, `SELECT attempts,deferrals,next_at FROM outbox WHERE id=?`, keeperID).Scan(&attempts, &deferrals, &nextAt); err != nil {
		t.Fatalf("merged delivery did not keep the lowest row ID: %v", err)
	}
	if attempts != 1 || deferrals != 2 || !scanTime(nextAt).Equal(early) {
		t.Fatalf("merged delivery = attempts %d deferrals %d next %q; want the lowest budgets and the earliest due time", attempts, deferrals, nextAt)
	}
	var history int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=? AND (sent_at IS NOT NULL OR terminal_at<>'')`, opaqueA).Scan(&history); err != nil || history != 2 {
		t.Fatalf("sent and terminal history under the deployment ID = %d, %v; want both kept", history, err)
	}

	health, err := s.ListDeliveryHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range []string{opaqueA, digestA, digestB} {
		if _, ok := health[identity]; ok {
			t.Fatalf("deployment health identity %s survived the import: %#v", identity, health)
		}
	}
	merged := health["managed:imported-a"]
	if merged.TerminalFailures != 3 || merged.Pending != 2 || !merged.LastSuccessAt.Equal(late) || !merged.LastFailureAt.Equal(early) || merged.LastErrorCode != "" {
		t.Fatalf("merged health = %#v, want summed failures, latest outcome times, and the newest error state", merged)
	}
	if health["managed:imported-b"].Pending != 1 {
		t.Fatalf("health for the digest-only destination = %#v", health["managed:imported-b"])
	}

	summaries := auditDetails(t, s, "notifications.config_imported")
	if len(summaries) != 1 || !strings.Contains(summaries[0], "imported-a") || !strings.Contains(summaries[0], "imported-b") || !strings.Contains(summaries[0], "imported 2 notification URLs") {
		t.Fatalf("import summary audit = %v", summaries)
	}
	replaced := auditDetails(t, s, "job.notification_destination_replaced")
	if len(replaced) != 6 {
		t.Fatalf("job reroute audits = %v, want one per changed job and imported destination", replaced)
	}
	var twoImportAudits int
	for _, detail := range replaced {
		if strings.HasPrefix(detail, twoImports.ID+":") {
			twoImportAudits++
		}
	}
	if twoImportAudits != 2 {
		t.Fatalf("audits for the job with two imported URLs = %d, want 2", twoImportAudits)
	}
	if routing := auditDetails(t, s, "notifications.update_routing"); len(routing) != 2 {
		t.Fatalf("update routing audits = %v, want one per imported destination", routing)
	}
	var leaked int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE detail LIKE ? OR detail LIKE ? OR detail LIKE '%generic%'`, "%"+digestA+"%", "%"+digestB+"%").Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("audit rows naming a URL digest or provider URL = %d, %v", leaked, err)
	}

	// A second start finds both URLs recorded and imports nothing.
	var auditsBefore int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit`).Scan(&auditsBefore); err != nil {
		t.Fatal(err)
	}
	again, err := s.ImportDeploymentNotifications(ctx, []DeploymentNotificationImport{testImport(digestA, "imported-a-again"), testImport(digestB, "imported-b-again")})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Imported) != 0 || again.Skipped != 2 {
		t.Fatalf("second import = %#v, want both URLs skipped", again)
	}
	var destinations, auditsAfter int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM managed_notifications`).Scan(&destinations); err != nil || destinations != 3 {
		t.Fatalf("managed destinations after a second import = %d, %v; want 3", destinations, err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit`).Scan(&auditsAfter); err != nil || auditsAfter != auditsBefore {
		t.Fatalf("a second import wrote %d audit rows", auditsAfter-auditsBefore)
	}
}

func sortedSelection(values ...string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return out
}

// Deleting an imported destination is the operator's decision. The URL stays
// recorded, so a later start neither recreates the destination nor treats the
// URL as a deployment destination again.
func TestImportedDeploymentNotificationsIncludeDeletedDestinations(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	digest, other := testURLDigest("deleted"), testURLDigest("never-imported")
	if _, err := s.ImportDeploymentNotifications(ctx, []DeploymentNotificationImport{testImport(digest, "deleted-destination")}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteManagedNotification(ctx, "deleted-destination", 1); err != nil {
		t.Fatal(err)
	}
	imported, err := s.ImportedDeploymentNotifications(ctx, []string{digest, other})
	if err != nil {
		t.Fatal(err)
	}
	if !imported[digest] || imported[other] || len(imported) != 1 {
		t.Fatalf("imported digests = %v, want only the deleted destination's URL", imported)
	}
	result, err := s.ImportDeploymentNotifications(ctx, []DeploymentNotificationImport{testImport(digest, "recreated")})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 0 || result.Skipped != 1 {
		t.Fatalf("import after delete = %#v, want the URL skipped", result)
	}
	if _, err := s.GetManagedNotification(ctx, "recreated"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted destination was recreated: %v", err)
	}
}

// Imported names follow the console label and never collide with an existing
// web-managed destination's unique name.
func TestImportDeploymentNotificationsChoosesUniqueNames(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	for _, name := range []string{"Deployment destination", "Deployment destination 2"} {
		if _, err := s.CreateManagedNotification(ctx, "", name, "generic", []byte{1}, []byte{2}, true); err != nil {
			t.Fatal(err)
		}
	}
	result, err := s.ImportDeploymentNotifications(ctx, []DeploymentNotificationImport{testImport(testURLDigest("x"), "x"), testImport(testURLDigest("y"), "y")})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 2 || result.Imported[0].Name != "Deployment destination 3" || result.Imported[1].Name != "Deployment destination 4" {
		t.Fatalf("imported names = %#v", result.Imported)
	}
}

// A failure anywhere in the transaction leaves no destination, no mapping,
// and no rewritten reference behind.
func TestImportDeploymentNotificationsRollsBackCompletely(t *testing.T) {
	for _, test := range []struct {
		name  string
		fault string
	}{
		{"audit rejected", `CREATE TRIGGER reject_import_audit BEFORE INSERT ON security_audit WHEN NEW.action='notifications.config_imported' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`},
		{"job revision rejected", `CREATE TRIGGER reject_job_revision BEFORE INSERT ON job_revisions BEGIN SELECT RAISE(ABORT,'revisions unavailable'); END`},
		{"update routing unreadable", `UPDATE application_update_state SET notification_destinations_json='{'`},
		{"outbox write rejected", `CREATE TRIGGER reject_outbox_move BEFORE UPDATE OF destination ON outbox BEGIN SELECT RAISE(ABORT,'outbox unavailable'); END`},
		{"health write rejected", `CREATE TRIGGER reject_health_merge BEFORE INSERT ON notification_delivery_health WHEN NEW.destination_identity LIKE 'managed:%' BEGIN SELECT RAISE(ABORT,'health unavailable'); END`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			s := openTestStore(t)
			digest := testURLDigest("rollback")
			ids, err := s.EnsureDeploymentNotificationIDs(ctx, []string{digest})
			if err != nil {
				t.Fatal(err)
			}
			opaque := ids[digest]
			job := testJob("rollback-import")
			job.NotificationDestinations = []string{"file:" + opaque}
			record, err := s.CreateJob(ctx, job)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SetApplicationUpdateDestinations(ctx, []string{"file:" + opaque}, AuditEntry{}); err != nil {
				t.Fatal(err)
			}
			if err := s.QueueEvent(ctx, opaque, testImportEvent("rollback")); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.ExecContext(ctx, test.fault); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ImportDeploymentNotifications(ctx, []DeploymentNotificationImport{testImport(digest, "rolled-back"), testImport(testURLDigest("second"), "second")}); err == nil {
				t.Fatal("import succeeded despite the fault")
			}
			var destinations, imported, mappings int
			if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM managed_notifications`).Scan(&destinations); err != nil {
				t.Fatal(err)
			}
			if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(imported_at<>''),0) FROM deployment_notification_ids`).Scan(&mappings, &imported); err != nil {
				t.Fatal(err)
			}
			if destinations != 0 || imported != 0 || mappings != 1 {
				t.Fatalf("after a failed import: %d destinations, %d of %d mappings imported", destinations, imported, mappings)
			}
			stored, err := s.GetJob(ctx, record.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Revision != record.Revision || !slices.Equal(stored.Job.NotificationDestinations, []string{"file:" + opaque}) {
				t.Fatalf("job routing changed although the import rolled back: %#v", stored.Job.NotificationDestinations)
			}
			if pending := pendingDestinations(t, s); pending[opaque] != 1 || len(pending) != 1 {
				t.Fatalf("pending deliveries after a failed import = %v", pending)
			}
			var healthIdentity string
			if err := s.DB.QueryRowContext(ctx, `SELECT destination_identity FROM notification_delivery_health`).Scan(&healthIdentity); err != nil || healthIdentity != opaque {
				t.Fatalf("delivery health after a failed import = %q, %v", healthIdentity, err)
			}
		})
	}
}

func TestImportDeploymentNotificationsRejectsIncompleteItems(t *testing.T) {
	s := openTestStore(t)
	valid := testImport(testURLDigest("valid"), "valid")
	for name, mutate := range map[string]func(*DeploymentNotificationImport){
		"digest":     func(item *DeploymentNotificationImport) { item.LegacyHash = "" },
		"name":       func(item *DeploymentNotificationImport) { item.Name = " " },
		"ciphertext": func(item *DeploymentNotificationImport) { item.Ciphertext = nil },
	} {
		item := valid
		mutate(&item)
		if _, err := s.ImportDeploymentNotifications(context.Background(), []DeploymentNotificationImport{item}); err == nil {
			t.Fatalf("import without %s succeeded", name)
		}
	}
	if result, err := s.ImportDeploymentNotifications(context.Background(), nil); err != nil || len(result.Imported) != 0 {
		t.Fatalf("empty import = %#v, %v", result, err)
	}
}

// Schema 50 records the import on the deployment ID rows of a populated
// schema-49 database without changing the rows it already has.
func TestMigration50AddsNotificationImportState(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "schema49.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := testURLDigest("schema49")
	ids, err := s.EnsureDeploymentNotificationIDs(ctx, []string{digest})
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`ALTER TABLE deployment_notification_ids DROP COLUMN managed_notification_id`,
		`ALTER TABLE deployment_notification_ids DROP COLUMN imported_at`,
		`DROP TABLE notification_config_import`,
		`PRAGMA user_version=49`,
	} {
		if _, err := raw.ExecContext(ctx, statement); err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	// A host command that opens the schema-49 file before the daemon has
	// upgraded it keeps treating every configured URL as not imported.
	existing, err := OpenExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := existing.ImportedDeploymentNotifications(ctx, []string{digest})
	if err != nil || len(imported) != 0 {
		t.Fatalf("imported digests before migration = %v, %v", imported, err)
	}
	if state, err := existing.NotificationConfigImportState(ctx); err != nil || state.Status != NotificationConfigImportNone {
		t.Fatalf("import state before migration = %#v, %v", state, err)
	}
	if err := existing.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	var version int
	if err := upgraded.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != schemaVersion {
		t.Fatalf("schema version = %d, %v; want %d", version, err, schemaVersion)
	}
	var opaque, managedID, importedAt string
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT opaque_id,managed_notification_id,imported_at FROM deployment_notification_ids WHERE legacy_hash=?`, digest).Scan(&opaque, &managedID, &importedAt); err != nil {
		t.Fatal(err)
	}
	if opaque != ids[digest] || managedID != "" || importedAt != "" {
		t.Fatalf("migrated mapping = %q/%q/%q, want the same opaque ID and no import", opaque, managedID, importedAt)
	}
	if state, err := upgraded.NotificationConfigImportState(ctx); err != nil || state.Status != NotificationConfigImportNone {
		t.Fatalf("import state after migration = %#v, %v", state, err)
	}
	if _, err := upgraded.ImportDeploymentNotifications(ctx, []DeploymentNotificationImport{testImport(digest, "after-upgrade")}); err != nil {
		t.Fatalf("import after upgrade: %v", err)
	}
}

// The health command reports the import outcome as a warning. A failed
// import keeps delivering from config.yaml, so the daemon stays healthy.
func TestHealthStatusReportsNotificationImportWarnings(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.AcquireDaemonLease(ctx, "daemon"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		state NotificationConfigImport
		want  []string
	}{
		{"nothing configured", NotificationConfigImport{Status: NotificationConfigImportNone}, nil},
		{"imported", NotificationConfigImport{Status: NotificationConfigImportImported, ConfiguredURLs: 2, ImportedURLs: 2}, []string{"notification URLs in config.yaml were imported; remove them from config.yaml"}},
		{"failed", NotificationConfigImport{Status: NotificationConfigImportFailed, ConfiguredURLs: 1, ErrorCode: "key_unavailable"}, []string{"notification URLs in config.yaml could not be imported (key_unavailable); they are still delivered from config.yaml"}},
		{"failed after an earlier import", NotificationConfigImport{Status: NotificationConfigImportFailed, ConfiguredURLs: 2, ImportedURLs: 1}, []string{"notification URLs in config.yaml were imported; remove them from config.yaml", "notification URLs in config.yaml could not be imported (import_failed); they are still delivered from config.yaml"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := s.RecordNotificationConfigImport(ctx, test.state); err != nil {
				t.Fatal(err)
			}
			health, err := s.HealthStatus(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if health.Status != "ready" || !slices.Equal(health.Warnings, test.want) {
				t.Fatalf("health = %#v, want ready with warnings %v", health, test.want)
			}
			recorded, err := s.NotificationConfigImportState(ctx)
			if err != nil || recorded.Status != test.state.Status || recorded.ConfiguredURLs != test.state.ConfiguredURLs || recorded.ImportedURLs != test.state.ImportedURLs || recorded.UpdatedAt.IsZero() {
				t.Fatalf("recorded state = %#v, %v", recorded, err)
			}
		})
	}
}
