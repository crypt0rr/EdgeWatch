package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func managedIntentOutbox(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := s.DB.QueryContext(context.Background(), `SELECT destination FROM outbox ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var destinations []string
	for rows.Next() {
		var destination string
		if err := rows.Scan(&destination); err != nil {
			t.Fatal(err)
		}
		destinations = append(destinations, destination)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return destinations
}

func managedIntentDiscardAudits(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := s.DB.QueryContext(context.Background(), `SELECT detail FROM security_audit WHERE action='notifications.pending_discarded' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return details
}

// An alert resolves its managed destination before the event transaction.
// A rename that commits in between keeps the credentials, so the alert must
// be queued under the destination's current revision rather than dropped.
func TestManagedIntentCapturedBeforeRenameIsQueuedUnderCurrentRevision(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, testJob("rename-window"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateManagedNotification(ctx, "ops", "Ops", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	captured := []string{"managed:ops:1"}
	if _, err := s.UpdateManagedNotificationWithAudit(ctx, "ops", 1, "Ops renamed", "generic", []byte{1}, []byte{2}, true, AuditEntry{Action: "notifications.updated", Detail: "renamed"}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ResetRuntimeWithOutboxAndAudit(ctx, job.ID, job.Job.Name, captured, AuditEntry{Action: "baseline.reset", Detail: "reset"})
	if err != nil || len(events) != 1 {
		t.Fatalf("reset events = %#v, %v", events, err)
	}
	if got := managedIntentOutbox(t, s); len(got) != 1 || got[0] != "managed:ops:2" {
		t.Fatalf("outbox after capture, rename, commit = %v, want [managed:ops:2]", got)
	}
	if audits := managedIntentDiscardAudits(t, s); len(audits) != 0 {
		t.Fatalf("rename recorded a discard: %v", audits)
	}

	// Several metadata edits still keep the credentials of the captured
	// revision, and a direct queue follows the same rule.
	if _, err := s.UpdateManagedNotification(ctx, "ops", 2, "Ops again", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueEvent(ctx, "managed:ops:1", model.Event{Type: "direct", Job: job.Job.Name, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if got := managedIntentOutbox(t, s); len(got) != 2 || got[0] != "managed:ops:3" || got[1] != "managed:ops:3" {
		t.Fatalf("outbox after second rename = %v, want both rows under managed:ops:3", got)
	}
}

func TestManagedIntentCapturedBeforeCredentialRotationIsDiscardedAndAudited(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, testJob("rotation-window"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateManagedNotification(ctx, "ops", "Ops", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	captured := []string{"managed:ops:1"}
	if _, err := s.UpdateManagedNotification(ctx, "ops", 1, "Ops", "generic", []byte{3}, []byte{4}, true); err != nil {
		t.Fatal(err)
	}
	// A later rename does not make the pre-rotation intent current again.
	if _, err := s.UpdateManagedNotification(ctx, "ops", 2, "Ops renamed", "generic", []byte{3}, []byte{4}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetRuntimeWithOutboxAndAudit(ctx, job.ID, job.Job.Name, captured, AuditEntry{Action: "baseline.reset", Detail: "reset"}); err != nil {
		t.Fatal(err)
	}
	if got := managedIntentOutbox(t, s); len(got) != 0 {
		t.Fatalf("pre-rotation intent was queued: %v", got)
	}
	audits := managedIntentDiscardAudits(t, s)
	if len(audits) != 1 || !strings.Contains(audits[0], "managed notification ops") || !strings.Contains(audits[0], "credential rotation") {
		t.Fatalf("rotation discard audits = %v", audits)
	}

	// An intent captured after the rotation keeps following renames.
	if _, err := s.UpdateRuntimeWithOutbox(ctx, job.ID, []string{"managed:ops:2"}, func(*model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "alert", Job: job.Job.Name, CreatedAt: time.Now().UTC()}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := managedIntentOutbox(t, s); len(got) != 1 || got[0] != "managed:ops:3" {
		t.Fatalf("post-rotation intent outbox = %v, want [managed:ops:3]", got)
	}
}

func TestManagedIntentCapturedBeforeDeletionIsDiscardedAndAudited(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, testJob("delete-window"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateManagedNotification(ctx, "ops", "Ops", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	captured := []string{"managed:ops:1"}
	if err := s.DeleteManagedNotification(ctx, "ops", 1); err != nil {
		t.Fatal(err)
	}
	ctx = WithAuditContext(ctx, "request-1", "192.0.2.10")
	if _, err := s.ResetRuntimeWithOutboxAndAudit(ctx, job.ID, job.Job.Name, captured, AuditEntry{Action: "baseline.reset", Detail: "reset"}); err != nil {
		t.Fatal(err)
	}
	if got := managedIntentOutbox(t, s); len(got) != 0 {
		t.Fatalf("intent for a deleted destination was queued: %v", got)
	}
	audits := managedIntentDiscardAudits(t, s)
	if len(audits) != 1 || !strings.Contains(audits[0], "managed notification ops") || !strings.Contains(audits[0], "deleted") {
		t.Fatalf("deletion discard audits = %v", audits)
	}
	var requestID string
	if err := s.DB.QueryRowContext(ctx, `SELECT request_id FROM security_audit WHERE action='notifications.pending_discarded'`).Scan(&requestID); err != nil || requestID != "request-1" {
		t.Fatalf("discard audit request id = %q, %v", requestID, err)
	}
}

func TestManagedIntentCapturedBeforePauseIsSkippedWithoutDiscardAudit(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, testJob("pause-window"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateManagedNotification(ctx, "ops", "Ops", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateManagedNotification(ctx, "ops", 1, "Ops", "generic", []byte{1}, []byte{2}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetRuntimeWithOutbox(ctx, job.ID, job.Job.Name, []string{"managed:ops:1"}); err != nil {
		t.Fatal(err)
	}
	if got := managedIntentOutbox(t, s); len(got) != 0 {
		t.Fatalf("intent for a paused destination was queued: %v", got)
	}
	if audits := managedIntentDiscardAudits(t, s); len(audits) != 0 {
		t.Fatalf("pause recorded a discard: %v", audits)
	}
}

func TestManagedIntentResolutionSkipsMalformedAndUnknownKeys(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.CreateManagedNotification(ctx, "ops", "Ops", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	event := model.Event{Type: "direct", Job: "job", CreatedAt: time.Now().UTC()}
	for _, key := range []string{"managed:ops", "managed::1", "managed:ops:x", "managed:ops:0"} {
		if err := s.QueueEvent(ctx, key, event); err != nil {
			t.Fatalf("queue malformed key %q: %v", key, err)
		}
	}
	if got := managedIntentOutbox(t, s); len(got) != 0 {
		t.Fatalf("malformed managed keys were queued: %v", got)
	}
	if audits := managedIntentDiscardAudits(t, s); len(audits) != 0 {
		t.Fatalf("malformed managed keys were audited: %v", audits)
	}
	// A revision newer than the destination's (for example from a database
	// restored behind the notifier) has unknown credentials.
	if err := s.QueueEvent(ctx, "managed:ops:2", event); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueEvent(ctx, "managed:gone:1", event); err != nil {
		t.Fatal(err)
	}
	if got := managedIntentOutbox(t, s); len(got) != 0 {
		t.Fatalf("unknown managed revisions were queued: %v", got)
	}
	audits := managedIntentDiscardAudits(t, s)
	if len(audits) != 2 || !strings.Contains(audits[0], "managed notification ops after credential rotation") || !strings.Contains(audits[1], "managed notification gone after the destination was deleted") {
		t.Fatalf("unknown managed revision audits = %v", audits)
	}
}

// Schema 49 adds the credential revision. Existing destinations have no
// history, so the migration conservatively treats their current revision as
// the one that set the credentials.
func TestMigration49RecordsCurrentRevisionAsCredentialRevision(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "credential-revision.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateManagedNotification(ctx, "ops", "Ops", "generic", []byte{1}, []byte{2}, true); err != nil {
		s.Close()
		t.Fatal(err)
	}
	for revision := int64(1); revision < 3; revision++ {
		if _, err := s.UpdateManagedNotification(ctx, "ops", revision, "Ops", "generic", []byte{1}, []byte{2}, true); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	job, err := s.CreateJob(ctx, testJob("credential-migration"))
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
	for _, statement := range []string{`ALTER TABLE managed_notifications DROP COLUMN credential_revision`, `PRAGMA user_version=48`} {
		if _, err := raw.ExecContext(ctx, statement); err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	var revision, credentialRevision int64
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT revision,credential_revision FROM managed_notifications WHERE id='ops'`).Scan(&revision, &credentialRevision); err != nil {
		t.Fatal(err)
	}
	if revision != 3 || credentialRevision != 3 {
		t.Fatalf("migrated revision/credential revision = %d/%d, want 3/3", revision, credentialRevision)
	}
	if _, err := upgraded.ResetRuntimeWithOutbox(ctx, job.ID, job.Job.Name, []string{"managed:ops:2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := upgraded.ResetRuntimeWithOutbox(ctx, job.ID, job.Job.Name, []string{"managed:ops:3"}); err != nil {
		t.Fatal(err)
	}
	if got := managedIntentOutbox(t, upgraded); len(got) != 1 || got[0] != "managed:ops:3" {
		t.Fatalf("outbox after migration = %v, want only the current-revision intent", got)
	}
}
