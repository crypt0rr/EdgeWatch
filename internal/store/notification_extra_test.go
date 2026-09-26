package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestManagedNotificationStoreCRUDAndLegacySelectionMaterialization(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if destinations, err := s.ListManagedNotifications(ctx); err != nil || len(destinations) != 0 {
		t.Fatalf("initial managed destinations = %#v, %v", destinations, err)
	}
	legacy, err := s.CreateJob(ctx, testJob("legacy-notification"))
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.CreateManagedNotificationWithLegacySelectionAndAudit(ctx, "destination-1", "Ops", "generic", []byte{1, 2}, []byte{3}, true, []string{"deployment:1"}, AuditEntry{Action: "notification.created"})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "destination-1" || created.Revision != 1 || !created.Enabled || string(created.Ciphertext) != string([]byte{1, 2}) {
		t.Fatalf("created destination = %#v", created)
	}
	loaded, err := s.GetManagedNotification(ctx, created.ID)
	if err != nil || loaded.Name != "Ops" || loaded.Provider != "generic" {
		t.Fatalf("loaded destination = %#v, %v", loaded, err)
	}
	if _, err := s.GetManagedNotification(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing destination error = %v", err)
	}
	all, err := s.ListManagedNotifications(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("destination list = %#v, %v", all, err)
	}
	storedJob, err := s.GetJob(ctx, legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedJob.Job.NotificationDestinations == nil || len(storedJob.Job.NotificationDestinations) != 1 || storedJob.Job.NotificationDestinations[0] != "deployment:1" || storedJob.Revision != 2 {
		t.Fatalf("legacy selection was not materialized: %#v", storedJob)
	}
	if _, err := s.CreateManagedNotificationWithAudit(ctx, "destination-audit", "Audited", "generic", []byte{9}, []byte{8}, false, AuditEntry{Action: "notification.created"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateManagedNotificationWithLegacySelection(ctx, "destination-legacy", "Legacy", "generic", []byte{7}, []byte{6}, true, []string{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateManagedNotification(ctx, "bad", "", "generic", []byte{1}, []byte{2}, true); err == nil {
		t.Fatal("empty managed destination name was accepted")
	}
	if _, err := s.CreateManagedNotification(ctx, "bad", "Name", "generic", nil, []byte{2}, true); err == nil {
		t.Fatal("empty managed destination ciphertext was accepted")
	}
	if _, err := s.UpdateManagedNotification(ctx, created.ID, 99, "Ops", "generic", []byte{4}, []byte{5}, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale destination update error = %v", err)
	}
	updated, err := s.UpdateManagedNotificationWithAudit(ctx, created.ID, 1, "Ops updated", "generic", []byte{4}, []byte{5}, false, AuditEntry{Action: "notification.updated"})
	if err != nil || updated.Revision != 2 || updated.Enabled {
		t.Fatalf("updated destination = %#v, %v", updated, err)
	}
	if err := s.DeleteManagedNotification(ctx, created.ID, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale destination delete error = %v", err)
	}
	if _, err := s.DeleteManagedNotificationWithAudit(ctx, created.ID, 2, AuditEntry{Action: "notification.deleted"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetManagedNotification(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted destination = %v", err)
	}

	second, err := s.CreateJob(ctx, testJob("second-legacy"))
	if err != nil {
		t.Fatal(err)
	}
	count, err := s.MaterializeLegacyNotificationSelections(ctx, []string{"managed:destination:1"})
	if err != nil || count != 1 {
		t.Fatalf("materialized job count = %d, %v", count, err)
	}
	secondStored, err := s.GetJob(ctx, second.ID)
	if err != nil || secondStored.Job.NotificationDestinations == nil || len(secondStored.Job.NotificationDestinations) != 1 {
		t.Fatalf("second selection = %#v, %v", secondStored, err)
	}
}

func TestManagedNotificationMetadataEditPreservesPendingDelivery(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	created, err := s.CreateManagedNotification(ctx, "destination-metadata", "Operations", "generic", []byte{1}, []byte{2}, true)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := managedNotificationKey(created.ID, created.Revision)
	if err := s.QueueEvent(ctx, oldKey, model.Event{Type: "metadata-preserved", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	updated, err := s.UpdateManagedNotificationWithAudit(ctx, created.ID, created.Revision, "Operations renamed", created.Provider, created.Ciphertext, created.Nonce, false, AuditEntry{Action: "notifications.updated", ActorUsername: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	newKey := managedNotificationKey(created.ID, updated.Revision)
	var destination string
	if err := s.DB.QueryRowContext(ctx, `SELECT destination FROM outbox WHERE sent_at IS NULL`).Scan(&destination); err != nil {
		t.Fatal(err)
	}
	if destination != newKey {
		t.Fatalf("pending destination = %q, want %q", destination, newKey)
	}
	var oldCount int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=?`, oldKey).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 {
		t.Fatalf("old revision delivery rows = %d, want 0", oldCount)
	}
}

func TestManagedNotificationCredentialEditDiscardsAndAuditsPendingDelivery(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	created, err := s.CreateManagedNotification(ctx, "destination-credentials", "Operations", "generic", []byte{1}, []byte{2}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.QueueEvent(ctx, managedNotificationKey(created.ID, created.Revision), model.Event{Type: "credential-discarded", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateManagedNotificationWithAudit(ctx, created.ID, created.Revision, created.Name, created.Provider, []byte{3}, []byte{4}, true, AuditEntry{Action: "notifications.updated", ActorUsername: "admin"}); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND destination LIKE ?`, "managed:"+created.ID+":%").Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("pending rows after credential rotation = %d, want 0", pending)
	}
	var detail, actor string
	if err := s.DB.QueryRowContext(ctx, `SELECT detail,actor_username FROM security_audit WHERE action='notifications.pending_discarded' ORDER BY id DESC LIMIT 1`).Scan(&detail, &actor); err != nil {
		t.Fatal(err)
	}
	if actor != "admin" || detail == "" || !containsAll(detail, "1", created.ID, "credential rotation") {
		t.Fatalf("pending-discard audit = detail %q actor %q", detail, actor)
	}
}

func containsAll(value string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(value, part) {
			return false
		}
	}
	return true
}

func TestDeleteManagedNotificationRemovesDeletedDestinationFromRouting(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	destination, err := s.CreateManagedNotification(ctx, "destination-deleted", "Operations", "generic", []byte{1}, []byte{2}, true)
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
	shared := create("shared-routing", []string{"file:kept", destination.ID})
	only := create("only-deleted-routing", []string{destination.ID})
	unrelated := create("unrelated-routing", []string{"file:kept"})
	legacy := create("legacy-routing", nil)
	archived := create("archived-routing", []string{destination.ID})
	if err := s.SetJobArchived(ctx, archived.ID, true); err != nil {
		t.Fatal(err)
	}
	archived, err = s.GetJob(ctx, archived.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetApplicationUpdateDestinations(ctx, []string{"file:kept", destination.ID}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}

	changed, err := s.DeleteManagedNotificationWithAudit(ctx, destination.ID, destination.Revision, AuditEntry{Action: "notifications.deleted", ActorUsername: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	wantChanged := []string{shared.ID, only.ID, archived.ID}
	slices.Sort(wantChanged)
	if !slices.Equal(changed, wantChanged) {
		t.Fatalf("jobs reported as changed = %#v, want %#v", changed, wantChanged)
	}

	for _, tc := range []struct {
		before JobRecord
		want   []string
	}{{shared, []string{"file:kept"}}, {only, []string{}}, {archived, []string{}}} {
		stored, getErr := s.GetJob(ctx, tc.before.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if stored.Revision != tc.before.Revision+1 || stored.Job.NotificationDestinations == nil || strings.Join(stored.Job.NotificationDestinations, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("job %s after destination delete = revision %d selection %#v, want revision %d selection %#v", tc.before.Job.Name, stored.Revision, stored.Job.NotificationDestinations, tc.before.Revision+1, tc.want)
		}
		if stored.Archived != tc.before.Archived || stored.Enabled != tc.before.Enabled || stored.Job.SecurityHash() != tc.before.Job.SecurityHash() {
			t.Fatalf("job %s lifecycle or scope changed: %#v", tc.before.Job.Name, stored)
		}
		var revisionJSON string
		if scanErr := s.DB.QueryRowContext(ctx, `SELECT definition_json FROM job_revisions WHERE job_id=? AND revision=?`, stored.ID, stored.Revision).Scan(&revisionJSON); scanErr != nil {
			t.Fatalf("job %s revision %d was not recorded: %v", tc.before.Job.Name, stored.Revision, scanErr)
		}
		if strings.Contains(revisionJSON, destination.ID) {
			t.Fatalf("job %s revision still references deleted destination: %s", tc.before.Job.Name, revisionJSON)
		}
		var audits int
		if scanErr := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='job.notification_destination_removed' AND actor_username='admin' AND detail LIKE ? AND detail LIKE ?`, "%"+stored.ID+"%", "%"+destination.ID+"%").Scan(&audits); scanErr != nil {
			t.Fatal(scanErr)
		}
		if audits != 1 {
			t.Fatalf("job %s routing scrub audit rows = %d, want 1", tc.before.Job.Name, audits)
		}
	}
	for _, before := range []JobRecord{unrelated, legacy} {
		stored, getErr := s.GetJob(ctx, before.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if stored.Revision != before.Revision || (before.Job.NotificationDestinations == nil) != (stored.Job.NotificationDestinations == nil) {
			t.Fatalf("unaffected job %s changed: %#v", before.Job.Name, stored)
		}
	}
	state, err := s.GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !state.UpdateNotificationDestinationsConfigured || strings.Join(state.UpdateNotificationDestinations, ",") != "file:kept" {
		t.Fatalf("update routing after destination delete = %#v", state)
	}
	var routingAudits int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='notifications.update_routing' AND actor_username='admin' AND detail LIKE ?`, "%"+destination.ID+"%").Scan(&routingAudits); err != nil {
		t.Fatal(err)
	}
	if routingAudits != 1 {
		t.Fatalf("update routing scrub audit rows = %d, want 1", routingAudits)
	}

	unused, err := s.CreateManagedNotification(ctx, "destination-unused", "Unused", "generic", []byte{3}, []byte{4}, true)
	if err != nil {
		t.Fatal(err)
	}
	changed, err = s.DeleteManagedNotificationWithAudit(ctx, unused.ID, unused.Revision, AuditEntry{Action: "notifications.deleted", ActorUsername: "admin"})
	if err != nil || len(changed) != 0 {
		t.Fatalf("delete of an unselected destination changed jobs %#v: %v", changed, err)
	}
	if state, err := s.GetApplicationUpdateState(ctx); err != nil || strings.Join(state.UpdateNotificationDestinations, ",") != "file:kept" {
		t.Fatalf("update routing after unrelated delete = %#v, %v", state, err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action IN ('job.notification_destination_removed','notifications.update_routing') AND detail LIKE ?`, "%"+unused.ID+"%").Scan(&routingAudits); err != nil || routingAudits != 0 {
		t.Fatalf("unrelated delete wrote %d routing audit rows: %v", routingAudits, err)
	}
}

func TestDeleteManagedNotificationRollsBackWhenRoutingCannotBeUpdated(t *testing.T) {
	for _, test := range []struct {
		name  string
		fault string
	}{
		{"unreadable job definition", `UPDATE jobs SET definition_json='{'`},
		{"job write rejected", `CREATE TRIGGER reject_job_update BEFORE UPDATE ON jobs BEGIN SELECT RAISE(ABORT,'jobs unavailable'); END`},
		{"job revision rejected", `CREATE TRIGGER reject_job_revision BEFORE INSERT ON job_revisions BEGIN SELECT RAISE(ABORT,'revisions unavailable'); END`},
		{"unreadable update routing", `UPDATE tenants SET update_destinations_json='{' WHERE is_default=1`},
		{"update routing write rejected", `CREATE TRIGGER reject_routing_update BEFORE UPDATE OF update_destinations_json ON tenants BEGIN SELECT RAISE(ABORT,'routing unavailable'); END`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			s := openTestStore(t)
			destination, err := s.CreateManagedNotification(ctx, "destination-fault", "Operations", "generic", []byte{1}, []byte{2}, true)
			if err != nil {
				t.Fatal(err)
			}
			job := testJob("fault-routing")
			job.NotificationDestinations = []string{destination.ID}
			record, err := s.CreateJob(ctx, job)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SetApplicationUpdateDestinations(ctx, []string{destination.ID}, AuditEntry{}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.ExecContext(ctx, test.fault); err != nil {
				t.Fatal(err)
			}
			if changed, err := s.DeleteManagedNotificationWithAudit(ctx, destination.ID, destination.Revision, AuditEntry{Action: "notifications.deleted"}); err == nil {
				t.Fatalf("delete succeeded although routing could not be updated; changed jobs %#v", changed)
			}
			if _, err := s.GetManagedNotification(ctx, destination.ID); err != nil {
				t.Fatalf("destination deleted although its routing update failed: %v", err)
			}
			var revision int64
			if err := s.DB.QueryRowContext(ctx, `SELECT revision FROM jobs WHERE id=?`, record.ID).Scan(&revision); err != nil || revision != record.Revision {
				t.Fatalf("job revision after failed delete = %d, %v; want %d", revision, err, record.Revision)
			}
		})
	}
}

func TestDeleteManagedNotificationReportsUnknownDestination(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.DeleteManagedNotificationWithAudit(context.Background(), "missing-destination", 1, AuditEntry{Action: "notifications.deleted"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete of unknown destination error = %v, want not found", err)
	}
}

func TestDeleteManagedNotificationRoutingScrubRollsBackWithDelete(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	destination, err := s.CreateManagedNotification(ctx, "destination-rollback", "Operations", "generic", []byte{1}, []byte{2}, true)
	if err != nil {
		t.Fatal(err)
	}
	job := testJob("rollback-routing")
	job.NotificationDestinations = []string{destination.ID}
	record, err := s.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER reject_scrub_audit BEFORE INSERT ON security_audit WHEN NEW.action='job.notification_destination_removed' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteManagedNotificationWithAudit(ctx, destination.ID, destination.Revision, AuditEntry{Action: "notifications.deleted"}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("delete with failing scrub audit error = %v, want audit unavailable", err)
	}
	stored, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != record.Revision || strings.Join(stored.Job.NotificationDestinations, ",") != destination.ID {
		t.Fatalf("job routing changed although the delete rolled back: %#v", stored)
	}
	if _, err := s.GetManagedNotification(ctx, destination.ID); err != nil {
		t.Fatalf("destination deleted although its routing scrub rolled back: %v", err)
	}
}
