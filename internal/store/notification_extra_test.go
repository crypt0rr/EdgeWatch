package store

import (
	"context"
	"errors"
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
	if err := s.DeleteManagedNotificationWithAudit(ctx, created.ID, 2, AuditEntry{Action: "notification.deleted"}); err != nil {
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
