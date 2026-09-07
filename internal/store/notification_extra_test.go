package store

import (
	"context"
	"errors"
	"testing"
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
