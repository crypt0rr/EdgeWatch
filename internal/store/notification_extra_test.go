package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestManagedNotificationStoreCRUDAndLegacySelectionMaterialization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	if destinations, err := defaultTenant(s).ListManagedNotifications(ctx); err != nil || len(destinations) != 0 {
		t.Fatalf("initial managed destinations = %#v, %v", destinations, err)
	}
	legacy, err := defaultTenant(s).CreateJob(ctx, testJob("legacy-notification"))
	if err != nil {
		t.Fatal(err)
	}
	created, err := defaultTenant(s).CreateManagedNotificationWithLegacySelectionAndAudit(ctx, "destination-1", "Ops", "generic", []byte{1, 2}, []byte{3}, true, []string{"deployment:1"}, AuditEntry{Action: "notification.created"})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "destination-1" || created.Revision != 1 || !created.Enabled || string(created.Ciphertext) != string([]byte{1, 2}) {
		t.Fatalf("created destination = %#v", created)
	}
	loaded, err := defaultTenant(s).GetManagedNotification(ctx, created.ID)
	if err != nil || loaded.Name != "Ops" || loaded.Provider != "generic" {
		t.Fatalf("loaded destination = %#v, %v", loaded, err)
	}
	systemLoaded, err := s.System().GetManagedNotification(ctx, created.ID)
	if err != nil || systemLoaded.ID != created.ID || systemLoaded.TenantID != DefaultTenantID {
		t.Fatalf("system-scoped destination lookup = %#v, %v", systemLoaded, err)
	}
	if _, err := defaultTenant(s).GetManagedNotification(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing destination error = %v", err)
	}
	all, err := defaultTenant(s).ListManagedNotifications(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("destination list = %#v, %v", all, err)
	}
	storedJob, err := defaultTenant(s).GetJob(ctx, legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedJob.Job.NotificationDestinations == nil || len(storedJob.Job.NotificationDestinations) != 1 || storedJob.Job.NotificationDestinations[0] != "deployment:1" || storedJob.Revision != 2 {
		t.Fatalf("legacy selection was not materialized: %#v", storedJob)
	}
	if _, err := defaultTenant(s).CreateManagedNotificationWithAudit(ctx, "destination-audit", "Audited", "generic", []byte{9}, []byte{8}, false, AuditEntry{Action: "notification.created"}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateManagedNotificationWithLegacySelection(ctx, "destination-legacy", "Legacy", "generic", []byte{7}, []byte{6}, true, []string{}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateManagedNotification(ctx, "bad", "", "generic", []byte{1}, []byte{2}, true); err == nil {
		t.Fatal("empty managed destination name was accepted")
	}
	if _, err := defaultTenant(s).CreateManagedNotification(ctx, "bad", "Name", "generic", nil, []byte{2}, true); err == nil {
		t.Fatal("empty managed destination ciphertext was accepted")
	}
	if _, err := defaultTenant(s).UpdateManagedNotification(ctx, created.ID, 99, "Ops", "generic", []byte{4}, []byte{5}, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale destination update error = %v", err)
	}
	updated, err := defaultTenant(s).UpdateManagedNotificationWithAudit(ctx, created.ID, 1, "Ops updated", "generic", []byte{4}, []byte{5}, false, AuditEntry{Action: "notification.updated"})
	if err != nil || updated.Revision != 2 || updated.Enabled {
		t.Fatalf("updated destination = %#v, %v", updated, err)
	}
	if err := defaultTenant(s).DeleteManagedNotification(ctx, created.ID, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale destination delete error = %v", err)
	}
	if _, err := defaultTenant(s).DeleteManagedNotificationWithAudit(ctx, created.ID, 2, AuditEntry{Action: "notification.deleted"}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).GetManagedNotification(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted destination = %v", err)
	}
	if _, err := s.System().GetManagedNotification(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted system-scoped destination = %v", err)
	}

	second, err := defaultTenant(s).CreateJob(ctx, testJob("second-legacy"))
	if err != nil {
		t.Fatal(err)
	}
	count, err := defaultTenant(s).MaterializeLegacyNotificationSelections(ctx, []string{"managed:destination:1"})
	if err != nil || count != 1 {
		t.Fatalf("materialized job count = %d, %v", count, err)
	}
	secondStored, err := defaultTenant(s).GetJob(ctx, second.ID)
	if err != nil || secondStored.Job.NotificationDestinations == nil || len(secondStored.Job.NotificationDestinations) != 1 {
		t.Fatalf("second selection = %#v, %v", secondStored, err)
	}
}

func TestManagedNotificationMetadataEditPreservesPendingDelivery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	created, err := defaultTenant(s).CreateManagedNotification(ctx, "destination-metadata", "Operations", "generic", []byte{1}, []byte{2}, true)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := managedNotificationKey(created.ID, created.Revision)
	if err := s.System().QueueEvent(ctx, oldKey, model.Event{Type: "metadata-preserved", TenantID: DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	updated, err := defaultTenant(s).UpdateManagedNotificationWithAudit(ctx, created.ID, created.Revision, "Operations renamed", created.Provider, created.Ciphertext, created.Nonce, false, AuditEntry{Action: "notifications.updated", ActorUsername: "admin"})
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
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	created, err := defaultTenant(s).CreateManagedNotification(ctx, "destination-credentials", "Operations", "generic", []byte{1}, []byte{2}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.System().QueueEvent(ctx, managedNotificationKey(created.ID, created.Revision), model.Event{Type: "credential-discarded", TenantID: DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).UpdateManagedNotificationWithAudit(ctx, created.ID, created.Revision, created.Name, created.Provider, []byte{3}, []byte{4}, true, AuditEntry{Action: "notifications.updated", ActorUsername: "admin"}); err != nil {
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

func TestManagedNotificationRotationPreservesNonWindowDeliveryBehavior(t *testing.T) {
	for _, keepPending := range []bool{false, true} {
		name := "discard"
		if keepPending {
			name = "keep"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := openTestStore(t)
			ts := defaultTenant(s)
			job, err := ts.CreateJob(ctx, testJob("rotation-"+name))
			if err != nil {
				t.Fatal(err)
			}
			destination, err := ts.CreateManagedNotification(ctx, "rotation-destination", "Ops", "generic", []byte{1}, []byte{2}, true)
			if err != nil {
				t.Fatal(err)
			}
			queuedAt := time.Now().UTC()
			for _, event := range []model.Event{
				{Type: "changes-detected", JobID: job.ID, TenantID: DefaultTenantID, ScanID: "non-window-change", CreatedAt: queuedAt, Changes: []model.Change{{Key: "change", Kind: "port"}}},
				{Type: "custom-notification", JobID: job.ID, TenantID: DefaultTenantID, CreatedAt: queuedAt},
			} {
				if err := s.System().QueueEvent(ctx, managedNotificationKey(destination.ID, destination.Revision), event); err != nil {
					t.Fatal(err)
				}
			}
			claimed, err := s.System().ClaimDueDeliveries(ctx, 10, "rotation-"+name)
			if err != nil || len(claimed) != 2 {
				t.Fatalf("claims before rotation = %d, %v", len(claimed), err)
			}
			for _, item := range claimed {
				if item.Event.Type == "changes-detected" {
					if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
						t.Fatalf("begin non-window change attempt: %v", err)
					}
				}
			}
			updated, err := ts.GetManagedNotification(ctx, destination.ID)
			if err != nil {
				t.Fatal(err)
			}
			if keepPending {
				updated, err = ts.UpdateManagedNotificationKeepingPendingWithAudit(ctx, destination.ID, updated.Revision, updated.Name, updated.Provider, []byte{3}, []byte{4}, true, AuditEntry{Action: "notifications.updated"})
			} else {
				updated, err = ts.UpdateManagedNotificationWithAudit(ctx, destination.ID, updated.Revision, updated.Name, updated.Provider, []byte{3}, []byte{4}, true, AuditEntry{Action: "notifications.updated"})
			}
			if err != nil {
				t.Fatal(err)
			}
			var rows int
			if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=? AND sent_at IS NULL`, managedNotificationKey(destination.ID, updated.Revision)).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if keepPending && rows != 2 {
				t.Fatalf("rows moved for keep-pending rotation = %d, want 2", rows)
			}
			if !keepPending && rows != 0 {
				t.Fatalf("rows remaining after discard rotation = %d, want 0", rows)
			}
			for _, item := range claimed {
				var marker, claim string
				err := s.DB.QueryRowContext(ctx, `SELECT attempt_started_at,claim_token FROM outbox WHERE id=?`, item.ID).Scan(&marker, &claim)
				if !keepPending {
					if !errors.Is(err, sql.ErrNoRows) {
						t.Fatalf("discarded row %d lookup = %v, want no rows", item.ID, err)
					}
					continue
				} else if err != nil {
					t.Fatal(err)
				}
				if marker != "" || claim != "" {
					t.Fatalf("kept non-window row %d marker=%q claim=%q; legacy rotation should release it", item.ID, marker, claim)
				}
			}
		})
	}
}

func TestManagedNotificationRotationRetainsStartedActiveWindowEventForReview(t *testing.T) {
	for _, keepPending := range []bool{false, true} {
		name := "discard"
		if keepPending {
			name = "keep"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := openTestStore(t)
			ts := defaultTenant(s)
			job := createWindowTestJob(t, ts, "rotation-window-"+name, "UTC")
			destination, err := ts.CreateManagedNotification(ctx, "rotation-window-destination", "Ops", "generic", []byte{1}, []byte{2}, true)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
			event := model.Event{Type: "changes-detected", JobID: job.ID, TenantID: DefaultTenantID, ScanID: "rotation-window-event", CreatedAt: time.Now().UTC(), Changes: []model.Change{{Key: "rotation-window-change", Kind: "port", Port: 443}}}
			if err := s.System().QueueEvent(ctx, managedNotificationKey(destination.ID, destination.Revision), event); err != nil {
				t.Fatal(err)
			}
			claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "rotation-window-"+name)
			if err != nil || len(claimed) != 1 {
				t.Fatalf("claim window-linked event = %d, %v", len(claimed), err)
			}
			if err := s.System().BeginDeliveryAttempt(ctx, claimed[0].ID, claimed[0].ClaimToken); err != nil {
				t.Fatal(err)
			}
			// The attempt starts before the scheduled window, then the rotation
			// occurs after that window has become active. This keeps the test's
			// setup deliverable while exercising active-window retention.
			if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,status='active' WHERE id=?`, sqliteTimestamp(time.Now().UTC().Add(-time.Second)), window.ID); err != nil {
				t.Fatal(err)
			}
			current, err := ts.GetManagedNotification(ctx, destination.ID)
			if err != nil {
				t.Fatal(err)
			}
			if keepPending {
				_, err = ts.UpdateManagedNotificationKeepingPendingWithAudit(ctx, destination.ID, current.Revision, current.Name, current.Provider, []byte{3}, []byte{4}, true, AuditEntry{Action: "notifications.updated"})
			} else {
				_, err = ts.UpdateManagedNotificationWithAudit(ctx, destination.ID, current.Revision, current.Name, current.Provider, []byte{3}, []byte{4}, true, AuditEntry{Action: "notifications.updated"})
			}
			if err != nil {
				t.Fatal(err)
			}
			var claim, marker string
			var coalesceAfter int
			if err := s.DB.QueryRowContext(ctx, `SELECT claim_token,attempt_started_at,coalesce_after_attempt FROM outbox WHERE id=?`, claimed[0].ID).Scan(&claim, &marker, &coalesceAfter); err != nil {
				t.Fatal(err)
			}
			if claim != claimed[0].ClaimToken || marker == "" || coalesceAfter != 1 {
				t.Fatalf("started window delivery after rotation = claim %q marker %q coalesce-after %d", claim, marker, coalesceAfter)
			}
			if released, err := s.System().ReleaseDeliveryClaims(ctx); err != nil || released != 1 {
				t.Fatalf("release after rotation = %d claims, %v", released, err)
			}
			closeAt := window.EndAt.Add(time.Second)
			summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return closeAt }, nil)
			if err != nil || !changed || summary.UnknownOutcomeEventCount != 1 || summary.InFlightEventCount != 0 {
				t.Fatalf("window review after rotation/recovery = %+v, changed %v, err %v", summary, changed, err)
			}
		})
	}
}

func TestManagedNotificationRotationTreatsFutureWindowAttemptAsUnlinked(t *testing.T) {
	for _, outcome := range []string{"keep-failure", "keep-success", "discard-failure", "discard-hard-stop", "discard-hard-stop-after-end"} {
		t.Run(outcome, func(t *testing.T) {
			ctx := context.Background()
			s := openTestStore(t)
			ts := defaultTenant(s)
			job := createWindowTestJob(t, ts, "rotation-future-"+outcome, "UTC")
			destination, err := ts.CreateManagedNotification(ctx, "rotation-future-destination", "Ops", "generic", []byte{1}, []byte{2}, true)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now().UTC().Add(7 * 24 * time.Hour).Truncate(time.Second)
			window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
			event := model.Event{Type: "changes-detected", JobID: job.ID, TenantID: DefaultTenantID, ScanID: "rotation-future-event", CreatedAt: time.Now().UTC(), Changes: []model.Change{{Key: "rotation-future-change", Kind: "port", Port: 443}}}
			if err := s.System().QueueEvent(ctx, managedNotificationKey(destination.ID, destination.Revision), event); err != nil {
				t.Fatal(err)
			}
			claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "rotation-future-"+outcome)
			if err != nil || len(claimed) != 1 {
				t.Fatalf("claim future-window event = %d, %v", len(claimed), err)
			}
			item := claimed[0]
			if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
				t.Fatal(err)
			}
			var linkedWindowID string
			if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id FROM outbox WHERE id=?`, item.ID).Scan(&linkedWindowID); err != nil || linkedWindowID != window.ID {
				t.Fatalf("attempt window association = %q, %v; want future window %q", linkedWindowID, err, window.ID)
			}
			current, err := ts.GetManagedNotification(ctx, destination.ID)
			if err != nil {
				t.Fatal(err)
			}
			keepPending := strings.HasPrefix(outcome, "keep-")
			if keepPending {
				_, err = ts.UpdateManagedNotificationKeepingPendingWithAudit(ctx, destination.ID, current.Revision, current.Name, current.Provider, []byte{3}, []byte{4}, true, AuditEntry{Action: "notifications.updated"})
			} else {
				_, err = ts.UpdateManagedNotificationWithAudit(ctx, destination.ID, current.Revision, current.Name, current.Provider, []byte{3}, []byte{4}, true, AuditEntry{Action: "notifications.updated"})
			}
			if err != nil {
				t.Fatal(err)
			}
			var selector, claim, marker, coalesced string
			var coalesceAfter int
			if err := s.DB.QueryRowContext(ctx, `SELECT destination,claim_token,attempt_started_at,coalesce_after_attempt,coalesced_at FROM outbox WHERE id=?`, item.ID).Scan(&selector, &claim, &marker, &coalesceAfter, &coalesced); err != nil {
				t.Fatal(err)
			}
			if keepPending {
				wantSelector := managedNotificationKey(destination.ID, current.Revision+1)
				if selector != wantSelector || claim != "" || marker != "" || coalesceAfter != 0 || coalesced != "" {
					t.Fatalf("keep-pending future attempt after rotation = selector %q claim %q marker %q coalesce-after %d coalesced %q; want moved and retryable", selector, claim, marker, coalesceAfter, coalesced)
				}
				var resultErr error
				if outcome == "keep-success" {
					resultErr = s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, nil)
				} else {
					resultErr = s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, ErrDeliveryProvider)
				}
				if !errors.Is(resultErr, ErrDeliveryClaimLost) {
					t.Fatalf("old provider result after selector rotation = %v; want lost claim", resultErr)
				}
				var sentAt string
				if err := s.DB.QueryRowContext(ctx, `SELECT coalesce(sent_at,'') FROM outbox WHERE id=?`, item.ID).Scan(&sentAt); err != nil {
					t.Fatal(err)
				}
				if sentAt != "" {
					t.Fatalf("stale %s result marked rotated outbox row sent at %q", outcome, sentAt)
				}
				retry, err := s.System().ClaimDueDeliveries(ctx, 1, "rotation-future-retry")
				if err != nil || len(retry) != 1 || retry[0].ID != item.ID || retry[0].Destination != wantSelector {
					t.Fatalf("future-window alert retry = %+v, %v; want same row with new selector %q", retry, err, wantSelector)
				}
				return
			}

			if claim != item.ClaimToken || marker == "" || coalesceAfter != 1 || coalesced != "" {
				t.Fatalf("discard future attempt before result/recovery = claim %q marker %q coalesce-after %d coalesced %q; want marked in-flight attempt", claim, marker, coalesceAfter, coalesced)
			}
			if outcome == "discard-failure" {
				if err := s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, ErrDeliveryProvider); err != nil {
					t.Fatal(err)
				}
			} else {
				if outcome == "discard-hard-stop-after-end" {
					end := time.Now().UTC().Add(-2 * time.Second).Truncate(time.Second)
					start := end.Add(-time.Hour)
					if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=?,status='expired' WHERE id=?`, sqliteTimestamp(start), sqliteTimestamp(end), window.ID); err != nil {
						t.Fatal(err)
					}
				}
				if released, err := s.System().ReleaseDeliveryClaims(ctx); err != nil || released != 1 {
					t.Fatalf("release after simulated hard stop = %d claims, %v", released, err)
				}
			}
			if err := s.DB.QueryRowContext(ctx, `SELECT claim_token,attempt_started_at,coalesce_after_attempt,coalesced_at FROM outbox WHERE id=?`, item.ID).Scan(&claim, &marker, &coalesceAfter, &coalesced); err != nil {
				t.Fatal(err)
			}
			if claim != "" || marker != "" || coalesceAfter != 0 || coalesced == "" {
				t.Fatalf("discarded future attempt after %s = claim %q marker %q coalesce-after %d coalesced %q; want immediately coalesced", outcome, claim, marker, coalesceAfter, coalesced)
			}
			if retry, err := s.System().ClaimDueDeliveries(ctx, 1, "rotation-future-no-retry"); err != nil || len(retry) != 0 {
				t.Fatalf("coalesced future-window attempt became retryable: %+v, %v", retry, err)
			}
			summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return window.EndAt.Add(time.Second) }, nil)
			if err != nil || !changed || summary.SuppressedEventCount != 0 || summary.InFlightEventCount != 0 || summary.UnknownOutcomeEventCount != 0 {
				t.Fatalf("future window close after %s attempt = %+v, changed %v, err %v; want no linked outcome", outcome, summary, changed, err)
			}
		})
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
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	destination, err := defaultTenant(s).CreateManagedNotification(ctx, "destination-deleted", "Operations", "generic", []byte{1}, []byte{2}, true)
	if err != nil {
		t.Fatal(err)
	}
	create := func(name string, selection []string) JobRecord {
		t.Helper()
		job := testJob(name)
		job.NotificationDestinations = selection
		record, createErr := defaultTenant(s).CreateJob(ctx, job)
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
	if err := defaultTenant(s).SetJobArchived(ctx, archived.ID, true); err != nil {
		t.Fatal(err)
	}
	archived, err = defaultTenant(s).GetJob(ctx, archived.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SetApplicationUpdateDestinations(ctx, []string{"file:kept", destination.ID}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}

	changed, err := defaultTenant(s).DeleteManagedNotificationWithAudit(ctx, destination.ID, destination.Revision, AuditEntry{Action: "notifications.deleted", ActorUsername: "admin"})
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
		stored, getErr := defaultTenant(s).GetJob(ctx, tc.before.ID)
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
		stored, getErr := defaultTenant(s).GetJob(ctx, before.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if stored.Revision != before.Revision || (before.Job.NotificationDestinations == nil) != (stored.Job.NotificationDestinations == nil) {
			t.Fatalf("unaffected job %s changed: %#v", before.Job.Name, stored)
		}
	}
	routing, err := defaultTenant(s).ApplicationUpdateRouting(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !routing.Configured || strings.Join(routing.Destinations, ",") != "file:kept" {
		t.Fatalf("update routing after destination delete = %#v", routing)
	}
	var routingAudits int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='notifications.update_routing' AND actor_username='admin' AND detail LIKE ?`, "%"+destination.ID+"%").Scan(&routingAudits); err != nil {
		t.Fatal(err)
	}
	if routingAudits != 1 {
		t.Fatalf("update routing scrub audit rows = %d, want 1", routingAudits)
	}

	unused, err := defaultTenant(s).CreateManagedNotification(ctx, "destination-unused", "Unused", "generic", []byte{3}, []byte{4}, true)
	if err != nil {
		t.Fatal(err)
	}
	changed, err = defaultTenant(s).DeleteManagedNotificationWithAudit(ctx, unused.ID, unused.Revision, AuditEntry{Action: "notifications.deleted", ActorUsername: "admin"})
	if err != nil || len(changed) != 0 {
		t.Fatalf("delete of an unselected destination changed jobs %#v: %v", changed, err)
	}
	if routing, err := defaultTenant(s).ApplicationUpdateRouting(ctx); err != nil || strings.Join(routing.Destinations, ",") != "file:kept" {
		t.Fatalf("update routing after unrelated delete = %#v, %v", routing, err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action IN ('job.notification_destination_removed','notifications.update_routing') AND detail LIKE ?`, "%"+unused.ID+"%").Scan(&routingAudits); err != nil || routingAudits != 0 {
		t.Fatalf("unrelated delete wrote %d routing audit rows: %v", routingAudits, err)
	}
}

func TestDeleteManagedNotificationRollsBackWhenRoutingCannotBeUpdated(t *testing.T) {
	t.Parallel()
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
			destination, err := defaultTenant(s).CreateManagedNotification(ctx, "destination-fault", "Operations", "generic", []byte{1}, []byte{2}, true)
			if err != nil {
				t.Fatal(err)
			}
			job := testJob("fault-routing")
			job.NotificationDestinations = []string{destination.ID}
			record, err := defaultTenant(s).CreateJob(ctx, job)
			if err != nil {
				t.Fatal(err)
			}
			if err := defaultTenant(s).SetApplicationUpdateDestinations(ctx, []string{destination.ID}, AuditEntry{}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.ExecContext(ctx, test.fault); err != nil {
				t.Fatal(err)
			}
			if changed, err := defaultTenant(s).DeleteManagedNotificationWithAudit(ctx, destination.ID, destination.Revision, AuditEntry{Action: "notifications.deleted"}); err == nil {
				t.Fatalf("delete succeeded although routing could not be updated; changed jobs %#v", changed)
			}
			if _, err := defaultTenant(s).GetManagedNotification(ctx, destination.ID); err != nil {
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
	t.Parallel()
	s := openTestStore(t)
	if _, err := defaultTenant(s).DeleteManagedNotificationWithAudit(context.Background(), "missing-destination", 1, AuditEntry{Action: "notifications.deleted"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete of unknown destination error = %v, want not found", err)
	}
}

func TestDeleteManagedNotificationRoutingScrubRollsBackWithDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	destination, err := defaultTenant(s).CreateManagedNotification(ctx, "destination-rollback", "Operations", "generic", []byte{1}, []byte{2}, true)
	if err != nil {
		t.Fatal(err)
	}
	job := testJob("rollback-routing")
	job.NotificationDestinations = []string{destination.ID}
	record, err := defaultTenant(s).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER reject_scrub_audit BEFORE INSERT ON security_audit WHEN NEW.action='job.notification_destination_removed' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).DeleteManagedNotificationWithAudit(ctx, destination.ID, destination.Revision, AuditEntry{Action: "notifications.deleted"}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("delete with failing scrub audit error = %v, want audit unavailable", err)
	}
	stored, err := defaultTenant(s).GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != record.Revision || strings.Join(stored.Job.NotificationDestinations, ",") != destination.ID {
		t.Fatalf("job routing changed although the delete rolled back: %#v", stored)
	}
	if _, err := defaultTenant(s).GetManagedNotification(ctx, destination.ID); err != nil {
		t.Fatalf("destination deleted although its routing scrub rolled back: %v", err)
	}
}
