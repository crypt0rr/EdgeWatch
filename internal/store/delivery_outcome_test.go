package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// Every code that deliveryErrorCode returns for a failure is one that the
// fingerprint table knows, so its fingerprints survive the read filter.
func TestDeliveryErrorCodesCoverEverySentinel(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		context.Canceled, context.DeadlineExceeded, ErrDeliveryDestinationLocked, ErrDeliveryDestinationMissing,
		ErrDeliveryDestinationExcluded, ErrDeliveryProvider, ErrDeliveryProviderPanic, ErrDeliveryIndeterminate,
		ErrDeliveryProviderTimeout, ErrDeliveryWorkerPanic, ErrDeliveryPayloadInvalid, errors.New("other"),
	} {
		code := deliveryErrorCode(err)
		if !slices.Contains(deliveryErrorCodes, code) {
			t.Errorf("deliveryErrorCode(%v) = %q, which deliveryErrorCodes does not list", err, code)
		}
		fingerprint := deliveryErrorFingerprint(&DeliveryFailure{Err: err, Class: DeliveryClassConnect})
		if currentErrorFingerprint(fingerprint) != fingerprint {
			t.Errorf("the fingerprint of %v is filtered out", err)
		}
	}
	if deliveryErrorFingerprint(nil) != "" || deliveryErrorClass(errors.New("other")) != "" {
		t.Fatal("no failure has a fingerprint or a class")
	}
	if got := (&DeliveryFailure{Err: ErrDeliveryProvider}).Error(); got != ErrDeliveryProvider.Error() {
		t.Fatalf("a failure without a class = %q", got)
	}
}

// A failure's fingerprint names its kind, never its destination: the same
// failure of two destinations has one fingerprint, another class has
// another, and a fingerprint that an earlier release derived from the
// destination URL is no longer returned.
func TestDeliveryErrorFingerprintNamesTheKindOfFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	fail := func(destination string, err error) {
		t.Helper()
		if err := s.System().QueueEvent(ctx, destination, model.Event{Type: "port-opened", Job: "edge", TenantID: DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		due, claimErr := s.System().ClaimDueDeliveries(ctx, 1, "owner-"+destination)
		if claimErr != nil || len(due) != 1 {
			t.Fatalf("claim %s = %+v, %v", destination, due, claimErr)
		}
		if err := s.System().DeliveryResultClaim(ctx, due[0].ID, due[0].ClaimToken, err); err != nil {
			t.Fatal(err)
		}
	}
	fail("deployment-one", &DeliveryFailure{Err: ErrDeliveryProvider, Class: DeliveryClassDNS})
	fail("deployment-two", &DeliveryFailure{Err: ErrDeliveryProvider, Class: DeliveryClassDNS})
	fail("deployment-three", &DeliveryFailure{Err: ErrDeliveryProvider, Class: DeliveryClassTLS})
	// An earlier release stored a digest of the error text, which held a
	// digest of the URL.
	urlDigest := sha256.Sum256([]byte("generic://hooks.example/secret"))
	legacy := sha256.Sum256([]byte("notification provider failed: notification delivery failed (" + hex.EncodeToString(urlDigest[:])[:12] + ")"))
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO notification_delivery_health(destination_identity,last_failure_at,last_error_code,last_error_fingerprint,updated_at) VALUES('deployment-legacy',?,?,?,?)`, time.Now().UTC().Format(time.RFC3339Nano), "delivery_failed", hex.EncodeToString(legacy[:])[:16], time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	health, err := defaultTenant(s).ListDeliveryHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	one, two, three := health["deployment-one"].LastErrorFingerprint, health["deployment-two"].LastErrorFingerprint, health["deployment-three"].LastErrorFingerprint
	if one == "" || one != two || three == one || three == "" {
		t.Fatalf("fingerprints = %q, %q, %q; want the two DNS failures alike and the TLS failure apart", one, two, three)
	}
	if got := health["deployment-legacy"]; got.LastErrorFingerprint != "" || got.LastErrorCode != "delivery_failed" {
		t.Fatalf("legacy health = %+v, want its URL-derived fingerprint left out", got)
	}
	var message string
	if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(json_extract(CAST(payload_json AS TEXT),'$.message'),'') FROM events WHERE type='notification-delivery-terminal'`).Scan(&message); err == nil && strings.Contains(message, hex.EncodeToString(urlDigest[:])[:8]) {
		t.Fatalf("a terminal event names a digest of the URL: %s", message)
	}
}

// A provider timeout is a provider attempt with a claim lease as its least
// delay, not a deferral: a provider that keeps hanging keeps its alert for
// the whole retry schedule instead of ending it after the deferral limit.
func TestProviderTimeoutIsAnAttemptWithALeaseFloor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.System().QueueEvent(ctx, "hanging", model.Event{Type: "port-opened", Job: "edge", TenantID: DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= deliveryMaxDeferrals+2; attempt++ {
		due, err := s.System().ClaimDueDeliveries(ctx, 1, "owner")
		if err != nil || len(due) != 1 {
			t.Fatalf("attempt %d: claim = %+v, %v", attempt, due, err)
		}
		before := time.Now().UTC()
		if err := s.System().DeliveryResultClaim(ctx, due[0].ID, due[0].ClaimToken, &DeliveryFailure{Err: ErrDeliveryProviderTimeout, Class: DeliveryClassTimeout}); err != nil {
			t.Fatal(err)
		}
		var attempts, deferrals int
		var next, terminal, code string
		if err := s.DB.QueryRowContext(ctx, `SELECT attempts,deferrals,next_at,terminal_at,last_error FROM outbox WHERE id=?`, due[0].ID).Scan(&attempts, &deferrals, &next, &terminal, &code); err != nil {
			t.Fatal(err)
		}
		if attempts != attempt || deferrals != 0 || terminal != "" || code != "provider_timeout" {
			t.Fatalf("attempt %d: attempts %d, deferrals %d, terminal %q, code %q", attempt, attempts, deferrals, terminal, code)
		}
		if delay := scanTime(next).Sub(before); delay < deliveryClaimLease-time.Second || (attempt > 6 && delay < deliveryRetryDelay(attempt)-time.Second) {
			t.Fatalf("attempt %d: retried after %s", attempt, delay)
		}
		if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=?`, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
}

// managedDestinationWithDeliveries creates a destination of the default
// tenant and queues count alerts for its current revision.
func managedDestinationWithDeliveries(t *testing.T, s *Store, name string, count int) ManagedNotification {
	t.Helper()
	ctx := context.Background()
	destination, err := defaultTenant(s).CreateManagedNotification(ctx, "", name, "generic", []byte("sealed "+name), []byte("nonce "+name), true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		event := model.Event{Type: "port-opened", Job: name, Message: name + "-" + string(rune('a'+i)), TenantID: DefaultTenantID, CreatedAt: time.Now().UTC().Add(time.Duration(i) * time.Second)}
		if err := s.System().QueueEvent(ctx, managedNotificationKey(destination.ID, destination.Revision), event); err != nil {
			t.Fatal(err)
		}
	}
	return destination
}

// destinationOutbox returns the selector, attempts, claim, and terminal state
// of the destination's unsent deliveries, ordered by ID.
func destinationOutbox(t *testing.T, s *Store, id string) []string {
	t.Helper()
	rows, err := s.DB.Query(`SELECT destination,attempts,deferrals,claim_token,terminal_at<>'' FROM outbox WHERE destination LIKE ? AND sent_at IS NULL ORDER BY id`, "managed:"+id+":%")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var destination, claim string
		var attempts, deferrals int
		var terminal bool
		if err := rows.Scan(&destination, &attempts, &deferrals, &claim, &terminal); err != nil {
			t.Fatal(err)
		}
		state := "pending"
		if terminal {
			state = "terminal"
		}
		claimState := "free"
		if claim != "" {
			claimState = "claimed"
		}
		out = append(out, fmt.Sprintf("%s %d %d %s %s", destination, attempts, deferrals, claimState, state))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Replacing credentials with keep-pending moves the destination's queued
// alerts to the new revision instead of discarding them: queued and retrying
// ones become due with fresh budgets and lose any claim, and one that failed
// for good stays failed, so it can be redelivered. An audit entry records
// the counts. Without keep-pending the alerts are still discarded.
func TestCredentialReplacementKeepsPendingDeliveriesWhenAsked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	kept := managedDestinationWithDeliveries(t, s, "kept", 3)
	discarded := managedDestinationWithDeliveries(t, s, "discarded", 2)
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET attempts=3,deferrals=1 WHERE destination=?`, managedNotificationKey(kept.ID, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET terminal_at=?,attempts=15 WHERE id=(SELECT MIN(id) FROM outbox WHERE destination=?)`, time.Now().UTC().Format(time.RFC3339Nano), managedNotificationKey(kept.ID, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_token='worker',claim_until=? WHERE id=(SELECT MAX(id) FROM outbox WHERE destination=?)`, time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), managedNotificationKey(kept.ID, 1)); err != nil {
		t.Fatal(err)
	}
	audit := AuditEntry{Action: "notifications.updated", Detail: "managed notification updated", ActorUsername: "admin"}
	updated, err := defaultTenant(s).UpdateManagedNotificationKeepingPendingWithAudit(ctx, kept.ID, kept.Revision, "kept", "generic", []byte("sealed repaired"), []byte("nonce repaired"), true, audit)
	if err != nil {
		t.Fatal(err)
	}
	next := managedNotificationKey(kept.ID, updated.Revision)
	if updated.Revision != 2 || updated.CredentialRevision != 2 {
		t.Fatalf("updated = revision %d, credential revision %d", updated.Revision, updated.CredentialRevision)
	}
	want := []string{next + " 15 1 free terminal", next + " 0 0 free pending", next + " 0 0 free pending"}
	if got := destinationOutbox(t, s, kept.ID); !reflect.DeepEqual(got, want) {
		t.Fatalf("kept deliveries = %q, want %q", got, want)
	}
	if got := auditDetails(t, s, "notifications.pending_kept"); len(got) != 1 || !strings.Contains(got[0], "kept 2 pending and 1 failed deliveries for managed notification "+kept.ID) {
		t.Fatalf("keep audit = %q", got)
	}
	if got := auditDetails(t, s, "notifications.pending_discarded"); len(got) != 0 {
		t.Fatalf("keeping the alerts audited a discard: %q", got)
	}
	if _, err := defaultTenant(s).UpdateManagedNotificationWithAudit(ctx, discarded.ID, discarded.Revision, "discarded", "generic", []byte("sealed rotated"), []byte("nonce rotated"), true, audit); err != nil {
		t.Fatal(err)
	}
	if got := destinationOutbox(t, s, discarded.ID); len(got) != 0 {
		t.Fatalf("the default replacement kept deliveries: %q", got)
	}
	if got := auditDetails(t, s, "notifications.pending_discarded"); len(got) != 1 || !strings.Contains(got[0], "discarded 2 pending deliveries") {
		t.Fatalf("discard audit = %q", got)
	}
	// A rename with keep-pending is an ordinary metadata edit.
	if _, err := defaultTenant(s).UpdateManagedNotificationKeepingPendingWithAudit(ctx, kept.ID, updated.Revision, "renamed", "generic", []byte("sealed repaired"), []byte("nonce repaired"), true, audit); err != nil {
		t.Fatal(err)
	}
	if got := auditDetails(t, s, "notifications.pending_kept"); len(got) != 1 {
		t.Fatalf("a rename audited kept deliveries: %q", got)
	}
}

// Terminal deliveries are listed newest first by their metadata only, and
// only those queued for the destination's current credentials. Redelivering
// them, or those that ids names, queues them for the current selector with
// fresh budgets, takes them off the destination's terminal failure count,
// and is audited with the count.
func TestTerminalDeliveriesListAndRedeliver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	destination := managedDestinationWithDeliveries(t, s, "webhook", 4)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET terminal_at=?,attempts=15,last_error='delivery_failed' WHERE id IN (SELECT id FROM outbox ORDER BY id LIMIT 3)`, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE notification_delivery_health SET terminal_failures=3 WHERE destination_identity=?`, "managed:"+destination.ID); err != nil {
		t.Fatal(err)
	}
	// A rename moves the pending delivery and leaves the terminal ones under
	// the earlier revision, whose credentials are still current.
	renamed, err := ts.UpdateManagedNotification(ctx, destination.ID, destination.Revision, "renamed", "generic", destination.Ciphertext, destination.Nonce, true)
	if err != nil {
		t.Fatal(err)
	}
	// A delivery queued for credentials that were replaced since is never
	// listed or redelivered.
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,terminal_at,attempts,tenant_id) VALUES(?,'{"type":"stale"}',?,?,15,?)`, managedNotificationKey(destination.ID, 0), stamp, stamp, DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	listed, err := ts.ListTerminalDeliveries(ctx, destination.ID, 0, 2)
	if err != nil || len(listed) != 2 {
		t.Fatalf("first page = %+v, %v", listed, err)
	}
	if listed[0].ID <= listed[1].ID || listed[0].EventType != "port-opened" || listed[0].Job != "webhook" || listed[0].Attempts != 15 || listed[0].ErrorCode != "delivery_failed" || listed[0].EventAt.IsZero() || listed[0].TerminalAt.IsZero() {
		t.Fatalf("first page = %+v", listed)
	}
	rest, err := ts.ListTerminalDeliveries(ctx, destination.ID, listed[1].ID, 0)
	if err != nil || len(rest) != 1 || rest[0].ID >= listed[1].ID {
		t.Fatalf("second page = %+v, %v", rest, err)
	}
	if _, err := ts.ListTerminalDeliveries(ctx, "00000000-0000-0000-0000-00000000dead", 0, 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown destination = %v", err)
	}
	audit := AuditEntry{Action: "notifications.redelivered", ActorUsername: "admin"}
	if count, err := ts.RedeliverTerminalDeliveries(ctx, destination.ID, []int64{}, audit); err != nil || count != 0 {
		t.Fatalf("an empty selection redelivered %d, %v", count, err)
	}
	count, err := ts.RedeliverTerminalDeliveries(ctx, destination.ID, []int64{listed[0].ID, 999999}, audit)
	if err != nil || count != 1 {
		t.Fatalf("redelivered %d, %v; want 1", count, err)
	}
	current := managedNotificationKey(destination.ID, renamed.Revision)
	var selector, terminal, next string
	var attempts int
	if err := s.DB.QueryRowContext(ctx, `SELECT destination,terminal_at,attempts,next_at FROM outbox WHERE id=?`, listed[0].ID).Scan(&selector, &terminal, &attempts, &next); err != nil {
		t.Fatal(err)
	}
	if selector != current || terminal != "" || attempts != 0 || scanTime(next).After(time.Now().UTC()) {
		t.Fatalf("redelivered row = %s, terminal %q, attempts %d, next %s", selector, terminal, attempts, next)
	}
	if count, err := ts.RedeliverTerminalDeliveries(ctx, destination.ID, nil, audit); err != nil || count != 2 {
		t.Fatalf("redelivering the rest = %d, %v; want 2", count, err)
	}
	if count, err := ts.RedeliverTerminalDeliveries(ctx, destination.ID, nil, audit); err != nil || count != 0 {
		t.Fatalf("redelivering again = %d, %v; want none", count, err)
	}
	var stale string
	if err := s.DB.QueryRowContext(ctx, `SELECT terminal_at FROM outbox WHERE destination=?`, managedNotificationKey(destination.ID, 0)).Scan(&stale); err != nil || stale == "" {
		t.Fatalf("the delivery for replaced credentials was requeued: %q, %v", stale, err)
	}
	health, err := ts.ListDeliveryHealth(ctx)
	if err != nil || health["managed:"+destination.ID].TerminalFailures != 0 || health["managed:"+destination.ID].Pending != 4 {
		t.Fatalf("health = %+v, %v; want no terminal failures and four pending", health["managed:"+destination.ID], err)
	}
	if got := auditDetails(t, s, "notifications.redelivered"); !reflect.DeepEqual(got, []string{
		"redelivered 1 failed deliveries for managed notification " + destination.ID,
		"redelivered 2 failed deliveries for managed notification " + destination.ID,
	}) {
		t.Fatalf("redelivery audit = %q", got)
	}
	if _, err := ts.RedeliverTerminalDeliveries(ctx, "00000000-0000-0000-0000-00000000dead", nil, audit); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown destination = %v", err)
	}
}
