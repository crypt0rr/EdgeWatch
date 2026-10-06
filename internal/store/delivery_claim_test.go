package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A worker may send a claimed delivery only while the claim is still its
// own and the delivery's tenant is active. A delivery that was sent, or
// whose claim is not the worker's, has lost its claim; a delivery of a
// disabled tenant is held; a platform delivery is never held.
func TestCheckDeliveryClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	owners := map[string]any{"claim-default": DefaultTenantID, "claim-b": secondTenantID, "claim-platform": nil}
	for destination, tenant := range owners {
		if _, err := f.store.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,tenant_id) VALUES(?,'{}',?,?)`, destination, stamp, tenant); err != nil {
			t.Fatal(err)
		}
	}
	claimed, err := f.store.System().ClaimDueDeliveries(ctx, 100, "owner")
	if err != nil {
		t.Fatal(err)
	}
	deliveries := map[string]Delivery{}
	for _, delivery := range claimed {
		if _, ours := owners[delivery.Destination]; ours {
			deliveries[delivery.Destination] = delivery
		}
	}
	if len(deliveries) != len(owners) {
		t.Fatalf("claimed deliveries = %+v", deliveries)
	}
	check := func(destination, claim string) error {
		return f.store.System().CheckDeliveryClaim(ctx, deliveries[destination].ID, claim)
	}
	for destination, delivery := range deliveries {
		if err := check(destination, delivery.ClaimToken); err != nil {
			t.Errorf("%s: check of its own claim = %v", destination, err)
		}
		for _, claim := range []string{"", "another-owner"} {
			if err := check(destination, claim); !errors.Is(err, ErrDeliveryClaimLost) {
				t.Errorf("%s: check of claim %q = %v, want ErrDeliveryClaimLost", destination, claim, err)
			}
		}
	}

	b, err := f.store.Platform().GetTenant(ctx, secondTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Platform().DisableTenant(ctx, secondTenantID, b.Revision, platformAudit("")); err != nil {
		t.Fatal(err)
	}
	if err := check("claim-b", deliveries["claim-b"].ClaimToken); !errors.Is(err, ErrDeliveryHeld) {
		t.Errorf("check of a disabled tenant's delivery = %v, want ErrDeliveryHeld", err)
	}
	for _, destination := range []string{"claim-default", "claim-platform"} {
		if err := check(destination, deliveries[destination].ClaimToken); err != nil {
			t.Errorf("%s: check after another tenant was disabled = %v", destination, err)
		}
	}

	sent := deliveries["claim-default"]
	if err := f.store.System().DeliveryResultClaim(ctx, sent.ID, sent.ClaimToken, nil); err != nil {
		t.Fatal(err)
	}
	if err := check("claim-default", sent.ClaimToken); !errors.Is(err, ErrDeliveryClaimLost) {
		t.Errorf("check of a sent delivery = %v, want ErrDeliveryClaimLost", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	platform := deliveries["claim-platform"]
	if err := f.store.System().CheckDeliveryClaim(canceled, platform.ID, platform.ClaimToken); err == nil || errors.Is(err, ErrDeliveryClaimLost) || errors.Is(err, ErrDeliveryHeld) {
		t.Errorf("check with a canceled context = %v, want the context error", err)
	}
}

func TestClaimDueDeliveriesDeadLettersUndecodablePayloadAndReturnsHealthyRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	for _, row := range []struct {
		destination string
		payload     string
	}{
		{destination: "invalid-payload", payload: `{"created_at":1}`},
		{destination: "valid-payload", payload: `{"type":"test","message":"healthy"}`},
	} {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,tenant_id) VALUES(?,?,?,?)`, row.destination, row.payload, stamp, DefaultTenantID); err != nil {
			t.Fatal(err)
		}
	}

	claimed, err := s.System().ClaimDueDeliveries(ctx, 16, "decode-test-owner")
	if err != nil {
		t.Fatalf("claim due deliveries: %v", err)
	}
	if len(claimed) != 1 || claimed[0].Destination != "valid-payload" {
		t.Fatalf("claim returned %+v, want the valid delivery only", claimed)
	}
	var terminalAt, lastError, claimToken string
	if err := s.DB.QueryRowContext(ctx, `SELECT terminal_at,last_error,claim_token FROM outbox WHERE destination='invalid-payload'`).Scan(&terminalAt, &lastError, &claimToken); err != nil {
		t.Fatal(err)
	}
	if terminalAt == "" || lastError != "payload_invalid" || claimToken != "" {
		t.Fatalf("invalid delivery state = terminal %q, error %q, claim %q", terminalAt, lastError, claimToken)
	}
	var terminalFailures int
	var healthCode string
	if err := s.DB.QueryRowContext(ctx, `SELECT terminal_failures,last_error_code FROM notification_delivery_health WHERE destination_identity='invalid-payload'`).Scan(&terminalFailures, &healthCode); err != nil {
		t.Fatal(err)
	}
	if terminalFailures != 1 || healthCode != "payload_invalid" {
		t.Fatalf("invalid delivery health = failures %d, code %q", terminalFailures, healthCode)
	}
	if next, err := s.System().ClaimDueDeliveries(ctx, 16, "decode-test-next-owner"); err != nil || len(next) != 0 {
		t.Fatalf("next claim after invalid payload = %+v, %v; want none", next, err)
	}
}

func TestFailInvalidDeliveryPayloadRejectsStaleClaimsAndStopsOnFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	system := s.System()
	if err := system.failInvalidDeliveryPayload(ctx, 1, ""); !errors.Is(err, ErrDeliveryClaimLost) {
		t.Fatalf("invalid payload without a claim = %v, want claim lost", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := system.failInvalidDeliveryPayload(canceled, 1, "owner"); !errors.Is(err, context.Canceled) {
		t.Fatalf("invalid payload with canceled context = %v, want canceled", err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,tenant_id,claim_token,claim_until) VALUES('invalid-claim','{}',?,?, 'current-owner', ?)`, stamp, DefaultTenantID, stamp)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if err := system.failInvalidDeliveryPayload(ctx, id, "stale-owner"); !errors.Is(err, ErrDeliveryClaimLost) {
		t.Fatalf("invalid payload with stale claim = %v, want claim lost", err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER reject_invalid_delivery_terminal_update BEFORE UPDATE ON outbox BEGIN SELECT RAISE(FAIL, 'forced update failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := system.failInvalidDeliveryPayload(ctx, id, "current-owner"); err == nil {
		t.Fatal("invalid payload terminal update succeeded despite the test trigger")
	}
	var claim string
	if err := s.DB.QueryRowContext(ctx, `SELECT claim_token FROM outbox WHERE id=?`, id).Scan(&claim); err != nil {
		t.Fatal(err)
	}
	if claim != "current-owner" {
		t.Fatalf("failed terminal update changed claim to %q", claim)
	}
}
