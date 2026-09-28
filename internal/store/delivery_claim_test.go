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
