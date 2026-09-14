package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCoveragePolicyErrorAndIdentityHelpers(t *testing.T) {
	var nilVerification *VerificationError
	if got := nilVerification.Error(); got != "database verification failed" {
		t.Fatalf("nil verification error = %q", got)
	}
	for _, tc := range []struct {
		value *VerificationError
		want  string
	}{
		{&VerificationError{}, "database verification failed"},
		{&VerificationError{IntegrityCheck: "not ok"}, "integrity_check: not ok"},
		{&VerificationError{ForeignKeyViolations: 2}, "foreign_key_check: 2 violation(s)"},
		{&VerificationError{IntegrityCheck: "not ok", ForeignKeyViolations: 1}, "integrity_check: not ok; foreign_key_check: 1 violation(s)"},
	} {
		if got := tc.value.Error(); got != tc.want {
			t.Errorf("verification error = %q, want %q", got, tc.want)
		}
	}
	var nilSidecar *RestoreSidecarError
	if got := nilSidecar.Error(); got != ErrRestoreSidecars.Error() || !errors.Is(nilSidecar, ErrRestoreSidecars) {
		t.Fatalf("nil sidecar error = %q", got)
	}
	sidecar := &RestoreSidecarError{Paths: []string{"a-wal", "b-shm"}}
	if got := sidecar.Error(); !strings.Contains(got, "a-wal") || !errors.Is(sidecar, ErrRestoreSidecars) {
		t.Fatalf("sidecar error = %q", got)
	}

	for _, tc := range []struct {
		selector, want string
	}{
		{"managed:alerts:1", "managed:alerts"},
		{"managed:alerts", "managed:alerts"},
		{"managed:", "managed:"},
		{"deployment:abc", "deployment:abc"},
		{"", ""},
	} {
		if got := deliveryIdentity(tc.selector); got != tc.want {
			t.Errorf("delivery identity %q = %q, want %q", tc.selector, got, tc.want)
		}
	}
	if deliveryErrorFingerprint(nil) != "" || deliverySelectorFingerprint("") == "" {
		t.Fatal("delivery fingerprints did not handle empty values")
	}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.Canceled, "canceled"},
		{context.DeadlineExceeded, "timeout"},
		{ErrDeliveryDestinationLocked, "destination_locked"},
		{ErrDeliveryDestinationMissing, "destination_missing"},
		{ErrDeliveryProviderPanic, "provider_panic"},
		{ErrDeliveryWorkerPanic, "worker_panic"},
		{ErrDeliveryIndeterminate, "delivery_indeterminate"},
		{ErrDeliveryProvider, "delivery_failed"},
		{fmt.Errorf("other"), "delivery_failed"},
		{nil, ""},
	} {
		if got := deliveryErrorCode(tc.err); got != tc.want {
			t.Errorf("delivery error code %v = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestCoveragePolicySSEAndUpdateEdgeCases(t *testing.T) {
	ctx := context.Background()
	if _, _, err := (*Store)(nil).ReserveSSEEventIDs(ctx, 1); err == nil {
		t.Fatal("nil store reserved SSE IDs")
	}
	s := openTestStore(t)
	if _, _, err := s.ReserveSSEEventIDs(ctx, 0); err == nil {
		t.Fatal("empty SSE range accepted")
	}
	if _, _, err := s.ReserveSSEEventIDs(ctx, uint64(^uint64(0))); err == nil {
		t.Fatal("oversized SSE range accepted")
	}
	if _, _, err := s.ReserveSSEEventIDsAfter(ctx, 1, uint64(^uint64(0))); err == nil {
		t.Fatal("exhausted SSE cursor accepted")
	}
	if _, err := s.RecordInstalledVersion(ctx, "", "", true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, applicationUpdateStateQuery()).Scan(new(string), new(string), new(string), new(string), new(string), new(string), new(string), new(string), new(string), new(string), new(string), new(string), new(string)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE application_update_state SET notification_destinations_json=? WHERE id=1`, `not-json`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetApplicationUpdateState(ctx); err == nil {
		t.Fatal("malformed update destinations were accepted")
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE application_update_state SET notification_destinations_json='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if state, err := s.GetApplicationUpdateState(ctx); err != nil || state.UpdateNotificationDestinationsConfigured {
		t.Fatalf("empty update destinations = %#v, %v", state, err)
	}

	// Exercise the time parser fallback used by legacy rows.
	if got := profileTime("not-a-time"); !got.IsZero() {
		t.Fatalf("invalid profile time = %v", got)
	}
	if got := profileTime(time.Now().UTC().Format(time.RFC3339Nano)); got.IsZero() {
		t.Fatal("valid profile time was lost")
	}
}
