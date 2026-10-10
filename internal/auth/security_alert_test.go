package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// Repeated rate-limit refusals of sign-ins to a unit's account, from one
// client and from several, produce one security alert to that unit's
// destination within the alert window; the default unit, which routes its
// own security alerts, gets none. The alert names the account and the first
// client, and neither the attempted password nor a URL.
func TestRepeatedRateLimitRefusalsSendOneSecurityAlert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _, _ := platformTestStore(t)
	addSecondUnit(t, s)
	scope, err := s.TenantScopeByID(ctx, platformTestTenantID)
	if err != nil {
		t.Fatal(err)
	}
	unit := s.Tenant(scope)
	if _, err := storetest.CreateUser(ctx, s, scope, store.User{Username: "bravo-admin", Role: store.RoleAdministrator, PasswordHash: cheapHash("unit b administrator password"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for owner, ts := range map[string]*store.TenantStore{"bravo": unit, "default": s.Tenant(store.DefaultTenantScope())} {
		destination, err := ts.CreateManagedNotification(ctx, "", owner+"-ops", "generic", []byte("sealed "+owner), []byte("nonce "+owner), true)
		if err != nil {
			t.Fatal(err)
		}
		if err := ts.SetSecurityAlertDestinations(ctx, []string{destination.ID}, store.AuditEntry{}); err != nil {
			t.Fatal(err)
		}
	}
	m := NewManager(s)
	const wrong = "wrong password not for alerts"
	for _, address := range []string{"203.0.113.11", "203.0.113.12", "203.0.113.13"} {
		for attempt := 0; attempt <= authFailureThreshold+3; attempt++ {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
			r.RemoteAddr = address + ":4000"
			_, _, err := m.LoginAs(ctx, r, "bravo-admin", wrong, "", "")
			if attempt >= authFailureThreshold && !errors.Is(err, ErrRateLimited) {
				t.Fatalf("attempt %d from %s = %v, want ErrRateLimited", attempt, address, err)
			}
		}
	}
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}
	var records int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action='auth.rate_limited' AND tenant_id=?`, platformTestTenantID).Scan(&records); err != nil || records != 3 {
		t.Fatalf("rate-limit records = %d, %v; want one per client", records, err)
	}
	rows, err := s.DB.Query(`SELECT COALESCE(tenant_id,''),CAST(payload_json AS TEXT) FROM outbox WHERE json_extract(CAST(payload_json AS TEXT),'$.type')=?`, model.EventSecurityAlert)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var payloads []string
	for rows.Next() {
		var tenant, payload string
		if err := rows.Scan(&tenant, &payload); err != nil {
			t.Fatal(err)
		}
		if tenant != platformTestTenantID {
			t.Errorf("a security alert went to %q", tenant)
		}
		payloads = append(payloads, payload)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 1 {
		t.Fatalf("security alerts = %v, want one", payloads)
	}
	for _, want := range []string{`"kind":"rate_limited"`, `"account":"bravo-admin"`, `"operation":"sign-in"`} {
		if !strings.Contains(payloads[0], want) {
			t.Errorf("alert %s lacks %s", payloads[0], want)
		}
	}
	for _, leak := range []string{wrong, "://"} {
		if strings.Contains(payloads[0], leak) {
			t.Errorf("alert %s contains %q", payloads[0], leak)
		}
	}
	held, err := s.System().FlushSecurityAlertWindows(ctx, time.Now().UTC().Add(store.SecurityAlertWindow+time.Minute))
	if err != nil || held != 1 {
		t.Fatalf("summaries after the window = %d, %v; want one for the two held episodes", held, err)
	}
}
