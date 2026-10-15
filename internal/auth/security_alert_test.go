package auth

import (
	"context"
	"encoding/json"
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

// Repeated rate-limit refusals and admitted wrong passwords produce one
// alert of each kind within their respective windows. The alerts go only to
// the unit's destination; the default unit gets none. The rate-limit alert
// names the first client, while the account-wide alert has no source address.
// Neither alert includes the attempted password or a URL.
func TestRepeatedRateLimitRefusalsCoalesceSecurityAlertsByKind(t *testing.T) {
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
	payloads := make(map[string]model.Event)
	payloadJSON := make(map[string]string)
	for rows.Next() {
		var tenant, payload string
		if err := rows.Scan(&tenant, &payload); err != nil {
			t.Fatal(err)
		}
		if tenant != platformTestTenantID {
			t.Errorf("a security alert went to %q", tenant)
		}
		var event model.Event
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			t.Fatalf("decode security alert %s: %v", payload, err)
		}
		if event.Type != model.EventSecurityAlert || event.Alert == nil {
			t.Errorf("unexpected outbox event: %+v", event)
			continue
		}
		kind := event.Alert.Kind
		if _, exists := payloads[kind]; exists {
			t.Errorf("duplicate %s alert in one window: %s", kind, payload)
		}
		payloads[kind] = event
		payloadJSON[kind] = payload
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 {
		t.Fatalf("security alerts = %v, want one per kind", payloads)
	}
	rateLimited, ok := payloads[model.SecurityAlertRateLimited]
	if !ok || rateLimited.Alert.Account != "bravo-admin" || rateLimited.Alert.Operation != "sign-in" || rateLimited.Alert.Source != "203.0.113.11" {
		t.Errorf("rate-limit alert = %+v, want one sign-in alert for the first client", rateLimited)
	}
	aggregate, ok := payloads[model.SecurityAlertAccountSignInFailures]
	if !ok || aggregate.Alert.Account != "bravo-admin" || aggregate.Alert.Count != model.SecurityAlertAccountSignInFailureCount || aggregate.Alert.Source != "" {
		t.Errorf("account-wide alert = %+v, want count-only alert without source attribution", aggregate)
	}
	for kind, payload := range payloadJSON {
		for _, leak := range []string{wrong, "://", "203.0.113.12", "203.0.113.13"} {
			if strings.Contains(payload, leak) {
				t.Errorf("%s alert %s contains %q", kind, payload, leak)
			}
		}
	}
	held, err := s.System().FlushSecurityAlertWindows(ctx, time.Now().UTC().Add(store.SecurityAlertWindow+time.Minute))
	if err != nil || held != 1 {
		t.Fatalf("summaries after the window = %d, %v; want one summary for the two suppressed rate-limit alerts", held, err)
	}
}
