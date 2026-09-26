package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// Sign-in and session authentication find an account of any tenant and
// carry its tenant. A failed attempt on a known account is recorded in the
// account's tenant. A tenant that is not active stops sign-in with the
// answer a wrong password gets, and records the attempt in that tenant.
func TestSignInCarriesTheAccountTenant(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const (
		otherTenantID = "00000000-0000-0000-0000-000000000200"
		password      = "correct horse battery staple"
	)
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, otherTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	scope, err := s.TenantScopeByID(ctx, otherTenantID)
	if err != nil {
		t.Fatal(err)
	}
	// The weakest hash that verification accepts keeps the checks cheap.
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(password), salt, 1, 8, 1, 32)
	hash := fmt.Sprintf("$ew$argon2id$v=19$m=8,t=1,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	user, err := s.Tenant(scope).CreateUser(ctx, store.User{Username: "other-operator", Role: store.RoleOperator, PasswordHash: hash, Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(s)
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		return r
	}
	lastAudit := func(action string) [2]string {
		t.Helper()
		var record [2]string
		if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(tenant_id,'<null>'),actor_kind FROM security_audit WHERE action=? ORDER BY id DESC LIMIT 1`, action).Scan(&record[0], &record[1]); err != nil {
			t.Fatalf("audit record %s: %v", action, err)
		}
		return record
	}
	want := [2]string{otherTenantID, store.AuditActorUnit}

	if _, _, err := m.LoginAs(ctx, request(), "other-operator", "wrong password", "", ""); err == nil {
		t.Fatal("a wrong password signed in")
	}
	if got := lastAudit("auth.login_failed"); got != want {
		t.Fatalf("failed sign-in audit record = %v, want %v", got, want)
	}

	// A session of the account authenticates with the account's tenant.
	if err := s.CreateSessionForUserWithAuditEntry(ctx, user.ID, digest("other-session"), "csrf", now, now.Add(time.Hour), store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	authenticated := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	authenticated.AddCookie(&http.Cookie{Name: SessionCookie, Value: "other-session"})
	session, ok := m.AuthenticateReadOnly(ctx, authenticated)
	if !ok || session.TenantID != otherTenantID || session.Username != "other-operator" {
		t.Fatalf("session = %+v, %v", session, ok)
	}
	if scope, err := s.TenantScopeForSession(ctx, session); err != nil || scope.ID() != otherTenantID {
		t.Fatalf("session scope = %q, %v", scope.ID(), err)
	}

	if _, err := s.DB.ExecContext(ctx, `UPDATE tenants SET state='disabled' WHERE id=?`, otherTenantID); err != nil {
		t.Fatal(err)
	}
	failures := 0
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='auth.login_failed'`).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if raw, _, err := m.LoginAs(ctx, request(), "other-operator", password, "", ""); err == nil || err.Error() != "invalid credentials" || raw != "" {
		t.Fatalf("sign-in to a disabled tenant = %q, %v", raw, err)
	}
	var after int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='auth.login_failed'`).Scan(&after); err != nil || after != failures+1 {
		t.Fatalf("failed sign-ins recorded = %d, %v; want %d", after, err, failures+1)
	}
	if got := lastAudit("auth.login_failed"); got != want {
		t.Fatalf("disabled tenant sign-in audit record = %v, want %v", got, want)
	}
	var sessions int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, user.ID).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("sessions after the refused sign-in = %d, %v", sessions, err)
	}
}
