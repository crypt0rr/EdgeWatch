package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestAuthenticateReadOnlyDoesNotTouchIdleTimestamp(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewManager(db)
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return now }
	token, err := m.EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(ctx, token, "administrator password"); err != nil {
		t.Fatal(err)
	}
	loginRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	loginRequest.RemoteAddr = "192.0.2.10:8080"
	raw, _, err := m.Login(ctx, loginRequest, "administrator password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	before, err := db.GetSession(ctx, digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	request.RemoteAddr = "192.0.2.10:8080"
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: raw})
	authenticated, ok := m.AuthenticateReadOnly(ctx, request)
	if !ok || authenticated.Username != "admin" || authenticated.Role != store.RoleAdministrator {
		t.Fatalf("read-only authentication = %#v, %t", authenticated, ok)
	}
	after, err := db.GetSession(ctx, digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !after.LastSeenAt.Equal(before.LastSeenAt) {
		t.Fatalf("read-only authentication touched idle timestamp: before=%s after=%s", before.LastSeenAt, after.LastSeenAt)
	}
	if got := sourceScope(nil); got != "source:unknown" {
		t.Fatalf("nil source scope = %q", got)
	}
	if got := m.sourceScope(request); got != "source:auth:192.0.2.10" {
		t.Fatalf("source scope = %q", got)
	}
}

func TestAuthenticateReadOnlyRejectsDisabledAccount(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewManager(db)
	token, err := m.EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(ctx, token, "administrator password"); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "192.0.2.20:8080"
	raw, _, err := m.Login(ctx, request, "administrator password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE users SET enabled=0 WHERE id=?`, store.LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: raw})
	if _, ok := m.AuthenticateReadOnly(ctx, request); ok {
		t.Fatal("disabled account authenticated through read-only path")
	}
}
