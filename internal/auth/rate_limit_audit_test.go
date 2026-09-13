package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestRateLimitAuditCoalescesRotatingLoginIdentities(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Date(2026, 9, 13, 7, 0, 0, 0, time.UTC)
	m := NewManager(db)
	m.Now = func() time.Time { return now }
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "198.51.100.10:443"
	for i := 0; i < 100; i++ {
		m.auditRateLimit(ctx, "unknown-login:user-"+strconv.Itoa(i), request)
	}
	var rows int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='auth.rate_limited'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("rotating usernames created %d rate-limit audits, want one", rows)
	}

	otherSource := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	otherSource.RemoteAddr = "198.51.100.11:443"
	m.auditRateLimit(ctx, "login:admin", otherSource)
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='auth.rate_limited'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("distinct sources created %d rate-limit audits, want two", rows)
	}
}

func TestRateAuditEndpointGroupsLoginSubjectsOnly(t *testing.T) {
	for subject, want := range map[string]string{
		"setup":                    "setup",
		"activation":               "activation",
		"password-confirmation":    "password-confirmation",
		"login:admin":              "login",
		"unknown-login:probe-user": "login",
		"custom":                   "custom",
	} {
		if got := rateAuditEndpoint(subject); got != want {
			t.Errorf("rateAuditEndpoint(%q) = %q, want %q", subject, got, want)
		}
	}
}
