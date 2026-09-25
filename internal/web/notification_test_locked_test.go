package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The aggregate notification test must fail, not report {"sent":0}, while an
// enabled web-managed destination is locked by a missing or wrong key.
func TestNotificationTestReportsLockedManagedDestination(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	// The destination is locked before the test and is never contacted.
	if _, err := server.App.Notifier.CreateManaged(ctx, "Ops", "generic://127.0.0.1:9/ops?disabletls=yes", true); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(db.Path), "notification.key")); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/test", nil)
	request.RemoteAddr = "127.0.0.1:4"
	response := httptest.NewRecorder()
	server.notificationTest(response, request, admin)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "notification_key_unavailable") {
		t.Fatalf("locked notification test = %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "generic://") || strings.Contains(response.Body.String(), "127.0.0.1:9") {
		t.Fatalf("locked notification test leaked a destination URL: %s", response.Body.String())
	}
	var failed, succeeded int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='notifications.test_failed'`).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='notifications.test'`).Scan(&succeeded); err != nil {
		t.Fatal(err)
	}
	if failed != 1 || succeeded != 0 {
		t.Fatalf("locked notification test audits: failed=%d succeeded=%d", failed, succeeded)
	}
}
