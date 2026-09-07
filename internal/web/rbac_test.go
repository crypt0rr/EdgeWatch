package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestRBACSeparatesViewerReadsAndOperatorNotificationManagement(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	adminHash, err := auth.PasswordHash("administrator password")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAdmin(ctx, store.Admin{Username: "admin", PasswordHash: adminHash, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	viewerHash, err := auth.PasswordHash("viewer account password")
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := s.CreateUser(ctx, store.User{Username: "viewer", DisplayName: "Read only", Role: store.RoleViewer, PasswordHash: viewerHash, Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	operatorHash, err := auth.PasswordHash("operator account password")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := s.CreateUser(ctx, store.User{Username: "operator", DisplayName: "Operator", Role: store.RoleOperator, PasswordHash: operatorHash, Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Version: 1, Database: filepath.Join(t.TempDir(), "edgewatch.db"), Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(NewServer(a, s, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer h.Close()

	login := func(username, password string) (string, store.Session) {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = "127.0.0.1:4567"
		raw, _, loginErr := auth.NewManager(s).LoginAs(ctx, r, username, password, "", "")
		if loginErr != nil {
			t.Fatal(loginErr)
		}
		session, sessionErr := s.GetSession(ctx, digest(raw))
		if sessionErr != nil {
			t.Fatal(sessionErr)
		}
		session.UserID = map[string]string{"viewer": viewer.ID, "operator": operator.ID}[username]
		// Authenticate resolves the identity from the persisted session; the
		// assignment above is only a guard against a malformed fixture.
		return raw, session
	}
	request := func(raw string, session store.Session, method, path, body string) *http.Response {
		req, requestErr := http.NewRequest(method, h.URL+path, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if method != http.MethodGet {
			req.Header.Set("X-CSRF-Token", session.CSRFToken)
		}
		response, requestErr := (&http.Client{}).Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}

	viewerRaw, viewerSession := login("viewer", "viewer account password")
	resp := request(viewerRaw, viewerSession, http.MethodGet, "/api/v1/jobs", "")
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("viewer jobs status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = request(viewerRaw, viewerSession, http.MethodPost, "/api/v1/jobs", `{}`)
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("viewer job mutation status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = request(viewerRaw, viewerSession, http.MethodGet, "/api/v1/notifications/destinations", "")
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("viewer notification status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = request(viewerRaw, viewerSession, http.MethodGet, "/api/v1/hosts", "")
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("viewer host inventory status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = request(viewerRaw, viewerSession, http.MethodGet, "/api/v1/scans/active", "")
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("viewer active scans status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	for _, path := range []string{"/api/v1/jobs/unknown/scans", "/api/v1/jobs/unknown/scans/scan-id", "/api/v1/jobs/unknown/events", "/api/v1/jobs/unknown/scan-cycle"} {
		resp = request(viewerRaw, viewerSession, http.MethodGet, path, "")
		if resp.StatusCode != http.StatusForbidden {
			resp.Body.Close()
			t.Fatalf("viewer %s status = %d", path, resp.StatusCode)
		}
		resp.Body.Close()
	}

	operatorRaw, operatorSession := login("operator", "operator account password")
	resp = request(operatorRaw, operatorSession, http.MethodGet, "/api/v1/notifications/destinations", "")
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("operator notification read status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = request(operatorRaw, operatorSession, http.MethodPost, "/api/v1/notifications/destinations", `{"name":"x","url":"generic://example.invalid","password":"operator account password"}`)
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("operator notification mutation status = %d", resp.StatusCode)
	}
	resp.Body.Close()
}
