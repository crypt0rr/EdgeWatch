package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/updatecheck"
)

func TestStatusLinksRunningVersionToItsRelease(t *testing.T) {
	server, db, admin := newUsersTestServer(t)
	viewerUser, err := db.CreateUser(context.Background(), store.User{Username: "viewer", DisplayName: "Read only", Role: store.RoleViewer, PasswordHash: "hash", Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	viewer := store.Session{UserID: viewerUser.ID, Username: viewerUser.Username, Role: store.RoleViewer}
	status := func(session store.Session) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		server.adminStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil), session)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	server.Version = "0.18.141"
	want := updatecheck.ReleasePageBase + "v0.18.141"
	for name, session := range map[string]store.Session{"administrator": admin, "viewer": viewer} {
		if got := status(session)["version_release_url"]; got != want {
			t.Fatalf("%s status version_release_url = %#v, want %q", name, got, want)
		}
	}

	for _, version := range []string{"dev", "", "0.18.141-3-gabc1234"} {
		server.Version = version
		for name, session := range map[string]store.Session{"administrator": admin, "viewer": viewer} {
			if got, ok := status(session)["version_release_url"]; ok {
				t.Fatalf("%s status for version %q linked %#v, want no release link", name, version, got)
			}
		}
	}
}
