package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// recordFailedBackup turns scheduled backups on for the server and records a
// failed backup after a good one, as the daemon does.
func recordFailedBackup(t *testing.T, server *Server, database string) {
	t.Helper()
	server.App.Config.Backup = config.Backup{Directory: "/var/lib/edgewatch/backups", Schedule: "0 3 * * *", Keep: 7}
	raw, err := json.Marshal(app.BackupStatus{Directory: "/var/lib/edgewatch/backups", LastSuccessAt: time.Now().UTC().Add(-26 * time.Hour), LastBackup: "edgewatch-scheduled-20261001T030000Z.db", LastFailureAt: time.Now().UTC(), LastError: "disk full", ConsecutiveFailures: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app.BackupStatusPath(database), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// With one unit, its administrators see the outcome of the scheduled
// backups in the status that the console shows them; operators and viewers
// do not, and nothing is shown while scheduled backups are off.
func TestScheduledBackupStatusInTheSingleUnitStatus(t *testing.T) {
	t.Parallel()
	server, db, admin := newUsersTestServer(t)
	status := func(role string) map[string]any {
		t.Helper()
		session := admin
		session.Role = role
		recorder := httptest.NewRecorder()
		server.adminStatus(recorder, httptest.NewRequest(http.MethodGet, consoleAPIBase+"/status", nil), session, defaultTenantStore(server))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status as %s = %d %s", role, recorder.Code, recorder.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	if _, shown := status(store.RoleAdministrator)["backups"]; shown {
		t.Fatal("the status reports scheduled backups while they are off")
	}
	recordFailedBackup(t, server, db.Path)
	backups, shown := status(store.RoleAdministrator)["backups"].(map[string]any)
	if !shown || backups["consecutive_failures"] != float64(1) || backups["last_error"] != "disk full" || backups["last_backup"] != "edgewatch-scheduled-20261001T030000Z.db" || backups["last_success_age_seconds"] == nil {
		t.Fatalf("administrator's backup status = %#v", backups)
	}
	for _, role := range []string{store.RoleOperator, store.RoleViewer} {
		if _, shown := status(role)["backups"]; shown {
			t.Errorf("%s's status reports the scheduled backups", role)
		}
	}
}

// The platform status reports the scheduled backups. Once more than one
// unit exists, a unit's status leaves them out, as it leaves out the other
// deployment-wide signals.
func TestScheduledBackupStatusOnThePlatform(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	platformStatus := func() map[string]any {
		t.Helper()
		response := f.call(t, actorPlatform, http.MethodGet, "/platform/status", "")
		if response.Code != http.StatusOK {
			t.Fatalf("platform status = %d %s", response.Code, response.Body.String())
		}
		var status map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		return status
	}
	if _, shown := platformStatus()["backups"]; shown {
		t.Fatal("the platform status reports scheduled backups while they are off")
	}
	recordFailedBackup(t, f.server, f.db.Path)
	if backups, shown := platformStatus()["backups"].(map[string]any); !shown || backups["last_error"] != "disk full" || backups["directory"] != "/var/lib/edgewatch/backups" {
		t.Fatalf("platform backup status = %#v", platformStatus()["backups"])
	}
	for _, actor := range []string{actorAdminA, actorAdminB} {
		if response := f.call(t, actor, http.MethodGet, "/status", ""); response.Code != http.StatusOK || strings.Contains(response.Body.String(), `"backups"`) {
			t.Errorf("%s's status with several units = %d %s, want no backups", actor, response.Code, response.Body.String())
		}
	}
}
