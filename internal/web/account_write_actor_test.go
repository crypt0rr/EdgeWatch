package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// gatedBody is a request body whose first Read tells the test that the
// request has passed the gate and its handler is reading the body, and then
// waits until the test releases it.
type gatedBody struct {
	body    io.Reader
	reading chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *gatedBody) Read(p []byte) (int, error) {
	b.once.Do(func() {
		close(b.reading)
		<-b.release
	})
	return b.body.Read(p)
}

// startGated sends the request as the actor through the API router, with a
// gatedBody, and returns once its handler has started reading the body.
// finish releases the body and returns the response.
func (f *platformFixture) startGated(t *testing.T, actor, method, path, body string) (finish func() *httptest.ResponseRecorder) {
	t.Helper()
	gate := &gatedBody{body: strings.NewReader(body), reading: make(chan struct{}), release: make(chan struct{})}
	account := f.sessions[actor]
	request := httptest.NewRequest(method, consoleAPIBase+path, gate)
	request.RemoteAddr = "127.0.0.1:9000"
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: account.raw})
	request.Header.Set("X-CSRF-Token", account.session.CSRFToken)
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.server.api(recorder, request)
	}()
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(gate.release) })
		<-done
	}
	t.Cleanup(release)
	select {
	case <-gate.reading:
	case <-done:
		t.Fatalf("%s %s answered before reading its body: %d %s", method, path, recorder.Code, recorder.Body.String())
	case <-time.After(10 * time.Second):
		t.Fatalf("%s %s did not read its body", method, path)
	}
	return func() *httptest.ResponseRecorder {
		release()
		return recorder
	}
}

// accountState is a text snapshot of every account, link, session and
// audit record, to show that a refused request wrote none of them.
func accountState(t *testing.T, db *store.Store) string {
	t.Helper()
	var state strings.Builder
	for _, query := range []string{
		`SELECT id||' '||COALESCE(tenant_id,'')||' '||username||' '||role||' '||enabled||' '||password_hash||' '||revision FROM users ORDER BY id`,
		`SELECT id_hash||' '||user_id||' '||issuer_user_id||' '||COALESCE(used_at,'') FROM user_invites ORDER BY id_hash`,
		`SELECT id_hash||' '||user_id FROM sessions ORDER BY id_hash`,
		`SELECT id||' '||action||' '||COALESCE(tenant_id,'')||' '||actor_user_id FROM security_audit ORDER BY id`,
	} {
		for _, row := range queryRows(t, db, query) {
			state.WriteString(row + "\n")
		}
		state.WriteString("--\n")
	}
	return state.String()
}

// queryRows returns the text of each row that the one-column query finds.
func queryRows(t *testing.T, db *store.Store, query string) []string {
	t.Helper()
	rows, err := db.DB.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			t.Fatal(err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

// countWhere counts the rows that the query finds.
func countWhere(t *testing.T, db *store.Store, query string, args ...any) int {
	t.Helper()
	var count int
	if err := db.DB.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// expectGateRefusal checks that the response is the gate's refusal of a
// route: 403 forbidden for the route permission.
func expectGateRefusal(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var payload struct {
		Error struct {
			Code    string            `json:"code"`
			Details map[string]string `json:"details"`
		} `json:"error"`
	}
	if response.Code != http.StatusForbidden || json.Unmarshal(response.Body.Bytes(), &payload) != nil || payload.Error.Code != "forbidden" || payload.Error.Details["permission"] != "route" {
		t.Fatalf("response = %d %s, want the gate's 403 forbidden", response.Code, response.Body.String())
	}
}

// A unit administrator's account write is authorized when its request
// passes the gate, and checked again when it is written. When another
// administrator demotes the actor while the request's body is still being
// read, the write is refused with the gate's 403, and no account, link,
// session or audit record is written. Without the demotion the same request
// succeeds.
func TestAccountWritesStopWhenTheAdministratorIsDemoted(t *testing.T) {
	t.Parallel()
	for _, route := range []struct {
		name, method, path, body string
		ok                       int
		// check runs after a refusal, with the fixture's accounts.
		check func(t *testing.T, f *platformFixture, actor, target string)
	}{
		{"create an account", http.MethodPost, "/users", confirmBody(`"username":"late-admin","role":"administrator"`), http.StatusCreated, func(t *testing.T, f *platformFixture, actor, target string) {
			if got := countWhere(t, f.db, `SELECT COUNT(*) FROM users WHERE username='late-admin'`); got != 0 {
				t.Errorf("the refused request created %d accounts", got)
			}
			if got := countWhere(t, f.db, `SELECT COUNT(*) FROM user_invites WHERE issuer_user_id=? AND used_at IS NULL`, actor); got != 0 {
				t.Errorf("the demoted administrator has %d usable links", got)
			}
			if got := countWhere(t, f.db, `SELECT COUNT(*) FROM security_audit WHERE action='user.created' AND actor_user_id=?`, actor); got != 0 {
				t.Errorf("the refused request recorded %d account creations", got)
			}
		}},
		{"reset an administrator's password", http.MethodPost, "/users/{second}/password-reset", confirmBody(""), http.StatusOK, func(t *testing.T, f *platformFixture, actor, target string) {
			if got := countWhere(t, f.db, `SELECT COUNT(*) FROM user_invites WHERE user_id=? AND used_at IS NULL`, target); got != 0 {
				t.Errorf("the refused request left %d usable links for the administrator", got)
			}
		}},
		{"issue a pending account's activation", http.MethodPost, "/users/{pending}/activation", confirmBody(""), http.StatusOK, func(t *testing.T, f *platformFixture, actor, target string) {
			if got := countWhere(t, f.db, `SELECT COUNT(*) FROM user_invites WHERE user_id=? AND used_at IS NULL`, target); got != 0 {
				t.Errorf("the refused request left %d usable links for the pending account", got)
			}
		}},
		{"change an account's role", http.MethodPatch, "/users/{operator}", confirmBody(`"role":"viewer"`), http.StatusOK, func(t *testing.T, f *platformFixture, actor, target string) {
			if user, err := f.a.GetUser(context.Background(), target); err != nil || user.Role != store.RoleOperator {
				t.Errorf("the operator after the refused change = %+v, %v", user, err)
			}
		}},
		{"revoke an account's sessions", http.MethodDelete, "/users/{operator}/sessions", confirmBody(""), http.StatusNoContent, func(t *testing.T, f *platformFixture, actor, target string) {
			if got := countWhere(t, f.db, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, target); got != 1 {
				t.Errorf("the operator has %d sessions after the refused revocation, want 1", got)
			}
		}},
		{"revoke a pending account's activation", http.MethodDelete, "/users/{invited}/activation", confirmBody(""), http.StatusNoContent, func(t *testing.T, f *platformFixture, actor, target string) {
			if got := countWhere(t, f.db, `SELECT COUNT(*) FROM user_invites WHERE user_id=? AND used_at IS NULL`, target); got != 1 {
				t.Errorf("the pending account has %d usable links after the refused revocation, want 1", got)
			}
		}},
	} {
		for _, demote := range []bool{true, false} {
			name := route.name
			if !demote {
				name += " without a demotion"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				f := newPlatformFixture(t)
				hash := cheapPasswordHash(platformFixturePassword)
				second, err := storetest.CreateUser(ctx, f.db, store.DefaultTenantScope(), store.User{Username: "alpha-second-admin", Role: store.RoleAdministrator, PasswordHash: hash, Enabled: true})
				if err != nil {
					t.Fatal(err)
				}
				pending, err := storetest.CreateUser(ctx, f.db, store.DefaultTenantScope(), store.User{Username: "alpha-pending", Role: store.RoleViewer, PasswordHash: "!pending"})
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				invited, err := f.a.CreateUserWithInvite(ctx, store.User{Username: "alpha-invited", Role: store.RoleViewer, PasswordHash: "!pending"}, "alpha-invited-link", now, now.Add(time.Hour), store.AuditEntry{Action: "user.created", ActorUserID: second.ID, ActorUsername: second.Username})
				if err != nil {
					t.Fatal(err)
				}
				actor, operator := f.users[actorAdminA].ID, f.users[actorOperatorA].ID
				targets := map[string]string{"{second}": second.ID, "{pending}": pending.ID, "{operator}": operator, "{invited}": invited.ID}
				path, target := route.path, ""
				for placeholder, id := range targets {
					if strings.Contains(path, placeholder) {
						path, target = strings.ReplaceAll(path, placeholder, id), id
					}
				}
				finish := f.startGated(t, actorAdminA, route.method, path, route.body)
				if !demote {
					if response := finish(); response.Code != route.ok {
						t.Fatalf("%s %s = %d %s, want %d", route.method, path, response.Code, response.Body.String(), route.ok)
					}
					return
				}
				demoted, err := f.a.GetUser(ctx, actor)
				if err != nil {
					t.Fatal(err)
				}
				demoted.Role = store.RoleViewer
				if err := f.a.UpdateUser(ctx, demoted, true, store.AuditEntry{Action: "user.updated", Detail: "demoted", ActorUserID: second.ID, ActorUsername: second.Username}); err != nil {
					t.Fatal(err)
				}
				before := accountState(t, f.db)
				expectGateRefusal(t, finish())
				if after := accountState(t, f.db); after != before {
					t.Fatalf("the refused request changed the accounts:\nbefore:\n%s\nafter:\n%s", before, after)
				}
				route.check(t, f, actor, target)
			})
		}
	}
}

// When the platform administrator disables a unit while one of its
// administrator's link requests is still reading its body, the write is
// refused with the gate's 403, and after the unit is enabled again it has
// no usable link: the disable revoked the older ones, and none was written
// after it. Without the disable the same request succeeds.
func TestLinksStopWhenTheUnitIsDisabled(t *testing.T) {
	t.Parallel()
	for _, route := range []struct {
		name, path, body string
		ok               int
	}{
		{"create an account", "/users", confirmBody(`"username":"bravo-late","role":"administrator"`), http.StatusCreated},
		{"reset a viewer's password", "/users/{viewer}/password-reset", confirmBody(""), http.StatusOK},
	} {
		for _, disable := range []bool{true, false} {
			name := route.name
			if !disable {
				name += " in an active unit"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				f := newPlatformFixture(t)
				path := strings.ReplaceAll(route.path, "{viewer}", f.viewerB)
				finish := f.startGated(t, actorAdminB, http.MethodPost, path, route.body)
				if !disable {
					if response := finish(); response.Code != route.ok {
						t.Fatalf("POST %s = %d %s, want %d", path, response.Code, response.Body.String(), route.ok)
					}
					return
				}
				unit, err := f.db.Platform().GetTenant(ctx, f.unitB)
				if err != nil {
					t.Fatal(err)
				}
				platformAudit := store.AuditEntry{ActorUserID: f.users[actorPlatform].ID, ActorUsername: "platform-root", ActorKind: store.AuditActorPlatform}
				if unit, err = f.server.App.DisableUnit(ctx, f.unitB, unit.Revision, platformAudit); err != nil {
					t.Fatal(err)
				}
				before := accountState(t, f.db)
				expectGateRefusal(t, finish())
				if after := accountState(t, f.db); after != before {
					t.Fatalf("the refused request changed the accounts:\nbefore:\n%s\nafter:\n%s", before, after)
				}
				if _, err := f.server.App.EnableUnit(ctx, f.unitB, unit.Revision, platformAudit); err != nil {
					t.Fatal(err)
				}
				if got := countWhere(t, f.db, `SELECT COUNT(*) FROM user_invites WHERE used_at IS NULL AND user_id IN (SELECT id FROM users WHERE tenant_id=?)`, f.unitB); got != 0 {
					t.Fatalf("unit B has %d usable links after it was enabled again", got)
				}
				if got := countWhere(t, f.db, `SELECT COUNT(*) FROM users WHERE username='bravo-late'`); got != 0 {
					t.Fatalf("the refused request created %d accounts", got)
				}
			})
		}
	}
}
