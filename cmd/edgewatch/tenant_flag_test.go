package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// tenantFlagFixture is a database with the default unit and the unit
// "other" of seedTwoTenants, and a config with business units off and one
// with them on. Both configs carry an inactive YAML job.
type tenantFlagFixture struct {
	dir, database string
	off, on       string
	ownJob        store.JobRecord
	webhookCalls  func() int32
}

func newTenantFlagFixture(t *testing.T) tenantFlagFixture {
	t.Helper()
	database := storetest.FreshPath(t)
	dir := filepath.Dir(database)
	rawURL, calls := importStartupWebhook(t)
	f := tenantFlagFixture{dir: dir, database: database, ownJob: seedTwoTenants(t, database, rawURL), webhookCalls: calls.Load}
	for _, config := range []struct {
		path  *string
		name  string
		extra string
	}{{&f.off, "off.yaml", ""}, {&f.on, "on.yaml", "experimental:\n  business_units: true\n"}} {
		*config.path = filepath.Join(dir, config.name)
		if err := os.WriteFile(*config.path, []byte("database: "+database+"\n"+config.extra+legacyCLIJobsYAML), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// cli runs the command line with configPath and JSON output, and returns
// its standard output.
func (f tenantFlagFixture) cli(t *testing.T, configPath string, args ...string) (string, error) {
	t.Helper()
	stdout, _, err := captureCLIOutput(t, func() error {
		return run(append(args, "--config", configPath, "--output", "json"))
	})
	return stdout, err
}

func (f tenantFlagFixture) setUnitState(t *testing.T, state string) {
	t.Helper()
	s, err := store.OpenExisting(f.database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, state, otherTenantID); err != nil {
		t.Fatal(err)
	}
}

type statusRow struct {
	Name             string `json:"name"`
	State            string `json:"state"`
	BaselineScanID   string `json:"baseline_scan_id"`
	ActiveIncidents  int    `json:"active_incidents"`
	LastScanID       string `json:"last_scan_id"`
	FailedDeliveries int    `json:"failed_deliveries"`
}

// With --tenant, every host command that acts on a unit's data acts on that
// unit only: it reads the unit's jobs, scans, events and baselines, runs the
// unit's job, changes the unit's baseline, tests the unit's destinations,
// and audits in the unit. The default unit's data stays as it was, although
// both units have a job named edge.
func TestHostCommandsWithTenantActOnlyOnThatUnit(t *testing.T) {
	ctx := context.Background()
	f := newTenantFlagFixture(t)
	// Every command that starts the application first freezes the default
	// unit's legacy notification selections, once. Let that happen before
	// the snapshot of the default unit's data.
	if _, err := f.cli(t, f.off, "notify", "test"); err != nil {
		t.Fatal(err)
	}
	before := otherTenantRows(t, f.database, store.DefaultTenantID)

	out, err := f.cli(t, f.on, "status", "--tenant", "other")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var rows []statusRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("status output %q: %v", out, err)
	}
	// The unit's two jobs, with its own scan, baseline, incident and failed
	// delivery, and not the default unit's inactive YAML job.
	if len(rows) != 2 || rows[0].Name != "edge" || rows[0].LastScanID != "scan-other" || rows[0].BaselineScanID != "scan-other" || rows[0].ActiveIncidents != 1 || rows[0].FailedDeliveries != 1 || rows[1].Name != "only-other" {
		t.Fatalf("status rows = %+v, want only the other unit's jobs", rows)
	}

	out, err = f.cli(t, f.on, "history", "--tenant", "other", "--job", "edge")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	var history struct {
		Scans  []model.Scan  `json:"scans"`
		Events []model.Event `json:"events"`
	}
	if err := json.Unmarshal([]byte(out), &history); err != nil {
		t.Fatalf("history output %q: %v", out, err)
	}
	if len(history.Scans) != 1 || history.Scans[0].ID != "scan-other" || len(history.Events) != 1 || history.Events[0].Message != "other tenant change" {
		t.Fatalf("history = %+v, want only the other unit's scan and event", history)
	}

	exportPath := filepath.Join(f.dir, "export-other.json")
	if _, err := f.cli(t, f.on, "baseline", "export", "--tenant", "other", "--out", exportPath); err != nil {
		t.Fatalf("baseline export: %v", err)
	}
	raw, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	var export store.BaselineExport
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatal(err)
	}
	if len(export.Jobs) != 2 || export.Jobs[0].JobID == f.ownJob.ID || export.Jobs[1].JobID == f.ownJob.ID || (export.Jobs[0].BaselineScanID != "scan-other" && export.Jobs[1].BaselineScanID != "scan-other") {
		t.Fatalf("baseline export = %s, want only the other unit's jobs", raw)
	}

	// approve takes only the unit's own scan for the unit's job.
	if _, err := f.cli(t, f.on, "baseline", "approve", "--tenant", "other", "--job", "edge", "--scan-id", "scan-default"); err == nil {
		t.Fatal("baseline approve accepted the default unit's scan")
	}
	if _, err := f.cli(t, f.on, "baseline", "approve", "--tenant", "other", "--job", "edge", "--scan-id", "scan-other"); err != nil {
		t.Fatalf("baseline approve: %v", err)
	}
	if _, err := f.cli(t, f.on, "baseline", "reset", "--tenant", "other", "--job", "edge"); err != nil {
		t.Fatalf("baseline reset: %v", err)
	}

	nmap := writeFakeNmap(t, f.dir, false)
	out, err = f.cli(t, f.on, "scan", "--tenant", "other", "--job", "only-other", "--nmap", nmap)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var scanned struct {
		Scan model.Scan `json:"scan"`
	}
	if err := json.Unmarshal([]byte(out), &scanned); err != nil || scanned.Scan.Job != "only-other" || scanned.Scan.Status != "success" {
		t.Fatalf("scan output = %s, %v; want a successful scan of the other unit's job", out, err)
	}

	callsBefore := f.webhookCalls()
	out, err = f.cli(t, f.on, "notify", "test", "--tenant", "other")
	if err != nil {
		t.Fatalf("notify test: %v", err)
	}
	var summary map[string]int
	if err := json.Unmarshal([]byte(out), &summary); err != nil || summary["tested"] != 1 || summary["failed"] != 0 {
		t.Fatalf("notify test summary = %s, %v; want the other unit's destination tested", out, err)
	}
	if got := f.webhookCalls() - callsBefore; got != 1 {
		t.Fatalf("the other unit's destination received %d test messages, want 1", got)
	}

	if after := otherTenantRows(t, f.database, store.DefaultTenantID); after != before {
		t.Fatalf("host commands with --tenant changed the default unit's data:\nbefore\n%s\nafter\n%s", before, after)
	}
	reader, err := store.OpenReadOnlyExisting(f.database)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var actions, actors []string
	auditRows, err := reader.DB.QueryContext(ctx, `SELECT action,COALESCE(actor_user_id,'') FROM security_audit WHERE actor_username='host-cli' AND actor_kind='host' AND tenant_id=? ORDER BY id`, otherTenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer auditRows.Close()
	for auditRows.Next() {
		var action string
		var actor sql.NullString
		if err := auditRows.Scan(&action, &actor); err != nil {
			t.Fatal(err)
		}
		actions, actors = append(actions, action), append(actors, actor.String)
	}
	if err := auditRows.Err(); err != nil {
		t.Fatal(err)
	}
	if want := "baseline.approved,baseline.reset,scan.run_requested,notifications.test"; strings.Join(actions, ",") != want {
		t.Fatalf("host audit actions in the other unit = %v, want %s", actions, want)
	}
	// The default unit's original administrator is not the other unit's.
	for _, actor := range actors {
		if actor == store.LegacyAdminUserID {
			t.Fatalf("the other unit's host audit names the default unit's administrator: %v", actors)
		}
	}
}

// withoutNextRun drops the next run times from status output, which move on
// the hour.
var withoutNextRun = regexp.MustCompile(`"next_run":"[^"]*",?`)

// Without --tenant, the host commands act on the default unit whether
// business units are on or off, with the same output.
func TestHostCommandsWithoutTenantKeepTheDefaultUnit(t *testing.T) {
	f := newTenantFlagFixture(t)
	for _, args := range [][]string{{"status"}, {"history"}, {"history", "--job", "edge"}, {"status", "--tenant", "default"}} {
		configs := []string{f.off, f.on}
		if args[len(args)-1] == "default" {
			// The default unit's own slug names the same data.
			configs = []string{f.on}
		}
		for _, config := range configs {
			out, err := f.cli(t, config, args...)
			if err != nil {
				t.Fatalf("%v with %s: %v", args, filepath.Base(config), err)
			}
			want, err := f.cli(t, f.off, strings.Fields(strings.ReplaceAll(strings.Join(args, " "), "--tenant default", ""))...)
			if err != nil {
				t.Fatal(err)
			}
			if out, want = withoutNextRun.ReplaceAllString(out, ""), withoutNextRun.ReplaceAllString(want, ""); out != want {
				t.Fatalf("%v with %s =\n%s\nwant\n%s", args, filepath.Base(config), out, want)
			}
			if !strings.Contains(out, "edge") || strings.Contains(out, "scan-other") || strings.Contains(out, "only-other") {
				t.Fatalf("%v with %s shows another unit's data: %s", args, filepath.Base(config), out)
			}
		}
	}
	out, err := f.cli(t, f.on, "status")
	if err != nil || !strings.Contains(out, `"legacy-yaml"`) {
		t.Fatalf("default unit's status = %s, %v; want its inactive YAML job", out, err)
	}
}

// --tenant is refused while business units are off, for an unknown or
// deleted unit, with an empty slug, and on commands that do not act on a
// unit's data. A unit that is being deleted is refused, and a disabled unit
// can be read but not scanned, changed or tested. Nothing is written.
func TestTenantFlagRefusals(t *testing.T) {
	f := newTenantFlagFixture(t)
	before := otherTenantRows(t, f.database, otherTenantID) + "\n" + otherTenantRows(t, f.database, store.DefaultTenantID)
	nmap := writeFakeNmap(t, f.dir, false)
	exportPath := filepath.Join(f.dir, "refused-export.json")
	commands := [][]string{
		{"status"}, {"history"}, {"scan", "--job", "only-other", "--nmap", nmap}, {"baseline", "export", "--out", exportPath},
		{"baseline", "approve", "--job", "edge", "--scan-id", "scan-other"}, {"baseline", "reset", "--job", "edge"}, {"notify", "test"},
		{"admin", "disable-totp", "--username", "admin"},
	}
	for _, args := range commands {
		if _, err := f.cli(t, f.off, append(args, "--tenant", "other")...); !errors.Is(err, app.ErrBusinessUnitsDisabled) || !strings.Contains(err.Error(), "--tenant") {
			t.Errorf("%v --tenant with business units off = %v", args, err)
		}
		if _, err := f.cli(t, f.on, append(args, "--tenant", "nobody")...); err == nil || !strings.Contains(err.Error(), `unknown business unit "nobody"`) {
			t.Errorf("%v --tenant nobody = %v", args, err)
		}
		if _, err := f.cli(t, f.on, append(args, "--tenant", " ")...); err == nil || !strings.Contains(err.Error(), "--tenant needs the slug") {
			t.Errorf("%v with an empty --tenant = %v", args, err)
		}
	}
	for name, args := range map[string][]string{
		"backup": {"backup", "--out", filepath.Join(f.dir, "backup.db")}, "verify": {"verify"}, "health": {"health"}, "daemon": {"daemon"},
		"config validate": {"config", "validate"}, "admin setup-token": {"admin", "setup-token", "--force"}, "admin platform-setup-token": {"admin", "platform-setup-token"},
	} {
		if _, err := f.cli(t, f.on, append(args, "--tenant", "other")...); err == nil || !strings.HasPrefix(err.Error(), "--tenant does not apply to "+name+";") {
			t.Errorf("%s --tenant = %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, "backup.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused backup wrote a file: %v", err)
	}
	// Slugs match exactly.
	if _, err := f.cli(t, f.on, "status", "--tenant", "Other"); err == nil || !strings.Contains(err.Error(), `unknown business unit "Other"`) {
		t.Fatalf("status --tenant Other = %v", err)
	}
	if _, err := os.Stat(exportPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused export wrote %s: %v", exportPath, err)
	}

	// A disabled unit can be read, but not scanned, changed or tested.
	f.setUnitState(t, store.TenantStateDisabled)
	for _, args := range commands[:4] {
		out, err := f.cli(t, f.on, append(args, "--tenant", "other")...)
		if args[0] == "scan" {
			if err == nil || !strings.Contains(err.Error(), `business unit "other" is disabled; enable it before running scan`) {
				t.Errorf("scan of a disabled unit = %v", err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%v of a disabled unit: %v", args, err)
		}
		if args[0] == "status" && !strings.Contains(out, "only-other") {
			t.Errorf("status of a disabled unit = %s", out)
		}
	}
	for _, args := range commands[4:7] {
		if _, err := f.cli(t, f.on, append(args, "--tenant", "other")...); err == nil || !strings.Contains(err.Error(), `business unit "other" is disabled`) {
			t.Errorf("%v of a disabled unit = %v", args, err)
		}
	}
	// A unit being deleted is refused for every command; a deleted unit has
	// no slug.
	f.setUnitState(t, store.TenantStateDeleting)
	for _, args := range commands[:7] {
		if _, err := f.cli(t, f.on, append(args, "--tenant", "other")...); err == nil || !strings.Contains(err.Error(), `business unit "other" is being deleted`) {
			t.Errorf("%v of a unit being deleted = %v", args, err)
		}
	}
	f.setUnitState(t, store.TenantStateDeleted)
	if _, err := f.cli(t, f.on, "status", "--tenant", "other"); err == nil || !strings.Contains(err.Error(), `unknown business unit "other"`) {
		t.Fatalf("status of a deleted unit = %v", err)
	}
	f.setUnitState(t, store.TenantStateActive)
	if err := os.Remove(exportPath); err != nil {
		t.Fatal(err)
	}
	after := otherTenantRows(t, f.database, otherTenantID) + "\n" + otherTenantRows(t, f.database, store.DefaultTenantID)
	if after != before {
		t.Fatalf("refused commands changed data:\nbefore\n%s\nafter\n%s", before, after)
	}
}

// The admin recovery commands find the account by its username across every
// unit. --tenant stops them unless the account belongs to that unit, and
// with business units on they print the account, its unit and its role
// before they act. With business units off their output is unchanged.
func TestAdminRecoveryWithTenant(t *testing.T) {
	ctx := context.Background()
	f := newTenantFlagFixture(t)
	s, err := store.Open(f.database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, store.Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	scope, err := s.TenantScopeByID(ctx, otherTenantID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Tenant(scope).CreateUser(ctx, store.User{Username: "other-admin", DisplayName: "Other", Role: store.RoleAdministrator, PasswordHash: "hash", Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	manager := auth.NewManager(s)
	manager.SetBusinessUnitsEnabled(true)
	token, err := manager.IssuePlatformSetupToken(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CompletePlatformSetup(ctx, token, "root", "platform administrator password"); err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(f.dir, "password")
	if err := os.WriteFile(passwordPath, []byte("replacement unit password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	passwordOf := func(username string) string {
		t.Helper()
		user, err := s.GetUserByUsername(ctx, username)
		if err != nil {
			t.Fatal(err)
		}
		return user.PasswordHash
	}
	admin := func(config string, args ...string) (string, error) {
		t.Helper()
		stdout, _, err := captureCLIOutput(t, func() error { return run(append(append([]string{"admin"}, args...), "--config", config)) })
		return stdout, err
	}

	// The account of another unit, or the platform's, is left alone.
	hashes := map[string]string{"admin": passwordOf("admin"), "root": passwordOf("root")}
	for username, where := range map[string]string{"admin": "the unit default", "root": "the platform"} {
		for _, action := range [][]string{{"reset-password", "--password-file", passwordPath}, {"disable-totp"}} {
			out, err := admin(f.on, append(action, "--username", username, "--tenant", "other")...)
			if err == nil || err.Error() != `user "`+username+`" belongs to `+where+`, not to business unit "other"; nothing was changed` || out != "" {
				t.Errorf("%s %s --tenant other = %q, %v", action[0], username, out, err)
			}
		}
		if got := passwordOf(username); got != hashes[username] {
			t.Errorf("a refused reset changed %s's password", username)
		}
	}
	if _, err := admin(f.on, "reset-password", "--username", "other-admin", "--tenant", "nobody", "--password-file", passwordPath); err == nil || !strings.Contains(err.Error(), `unknown business unit "nobody"`) {
		t.Fatalf("reset-password --tenant nobody = %v", err)
	}

	// The unit's own account is reset, after the command names it.
	out, err := admin(f.on, "reset-password", "--username", "other-admin", "--tenant", "other", "--password-file", passwordPath)
	if err != nil || out != `user "other-admin" (unit other, administrator)`+"\n" {
		t.Fatalf("reset-password of the unit's account = %q, %v", out, err)
	}
	if recovered, err := s.GetUserByUsername(ctx, "other-admin"); err != nil || recovered.ID != other.ID || !auth.VerifyPassword(recovered.PasswordHash, "replacement unit password") {
		t.Fatalf("the unit's account after reset = %+v, %v", recovered, err)
	}
	if out, err := admin(f.on, "disable-totp", "--username", "other-admin", "--tenant", "other"); err != nil || out != `user "other-admin" (unit other, administrator)`+"\n" {
		t.Fatalf("disable-totp of the unit's account = %q, %v", out, err)
	}

	// With business units on, the account is named before the command acts,
	// with or without --tenant; with them off, nothing is printed.
	for _, check := range []struct{ config, username, want string }{
		{f.on, "admin", `user "admin" (unit default, administrator)` + "\n"},
		{f.on, "root", `user "root" (platform, platform_admin)` + "\n"},
		{f.off, "admin", ""},
		{f.off, "other-admin", ""},
	} {
		if out, err := admin(check.config, "disable-totp", "--username", check.username); err != nil || out != check.want {
			t.Errorf("disable-totp %s with %s = %q, %v; want %q", check.username, filepath.Base(check.config), out, err, check.want)
		}
	}
	if out, err := admin(f.on, "disable-totp", "--username", "admin", "--tenant", "default"); err != nil || out != `user "admin" (unit default, administrator)`+"\n" {
		t.Fatalf("disable-totp admin --tenant default = %q, %v", out, err)
	}
}
