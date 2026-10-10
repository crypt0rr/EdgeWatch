package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// failStatement makes every statement of the event (INSERT, UPDATE, or
// DELETE) on the table fail, as a full disk or a broken schema would.
func failStatement(t *testing.T, s *Store, event, table string) {
	t.Helper()
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_` + table + `_` + event + ` BEFORE ` + event + ` ON ` + table + ` BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
}

// execAll runs the statements and fails the test on the first error.
func execAll(t *testing.T, s *Store, statements ...string) {
	t.Helper()
	for _, statement := range statements {
		if _, err := s.DB.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// closeWriter closes the store's writer pool, so a write cannot begin while
// the reader still answers.
func closeWriter(t *testing.T, s *Store) {
	t.Helper()
	if s.ReadDB == nil {
		t.Skip("the store has no separate reader")
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
}

// A deployment alert that cannot be recorded is an error at every step:
// reading the recorded state, beginning the write, creating the platform's
// row, the audit record, and saving the new state. Nothing is half-written,
// because each step shares the alert's transaction.
func TestDeploymentAlertsReportStorageFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC()
	degraded := SandboxHealth{Scanner: model.SandboxStateUnconfined}
	rolledBack := func(s *Store) error {
		_, err := s.Platform().RecordInstalledVersionRollback(ctx, "v1.0.0", now)
		return err
	}
	installed := `UPDATE application_update_state SET installed_version='v2.0.0' WHERE id=1`
	failures := `UPDATE platform_alert_state SET failed_deliveries=2,failed_platform_deliveries=1 WHERE id=1`
	reported := func(s *Store) error {
		_, err := s.Platform().RecordDeliveryFailureHealth(ctx, now)
		return err
	}
	sandbox := func(s *Store) error {
		_, err := s.Platform().RecordSandboxHealth(ctx, degraded, now)
		return err
	}
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, s *Store)
		run   func(s *Store) error
	}{
		{"sandbox state unreadable", func(t *testing.T, s *Store) { execAll(t, s, `DROP TABLE platform_alert_state`) }, sandbox},
		{"sandbox write cannot begin", closeWriter, sandbox},
		{"sandbox row cannot be created", func(t *testing.T, s *Store) { failStatement(t, s, "INSERT", "platform_alert_state") }, sandbox},
		{"sandbox audit fails", func(t *testing.T, s *Store) { failStatement(t, s, "INSERT", "security_audit") }, sandbox},
		{"sandbox state cannot be saved", func(t *testing.T, s *Store) { failStatement(t, s, "UPDATE", "platform_alert_state") }, sandbox},
		{"rollback write cannot begin", closeWriter, rolledBack},
		{"rollback without the update row", func(t *testing.T, s *Store) { execAll(t, s, `DELETE FROM application_update_state`) }, rolledBack},
		{"first version cannot be saved", func(t *testing.T, s *Store) { failStatement(t, s, "UPDATE", "application_update_state") }, rolledBack},
		{"rollback version cannot be saved", func(t *testing.T, s *Store) {
			execAll(t, s, installed)
			failStatement(t, s, "UPDATE", "application_update_state")
		}, rolledBack},
		{"rollback row cannot be created", func(t *testing.T, s *Store) {
			execAll(t, s, installed)
			failStatement(t, s, "INSERT", "platform_alert_state")
		}, rolledBack},
		{"rollback state unreadable", func(t *testing.T, s *Store) {
			execAll(t, s, installed, `ALTER TABLE platform_alert_state DROP COLUMN rollback_alerted_at`)
		}, rolledBack},
		{"rollback audit fails", func(t *testing.T, s *Store) {
			execAll(t, s, installed)
			failStatement(t, s, "INSERT", "security_audit")
		}, rolledBack},
		{"rollback alert time cannot be saved", func(t *testing.T, s *Store) {
			execAll(t, s, installed)
			failStatement(t, s, "UPDATE", "platform_alert_state")
		}, rolledBack},
		{"failure report cannot begin", func(t *testing.T, s *Store) {
			execAll(t, s, failures)
			closeWriter(t, s)
		}, reported},
		{"failure report audit fails", func(t *testing.T, s *Store) {
			execAll(t, s, failures)
			failStatement(t, s, "INSERT", "security_audit")
		}, reported},
		{"failure counts cannot be reset", func(t *testing.T, s *Store) {
			execAll(t, s, failures)
			failStatement(t, s, "UPDATE", "platform_alert_state")
		}, reported},
		{"deployment routing malformed", func(t *testing.T, s *Store) {
			execAll(t, s, failures, `UPDATE platform_alert_state SET health_destinations_json='not json' WHERE id=1`)
		}, reported},
		{"failure state unreadable", func(t *testing.T, s *Store) { execAll(t, s, `DROP TABLE platform_alert_state`) }, reported},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := openTestStore(t)
			test.setup(t, s)
			if err := test.run(s); err == nil {
				t.Fatal("the failure was not reported")
			}
		})
	}
}

// Without the platform's alert row there is nothing to report, and a
// failed delivery that cannot be counted still records its outcome.
func TestFailedDeliveriesWithoutTheAlertRow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	execAll(t, s, `DELETE FROM platform_alert_state`)
	if recorded, err := s.Platform().RecordDeliveryFailureHealth(ctx, time.Now().UTC()); err != nil || recorded {
		t.Fatalf("report without a row = %v, %v", recorded, err)
	}
	execAll(t, s, `DROP TABLE platform_alert_state`)
	terminalizeDelivery(t, s, "deployment-destination", model.Event{Type: "changes-detected", TenantID: DefaultTenantID, Message: "alert", CreatedAt: time.Now().UTC()})
	if count := countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='notification-delivery-terminal'`); count != 1 {
		t.Fatalf("terminal delivery events = %d, want the outcome recorded", count)
	}
}

// The routing reads and writes report a tenant that does not exist, a
// broken schema, and a write that fails, and change nothing.
func TestAlertRoutingReportsStorageFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	missing := TenantScope{id: "00000000-0000-0000-0000-00000000beef"}
	t.Run("unknown tenant", func(t *testing.T) {
		s := openTestStore(t)
		ctx := context.Background()
		if _, err := s.Tenant(missing).SecurityAlertRouting(ctx); err == nil {
			t.Error("an unknown tenant's routing was read")
		}
		if err := s.Tenant(missing).SetSecurityAlertDestinations(ctx, nil, AuditEntry{}); err == nil {
			t.Error("an unknown tenant's routing was written")
		}
	})
	t.Run("empty stored routing", func(t *testing.T) {
		s := openTestStore(t)
		ctx := context.Background()
		execAll(t, s, `UPDATE tenants SET security_destinations_json=''`)
		if routing, err := defaultTenant(s).SecurityAlertRouting(ctx); err != nil || routing == nil || len(routing) != 0 {
			t.Errorf("routing = %v, %v", routing, err)
		}
	})
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, s *Store)
		run   func(s *Store) error
	}{
		{"unit routing unreadable", func(t *testing.T, s *Store) {
			execAll(t, s, `ALTER TABLE tenants DROP COLUMN security_destinations_json`)
		}, func(s *Store) error {
			_, err := defaultTenant(s).SecurityAlertRouting(ctx)
			return err
		}},
		{"unit routing write cannot begin", closeWriter, func(s *Store) error {
			return defaultTenant(s).SetSecurityAlertDestinations(ctx, []string{}, AuditEntry{})
		}},
		{"unit routing cannot be saved", func(t *testing.T, s *Store) { failStatement(t, s, "UPDATE", "tenants") }, func(s *Store) error {
			return defaultTenant(s).SetSecurityAlertDestinations(ctx, []string{}, AuditEntry{})
		}},
		{"unit routing audit fails", func(t *testing.T, s *Store) { failStatement(t, s, "INSERT", "security_audit") }, func(s *Store) error {
			return defaultTenant(s).SetSecurityAlertDestinations(ctx, []string{}, AuditEntry{})
		}},
		{"platform routing malformed", func(t *testing.T, s *Store) {
			execAll(t, s, `UPDATE platform_alert_state SET security_destinations_json='not json'`)
		}, func(s *Store) error {
			_, err := s.Platform().PlatformAlertRouting(ctx)
			return err
		}},
		{"platform deployment routing malformed", func(t *testing.T, s *Store) {
			execAll(t, s, `UPDATE platform_alert_state SET health_destinations_json='not json'`)
		}, func(s *Store) error {
			_, err := s.Platform().PlatformAlertRouting(ctx)
			return err
		}},
		{"platform routing unreadable", func(t *testing.T, s *Store) { execAll(t, s, `DROP TABLE platform_alert_state`) }, func(s *Store) error {
			_, err := s.Platform().PlatformAlertRouting(ctx)
			return err
		}},
		{"platform routing write cannot begin", closeWriter, func(s *Store) error {
			return s.Platform().SetPlatformHealthAlertDestinations(ctx, []string{}, AuditEntry{ActorUserID: platformAdminID})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := openTestStore(t)
			test.setup(t, s)
			if err := test.run(s); err == nil {
				t.Fatal("the failure was not reported")
			}
		})
	}
	// A platform routing write fails at its row, its column, or its audit.
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, s *Store)
	}{
		{"row", func(t *testing.T, s *Store) { failStatement(t, s, "INSERT", "platform_alert_state") }},
		{"column", func(t *testing.T, s *Store) { failStatement(t, s, "UPDATE", "platform_alert_state") }},
		{"audit", func(t *testing.T, s *Store) { failStatement(t, s, "INSERT", "security_audit") }},
	} {
		t.Run("platform routing "+test.name+" fails", func(t *testing.T) {
			s := openTestStore(t)
			ctx := context.Background()
			insertTenantUser(t, s, platformAdminID, nil, RolePlatformAdmin)
			test.setup(t, s)
			if err := s.Platform().SetPlatformSecurityAlertDestinations(ctx, []string{}, AuditEntry{ActorUserID: platformAdminID}); err == nil {
				t.Fatal("the failure was not reported")
			}
		})
	}
}

// Deleting a destination fails as a whole when its owner's alert routing is
// malformed, so the destination and every routing stay as they were.
func TestDeletingADestinationWithMalformedAlertRouting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newSecurityAlertFixture(t)
	ids := tenantFixtureNotifications
	execAll(t, f.store, `UPDATE tenants SET security_destinations_json='not json' WHERE id='`+secondTenantID+`'`)
	if _, err := f.store.Tenant(f.b).DeleteManagedNotificationWithAudit(ctx, ids.b, 1, AuditEntry{Action: "notifications.deleted", ActorUserID: accountAdminB}); err == nil {
		t.Error("a delete with a malformed unit routing succeeded")
	}
	execAll(t, f.store, `UPDATE platform_alert_state SET health_destinations_json='not json'`)
	if err := f.store.Platform().DeletePlatformNotificationWithAudit(ctx, ids.platform, 1, AuditEntry{ActorUserID: platformAdminID}); err == nil {
		t.Error("a delete with a malformed platform routing succeeded")
	}
	if _, err := f.store.Tenant(f.b).GetManagedNotification(ctx, ids.b); err != nil {
		t.Errorf("tenant B's destination after the failed delete: %v", err)
	}
	execAll(t, f.store, `DROP TABLE platform_alert_state`)
	if err := f.store.Platform().DeletePlatformNotificationWithAudit(ctx, ids.platform, 1, AuditEntry{ActorUserID: platformAdminID}); err == nil {
		t.Error("a delete without the platform's alert table succeeded")
	}
}

// The alert of a rate limit names its operation from a fixed vocabulary and
// only a name that can be an account's; any other subject is an
// authentication event without an account.
func TestSecurityAlertDetailVocabulary(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		subject, operation, account string
		platform                    bool
	}{
		{"setup", "first setup", "", false},
		{"password-confirmation", "password confirmation", "", false},
		{"totp-confirmation", "TOTP confirmation", "", true},
		{"login:Alice", "sign-in", "alice", false},
		{"login:", "sign-in", "", false},
		{"something-else", "authentication", "", false},
	} {
		got := securityAlertDetail(AuditEntry{ActorUsername: test.subject, SourceIP: "192.0.2.1"}, model.SecurityAlertRateLimited, test.platform)
		if got.Operation != test.operation || got.Account != test.account || got.Source != "192.0.2.1" {
			t.Errorf("%q: detail = %+v", test.subject, got)
		}
	}
	if got := securityAlertDetail(AuditEntry{ActorUsername: "bad/name"}, model.SecurityAlertRecoveryCodeUsed, false); got.Account != "" {
		t.Errorf("an invalid name became the account: %+v", got)
	}
	if kind := securityAlertKindOf(AuditEntry{Action: "user.created", ActorKind: AuditActorPlatform}); kind != "" {
		t.Errorf("a platform action without a tenant alerts as %q", kind)
	}
	if kind := securityAlertKindOf(AuditEntry{Action: "user.updated", ActorKind: AuditActorPlatform, TenantID: DefaultTenantID}); kind != "" {
		t.Errorf("user.updated alerts as %q", kind)
	}
}

// A security alert whose window cannot be read or written, or whose
// owner's routing cannot be read, is not queued, and the audit record is
// kept.
func TestSecurityAlertFailuresKeepTheRecord(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, s *Store)
	}{
		{"windows missing", func(t *testing.T, s *Store) { execAll(t, s, `DROP TABLE security_alert_windows`) }},
		{"window cannot be opened", func(t *testing.T, s *Store) { failStatement(t, s, "INSERT", "security_alert_windows") }},
		{"routing unreadable", func(t *testing.T, s *Store) {
			execAll(t, s, `ALTER TABLE tenants DROP COLUMN security_destinations_json`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSecurityAlertFixture(t)
			test.setup(t, f.store)
			rateLimited(t, f.store, secondTenantID, "198.51.100.1")
			if alerts := queuedAlerts(t, f.store, model.EventSecurityAlert); len(alerts) != 0 {
				t.Errorf("alerts = %+v", alerts)
			}
			if count := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE action='auth.rate_limited'`); count != 1 {
				t.Errorf("rate-limit records = %d, want the record kept", count)
			}
		})
	}
	t.Run("held window cannot be counted", func(t *testing.T) {
		f := newSecurityAlertFixture(t)
		rateLimited(t, f.store, secondTenantID, "198.51.100.1")
		failStatement(t, f.store, "UPDATE", "security_alert_windows")
		rateLimited(t, f.store, secondTenantID, "198.51.100.2")
		if count := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE action='auth.rate_limited'`); count != 2 {
			t.Errorf("rate-limit records = %d, want both kept", count)
		}
	})
	t.Run("an alert of a window that ended cannot reopen it", func(t *testing.T) {
		f := newSecurityAlertFixture(t)
		execAll(t, f.store, `INSERT INTO security_alert_windows(tenant_id,kind,started_at,suppressed) VALUES('`+secondTenantID+`','rate_limited','2026-01-01T00:00:00.000000000Z',1)`)
		failStatement(t, f.store, "UPDATE", "security_alert_windows")
		rateLimited(t, f.store, secondTenantID, "198.51.100.3")
		if alerts := queuedAlerts(t, f.store, model.EventSecurityAlert); len(alerts) != 0 {
			t.Errorf("alerts = %+v", alerts)
		}
	})
}

// The flush of ended windows reports a failure to read them, to queue a
// summary, and to reopen or remove a window.
func TestFlushSecurityAlertWindowsReportsFailures(t *testing.T) {
	t.Parallel()
	later := time.Now().UTC().Add(2 * SecurityAlertWindow)
	held := `INSERT INTO security_alert_windows(tenant_id,kind,started_at,suppressed) VALUES('` + secondTenantID + `','rate_limited','2026-01-01T00:00:00.000000000Z',2)`
	empty := `INSERT INTO security_alert_windows(tenant_id,kind,started_at,suppressed) VALUES('` + secondTenantID + `','second_factor_locked','2026-01-01T00:00:00.000000000Z',0)`
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, s *Store)
	}{
		{"windows unreadable", func(t *testing.T, s *Store) { execAll(t, s, `DROP TABLE security_alert_windows`) }},
		{"write cannot begin", func(t *testing.T, s *Store) {
			execAll(t, s, held)
			closeWriter(t, s)
		}},
		{"routing unreadable", func(t *testing.T, s *Store) {
			execAll(t, s, held, `ALTER TABLE tenants DROP COLUMN security_destinations_json`)
		}},
		{"summary cannot be queued", func(t *testing.T, s *Store) {
			execAll(t, s, held)
			failStatement(t, s, "INSERT", "outbox")
		}},
		{"window cannot be reopened", func(t *testing.T, s *Store) {
			execAll(t, s, held)
			failStatement(t, s, "UPDATE", "security_alert_windows")
		}},
		{"window cannot be removed", func(t *testing.T, s *Store) {
			execAll(t, s, empty)
			failStatement(t, s, "DELETE", "security_alert_windows")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSecurityAlertFixture(t)
			test.setup(t, f.store)
			if _, err := f.store.System().FlushSecurityAlertWindows(context.Background(), later); err == nil {
				t.Fatal("the failure was not reported")
			}
		})
	}
}

// The alert hook can be removed again, and the platform's health and
// telemetry wrappers answer for the deployment.
func TestAlertWakeAndPlatformDeploymentReads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	woken := 0
	s.SetAlertWake(func() { woken++ })
	s.SetAlertWake(nil)
	if err := s.AuditEntry(ctx, AuditEntry{Action: "auth.rate_limited", ActorUsername: "setup"}); err != nil {
		t.Fatal(err)
	}
	if woken != 0 {
		t.Errorf("a removed hook ran %d times", woken)
	}
	if _, err := s.Platform().HealthStatus(ctx); err == nil {
		t.Error("a deployment without a daemon heartbeat reported healthy")
	}
	telemetry, err := s.Platform().DeploymentTelemetry(ctx)
	if err != nil || telemetry.DatabaseBytes <= 0 {
		t.Errorf("telemetry = %+v, %v", telemetry, err)
	}
}

// A record that sends a security alert reports a write that cannot begin as
// an unavailable audit.
func TestAlertingAuditRecordWithoutTheWriter(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	closeWriter(t, s)
	if err := s.AuditEntry(context.Background(), AuditEntry{Action: "auth.rate_limited", ActorUsername: "setup"}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("audit = %v, want ErrAuditUnavailable", err)
	}
}
