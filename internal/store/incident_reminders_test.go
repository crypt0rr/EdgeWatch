package store

import (
	"context"
	"errors"
	"testing"
)

func init() {
	tenantStoreLeakCases["IncidentRemindersEnabled"] = tenantLeakCase{run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		if err := f.store.Tenant(f.a).SetIncidentRemindersEnabled(ctx, false, AuditEntry{}); err != nil {
			t.Fatal(err)
		}
		for _, check := range []struct {
			scope TenantScope
			want  bool
		}{{f.a, false}, {f.b, true}} {
			got, err := f.store.Tenant(check.scope).IncidentRemindersEnabled(ctx)
			if err != nil || got != check.want {
				t.Errorf("tenant %s: reminders=%t, %v; want %t", check.scope.ID(), got, err, check.want)
			}
		}
	}}
	tenantStoreLeakCases["SetIncidentRemindersEnabled"] = tenantLeakCase{writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		if err := f.store.Tenant(f.b).SetIncidentRemindersEnabled(ctx, false, AuditEntry{}); err != nil {
			t.Fatal(err)
		}
		if got, err := f.store.Tenant(f.a).IncidentRemindersEnabled(ctx); err != nil || !got {
			t.Fatalf("tenant B changed A's reminders: %t, %v", got, err)
		}
		if got, err := f.store.Tenant(f.b).IncidentRemindersEnabled(ctx); err != nil || got {
			t.Fatalf("tenant B's reminders were not disabled: %t, %v", got, err)
		}
	}}
	tenantStoreLeakCases["IncidentReminderSettings"] = tenantLeakCase{run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		cadence := IncidentReminderCadenceDaily
		if _, err := f.store.Tenant(f.a).SetIncidentReminderSettings(ctx, nil, &cadence, AuditEntry{}); err != nil {
			t.Fatal(err)
		}
		for _, check := range []struct {
			scope   TenantScope
			cadence string
		}{{f.a, IncidentReminderCadenceDaily}, {f.b, IncidentReminderCadenceHourly}} {
			got, err := f.store.Tenant(check.scope).IncidentReminderSettings(ctx)
			if err != nil || got.Cadence != check.cadence {
				t.Errorf("tenant %s: cadence=%q, %v; want %q", check.scope.ID(), got.Cadence, err, check.cadence)
			}
		}
	}}
	tenantStoreLeakCases["SetIncidentReminderSettings"] = tenantLeakCase{writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		cadence := IncidentReminderCadenceHourly
		if _, err := f.store.Tenant(f.b).SetIncidentReminderSettings(ctx, nil, &cadence, AuditEntry{}); err != nil {
			t.Fatal(err)
		}
		if got, err := f.store.Tenant(f.a).IncidentReminderSettings(ctx); err != nil || got.Cadence != IncidentReminderCadenceHourly {
			t.Fatalf("tenant B changed A's cadence: %q, %v", got.Cadence, err)
		}
		if got, err := f.store.Tenant(f.b).IncidentReminderSettings(ctx); err != nil || got.Cadence != cadence {
			t.Fatalf("tenant B cadence=%q, %v; want %q", got.Cadence, err, cadence)
		}
	}}
}

func TestIncidentRemindersDefaultEnabledAndAudited(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	ts := defaultTenant(s)
	if enabled, err := ts.IncidentRemindersEnabled(ctx); err != nil || !enabled {
		t.Fatalf("default reminders=%t, %v", enabled, err)
	}
	if settings, err := ts.IncidentReminderSettings(ctx); err != nil || !settings.Enabled || settings.Cadence != IncidentReminderCadenceHourly {
		t.Fatalf("default reminder settings=%+v, %v", settings, err)
	}
	if err := ts.SetIncidentRemindersEnabled(ctx, false, AuditEntry{Action: "notifications.incident_reminders_changed", Detail: "disabled"}); err != nil {
		t.Fatal(err)
	}
	var cadenceExplicit bool
	if err := s.DB.QueryRowContext(ctx, `SELECT incident_reminder_cadence_explicit FROM tenants WHERE id=?`, DefaultTenantID).Scan(&cadenceExplicit); err != nil || cadenceExplicit {
		t.Fatalf("enablement change marked cadence explicit=%t, %v; want false", cadenceExplicit, err)
	}
	if enabled, err := ts.IncidentRemindersEnabled(ctx); err != nil || enabled {
		t.Fatalf("disabled reminders=%t, %v", enabled, err)
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE tenant_id=? AND action='notifications.incident_reminders_changed'`, DefaultTenantID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("reminder audit count=%d, %v", count, err)
	}
	if err := s.Tenant(TenantScope{}).SetIncidentRemindersEnabled(ctx, true, AuditEntry{}); !errors.Is(err, ErrNoTenantScope) {
		t.Fatalf("empty scope changed reminders: %v", err)
	}
	cadence := IncidentReminderCadenceDaily
	if _, err := ts.SetIncidentReminderSettings(ctx, nil, &cadence, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if settings, err := ts.IncidentReminderSettings(ctx); err != nil || settings.Enabled || settings.Cadence != cadence {
		t.Fatalf("partial update settings=%+v, %v; want disabled, %q", settings, err, cadence)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT incident_reminder_cadence_explicit FROM tenants WHERE id=?`, DefaultTenantID).Scan(&cadenceExplicit); err != nil || !cadenceExplicit {
		t.Fatalf("saved cadence explicit=%t, %v; want true", cadenceExplicit, err)
	}
	invalid := "weekly"
	if _, err := ts.SetIncidentReminderSettings(ctx, nil, &invalid, AuditEntry{}); err == nil {
		t.Fatal("invalid reminder cadence was accepted")
	}
}

func TestIncidentRemindersMissingTenantReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	ts := s.Tenant(TenantScope{id: "00000000-0000-4000-8000-000000000099"})
	if _, err := ts.IncidentRemindersEnabled(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing tenant reminder read error = %v, want ErrNotFound", err)
	}
	if err := ts.SetIncidentRemindersEnabled(ctx, false, AuditEntry{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing tenant reminder write error = %v, want ErrNotFound", err)
	}
	if _, err := ts.IncidentReminderSettings(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing tenant reminder settings error = %v, want ErrNotFound", err)
	}
}

func TestMigration61UsesHourlyForInheritedDefaultAndPreservesSavedCadence(t *testing.T) {
	tests := []struct {
		name              string
		storedCadence     string
		saveCadence       bool
		legacyAudit       bool
		disableReminders  bool
		wantCadence       string
		wantCadenceMarked bool
		wantEnabled       bool
	}{
		{name: "inherited every scan", storedCadence: IncidentReminderCadenceEveryScan, wantCadence: IncidentReminderCadenceHourly, wantEnabled: true},
		{name: "explicit every scan", storedCadence: IncidentReminderCadenceEveryScan, saveCadence: true, wantCadence: IncidentReminderCadenceEveryScan, wantCadenceMarked: true, wantEnabled: true},
		{name: "legacy setting audit is treated conservatively", storedCadence: IncidentReminderCadenceEveryScan, legacyAudit: true, wantCadence: IncidentReminderCadenceEveryScan, wantCadenceMarked: true, wantEnabled: true},
		{name: "saved non-default cadence", storedCadence: IncidentReminderCadenceDaily, wantCadence: IncidentReminderCadenceDaily, wantCadenceMarked: true, wantEnabled: true},
		{name: "disabled reminders stay disabled", storedCadence: IncidentReminderCadenceEveryScan, disableReminders: true, wantCadence: IncidentReminderCadenceHourly},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := openTestStore(t)
			ctx := context.Background()
			if test.saveCadence {
				cadence := test.storedCadence
				if _, err := defaultTenant(s).SetIncidentReminderSettings(ctx, nil, &cadence, AuditEntry{Action: "notifications.incident_reminders_changed"}); err != nil {
					t.Fatal(err)
				}
			} else if _, err := s.DB.ExecContext(ctx, `UPDATE tenants SET incident_reminder_cadence=? WHERE id=?`, test.storedCadence, DefaultTenantID); err != nil {
				t.Fatal(err)
			}
			if test.disableReminders {
				if _, err := s.DB.ExecContext(ctx, `UPDATE tenants SET incident_reminders_enabled=0 WHERE id=?`, DefaultTenantID); err != nil {
					t.Fatal(err)
				}
			}
			if test.legacyAudit {
				// Older audit entries do not distinguish a cadence save from an
				// enable/disable change, so keep a possibly explicit every-scan
				// preference rather than guessing that it was inherited.
				if _, err := s.DB.ExecContext(ctx, `INSERT INTO security_audit(action,detail,created_at) VALUES('notifications.incident_reminders_changed','settings changed',datetime('now'))`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.DB.ExecContext(ctx, `ALTER TABLE tenants DROP COLUMN incident_reminder_cadence_explicit`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.ExecContext(ctx, `PRAGMA user_version=60`); err != nil {
				t.Fatal(err)
			}
			path := s.Path
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			upgraded, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer upgraded.Close()
			settings, err := defaultTenant(upgraded).IncidentReminderSettings(ctx)
			if err != nil || settings.Enabled != test.wantEnabled || settings.Cadence != test.wantCadence {
				t.Fatalf("upgraded reminder settings=%+v, %v; want enabled=%t cadence %q", settings, err, test.wantEnabled, test.wantCadence)
			}
			var cadenceMarked bool
			if err := upgraded.DB.QueryRowContext(ctx, `SELECT incident_reminder_cadence_explicit FROM tenants WHERE id=?`, DefaultTenantID).Scan(&cadenceMarked); err != nil || cadenceMarked != test.wantCadenceMarked {
				t.Fatalf("upgraded cadence explicit=%t, %v; want %t", cadenceMarked, err, test.wantCadenceMarked)
			}
			if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
				t.Fatalf("upgraded schema=%d, want %d", version, schemaVersion)
			}
		})
	}
}

func TestMigration59EnablesReminders(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.DB.ExecContext(ctx, `ALTER TABLE tenants DROP COLUMN incident_reminders_enabled`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `PRAGMA user_version=58`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Open(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	if enabled, err := defaultTenant(upgraded).IncidentRemindersEnabled(ctx); err != nil || !enabled {
		t.Fatalf("upgraded reminders=%t, %v", enabled, err)
	}
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("upgraded schema=%d, want %d", version, schemaVersion)
	}
}
