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
}

func TestIncidentRemindersDefaultEnabledAndAudited(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	ts := defaultTenant(s)
	if enabled, err := ts.IncidentRemindersEnabled(ctx); err != nil || !enabled {
		t.Fatalf("default reminders=%t, %v", enabled, err)
	}
	if err := ts.SetIncidentRemindersEnabled(ctx, false, AuditEntry{Action: "notifications.incident_reminders_changed", Detail: "disabled"}); err != nil {
		t.Fatal(err)
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
