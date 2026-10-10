package store

// migration67Statements adds the routing and the state of the security and
// deployment-health alerts:
//
//   - tenants.security_destinations_json is a tenant's security alert
//     routing, the IDs of the web-managed destinations of the tenant that
//     its security alerts go to. Its default, an empty selection, keeps
//     them off, so every existing and new tenant opts in itself.
//   - platform_alert_state is the platform's singleton row: the platform's
//     security alert and deployment alert routing, both empty by default,
//     the sandbox states that the last deployment-health alerts reported,
//     when they and the last rollback alert were raised, and the count of
//     alerts that failed for good and were not reported yet.
//   - security_alert_windows holds the open alert window of each owner, a
//     tenant or the platform (a NULL tenant), and alert kind. An alert
//     opens a window; the alerts of the same kind within it are counted
//     instead of sent, and reported together once it ends.
//
// Every statement is safe to run again.
func migration67Statements() []string {
	return []string{
		"ALTER TABLE tenants ADD COLUMN security_destinations_json TEXT NOT NULL DEFAULT '[]'",
		`CREATE TABLE IF NOT EXISTS platform_alert_state (
 id INTEGER PRIMARY KEY CHECK(id=1),
 security_destinations_json TEXT NOT NULL DEFAULT '[]',
 health_destinations_json TEXT NOT NULL DEFAULT '[]',
 scanner_sandbox TEXT NOT NULL DEFAULT '',
 scanner_sandbox_alerted_at TEXT NOT NULL DEFAULT '',
 notification_sandbox TEXT NOT NULL DEFAULT '',
 notification_sandbox_alerted_at TEXT NOT NULL DEFAULT '',
 rollback_alerted_at TEXT NOT NULL DEFAULT '',
 failed_deliveries INTEGER NOT NULL DEFAULT 0,
 failed_platform_deliveries INTEGER NOT NULL DEFAULT 0,
 failed_deliveries_since TEXT NOT NULL DEFAULT '',
 failed_deliveries_alerted_at TEXT NOT NULL DEFAULT ''
);`,
		"INSERT OR IGNORE INTO platform_alert_state(id) VALUES(1)",
		`CREATE TABLE IF NOT EXISTS security_alert_windows (
 id INTEGER PRIMARY KEY,
 tenant_id TEXT REFERENCES tenants(id),
 kind TEXT NOT NULL,
 started_at TEXT NOT NULL,
 suppressed INTEGER NOT NULL DEFAULT 0
);`,
		"CREATE UNIQUE INDEX IF NOT EXISTS security_alert_windows_owner ON security_alert_windows(COALESCE(tenant_id,''),kind)",
		"CREATE INDEX IF NOT EXISTS security_alert_windows_started ON security_alert_windows(started_at)",
	}
}
