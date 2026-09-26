package store

import (
	"sort"
	"strings"
)

// Security audit categories. The category says what an audit record is
// about, independently of who performed the action:
//
//   - account: an identity and its credentials, such as sign-in, failed
//     authentication, sessions, passwords, TOTP, and account lifecycle.
//   - platform: the deployment itself, such as backups, restores, and the
//     import of deployment configuration.
//   - data: the monitored data and its configuration, such as jobs, scans,
//     baselines, incidents, notification destinations and routing, scanner
//     profiles, and the public status page.
//
// The platform view shows the account and platform records.
const (
	auditCategoryAccount  = "account"
	auditCategoryPlatform = "platform"
	auditCategoryData     = "data"
)

// auditActionCategories assigns a category to every audit action that
// EdgeWatch writes. Each action is listed on purpose, including the data
// actions that would also get the data category by default, so a new action
// needs an explicit decision; TestAuditActionLiteralsHaveExplicitCategories
// fails for an action string that is missing here.
var auditActionCategories = map[string]string{
	// Sign-in, sign-out, and failed, throttled, or confirmed authentication.
	"admin.login":                        auditCategoryAccount,
	"admin.logout":                       auditCategoryAccount,
	"user.login":                         auditCategoryAccount,
	"user.logout":                        auditCategoryAccount,
	"auth.activation_failed":             auditCategoryAccount,
	"auth.login_failed":                  auditCategoryAccount,
	"auth.password_confirmation_failed":  auditCategoryAccount,
	"auth.rate_limited":                  auditCategoryAccount,
	"auth.recovery_code_used":            auditCategoryAccount,
	"auth.setup_failed":                  auditCategoryAccount,
	"auth.totp_confirmation_failed":      auditCategoryAccount,
	"auth.totp_failed":                   auditCategoryAccount,
	"auth.legacy_recovery_codes_retired": auditCategoryAccount,

	// Account lifecycle, credentials, and sessions. The setup token is the
	// one-time credential for creating the first administrator account.
	"admin.setup":                       auditCategoryAccount,
	"admin.setup_token_reissued":        auditCategoryAccount,
	"admin.display_name_changed":        auditCategoryAccount,
	"admin.password_changed":            auditCategoryAccount,
	"admin.password_reset":              auditCategoryAccount,
	"admin.sessions_revoked":            auditCategoryAccount,
	"admin.totp_disabled":               auditCategoryAccount,
	"admin.totp_enabled":                auditCategoryAccount,
	"admin.totp_recovery_codes_rotated": auditCategoryAccount,
	"user.activated":                    auditCategoryAccount,
	"user.activation_issued":            auditCategoryAccount,
	"user.activation_revoked":           auditCategoryAccount,
	"user.created":                      auditCategoryAccount,
	"user.display_name_changed":         auditCategoryAccount,
	"user.password_changed":             auditCategoryAccount,
	"user.password_reset":               auditCategoryAccount,
	"user.password_reset_issued":        auditCategoryAccount,
	"user.sessions_revoked":             auditCategoryAccount,
	"user.totp_disabled":                auditCategoryAccount,
	"user.totp_enabled":                 auditCategoryAccount,
	"user.totp_recovery_codes_rotated":  auditCategoryAccount,
	"user.updated":                      auditCategoryAccount,

	// Deployment operations: host backups and restores, and the one-time
	// import of the notification URLs from config.yaml.
	"database.backup":                     auditCategoryPlatform,
	"database.restore":                    auditCategoryPlatform,
	"database.restore.pending_deliveries": auditCategoryPlatform,
	"notifications.config_imported":       auditCategoryPlatform,

	// Monitored data and its configuration.
	"baseline.approved":                     auditCategoryData,
	"baseline.reset":                        auditCategoryData,
	"incident.accepted":                     auditCategoryData,
	"incident.suppressed":                   auditCategoryData,
	"job.archived":                          auditCategoryData,
	"job.created":                           auditCategoryData,
	"job.deleted":                           auditCategoryData,
	"job.notification_destination_removed":  auditCategoryData,
	"job.notification_destination_replaced": auditCategoryData,
	"job.paused":                            auditCategoryData,
	"job.rebaseline_requested":              auditCategoryData,
	"job.restored":                          auditCategoryData,
	"job.resumed":                           auditCategoryData,
	"job.updated":                           auditCategoryData,
	"notifications.created":                 auditCategoryData,
	"notifications.deleted":                 auditCategoryData,
	"notifications.pending_discarded":       auditCategoryData,
	"notifications.test":                    auditCategoryData,
	"notifications.test_failed":             auditCategoryData,
	"notifications.update_routing":          auditCategoryData,
	"notifications.updated":                 auditCategoryData,
	"public_dashboard.updated":              auditCategoryData,
	"scan.cancel_requested":                 auditCategoryData,
	"scan.cycle_discarded":                  auditCategoryData,
	"scan.run_requested":                    auditCategoryData,
	"scanner_profile.archived":              auditCategoryData,
	"scanner_profile.created":               auditCategoryData,
	"scanner_profile.restored":              auditCategoryData,
	"scanner_profile.updated":               auditCategoryData,
}

// auditCategory returns the category of an audit action. An action that is
// not listed in auditActionCategories is data: records about the monitored
// data are the most common, and the data category keeps an unlisted record
// out of the platform view rather than showing it there.
func auditCategory(action string) string {
	if category, ok := auditActionCategories[action]; ok {
		return category
	}
	return auditCategoryData
}

// auditCategoryBackfillStatement categorizes the audit records that have no
// category yet, the records written before schema 51, with the same mapping
// as auditCategory. The action names are constants of this package.
func auditCategoryBackfillStatement() string {
	byCategory := map[string][]string{}
	for action, category := range auditActionCategories {
		if category != auditCategoryData {
			byCategory[category] = append(byCategory[category], "'"+strings.ReplaceAll(action, "'", "''")+"'")
		}
	}
	var statement strings.Builder
	statement.WriteString("UPDATE security_audit SET category=CASE")
	for _, category := range []string{auditCategoryAccount, auditCategoryPlatform} {
		actions := byCategory[category]
		sort.Strings(actions)
		statement.WriteString(" WHEN action IN (" + strings.Join(actions, ",") + ") THEN '" + category + "'")
	}
	statement.WriteString(" ELSE '" + auditCategoryData + "' END WHERE category=''")
	return statement.String()
}
