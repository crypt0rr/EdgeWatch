package model

// The kinds of a security alert, as AlertDetail.Kind names them. A summary
// reports, by its Subject, the events of one kind that the alert window of
// their owner held back.
const (
	SecurityAlertRateLimited            = "rate_limited"
	SecurityAlertSecondFactorLocked     = "second_factor_locked"
	SecurityAlertRecoveryCodeUsed       = "recovery_code_used"
	SecurityAlertPlatformInvitation     = "platform_invitation"
	SecurityAlertPlatformPasswordReset  = "platform_password_reset"
	SecurityAlertPlatformSessionsEnded  = "platform_sessions_revoked"
	SecurityAlertPlatformAccountActions = "platform_account_action"
	SecurityAlertSummary                = "summary"
)

// The kinds of a deployment-health alert.
const (
	HealthAlertSandboxDegraded  = "sandbox_degraded"
	HealthAlertSandboxRecovered = "sandbox_recovered"
	HealthAlertVersionRollback  = "version_rollback"
	HealthAlertDeliveryFailures = "delivery_failures"
)

// The confinement states of a sandbox that a deployment-health alert
// reports, from the best to the worst.
const (
	SandboxStateSandboxed    = "sandboxed"
	SandboxStateIdentityOnly = "identity_only"
	SandboxStateLandlockOnly = "landlock_only"
	SandboxStateUnconfined   = "unconfined"
)

// SecurityAlertWindowKind returns the kind whose alert window coalesces an
// alert of the kind. The platform administrator's actions on accounts share
// one window.
func SecurityAlertWindowKind(kind string) string {
	switch kind {
	case SecurityAlertPlatformInvitation, SecurityAlertPlatformPasswordReset, SecurityAlertPlatformSessionsEnded:
		return SecurityAlertPlatformAccountActions
	default:
		return kind
	}
}
