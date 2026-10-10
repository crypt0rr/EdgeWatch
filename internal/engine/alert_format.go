package engine

import (
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// securityAlertHeadline is the first line of a security alert of the kind.
func securityAlertHeadline(kind string) string {
	switch kind {
	case model.SecurityAlertRateLimited:
		return "authentication attempts were rate limited"
	case model.SecurityAlertSecondFactorLocked:
		return "an account's one-time codes were locked after repeated wrong codes"
	case model.SecurityAlertRecoveryCodeUsed:
		return "an account signed in with a recovery code"
	case model.SecurityAlertPlatformInvitation:
		return "a platform administrator invited a unit administrator"
	case model.SecurityAlertPlatformPasswordReset:
		return "a platform administrator issued a password-reset link"
	case model.SecurityAlertPlatformSessionsEnded:
		return "a platform administrator ended an account's sessions"
	default:
		return "security event"
	}
}

// securityAlertPhrase names several events of the coalescing kind, for a
// summary or for the events that an alert reports beyond its own.
func securityAlertPhrase(kind string) string {
	switch kind {
	case model.SecurityAlertRateLimited:
		return "rate-limit episodes"
	case model.SecurityAlertSecondFactorLocked:
		return "second-factor lockouts"
	case model.SecurityAlertRecoveryCodeUsed:
		return "sign-ins with a recovery code"
	case model.SecurityAlertPlatformAccountActions:
		return "platform administrator actions on the unit's accounts"
	default:
		return "security events"
	}
}

// sandboxStateText describes a confinement state.
func sandboxStateText(state string) string {
	switch state {
	case model.SandboxStateSandboxed:
		return "sandboxed with Landlock"
	case model.SandboxStateIdentityOnly:
		return "sandboxed without Landlock"
	case model.SandboxStateLandlockOnly:
		return "UID 0, restricted only by Landlock"
	case model.SandboxStateUnconfined:
		return "unconfined as UID 0"
	default:
		return "not recorded"
	}
}

// sandboxSubjectText names the processes of a sandbox.
func sandboxSubjectText(subject string) string {
	if subject == "notification" {
		return "notification process"
	}
	return "scanner processes"
}

// alertTime formats a time of an alert to the minute, in UTC.
func alertTime(value time.Time) string {
	return value.UTC().Format("2006-01-02 15:04 UTC")
}

// formatSecurityAlert renders a security alert. Names that administrators
// chose, such as a unit's name or a username, and the client address are
// neutralized for providers that interpret markup; the rest is fixed
// wording, a count, or a time.
func formatSecurityAlert(e model.Event) string {
	alert := model.AlertDetail{}
	if e.Alert != nil {
		alert = *e.Alert
	}
	var b strings.Builder
	b.WriteString("🔐 EdgeWatch security alert: ")
	if alert.Kind == model.SecurityAlertSummary {
		b.WriteString(strconv.Itoa(alert.Count))
		b.WriteString(" more ")
		b.WriteString(securityAlertPhrase(alert.Subject))
		if !alert.Since.IsZero() {
			b.WriteString(" since ")
			b.WriteString(alertTime(alert.Since))
		}
	} else {
		b.WriteString(securityAlertHeadline(alert.Kind))
	}
	writeAlertLine(&b, "Business unit", alert.Unit)
	writeAlertLine(&b, "Account", alert.Account)
	writeAlertLine(&b, "Platform administrator", alert.Actor)
	writeAlertLine(&b, "Operation", alert.Operation)
	writeAlertLine(&b, "Source", alert.Source)
	if alert.Kind != model.SecurityAlertSummary && alert.Count > 0 {
		b.WriteString("\nAlso: ")
		b.WriteString(strconv.Itoa(alert.Count))
		b.WriteString(" more ")
		b.WriteString(securityAlertPhrase(model.SecurityAlertWindowKind(alert.Kind)))
		if !alert.Since.IsZero() {
			b.WriteString(" since ")
			b.WriteString(alertTime(alert.Since))
		}
	}
	b.WriteString("\nReview the security audit for details.")
	return b.String()
}

// formatHealthAlert renders a deployment-health alert: fixed wording,
// states, versions, counts, and times only.
func formatHealthAlert(e model.Event) string {
	alert := model.AlertDetail{}
	if e.Alert != nil {
		alert = *e.Alert
	}
	var b strings.Builder
	switch alert.Kind {
	case model.HealthAlertSandboxDegraded:
		b.WriteString("⚠️ EdgeWatch deployment alert: the ")
		b.WriteString(sandboxSubjectText(alert.Subject))
		b.WriteString(" lost confinement")
		writeAlertLine(&b, "Now", sandboxStateText(alert.Current))
		writeAlertLine(&b, "Before", sandboxStateText(alert.Previous))
		b.WriteString("\nRun edgewatch health and see the container hardening guide.")
	case model.HealthAlertSandboxRecovered:
		b.WriteString("🟢 EdgeWatch deployment alert: the ")
		b.WriteString(sandboxSubjectText(alert.Subject))
		b.WriteString(" regained confinement")
		writeAlertLine(&b, "Now", sandboxStateText(alert.Current))
		writeAlertLine(&b, "Before", sandboxStateText(alert.Previous))
	case model.HealthAlertVersionRollback:
		b.WriteString("⚠️ EdgeWatch deployment alert: EdgeWatch was rolled back to an older version")
		writeAlertLine(&b, "Previous version", alert.Previous)
		writeAlertLine(&b, "Current version", alert.Current)
	case model.HealthAlertDeliveryFailures:
		b.WriteString("⚠️ EdgeWatch deployment alert: ")
		b.WriteString(strconv.Itoa(alert.Count))
		if alert.Count == 1 {
			b.WriteString(" alert failed for good")
		} else {
			b.WriteString(" alerts failed for good")
		}
		if !alert.Since.IsZero() {
			b.WriteString(" since ")
			b.WriteString(alertTime(alert.Since))
		}
		b.WriteString("\nPlatform destinations: ")
		b.WriteString(strconv.Itoa(alert.PlatformCount))
		b.WriteString("\nBusiness units' destinations: ")
		b.WriteString(strconv.Itoa(max(alert.Count-alert.PlatformCount, 0)))
		b.WriteString("\nReview delivery health on the Notifications pages.")
	default:
		b.WriteString("⚠️ EdgeWatch deployment alert")
	}
	return b.String()
}

// writeAlertLine adds a labelled line for a value that is not empty.
func writeAlertLine(b *strings.Builder, label, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	b.WriteString("\n")
	b.WriteString(label)
	b.WriteString(": ")
	b.WriteString(sanitizeNotificationText(value))
}
