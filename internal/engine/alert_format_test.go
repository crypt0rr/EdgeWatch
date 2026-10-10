package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestFormatSecurityAlerts(t *testing.T) {
	since := time.Date(2026, 10, 10, 12, 30, 45, 0, time.UTC)
	cases := []struct {
		name  string
		alert *model.AlertDetail
		want  string
	}{
		{
			name:  "platform password reset",
			alert: &model.AlertDetail{Kind: model.SecurityAlertPlatformPasswordReset, Unit: "Finance", Account: "alice", Actor: "root-admin"},
			want: "🔐 EdgeWatch security alert: a platform administrator issued a password-reset link\n" +
				"Business unit: Finance\nAccount: alice\nPlatform administrator: root-admin\n" +
				"Review the security audit for details.",
		},
		{
			name:  "rate limit with held episodes",
			alert: &model.AlertDetail{Kind: model.SecurityAlertRateLimited, Operation: "sign-in", Account: "alice", Source: "2001:db8::7", Count: 3, Since: since},
			want: "🔐 EdgeWatch security alert: authentication attempts were rate limited\n" +
				"Account: alice\nOperation: sign-in\nSource: 2001:db8::7\n" +
				"Also: 3 more rate-limit episodes since 2026-10-10 12:30 UTC\n" +
				"Review the security audit for details.",
		},
		{
			name:  "summary",
			alert: &model.AlertDetail{Kind: model.SecurityAlertSummary, Subject: model.SecurityAlertPlatformAccountActions, Unit: "Finance", Count: 2, Since: since},
			want: "🔐 EdgeWatch security alert: 2 more platform administrator actions on the unit's accounts since 2026-10-10 12:30 UTC\n" +
				"Business unit: Finance\nReview the security audit for details.",
		},
		{
			name:  "lockout",
			alert: &model.AlertDetail{Kind: model.SecurityAlertSecondFactorLocked, Account: "alice", Source: "192.0.2.1"},
			want: "🔐 EdgeWatch security alert: an account's one-time codes were locked after repeated wrong codes\n" +
				"Account: alice\nSource: 192.0.2.1\nReview the security audit for details.",
		},
		{
			name:  "unknown kind without detail",
			alert: nil,
			want:  "🔐 EdgeWatch security alert: security event\nReview the security audit for details.",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := FormatEvent(model.Event{Type: model.EventSecurityAlert, Message: "ignored", Alert: test.alert}); got != test.want {
				t.Errorf("FormatEvent() = %q, want %q", got, test.want)
			}
		})
	}
	for _, kind := range []string{model.SecurityAlertRecoveryCodeUsed, model.SecurityAlertPlatformInvitation, model.SecurityAlertPlatformSessionsEnded} {
		if got := FormatEvent(model.Event{Type: model.EventSecurityAlert, Alert: &model.AlertDetail{Kind: kind}}); strings.Contains(got, "security event") {
			t.Errorf("kind %s has no headline: %q", kind, got)
		}
	}
	for _, kind := range []string{model.SecurityAlertSecondFactorLocked, model.SecurityAlertRecoveryCodeUsed, "other"} {
		if got := FormatEvent(model.Event{Type: model.EventSecurityAlert, Alert: &model.AlertDetail{Kind: model.SecurityAlertSummary, Subject: kind, Count: 1}}); !strings.Contains(got, "1 more") {
			t.Errorf("summary of %s = %q", kind, got)
		}
	}
}

// Names that administrators chose are neutralized for providers that read
// markup, and line breaks cannot add lines.
func TestFormatSecurityAlertNeutralizesNames(t *testing.T) {
	got := FormatEvent(model.Event{Type: model.EventSecurityAlert, Alert: &model.AlertDetail{Kind: model.SecurityAlertRecoveryCodeUsed, Unit: "[Ops](https://example.test)\nFake: line", Account: "*bob*"}})
	for _, raw := range []string{"[Ops]", "(https", "\nFake", "*bob*"} {
		if strings.Contains(got, raw) {
			t.Errorf("FormatEvent() = %q keeps %q", got, raw)
		}
	}
}

func TestFormatHealthAlerts(t *testing.T) {
	since := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		alert *model.AlertDetail
		want  string
	}{
		{
			name:  "sandbox degraded",
			alert: &model.AlertDetail{Kind: model.HealthAlertSandboxDegraded, Subject: "scanner", Previous: model.SandboxStateSandboxed, Current: model.SandboxStateUnconfined},
			want: "⚠️ EdgeWatch deployment alert: the scanner processes lost confinement\n" +
				"Now: unconfined as UID 0\nBefore: sandboxed with Landlock\n" +
				"Run edgewatch health and see the container hardening guide.",
		},
		{
			name:  "sandbox recovered",
			alert: &model.AlertDetail{Kind: model.HealthAlertSandboxRecovered, Subject: "notification", Previous: model.SandboxStateLandlockOnly, Current: model.SandboxStateIdentityOnly},
			want: "🟢 EdgeWatch deployment alert: the notification process regained confinement\n" +
				"Now: sandboxed without Landlock\nBefore: UID 0, restricted only by Landlock",
		},
		{
			name:  "first observation",
			alert: &model.AlertDetail{Kind: model.HealthAlertSandboxDegraded, Subject: "scanner", Current: model.SandboxStateLandlockOnly},
			want: "⚠️ EdgeWatch deployment alert: the scanner processes lost confinement\n" +
				"Now: UID 0, restricted only by Landlock\nBefore: not recorded\n" +
				"Run edgewatch health and see the container hardening guide.",
		},
		{
			name:  "rollback",
			alert: &model.AlertDetail{Kind: model.HealthAlertVersionRollback, Previous: "0.36.1", Current: "0.36.0"},
			want:  "⚠️ EdgeWatch deployment alert: EdgeWatch was rolled back to an older version\nPrevious version: 0.36.1\nCurrent version: 0.36.0",
		},
		{
			name:  "failed deliveries",
			alert: &model.AlertDetail{Kind: model.HealthAlertDeliveryFailures, Count: 5, PlatformCount: 2, Since: since},
			want: "⚠️ EdgeWatch deployment alert: 5 alerts failed for good since 2026-10-10 08:00 UTC\n" +
				"Platform destinations: 2\nBusiness units' destinations: 3\nReview delivery health on the Notifications pages.",
		},
		{
			name:  "one failed delivery",
			alert: &model.AlertDetail{Kind: model.HealthAlertDeliveryFailures, Count: 1},
			want: "⚠️ EdgeWatch deployment alert: 1 alert failed for good\n" +
				"Platform destinations: 0\nBusiness units' destinations: 1\nReview delivery health on the Notifications pages.",
		},
		{
			name:  "unknown",
			alert: nil,
			want:  "⚠️ EdgeWatch deployment alert",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := FormatEvent(model.Event{Type: model.EventHealthAlert, Alert: test.alert}); got != test.want {
				t.Errorf("FormatEvent() = %q, want %q", got, test.want)
			}
		})
	}
}
