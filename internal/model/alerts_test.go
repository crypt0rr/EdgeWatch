package model

import "testing"

// The platform administrator's actions on accounts share one alert window;
// every other kind has its own.
func TestSecurityAlertWindowKind(t *testing.T) {
	for kind, want := range map[string]string{
		SecurityAlertPlatformInvitation:    SecurityAlertPlatformAccountActions,
		SecurityAlertPlatformPasswordReset: SecurityAlertPlatformAccountActions,
		SecurityAlertPlatformSessionsEnded: SecurityAlertPlatformAccountActions,
		SecurityAlertRateLimited:           SecurityAlertRateLimited,
		SecurityAlertSecondFactorLocked:    SecurityAlertSecondFactorLocked,
	} {
		if got := SecurityAlertWindowKind(kind); got != want {
			t.Errorf("SecurityAlertWindowKind(%s) = %s, want %s", kind, got, want)
		}
	}
}
