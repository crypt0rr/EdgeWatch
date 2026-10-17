package main

import (
	"errors"
	"strings"
	"testing"
)

func TestScannerIdentityRecoveryCommandRequiresConfirmationAndBypassesConfig(t *testing.T) {
	previous := recoverScannerIdentityOffline
	t.Cleanup(func() { recoverScannerIdentityOffline = previous })
	called := false
	recoverScannerIdentityOffline = func(confirmed bool) error {
		called = true
		if !confirmed {
			t.Fatal("recovery hook did not receive the explicit confirmation")
		}
		return nil
	}

	if err := run([]string{"scanner-identities", "recover"}); err == nil || !strings.Contains(err.Error(), "--confirm-all-volume-users-stopped") {
		t.Fatalf("recovery without confirmation = %v", err)
	}
	if called {
		t.Fatal("recovery hook ran without explicit operator confirmation")
	}
	if err := run([]string{"scanner-identities", "recover", "--config", "/does/not/exist"}); err == nil || !strings.Contains(err.Error(), "--config does not apply") {
		t.Fatalf("recovery accepted config flag = %v", err)
	}
	if called {
		t.Fatal("recovery hook ran before command flags were validated")
	}
	if err := run([]string{"scanner-identities", "recover", "--confirm-all-volume-users-stopped"}); err != nil {
		t.Fatalf("confirmed recovery command = %v", err)
	}
	if !called {
		t.Fatal("confirmed recovery command did not invoke the recovery hook")
	}
}

func TestScannerIdentityRecoveryCommandPropagatesRecoveryFailure(t *testing.T) {
	previous := recoverScannerIdentityOffline
	t.Cleanup(func() { recoverScannerIdentityOffline = previous })
	want := errors.New("scanner identity recovery refused")
	recoverScannerIdentityOffline = func(bool) error { return want }
	if err := run([]string{"scanner-identities", "recover", "--confirm-all-volume-users-stopped"}); !errors.Is(err, want) {
		t.Fatalf("confirmed recovery error = %v, want %v", err, want)
	}
}
