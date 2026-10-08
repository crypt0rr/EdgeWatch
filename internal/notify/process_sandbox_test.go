package notify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/sandbox"
)

func TestNotificationProcessStartsInTheSandbox(t *testing.T) {
	originalExecutable := notificationExecutable
	originalCommand := notificationCommandContext
	t.Cleanup(func() {
		notificationExecutable = originalExecutable
		notificationCommandContext = originalCommand
		SetSandbox(nil)
	})
	child := filepath.Join(t.TempDir(), "edgewatch")
	if err := os.WriteFile(child, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	notificationExecutable = func() (string, error) { return child, nil }
	var started *exec.Cmd
	notificationCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		started = exec.CommandContext(ctx, name, args...)
		return started
	}
	SetSandbox(sandbox.NewEnforcedFor(sandbox.Notifier).WithLandlock(child, 6))
	// An unprivileged test process cannot change identity, so the start may
	// be refused; the command it built is what matters.
	_ = runNotificationProcess(context.Background(), "generic://127.0.0.1/hook", "test")
	if started == nil {
		t.Fatal("no notification process was built")
	}
	want := []string{child, sandbox.ExecCommand, "--profile", "notifier", "--files", "0", "--", child, "notify-send"}
	if !reflect.DeepEqual(started.Args, want) {
		t.Fatalf("notification process = %q, want %q", started.Args, want)
	}
	credential := started.SysProcAttr.Credential
	if credential == nil || credential.Uid != sandbox.NotifierUID || credential.Gid != sandbox.NotifierGID || len(started.SysProcAttr.AmbientCaps) != 0 {
		t.Fatalf("notification process attributes = %+v", started.SysProcAttr)
	}

	// Without a policy, the process starts as before.
	SetSandbox(nil)
	_ = runNotificationProcess(context.Background(), "generic://127.0.0.1/hook", "test")
	if !reflect.DeepEqual(started.Args, []string{child, "notify-send"}) || started.SysProcAttr != nil {
		t.Fatalf("unconfined notification process = %q %+v", started.Args, started.SysProcAttr)
	}
}

func TestChildEnvironmentIsTheNotificationProcessEnvironment(t *testing.T) {
	t.Setenv("SSL_CERT_DIR", "/etc/corp-ca")
	t.Setenv("EDGEWATCH_TEST_SECRET", "must-not-reach-provider")
	environment := ChildEnvironment()
	if !reflect.DeepEqual(environment, notificationChildEnvironment()) || !strings.Contains(strings.Join(environment, "\n"), "SSL_CERT_DIR=/etc/corp-ca") || strings.Contains(strings.Join(environment, "\n"), "EDGEWATCH_TEST_SECRET") {
		t.Fatalf("child environment = %q", environment)
	}
}

func TestCheckChildTrustReadsTheCertificateAuthorities(t *testing.T) {
	dir := t.TempDir()
	readable := filepath.Join(dir, "readable.pem")
	if err := os.WriteFile(readable, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	certificates := filepath.Join(dir, "certs")
	if err := os.MkdirAll(filepath.Join(certificates, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certificates, "ca.pem"), []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", readable)
	t.Setenv("SSL_CERT_DIR", filepath.Join(dir, "missing")+":"+certificates+":")
	if err := CheckChildTrust(); err != nil {
		t.Fatalf("readable certificate authorities = %v", err)
	}
	t.Setenv("SSL_CERT_FILE", filepath.Join(dir, "missing.pem"))
	if err := CheckChildTrust(); err != nil {
		t.Fatalf("a missing SSL_CERT_FILE = %v, want it skipped as Go does", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("UID 0 reads any file")
	}
	unreadable := filepath.Join(dir, "unreadable.pem")
	if err := os.WriteFile(unreadable, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", unreadable)
	if err := CheckChildTrust(); err == nil || !strings.Contains(err.Error(), "read SSL_CERT_FILE") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("an unreadable SSL_CERT_FILE = %v", err)
	}
	t.Setenv("SSL_CERT_FILE", "")
	if err := os.Chmod(filepath.Join(certificates, "ca.pem"), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := CheckChildTrust(); err == nil || !strings.Contains(err.Error(), "read SSL_CERT_DIR") {
		t.Fatalf("an unreadable file in SSL_CERT_DIR = %v", err)
	}
	if err := os.Chmod(certificates, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(certificates, 0o700) })
	if err := CheckChildTrust(); err == nil || !strings.Contains(err.Error(), "read SSL_CERT_DIR") {
		t.Fatalf("an unreadable SSL_CERT_DIR = %v", err)
	}
}
