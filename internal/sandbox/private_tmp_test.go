package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPortablePrivateTemporaryDirectoryLifecycle(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TMPDIR", root)

	command := exec.Command("/bin/true")
	command.Env = []string{
		"KEEP=present",
		"TMPDIR=/old/one",
		"TMP=old-temp",
		"TMPDIR=/old/two",
		"TEMP=old-temp",
	}
	temporary, err := preparePrivateTemporaryDirectory(context.Background(), command, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := temporary.implementation.(*portablePrivateTemporaryDirectory).path
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("portable temp directory was not created: %v", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 || filepath.Dir(path) != root {
		t.Fatalf("portable temp directory = %q mode %04o, want child of test root with mode 0700", path, info.Mode().Perm())
	}
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		values := environmentValues(command.Env, key)
		if len(values) != 1 || values[0] != path {
			t.Errorf("%s environment values = %q, want one value %q", key, values, path)
		}
	}
	if values := environmentValues(command.Env, "KEEP"); len(values) != 1 || values[0] != "present" {
		t.Errorf("unrelated environment was not preserved: %q", command.Env)
	}
	if err := temporary.Started(); err != nil {
		t.Fatalf("portable start hook: %v", err)
	}
	if err := temporary.WaitReady(context.Background()); err != nil {
		t.Fatalf("portable readiness: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := temporary.WaitReady(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("portable readiness after cancellation = %v, want context.Canceled", err)
	}
	if err := temporary.Cleanup(cancelled); err != nil {
		t.Fatalf("portable cleanup: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("portable directory remains after cleanup: %v", err)
	}
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("portable cleanup is not idempotent: %v", err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatalf("portable close: %v", err)
	}
}

func TestPortablePrivateTemporaryDirectoryRejectsInvalidOrCancelledPreparation(t *testing.T) {
	var nilContext context.Context
	if _, err := preparePortablePrivateTemporaryDirectory(nilContext, exec.Command("/bin/true")); err == nil {
		t.Fatal("portable preparation accepted a nil context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	command := exec.Command("/bin/true")
	if _, err := preparePortablePrivateTemporaryDirectory(ctx, command); !errors.Is(err, context.Canceled) {
		t.Fatalf("portable preparation with cancelled context = %v, want context.Canceled", err)
	}
	if len(command.Env) != 0 {
		t.Fatalf("cancelled preparation changed command environment: %q", command.Env)
	}
	if _, err := preparePortablePrivateTemporaryDirectory(context.Background(), nil); err == nil {
		t.Fatal("portable preparation accepted a nil command")
	}
	if _, err := preparePortablePrivateTemporaryDirectory(context.Background(), &exec.Cmd{}); err == nil {
		t.Fatal("portable preparation accepted a command without an executable")
	}
	missingTempRoot := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TMPDIR", missingTempRoot)
	commandWithUnwritableTempRoot := exec.Command("/bin/true")
	if _, err := preparePortablePrivateTemporaryDirectory(context.Background(), commandWithUnwritableTempRoot); err == nil {
		t.Fatal("portable preparation succeeded with a missing temp root")
	}
	if len(commandWithUnwritableTempRoot.Env) != 0 {
		t.Fatalf("failed portable preparation changed command environment: %q", commandWithUnwritableTempRoot.Env)
	}

	var nilImplementation *PrivateTemporaryDirectory
	if err := nilImplementation.Started(); err != nil {
		t.Fatalf("nil temporary start hook: %v", err)
	}
	if err := nilImplementation.WaitReady(context.Background()); err != nil {
		t.Fatalf("nil temporary readiness hook: %v", err)
	}
	if err := nilImplementation.Cleanup(context.Background()); err != nil {
		t.Fatalf("nil temporary cleanup hook: %v", err)
	}
	if err := nilImplementation.Close(); err != nil {
		t.Fatalf("nil temporary close hook: %v", err)
	}
}

func TestPortablePrivateTemporaryCleanupFailureRemainsRetryable(t *testing.T) {
	temporary := &portablePrivateTemporaryDirectory{path: filepath.Join(t.TempDir(), "invalid\x00path")}
	if err := temporary.Cleanup(context.Background()); err == nil {
		t.Fatal("portable cleanup accepted an invalid path")
	}
	if temporary.cleaned {
		t.Fatal("failed portable cleanup marked the directory removed")
	}

	root := t.TempDir()
	path := filepath.Join(root, "owned")
	nested := filepath.Join(path, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "artifact"), []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	temporary.path = path
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("retry portable cleanup: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("portable temporary tree remains after retry: %v", err)
	}
	if !temporary.cleaned {
		t.Fatal("successful portable cleanup did not mark the directory removed")
	}
}

func TestSetEnvironmentValidatesAndReplacesOneVariable(t *testing.T) {
	command := exec.Command("/bin/true")
	command.Env = []string{"A=1", "TMPDIR=first", "B=2", "TMPDIR=second"}
	if err := setEnvironment(command, "TMPDIR", "/private/temp"); err != nil {
		t.Fatal(err)
	}
	if values := environmentValues(command.Env, "TMPDIR"); len(values) != 1 || values[0] != "/private/temp" {
		t.Fatalf("replaced TMPDIR values = %q", values)
	}
	for _, test := range []struct {
		name  string
		cmd   *exec.Cmd
		key   string
		value string
	}{
		{name: "nil command", key: "TMPDIR", value: "/private/temp"},
		{name: "empty key", cmd: command, value: "/private/temp"},
		{name: "equals in key", cmd: command, key: "TMPDIR=other", value: "/private/temp"},
		{name: "nul in key", cmd: command, key: "TMPDIR\x00", value: "/private/temp"},
		{name: "nul in value", cmd: command, key: "TMPDIR", value: "/private\x00temp"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := setEnvironment(test.cmd, test.key, test.value); err == nil {
				t.Fatal("invalid environment assignment succeeded")
			}
		})
	}
}

func TestPrivateTemporaryExecutionEnvironmentPreservesAndValidatesEnvironment(t *testing.T) {
	original := []string{"KEEP=present", "TMPDIR=/old/one", "PATH=/usr/bin", "TMPDIR=/old/two"}
	got, err := privateTemporaryExecutionEnvironment(original, "/tmp/edgewatch-owned")
	if err != nil {
		t.Fatal(err)
	}
	if values := environmentValues(got, "TMPDIR"); len(values) != 1 || values[0] != "/tmp/edgewatch-owned" {
		t.Fatalf("helper TMPDIR = %q", values)
	}
	if values := environmentValues(got, "KEEP"); len(values) != 1 || values[0] != "present" {
		t.Fatalf("helper environment lost unrelated values: %q", got)
	}
	if !reflect.DeepEqual(original, []string{"KEEP=present", "TMPDIR=/old/one", "PATH=/usr/bin", "TMPDIR=/old/two"}) {
		t.Fatalf("helper environment builder mutated its input: %q", original)
	}
	if _, err := privateTemporaryExecutionEnvironment(original, "/tmp/bad\x00path"); err == nil {
		t.Fatal("helper environment accepted an invalid temporary path")
	}
}

func environmentValues(environment []string, key string) []string {
	var values []string
	for _, entry := range environment {
		name, value, ok := strings.Cut(entry, "=")
		if ok && name == key {
			values = append(values, value)
		}
	}
	return values
}
