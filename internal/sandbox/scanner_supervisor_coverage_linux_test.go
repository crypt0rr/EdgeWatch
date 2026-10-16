//go:build linux

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestPrepareLinuxScannerInvocationUsesConfiguredHelperFallback(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name            string
		temporaryHelper string
	}{
		{name: "temporary helper", temporaryHelper: executable},
		{name: "current executable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := &supervisorTestLease{identityOK: true, livenessFile: scannerLivenessTestFile(t)}
			policy := scannerPreparationPolicy("")
			policy.temporaryHelper = test.temporaryHelper
			policy.identityAllocator = func(context.Context) (identityLease, error) { return lease, nil }
			command := exec.Command("/bin/true", "--version")
			originalPath := command.Path
			originalArgs := append([]string(nil), command.Args...)

			invocation, err := prepareLinuxScannerInvocation(context.Background(), command, policy, false)
			if err != nil {
				t.Fatalf("prepare using helper fallback: %v", err)
			}
			if invocation == nil || command.Path != executable || len(command.ExtraFiles) != 3 || command.SysProcAttr != nil {
				t.Fatalf("prepared invocation=%v path=%q extra=%d sysproc=%+v", invocation, command.Path, len(command.ExtraFiles), command.SysProcAttr)
			}
			if !reflect.DeepEqual(command.Args, []string{executable, ExecCommand, scannerSupervisorFlag, "--files", "1", "--request-fd", "4", "--result-fd", "5"}) {
				t.Fatalf("supervisor wrapper args = %q", command.Args)
			}
			if err := invocation.StartFailed(true); err != nil {
				t.Fatalf("release identity after helper setup failure: %v", err)
			}
			if lease.releases != 1 || lease.quarantines != 0 {
				t.Fatalf("helper fallback lease accounting = release %d quarantine %d", lease.releases, lease.quarantines)
			}
			if command.Path == originalPath || reflect.DeepEqual(command.Args, originalArgs) {
				t.Fatal("valid helper fallback did not install the supervisor wrapper")
			}
		})
	}
}

func TestPrepareLinuxScannerInvocationRejectsNilContextBeforeLease(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := scannerPreparationPolicy(executable)
	allocatorCalls := 0
	policy.identityAllocator = func(context.Context) (identityLease, error) {
		allocatorCalls++
		return &supervisorTestLease{identityOK: true}, nil
	}
	command := exec.Command("/bin/true")
	originalPath := command.Path
	originalArgs := append([]string(nil), command.Args...)
	var nilContext context.Context
	if invocation, err := prepareLinuxScannerInvocation(nilContext, command, policy, false); invocation != nil || err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil-context preparation = %v, %v; want refusal", invocation, err)
	}
	if allocatorCalls != 0 || command.Path != originalPath || !reflect.DeepEqual(command.Args, originalArgs) {
		t.Fatalf("nil context acquired identity or mutated command: calls=%d path=%q args=%q", allocatorCalls, command.Path, command.Args)
	}
}

func TestScannerSupervisorEntryPointRejectsMalformedArgumentsBeforeSetup(t *testing.T) {
	err := execScannerSupervisor(nil)
	if err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("malformed supervisor entry arguments = %v; want usage refusal before setup", err)
	}
}
