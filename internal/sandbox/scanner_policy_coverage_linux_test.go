//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseExecArgsAcceptsDistinctLaunchContracts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		want execRequest
	}{
		{
			name: "private scanner leaf",
			args: []string{"--profile", "scanner", "--files", "1", "--liveness-fd", "3", "--private-tmp", "--private-root-fd", "4", "--private-leaf-fd", "5", "--control-fd", "6", "--landlock", "--seccomp", "--", "/usr/local/bin/naabu", "-version"},
			want: execRequest{profile: Scanner, files: 1, livenessFD: 3, privateTemp: true, privateRootFD: 4, privateLeafFD: 5, privateNamespaceFD: -1, controlFD: 6, landlock: true, seccomp: true, argv: []string{"/usr/local/bin/naabu", "-version"}},
		},
		{
			name: "private namespace creator",
			args: []string{"--profile", "scanner", "--files", "1", "--liveness-fd", "3", "--private-tmp", "--private-create", "--private-root-fd", "4", "--private-namespace-fd", "5", "--control-fd", "6", "--landlock", "--seccomp", "--", "/usr/local/bin/edgewatch", "create-private-tmp"},
			want: execRequest{profile: Scanner, files: 1, livenessFD: 3, seccomp: true, privateTemp: true, privateCreate: true, privateRootFD: 4, privateLeafFD: -1, privateNamespaceFD: 5, controlFD: 6, landlock: true, argv: []string{"/usr/local/bin/edgewatch", "create-private-tmp"}},
		},
		{
			name: "identity-only scanner",
			args: []string{"--profile", "scanner", "--files", "1", "--liveness-fd", "3", "--identity-only", "--seccomp", "--", "/usr/bin/nmap", "-n"},
			want: execRequest{profile: Scanner, files: 1, livenessFD: 3, privateRootFD: -1, privateLeafFD: -1, privateNamespaceFD: -1, controlFD: -1, seccomp: true, identityOnly: true, argv: []string{"/usr/bin/nmap", "-n"}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseExecArgs(test.args)
			if err != nil {
				t.Fatalf("parseExecArgs() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("parseExecArgs() = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestParseExecArgsRejectsMalformedPrivateAndIdentityRequests(t *testing.T) {
	t.Parallel()
	validPrivate := []string{"--profile", "scanner", "--files", "1", "--liveness-fd", "3", "--private-tmp", "--private-root-fd", "4", "--private-leaf-fd", "5", "--control-fd", "6", "--", "/usr/local/bin/naabu"}
	validCreate := []string{"--profile", "scanner", "--files", "1", "--liveness-fd", "3", "--private-tmp", "--private-create", "--private-root-fd", "4", "--private-namespace-fd", "5", "--control-fd", "6", "--", "/usr/local/bin/edgewatch"}
	tests := []struct {
		name string
		args []string
	}{
		{name: "duplicate private temp", args: []string{"--profile", "scanner", "--files", "0", "--private-tmp", "--private-tmp", "--private-root-fd", "3", "--private-leaf-fd", "4", "--control-fd", "5", "--", "/usr/bin/nmap"}},
		{name: "duplicate private create", args: append(append(append([]string(nil), validCreate[:6]...), "--private-create"), validCreate[6:]...)},
		{name: "private root descriptor missing value", args: []string{"--profile", "scanner", "--files", "0", "--private-tmp", "--private-root-fd"}},
		{name: "private root descriptor below inherited range", args: []string{"--profile", "scanner", "--files", "0", "--private-tmp", "--private-root-fd", "2"}},
		{name: "private leaf descriptor is not numeric", args: []string{"--profile", "scanner", "--files", "0", "--private-tmp", "--private-leaf-fd", "x"}},
		{name: "private namespace descriptor missing value", args: []string{"--profile", "scanner", "--files", "0", "--private-tmp", "--private-create", "--private-namespace-fd"}},
		{name: "control descriptor is not numeric", args: []string{"--profile", "scanner", "--files", "0", "--private-tmp", "--control-fd", "three"}},
		{name: "duplicate control descriptor", args: []string{"--profile", "scanner", "--files", "0", "--private-tmp", "--private-root-fd", "3", "--private-leaf-fd", "4", "--control-fd", "5", "--control-fd", "6", "--", "/usr/bin/nmap"}},
		{name: "duplicate landlock flag", args: append(append([]string(nil), validPrivate[:len(validPrivate)-2]...), "--landlock", "--landlock", "--", "/usr/local/bin/naabu")},
		{name: "duplicate seccomp flag", args: append(append([]string(nil), validPrivate[:len(validPrivate)-2]...), "--seccomp", "--seccomp", "--", "/usr/local/bin/naabu")},
		{name: "duplicate identity-only flag", args: []string{"--profile", "scanner", "--files", "0", "--identity-only", "--identity-only", "--seccomp", "--", "/usr/bin/nmap"}},
		{name: "private create requires namespace instead of leaf", args: []string{"--profile", "scanner", "--files", "0", "--private-tmp", "--private-create", "--private-root-fd", "3", "--private-leaf-fd", "4", "--control-fd", "5", "--", "/usr/local/bin/edgewatch"}},
		{name: "private create descriptor order", args: []string{"--profile", "scanner", "--files", "1", "--private-tmp", "--private-create", "--private-root-fd", "3", "--private-namespace-fd", "5", "--control-fd", "6", "--", "/usr/local/bin/edgewatch"}},
		{name: "private leaf descriptor order", args: []string{"--profile", "scanner", "--files", "1", "--private-tmp", "--private-root-fd", "4", "--private-leaf-fd", "6", "--control-fd", "7", "--", "/usr/local/bin/naabu"}},
		{name: "private leaf request forbids namespace descriptor", args: []string{"--profile", "scanner", "--files", "0", "--private-tmp", "--private-root-fd", "3", "--private-leaf-fd", "4", "--private-namespace-fd", "5", "--control-fd", "6", "--", "/usr/local/bin/naabu"}},
		{name: "private create flag requires private temp mode", args: []string{"--profile", "scanner", "--files", "0", "--private-create", "--", "/usr/local/bin/edgewatch"}},
		{name: "private descriptors require private temp mode", args: []string{"--profile", "scanner", "--files", "0", "--private-root-fd", "3", "--", "/usr/bin/nmap"}},
		{name: "landlock requires private temp mode", args: []string{"--profile", "scanner", "--files", "0", "--landlock", "--", "/usr/bin/nmap"}},
		{name: "identity-only requires seccomp", args: []string{"--profile", "scanner", "--files", "0", "--identity-only", "--", "/usr/bin/nmap"}},
		{name: "identity-only is scanner-only", args: []string{"--profile", "notifier", "--files", "0", "--identity-only", "--seccomp", "--", "/usr/bin/edgewatch"}},
		{name: "identity-only excludes landlock", args: []string{"--profile", "scanner", "--files", "0", "--identity-only", "--seccomp", "--private-tmp", "--private-root-fd", "3", "--private-leaf-fd", "4", "--control-fd", "5", "--landlock", "--", "/usr/bin/nmap"}},
		{name: "identity-only excludes resource-only", args: []string{"--profile", "scanner", "--files", "0", "--identity-only", "--seccomp", "--resource-only", "--file-size-limit", "1024", "--", "/usr/bin/nmap"}},
		{name: "identity-only excludes file size limit", args: []string{"--profile", "scanner", "--files", "0", "--identity-only", "--seccomp", "--file-size-limit", "1024", "--", "/usr/bin/nmap"}},
		{name: "resource-only excludes identity-only", args: []string{"--profile", "scanner", "--files", "0", "--resource-only", "--identity-only", "--seccomp", "--file-size-limit", "1024", "--", "/usr/bin/nmap"}},
	}
	_ = validCreate
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseExecArgs(test.args); err == nil || !strings.Contains(err.Error(), "usage: sandbox-exec") {
				t.Fatalf("parseExecArgs() error = %v, want usage rejection", err)
			}
		})
	}
}

func TestRunConfinedPreservesExplicitOffExecutionAndEnvironment(t *testing.T) {
	t.Parallel()
	outputPath := filepath.Join(t.TempDir(), "result")
	policy := &Policy{profile: Scanner, status: Status{Mode: ModeOff}}
	command := []string{"/bin/sh", "-c", `printf '%s' "$EDGEWATCH_POLICY_VALUE" > "$EDGEWATCH_POLICY_OUTPUT"`}
	environment := []string{"EDGEWATCH_POLICY_VALUE=off-mode-ran", "EDGEWATCH_POLICY_OUTPUT=" + outputPath}
	if err := runConfined(policy, command, environment); err != nil {
		t.Fatalf("runConfined() with explicit Off = %v", err)
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil || string(contents) != "off-mode-ran" {
		t.Fatalf("explicit Off output = %q, %v", contents, err)
	}
}

func TestRunConfinedIdentityOnlyHelperInstallsSeccompWithoutLandlock(t *testing.T) {
	t.Parallel()
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "status")
	outsidePath := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outsidePath, []byte("readable without Landlock"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `test -r "$EDGEWATCH_POLICY_OUTSIDE" || exit 20
while IFS=: read -r key value; do
  case "$key" in
    NoNewPrivs|Seccomp) printf '%s:%s\n' "$key" "$value" >> "$EDGEWATCH_POLICY_OUTPUT" ;;
  esac
done < /proc/self/status`
	livenessFile := scannerLivenessTestFile(t)
	policy := &Policy{profile: Scanner, status: Status{Mode: ModeAuto}, identityOnlyHelper: helper, identityOnlyLivenessFile: func() (*os.File, error) { return livenessFile, nil }}
	environment := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "EDGEWATCH_POLICY_OUTPUT=" + outputPath, "EDGEWATCH_POLICY_OUTSIDE=" + outsidePath}
	if err := runConfined(policy, []string{"/bin/sh", "-c", script}, environment); err != nil {
		t.Fatalf("runConfined() identity-only helper = %v", err)
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "NoNewPrivs:\t1") || !strings.Contains(string(contents), "Seccomp:\t2") {
		t.Fatalf("identity-only helper status = %q, want NNP and seccomp", contents)
	}
}

func TestRunConfinedBoundsReturnedDiagnostic(t *testing.T) {
	t.Parallel()
	command := []string{"/bin/sh", "-c", `printf '%05000d' 0 >&2; printf 'TAIL_SENTINEL\n' >&2; exit 7`}
	err := runConfined(nil, command, nil)
	if err == nil || !strings.Contains(err.Error(), "diagnostic exceeded 4096 bytes") {
		t.Fatalf("runConfined() error = %v, want a bounded-output failure", err)
	}
	if strings.Contains(err.Error(), "TAIL_SENTINEL") || len(err.Error()) > maxProbeDiagnostic+128 {
		t.Fatalf("runConfined() returned unbounded diagnostic: length=%d contains_tail=%t", len(err.Error()), strings.Contains(err.Error(), "TAIL_SENTINEL"))
	}
}
