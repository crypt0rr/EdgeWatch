//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestMain lets the test binary stand in for the EdgeWatch executable as the
// sandbox-exec command.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == ExecCommand {
		if err := Exec(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(126)
	}
	os.Exit(m.Run())
}

func requireLandlock(t *testing.T) int {
	t.Helper()
	abi, err := landlockVersion()
	if err != nil {
		t.Skipf("this kernel offers no Landlock: %v", err)
	}
	return abi
}

func TestParseExecArgs(t *testing.T) {
	t.Parallel()
	profile, files, argv, err := parseExecArgs([]string{"--profile", "scanner", "--files", "2", "--", "/usr/bin/nmap", "--privileged", "-oX", "/dev/fd/3"})
	if err != nil || profile != Scanner || files != 2 || strings.Join(argv, " ") != "/usr/bin/nmap --privileged -oX /dev/fd/3" {
		t.Fatalf("parse = %q %d %q %v", profile, files, argv, err)
	}
	if profile, _, _, err := parseExecArgs([]string{"--profile", "notifier", "--files", "0", "--", "/usr/local/bin/edgewatch", "notify-send"}); err != nil || profile != Notifier {
		t.Fatalf("notifier parse = %q %v", profile, err)
	}
	for name, args := range map[string][]string{
		"empty":           nil,
		"no profile":      {"--files", "0", "--", "/usr/bin/nmap", "-n", "x"},
		"unknown profile": {"--profile", "daemon", "--files", "0", "--", "/usr/bin/nmap"},
		"no program":      {"--profile", "scanner", "--files", "0", "--"},
		"no separator":    {"--profile", "scanner", "--files", "0", "/usr/bin/nmap", "-n"},
		"bad count":       {"--profile", "scanner", "--files", "x", "--", "/usr/bin/nmap"},
		"negative":        {"--profile", "scanner", "--files", "-1", "--", "/usr/bin/nmap"},
		"too many files":  {"--profile", "scanner", "--files", "17", "--", "/usr/bin/nmap"},
	} {
		if _, _, _, err := parseExecArgs(args); err == nil || !strings.Contains(err.Error(), "usage: sandbox-exec") {
			t.Errorf("%s: parse = %v, want usage", name, err)
		}
	}
	if _, _, _, err := parseExecArgs([]string{"--profile", "scanner", "--files", "0", "--", "nmap"}); err == nil || !strings.Contains(err.Error(), "not an absolute path") {
		t.Fatalf("relative program = %v", err)
	}
	if err := execLandlocked([]string{"--files"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("sandbox-exec with bad arguments = %v", err)
	}
}

func TestHandledAccessFollowsTheABI(t *testing.T) {
	t.Parallel()
	abi1 := handledAccess(1)
	if abi1&unix.LANDLOCK_ACCESS_FS_MAKE_REG == 0 || abi1&(unix.LANDLOCK_ACCESS_FS_REFER|unix.LANDLOCK_ACCESS_FS_TRUNCATE) != 0 {
		t.Fatalf("ABI 1 access = %#x", abi1)
	}
	if handledAccess(2)&unix.LANDLOCK_ACCESS_FS_REFER == 0 || handledAccess(2)&unix.LANDLOCK_ACCESS_FS_TRUNCATE != 0 {
		t.Fatalf("ABI 2 access = %#x", handledAccess(2))
	}
	if handledAccess(6)&unix.LANDLOCK_ACCESS_FS_TRUNCATE == 0 || handledAccess(6)&unix.LANDLOCK_ACCESS_FS_IOCTL_DEV != 0 {
		t.Fatalf("ABI 6 access = %#x, want TRUNCATE without IOCTL_DEV", handledAccess(6))
	}
	if handledScopes(5) != 0 || handledScopes(6) != unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET|unix.LANDLOCK_SCOPE_SIGNAL {
		t.Fatalf("scopes = %#x, %#x", handledScopes(5), handledScopes(6))
	}
}

// onRestrictedThread runs fn on an OS thread restricted with Landlock to
// paths and inherited. The thread is never unlocked, so it ends with the
// goroutine and the restriction reaches no other code of the test.
func onRestrictedThread(t *testing.T, paths []landlockPath, inherited []int, fn func() map[string]error) map[string]error {
	t.Helper()
	results := make(chan map[string]error, 1)
	go func() {
		runtime.LockOSThread()
		if err := restrictSelf(paths, inherited); err != nil {
			results <- map[string]error{"restrict": err}
			return
		}
		results <- fn()
	}()
	return <-results
}

func tryOpen(path string, flags int) error {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC, 0o600)
	if err == nil {
		_ = unix.Close(fd)
	}
	return err
}

func checkAccess(t *testing.T, got map[string]error, allowed, denied []string) {
	t.Helper()
	if err := got["restrict"]; err != nil {
		t.Fatal(err)
	}
	for _, name := range allowed {
		if err := got[name]; err != nil {
			t.Errorf("%s: %v, want allowed", name, err)
		}
	}
	for _, name := range denied {
		if err := got[name]; !errors.Is(err, unix.EACCES) {
			t.Errorf("%s: %v, want permission denied", name, err)
		}
	}
}

func TestRestrictSelfLimitsTheThreadToTheScannerFiles(t *testing.T) {
	t.Parallel()
	requireLandlock(t)
	dir := t.TempDir()
	create := func(name string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("data\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	targets, err := os.Open(create("targets"))
	if err != nil {
		t.Fatal(err)
	}
	defer targets.Close()
	output, err := os.OpenFile(create("output.xml"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	private := create("edgewatch.db")
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipeRead.Close()
	defer pipeWrite.Close()
	targetsFD, outputFD := int(targets.Fd()), int(output.Fd())

	// The test's files lie below the temporary directory, which scanner
	// processes may write. Without that rule, the directory stands in for
	// the data directory.
	var withoutTemporary []landlockPath
	for _, path := range profilePaths(Scanner, os.Getenv) {
		if path.path != "/tmp" {
			withoutTemporary = append(withoutTemporary, path)
		}
	}
	got := onRestrictedThread(t, withoutTemporary, []int{targetsFD, outputFD, int(pipeRead.Fd())}, func() map[string]error {
		return map[string]error{
			"read a system directory":     tryOpen("/usr", unix.O_RDONLY|unix.O_DIRECTORY),
			"read the inherited targets":  tryOpen(fmt.Sprintf("/proc/self/fd/%d", targetsFD), unix.O_RDONLY),
			"write the inherited output":  tryOpen(fmt.Sprintf("/proc/self/fd/%d", outputFD), unix.O_WRONLY|unix.O_TRUNC),
			"write the null device":       tryOpen("/dev/null", unix.O_WRONLY|unix.O_TRUNC),
			"write the inherited targets": tryOpen(fmt.Sprintf("/proc/self/fd/%d", targetsFD), unix.O_WRONLY),
			"read the inherited output":   tryOpen(fmt.Sprintf("/proc/self/fd/%d", outputFD), unix.O_RDONLY),
			"read a private file":         tryOpen(private, unix.O_RDONLY),
			"list a private directory":    tryOpen(dir, unix.O_RDONLY|unix.O_DIRECTORY),
			"create a private file":       tryOpen(filepath.Join(dir, "created"), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL),
		}
	})
	checkAccess(t, got,
		[]string{"read a system directory", "read the inherited targets", "write the inherited output", "write the null device"},
		[]string{"write the inherited targets", "read the inherited output", "read a private file", "list a private directory", "create a private file"})

	scratch := filepath.Join("/tmp", fmt.Sprintf("edgewatch-landlock-test-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.Remove(scratch) })
	got = onRestrictedThread(t, profilePaths(Scanner, os.Getenv), nil, func() map[string]error {
		return map[string]error{
			"create a temporary file":         tryOpen(scratch, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL),
			"create a file in /etc":           tryOpen("/etc/edgewatch-landlock-test", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL),
			"write a system file":             tryOpen("/etc/hosts", unix.O_WRONLY),
			"read the hosts file, if present": tryOpen("/etc/hosts", unix.O_RDONLY),
		}
	})
	if errors.Is(got["read the hosts file, if present"], unix.ENOENT) {
		delete(got, "read the hosts file, if present")
		got["write a system file"] = unix.EACCES
	}
	checkAccess(t, got, []string{"create a temporary file", "read the hosts file, if present"}, []string{"create a file in /etc", "write a system file"})
}

func TestNotifierPathsAddTheCertificateAuthoritiesOnly(t *testing.T) {
	t.Parallel()
	has := func(paths []landlockPath, path string) uint64 {
		for _, candidate := range paths {
			if candidate.path == path {
				return candidate.access
			}
		}
		return 0
	}
	environment := map[string]string{"SSL_CERT_FILE": "/run/secrets/ca.pem", "SSL_CERT_DIR": "/etc/corp-ca::/opt/ca"}
	notifier := profilePaths(Notifier, func(key string) string { return environment[key] })
	for _, path := range []string{"/run/secrets/ca.pem", "/etc/corp-ca", "/opt/ca"} {
		if has(notifier, path) != landlockRead {
			t.Errorf("notifier access to %s = %#x, want read", path, has(notifier, path))
		}
	}
	if has(notifier, "/tmp") != 0 || has(notifier, "/dev/tty") != 0 || has(notifier, "") != 0 {
		t.Fatalf("the notifier may open a scanner path: %+v", notifier)
	}
	scanner := profilePaths(Scanner, func(key string) string { return environment[key] })
	if has(scanner, "/tmp") != landlockTemporary || has(scanner, "/run/secrets/ca.pem") != 0 {
		t.Fatalf("scanner paths = %+v", scanner)
	}

	// On a restricted thread, the notifier reads the certificate file its
	// environment names and nothing else beside it, and creates no file,
	// not even in /tmp.
	requireLandlock(t)
	dir := t.TempDir()
	certificate, other := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "edgewatch.db")
	for _, path := range []string{certificate, other} {
		if err := os.WriteFile(path, []byte("data\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scratch := filepath.Join("/tmp", fmt.Sprintf("edgewatch-notifier-test-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.Remove(scratch) })
	paths := profilePaths(Notifier, func(key string) string {
		if key == "SSL_CERT_FILE" {
			return certificate
		}
		return ""
	})
	got := onRestrictedThread(t, paths, nil, func() map[string]error {
		return map[string]error{
			"read the certificate file": tryOpen(certificate, unix.O_RDONLY),
			"read a file beside it":     tryOpen(other, unix.O_RDONLY),
			"create a temporary file":   tryOpen(scratch, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL),
			"write the null device":     tryOpen("/dev/null", unix.O_WRONLY),
		}
	})
	checkAccess(t, got, []string{"read the certificate file", "write the null device"}, []string{"read a file beside it", "create a temporary file"})
}

func TestRulesReportWhatCannotBeAllowed(t *testing.T) {
	t.Parallel()
	abi := requireLandlock(t)
	ruleset, err := createRuleset(abi)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ruleset)
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "both"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipeRead.Close()
	defer pipeWrite.Close()
	handled := handledAccess(abi)
	if err := addDescriptorRule(ruleset, int(file.Fd()), handled); err != nil {
		t.Fatalf("a read-write descriptor: %v", err)
	}
	if err := addRule(ruleset, int(pipeWrite.Fd()), handled); err != nil {
		t.Fatalf("a pipe takes no rule, but adding it failed: %v", err)
	}
	if err := addRule(ruleset, int(file.Fd()), unix.LANDLOCK_ACCESS_FS_MAKE_DIR); err != nil {
		t.Fatalf("a file without file rights takes no rule, but adding it failed: %v", err)
	}
	if err := addPathRule(ruleset, filepath.Join(t.TempDir(), "missing"), landlockRead); err != nil {
		t.Fatalf("a missing path = %v, want it skipped", err)
	}
	if err := addPathRule(ruleset, "/"+strings.Repeat("x", 300), landlockRead); err == nil || !strings.Contains(err.Error(), "for the Landlock ruleset") {
		t.Fatalf("an unopenable path = %v", err)
	}
	if err := addPathRule(-1, "/usr", landlockRead); err == nil || !strings.Contains(err.Error(), "allow /usr") {
		t.Fatalf("a rule for a closed ruleset = %v", err)
	}
	if err := addDescriptorRule(-1, int(file.Fd()), handled); err == nil || !strings.Contains(err.Error(), "allow inherited descriptor") {
		t.Fatalf("a descriptor rule for a closed ruleset = %v", err)
	}
	// A descriptor number that was closed could be reused by a parallel
	// test; -1 is never open.
	const closedFD = -1
	if err := addDescriptorRule(ruleset, closedFD, handled); err == nil || !strings.Contains(err.Error(), "inherited descriptor -1") {
		t.Fatalf("a closed descriptor = %v", err)
	}
	if err := addRule(ruleset, closedFD, landlockRead); err == nil {
		t.Fatal("a rule for a closed descriptor was added")
	}
	missing := onRestrictedThread(t, nil, []int{closedFD}, func() map[string]error { return nil })
	if err := missing["restrict"]; err == nil || !strings.Contains(err.Error(), "inherited descriptor") {
		t.Fatalf("restricting with a closed inherited descriptor = %v", err)
	}
	unopenable := onRestrictedThread(t, []landlockPath{{"/" + strings.Repeat("x", 300), landlockRead}}, nil, func() map[string]error { return nil })
	if err := unopenable["restrict"]; err == nil {
		t.Fatal("restricting with an unopenable path succeeded")
	}
}

func TestSandboxExecRestrictsTheScannerProcess(t *testing.T) {
	t.Parallel()
	abi := requireLandlock(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := (*Policy)(nil).WithLandlock(helper, abi)
	private, err := filepath.Abs("sandbox.go")
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(filepath.Join(t.TempDir(), "output"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	run := func(script string) error {
		t.Helper()
		cmd := exec.Command("/bin/sh", "-c", script)
		path, err := policy.InheritFile(cmd, output, Write)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Env = []string{"PATH=/usr/bin:/bin", "OUTPUT=" + path, "PRIVATE=" + private}
		policy.Confine(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := run(`echo restricted > "$OUTPUT" && cat /dev/null`); err != nil {
		t.Fatalf("an allowed scanner action failed: %v", err)
	}
	if data, err := os.ReadFile(output.Name()); err != nil || string(data) != "restricted\n" {
		t.Fatalf("inherited output = %q, %v", data, err)
	}
	for name, script := range map[string]string{
		"read a private file":      `cat "$PRIVATE"`,
		"list a private directory": `ls "$(dirname "$PRIVATE")"`,
		"execute a dropped file":   `dir=$(mktemp -d) && trap 'rm -rf "$dir"' EXIT && cp /bin/true "$dir/run" && echo copied && "$dir/run"`,
	} {
		err := run(script)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			t.Errorf("%s: %v, want permission denied", name, err)
		}
		// The dropped file is written to /tmp; only executing it is refused.
		if name == "execute a dropped file" && (err == nil || !strings.Contains(err.Error(), "copied")) {
			t.Errorf("%s: %v, want the copy to /tmp to succeed", name, err)
		}
	}
}

func TestRunConfinedStartsTheProgramRestricted(t *testing.T) {
	t.Parallel()
	abi := requireLandlock(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := (*Policy)(nil).WithLandlock(helper, abi)
	if err := runConfined(policy, []string{"/bin/sh", "-c", "exit 0"}, nil); err != nil {
		t.Fatalf("a scanner that starts restricted = %v", err)
	}
	if err := runConfined(policy, []string{filepath.Join(t.TempDir(), "naabu"), "-version"}, nil); err != nil {
		t.Fatalf("a scanner that is not installed = %v, want it skipped", err)
	}
	err = runConfined(policy, []string{"/bin/sh", "-c", "echo first >&2; echo cannot open libpcap >&2; exit 3"}, nil)
	if err == nil || err.Error() != "exit status 3: cannot open libpcap" {
		t.Fatalf("a scanner that fails restricted = %v, want its last diagnostic line", err)
	}
	if err := runConfined(policy, []string{"/bin/sh", "-c", "exit 4"}, nil); err == nil || err.Error() != "exit status 4" {
		t.Fatalf("a silent failure = %v", err)
	}
}

func TestSandboxExecReportsAProgramThatCannotStart(t *testing.T) {
	t.Parallel()
	requireLandlock(t)
	results := make(chan error, 1)
	go func() {
		// sandbox-exec locks and restricts this goroutine's thread, which
		// then ends with the goroutine.
		results <- execLandlocked([]string{"--profile", "scanner", "--files", "0", "--", filepath.Join(os.TempDir(), "edgewatch-missing-scanner")})
	}()
	if err := <-results; !errors.Is(err, unix.ENOENT) || !strings.Contains(err.Error(), "sandbox-exec: execute") {
		t.Fatalf("missing program = %v", err)
	}
}

func TestBoundedBufferKeepsTheFirstBytes(t *testing.T) {
	t.Parallel()
	buffer := &boundedBuffer{limit: 4}
	if n, err := buffer.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("write = %d, %v", n, err)
	}
	if n, err := buffer.Write([]byte("defg")); n != 4 || err != nil || buffer.String() != "abcd" {
		t.Fatalf("write past the limit = %d, %v, %q", n, err, buffer.String())
	}
	if lastLine("") != "" || lastLine("one\ntwo\n") != "two" {
		t.Fatal("lastLine")
	}
}
