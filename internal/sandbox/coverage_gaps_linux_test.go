//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestInspectScannerWithReportsUnavailableAndDisabledBranches(t *testing.T) {
	tests := []struct {
		name      string
		options   Options
		change    func(*environment)
		inspect   bool
		poolErr   bool
		wantState string
		wantPart  string
	}{
		{name: "invalid mode", options: Options{Mode: "invalid"}, wantState: StateUnavailable, wantPart: "must be auto"},
		{name: "nonroot daemon", change: func(env *environment) { env.euid = 1234 }, wantState: StateUnavailable, wantPart: "runs as UID 1234"},
		{name: "unmapped identity range", change: func(env *environment) { env.identityRangeErr = errors.New("unmapped") }, wantState: StateUnavailable, wantPart: "UID/GID range"},
		{name: "capability read failure", change: func(env *environment) { env.capErr = errors.New("unavailable") }, wantState: StateUnavailable, wantPart: "capabilities could not be verified"},
		{name: "missing pool inspector", inspect: true, wantState: StateUnavailable, wantPart: "pool could not be inspected"},
		{name: "pool inspection error", poolErr: true, wantState: StateUnavailable, wantPart: "durable lease state"},
		{name: "seccomp inspection failure", change: func(env *environment) { env.seccompErr = errors.New("seccomp unavailable") }, wantState: StateUnavailable, wantPart: "seccomp"},
		{name: "invalid required landlock mode", options: Options{Mode: ModeRequired, Landlock: "invalid"}, wantState: StateUnavailable, wantPart: "scanner.landlock"},
		{name: "optional landlock failure", change: func(env *environment) { env.landlockErr = errors.New("unsupported") }, wantState: StateEnforced, wantPart: "unsupported"},
		{name: "required landlock failure", options: Options{Mode: ModeRequired, Landlock: ModeRequired}, change: func(env *environment) { env.landlockErr = errors.New("unsupported") }, wantState: StateUnavailable, wantPart: "unsupported"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env, _ := containerEnvironment()
			if test.change != nil {
				test.change(&env)
			}
			var inspect func(context.Context) (*ScannerIdentityPoolStatus, error)
			if !test.inspect {
				inspect = func(context.Context) (*ScannerIdentityPoolStatus, error) {
					if test.poolErr {
						return nil, errors.New("scanner identity allocator journal unavailable")
					}
					return scannerIdentityPoolStatus(StateEnforced, ""), nil
				}
			}
			policy := inspectScannerWith(test.options, env, inspect)
			status := policy.Status()
			if status.State != test.wantState {
				t.Fatalf("scanner state = %+v; want %q", status, test.wantState)
			}
			if !contains(status.Reason, test.wantPart) && !contains(status.Landlock.Reason, test.wantPart) {
				t.Fatalf("scanner status does not explain %q: %+v", test.wantPart, status)
			}
		})
	}

	policy := inspectScanner(Options{Mode: ModeOff})
	status := policy.Status()
	if status.State != StateDisabled || status.IdentityPool == nil || status.IdentityPool.State != StateDisabled || status.Landlock.State != StateDisabled || status.Seccomp.State != StateDisabled {
		t.Fatalf("off-mode inspection = %+v; want every scanner boundary disabled", status)
	}

	env, _ := containerEnvironment()
	env.executableErr = errors.New("executable metadata unavailable")
	policy = inspectScannerWith(Options{Mode: ModeAuto}, env, func(context.Context) (*ScannerIdentityPoolStatus, error) {
		return scannerIdentityPoolStatus(StateEnforced, ""), nil
	})
	if status = policy.Status(); status.State != StateUnavailable || status.Seccomp.State != StateUnavailable {
		t.Fatalf("executable failure status = %+v; want unavailable seccomp", status)
	}

	env, _ = containerEnvironment()
	policy = inspectScannerWith(Options{Mode: ModeAuto, Landlock: ModeOff}, env, func(context.Context) (*ScannerIdentityPoolStatus, error) {
		return scannerIdentityPoolStatus(StateEnforced, ""), nil
	})
	if status = policy.Status(); status.State != StateEnforced || status.Landlock.State != StateDisabled {
		t.Fatalf("Landlock-off status = %+v; want enforced scanner with disabled Landlock", status)
	}
}

func TestScannerIdentityInspectionRejectsInvalidInputsAndDurableState(t *testing.T) {
	setup := func(t *testing.T, allocator *scannerIdentityAllocator) {
		t.Helper()
		lease, err := allocator.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.release(); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name        string
		waitForLock bool
		prepare     func(*testing.T, *scannerIdentityAllocator)
		mutate      func(*scannerIdentityAllocator)
	}{
		{name: "nil context"},
		{name: "incomplete allocator", mutate: func(a *scannerIdentityAllocator) { a.bootID = nil }},
		{name: "boot ID read failure", mutate: func(a *scannerIdentityAllocator) {
			a.bootID = func() (string, error) { return "", errors.New("unavailable") }
		}},
		{name: "invalid boot ID", mutate: func(a *scannerIdentityAllocator) { a.bootID = func() (string, error) { return "invalid", nil } }},
		{name: "PID namespace read failure", mutate: func(a *scannerIdentityAllocator) {
			a.pidNamespace = func() (uint64, error) { return 0, errors.New("unavailable") }
		}},
		{name: "zero PID namespace", mutate: func(a *scannerIdentityAllocator) { a.pidNamespace = func() (uint64, error) { return 0, nil } }},
		{name: "UID map validation failure", mutate: func(a *scannerIdentityAllocator) {
			a.validateMap = func(uint32, uint32) error { return errors.New("invalid map") }
		}},
		{name: "identity census failure", mutate: func(a *scannerIdentityAllocator) {
			a.inUse = func(uint32, uint32) (map[uint32]struct{}, error) { return nil, errors.New("unavailable") }
		}},
		{name: "private directory missing", mutate: func(a *scannerIdentityAllocator) { a.markerDir = filepath.Join(a.markerDir, "missing") }},
		{name: "allocator lock missing", prepare: func(t *testing.T, a *scannerIdentityAllocator) {
			setup(t, a)
			if err := os.Remove(filepath.Join(a.directory, scannerIdentityLock)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "inspection canceled while waiting for lock", waitForLock: true, prepare: func(t *testing.T, a *scannerIdentityAllocator) {
			setup(t, a)
			fd, err := unix.Open(filepath.Join(a.directory, scannerIdentityLock), unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
				_ = unix.Close(fd)
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) })
		}},
		{name: "boot marker missing", prepare: func(t *testing.T, a *scannerIdentityAllocator) {
			setup(t, a)
			if err := os.Remove(filepath.Join(a.markerDir, scannerIdentityMarker)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "journal missing", prepare: func(t *testing.T, a *scannerIdentityAllocator) {
			setup(t, a)
			if err := os.Remove(filepath.Join(a.directory, scannerIdentityJournalName)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "journal corrupt", prepare: func(t *testing.T, a *scannerIdentityAllocator) {
			setup(t, a)
			if err := os.WriteFile(filepath.Join(a.directory, scannerIdentityJournalName), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "invalid lease journal", prepare: func(t *testing.T, a *scannerIdentityAllocator) {
			setup(t, a)
			if err := writeTestScannerIdentityJournal(a, scannerIdentityJournal{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17, Leases: map[uint32]scannerIdentityJournalEntry{61000: {GID: 61000, Token: "bad", State: "unknown"}}}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "private scope probe error", prepare: func(t *testing.T, a *scannerIdentityAllocator) {
			setup(t, a)
			a.privateScope = func(uint64) (bool, error) { return false, errors.New("scope unavailable") }
		}},
		{name: "private scope mismatch", prepare: func(t *testing.T, a *scannerIdentityAllocator) {
			setup(t, a)
			a.privateScope = func(uint64) (bool, error) { return true, nil }
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allocator := newTestScannerIdentityAllocator(t, 1)
			if test.prepare != nil {
				test.prepare(t, allocator)
			}
			if test.mutate != nil {
				test.mutate(allocator)
			}
			ctx := context.Background()
			if test.waitForLock {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancel()
			}
			if _, err := allocator.inspect(ctx); err == nil {
				t.Fatal("inspection accepted an invalid input or unavailable durable state")
			}
		})
	}

	if _, err := (*scannerIdentityAllocator)(nil).inspect(context.Background()); err == nil {
		t.Fatal("inspection accepted a nil allocator")
	}
}

func TestScannerIdentityInspectionHelpersFailClosed(t *testing.T) {
	allocator := newTestScannerIdentityAllocator(t, 1)
	status := scannerIdentityPoolCounts(allocator, scannerIdentityJournal{Leases: map[uint32]scannerIdentityJournalEntry{
		61000: {State: "active"}, 61001: {State: "quarantined"},
	}}, map[uint32]struct{}{61002: {}, 61003: {}})
	if status.Free != 0 || status.Active != 1 || status.Quarantined != 1 || status.InUseByOtherProcesses != 2 {
		t.Fatalf("overcommitted pool counts = %+v; want zero free slots", status)
	}

	root := t.TempDir()
	if _, _, err := openScannerIdentityDirectoriesReadOnly(filepath.Join(root, "nested", "leases"), root); err == nil {
		t.Fatal("read-only open accepted non-sibling allocator directories")
	}
	if _, _, err := openScannerIdentityDirectoriesReadOnly(filepath.Join(root, "leases"), filepath.Join(root, "missing")); err == nil {
		t.Fatal("read-only open accepted a missing trusted parent")
	}
	missingParent := filepath.Join(root, "missing-parent")
	if _, _, err := openScannerIdentityDirectoriesReadOnly(filepath.Join(missingParent, "leases"), missingParent); err == nil {
		t.Fatal("read-only open accepted a missing sibling parent")
	}
	unsafeParent := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafeParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openScannerIdentityDirectoriesReadOnly(filepath.Join(unsafeParent, "leases"), unsafeParent); err == nil {
		t.Fatal("read-only open accepted a writable trusted parent")
	}
	missingChild := filepath.Join(root, "child")
	if err := os.Mkdir(missingChild, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openScannerIdentityDirectoriesReadOnly(filepath.Join(missingChild, "leases"), missingChild); err == nil {
		t.Fatal("read-only open accepted a missing private directory")
	}
	unsafeChild := filepath.Join(root, "unsafe-child")
	if err := os.Mkdir(unsafeChild, 0o700); err != nil {
		t.Fatal(err)
	}
	childPath := filepath.Join(unsafeChild, "leases")
	if err := os.Mkdir(childPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openScannerIdentityDirectoriesReadOnly(childPath, unsafeChild); err == nil {
		t.Fatal("read-only open accepted a non-private allocator directory")
	}

	path, markerDir, directory := scannerIdentityDirectoryFixture(t)
	directoryFD, markerFD, err := openScannerIdentityDirectories(path, markerDir)
	if err != nil {
		t.Fatal(err)
	}
	lockFD, err := openScannerIdentityLock(directoryFD)
	if err != nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		t.Fatal(err)
	}
	_ = unix.Close(lockFD)
	_ = unix.Close(directoryFD)
	_ = unix.Close(markerFD)
	directoryFD = mustOpenScannerIdentityDirectory(t, path, markerDir)
	lockFD, err = openExistingScannerIdentityLock(directoryFD)
	if err != nil {
		t.Fatalf("open existing lock: %v", err)
	}
	_ = unix.Close(lockFD)
	_ = unix.Close(directoryFD)
	if err := os.Remove(filepath.Join(directory, scannerIdentityLock)); err != nil {
		t.Fatal(err)
	}
	directoryFD, markerFD, err = openScannerIdentityDirectoriesReadOnly(path, markerDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openExistingScannerIdentityLock(directoryFD); err == nil {
		t.Fatal("missing existing lock was accepted")
	}
	if err := os.Mkdir(filepath.Join(directory, scannerIdentityLock), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := openExistingScannerIdentityLock(directoryFD); err == nil {
		t.Fatal("directory-shaped existing lock was accepted")
	}
	if err := os.Remove(filepath.Join(directory, scannerIdentityLock)); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(directoryFD)
	_ = unix.Close(markerFD)

	if err := lockScannerIdentityShared(context.Background(), -1); err == nil {
		t.Fatal("shared allocator lock accepted an invalid descriptor")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lockScannerIdentityShared(ctx, -1); !errors.Is(err, context.Canceled) {
		t.Fatalf("shared allocator lock with canceled context = %v", err)
	}

	path, markerDir, _ = scannerIdentityDirectoryFixture(t)
	directoryFD, markerFD, err = openScannerIdentityDirectories(path, markerDir)
	if err != nil {
		t.Fatal(err)
	}
	exclusiveFD, err := openScannerIdentityLock(directoryFD)
	if err != nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		t.Fatal(err)
	}
	sharedFD, err := openExistingScannerIdentityLock(directoryFD)
	if err != nil {
		_ = unix.Close(exclusiveFD)
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		t.Fatal(err)
	}
	if err := unix.Flock(exclusiveFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = unix.Flock(exclusiveFD, unix.LOCK_UN)
	}()
	if err := lockScannerIdentityShared(context.Background(), sharedFD); err != nil {
		t.Fatalf("shared lock did not acquire after the writer released it: %v", err)
	}
	_ = unix.Flock(sharedFD, unix.LOCK_UN)
	_ = unix.Close(sharedFD)
	_ = unix.Close(exclusiveFD)
	_ = unix.Close(directoryFD)
	_ = unix.Close(markerFD)
}

func mustOpenScannerIdentityDirectory(t *testing.T, path, markerDir string) int {
	t.Helper()
	directoryFD, markerFD, err := openScannerIdentityDirectoriesReadOnly(path, markerDir)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(markerFD)
	return directoryFD
}

func TestInspectScannerFallbackAndPoolNilContext(t *testing.T) {
	status := InspectScanner(Options{Mode: ModeOff}).Status()
	if status.State != StateDisabled || status.IdentityPool == nil || status.IdentityPool.State != StateDisabled {
		t.Fatalf("Linux scanner inspection = %+v; want disabled status", status)
	}
	status = inspectScannerFallback(Options{Mode: ModeOff}).Status()
	if status.State != StateDisabled || status.IdentityPool == nil || status.IdentityPool.State != StateDisabled {
		t.Fatalf("non-Linux off-mode scanner status = %+v", status)
	}
	if _, err := InspectScannerIdentityPool(nil); err == nil {
		t.Fatal("identity-pool inspection accepted a nil context")
	}
	pool, err := unavailableScannerIdentityPool(context.Background())
	if err == nil || pool == nil || pool.State != StateUnavailable {
		t.Fatalf("non-Linux identity-pool fallback = %+v, %v; want unavailable status and error", pool, err)
	}
}

func TestScannerIdentityUnavailableReasonClassification(t *testing.T) {
	for _, test := range []struct{ err, want string }{
		{"", "check the allocator state"},
		{"scanner identity allocator: PID namespace changed without exclusive private-scope proof", "stop all other EdgeWatch processes"},
		{"PID namespace changed without exclusive private-scope proof at /private/journal", "check the allocator state"},
		{"UID map is not available", "full scanner identity range"},
		{"scanner allocator journal is unavailable", "preserve the journal and boot marker"},
		{"generic failure", "check the allocator state"},
	} {
		var err error
		if test.err != "" {
			err = errors.New(test.err)
		}
		if got := scannerIdentityProbeUnavailableReason(err); !contains(got, test.want) {
			t.Errorf("probe reason for %q = %q, want %q", test.err, got, test.want)
		}
	}
	if got := scannerIdentityProbeUnavailableReason(errScannerIdentityPoolExhausted); got != errScannerIdentityPoolExhausted.Error() {
		t.Fatalf("pool exhaustion reason = %q", got)
	}
	if got := scannerIdentityRuntimeUnavailableReason(nil); !contains(got, "could not be retained") {
		t.Fatalf("nil runtime error reason = %q", got)
	}
	if got := scannerIdentityRuntimeUnavailableReason(errors.New("generic")); !contains(got, "check the configured UID/GID mapping") {
		t.Fatalf("generic runtime error reason = %q", got)
	}
	if got := scannerSeccompProbeUnavailableReason(errors.New("signal: bad system call")); !contains(got, "seccomp filter (signal: bad system call)") {
		t.Fatalf("seccomp failure reason = %q", got)
	}
}

func contains(value, fragment string) bool { return strings.Contains(value, fragment) }
