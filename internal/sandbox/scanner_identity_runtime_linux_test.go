//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateScannerRuntimeBootstrapRequiresPID1AndVerifiedScope(t *testing.T) {
	t.Run("non PID1 cannot establish a scope", func(t *testing.T) {
		called := false
		got, err := privateScannerRuntimeFor(42, func() (uint64, error) {
			called = true
			return 91, nil
		}, func(uint64) (bool, error) {
			called = true
			return true, nil
		})
		if err != nil || got || called {
			t.Fatalf("non-PID1 scope bootstrap = %t, %v, probes called=%t; want false, nil, no probes", got, err, called)
		}
	})

	t.Run("PID1 uses current namespace and private mount probes", func(t *testing.T) {
		scopeCalls := 0
		got, err := privateScannerRuntimeFor(1, func() (uint64, error) { return 91, nil }, func(namespace uint64) (bool, error) {
			scopeCalls++
			if namespace != 91 {
				t.Fatalf("private-scope probe namespace=%d, want 91", namespace)
			}
			return true, nil
		})
		if err != nil || !got || scopeCalls != 1 {
			t.Fatalf("PID1 private scope = %t, %v, probe calls=%d; want true, nil, 1", got, err, scopeCalls)
		}
	})

	t.Run("namespace probe error fails closed", func(t *testing.T) {
		want := errors.New("namespace read failed")
		got, err := privateScannerRuntimeFor(1, func() (uint64, error) { return 0, want }, func(uint64) (bool, error) {
			t.Fatal("private scope was probed without a namespace")
			return false, nil
		})
		if got || !errors.Is(err, want) {
			t.Fatalf("PID1 namespace failure = %t, %v; want false and %v", got, err, want)
		}
	})

	t.Run("zero namespace is rejected", func(t *testing.T) {
		called := false
		got, err := privateScannerRuntimeFor(1, func() (uint64, error) { return 0, nil }, func(uint64) (bool, error) {
			called = true
			return true, nil
		})
		if got || err == nil || called {
			t.Fatalf("zero namespace scope = %t, %v, probe called=%t; want error without scope probe", got, err, called)
		}
	})

	t.Run("shared mount is not private", func(t *testing.T) {
		got, err := privateScannerRuntimeFor(1, func() (uint64, error) { return 91, nil }, func(uint64) (bool, error) {
			return false, nil
		})
		if err != nil || got {
			t.Fatalf("shared mount scope = %t, %v; want false, nil", got, err)
		}
	})

	t.Run("mount inspection error is preserved", func(t *testing.T) {
		want := errors.New("mount inspection failed")
		got, err := privateScannerRuntimeFor(1, func() (uint64, error) { return 91, nil }, func(uint64) (bool, error) {
			return false, want
		})
		if got || !errors.Is(err, want) {
			t.Fatalf("mount inspection error = %t, %v; want false and %v", got, err, want)
		}
	})

	t.Run("missing probes fail closed", func(t *testing.T) {
		if got, err := privateScannerRuntimeFor(1, nil, nil); got || err == nil {
			t.Fatalf("missing probes = %t, %v; want false and error", got, err)
		}
	})
}

func TestEnsureScannerIdentityDirectoryAtEnforcesDurableParentContract(t *testing.T) {
	t.Run("daemon-owned private directory is accepted", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "durable-state")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := ensureScannerIdentityDirectoryAt(parent); err != nil {
			t.Fatalf("accept private durable parent: %v", err)
		}
	})

	t.Run("group or other writable parent is rejected", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "writable-state")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o770); err != nil {
			t.Fatal(err)
		}
		if err := ensureScannerIdentityDirectoryAt(parent); err == nil {
			t.Fatal("accepted group-writable durable parent")
		}
	})

	t.Run("non-searchable parent is rejected", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "unsearchable-state")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		if err := ensureScannerIdentityDirectoryAt(parent); err == nil {
			t.Fatal("accepted durable parent without owner write and search permission")
		}
	})

	t.Run("symlinked parent is rejected", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		link := filepath.Join(root, "link")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := ensureScannerIdentityDirectoryAt(link); err == nil {
			t.Fatal("followed a symlink for the durable state parent")
		}
	})

	t.Run("missing parent is rejected", func(t *testing.T) {
		if err := ensureScannerIdentityDirectoryAt(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("accepted a missing durable state parent")
		}
	})
}

func TestReserveLinuxScannerIdentityFailureAndSuccessContracts(t *testing.T) {
	allocatorError := errors.New("durable allocator unavailable")
	newPolicy := func() *Policy {
		return &Policy{
			profile: Scanner,
			status:  Status{Mode: ModeAuto},
			enforce: true,
		}
	}

	t.Run("nil and canceled contexts fail before lease", func(t *testing.T) {
		policy := newPolicy()
		calls := 0
		policy.identityAllocator = func(context.Context) (identityLease, error) {
			calls++
			return &identityLeaseProbe{uid: 61000, gid: 61000, identityOK: true}, nil
		}
		var nilContext context.Context
		if got, err := reserveLinuxScannerIdentity(nilContext, policy); err == nil || got != nil {
			t.Fatalf("nil context reservation = %v, %v; want refusal", got, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if got, err := reserveLinuxScannerIdentity(ctx, policy); !errors.Is(err, context.Canceled) || got != nil {
			t.Fatalf("canceled context reservation = %v, %v; want context.Canceled", got, err)
		}
		if calls != 0 {
			t.Fatalf("invalid contexts called the allocator %d times", calls)
		}
	})

	t.Run("off policy does not allocate", func(t *testing.T) {
		policy := newPolicy()
		policy.status.Mode = ModeOff
		policy.identityAllocator = func(context.Context) (identityLease, error) {
			t.Fatal("explicit Off requested an identity lease")
			return nil, nil
		}
		if got, err := reserveLinuxScannerIdentity(context.Background(), policy); err != nil || got != nil {
			t.Fatalf("Off reservation = %v, %v; want nil, nil", got, err)
		}
	})

	t.Run("wrong profile and unenforced policy fail closed", func(t *testing.T) {
		wrongProfile := newPolicy()
		wrongProfile.profile = Notifier
		if got, err := reserveLinuxScannerIdentity(context.Background(), wrongProfile); got != nil || err == nil {
			t.Fatalf("notifier reservation = %v, %v; want refusal", got, err)
		}
		unenforced := newPolicy()
		unenforced.enforce = false
		if got, err := reserveLinuxScannerIdentity(context.Background(), unenforced); got != nil || err == nil {
			t.Fatalf("unenforced scanner reservation = %v, %v; want refusal", got, err)
		}
	})

	t.Run("allocator error is preserved", func(t *testing.T) {
		policy := newPolicy()
		policy.identityAllocator = func(context.Context) (identityLease, error) { return nil, allocatorError }
		if got, err := reserveLinuxScannerIdentity(context.Background(), policy); got != nil || !errors.Is(err, allocatorError) {
			t.Fatalf("allocator failure = %v, %v; want nil and %v", got, err, allocatorError)
		}
	})

	t.Run("valid reservation exposes identity until cleanup", func(t *testing.T) {
		lease := &identityLeaseProbe{uid: 61009, gid: 61009, identityOK: true}
		policy := newPolicy()
		policy.identityAllocator = func(context.Context) (identityLease, error) { return lease, nil }
		reservation, err := reserveLinuxScannerIdentity(context.Background(), policy)
		if err != nil {
			t.Fatal(err)
		}
		uid, gid, ok := reservation.Identity()
		if !ok || uid != 61009 || gid != 61009 {
			t.Fatalf("reserved identity = %d:%d, %t", uid, gid, ok)
		}
		if err := reservation.Finish(true); err != nil {
			t.Fatal(err)
		}
		if lease.releases != 1 || lease.quarantines != 0 {
			t.Fatalf("reservation cleanup actions = releases %d quarantines %d", lease.releases, lease.quarantines)
		}
	})
}

func TestScannerIdentityAcquireRejectsUnavailableInputsAndUsesSnapshotSafely(t *testing.T) {
	bootErr := errors.New("boot identity unavailable")
	namespaceErr := errors.New("PID namespace unavailable")
	runtimeErr := errors.New("runtime scope unavailable")
	mapErr := errors.New("ID mapping unavailable")
	processErr := errors.New("process census unavailable")

	t.Run("invalid allocator configuration fails before touching durable state", func(t *testing.T) {
		mutations := map[string]func(*scannerIdentityAllocator){
			"empty path":                  func(allocator *scannerIdentityAllocator) { allocator.directory = "" },
			"empty marker path":           func(allocator *scannerIdentityAllocator) { allocator.markerDir = "" },
			"zero range":                  func(allocator *scannerIdentityAllocator) { allocator.count = 0 },
			"zero first ID":               func(allocator *scannerIdentityAllocator) { allocator.uidStart = 0 },
			"overflowing range":           func(allocator *scannerIdentityAllocator) { allocator.uidStart, allocator.count = ^uint32(0), 2 },
			"missing boot probe":          func(allocator *scannerIdentityAllocator) { allocator.bootID = nil },
			"missing namespace probe":     func(allocator *scannerIdentityAllocator) { allocator.pidNamespace = nil },
			"missing runtime probe":       func(allocator *scannerIdentityAllocator) { allocator.privateRuntime = nil },
			"missing private-scope probe": func(allocator *scannerIdentityAllocator) { allocator.privateScope = nil },
			"missing ID-map validator":    func(allocator *scannerIdentityAllocator) { allocator.validateMap = nil },
			"missing process census":      func(allocator *scannerIdentityAllocator) { allocator.inUse = nil },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				allocator := newTestScannerIdentityAllocator(t, 1)
				mutate(allocator)
				if lease, err := allocator.acquire(context.Background()); lease != nil || err == nil {
					t.Fatalf("invalid allocator returned lease %v, error %v; want fail-closed refusal", lease, err)
				}
				if _, err := os.Stat(allocator.directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("invalid allocator touched private state: stat error %v", err)
				}
			})
		}
	})

	t.Run("kernel identity and mapping failures stop before lease creation", func(t *testing.T) {
		cases := []struct {
			name      string
			setup     func(*scannerIdentityAllocator)
			wantText  string
			wantCause error
		}{
			{name: "boot read error", setup: func(a *scannerIdentityAllocator) { a.bootID = func() (string, error) { return "", bootErr } }, wantText: "kernel boot identity is unavailable"},
			{name: "malformed boot ID", setup: func(a *scannerIdentityAllocator) { a.bootID = func() (string, error) { return "not-a-boot-id", nil } }, wantText: "kernel boot identity is unavailable"},
			{name: "namespace read error", setup: func(a *scannerIdentityAllocator) { a.pidNamespace = func() (uint64, error) { return 0, namespaceErr } }, wantText: "PID namespace identity is unavailable"},
			{name: "zero namespace", setup: func(a *scannerIdentityAllocator) { a.pidNamespace = func() (uint64, error) { return 0, nil } }, wantText: "PID namespace identity is unavailable"},
			{name: "private runtime read error", setup: func(a *scannerIdentityAllocator) {
				a.privateRuntime = func() (bool, error) { return false, runtimeErr }
			}, wantText: "private runtime scope is unavailable"},
			{name: "unmapped pool", setup: func(a *scannerIdentityAllocator) { a.validateMap = func(uint32, uint32) error { return mapErr } }, wantCause: mapErr},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				allocator := newTestScannerIdentityAllocator(t, 1)
				test.setup(allocator)
				lease, err := allocator.acquire(context.Background())
				if lease != nil || err == nil {
					t.Fatalf("allocator acquisition = %v, %v; want fail-closed refusal", lease, err)
				}
				if test.wantText != "" && !strings.Contains(err.Error(), test.wantText) {
					t.Fatalf("allocator error %v does not identify %q", err, test.wantText)
				}
				if test.wantCause != nil && !errors.Is(err, test.wantCause) {
					t.Fatalf("allocator error %v does not preserve %v", err, test.wantCause)
				}
				if _, statErr := os.Stat(allocator.directory); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("failed kernel preflight touched durable state: %v", statErr)
				}
			})
		}
	})

	t.Run("unreadable process census fails closed", func(t *testing.T) {
		allocator := newTestScannerIdentityAllocator(t, 1)
		allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) { return nil, processErr }
		lease, err := allocator.acquire(context.Background())
		if lease != nil || err == nil || !strings.Contains(err.Error(), "current identity use cannot be inspected") {
			t.Fatalf("unreadable process census = %v, %v; want refusal", lease, err)
		}
		if _, statErr := os.Stat(filepath.Join(allocator.directory, scannerIdentityJournalName)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("census failure touched the durable journal: %v", statErr)
		}
	})

	t.Run("cancellation after initialization creates no lease", func(t *testing.T) {
		allocator := newTestScannerIdentityAllocator(t, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		controlled := &cancelOnErrCallContext{Context: ctx, cancel: cancel, call: 8}
		lease, err := allocator.acquire(controlled)
		if lease != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled pre-reservation acquire = %v, %v; want context.Canceled", lease, err)
		}
		journal, readErr := readTestScannerIdentityJournal(allocator)
		if readErr != nil || len(journal.Leases) != 0 {
			t.Fatalf("pre-reservation cancellation persisted a lease: journal=%+v read error=%v", journal, readErr)
		}
	})

	t.Run("all currently used IDs leave the durable pool empty", func(t *testing.T) {
		allocator := newTestScannerIdentityAllocator(t, 1)
		allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) {
			return map[uint32]struct{}{61000: {}}, nil
		}
		lease, err := allocator.acquire(context.Background())
		if lease != nil || !errors.Is(err, errScannerIdentityPoolExhausted) {
			t.Fatalf("occupied pool acquisition = %v, %v; want exhausted", lease, err)
		}
		journal, readErr := readTestScannerIdentityJournal(allocator)
		if readErr != nil || len(journal.Leases) != 0 {
			t.Fatalf("occupied pool persisted a lease: journal=%+v read error=%v", journal, readErr)
		}
	})
}

type cancelOnErrCallContext struct {
	context.Context
	cancel context.CancelFunc
	call   int
	calls  int
}

func (ctx *cancelOnErrCallContext) Err() error {
	ctx.calls++
	if ctx.calls == ctx.call {
		ctx.cancel()
	}
	return ctx.Context.Err()
}
