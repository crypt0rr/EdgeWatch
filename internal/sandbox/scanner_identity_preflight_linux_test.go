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

// scannerCensusDeadlineContext expires at a chosen context check so a test
// can prove that a large process census stops between process reads without
// relying on scheduler timing.
type scannerCensusDeadlineContext struct {
	context.Context
	deadlineCheck int
	checks        int
}

func (ctx *scannerCensusDeadlineContext) Err() error {
	ctx.checks++
	if ctx.checks >= ctx.deadlineCheck {
		return context.DeadlineExceeded
	}
	return ctx.Context.Err()
}

func TestValidateScannerIdentityRangeMappingFromPaths(t *testing.T) {
	root := t.TempDir()
	uidPath := filepath.Join(root, "uid_map")
	gidPath := filepath.Join(root, "gid_map")
	write := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("every candidate UID and GID is mapped across ranges", func(t *testing.T) {
		write(uidPath, "0 100000 60000\n60000 300000 32\n60032 400000 32\n")
		write(gidPath, "0 200000 60000\n60000 500000 64\n")
		if err := validateScannerIdentityRangeMappingFromPaths(60000, 64, uidPath, gidPath); err != nil {
			t.Fatalf("validate complete scanner identity range: %v", err)
		}
	})

	t.Run("unavailable UID map fails closed", func(t *testing.T) {
		if err := validateScannerIdentityRangeMappingFromPaths(60000, 64, filepath.Join(root, "missing-uid"), gidPath); err == nil || !strings.Contains(err.Error(), "UID mapping is unavailable") {
			t.Fatalf("missing UID map error = %v; want unavailable UID mapping", err)
		}
	})

	t.Run("malformed GID map fails closed", func(t *testing.T) {
		write(uidPath, "60000 300000 64\n")
		write(gidPath, "not-a-map\n")
		if err := validateScannerIdentityRangeMappingFromPaths(60000, 64, uidPath, gidPath); err == nil || !strings.Contains(err.Error(), "GID mapping is unavailable") {
			t.Fatalf("malformed GID map error = %v; want unavailable GID mapping", err)
		}
	})

	t.Run("unmapped final candidate rejects the whole pool", func(t *testing.T) {
		write(uidPath, "60000 300000 64\n")
		write(gidPath, "60000 500000 63\n")
		err := validateScannerIdentityRangeMappingFromPaths(60000, 64, uidPath, gidPath)
		if err == nil || !strings.Contains(err.Error(), "required UID/GID 60063 is not mapped") {
			t.Fatalf("partially mapped pool error = %v; want final unmapped candidate", err)
		}
	})
}

func TestLockScannerIdentityCancellationAndInvalidDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allocator.lock")
	first, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(first)
	second, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(second)
	if err := unix.Flock(first, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	if err := lockScannerIdentity(ctx, second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended lock result = %v; want context deadline", err)
	}
	if err := unix.Flock(first, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := lockScannerIdentity(context.Background(), second); err != nil {
		t.Fatalf("lock after prior owner released: %v", err)
	}
	if err := unix.Flock(second, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := lockScannerIdentity(context.Background(), -1); err == nil || !strings.Contains(err.Error(), "allocator lock failed") {
		t.Fatalf("invalid descriptor result = %v; want lock failure", err)
	}
}

func TestReleasedScannerIdentityLeaseCannotBeReused(t *testing.T) {
	lease, err := newTestScannerIdentityAllocator(t, 1).acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := lease.identity(); !ok {
		t.Fatal("active lease did not expose its identity")
	}
	if err := lease.release(); err != nil {
		t.Fatal(err)
	}
	if uid, gid, ok := lease.identity(); ok || uid != 0 || gid != 0 {
		t.Fatalf("released identity = %d:%d, %t; want unavailable", uid, gid, ok)
	}
	if err := lease.release(); err == nil || !strings.Contains(err.Error(), "lease is unavailable") {
		t.Fatalf("second release = %v; want unavailable lease", err)
	}
	if err := lease.quarantine(); err == nil || !strings.Contains(err.Error(), "lease is unavailable") {
		t.Fatalf("quarantine after release = %v; want unavailable lease", err)
	}
}

func TestScannerIdentityCensusFailsClosedWhenSourcesAreUnavailable(t *testing.T) {
	root := t.TempDir()
	accounts := filepath.Join(root, "accounts")
	if err := os.Mkdir(accounts, 0o700); err != nil {
		t.Fatal(err)
	}
	passwdPath := filepath.Join(accounts, "passwd")
	groupPath := filepath.Join(accounts, "group")
	for _, path := range []string{passwdPath, groupPath} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	procRoot := filepath.Join(root, "proc")
	if err := os.Mkdir(procRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Run("unavailable proc tree", func(t *testing.T) {
		if _, err := scannerIdentitiesInUseAt(filepath.Join(root, "missing-proc"), passwdPath, groupPath, 61000, 64); err == nil {
			t.Fatal("unavailable process census was accepted")
		}
	})

	t.Run("unavailable local account source", func(t *testing.T) {
		if _, err := scannerIdentitiesInUseAt(procRoot, filepath.Join(root, "missing-passwd"), groupPath, 61000, 64); err == nil {
			t.Fatal("unavailable passwd source was accepted")
		}
	})
}

func TestScannerIdentityProcessCensusStopsAtDeadlineCheck(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	accountRoot := filepath.Join(root, "accounts")
	for _, path := range []string{procRoot, accountRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"passwd", "group"} {
		if err := os.WriteFile(filepath.Join(accountRoot, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, pid := range []string{"101", "102", "103"} {
		processPath := filepath.Join(procRoot, pid)
		if err := os.Mkdir(processPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if pid == "102" {
			if err := os.Mkdir(filepath.Join(processPath, "status"), 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(processPath, "status"), []byte("Uid:\t61000\t61000\t61000\t61000\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx := &scannerCensusDeadlineContext{Context: base, deadlineCheck: 12}
	_, err := scannerIdentitiesInUseAtContext(ctx, procRoot, filepath.Join(accountRoot, "passwd"), filepath.Join(accountRoot, "group"), 61000, 4)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("process census error = %v; want deadline exceeded before PID 102 is read", err)
	}
	if ctx.checks != ctx.deadlineCheck {
		t.Fatalf("process census made %d context checks; want it to stop at %d", ctx.checks, ctx.deadlineCheck)
	}
}

func TestScannerIdentityCensusRejectsOversizedLiveSources(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	accountRoot := filepath.Join(root, "accounts")
	for _, path := range []string{procRoot, accountRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	passwdPath := filepath.Join(accountRoot, "passwd")
	groupPath := filepath.Join(accountRoot, "group")
	for _, path := range []string{passwdPath, groupPath} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("oversized live process status fails the census closed", func(t *testing.T) {
		processPath := filepath.Join(procRoot, "404")
		if err := os.Mkdir(processPath, 0o700); err != nil {
			t.Fatal(err)
		}
		statusPath := filepath.Join(processPath, "status")
		if err := os.WriteFile(statusPath, []byte(strings.Repeat("x", scannerIdentityProcessStatusMaxBytes+1)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := scannerIdentitiesInUseAt(procRoot, passwdPath, groupPath, 61000, 4)
		if err == nil || !strings.Contains(err.Error(), "live process status is unreadable") {
			t.Fatalf("oversized live process status error = %v; want fail-closed census refusal", err)
		}
	})

	t.Run("oversized local account database fails the census", func(t *testing.T) {
		if err := os.WriteFile(passwdPath, []byte(strings.Repeat("x", scannerIdentityAccountsMaxBytes+1)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := scannerIdentitiesInUseAt(procRoot, passwdPath, groupPath, 61000, 4)
		if err == nil || !strings.Contains(err.Error(), "local account database exceeds the size limit") {
			t.Fatalf("oversized account database error = %v; want bounded-read refusal", err)
		}
	})
}

func TestScannerIdentityCensusRejectsNilAndCanceledContexts(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	accountRoot := filepath.Join(root, "accounts")
	for _, path := range []string{procRoot, accountRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	passwdPath := filepath.Join(accountRoot, "passwd")
	groupPath := filepath.Join(accountRoot, "group")
	for _, path := range []string{passwdPath, groupPath} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	//nolint:staticcheck // This deliberately verifies that a nil context is rejected.
	if _, err := scannerIdentitiesInUseAtContext(nil, procRoot, passwdPath, groupPath, 61000, 4); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil census context error = %v; want explicit refusal", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scannerIdentitiesInUseAtContext(ctx, procRoot, passwdPath, groupPath, 61000, 4); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled census context error = %v; want context.Canceled", err)
	}
}

func TestScannerIdentityCurrentInUseChecksContextAndCensus(t *testing.T) {
	t.Run("missing allocator or context fails closed", func(t *testing.T) {
		var allocator *scannerIdentityAllocator
		if _, err := allocator.currentInUse(context.Background()); err == nil {
			t.Fatal("nil allocator supplied a process census")
		}
		allocator = newTestScannerIdentityAllocator(t, 2)
		//nolint:staticcheck // This deliberately verifies that a nil context is rejected.
		if _, err := allocator.currentInUse(nil); err == nil {
			t.Fatal("nil context supplied a process census")
		}
		allocator.inUse = nil
		if _, err := allocator.currentInUse(context.Background()); err == nil {
			t.Fatal("missing census callback was accepted")
		}
	})

	t.Run("canceled context does not start census", func(t *testing.T) {
		allocator := newTestScannerIdentityAllocator(t, 2)
		called := false
		allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) {
			called = true
			return nil, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := allocator.currentInUse(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled census error = %v; want context.Canceled", err)
		}
		if called {
			t.Fatal("census ran after its context was canceled")
		}
	})

	t.Run("context-aware census receives configured pool and returns its error", func(t *testing.T) {
		allocator := newTestScannerIdentityAllocator(t, 2)
		want := map[uint32]struct{}{61001: {}}
		called := false
		allocator.inUseContext = func(ctx context.Context, start, count uint32) (map[uint32]struct{}, error) {
			called = true
			if ctx == nil || start != 61000 || count != 2 {
				t.Fatalf("context-aware census args = %v, %d, %d", ctx, start, count)
			}
			return want, nil
		}
		got, err := allocator.currentInUse(context.Background())
		if err != nil || !called || len(got) != 1 {
			t.Fatalf("context-aware census = %v, %v, called=%t; want configured result", got, err, called)
		}
		if _, ok := got[61001]; !ok {
			t.Fatalf("context-aware census identities = %v; want reserved UID 61001", got)
		}

		wantErr := errors.New("process census unavailable")
		allocator.inUseContext = func(context.Context, uint32, uint32) (map[uint32]struct{}, error) { return nil, wantErr }
		if _, err := allocator.currentInUse(context.Background()); !errors.Is(err, wantErr) {
			t.Fatalf("context-aware census error = %v; want %v", err, wantErr)
		}
	})

	t.Run("legacy census propagates failure and rejects post-census cancellation", func(t *testing.T) {
		allocator := newTestScannerIdentityAllocator(t, 2)
		wantErr := errors.New("legacy census unavailable")
		allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) { return nil, wantErr }
		if _, err := allocator.currentInUse(context.Background()); !errors.Is(err, wantErr) {
			t.Fatalf("legacy census error = %v; want %v", err, wantErr)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) {
			cancel()
			return map[uint32]struct{}{61000: {}}, nil
		}
		if _, err := allocator.currentInUse(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("post-census cancellation error = %v; want context.Canceled", err)
		}
	})
}

func TestScannerIdentityInspectionReturnsCensusCancellation(t *testing.T) {
	for _, test := range []struct {
		name      string
		cancelErr bool
	}{
		{name: "census cancellation"},
		{name: "context canceled after census", cancelErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			allocator := newTestScannerIdentityAllocator(t, 1)
			lease, err := allocator.acquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.release(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			allocator.inUseContext = func(ctx context.Context, _, _ uint32) (map[uint32]struct{}, error) {
				cancel()
				if test.cancelErr {
					return map[uint32]struct{}{}, nil
				}
				return nil, context.Canceled
			}
			if _, err := allocator.inspect(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled identity inspection error = %v; want context.Canceled", err)
			}
		})
	}
}

func TestWriteScannerIdentityFileDoesNotReplaceUnexpectedDirectory(t *testing.T) {
	root := t.TempDir()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := os.Mkdir(filepath.Join(root, "leases.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeScannerIdentityFile(fd, "leases.json", []byte(`{"version":2}`)); err == nil {
		t.Fatal("atomic state writer replaced an unexpected directory")
	}
	info, err := os.Stat(filepath.Join(root, "leases.json"))
	if err != nil || !info.IsDir() {
		t.Fatalf("unexpected state path after failed write = %v, %v; want original directory intact", info, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "leases.json" {
		t.Fatalf("failed atomic write left temporary state behind: %v", entries)
	}
}
