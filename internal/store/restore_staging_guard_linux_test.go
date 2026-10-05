//go:build linux

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireRestoreStagingGuardLinuxFailureAndCancellation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, supported, err := acquireRestoreStagingGuardLinux(context.Background(), filepath.Join(dir, "missing")); err == nil || !supported {
		t.Fatalf("guard for missing directory = supported %v, error %v; want supported error", supported, err)
	}
	filePath := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(filePath, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, supported, err := acquireRestoreStagingGuardLinux(context.Background(), filePath); err == nil || !supported {
		t.Fatalf("guard for file = supported %v, error %v; want supported error", supported, err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, supported, err := acquireRestoreStagingGuardLinux(canceled, dir); !errors.Is(err, context.Canceled) || !supported {
		t.Fatalf("guard with canceled context = supported %v, error %v; want context.Canceled", supported, err)
	}

	unlock, supported, err := acquireRestoreStagingGuardLinux(context.Background(), dir)
	if err != nil || !supported {
		t.Fatalf("acquire initial guard = supported %v, error %v", supported, err)
	}
	defer unlock()

	waiting, stopWaiting := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stopWaiting()
	if _, supported, err := acquireRestoreStagingGuardLinux(waiting, dir); !errors.Is(err, context.DeadlineExceeded) || !supported {
		t.Fatalf("contended guard = supported %v, error %v; want context deadline", supported, err)
	}
	unlock()
	unlock() // The returned release function is idempotent.
}

func TestAcquireUnsupportedRestoreStagingGuard(t *testing.T) {
	t.Parallel()
	unlock, supported, err := acquireUnsupportedRestoreStagingGuard(context.Background(), t.TempDir())
	if unlock != nil || supported || err != nil {
		t.Fatalf("unsupported guard = unlock %v, supported %v, error %v; want nil, false, nil", unlock != nil, supported, err)
	}
}
