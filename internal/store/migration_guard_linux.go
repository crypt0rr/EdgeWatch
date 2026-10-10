//go:build linux

package store

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

func init() {
	acquireMigrationGuard = acquireMigrationGuardLinux
}

// acquireMigrationGuardLinux takes the flock of the directory that
// acquireRestoreStagingGuardLinux takes, without waiting for it. Two locks
// on separately opened descriptors conflict, also within one process.
func acquireMigrationGuardLinux(directory string) (func(), error) {
	file, err := os.Open(directory)
	if err != nil {
		return nil, fmt.Errorf("open the database directory to lock it: %w", err)
	}
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			var once sync.Once
			return func() {
				once.Do(func() {
					_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
					_ = file.Close()
				})
			}, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("%w: %s", ErrMigrationInProgress, directory)
		}
		return nil, fmt.Errorf("%w: %s: %w", errMigrationGuardUnsupported, directory, err)
	}
}
