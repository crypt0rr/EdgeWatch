//go:build linux

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	acquireRestoreStagingGuard = acquireRestoreStagingGuardLinux
}

func acquireRestoreStagingGuardLinux(ctx context.Context, parent string) (func(), bool, error) {
	file, err := os.Open(parent)
	if err != nil {
		return nil, true, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, true, err
	}
	if !info.IsDir() {
		_ = file.Close()
		return nil, true, errors.New("restore staging guard is not a directory")
	}
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return nil, true, err
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
			}, true, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = file.Close()
			return nil, true, fmt.Errorf("lock restore destination directory: %w", err)
		}
		timer := time.NewTimer(40 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = file.Close()
			return nil, true, ctx.Err()
		case <-timer.C:
		}
	}
}
