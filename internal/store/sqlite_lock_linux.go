//go:build linux

package store

import (
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// SQLite's unix VFS locks these bytes of the main database file. Every
// connection holds a read lock on the SHARED range while it reads, and a
// WAL-mode connection keeps that lock for as long as it has the WAL open. A
// connection first read-locks the PENDING byte to acquire SHARED. RESERVED
// sits between the two and is write-locked by a rollback-journal writer.
const (
	sqlitePendingByte = 0x40000000
	sqliteSharedFirst = sqlitePendingByte + 2
	sqliteSharedSize  = 510
)

func init() {
	lockSQLiteDatabase = lockSQLiteDatabaseOFD
}

// lockSQLiteDatabaseOFD takes a non-blocking write lock over the PENDING,
// RESERVED and SHARED bytes, the same test sqlite3WalClose uses before it
// deletes a WAL. The lock conflicts with every connection that holds SHARED,
// and while it is held no connection can acquire SHARED. It is an open file
// description (OFD) lock, so it also conflicts with POSIX locks that SQLite
// holds in this process.
func lockSQLiteDatabaseOFD(database string) (func(), bool) {
	file, err := os.OpenFile(database, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false
	}
	locked := false
	defer func() {
		if !locked {
			_ = file.Close()
		}
	}()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, false
	}
	setLock := func(lockType int16) error {
		lock := unix.Flock_t{
			Type:   lockType,
			Whence: io.SeekStart,
			Start:  sqlitePendingByte,
			Len:    sqliteSharedFirst + sqliteSharedSize - sqlitePendingByte,
		}
		var lockErr error
		if err := raw.Control(func(fd uintptr) {
			lockErr = unix.FcntlFlock(fd, unix.F_OFD_SETLK, &lock)
		}); err != nil {
			return err
		}
		return lockErr
	}
	if err := setLock(unix.F_WRLCK); err != nil {
		return nil, false
	}
	locked = true
	return func() {
		_ = setLock(unix.F_UNLCK)
		_ = file.Close()
	}, true
}
