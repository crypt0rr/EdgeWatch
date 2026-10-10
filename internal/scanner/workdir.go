package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// scanRunPrefix names the directory each EdgeWatch process keeps its scan
// files in, below the scanner's temporary directory.
const scanRunPrefix = "run-"

// staleRunAge keeps a process from removing the directory of a process that
// created it a moment ago and has not locked it yet.
const staleRunAge = time.Minute

// SetTemporaryDirectory makes the scanner create the private files of its
// scans, Nmap's XML output and Naabu's target list, below dir instead of the
// system's temporary directory, so where they land does not depend on
// TMPDIR. It creates dir with mode 0700 when it is missing and refuses a dir
// that is not a directory of this process's user with no group or other
// permissions: a confined scanner then cannot reach a file there by its
// path, only through the descriptor it inherits, and Landlock never grants a
// scanner the data directory that dir lies in. The files go into a
// directory of this process below dir, which it locks while it runs; the
// directories that processes which no longer run left behind, with the files
// of scans they were stopped in, are removed.
func (n *Nmap) SetTemporaryDirectory(dir string) error {
	dir = filepath.Clean(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create the scanner temporary directory: %w", err)
	}
	if err := requirePrivateDirectory(dir); err != nil {
		return err
	}
	removeStaleScanRuns(dir, time.Now())
	run, err := os.MkdirTemp(dir, scanRunPrefix)
	if err != nil {
		return fmt.Errorf("create the scanner temporary directory: %w", err)
	}
	lock, err := lockDirectory(run)
	if err != nil {
		_ = os.Remove(run)
		return fmt.Errorf("lock the scanner temporary directory: %w", err)
	}
	if n.workDirLock != nil {
		_ = n.workDirLock.Close()
	}
	n.workDir, n.workDirLock = run, lock
	return nil
}

// requirePrivateDirectory refuses a path that is not a directory, such as a
// symbolic link, or that grants its group or others any access.
func requirePrivateDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect the scanner temporary directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("the scanner temporary directory %s is not a directory", dir)
	}
	if !ownedByCurrentUser(info) {
		return fmt.Errorf("the scanner temporary directory %s belongs to another user", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("restrict the scanner temporary directory: %w", err)
		}
	}
	return nil
}

// removeStaleScanRuns removes the scan directories below dir whose process
// no longer holds their lock. A directory modified within staleRunAge is
// kept, because its process may not have locked it yet.
func removeStaleScanRuns(dir string, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), scanRunPrefix) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil || now.Sub(info.ModTime()) < staleRunAge {
			continue
		}
		if locked, err := directoryLocked(path); err == nil && !locked {
			_ = os.RemoveAll(path)
		}
	}
}
