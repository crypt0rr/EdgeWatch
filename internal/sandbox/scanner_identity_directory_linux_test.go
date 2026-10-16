//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenScannerIdentityDirectoriesCreatesPrivateDurableState(t *testing.T) {
	root := t.TempDir()
	markerDir := filepath.Join(root, "data")
	if err := os.Mkdir(markerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(markerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(markerDir, "scanner-identities")

	directoryFD, markerFD, err := openScannerIdentityDirectories(path, markerDir)
	if err != nil {
		t.Fatalf("create durable identity directory: %v", err)
	}
	defer unix.Close(directoryFD)
	defer unix.Close(markerFD)
	var directory unix.Stat_t
	if err := unix.Fstat(directoryFD, &directory); err != nil {
		t.Fatal(err)
	}
	if directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Mode&0o7777 != 0o700 || directory.Uid != uint32(os.Geteuid()) {
		t.Fatalf("created identity directory metadata = mode %#o uid %d; want 0700 owned by daemon", directory.Mode, directory.Uid)
	}
	if got, err := os.Lstat(path); err != nil || !got.IsDir() {
		t.Fatalf("durable identity directory path = %v, %v", got, err)
	}

	lockFD, err := openScannerIdentityLock(directoryFD)
	if err != nil {
		t.Fatalf("create durable allocator lock: %v", err)
	}
	defer unix.Close(lockFD)
	var lock unix.Stat_t
	if err := unix.Fstat(lockFD, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Mode&unix.S_IFMT != unix.S_IFREG || lock.Mode&0o7777 != 0o600 || lock.Uid != uint32(os.Geteuid()) || lock.Nlink != 1 || lock.Size != 0 {
		t.Fatalf("allocator lock metadata = mode %#o uid %d links %d size %d", lock.Mode, lock.Uid, lock.Nlink, lock.Size)
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("lock newly created allocator file: %v", err)
	}
	if err := unix.Flock(lockFD, unix.LOCK_UN); err != nil {
		t.Fatalf("unlock newly created allocator file: %v", err)
	}
}

func TestOpenScannerIdentityDirectoriesRejectsUnsafeParents(t *testing.T) {
	t.Run("mismatched sibling paths", func(t *testing.T) {
		root := t.TempDir()
		markerDir := filepath.Join(root, "data")
		if err := os.Mkdir(markerDir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "other", "scanner-identities")
		if directoryFD, markerFD, err := openScannerIdentityDirectories(path, markerDir); err == nil {
			_ = unix.Close(directoryFD)
			_ = unix.Close(markerFD)
			t.Fatal("mismatched allocator and marker paths were accepted")
		} else if !strings.Contains(err.Error(), "sibling directories") {
			t.Fatalf("mismatched paths error = %v, want sibling-path refusal", err)
		}
		if _, err := os.Lstat(filepath.Join(root, "other")); !os.IsNotExist(err) {
			t.Fatalf("mismatched path caused filesystem mutation: %v", err)
		}
	})

	t.Run("symlinked marker parent", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "trusted-target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		markerDir := filepath.Join(root, "marker-link")
		if err := os.Symlink(target, markerDir); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(markerDir, "scanner-identities")
		if directoryFD, markerFD, err := openScannerIdentityDirectories(path, markerDir); err == nil {
			_ = unix.Close(directoryFD)
			_ = unix.Close(markerFD)
			t.Fatal("symlinked marker parent was accepted")
		} else if !strings.Contains(err.Error(), "trusted parent is unavailable") {
			t.Fatalf("symlinked parent error = %v, want no-follow refusal", err)
		}
		if _, err := os.Lstat(filepath.Join(target, "scanner-identities")); !os.IsNotExist(err) {
			t.Fatalf("symlinked parent caused target mutation: %v", err)
		}
	})

	for _, test := range []struct {
		name string
		mode os.FileMode
		want string
	}{
		{name: "group writable", mode: 0o770, want: "not group/other writable"},
		{name: "owner lacks write and search", mode: 0o500, want: "not group/other writable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			markerDir := filepath.Join(root, "data")
			if err := os.Mkdir(markerDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(markerDir, test.mode); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(markerDir, "scanner-identities")
			if directoryFD, markerFD, err := openScannerIdentityDirectories(path, markerDir); err == nil {
				_ = unix.Close(directoryFD)
				_ = unix.Close(markerFD)
				t.Fatalf("unsafe parent mode %#o was accepted", test.mode)
			} else if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsafe parent mode %#o error = %v, want %q", test.mode, err, test.want)
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("unsafe parent caused private directory mutation: %v", err)
			}
		})
	}
}

func TestOpenScannerIdentityDirectoriesRejectsSymlinkOrUnsafeStateDirectory(t *testing.T) {
	t.Run("symlinked state directory", func(t *testing.T) {
		root := t.TempDir()
		markerDir := filepath.Join(root, "data")
		if err := os.Mkdir(markerDir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(markerDir, "scanner-identities")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if directoryFD, markerFD, err := openScannerIdentityDirectories(path, markerDir); err == nil {
			_ = unix.Close(directoryFD)
			_ = unix.Close(markerFD)
			t.Fatal("symlinked identity directory was accepted")
		} else if !strings.Contains(err.Error(), "private directory is unavailable") {
			t.Fatalf("symlinked identity directory error = %v", err)
		}
		if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
			t.Fatalf("symlink target changed: entries=%v err=%v", entries, err)
		}
	})

	t.Run("permissive existing directory", func(t *testing.T) {
		root := t.TempDir()
		markerDir := filepath.Join(root, "data")
		if err := os.Mkdir(markerDir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(markerDir, "scanner-identities")
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if directoryFD, markerFD, err := openScannerIdentityDirectories(path, markerDir); err == nil {
			_ = unix.Close(directoryFD)
			_ = unix.Close(markerFD)
			t.Fatal("permissive existing identity directory was accepted")
		} else if !strings.Contains(err.Error(), "directory is not private to the daemon") {
			t.Fatalf("permissive identity directory error = %v", err)
		}
		stat, err := os.Stat(path)
		if err != nil || stat.Mode().Perm() != 0o755 {
			t.Fatalf("refused directory mode changed: %v, %v", stat, err)
		}
	})
}

func TestOpenScannerIdentityLockRejectsUnsafeMetadata(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, dirFD int, directory string)
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, dirFD int, directory string) {
				target := filepath.Join(filepath.Dir(directory), "lock-target")
				if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(directory, scannerIdentityLock)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "permissive mode",
			setup: func(t *testing.T, dirFD int, directory string) {
				path := filepath.Join(directory, scannerIdentityLock)
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard link",
			setup: func(t *testing.T, dirFD int, directory string) {
				path := filepath.Join(directory, scannerIdentityLock)
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(path, filepath.Join(filepath.Dir(directory), "lock-alias")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "nonempty lock",
			setup: func(t *testing.T, dirFD int, directory string) {
				if err := os.WriteFile(filepath.Join(directory, scannerIdentityLock), []byte("unexpected"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, markerDir, directory := scannerIdentityDirectoryFixture(t)
			directoryFD, markerFD, err := openScannerIdentityDirectories(path, markerDir)
			if err != nil {
				t.Fatalf("open private test directory: %v", err)
			}
			defer unix.Close(directoryFD)
			defer unix.Close(markerFD)
			test.setup(t, directoryFD, directory)
			if lockFD, err := openScannerIdentityLock(directoryFD); err == nil {
				_ = unix.Close(lockFD)
				t.Fatal("unsafe allocator lock metadata was accepted")
			}
		})
	}
}

func scannerIdentityDirectoryFixture(t *testing.T) (path, markerDir, directory string) {
	t.Helper()
	root := t.TempDir()
	markerDir = filepath.Join(root, "data")
	if err := os.Mkdir(markerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(markerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(markerDir, "scanner-identities")
	directory = path
	return path, markerDir, directory
}
