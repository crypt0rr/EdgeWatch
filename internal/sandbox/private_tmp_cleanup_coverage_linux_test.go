//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func newPrivateTemporaryCleanupCoverageLeaf(t *testing.T) (string, int, unix.Stat_t) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "leaf")
	if err := os.Mkdir(path, privateTemporaryFallbackMode); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return path, fd, stat
}

func TestCleanPrivateDirectoryContentsRejectsInvalidOrChangedLeaf(t *testing.T) {
	for _, test := range []struct {
		name string
		want string
		stat func(unix.Stat_t) *unix.Stat_t
	}{
		{name: "missing expected identity", want: "invalid private temporary leaf"},
		{
			name: "unsupported mode",
			want: "invalid private temporary leaf",
			stat: func(stat unix.Stat_t) *unix.Stat_t {
				stat.Mode = unix.S_IFDIR | 0o755
				return &stat
			},
		},
		{
			name: "changed inode",
			want: "private temporary leaf identity changed",
			stat: func(stat unix.Stat_t) *unix.Stat_t {
				stat.Ino++
				return &stat
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, fd, actual := newPrivateTemporaryCleanupCoverageLeaf(t)
			artifact := filepath.Join(path, "preserve")
			if err := os.WriteFile(artifact, []byte("unverified cleanup must not mutate"), 0o600); err != nil {
				t.Fatal(err)
			}
			var expected *unix.Stat_t
			if test.stat == nil {
				expected = nil
			} else {
				expected = test.stat(actual)
			}
			if err := cleanPrivateDirectoryContents(fd, expected, actual.Uid, actual.Gid); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("cleanup error = %v, want %q", err, test.want)
			}
			if contents, err := os.ReadFile(artifact); err != nil || string(contents) != "unverified cleanup must not mutate" {
				t.Fatalf("rejected cleanup changed artifact: %q, %v", contents, err)
			}
		})
	}
}

func TestRemovePrivateDirectoryContentsRejectsUnexpectedOwner(t *testing.T) {
	path, fd, stat := newPrivateTemporaryCleanupCoverageLeaf(t)
	artifact := filepath.Join(path, "owned")
	if err := os.WriteFile(artifact, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongOwner := stat.Uid + 1
	if wrongOwner == stat.Uid {
		wrongOwner = stat.Uid - 1
	}
	duplicate, err := unix.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(duplicate)
	if err := removePrivateDirectoryContents(duplicate, uint64(stat.Dev), wrongOwner, stat.Gid, 0, &cleanupBudget{}); err == nil || !strings.Contains(err.Error(), "ownership changed") {
		t.Fatalf("cleanup with mismatched owner error = %v", err)
	}
	if contents, err := os.ReadFile(artifact); err != nil || string(contents) != "preserve" {
		t.Fatalf("owner mismatch removed or changed artifact: %q, %v", contents, err)
	}
}

func TestRemovePrivateDirectoryContentsRejectsUnreadableSubdirectory(t *testing.T) {
	path, fd, stat := newPrivateTemporaryCleanupCoverageLeaf(t)
	blocked := filepath.Join(path, "blocked")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(blocked, "preserve")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chmod(blocked, 0o700); err != nil {
			t.Errorf("restore blocked directory permissions: %v", err)
		}
	}()
	duplicate, err := unix.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(duplicate)
	if err := removePrivateDirectoryContents(duplicate, uint64(stat.Dev), stat.Uid, stat.Gid, 0, &cleanupBudget{}); err == nil || !strings.Contains(err.Error(), "open private temporary subdirectory failed") {
		t.Fatalf("cleanup of unreadable child error = %v", err)
	}
	if err := os.Chmod(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if contents, err := os.ReadFile(marker); err != nil || string(contents) != "preserve" {
		t.Fatalf("unreadable-child rejection changed nested artifact: %q, %v", contents, err)
	}
}
