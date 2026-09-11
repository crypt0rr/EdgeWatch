package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWriteFileIsPrivateCrashSafeAndNonReplacing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "export.json")
	got, err := AtomicWriteFile(path, ".edgewatch-test-", func(tempPath string) error {
		return os.WriteFile(tempPath, []byte("canonical"), 0o600)
	}, nil)
	if err != nil || got != path {
		t.Fatalf("atomic write = %q, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode = %o, want 600", info.Mode().Perm())
	}
	if err := os.WriteFile(filepath.Join(dir, "sentinel"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AtomicWriteFile(path, ".edgewatch-test-", func(tempPath string) error {
		return os.WriteFile(tempPath, []byte("replacement"), 0o600)
	}, nil); err == nil {
		t.Fatal("existing output was replaced")
	}

	linkTarget := filepath.Join(dir, "target")
	if err := os.WriteFile(linkTarget, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "link")
	if err := os.Symlink(linkTarget, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := AtomicWriteFile(linkPath, ".edgewatch-test-", func(tempPath string) error {
		return os.WriteFile(tempPath, []byte("unsafe"), 0o600)
	}, nil); err == nil {
		t.Fatal("symbolic-link output was accepted")
	}

	failedPath := filepath.Join(dir, "failed.json")
	if _, err := AtomicWriteFile(failedPath, ".edgewatch-test-", func(tempPath string) error {
		if writeErr := os.WriteFile(tempPath, make([]byte, 4096), 0o600); writeErr != nil {
			return writeErr
		}
		return errors.New("simulated interrupted export")
	}, nil); err == nil {
		t.Fatal("failed writer returned success")
	}
	if _, err := os.Stat(failedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed output = %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".edgewatch-test-") {
			t.Fatalf("temporary output directory was left behind: %s", entry.Name())
		}
	}
}
