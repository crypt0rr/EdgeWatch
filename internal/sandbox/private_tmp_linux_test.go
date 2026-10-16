//go:build linux

package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func newPrivateTemporaryProtocolFixture(t *testing.T) (*linuxPrivateTemporaryDirectory, privateTemporaryInit, []byte) {
	t.Helper()
	temporary := &linuxPrivateTemporaryDirectory{
		filesystem: realPrivateTemporaryFilesystemOps(),
		uid:        uint32(os.Geteuid()),
		gid:        uint32(os.Getegid()),
		leafMode:   privateTemporaryMode,
	}
	if err := temporary.createNamespace(); err != nil {
		t.Fatalf("create protocol fixture namespace: %v", err)
	}
	if err := temporary.createLeaf(); err != nil {
		_ = temporary.Close()
		t.Fatalf("create protocol fixture leaf: %v", err)
	}
	t.Cleanup(func() {
		if err := temporary.Cleanup(context.Background()); err != nil {
			t.Errorf("clean protocol fixture: %v", err)
		}
		if err := temporary.Close(); err != nil {
			t.Errorf("close protocol fixture: %v", err)
		}
	})
	if _, err := rand.Read(temporary.nonce[:]); err != nil {
		t.Fatal(err)
	}
	var namespace, leaf unix.Stat_t
	if err := unix.Fstat(int(temporary.namespace.Fd()), &namespace); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(int(temporary.leaf.Fd()), &leaf); err != nil {
		t.Fatal(err)
	}
	message, err := encodePrivateTemporaryInit(temporary.namespaceName, temporary.name, temporary.nonce, &namespace, &leaf)
	if err != nil {
		t.Fatalf("encode protocol fixture: %v", err)
	}
	initialization, err := decodePrivateTemporaryInit(message)
	if err != nil {
		t.Fatalf("decode protocol fixture: %v", err)
	}
	return temporary, initialization, message
}

type privateTemporaryCreatedEntry struct {
	parentFD int
	name     string
}

func recordSuccessfulPrivateTemporaryMkdirs(t *testing.T, filesystem *privateTemporaryFilesystemOps) *[]privateTemporaryCreatedEntry {
	t.Helper()
	original := filesystem.mkdirat
	var created []privateTemporaryCreatedEntry
	filesystem.mkdirat = func(parentFD int, name string, mode uint32) error {
		pinnedParent, err := unix.Dup(parentFD)
		if err != nil {
			return err
		}
		unix.CloseOnExec(pinnedParent)
		if err := original(parentFD, name, mode); err != nil {
			_ = unix.Close(pinnedParent)
			return err
		}
		created = append(created, privateTemporaryCreatedEntry{parentFD: pinnedParent, name: name})
		return nil
	}
	return &created
}

func assertPrivateTemporaryEntriesExist(t *testing.T, created []privateTemporaryCreatedEntry) {
	t.Helper()
	for _, entry := range created {
		var stat unix.Stat_t
		if err := unix.Fstatat(entry.parentFD, entry.name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Errorf("owned setup entry %q was absent at cancellation: %v", entry.name, err)
		}
	}
}

func assertPrivateTemporaryEntriesAbsent(t *testing.T, created *[]privateTemporaryCreatedEntry) {
	t.Helper()
	if created == nil {
		t.Fatal("created-entry recorder is nil")
	}
	for _, entry := range *created {
		defer unix.Close(entry.parentFD)
		var stat unix.Stat_t
		if err := unix.Fstatat(entry.parentFD, entry.name, &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			t.Errorf("rollback left created entry %q: %v", entry.name, err)
		}
	}
}

func TestCreateNamespaceRollsBackAfterOwnedSetupFailures(t *testing.T) {
	for _, stage := range []string{"root open", "root fstat", "mkdirat", "openat", "fchmod", "namespace fstat", "fstatat", "name collisions"} {
		t.Run(stage, func(t *testing.T) {
			filesystem := realPrivateTemporaryFilesystemOps()
			temporary := &linuxPrivateTemporaryDirectory{
				filesystem: filesystem,
				uid:        uint32(os.Geteuid()),
				gid:        uint32(os.Getegid()),
			}
			fail := func() error { return unix.EIO }
			switch stage {
			case "root open":
				filesystem.open = func(string, int, uint32) (int, error) { return -1, fail() }
			case "root fstat":
				filesystem.fstat = func(int, *unix.Stat_t) error { return fail() }
			case "mkdirat":
				filesystem.mkdirat = func(int, string, uint32) error { return fail() }
			case "openat":
				filesystem.openat = func(int, string, int, uint32) (int, error) { return -1, fail() }
			case "fchmod":
				filesystem.fchmod = func(int, uint32) error { return fail() }
			case "namespace fstat":
				original := filesystem.fstat
				calls := 0
				filesystem.fstat = func(fd int, stat *unix.Stat_t) error {
					calls++
					if calls == 2 {
						return fail()
					}
					return original(fd, stat)
				}
			case "fstatat":
				filesystem.fstatat = func(int, string, *unix.Stat_t, int) error { return fail() }
			case "name collisions":
				filesystem.mkdirat = func(int, string, uint32) error { return unix.EEXIST }
			}
			created := recordSuccessfulPrivateTemporaryMkdirs(t, &filesystem)
			temporary.filesystem = filesystem

			if err := temporary.createNamespace(); err == nil {
				t.Fatal("namespace creation unexpectedly succeeded")
			}
			if temporary.namespace != nil || temporary.namespaceName != "" {
				t.Fatalf("failed setup retained a namespace handle/name: %v %q", temporary.namespace, temporary.namespaceName)
			}
			if err := temporary.Close(); err != nil {
				t.Fatalf("close setup descriptors: %v", err)
			}
			assertPrivateTemporaryEntriesAbsent(t, created)
		})
	}
}

func TestCreateLeafRequiresPinnedNamespaceAndSupportedMode(t *testing.T) {
	filesystem := realPrivateTemporaryFilesystemOps()
	if err := (&linuxPrivateTemporaryDirectory{filesystem: filesystem, leafMode: privateTemporaryMode}).createLeaf(); err == nil {
		t.Fatal("leaf creation succeeded without a pinned namespace")
	}

	temporary := &linuxPrivateTemporaryDirectory{
		filesystem: filesystem,
		uid:        uint32(os.Geteuid()),
		gid:        uint32(os.Getegid()),
		leafMode:   unix.S_IFDIR | privateTemporaryMode,
	}
	if err := temporary.createNamespace(); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	t.Cleanup(func() {
		if err := temporary.Cleanup(context.Background()); err != nil {
			t.Errorf("cleanup unsupported leaf mode fixture: %v", err)
		}
		_ = temporary.Close()
	})
	if err := temporary.createLeaf(); err == nil {
		t.Fatal("leaf creation accepted a mode containing file-type bits")
	}
	if temporary.leaf != nil || temporary.name != "" {
		t.Fatalf("unsupported leaf mode changed temporary state: leaf=%v name=%q", temporary.leaf, temporary.name)
	}
}

func TestCreateLeafNamedRollsBackAfterOwnedSetupFailures(t *testing.T) {
	for _, stage := range []string{"invalid name", "mkdirat", "openat", "fchmod", "fstat", "fstatat"} {
		t.Run(stage, func(t *testing.T) {
			filesystem := realPrivateTemporaryFilesystemOps()
			temporary := &linuxPrivateTemporaryDirectory{
				filesystem: filesystem,
				uid:        uint32(os.Geteuid()),
				gid:        uint32(os.Getegid()),
				leafMode:   privateTemporaryMode,
			}
			if err := temporary.createNamespace(); err != nil {
				t.Fatalf("create namespace: %v", err)
			}
			t.Cleanup(func() {
				if temporary.leaf == nil {
					temporary.name = ""
				}
				if err := temporary.Cleanup(context.Background()); err != nil {
					t.Errorf("cleanup failed leaf setup: %v", err)
				}
				_ = temporary.Close()
			})
			temporary.name = privateTemporaryPrefix + strings.Repeat("a", privateTemporaryNonceSize*2)
			fail := func() error { return unix.EIO }
			switch stage {
			case "mkdirat":
				filesystem.mkdirat = func(int, string, uint32) error { return fail() }
			case "openat":
				filesystem.openat = func(int, string, int, uint32) (int, error) { return -1, fail() }
			case "fchmod":
				filesystem.fchmod = func(int, uint32) error { return fail() }
			case "fstat":
				original := filesystem.fstat
				failed := false
				filesystem.fstat = func(fd int, stat *unix.Stat_t) error {
					if !failed {
						failed = true
						return fail()
					}
					return original(fd, stat)
				}
			case "fstatat":
				original := filesystem.fstatat
				failed := false
				filesystem.fstatat = func(fd int, name string, stat *unix.Stat_t, flags int) error {
					if !failed {
						failed = true
						return fail()
					}
					return original(fd, name, stat, flags)
				}
			case "invalid name":
				temporary.name = "not-a-private-leaf"
			}
			created := recordSuccessfulPrivateTemporaryMkdirs(t, &filesystem)
			temporary.filesystem = filesystem

			if err := temporary.createLeafNamed(); err == nil {
				t.Fatal("leaf creation unexpectedly succeeded")
			}
			if temporary.leaf != nil {
				t.Fatal("failed leaf setup retained a pinned descriptor")
			}
			assertPrivateTemporaryEntriesAbsent(t, created)
			var stat unix.Stat_t
			if err := unix.Fstatat(int(temporary.namespace.Fd()), temporary.name, &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
				t.Fatalf("failed %s setup left an unpinned leaf: %v", stage, err)
			}
		})
	}
}

func TestCreateLeafRetriesRandomNameCollisions(t *testing.T) {
	for _, collisionCount := range []int{1, 8} {
		name := "retry after collision"
		if collisionCount == 8 {
			name = "fail after bounded collisions"
		}
		t.Run(name, func(t *testing.T) {
			filesystem := realPrivateTemporaryFilesystemOps()
			temporary := &linuxPrivateTemporaryDirectory{
				filesystem: filesystem,
				uid:        uint32(os.Geteuid()),
				gid:        uint32(os.Getegid()),
				leafMode:   privateTemporaryMode,
			}
			if err := temporary.createNamespace(); err != nil {
				t.Fatalf("create namespace: %v", err)
			}
			originalMkdirat := filesystem.mkdirat
			attempts := 0
			filesystem.mkdirat = func(fd int, name string, mode uint32) error {
				attempts++
				if attempts <= collisionCount {
					return unix.EEXIST
				}
				return originalMkdirat(fd, name, mode)
			}
			created := recordSuccessfulPrivateTemporaryMkdirs(t, &filesystem)
			temporary.filesystem = filesystem
			t.Cleanup(func() {
				if err := temporary.Cleanup(context.Background()); err != nil {
					t.Errorf("cleanup temporary directory: %v", err)
				}
				_ = temporary.Close()
			})

			err := temporary.createLeaf()
			if collisionCount < 8 {
				if err != nil {
					t.Fatalf("create leaf after collision: %v", err)
				}
				if temporary.leaf == nil || temporary.name == "" || len(*created) != 1 {
					t.Fatalf("leaf retry state: descriptor=%v name=%q created=%v", temporary.leaf, temporary.name, *created)
				}
				if (*created)[0].name != temporary.name {
					t.Fatalf("pinned leaf name %q differs from created name %q", temporary.name, (*created)[0].name)
				}
				assertPrivateTemporaryEntriesExist(t, *created)
				if attempts != 2 {
					t.Fatalf("mkdir attempts = %d, want one collision plus one create", attempts)
				}
			} else {
				if err == nil || temporary.leaf != nil {
					t.Fatalf("bounded collision result = %v with leaf %v", err, temporary.leaf)
				}
				if len(*created) != 0 || attempts != 8 {
					t.Fatalf("bounded collision attempts=%d created=%v, want 8 collisions and no leaf", attempts, *created)
				}
			}
		})
	}
}

func TestLinuxPreparationSetupFailuresDoNotStartOrModifyScannerCommand(t *testing.T) {
	for _, stage := range []string{"namespace pin", "leaf pin", "leaf chmod", "leaf revalidation"} {
		t.Run(stage, func(t *testing.T) {
			filesystem := realPrivateTemporaryFilesystemOps()
			fail := func() error { return unix.EIO }
			switch stage {
			case "namespace pin":
				original := filesystem.openat
				filesystem.openat = func(fd int, name string, flags int, mode uint32) (int, error) {
					if strings.HasPrefix(name, privateNamespacePrefix) {
						return -1, fail()
					}
					return original(fd, name, flags, mode)
				}
			case "leaf pin":
				original := filesystem.openat
				filesystem.openat = func(fd int, name string, flags int, mode uint32) (int, error) {
					if strings.HasPrefix(name, privateTemporaryPrefix) {
						return -1, fail()
					}
					return original(fd, name, flags, mode)
				}
			case "leaf chmod":
				original := filesystem.fchmod
				calls := 0
				filesystem.fchmod = func(fd int, mode uint32) error {
					calls++
					if calls == 2 {
						return fail()
					}
					return original(fd, mode)
				}
			case "leaf revalidation":
				original := filesystem.fstatat
				failed := false
				filesystem.fstatat = func(fd int, name string, stat *unix.Stat_t, flags int) error {
					if strings.HasPrefix(name, privateTemporaryPrefix) && !failed {
						failed = true
						return fail()
					}
					return original(fd, name, stat, flags)
				}
			}
			created := recordSuccessfulPrivateTemporaryMkdirs(t, &filesystem)
			command := exec.Command("/bin/true")
			command.Env = []string{"TMPDIR=/original", "TMPDIR=/duplicate", "PATH=/original"}
			originalEnv := append([]string(nil), command.Env...)
			if temporary, err := prepareLinuxPrivateTemporaryDirectoryWithFilesystem(context.Background(), command, nil, filesystem); err == nil {
				if temporary != nil {
					_ = temporary.Cleanup(context.Background())
					_ = temporary.Close()
				}
				t.Fatal("injected setup failure was accepted")
			}
			if command.Process != nil {
				t.Fatal("setup failure started the scanner")
			}
			if !reflect.DeepEqual(command.Env, originalEnv) {
				t.Fatalf("setup failure changed scanner environment: got %q want %q", command.Env, originalEnv)
			}
			assertPrivateTemporaryEntriesAbsent(t, created)
		})
	}
}

func TestPrivateTemporaryCleanupRejectsUnpinnedLeafThenRemovesEmptyNamespace(t *testing.T) {
	temporary := &linuxPrivateTemporaryDirectory{
		filesystem: realPrivateTemporaryFilesystemOps(),
		uid:        uint32(os.Geteuid()),
		gid:        uint32(os.Getegid()),
		leafMode:   privateTemporaryMode,
	}
	if err := temporary.createNamespace(); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	t.Cleanup(func() { _ = temporary.Close() })
	temporary.name = privateTemporaryPrefix + strings.Repeat("b", privateTemporaryNonceSize*2)
	if err := unix.Mkdirat(int(temporary.namespace.Fd()), temporary.name, 0o700); err != nil {
		t.Fatalf("create unpinned directory: %v", err)
	}
	if err := temporary.Cleanup(context.Background()); err == nil {
		t.Fatal("cleanup accepted an unpinned leaf")
	}
	if _, err := os.Lstat(temporary.path()); err != nil {
		t.Fatalf("cleanup removed the unpinned entry: %v", err)
	}
	if err := unix.Unlinkat(int(temporary.namespace.Fd()), temporary.name, unix.AT_REMOVEDIR); err != nil {
		t.Fatalf("remove test-owned unpinned entry: %v", err)
	}
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup empty namespace after unpinned entry was removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join("/tmp", temporary.namespaceName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty invocation namespace remains: %v", err)
	}
}

func TestPrivateTemporaryCleanupFailsClosedOnUnsupportedEntryAndCanRetry(t *testing.T) {
	temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
	path := filepath.Join(temporary.path(), "unsupported-entry")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Cleanup(context.Background()); err == nil {
		t.Fatal("cleanup accepted an unsupported FIFO entry")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("failed cleanup removed the unsupported entry: %v", err)
	}
	if _, err := os.Stat(temporary.path()); err != nil {
		t.Fatalf("failed cleanup removed the pinned leaf: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove test-owned FIFO: %v", err)
	}
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("retry cleanup after removing unsupported entry: %v", err)
	}
}

func TestPrivateTemporaryWaitReadyRejectsMalformedOrUnacknowledgedHelper(t *testing.T) {
	for _, stage := range []string{"malformed packet", "unexpected descriptor", "wrong same-length name", "wrong nonce", "wrong leaf identity", "acknowledgement failure"} {
		t.Run(stage, func(t *testing.T) {
			temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
			temporary.private = true
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			temporary.parent = os.NewFile(uintptr(pair[0]), "private temporary parent control")
			t.Cleanup(func() { _ = unix.Close(pair[1]) })

			var leaf unix.Stat_t
			if err := unix.Fstat(int(temporary.leaf.Fd()), &leaf); err != nil {
				t.Fatal(err)
			}
			message, err := encodePrivateTemporaryMessage(temporary.name, temporary.nonce, &leaf)
			if err != nil {
				t.Fatal(err)
			}
			var control []byte
			switch stage {
			case "malformed packet":
				message = []byte("bad")
			case "unexpected descriptor":
				file, err := os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				control = unix.UnixRights(int(file.Fd()))
			case "wrong same-length name":
				message[len(privateTemporaryMessageMagic)+1] ^= 1
			case "wrong nonce":
				message[len(message)-len(temporary.nonce)] ^= 1
			case "wrong leaf identity":
				binary.LittleEndian.PutUint64(message[len(privateTemporaryMessageMagic)+1+len(temporary.name):], uint64(leaf.Ino+1))
			}
			if n, err := unix.SendmsgN(pair[1], message, control, nil, 0); err != nil || n != len(message) {
				t.Fatalf("send readiness packet: n=%d err=%v", n, err)
			}
			if stage == "acknowledgement failure" {
				if err := unix.Close(pair[1]); err != nil {
					t.Fatal(err)
				}
			}
			if err := temporary.WaitReady(context.Background()); err == nil {
				t.Fatal("invalid or unacknowledged readiness was accepted")
			}
			if temporary.accepted {
				t.Fatal("failed readiness changed the accepted state")
			}
			temporary.private = false
		})
	}
}

func TestLinuxPrivateTemporaryStartedAndWaitReadyAreNoOpsWithoutHelper(t *testing.T) {
	var missing *linuxPrivateTemporaryDirectory
	if err := missing.Started(); err != nil {
		t.Fatalf("nil temporary start hook: %v", err)
	}
	if err := missing.WaitReady(context.Background()); err != nil {
		t.Fatalf("nil temporary readiness hook: %v", err)
	}

	temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
	if err := temporary.Started(); err != nil {
		t.Fatalf("fallback start hook: %v", err)
	}
	if !temporary.started || temporary.child != nil {
		t.Fatalf("fallback start state = started %v child %v", temporary.started, temporary.child)
	}
	if err := temporary.Started(); err != nil {
		t.Fatalf("idempotent fallback start hook: %v", err)
	}
	if err := temporary.WaitReady(context.Background()); err != nil {
		t.Fatalf("fallback readiness hook: %v", err)
	}
}

func TestPrivateTemporaryInitRoundTripAndRejectsMalformedPackets(t *testing.T) {
	temporary, initialization, encoded := newPrivateTemporaryProtocolFixture(t)
	if initialization.namespaceName != temporary.namespaceName || initialization.name != temporary.name || initialization.nonce != temporary.nonce {
		t.Fatalf("decoded initialization = %+v, want the pinned names and nonce", initialization)
	}
	if err := validatePrivateTemporaryLocation(int(temporary.namespace.Fd()), int(temporary.leaf.Fd()), initialization); err != nil {
		t.Fatalf("validate pinned location: %v", err)
	}

	for name, mutate := range map[string]func([]byte) []byte{
		"bad magic":              func(message []byte) []byte { message[0] ^= 1; return message },
		"short packet":           func(message []byte) []byte { return message[:len(message)-1] },
		"empty namespace":        func(message []byte) []byte { message[len(privateTemporaryInitMagic)] = 0; return message },
		"invalid namespace name": func(message []byte) []byte { message[len(privateTemporaryInitMagic)+1] = '!'; return message },
		"empty leaf": func(message []byte) []byte {
			namespaceLength := int(message[len(privateTemporaryInitMagic)])
			message[len(privateTemporaryInitMagic)+1+namespaceLength] = 0
			return message
		},
		"mismatched directory mode": func(message []byte) []byte {
			namespaceLength := int(message[len(privateTemporaryInitMagic)])
			leafLengthOffset := len(privateTemporaryInitMagic) + 1 + namespaceLength
			leafLength := int(message[leafLengthOffset])
			leafStatOffset := leafLengthOffset + 1 + leafLength + 28
			leafStatOffset += 24
			binary.LittleEndian.PutUint32(message[leafStatOffset:leafStatOffset+4], unix.S_IFDIR|0o700)
			return message
		},
	} {
		t.Run(name, func(t *testing.T) {
			message := mutate(append([]byte(nil), encoded...))
			if _, err := decodePrivateTemporaryInit(message); err == nil {
				t.Fatal("malformed initialization was accepted")
			}
		})
	}
	if _, err := encodePrivateTemporaryInit("../namespace", temporary.name, temporary.nonce, &initialization.namespace, &initialization.leaf); err == nil {
		t.Fatal("encoder accepted a path-like namespace name")
	}
	if _, err := encodePrivateTemporaryInit(temporary.namespaceName, temporary.name, temporary.nonce, nil, &initialization.leaf); err == nil {
		t.Fatal("encoder accepted a missing namespace stat")
	}
	if _, err := decodePrivateTemporaryInit(nil); err == nil {
		t.Fatal("decoder accepted an empty initialization")
	}
}

func TestReadPrivateTemporaryInitRejectsAncillaryDescriptors(t *testing.T) {
	_, _, message := newPrivateTemporaryProtocolFixture(t)
	for _, withDescriptor := range []bool{false, true} {
		name := "valid packet"
		if withDescriptor {
			name = "unexpected descriptor"
		}
		t.Run(name, func(t *testing.T) {
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pair[0])
			defer unix.Close(pair[1])
			var rights []byte
			if withDescriptor {
				file, err := os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				rights = unix.UnixRights(int(file.Fd()))
			}
			if n, err := unix.SendmsgN(pair[1], message, rights, nil, 0); err != nil || n != len(message) {
				t.Fatalf("send initialization packet: n=%d err=%v", n, err)
			}
			initialization, err := readPrivateTemporaryInit(pair[0])
			if withDescriptor {
				if err == nil {
					t.Fatal("initialization with an unexpected descriptor was accepted")
				}
			} else if err != nil || initialization.name == "" {
				t.Fatalf("read valid initialization = %+v, %v", initialization, err)
			}
		})
	}
}

func TestCloseReceivedDescriptorsClosesEveryReceivedFD(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := unix.SendmsgN(pair[1], []byte("descriptor"), unix.UnixRights(int(file.Fd())), nil, 0); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 32)
	control := make([]byte, unix.CmsgSpace(4))
	_, controlN, _, _, err := unix.Recvmsg(pair[0], data, control, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := unix.ParseSocketControlMessage(control[:controlN])
	if err != nil || len(messages) != 1 {
		t.Fatalf("parse received descriptor message: %v, %d messages", err, len(messages))
	}
	fds, err := unix.ParseUnixRights(&messages[0])
	if err != nil || len(fds) != 1 {
		t.Fatalf("parse received descriptors: %v, %v", fds, err)
	}
	if err := closeReceivedDescriptors(control[:controlN]); err == nil {
		t.Fatal("unexpected descriptor control message was accepted")
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("received descriptor remains open after rejection: %v", err)
	}
}

func TestValidatePrivateTemporaryLocationRejectsChangedIdentity(t *testing.T) {
	temporary, initialization, _ := newPrivateTemporaryProtocolFixture(t)
	wrongInode := initialization
	wrongInode.leaf.Ino++
	if err := validatePrivateTemporaryLocation(int(temporary.namespace.Fd()), int(temporary.leaf.Fd()), wrongInode); err == nil {
		t.Fatal("location validation accepted a changed leaf inode")
	}
	wrongNamespace := initialization
	wrongNamespace.namespace.Mode = unix.S_IFDIR | 0o700
	if err := validatePrivateTemporaryLocation(int(temporary.namespace.Fd()), int(temporary.leaf.Fd()), wrongNamespace); err == nil {
		t.Fatal("location validation accepted a changed namespace mode")
	}
	if err := validatePrivateTemporaryLocation(int(temporary.leaf.Fd()), int(temporary.leaf.Fd()), initialization); err == nil {
		t.Fatal("location validation accepted the leaf as the namespace descriptor")
	}
	if err := unix.Renameat(int(temporary.namespace.Fd()), temporary.name, int(temporary.namespace.Fd()), temporary.name+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateTemporaryLocation(int(temporary.namespace.Fd()), int(temporary.leaf.Fd()), initialization); err == nil {
		t.Fatal("location validation accepted a renamed leaf entry")
	}
	if err := unix.Renameat(int(temporary.namespace.Fd()), temporary.name+"-moved", int(temporary.namespace.Fd()), temporary.name); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateTemporaryReadinessMessageRoundTripAndAck(t *testing.T) {
	temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
	var stat unix.Stat_t
	if err := unix.Fstat(int(temporary.leaf.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	message, err := encodePrivateTemporaryMessage(temporary.name, temporary.nonce, &stat)
	if err != nil {
		t.Fatal(err)
	}
	device, inode, uid, gid, mode, err := decodePrivateTemporaryMessage(message, temporary.name, temporary.nonce)
	if err != nil || device != uint64(stat.Dev) || inode != stat.Ino || uid != stat.Uid || gid != stat.Gid || mode != stat.Mode {
		t.Fatalf("decoded readiness = dev %d inode %d uid %d gid %d mode %#o err %v", device, inode, uid, gid, mode, err)
	}
	for _, test := range []struct {
		name   string
		input  []byte
		expect string
	}{
		{name: "wrong name", input: message, expect: temporary.name + "-wrong"},
		{name: "short message", input: message[:len(message)-1], expect: temporary.name},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, _, _, err := decodePrivateTemporaryMessage(test.input, test.expect, temporary.nonce); err == nil {
				t.Fatal("invalid readiness message was accepted")
			}
		})
	}
	if _, err := encodePrivateTemporaryMessage(temporary.name, temporary.nonce, nil); err == nil {
		t.Fatal("readiness encoder accepted a nil stat")
	}

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	ready := make(chan error, 1)
	go func() { ready <- helperSendPrivateTemporaryReady(pair[0], temporary.name, temporary.nonce, &stat) }()
	received := make([]byte, privateTemporaryMessageMax)
	n, err := unix.Read(pair[1], received)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err := decodePrivateTemporaryMessage(received[:n], temporary.name, temporary.nonce); err != nil {
		t.Fatalf("helper readiness packet: %v", err)
	}
	if n, err := unix.Write(pair[1], []byte{1}); err != nil || n != 1 {
		t.Fatalf("send readiness ACK: n=%d err=%v", n, err)
	}
	if err := <-ready; err != nil {
		t.Fatalf("helper did not accept ACK: %v", err)
	}

	badAckPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	badAck := make(chan error, 1)
	go func() {
		badAck <- helperSendPrivateTemporaryReady(badAckPair[0], temporary.name, temporary.nonce, &stat)
	}()
	if _, err := unix.Read(badAckPair[1], received); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(badAckPair[1], []byte{0}); err != nil {
		t.Fatal(err)
	}
	if err := <-badAck; err == nil {
		t.Fatal("helper accepted a negative readiness ACK")
	}
	_ = unix.Close(badAckPair[0])
	_ = unix.Close(badAckPair[1])
	if err := helperSendPrivateTemporaryReady(-1, temporary.name, temporary.nonce, &stat); err == nil {
		t.Fatal("helper sent readiness over an invalid control descriptor")
	}
}

func TestPrivateTemporaryCleanerRemovesOwnedNestedArtifactsAndFailsClosed(t *testing.T) {
	temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
	leafPath := temporary.path()
	levelDB := filepath.Join(leafPath, "ipranger-map", "leveldb")
	if err := os.MkdirAll(levelDB, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"MANIFEST-000001": "manifest", "000002.ldb": "table", "CURRENT": "MANIFEST-000001"} {
		if err := os.WriteFile(filepath.Join(levelDB, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(leafPath, "outside-link")); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(temporary.leaf.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	request := privateTemporaryCleanupRequest{
		device: uint64(stat.Dev), inode: stat.Ino, leafUID: stat.Uid, leafGID: stat.Gid,
		uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()),
	}
	wrongIdentity := request
	wrongIdentity.inode++
	if err := cleanupPrivateTemporaryDirectoryFD(wrongIdentity, int(temporary.leaf.Fd())); err == nil {
		t.Fatal("cleaner accepted a leaf with the wrong inode")
	}
	if _, err := os.Stat(filepath.Join(levelDB, "MANIFEST-000001")); err != nil {
		t.Fatalf("identity failure changed temporary content: %v", err)
	}
	cleanupArgs := []string{
		"--device", strconv.FormatUint(request.device, 10),
		"--inode", strconv.FormatUint(request.inode, 10),
		"--leaf-uid", strconv.FormatUint(uint64(request.leafUID), 10),
		"--leaf-gid", strconv.FormatUint(uint64(request.leafGID), 10),
		"--uid", strconv.FormatUint(uint64(request.uid), 10),
		"--gid", strconv.FormatUint(uint64(request.gid), 10),
	}
	if err := cleanupPrivateTemporaryDirectoryWithDescriptor(cleanupArgs, -1); err == nil {
		t.Fatal("cleaner accepted an invalid inherited descriptor")
	}
	if err := execLandlocked([]string{"--cleanup-private-tmp", "--bad-argument"}); err == nil {
		t.Fatal("sandbox helper accepted malformed cleanup arguments")
	}
	if err := cleanupPrivateTemporaryDirectoryWithDescriptor(cleanupArgs, int(temporary.leaf.Fd())); err != nil {
		t.Fatalf("clean nested scanner artifacts: %v", err)
	}
	entries, err := os.ReadDir(leafPath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cleaned leaf contents = %v, %v; want empty", entries, err)
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != "preserve" {
		t.Fatalf("cleaner followed outside symlink: %q, %v", got, err)
	}

	fifo := filepath.Join(leafPath, "unsupported-fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupPrivateTemporaryDirectoryFD(request, int(temporary.leaf.Fd())); err == nil {
		t.Fatal("cleaner accepted an unsupported FIFO")
	}
	if info, err := os.Lstat(fifo); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("failed cleanup removed or changed unsupported FIFO: %v, %v", info, err)
	}
	if err := os.Remove(fifo); err != nil {
		t.Fatal(err)
	}
}

func linuxTemporaryState(t *testing.T, temporary *PrivateTemporaryDirectory) *linuxPrivateTemporaryDirectory {
	t.Helper()
	if temporary == nil {
		t.Fatal("private temporary directory is nil")
	}
	state, ok := temporary.implementation.(*linuxPrivateTemporaryDirectory)
	if !ok || state == nil {
		t.Fatalf("private temporary implementation = %T, want Linux helper", temporary.implementation)
	}
	return state
}

func linuxTemporaryPath(t *testing.T, temporary *PrivateTemporaryDirectory) string {
	t.Helper()
	return linuxTemporaryState(t, temporary).path()
}

func TestPreparePrivateTemporaryDirectoryKeepsControlFDOutsideDataFiles(t *testing.T) {
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	cmd := exec.Command("/bin/true")
	cmd.ExtraFiles = []*os.File{data}
	policy := NewEnforced().WithLandlock(helper, 6).WithSeccomp()
	temporary, err := PreparePrivateTemporaryDirectory(context.Background(), cmd, policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := temporary.Cleanup(t.Context()); err != nil {
			t.Errorf("cleanup private temporary directory: %v", err)
		}
	})
	defer temporary.Close()

	wantPrefix := []string{helper, ExecCommand, "--profile", "scanner", "--files", "1", "--private-tmp", "--private-root-fd", "4", "--private-leaf-fd", "5", "--control-fd", "6"}
	if len(cmd.Args) < len(wantPrefix) || !reflect.DeepEqual(cmd.Args[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("helper argv prefix = %q, want %q", cmd.Args, wantPrefix)
	}
	if len(cmd.ExtraFiles) != 4 || cmd.ExtraFiles[0] != data || cmd.ExtraFiles[1] != linuxTemporaryState(t, temporary).namespace || cmd.ExtraFiles[2] != linuxTemporaryState(t, temporary).leaf || cmd.ExtraFiles[3] != linuxTemporaryState(t, temporary).child {
		t.Fatalf("inherited descriptors = %v, want data FD followed by namespace, leaf, and control FDs", cmd.ExtraFiles)
	}
	request, err := parseExecArgs(cmd.Args[2:])
	if err != nil {
		t.Fatal(err)
	}
	if request.files != 1 || request.privateRootFD != 4 || request.privateLeafFD != 5 || request.controlFD != 6 || !request.landlock || !request.seccomp || !request.privateTemp {
		t.Fatalf("private temporary helper request = %+v", request)
	}
}

func TestConfigurePrivateTemporaryCommandRejectsTooManyDataFilesWithoutMutation(t *testing.T) {
	temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	temporary.child = writeEnd
	t.Cleanup(func() { _ = readEnd.Close() })
	data, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	command := exec.Command("/bin/true", "argument")
	command.Env = []string{"KEEP=original"}
	command.ExtraFiles = make([]*os.File, maxInheritedFiles+1)
	for index := range command.ExtraFiles {
		command.ExtraFiles[index] = data
	}
	originalPath := command.Path
	originalArgs := append([]string(nil), command.Args...)
	originalFiles := append([]*os.File(nil), command.ExtraFiles...)
	if err := temporary.configureCommand(command, nil); err == nil || !strings.Contains(err.Error(), "too many inherited descriptors") {
		t.Fatalf("configure command with too many data descriptors = %v", err)
	}
	if command.Path != originalPath || !reflect.DeepEqual(command.Args, originalArgs) || !reflect.DeepEqual(command.ExtraFiles, originalFiles) || !reflect.DeepEqual(command.Env, []string{"KEEP=original"}) {
		t.Fatalf("rejected command was mutated: path=%q args=%q files=%d env=%q", command.Path, command.Args, len(command.ExtraFiles), command.Env)
	}
}

func TestDetectedIdentityOnlyPolicyKeepsTemporaryHelper(t *testing.T) {
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env, _ := containerEnvironment()
	env.executable, env.executableErr = helper, nil
	policy := detect(Options{Landlock: ModeOff}, env)
	if !policy.Enforced() || policy.Restricted() || policy.temporaryHelper != helper {
		t.Fatalf("detected identity-only policy = %+v, temporary helper %q", policy.Status(), policy.temporaryHelper)
	}
	command := exec.Command("/bin/true")
	temporary, err := PreparePrivateTemporaryDirectory(context.Background(), command, policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = temporary.Close()
		if err := os.Remove(linuxTemporaryPath(t, temporary)); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove test leaf: %v", err)
		}
		if err := os.Remove(filepath.Dir(linuxTemporaryPath(t, temporary))); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove test namespace: %v", err)
		}
	})
	if !linuxTemporaryState(t, temporary).private || linuxTemporaryState(t, temporary).landlocked || linuxTemporaryState(t, temporary).leafMode != privateTemporaryMode {
		t.Fatalf("identity-only temp policy private=%v Landlock=%v leaf-mode=%#o", linuxTemporaryState(t, temporary).private, linuxTemporaryState(t, temporary).landlocked, linuxTemporaryState(t, temporary).leafMode)
	}
	if command.SysProcAttr == nil || command.SysProcAttr.Credential == nil || command.SysProcAttr.Credential.Uid != UID || command.SysProcAttr.Credential.Gid != GID || len(command.SysProcAttr.Credential.Groups) != 0 {
		t.Fatalf("identity-only helper credentials = %+v, want scanner UID/GID with no supplementary groups", command.SysProcAttr)
	}
	if !slices.Contains(command.Args, "--private-tmp") || slices.Contains(command.Args, "--landlock") {
		t.Fatalf("identity-only helper arguments = %q", command.Args)
	}
}

func TestParsePrivateTemporaryCleanupArgsUsesExactHelperArgvCount(t *testing.T) {
	args := []string{"--device", "1", "--inode", "2", "--leaf-uid", strconv.Itoa(os.Geteuid()), "--leaf-gid", strconv.Itoa(os.Getegid()), "--uid", "65532", "--gid", "65532", "--landlock"}
	request, err := parsePrivateTemporaryCleanupArgs(args)
	if err != nil {
		t.Fatalf("parse valid cleanup argv (%d values): %v", len(args), err)
	}
	if request.device != 1 || request.inode != 2 || request.leafUID != uint32(os.Geteuid()) || request.leafGID != uint32(os.Getegid()) || request.uid != UID || request.gid != GID || !request.landlock {
		t.Fatalf("cleanup request = %+v", request)
	}

	for name, invalid := range map[string][]string{
		"missing final pair":          args[:len(args)-3],
		"extra pair":                  append(append([]string(nil), args...), "--extra", "value"),
		"unknown instead of required": {"--device", "1", "--inode", "2", "--leaf-uid", "0", "--leaf-gid", "0", "--uid", "65532", "--other", "65532"},
		"duplicate key":               {"--device", "1", "--device", "1", "--inode", "2", "--leaf-uid", "0", "--leaf-gid", "0", "--uid", "65532", "--gid", "65532"},
		"missing option value":        {"--device"},
		"positional argument":         {"unexpected"},
		"invalid number":              {"--device", "x", "--inode", "2", "--leaf-uid", "0", "--leaf-gid", "0", "--uid", "65532", "--gid", "65532"},
		"overflowing identity":        {"--device", "1", "--inode", "2", "--leaf-uid", "4294967296", "--leaf-gid", "0", "--uid", "65532", "--gid", "65532"},
		"duplicate Landlock flag":     append(append([]string(nil), args...), "--landlock"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePrivateTemporaryCleanupArgs(invalid); err == nil || !strings.Contains(err.Error(), "usage: sandbox-exec --cleanup-private-tmp") {
				t.Fatalf("parse invalid cleanup argv (%d values) = %v, want usage error", len(invalid), err)
			}
		})
	}
}

func TestPrivateTemporaryAPIsRejectNilAndPreCancelledContexts(t *testing.T) {
	command := exec.Command("/bin/true")
	var nilContext context.Context
	if _, err := PreparePrivateTemporaryDirectory(nilContext, command, nil); err == nil {
		t.Fatal("prepare accepted a nil context")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PreparePrivateTemporaryDirectory(cancelled, command, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("prepare with a cancelled context = %v, want context.Canceled", err)
	}
	if len(command.Env) != 0 {
		t.Fatalf("cancelled preparation modified the environment: %q", command.Env)
	}

	temporary, err := PreparePrivateTemporaryDirectory(context.Background(), command, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer temporary.Close()
	if err := temporary.WaitReady(nilContext); err == nil {
		t.Fatal("readiness accepted a nil context")
	}
	if err := temporary.Cleanup(nilContext); err == nil {
		t.Fatal("cleanup accepted a nil context")
	}
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup after nil-context rejection: %v", err)
	}
}

func TestPrivateTemporaryPreparationRejectsMissingScannerBeforeStart(t *testing.T) {
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/path/that/does/not/exist/edgewatch-scanner")
	policy := (*Policy)(nil).WithLandlock(helper, 6)
	if _, err := PreparePrivateTemporaryDirectory(context.Background(), command, policy); err == nil || !strings.Contains(err.Error(), "scanner executable is unavailable") {
		t.Fatalf("prepare missing scanner = %v, want executable error", err)
	}
	if command.Process != nil {
		t.Fatal("missing scanner unexpectedly started")
	}
	if len(command.Env) != 0 {
		t.Fatalf("missing scanner preparation modified the environment: %q", command.Env)
	}
}

func TestLinuxPrivateTemporaryPreparationRejectsInvalidInputsBeforeCreatingDirectories(t *testing.T) {
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	scannerPolicy := (*Policy)(nil).WithLandlock(helper, 6)
	cases := []struct {
		name   string
		cmd    *exec.Cmd
		policy *Policy
	}{
		{name: "nil command", policy: scannerPolicy},
		{name: "empty command path", cmd: &exec.Cmd{Args: []string{"/bin/true"}}, policy: scannerPolicy},
		{name: "empty command arguments", cmd: &exec.Cmd{Path: "/bin/true"}, policy: scannerPolicy},
		{name: "required helper unavailable", cmd: exec.Command("/bin/true"), policy: NewEnforced()},
		{name: "helper belongs to another profile", cmd: exec.Command("/bin/true"), policy: NewEnforcedFor(Notifier).WithLandlock(helper, 6)},
		{name: "relative helper path", cmd: exec.Command("/bin/true"), policy: &Policy{profile: Scanner, helper: "edgewatch"}},
		{name: "command already has an executable error", cmd: &exec.Cmd{Path: "/bin/true", Args: []string{"/bin/true"}, Err: errors.New("saved lookup error")}, policy: scannerPolicy},
		{name: "scanner path does not exist", cmd: &exec.Cmd{Path: "/no/such/edgewatch-scanner", Args: []string{"/no/such/edgewatch-scanner"}}, policy: scannerPolicy},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			filesystem := realPrivateTemporaryFilesystemOps()
			mkdirCalls := 0
			filesystem.mkdirat = func(int, string, uint32) error {
				mkdirCalls++
				return unix.EIO
			}
			command := test.cmd
			if command != nil {
				command.Env = []string{"TMPDIR=/original", "TMPDIR=/duplicate"}
			}
			if _, err := prepareLinuxPrivateTemporaryDirectoryWithFilesystem(context.Background(), command, test.policy, filesystem); err == nil {
				t.Fatal("invalid preparation input was accepted")
			}
			if mkdirCalls != 0 {
				t.Fatalf("invalid preparation attempted %d namespace creations", mkdirCalls)
			}
			if command != nil {
				if command.Process != nil {
					t.Fatal("invalid preparation started a process")
				}
				if !reflect.DeepEqual(command.Env, []string{"TMPDIR=/original", "TMPDIR=/duplicate"}) {
					t.Fatalf("invalid preparation changed the command environment: %q", command.Env)
				}
			}
		})
	}
}

func TestLinuxPrivateTemporaryPreparationCleansAfterCancellationAtEachSetupBoundary(t *testing.T) {
	for _, cancelAt := range []int{2, 3} {
		name := "after namespace"
		if cancelAt == 3 {
			name = "after leaf pin"
		}
		t.Run(name, func(t *testing.T) {
			filesystem := realPrivateTemporaryFilesystemOps()
			created := recordSuccessfulPrivateTemporaryMkdirs(t, &filesystem)
			createdAtCancel := 0
			ctx, cancel := context.WithCancel(context.Background())
			checked := &cancelAfterErrChecks{Context: ctx, cancel: cancel, cancelAt: cancelAt}
			checked.onCancel = func() {
				createdAtCancel = len(*created)
				assertPrivateTemporaryEntriesExist(t, *created)
			}
			command := exec.Command("/bin/true")
			command.Env = []string{"TMPDIR=/original"}
			if _, err := prepareLinuxPrivateTemporaryDirectoryWithFilesystem(checked, command, nil, filesystem); !errors.Is(err, context.Canceled) {
				t.Fatalf("preparation error = %v, want context.Canceled", err)
			}
			if checked.checks != cancelAt {
				t.Fatalf("context checks = %d, want cancellation at check %d", checked.checks, cancelAt)
			}
			if want := cancelAt - 1; createdAtCancel != want {
				t.Fatalf("cancel observed %d owned setup entries, want %d", createdAtCancel, want)
			}
			if !reflect.DeepEqual(command.Env, []string{"TMPDIR=/original"}) || command.Process != nil {
				t.Fatalf("cancelled preparation changed or started the command: env=%q process=%v", command.Env, command.Process)
			}
			assertPrivateTemporaryEntriesAbsent(t, created)
		})
	}
}

type cancelAfterErrChecks struct {
	context.Context
	cancel   context.CancelFunc
	cancelAt int
	checks   int
	onCancel func()
}

func (ctx *cancelAfterErrChecks) Err() error {
	ctx.checks++
	if ctx.checks == ctx.cancelAt {
		if ctx.onCancel != nil {
			ctx.onCancel()
		}
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestPrivateTemporaryCleanupValidatorRejectsMismatchedOwnerAndIdentity(t *testing.T) {
	temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
	var stat unix.Stat_t
	if err := unix.Fstat(int(temporary.leaf.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	request := privateTemporaryCleanupRequest{
		device: uint64(stat.Dev), inode: stat.Ino, leafUID: stat.Uid, leafGID: stat.Gid,
		uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()),
	}
	cases := []struct {
		name   string
		mutate func(*privateTemporaryCleanupRequest)
	}{
		{name: "wrong process uid", mutate: func(request *privateTemporaryCleanupRequest) { request.uid++ }},
		{name: "wrong process gid", mutate: func(request *privateTemporaryCleanupRequest) { request.gid++ }},
		{name: "wrong device", mutate: func(request *privateTemporaryCleanupRequest) { request.device++ }},
		{name: "wrong inode", mutate: func(request *privateTemporaryCleanupRequest) { request.inode++ }},
		{name: "wrong leaf uid", mutate: func(request *privateTemporaryCleanupRequest) { request.leafUID++ }},
		{name: "wrong leaf gid", mutate: func(request *privateTemporaryCleanupRequest) { request.leafGID++ }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			invalid := request
			test.mutate(&invalid)
			if err := cleanupPrivateTemporaryDirectoryFD(invalid, int(temporary.leaf.Fd())); err == nil {
				t.Fatal("cleanup accepted a mismatched identity")
			}
		})
	}
	if err := cleanupPrivateTemporaryDirectoryFD(request, -1); err == nil {
		t.Fatal("cleanup accepted an invalid leaf descriptor")
	}
	if err := cleanupPrivateTemporaryDirectoryFD(request, int(temporary.leaf.Fd())); err != nil {
		t.Fatalf("valid cleanup request failed after rejected cases: %v", err)
	}
}

func TestPrivateTemporaryLandlockRightsAreScopedToTheLeaf(t *testing.T) {
	requireLandlock(t)
	rootPath, err := os.MkdirTemp("/tmp", "edgewatch-private-tmp-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(rootPath)
	if err := os.Chmod(rootPath, privateNamespaceMode); err != nil {
		t.Fatal(err)
	}
	leafPath := filepath.Join(rootPath, "leaf")
	if err := os.Mkdir(leafPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(leafPath, privateTemporaryMode); err != nil {
		t.Fatal(err)
	}
	leafFD, err := unix.Open(leafPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(leafFD)
	leafExecutable := filepath.Join(leafPath, "scanner-written-executable")
	if err := os.WriteFile(leafExecutable, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(leafExecutable, 0o700); err != nil {
		t.Fatal(err)
	}
	outsidePath := filepath.Join("/tmp", "edgewatch-private-tmp-escape-test")
	_ = os.Remove(outsidePath)
	defer os.Remove(outsidePath)
	if err := os.WriteFile(outsidePath, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	rootSibling := filepath.Join(rootPath, "sibling")
	results := make(chan map[string]error, 1)
	go func() {
		runtime.LockOSThread()
		if err := restrictPrivateTemporary(execRequest{profile: Scanner, landlock: true}, leafFD); err != nil {
			results <- map[string]error{"restrict": err}
			return
		}
		insidePath := filepath.Join(leafPath, "probe")
		writeInsideErr := os.WriteFile(insidePath, []byte("ok"), 0o600)
		readLeafErr := func() error { _, err := os.ReadDir(leafPath); return err }()
		executeLeafErr := exec.Command(leafExecutable).Run()
		_, readOutsideErr := os.ReadFile(outsidePath)
		_, readTmpErr := os.ReadDir("/tmp")
		_, readRootErr := os.ReadDir(rootPath)
		writeRootErr := os.WriteFile(rootSibling, []byte("outside"), 0o600)
		results <- map[string]error{
			"inside":       writeInsideErr,
			"read-leaf":    readLeafErr,
			"execute-leaf": executeLeafErr,
			"outside":      readOutsideErr,
			"tmp":          readTmpErr,
			"root":         readRootErr,
			"sibling":      writeRootErr,
		}
	}()
	got := <-results
	if err := got["restrict"]; err != nil {
		t.Fatal(err)
	}
	if err := got["inside"]; err != nil {
		t.Errorf("write in the invocation leaf: %v", err)
	}
	if err := got["read-leaf"]; err != nil {
		t.Errorf("list invocation leaf required by hmap: %v", err)
	}
	if !errors.Is(got["execute-leaf"], unix.EACCES) {
		t.Errorf("execute scanner-created leaf file = %v, want Landlock denial", got["execute-leaf"])
	}
	for _, denied := range []string{"outside", "tmp", "root", "sibling"} {
		if !errors.Is(got[denied], unix.EACCES) {
			t.Errorf("%s access = %v, want Landlock denial", denied, got[denied])
		}
	}
}

func TestPrivateTemporaryLandlockSupportsNestedHMapArtifactsAndCleansThem(t *testing.T) {
	abi := requireLandlock(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := (*Policy)(nil).WithLandlock(helper, abi)
	command := exec.Command("/bin/sh", "-c", `
set -eu
umask 077
ls "$TMPDIR" >/dev/null
mkdir -p "$TMPDIR/ipranger-map/leveldb"
printf 'manifest\n' > "$TMPDIR/ipranger-map/leveldb/MANIFEST-000001"
printf 'table-data\n' > "$TMPDIR/ipranger-map/leveldb/000002.ldb"
printf 'manifest-000001\n' > "$TMPDIR/ipranger-map/leveldb/CURRENT.tmp"
mv "$TMPDIR/ipranger-map/leveldb/CURRENT.tmp" "$TMPDIR/ipranger-map/leveldb/CURRENT"
test "$(cat "$TMPDIR/ipranger-map/leveldb/MANIFEST-000001")" = manifest
test "$(cat "$TMPDIR/ipranger-map/leveldb/000002.ldb")" = table-data
`)
	command.Env = []string{"PATH=/bin:/usr/bin", "HOME=/nonexistent"}
	process := startPrivateTemporaryTestProcess(t, policy, command)
	if err := process.wait(); err != nil {
		t.Fatalf("create nested hmap/LevelDB-compatible artifacts: %v", err)
	}
	levelDBPath := filepath.Join(linuxTemporaryPath(t, process.temporary), "ipranger-map", "leveldb")
	entries, err := os.ReadDir(levelDBPath)
	if err != nil || len(entries) != 3 {
		t.Fatalf("nested artifacts = %v, %v; want manifest, table, and current marker", entries, err)
	}
	if err := process.cleanup(); err != nil {
		t.Fatalf("clean nested hmap/LevelDB-compatible artifacts: %v", err)
	}
	if _, err := os.Stat(linuxTemporaryPath(t, process.temporary)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private temporary leaf remains after nested cleanup: %v", err)
	}
}

func TestDetectedIdentityOnlyPolicyUsesHelperAndCleansNestedArtifacts(t *testing.T) {
	env := systemEnvironment()
	if env.euid != 0 || env.effective&(1<<unix.CAP_SETUID) == 0 || env.effective&(1<<unix.CAP_SETGID) == 0 {
		t.Skip("the test runtime cannot start a child as the scanner identity")
	}
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env.executable, env.executableErr = helper, nil
	env.landlockErr = unix.ENOSYS
	env.run = func(*Policy, []string, []string) error { return nil }
	policy := detect(Options{Landlock: ModeOff}, env)
	if !policy.Enforced() || policy.Restricted() || policy.temporaryHelper != helper {
		t.Fatalf("identity-only detected policy = %+v, helper %q", policy.Status(), policy.temporaryHelper)
	}

	var inheritedLimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &inheritedLimit); err != nil {
		t.Fatal(err)
	}
	wantOpenFiles := min(inheritedLimit.Cur, min(inheritedLimit.Max, ScannerMaxOpenFiles))
	command := exec.Command("/bin/sh", "-c", `set -eu
id -u > "$TMPDIR/uid"
ulimit -n > "$TMPDIR/nofile-limit"
mkdir -p "$TMPDIR/ipranger-map/leveldb"
printf 'manifest\n' > "$TMPDIR/ipranger-map/leveldb/MANIFEST-000001"
`)
	command.Env = []string{"PATH=/bin:/usr/bin", "HOME=/nonexistent"}
	temporary, err := PreparePrivateTemporaryDirectory(context.Background(), command, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer temporary.Close()
	if linuxTemporaryState(t, temporary).landlocked || linuxTemporaryState(t, temporary).leafMode != privateTemporaryMode {
		t.Fatalf("identity-only temporary policy landlocked=%v leaf-mode=%#o", linuxTemporaryState(t, temporary).landlocked, linuxTemporaryState(t, temporary).leafMode)
	}
	if err := command.Start(); err != nil {
		_ = temporary.Cleanup(context.Background())
		t.Fatalf("start identity-only helper: %v", err)
	}
	if err := temporary.Started(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = temporary.Cleanup(context.Background())
		t.Fatal(err)
	}
	if err := temporary.WaitReady(context.Background()); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = temporary.Cleanup(context.Background())
		t.Fatalf("wait for identity-only helper: %v", err)
	}
	if err := command.Wait(); err != nil {
		_ = temporary.Cleanup(context.Background())
		t.Fatalf("identity-only scanner process: %v", err)
	}
	uid, err := os.ReadFile(filepath.Join(linuxTemporaryPath(t, temporary), "uid"))
	if err != nil || strings.TrimSpace(string(uid)) != strconv.Itoa(UID) {
		t.Fatalf("scanner uid = %q, %v; want %d", uid, err, UID)
	}
	openFiles, err := os.ReadFile(filepath.Join(linuxTemporaryPath(t, temporary), "nofile-limit"))
	if err != nil {
		t.Fatalf("read scanner file descriptor limit: %v", err)
	}
	gotOpenFiles, err := strconv.ParseUint(strings.TrimSpace(string(openFiles)), 10, 64)
	if err != nil || gotOpenFiles != wantOpenFiles {
		t.Fatalf("scanner open file limit = %q, %v; want %d", openFiles, err, wantOpenFiles)
	}
	if _, err := os.Stat(filepath.Join(linuxTemporaryPath(t, temporary), "ipranger-map", "leveldb", "MANIFEST-000001")); err != nil {
		t.Fatalf("identity-only nested artifact missing: %v", err)
	}
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("clean identity-only nested artifacts: %v", err)
	}
	if _, err := os.Stat(linuxTemporaryPath(t, temporary)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity-only temporary directory remains: %v", err)
	}
}

func TestIdentityOnlyScannerProcFDAccessIsHostDependent(t *testing.T) {
	env := systemEnvironment()
	if env.euid != 0 || env.effective&(1<<unix.CAP_SETUID) == 0 || env.effective&(1<<unix.CAP_SETGID) == 0 || env.effective&(1<<unix.CAP_KILL) == 0 {
		t.Skip("the test runtime cannot start and clean up scanner-identity children")
	}
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env.executable, env.executableErr = helper, nil
	env.landlockErr = unix.ENOSYS
	env.run = func(*Policy, []string, []string) error { return nil }
	policy := detect(Options{Landlock: ModeOff}, env)
	if !policy.Enforced() || policy.Restricted() || policy.temporaryHelper != helper {
		t.Fatalf("identity-only scanner policy = %+v, helper %q", policy.Status(), policy.temporaryHelper)
	}

	privateDir := t.TempDir()
	if err := os.Chmod(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(privateDir, "targets")
	if err := os.WriteFile(targetPath, []byte("another-unit.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := os.Open(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	defer targets.Close()

	xmlPath := filepath.Join(privateDir, "nmap.xml")
	if err := os.WriteFile(xmlPath, []byte("original XML\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	xmlOutput, err := os.OpenFile(xmlPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer xmlOutput.Close()

	targetCommand := exec.Command(helper, privateTemporaryProcFDCheck)
	targetCommand.Env = []string{"PATH=/bin:/usr/bin", "HOME=/nonexistent"}
	if _, err := policy.InheritFile(targetCommand, targets, Read); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.InheritFile(targetCommand, xmlOutput, Write); err != nil {
		t.Fatal(err)
	}
	targetOutput, err := targetCommand.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	targetInput, err := targetCommand.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	target := startPrivateTemporaryTestProcess(t, policy, targetCommand)
	ready := make(chan struct {
		line string
		err  error
	}, 1)
	go func() {
		line, err := bufio.NewReader(targetOutput).ReadString('\n')
		ready <- struct {
			line string
			err  error
		}{line: line, err: err}
	}()
	var targetIdentity string
	select {
	case result := <-ready:
		if result.err != nil {
			t.Fatalf("read identity-only scanner state: %v", result.err)
		}
		targetIdentity = result.line
	case <-time.After(5 * time.Second):
		t.Fatal("identity-only scanner did not report its process state")
	}
	var uid, gid, dumpable, targetAccess, xmlAccess int
	if n, err := fmt.Sscanf(targetIdentity, "uid=%d gid=%d dumpable=%d target-access=%d xml-access=%d", &uid, &gid, &dumpable, &targetAccess, &xmlAccess); err != nil || n != 5 {
		t.Fatalf("scanner process state = %q, parsed %d fields: %v", targetIdentity, n, err)
	}
	if uid != UID || gid != GID || dumpable < 0 || dumpable > 2 || targetAccess != unix.O_RDONLY || xmlAccess != unix.O_WRONLY {
		t.Fatalf("scanner process state = %q, want identity %d:%d and read/write-only descriptors", targetIdentity, UID, GID)
	}

	peerScript := strings.Join([]string{
		"set +e",
		`id -u > "$TMPDIR/peer-uid"`,
		`cat "$TARGET_PATH" > "$TMPDIR/by-name.out" 2> "$TMPDIR/by-name.err"; by_name=$?`,
		`cat "/proc/$OTHER_PID/fd/3" > "$TMPDIR/proc-target.out" 2> "$TMPDIR/proc-target.err"; proc_target=$?`,
		`(printf 'forged XML\n' > "/proc/$OTHER_PID/fd/4") 2> "$TMPDIR/proc-xml.err"; proc_xml=$?`,
		`printf '%s %s %s\n' "$by_name" "$proc_target" "$proc_xml"`,
	}, "\n")
	peerCommand := exec.Command("/bin/sh", "-c", peerScript)
	peerCommand.Env = []string{
		"PATH=/bin:/usr/bin", "HOME=/nonexistent",
		"TARGET_PATH=" + targetPath,
		"OTHER_PID=" + strconv.Itoa(targetCommand.Process.Pid),
	}
	var peerOutput bytes.Buffer
	peerCommand.Stdout = &peerOutput
	peer := startPrivateTemporaryTestProcess(t, policy, peerCommand)
	if err := peer.wait(); err != nil {
		t.Fatalf("identity-only peer probe: %v", err)
	}
	statuses := strings.Fields(peerOutput.String())
	if len(statuses) != 3 {
		t.Fatalf("peer access statuses = %q, want three exit codes", peerOutput.String())
	}
	byNameStatus, err := strconv.Atoi(statuses[0])
	if err != nil || byNameStatus == 0 {
		t.Fatalf("peer opened target by path: status %q, err %v", statuses[0], err)
	}
	byNameErr, err := os.ReadFile(filepath.Join(linuxTemporaryPath(t, peer.temporary), "by-name.err"))
	if err != nil || !procFDPermissionDenied(byNameErr) {
		t.Fatalf("target pathname denial = %q, %v; want an OS permission denial", byNameErr, err)
	}
	peerUID, err := os.ReadFile(filepath.Join(linuxTemporaryPath(t, peer.temporary), "peer-uid"))
	if err != nil || strings.TrimSpace(string(peerUID)) != strconv.Itoa(UID) {
		t.Fatalf("peer UID = %q, %v; want %d", peerUID, err, UID)
	}

	procTargetStatus, err := strconv.Atoi(statuses[1])
	if err != nil {
		t.Fatalf("parse proc target status %q: %v", statuses[1], err)
	}
	procXMLStatus, err := strconv.Atoi(statuses[2])
	if err != nil {
		t.Fatalf("parse proc XML status %q: %v", statuses[2], err)
	}
	procTargetErr, err := os.ReadFile(filepath.Join(linuxTemporaryPath(t, peer.temporary), "proc-target.err"))
	if err != nil {
		t.Fatal(err)
	}
	procXMLErr, err := os.ReadFile(filepath.Join(linuxTemporaryPath(t, peer.temporary), "proc-xml.err"))
	if err != nil {
		t.Fatal(err)
	}
	if procTargetStatus == 0 {
		got, err := os.ReadFile(filepath.Join(linuxTemporaryPath(t, peer.temporary), "proc-target.out"))
		if err != nil || string(got) != "another-unit.example\n" {
			t.Fatalf("proc-fd target contents = %q, %v", got, err)
		}
	} else if !procFDPermissionDenied(procTargetErr) {
		t.Fatalf("proc-fd target read failed for an unexpected reason: %q", procTargetErr)
	}
	gotXML, err := os.ReadFile(xmlPath)
	if err != nil {
		t.Fatal(err)
	}
	if procXMLStatus == 0 {
		if string(gotXML) != "forged XML\n" {
			t.Fatalf("proc-fd XML write status succeeded but contents are %q", gotXML)
		}
	} else {
		if !procFDPermissionDenied(procXMLErr) {
			t.Fatalf("proc-fd XML write failed for an unexpected reason: %q", procXMLErr)
		}
		if string(gotXML) != "original XML\n" {
			t.Fatalf("denied proc-fd XML write changed contents to %q", gotXML)
		}
	}
	t.Logf("identity-only same-UID helper: %s; pathname access denied; proc target read status=%d (%q), XML write status=%d (%q)", strings.TrimSpace(targetIdentity), procTargetStatus, strings.TrimSpace(string(procTargetErr)), procXMLStatus, strings.TrimSpace(string(procXMLErr)))
	if err := peer.cleanup(); err != nil {
		t.Fatalf("clean identity-only peer: %v", err)
	}
	if err := targetInput.Close(); err != nil {
		t.Fatal(err)
	}
	if err := target.wait(); err != nil {
		t.Fatalf("identity-only scanner helper: %v", err)
	}
	if err := target.cleanup(); err != nil {
		t.Fatalf("clean identity-only scanner: %v", err)
	}
}

func procFDPermissionDenied(message []byte) bool {
	message = bytes.ToLower(message)
	return bytes.Contains(message, []byte("permission denied")) ||
		bytes.Contains(message, []byte("operation not permitted")) ||
		bytes.Contains(message, []byte("no such file or directory"))
}

func TestConcurrentPrivateTemporaryHelpersCannotOpenSiblingOrProcFD(t *testing.T) {
	abi := requireLandlock(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := (*Policy)(nil).WithLandlock(helper, abi)
	targetPath := filepath.Join(t.TempDir(), "targets")
	if err := os.WriteFile(targetPath, []byte("target.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := os.Open(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	defer targets.Close()

	firstCommand := exec.Command("/bin/sh", "-c", `
IFS= read -r target < /dev/fd/3 || exit 31
[ "$target" = target.example ] || exit 32
printf '%s\n' private-data > "$TMPDIR/secret"
exec 8<"$TMPDIR/secret"
printf 'ready\n'
IFS= read -r _
`)
	firstCommand.Env = []string{"PATH=/bin:/usr/bin", "HOME=/nonexistent"}
	firstCommand.ExtraFiles = []*os.File{targets}
	firstOutput, err := firstCommand.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	firstInput, err := firstCommand.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	first := startPrivateTemporaryTestProcess(t, policy, firstCommand)
	line := make(chan struct {
		value string
		err   error
	}, 1)
	go func() {
		value, err := bufio.NewReader(firstOutput).ReadString('\n')
		line <- struct {
			value string
			err   error
		}{value: value, err: err}
	}()
	select {
	case ready := <-line:
		if ready.err != nil || ready.value != "ready\n" {
			t.Fatalf("first scanner readiness = %q, %v", ready.value, ready.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first scanner did not become ready")
	}
	if got, err := os.ReadFile(filepath.Join(linuxTemporaryPath(t, first.temporary), "secret")); err != nil || string(got) != "private-data\n" {
		t.Fatalf("first scanner temporary output = %q, %v", got, err)
	}
	for _, descriptor := range []string{"4", "5", "6"} {
		path := filepath.Join("/proc", strconv.Itoa(first.command.Process.Pid), "fd", descriptor)
		if target, err := os.Readlink(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("control descriptor %s survived scanner exec as %q (%v)", descriptor, target, err)
		}
	}

	secondCommand := exec.Command("/bin/sh", "-c", `
if IFS= read -r _ < "$OTHER_TMPDIR/secret" 2>/dev/null; then echo direct-open; else echo direct-denied; fi
if IFS= read -r _ < "/proc/$OTHER_PID/fd/8" 2>/dev/null; then echo proc-fd-open; else echo proc-fd-denied; fi
if /bin/ls /tmp >/dev/null 2>&1; then echo tmp-list; else echo tmp-denied; fi
if /bin/ls "$OTHER_NAMESPACE" >/dev/null 2>&1; then echo namespace-list; else echo namespace-denied; fi
`)
	secondCommand.Env = []string{
		"PATH=/bin:/usr/bin", "HOME=/nonexistent",
		"OTHER_TMPDIR=" + linuxTemporaryPath(t, first.temporary),
		"OTHER_NAMESPACE=/tmp/" + linuxTemporaryState(t, first.temporary).namespaceName,
		"OTHER_PID=" + strconv.Itoa(first.command.Process.Pid),
	}
	var secondOutput bytes.Buffer
	secondCommand.Stdout = &secondOutput
	second := startPrivateTemporaryTestProcess(t, policy, secondCommand)
	if err := second.wait(); err != nil {
		t.Fatalf("second scanner helper: %v", err)
	}
	if err := second.cleanup(); err != nil {
		t.Fatalf("clean second invocation: %v", err)
	}
	want := "direct-denied\nproc-fd-denied\ntmp-denied\nnamespace-denied\n"
	if got := secondOutput.String(); got != want {
		t.Fatalf("second scanner access checks = %q, want %q", got, want)
	}
	if _, err := firstInput.Write([]byte("continue\n")); err != nil {
		t.Fatal(err)
	}
	if err := first.wait(); err != nil {
		t.Fatalf("first scanner helper: %v", err)
	}
	if err := first.cleanup(); err != nil {
		t.Fatalf("clean first invocation: %v", err)
	}
	if _, err := os.Stat(linuxTemporaryPath(t, first.temporary)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first temporary directory remains after cleanup: %v", err)
	}
}

func TestPrivateTemporaryCleanupAfterCancellationDoesNotFollowSymlinks(t *testing.T) {
	abi := requireLandlock(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := (*Policy)(nil).WithLandlock(helper, abi)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", `
printf 'private-data\n' > "$TMPDIR/payload"
printf 'ready\n'
IFS= read -r _
`)
	command.Env = []string{"PATH=/bin:/usr/bin", "HOME=/nonexistent"}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	process := startPrivateTemporaryTestProcess(t, policy, command)
	ready, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || ready != "ready\n" {
		t.Fatalf("cancelled scanner readiness = %q, %v", ready, err)
	}
	leafPath := linuxTemporaryPath(t, process.temporary)
	if got, err := os.ReadFile(filepath.Join(leafPath, "payload")); err != nil || string(got) != "private-data\n" {
		t.Fatalf("payload before cancellation = %q, %v", got, err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("must survive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(leafPath, "link-outside")); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := process.wait(); err == nil {
		t.Fatal("cancelled helper unexpectedly exited successfully")
	}
	if err := process.cleanup(); err != nil {
		t.Fatalf("clean cancelled scanner temporary directory: %v", err)
	}
	if _, err := os.Stat(leafPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary directory remains after cancellation: %v", err)
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != "must survive" {
		t.Fatalf("cleanup followed a symlink outside the leaf: %q, %v", got, err)
	}
}

func TestParentCreatesAndPinsStickyLeafBeforeChildStart(t *testing.T) {
	abi := requireLandlock(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := (*Policy)(nil).WithLandlock(helper, abi)
	command := exec.Command("/bin/true")
	temporary, err := PreparePrivateTemporaryDirectory(context.Background(), command, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer temporary.Close()
	var pinned, named unix.Stat_t
	if err := unix.Fstat(int(linuxTemporaryState(t, temporary).leaf.Fd()), &pinned); err != nil {
		t.Fatal(err)
	}
	if pinned.Mode != unix.S_IFDIR|privateTemporaryMode || pinned.Uid != uint32(os.Geteuid()) || pinned.Gid != uint32(os.Getegid()) {
		t.Fatalf("parent-created leaf stat = mode %#o uid %d gid %d", pinned.Mode, pinned.Uid, pinned.Gid)
	}
	if err := unix.Fstatat(int(linuxTemporaryState(t, temporary).namespace.Fd()), linuxTemporaryState(t, temporary).name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&pinned, &named) || named.Mode != pinned.Mode {
		t.Fatalf("pinned leaf entry = %+v, %v", named, err)
	}
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("clean parent-created empty leaf: %v", err)
	}
	if _, err := os.Stat(linuxTemporaryPath(t, temporary)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("parent-created temporary leaf remains: %v", err)
	}
}

func TestParentLeafCreationDoesNotAdoptOrRemoveCollision(t *testing.T) {
	abi := requireLandlock(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := (*Policy)(nil).WithLandlock(helper, abi)
	temporary, err := PreparePrivateTemporaryDirectory(context.Background(), exec.Command("/bin/true"), policy)
	if err != nil {
		t.Fatal(err)
	}
	defer temporary.Close()
	originalName := linuxTemporaryState(t, temporary).name
	collision := privateTemporaryPrefix + strings.Repeat("a", 32)
	if err := unix.Mkdirat(int(linuxTemporaryState(t, temporary).namespace.Fd()), collision, 0o700); err != nil {
		t.Fatal(err)
	}
	collisionFD, err := unix.Openat(int(linuxTemporaryState(t, temporary).namespace.Fd()), collision, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(collisionFD)
	if err := unix.Mkdirat(collisionFD, "owned-by-other", 0o700); err != nil {
		t.Fatal(err)
	}
	linuxTemporaryState(t, temporary).name = collision
	if err := linuxTemporaryState(t, temporary).createLeafNamed(); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("create colliding leaf = %v, want EEXIST", err)
	}
	var found unix.Stat_t
	if err := unix.Fstatat(int(linuxTemporaryState(t, temporary).namespace.Fd()), collision, &found, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatalf("colliding entry was removed: %v", err)
	}
	if found.Mode != unix.S_IFDIR|0o700 || found.Uid != uint32(os.Geteuid()) || found.Gid != uint32(os.Getegid()) {
		t.Fatalf("colliding entry changed unexpectedly: mode=%#o", found.Mode)
	}
	if err := unix.Unlinkat(collisionFD, "owned-by-other", unix.AT_REMOVEDIR); err != nil {
		t.Fatal(err)
	}
	if err := unix.Unlinkat(int(linuxTemporaryState(t, temporary).namespace.Fd()), collision, unix.AT_REMOVEDIR); err != nil {
		t.Fatal(err)
	}
	linuxTemporaryState(t, temporary).name = originalName
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup parent-owned invocation leaf: %v", err)
	}
}

func TestPrivateTemporaryStartupFailureBeforeAckReclaimsLeaf(t *testing.T) {
	abi := requireLandlock(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := (*Policy)(nil).WithLandlock(helper, abi)
	command := exec.Command("/bin/sh", "-c", `printf launched > "$TMPDIR/started"; sleep 30`)
	command.Env = []string{"PATH=/bin:/usr/bin", "HOME=/nonexistent"}
	temporary, err := PreparePrivateTemporaryDirectory(context.Background(), command, policy)
	if err != nil {
		t.Fatal(err)
	}
	var waited bool
	t.Cleanup(func() {
		if !waited && command.Process != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		if err := temporary.Cleanup(context.Background()); err != nil {
			t.Errorf("clean pre-ack scanner startup: %v", err)
		}
		_ = temporary.Close()
	})
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Started(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		waited = true
		t.Fatal(err)
	}
	// The parent-owned leaf exists before helper startup. Wait for readiness,
	// then close the channel before ACK so the scanner executable cannot run.
	poll := []unix.PollFd{{Fd: int32(linuxTemporaryState(t, temporary).parent.Fd()), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
	deadline := time.Now().Add(5 * time.Second)
	for poll[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) == 0 {
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_ = command.Wait()
			waited = true
			t.Fatal("helper did not reach readiness")
		}
		_, err := unix.Poll(poll, 10)
		if err != nil && !errors.Is(err, unix.EINTR) {
			t.Fatal(err)
		}
	}
	if err := linuxTemporaryState(t, temporary).parent.Close(); err != nil {
		t.Fatal(err)
	}
	linuxTemporaryState(t, temporary).parent = nil
	if err := command.Wait(); err == nil {
		t.Fatal("helper unexpectedly started the scanner without a parent ACK")
	}
	waited = true
	if _, err := os.Stat(filepath.Join(linuxTemporaryPath(t, temporary), "started")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scanner executable ran before parent ACK: %v", err)
	}
	entries, err := os.ReadDir(linuxTemporaryPath(t, temporary))
	if err != nil || len(entries) != 0 {
		t.Fatalf("pre-ack leaf contents = %v, %v; want empty", entries, err)
	}
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("recover leaf after readiness failure: %v", err)
	}
	if _, err := os.Stat(linuxTemporaryPath(t, temporary)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed-start temporary leaf remains: %v", err)
	}
}

func TestParentPinnedLeafReclaimsWhenHelperDiesBeforeInitialization(t *testing.T) {
	abi := requireLandlock(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := (*Policy)(nil).WithLandlock(helper, abi)
	command := exec.Command("/bin/sh", "-c", `printf scanner-ran > "$TMPDIR/started"`)
	command.Env = []string{"PATH=/bin:/usr/bin", "HOME=/nonexistent"}
	temporary, err := PreparePrivateTemporaryDirectory(context.Background(), command, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer temporary.Close()
	if err := command.Start(); err != nil {
		_ = temporary.Cleanup(context.Background())
		t.Fatal(err)
	}
	if err := command.Process.Kill(); err != nil {
		_ = command.Wait()
		_ = temporary.Cleanup(context.Background())
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("helper unexpectedly survived termination before initialization")
	}
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup parent-pinned leaf after helper death: %v", err)
	}
	if _, err := os.Stat(filepath.Join(linuxTemporaryPath(t, temporary), "started")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scanner ran before helper initialization: %v", err)
	}
	if _, err := os.Stat(linuxTemporaryPath(t, temporary)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("leaf remains after pre-initialization helper death: %v", err)
	}
	if _, err := os.Stat(filepath.Join("/tmp", linuxTemporaryState(t, temporary).namespaceName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("namespace remains after pre-initialization helper death: %v", err)
	}
}

func TestPrivateTemporaryReadinessHonorsCancellation(t *testing.T) {
	abi := requireLandlock(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := (*Policy)(nil).WithLandlock(helper, abi)
	command := exec.Command("/bin/sh", "-c", `printf scanner-ran > "$TMPDIR/started"`)
	command.Env = []string{"PATH=/bin:/usr/bin", "HOME=/nonexistent"}
	temporary, err := PreparePrivateTemporaryDirectory(context.Background(), command, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer temporary.Close()
	if err := command.Start(); err != nil {
		_ = temporary.Cleanup(context.Background())
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := temporary.WaitReady(ctx); err == nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("readiness wait succeeded without initialization")
	}
	if err := command.Process.Kill(); err != nil {
		_ = command.Wait()
		_ = temporary.Cleanup(context.Background())
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("helper unexpectedly survived cancellation")
	}
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup leaf after readiness cancellation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(linuxTemporaryPath(t, temporary), "started")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scanner ran after readiness cancellation: %v", err)
	}
}

func TestPrivateTemporaryCleanupFailureKeepsNamespaceForRetry(t *testing.T) {
	abi := requireLandlock(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := (*Policy)(nil).WithLandlock(helper, abi)
	command := exec.Command("/bin/sh", "-c", "IFS= read -r _")
	command.Env = []string{"PATH=/bin:/usr/bin", "HOME=/nonexistent"}
	if _, err := command.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	process := startPrivateTemporaryTestProcess(t, policy, command)
	if err := process.stop(); err == nil {
		t.Fatal("stopped scanner helper unexpectedly exited successfully")
	}
	fifo := filepath.Join(linuxTemporaryPath(t, process.temporary), "unsupported-entry")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := process.temporary.Cleanup(context.Background()); err == nil {
		t.Fatal("cleanup accepted an unsupported entry instead of failing closed")
	}
	if _, err := os.Stat(linuxTemporaryPath(t, process.temporary)); err != nil {
		t.Fatalf("failed cleanup removed the directory needed for a safe retry: %v", err)
	}
	if err := os.Remove(fifo); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := process.temporary.Cleanup(cancelled); err != nil {
		t.Fatalf("retry cleanup after removing unsupported entry: %v", err)
	}
	if _, err := os.Stat(linuxTemporaryPath(t, process.temporary)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary directory remains after cleanup retry: %v", err)
	}
}

func TestPrivateTemporaryCleanupRefusesReplacedPinnedEntries(t *testing.T) {
	t.Run("namespace entry", func(t *testing.T) {
		temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
		rootFD := int(temporary.root.Fd())
		movedName := temporary.namespaceName + "-moved"
		if err := unix.Renameat(rootFD, temporary.namespaceName, rootFD, movedName); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkdirat(rootFD, temporary.namespaceName, privateNamespaceMode); err != nil {
			t.Fatal(err)
		}
		if err := temporary.Cleanup(context.Background()); err == nil {
			t.Fatal("cleanup accepted a replacement invocation namespace")
		}
		if temporary.cleaned {
			t.Fatal("failed namespace identity validation marked cleanup complete")
		}
		var moved, replacement unix.Stat_t
		if err := unix.Fstatat(rootFD, movedName, &moved, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Fatalf("original pinned namespace entry was removed: %v", err)
		}
		if err := unix.Fstatat(rootFD, temporary.namespaceName, &replacement, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Fatalf("replacement namespace entry was removed: %v", err)
		}
		if sameObject(&temporary.namespaceStat, &replacement) {
			t.Fatal("replacement unexpectedly has the pinned namespace identity")
		}
		if err := unix.Unlinkat(rootFD, temporary.namespaceName, unix.AT_REMOVEDIR); err != nil {
			t.Fatalf("remove test replacement namespace: %v", err)
		}
		if err := unix.Renameat(rootFD, movedName, rootFD, temporary.namespaceName); err != nil {
			t.Fatalf("restore pinned namespace entry: %v", err)
		}
		if err := temporary.Cleanup(context.Background()); err != nil {
			t.Fatalf("cleanup restored invocation namespace: %v", err)
		}
	})

	t.Run("leaf entry", func(t *testing.T) {
		temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
		namespaceFD := int(temporary.namespace.Fd())
		movedName := temporary.name + "-moved"
		if err := unix.Renameat(namespaceFD, temporary.name, namespaceFD, movedName); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkdirat(namespaceFD, temporary.name, privateTemporaryMode); err != nil {
			t.Fatal(err)
		}
		if err := unix.Fchmodat(namespaceFD, temporary.name, privateTemporaryMode, 0); err != nil {
			t.Fatal(err)
		}
		if err := temporary.Cleanup(context.Background()); err == nil {
			t.Fatal("cleanup accepted a replacement leaf entry")
		}
		if temporary.cleaned {
			t.Fatal("failed leaf identity validation marked cleanup complete")
		}
		var moved, replacement unix.Stat_t
		if err := unix.Fstatat(namespaceFD, movedName, &moved, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Fatalf("original pinned leaf entry was removed: %v", err)
		}
		if err := unix.Fstatat(namespaceFD, temporary.name, &replacement, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Fatalf("replacement leaf entry was removed: %v", err)
		}
		if sameObject(&temporary.leafStat, &replacement) {
			t.Fatal("replacement unexpectedly has the pinned leaf identity")
		}
		if err := unix.Unlinkat(namespaceFD, temporary.name, unix.AT_REMOVEDIR); err != nil {
			t.Fatalf("remove test replacement leaf: %v", err)
		}
		if err := unix.Renameat(namespaceFD, movedName, namespaceFD, temporary.name); err != nil {
			t.Fatalf("restore pinned leaf entry: %v", err)
		}
		if err := temporary.Cleanup(context.Background()); err != nil {
			t.Fatalf("cleanup restored leaf: %v", err)
		}
	})
}

func TestPrivateTemporaryCleanupRetainsNamespaceWhenItIsNotEmpty(t *testing.T) {
	temporary := &linuxPrivateTemporaryDirectory{filesystem: realPrivateTemporaryFilesystemOps()}
	if err := temporary.createNamespace(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = temporary.Close() })
	blocker, err := unix.Openat(int(temporary.namespace.Fd()), "pending", unix.O_CREAT|unix.O_WRONLY|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(blocker); err != nil {
		t.Fatal(err)
	}
	if err := temporary.ensureDirectoryEmpty(temporary.namespace); err == nil {
		t.Fatal("empty-directory check accepted a pending entry")
	}
	if err := temporary.removeNamespace(); err == nil {
		t.Fatal("namespace removal accepted a pending entry")
	}
	var named unix.Stat_t
	if err := unix.Fstatat(int(temporary.root.Fd()), temporary.namespaceName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatalf("failed removal lost the invocation namespace: %v", err)
	}
	if err := unix.Unlinkat(int(temporary.namespace.Fd()), "pending", 0); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup after removing pending entry: %v", err)
	}
}

func TestPrivateTemporaryCleanupBoundsRecursionAndEntryCount(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
		fd, err := unix.Openat(int(temporary.leaf.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			t.Fatal(err)
		}
		if err := removePrivateDirectoryContents(fd, uint64(stat.Dev), stat.Uid, stat.Gid, privateTemporaryCleanupDepth+1, &cleanupBudget{}); err == nil {
			t.Fatal("cleaner accepted a directory beyond its recursion limit")
		}
		if entries, err := os.ReadDir(temporary.path()); err != nil || len(entries) != 0 {
			t.Fatalf("depth rejection changed leaf contents: %v, %v", entries, err)
		}
	})

	t.Run("entry count", func(t *testing.T) {
		temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
		artifact := filepath.Join(temporary.path(), "owned-artifact")
		if err := os.WriteFile(artifact, []byte("keep on rejected cleanup"), 0o600); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Openat(int(temporary.leaf.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			t.Fatal(err)
		}
		budget := cleanupBudget{entries: privateTemporaryCleanupEntries}
		if err := removePrivateDirectoryContents(fd, uint64(stat.Dev), stat.Uid, stat.Gid, 0, &budget); err == nil {
			t.Fatal("cleaner accepted an entry beyond its total-entry limit")
		}
		if contents, err := os.ReadFile(artifact); err != nil || string(contents) != "keep on rejected cleanup" {
			t.Fatalf("entry-limit rejection removed or changed the artifact: %q, %v", contents, err)
		}
	})
}

func TestPrivateTemporaryCleanupHelperFailurePreservesArtifacts(t *testing.T) {
	temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
	artifact := filepath.Join(temporary.path(), "retained")
	if err := os.WriteFile(artifact, []byte("do not report success"), 0o600); err != nil {
		t.Fatal(err)
	}
	var leaf unix.Stat_t
	if err := unix.Fstat(int(temporary.leaf.Fd()), &leaf); err != nil {
		t.Fatal(err)
	}
	temporary.helper = "/bin/false"
	if err := temporary.cleanupWithHelper(context.Background(), &leaf); err == nil {
		t.Fatal("failed cleanup helper was accepted")
	}
	if contents, err := os.ReadFile(artifact); err != nil || string(contents) != "do not report success" {
		t.Fatalf("failed helper changed the artifact: %q, %v", contents, err)
	}
}

func TestPrivateTemporaryCleanupHelperUsesPinnedScannerLeafMode(t *testing.T) {
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	temporary := &linuxPrivateTemporaryDirectory{
		filesystem:    realPrivateTemporaryFilesystemOps(),
		helper:        helper,
		uid:           uint32(os.Geteuid()),
		gid:           uint32(os.Getegid()),
		private:       true,
		leafMode:      privateScannerTemporaryMode,
		namespaceMode: privateScannerNamespaceMode,
	}
	if err := temporary.createNamespace(); err != nil {
		t.Fatalf("create scanner invocation namespace: %v", err)
	}
	if err := temporary.createLeaf(); err != nil {
		_ = temporary.Close()
		t.Fatalf("create scanner-owned leaf: %v", err)
	}
	t.Cleanup(func() {
		if !temporary.cleaned {
			if err := temporary.Cleanup(context.Background()); err != nil {
				t.Errorf("cleanup scanner-owned leaf: %v", err)
			}
		}
		if err := temporary.Close(); err != nil {
			t.Errorf("close scanner-owned temporary directory: %v", err)
		}
	})
	artifact := filepath.Join(temporary.path(), "CURRENT")
	if err := os.WriteFile(artifact, []byte("MANIFEST-000001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var leaf unix.Stat_t
	if err := unix.Fstat(int(temporary.leaf.Fd()), &leaf); err != nil {
		t.Fatal(err)
	}
	if leaf.Mode != unix.S_IFDIR|privateScannerTemporaryMode {
		t.Fatalf("scanner-owned leaf mode = %#o, want %#o", leaf.Mode, unix.S_IFDIR|privateScannerTemporaryMode)
	}
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("helper-backed cleanup of 0700 scanner leaf: %v", err)
	}
	for _, path := range []string{temporary.path(), filepath.Join("/tmp", temporary.namespaceName)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("cleanup left %q: %v", path, err)
		}
	}
}

func TestPrivateTemporaryStartedReportsControlSetupFailures(t *testing.T) {
	t.Run("closed child endpoint", func(t *testing.T) {
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(pair[1])
		child := os.NewFile(uintptr(pair[0]), "closed private temporary child endpoint")
		if err := child.Close(); err != nil {
			t.Fatal(err)
		}
		temporary := &linuxPrivateTemporaryDirectory{child: child}
		if err := temporary.Started(); err == nil {
			t.Fatal("started accepted a child endpoint that could not be closed")
		}
		if !temporary.started || temporary.child != nil {
			t.Fatalf("failed start state = started %v child %v", temporary.started, temporary.child)
		}
	})

	t.Run("invalid initialization", func(t *testing.T) {
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(pair[1])
		temporary := &linuxPrivateTemporaryDirectory{
			private: true, parent: os.NewFile(uintptr(pair[0]), "private temporary parent"),
			namespaceName: "../invalid", name: privateTemporaryPrefix + strings.Repeat("a", privateTemporaryNonceSize*2),
		}
		defer temporary.Close()
		if err := temporary.Started(); err == nil {
			t.Fatal("started sent an invalid initialization")
		}
	})

	t.Run("closed peer", func(t *testing.T) {
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(pair[1])
		temporary := &linuxPrivateTemporaryDirectory{
			private: true, parent: os.NewFile(uintptr(pair[0]), "private temporary parent"),
			namespaceName: privateNamespacePrefix + strings.Repeat("b", privateTemporaryNonceSize*2),
			name:          privateTemporaryPrefix + strings.Repeat("c", privateTemporaryNonceSize*2),
			namespaceStat: unix.Stat_t{Mode: unix.S_IFDIR | privateNamespaceMode, Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid())},
			leafStat:      unix.Stat_t{Mode: unix.S_IFDIR | privateTemporaryMode, Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid())},
		}
		defer temporary.Close()
		if err := temporary.Started(); err == nil {
			t.Fatal("started accepted a closed helper control peer")
		}
	})
}

type privateTemporaryTestProcess struct {
	command   *exec.Cmd
	temporary *PrivateTemporaryDirectory
	waited    bool
	cleaned   bool
}

func startPrivateTemporaryTestProcess(t *testing.T, policy *Policy, command *exec.Cmd) *privateTemporaryTestProcess {
	t.Helper()
	temporary, err := PreparePrivateTemporaryDirectory(context.Background(), command, policy)
	if err != nil {
		t.Fatalf("prepare private scanner command: %v", err)
	}
	process := &privateTemporaryTestProcess{command: command, temporary: temporary}
	t.Cleanup(func() {
		if err := process.cleanup(); err != nil {
			t.Errorf("clean private scanner process: %v", err)
		}
	})
	if err := command.Start(); err != nil {
		_ = temporary.Cleanup(context.Background())
		_ = temporary.Close()
		t.Fatalf("start private scanner command: %v", err)
	}
	if err := temporary.Started(); err != nil {
		_ = process.stop()
		_ = process.cleanup()
		t.Fatalf("start private scanner helper: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := temporary.WaitReady(ctx); err != nil {
		_ = process.stop()
		_ = process.cleanup()
		t.Fatalf("wait for private scanner helper: %v", err)
	}
	return process
}

func (process *privateTemporaryTestProcess) wait() error {
	if process.waited {
		return nil
	}
	err := process.command.Wait()
	process.waited = true
	return err
}

func (process *privateTemporaryTestProcess) stop() error {
	if process.waited || process.command.Process == nil {
		return nil
	}
	_ = process.command.Process.Kill()
	return process.wait()
}

func (process *privateTemporaryTestProcess) cleanup() error {
	if process.cleaned {
		return nil
	}
	if !process.waited && process.command.Process != nil {
		_ = process.stop()
	}
	cleanupErr := process.temporary.Cleanup(context.Background())
	closeErr := process.temporary.Close()
	process.cleaned = true
	return errors.Join(cleanupErr, closeErr)
}
