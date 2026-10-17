//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	privateTemporaryCreateChildEnv = "EDGEWATCH_PRIVATE_CREATE_CHILD"
	privateTemporaryCreateUIDEnv   = "EDGEWATCH_PRIVATE_CREATE_UID"
	privateTemporaryCreateGIDEnv   = "EDGEWATCH_PRIVATE_CREATE_GID"
)

// TestPrivateTemporaryCreateExecChild is re-executed by sandbox-exec in the
// parent/helper protocol test below. It validates the helper's TMPDIR and
// writes nested artifacts that the parent must remove through the cleanup
// helper after the child exits.
func TestPrivateTemporaryCreateExecChild(t *testing.T) {
	if os.Getenv(privateTemporaryCreateChildEnv) != "1" {
		return
	}
	wantUID, err := strconv.Atoi(os.Getenv(privateTemporaryCreateUIDEnv))
	if err != nil || os.Geteuid() != wantUID {
		t.Fatalf("child euid=%d, expected %d (parse error %v)", os.Geteuid(), wantUID, err)
	}
	wantGID, err := strconv.Atoi(os.Getenv(privateTemporaryCreateGIDEnv))
	if err != nil || os.Getegid() != wantGID {
		t.Fatalf("child egid=%d, expected %d (parse error %v)", os.Getegid(), wantGID, err)
	}
	leaf := os.Getenv("TMPDIR")
	info, err := os.Stat(leaf)
	if err != nil {
		t.Fatalf("stat inherited scanner leaf: %v", err)
	}
	if !info.IsDir() || info.Mode().Perm() != privateScannerTemporaryMode {
		t.Fatalf("inherited scanner leaf mode=%#o, want directory mode %#o", info.Mode(), privateScannerTemporaryMode)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != wantUID || int(stat.Gid) != wantGID {
		t.Fatalf("inherited scanner leaf owner=%v, want uid/gid %d/%d", info.Sys(), wantUID, wantGID)
	}
	// The scanner controls its TMPDIR permissions and may create deeper trees
	// than a recursive cleanup routine can safely walk.
	if err := os.Chmod(leaf, 0o755); err != nil {
		t.Fatalf("change scanner-owned TMPDIR mode: %v", err)
	}
	nested := leaf
	for depth := 0; depth < 40; depth++ {
		nested = filepath.Join(nested, "level")
		if err := os.Mkdir(nested, 0o700); err != nil {
			t.Fatalf("create scanner artifact directory at depth %d: %v", depth+1, err)
		}
	}
	if err := os.WriteFile(filepath.Join(nested, "CURRENT"), []byte("MANIFEST-000001\n"), 0o600); err != nil {
		t.Fatalf("write scanner artifact: %v", err)
	}
}

type privateTemporaryCreateTestLease struct {
	uid, gid       int
	released       bool
	quarantined    bool
	releaseCalls   int
	quarantineCall int
}

func (lease *privateTemporaryCreateTestLease) identity() (int, int, bool) {
	return lease.uid, lease.gid, true
}

func (lease *privateTemporaryCreateTestLease) release() error {
	lease.releaseCalls++
	lease.released = true
	return nil
}

func (lease *privateTemporaryCreateTestLease) quarantine() error {
	lease.quarantineCall++
	lease.quarantined = true
	return nil
}

func privateTemporaryCreatePolicy(t *testing.T) (*Policy, *ScannerIdentityReservation, *privateTemporaryCreateTestLease) {
	t.Helper()
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	lease := &privateTemporaryCreateTestLease{uid: os.Geteuid(), gid: os.Getegid()}
	reservation := &ScannerIdentityReservation{lease: lease}
	policy := (&Policy{
		profile:         Scanner,
		status:          Status{Mode: ModeAuto, State: StateEnforced},
		temporaryHelper: helper,
	}).WithScannerIdentityReservation(reservation)
	t.Cleanup(func() {
		if !reservation.finished && !reservation.claimed {
			if err := reservation.Finish(false); err != nil {
				t.Errorf("finish test scanner reservation: %v", err)
			}
		}
	})
	return policy, reservation, lease
}

func TestPrivateTemporaryPrepareFailureReleasesUnusedScannerLease(t *testing.T) {
	policy, reservation, lease := privateTemporaryCreatePolicy(t)
	command := exec.Command(filepath.Join(t.TempDir(), "missing-naabu"))
	if temporary, err := PreparePrivateTemporaryDirectory(context.Background(), command, policy); err == nil || temporary != nil {
		if temporary != nil {
			_ = temporary.Close()
		}
		t.Fatalf("prepare with missing Naabu executable = %v, %v; want failure before a child starts", temporary, err)
	}
	if err := reservation.Finish(true); err != nil {
		t.Fatalf("release lease after pre-start Prepare failure: %v", err)
	}
	if !lease.released || lease.releaseCalls != 1 || lease.quarantined || lease.quarantineCall != 0 {
		t.Fatalf("pre-start lease state = %+v; want one release and no quarantine", lease)
	}
}

func newPrivateTemporaryCreateFixture(t *testing.T) *linuxPrivateTemporaryDirectory {
	t.Helper()
	temporary := &linuxPrivateTemporaryDirectory{
		filesystem:    realPrivateTemporaryFilesystemOps(),
		uid:           uint32(os.Geteuid()),
		gid:           uint32(os.Getegid()),
		leafMode:      privateScannerTemporaryMode,
		namespaceMode: privateScannerNamespaceMode,
		childCreates:  true,
	}
	if err := temporary.createNamespace(); err != nil {
		t.Fatal(err)
	}
	if err := temporary.newChildCreatedNames(); err != nil {
		_ = temporary.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		temporary.private = false
		if err := temporary.Cleanup(context.Background()); err != nil {
			t.Errorf("cleanup child-create protocol fixture: %v", err)
		}
		if err := temporary.Close(); err != nil {
			t.Errorf("close child-create protocol fixture: %v", err)
		}
	})
	return temporary
}

func privateTemporaryCreateInitPacket(t *testing.T, temporary *linuxPrivateTemporaryDirectory) []byte {
	t.Helper()
	if err := unix.Fstat(int(temporary.root.Fd()), &temporary.rootStat); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(int(temporary.namespace.Fd()), &temporary.namespaceStat); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Getrandom(temporary.nonce[:], 0); err != nil {
		t.Fatal(err)
	}
	packet, err := encodePrivateTemporaryCreateInit(temporary.namespaceName, temporary.name, temporary.nonce, &temporary.rootStat, &temporary.namespaceStat)
	if err != nil {
		t.Fatalf("encode child-create initialization: %v", err)
	}
	return packet
}

func TestPreparePrivateTemporaryCreateExecCreatesLeafFromPinnedParentDescriptors(t *testing.T) {
	temporary := newPrivateTemporaryCreateFixture(t)
	packet := privateTemporaryCreateInitPacket(t, temporary)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	if n, err := unix.SendmsgN(pair[1], packet, nil, nil, 0); err != nil || n != len(packet) {
		t.Fatalf("send child-create initialization: n=%d err=%v", n, err)
	}
	setup, err := preparePrivateTemporaryCreateExec(execRequest{
		privateRootFD:      int(temporary.root.Fd()),
		privateNamespaceFD: int(temporary.namespace.Fd()),
		controlFD:          pair[0],
	})
	if err != nil {
		t.Fatalf("prepare helper-created leaf: %v", err)
	}
	if !setup.initialization.childCreates || setup.initialization.name != temporary.name {
		t.Fatalf("decoded child-create setup = %+v", setup.initialization)
	}
	if values := environmentValues(setup.environment, "TMPDIR"); len(values) != 1 || values[0] != temporary.path() {
		t.Fatalf("helper TMPDIR = %q, want %q", values, temporary.path())
	}
	var actual, named unix.Stat_t
	if err := unix.Fstatat(int(temporary.namespace.Fd()), temporary.name, &actual, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatalf("stat helper-created leaf: %v", err)
	}
	if !sameObject(&setup.leafStat, &actual) || actual.Mode != unix.S_IFDIR|privateScannerTemporaryMode || actual.Uid != temporary.uid || actual.Gid != temporary.gid {
		t.Fatalf("helper-created leaf stat=%+v, setup=%+v", actual, setup.leafStat)
	}
	if err := unix.Fstatat(int(temporary.root.Fd()), temporary.namespaceName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&temporary.namespaceStat, &named) {
		t.Fatalf("parent namespace entry changed: %+v, %v", named, err)
	}
}

func TestPreparePrivateTemporaryCreateExecRejectsChangedParentAndLeafCollision(t *testing.T) {
	for _, stage := range []string{"wrong root descriptor", "wrong namespace descriptor", "existing leaf collision"} {
		t.Run(stage, func(t *testing.T) {
			temporary := newPrivateTemporaryCreateFixture(t)
			packet := privateTemporaryCreateInitPacket(t, temporary)
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pair[0])
			defer unix.Close(pair[1])
			if stage == "existing leaf collision" {
				if err := unix.Mkdirat(int(temporary.namespace.Fd()), temporary.name, privateScannerTemporaryMode); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(temporary.path(), "owned-marker"), []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := unix.SendmsgN(pair[1], packet, nil, nil, 0); err != nil || n != len(packet) {
				t.Fatalf("send initialization: n=%d err=%v", n, err)
			}
			rootFD, namespaceFD := int(temporary.root.Fd()), int(temporary.namespace.Fd())
			switch stage {
			case "wrong root descriptor":
				rootFD = namespaceFD
			case "wrong namespace descriptor":
				namespaceFD = rootFD
			}
			_, err = preparePrivateTemporaryCreateExec(execRequest{privateRootFD: rootFD, privateNamespaceFD: namespaceFD, controlFD: pair[0]})
			if err == nil {
				t.Fatal("helper accepted changed parent descriptors or a colliding leaf")
			}
			if stage == "existing leaf collision" {
				if got, readErr := os.ReadFile(filepath.Join(temporary.path(), "owned-marker")); readErr != nil || string(got) != "preserve" {
					t.Fatalf("collision marker changed: %q, %v", got, readErr)
				}
			}
			if stage != "existing leaf collision" {
				if _, statErr := os.Lstat(temporary.path()); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("rejected setup created or adopted a leaf: %v", statErr)
				}
			}
		})
	}
}

func TestHelperSendPrivateTemporaryCreateReadyRequiresParentAcknowledgment(t *testing.T) {
	for _, test := range []struct {
		name      string
		ack       byte
		wantError bool
	}{
		{name: "valid ACK", ack: 1},
		{name: "invalid ACK", ack: 0, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			temporary := newPrivateTemporaryCreateFixture(t)
			if err := unix.Mkdirat(int(temporary.namespace.Fd()), temporary.name, privateScannerTemporaryMode); err != nil {
				t.Fatal(err)
			}
			var leaf unix.Stat_t
			if err := unix.Fstatat(int(temporary.namespace.Fd()), temporary.name, &leaf, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				t.Fatal(err)
			}
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pair[0])
			defer unix.Close(pair[1])
			peerResult := make(chan error, 1)
			go func() {
				message := make([]byte, privateTemporaryMessageMax)
				n, _, flags, _, recvErr := unix.Recvmsg(pair[0], message, nil, 0)
				if recvErr != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
					peerResult <- errors.New("readiness packet was unreadable or truncated")
					return
				}
				device, inode, uid, gid, mode, decodeErr := decodePrivateTemporaryCreateMessage(message[:n], temporary.name, temporary.nonce)
				if decodeErr != nil || device != uint64(leaf.Dev) || inode != leaf.Ino || uid != leaf.Uid || gid != leaf.Gid || mode != leaf.Mode {
					peerResult <- errors.New("readiness packet did not describe the pinned leaf")
					return
				}
				_, writeErr := unix.Write(pair[0], []byte{test.ack})
				peerResult <- writeErr
			}()
			helperErr := helperSendPrivateTemporaryCreateReady(pair[1], temporary.name, temporary.nonce, &leaf)
			peerErr := <-peerResult
			if peerErr != nil {
				t.Fatalf("parent protocol fixture: %v", peerErr)
			}
			if (helperErr != nil) != test.wantError {
				t.Fatalf("helper ACK result = %v, wantError=%v", helperErr, test.wantError)
			}
		})
	}
}

func TestPrivateTemporaryChildCreatesLeafThroughHelperAndParentPinsIt(t *testing.T) {
	policy, reservation, lease := privateTemporaryCreatePolicy(t)
	executable := mustExecutable(t)
	command := exec.Command(executable, "-test.run=^TestPrivateTemporaryCreateExecChild$")
	command.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/nonexistent",
		privateTemporaryCreateChildEnv + "=1",
		privateTemporaryCreateUIDEnv + "=" + strconv.Itoa(lease.uid),
		privateTemporaryCreateGIDEnv + "=" + strconv.Itoa(lease.gid),
	}
	process := startPrivateTemporaryTestProcess(t, policy, command)
	temporary := linuxTemporaryState(t, process.temporary)
	if !temporary.childCreates || temporary.leaf == nil || !temporary.accepted {
		t.Fatalf("child-created handshake state: childCreates=%v leaf=%v accepted=%v", temporary.childCreates, temporary.leaf, temporary.accepted)
	}
	var namespace unix.Stat_t
	if err := unix.Fstat(int(temporary.namespace.Fd()), &namespace); err != nil {
		t.Fatal(err)
	}
	if namespace.Mode != unix.S_IFDIR|privateNamespaceMode || temporary.namespaceMode != privateNamespaceMode {
		t.Fatalf("scanner namespace mode=%#o state=%#o, want sealed %#o", namespace.Mode, temporary.namespaceMode, unix.S_IFDIR|privateNamespaceMode)
	}
	var pinned, named unix.Stat_t
	if err := unix.Fstat(int(temporary.leaf.Fd()), &pinned); err != nil {
		t.Fatal(err)
	}
	if pinned.Mode != unix.S_IFDIR|privateScannerTemporaryMode || pinned.Uid != uint32(lease.uid) || pinned.Gid != uint32(lease.gid) {
		t.Fatalf("pinned scanner leaf mode=%#o uid/gid=%d/%d", pinned.Mode, pinned.Uid, pinned.Gid)
	}
	if err := unix.Fstatat(int(temporary.namespace.Fd()), temporary.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&pinned, &named) {
		t.Fatalf("parent-pinned leaf entry = %+v, %v", named, err)
	}
	if err := process.wait(); err != nil {
		t.Fatalf("scanner child after readiness ACK: %v", err)
	}
	deep := temporary.path()
	for depth := 0; depth < 40; depth++ {
		deep = filepath.Join(deep, "level")
	}
	current := filepath.Join(deep, "CURRENT")
	if got, err := os.ReadFile(current); err != nil || string(got) != "MANIFEST-000001\n" {
		t.Fatalf("child-created artifact = %q, %v", got, err)
	}
	if err := process.cleanup(); err != nil {
		t.Fatalf("cleanup child-created scanner artifacts: %v", err)
	}
	if _, err := os.Lstat(filepath.Join("/tmp", temporary.namespaceName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("child-created namespace remains after helper cleanup: %v", err)
	}
	if err := reservation.Finish(true); err != nil {
		t.Fatalf("release reservation after cleanup: %v", err)
	}
	if !lease.released || lease.releaseCalls != 1 || lease.quarantined || lease.quarantineCall != 0 {
		t.Fatalf("lease release state = %+v", lease)
	}
}

func TestPrivateTemporaryChildReadinessRejectsChangedIdentityAndReclaimsOnlyAfterward(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*unix.Stat_t, []byte)
	}{
		{
			name: "inode changed",
			edit: func(stat *unix.Stat_t, _ []byte) { stat.Ino++ },
		},
		{
			name: "owner changed",
			edit: func(stat *unix.Stat_t, _ []byte) { stat.Uid++ },
		},
		{
			name: "nonce changed",
			edit: func(_ *unix.Stat_t, packet []byte) { packet[len(packet)-1] ^= 1 },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			temporary := &linuxPrivateTemporaryDirectory{
				filesystem:    realPrivateTemporaryFilesystemOps(),
				uid:           uint32(os.Geteuid()),
				gid:           uint32(os.Getegid()),
				leafMode:      privateScannerTemporaryMode,
				namespaceMode: privateScannerNamespaceMode,
				childCreates:  true,
				private:       true,
			}
			t.Cleanup(func() {
				temporary.private = false
				if err := temporary.Cleanup(context.Background()); err != nil {
					t.Errorf("cleanup child-created readiness fixture: %v", err)
				}
				if err := temporary.Close(); err != nil {
					t.Errorf("close child-created readiness fixture: %v", err)
				}
			})
			if err := temporary.createNamespace(); err != nil {
				t.Fatal(err)
			}
			if err := temporary.newChildCreatedNames(); err != nil {
				_ = temporary.Close()
				t.Fatal(err)
			}
			if err := unix.Mkdirat(int(temporary.namespace.Fd()), temporary.name, privateScannerTemporaryMode); err != nil {
				_ = temporary.Close()
				t.Fatal(err)
			}
			var leaf unix.Stat_t
			if err := unix.Fstatat(int(temporary.namespace.Fd()), temporary.name, &leaf, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				_ = unix.Unlinkat(int(temporary.namespace.Fd()), temporary.name, unix.AT_REMOVEDIR)
				_ = temporary.Close()
				t.Fatal(err)
			}
			packet, err := encodePrivateTemporaryCreateMessage(temporary.name, temporary.nonce, &leaf)
			if err != nil {
				t.Fatal(err)
			}
			claimed := leaf
			test.edit(&claimed, packet)
			if test.name != "nonce changed" {
				packet, err = encodePrivateTemporaryCreateMessage(temporary.name, temporary.nonce, &claimed)
				if err != nil {
					t.Fatal(err)
				}
			}
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			temporary.parent = os.NewFile(uintptr(pair[0]), "child-create parent control")
			if n, err := unix.SendmsgN(pair[1], packet, nil, nil, 0); err != nil || n != len(packet) {
				_ = unix.Close(pair[1])
				_ = temporary.Close()
				t.Fatalf("send readiness: n=%d err=%v", n, err)
			}
			if err := temporary.WaitReady(context.Background()); err == nil {
				_ = unix.Close(pair[1])
				_ = temporary.Close()
				t.Fatal("parent accepted child readiness for a changed leaf identity")
			}
			if temporary.accepted || temporary.leaf != nil {
				t.Fatalf("rejected readiness changed parent pin state: accepted=%v leaf=%v", temporary.accepted, temporary.leaf)
			}
			if _, err := os.Lstat(temporary.path()); err != nil {
				t.Fatalf("rejected readiness removed the untrusted leaf: %v", err)
			}
			if err := unix.Close(pair[1]); err != nil {
				t.Fatal(err)
			}
			// The test created this directory as the current owner. After
			// rejecting the readiness packet, cleanup independently pins and
			// verifies the actual leaf before removing it.
			temporary.private = false
			if err := temporary.Cleanup(context.Background()); err != nil {
				t.Fatalf("cleanup actual leaf after rejecting the forged packet: %v", err)
			}
			if _, err := os.Lstat(filepath.Join("/tmp", temporary.namespaceName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("namespace remains after verified cleanup: %v", err)
			}
			if err := temporary.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPrivateTemporaryChildCreateCleanupRemovesNamespaceWhenNoLeafExists(t *testing.T) {
	policy, reservation, lease := privateTemporaryCreatePolicy(t)
	command := exec.Command("/bin/true")
	temporary, err := prepareLinuxPrivateTemporaryDirectory(context.Background(), command, policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := temporary.Cleanup(context.Background()); err != nil {
			t.Errorf("cleanup unstarted child-create fixture: %v", err)
		}
		if err := temporary.Close(); err != nil {
			t.Errorf("close unstarted child-create fixture: %v", err)
		}
	})
	if !temporary.childCreates || temporary.name == "" || temporary.leaf != nil {
		t.Fatalf("unstarted child-create state: childCreates=%v name=%q leaf=%v", temporary.childCreates, temporary.name, temporary.leaf)
	}
	namespacePath := filepath.Join("/tmp", temporary.namespaceName)
	if err := temporary.Cleanup(context.Background()); err != nil {
		_ = temporary.Close()
		t.Fatalf("cleanup namespace before child created leaf: %v", err)
	}
	if _, err := os.Lstat(namespacePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty pre-start namespace remains: %v", err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reservation.Finish(true); err != nil {
		t.Fatalf("release reservation after empty-namespace cleanup: %v", err)
	}
	if !lease.released || lease.quarantined {
		t.Fatalf("pre-start reservation state = %+v", lease)
	}
}

func mustExecutable(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return executable
}

var _ identityLease = (*privateTemporaryCreateTestLease)(nil)
