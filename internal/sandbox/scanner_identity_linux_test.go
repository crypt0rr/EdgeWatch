//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

const (
	testScannerBootID  = "00000000-0000-0000-0000-000000000001"
	testScannerBootID2 = "00000000-0000-0000-0000-000000000002"
)

func newTestScannerIdentityAllocator(t *testing.T, count uint32) *scannerIdentityAllocator {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return newScannerIdentityAllocatorForTest(filepath.Join(parent, "leases"), 61000, count, testScannerBootID, 17)
}

func usePrivateScannerRuntime(allocator *scannerIdentityAllocator) *scannerIdentityAllocator {
	allocator.privateRuntime = func() (bool, error) { return true, nil }
	return allocator
}

func useAttestedPrivateScannerScope(allocator *scannerIdentityAllocator, namespace uint64) *scannerIdentityAllocator {
	allocator.privateRuntime = func() (bool, error) { return false, nil }
	allocator.privateScope = func(current uint64) (bool, error) { return current == namespace, nil }
	return allocator
}

func TestScannerIdentityAllocatorDurableLeaseState(t *testing.T) {
	allocator := newTestScannerIdentityAllocator(t, 2)
	first, err := allocator.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := allocator.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstUID, firstGID, ok := first.identity()
	if !ok || firstUID != 61000 || firstGID != firstUID {
		t.Fatalf("first identity = %d:%d, %v; want 61000:61000", firstUID, firstGID, ok)
	}
	secondUID, _, ok := second.identity()
	if !ok || secondUID != 61001 {
		t.Fatalf("second identity = %d, %v; want 61001", secondUID, ok)
	}
	if err := first.quarantine(); err != nil {
		t.Fatal(err)
	}
	if _, err := allocator.acquire(context.Background()); !errors.Is(err, errScannerIdentityPoolExhausted) {
		t.Fatalf("acquire with one quarantined and one active lease = %v; want exhausted", err)
	}
	if err := first.release(); err == nil {
		t.Fatal("quarantined lease was released")
	}

	journal, err := readTestScannerIdentityJournal(allocator)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Leases[61000].State != "quarantined" || journal.Leases[61001].State != "active" {
		t.Fatalf("persisted lease states = %+v", journal.Leases)
	}

	// A fresh allocator object represents a daemon restart. The old active
	// lease remains unavailable until its owning supervisor proves cleanup.
	restarted := newScannerIdentityAllocatorForTest(allocator.directory, allocator.uidStart, allocator.count, testScannerBootID, 17)
	if err := second.release(); err != nil {
		t.Fatal(err)
	}
	reused, err := restarted.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	uid, _, ok := reused.identity()
	if !ok || uid != 61001 {
		t.Fatalf("reused identity = %d, %v; want released slot 61001", uid, ok)
	}
	if err := reused.release(); err != nil {
		t.Fatal(err)
	}
}

func TestScannerIdentityAllocatorFirstInitAndMissingStateFailClosed(t *testing.T) {
	allocator := newTestScannerIdentityAllocator(t, 2)
	lease, err := allocator.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(allocator.directory, scannerIdentityJournalName)); err != nil {
		t.Fatalf("first acquire did not persist its journal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(allocator.markerDir, scannerIdentityMarker)); err != nil {
		t.Fatalf("first acquire did not persist its sibling boot marker: %v", err)
	}

	// Losing the private lease directory's journal must not turn an existing
	// same-boot allocator into a fresh pool while an invocation may be alive.
	if err := os.Remove(filepath.Join(allocator.directory, scannerIdentityJournalName)); err != nil {
		t.Fatal(err)
	}
	if _, err := allocator.acquire(context.Background()); err == nil {
		t.Fatal("same-boot missing journal was treated as first initialization")
	}

	// Likewise, an active durable journal cannot be adopted when its anchor is
	// missing. The allocator has lost the evidence that defines its scope.
	if err := os.Remove(filepath.Join(allocator.markerDir, scannerIdentityMarker)); err != nil {
		t.Fatal(err)
	}
	if err := writeTestScannerIdentityJournal(allocator, scannerIdentityJournal{
		Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17,
		Leases: map[uint32]scannerIdentityJournalEntry{61000: {GID: 61000, Token: lease.token, State: "active"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := allocator.acquire(context.Background()); err == nil {
		t.Fatal("same-boot missing marker was treated as first initialization")
	}
}

func TestScannerIdentityAllocatorRecoversOnlyInterruptedEmptyInitialization(t *testing.T) {
	allocator := newTestScannerIdentityAllocator(t, 1)
	if err := os.Mkdir(allocator.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeTestScannerIdentityJournal(allocator, scannerIdentityJournal{
		Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17,
		Leases: make(map[uint32]scannerIdentityJournalEntry),
	}); err != nil {
		t.Fatal(err)
	}
	lease, err := allocator.acquire(context.Background())
	if err != nil {
		t.Fatalf("complete interrupted empty initialization: %v", err)
	}
	if _, err := os.Stat(filepath.Join(allocator.markerDir, scannerIdentityMarker)); err != nil {
		t.Fatalf("recovered initialization did not write marker: %v", err)
	}
	if err := lease.release(); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(filepath.Join(allocator.markerDir, scannerIdentityMarker)); err != nil {
		t.Fatal(err)
	}
	if err := writeTestScannerIdentityJournal(allocator, scannerIdentityJournal{
		Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17,
		Leases: map[uint32]scannerIdentityJournalEntry{61000: {GID: 61000, Token: "0123456789abcdef0123456789abcdef", State: "active"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := allocator.acquire(context.Background()); err == nil {
		t.Fatal("missing marker with a nonempty same-boot journal was recovered")
	}
}

func TestScannerIdentityAllocatorBootAndNamespaceScope(t *testing.T) {
	allocator := newTestScannerIdentityAllocator(t, 1)
	oldLease, err := allocator.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	changedNamespace := newScannerIdentityAllocatorForTest(allocator.directory, allocator.uidStart, allocator.count, testScannerBootID, 18)
	if _, err := changedNamespace.acquire(context.Background()); err == nil {
		t.Fatal("same-boot PID namespace mismatch was accepted")
	}

	// A new kernel boot proves that no process holding the old lease survived.
	newBoot := newScannerIdentityAllocatorForTest(allocator.directory, allocator.uidStart, allocator.count, testScannerBootID2, 18)
	newLease, err := newBoot.acquire(context.Background())
	if err != nil {
		t.Fatalf("reset allocator after kernel boot change: %v", err)
	}
	if uid, _, ok := newLease.identity(); !ok || uid != 61000 {
		t.Fatalf("new boot lease identity = %d, %v; want 61000", uid, ok)
	}
	if err := oldLease.release(); err == nil {
		t.Fatal("old-boot lease was released into the new scope")
	}
	if err := newLease.release(); err != nil {
		t.Fatal(err)
	}
}

func TestScannerIdentityAllocatorChangesPrivateNamespaceOnlyWithEmptyJournal(t *testing.T) {
	t.Run("graceful restart in private runtime", func(t *testing.T) {
		allocator := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 1))
		lease, err := allocator.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.release(); err != nil {
			t.Fatal(err)
		}

		restarted := newScannerIdentityAllocatorForTest(allocator.directory, allocator.uidStart, allocator.count, testScannerBootID, 18)
		usePrivateScannerRuntime(restarted)
		next, err := restarted.acquire(context.Background())
		if err != nil {
			t.Fatalf("acquire after empty private-runtime namespace change: %v", err)
		}
		journal, err := readTestScannerIdentityJournal(restarted)
		if err != nil {
			t.Fatal(err)
		}
		if journal.PIDNamespace != 18 || !journal.PrivateRuntime || len(journal.Leases) != 1 {
			t.Fatalf("transitioned journal = %+v", journal)
		}
		markerData, err := os.ReadFile(filepath.Join(restarted.markerDir, scannerIdentityMarker))
		if err != nil {
			t.Fatal(err)
		}
		var marker scannerIdentityScope
		if err := json.Unmarshal(markerData, &marker); err != nil {
			t.Fatal(err)
		}
		if marker.PIDNamespace != 18 || !marker.PrivateRuntime {
			t.Fatalf("transitioned marker = %+v", marker)
		}
		if err := next.release(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("occupied old namespace fails closed", func(t *testing.T) {
		allocator := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 1))
		lease, err := allocator.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		restarted := newScannerIdentityAllocatorForTest(allocator.directory, allocator.uidStart, allocator.count, testScannerBootID, 18)
		usePrivateScannerRuntime(restarted)
		if _, err := restarted.acquire(context.Background()); err == nil {
			t.Fatal("nonempty prior namespace journal was reused")
		}
		journal, err := readTestScannerIdentityJournal(allocator)
		if err != nil {
			t.Fatal(err)
		}
		if journal.PIDNamespace != 17 || journal.Leases[61000].State != "active" {
			t.Fatalf("failed transition changed prior journal: %+v", journal)
		}
		if err := lease.release(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("untrusted runtime cannot transition", func(t *testing.T) {
		allocator := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 1))
		lease, err := allocator.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.release(); err != nil {
			t.Fatal(err)
		}
		restarted := newScannerIdentityAllocatorForTest(allocator.directory, allocator.uidStart, allocator.count, testScannerBootID, 18)
		if _, err := restarted.acquire(context.Background()); err == nil {
			t.Fatal("non-private runtime transitioned PID namespace")
		}
	})

	t.Run("completes interrupted journal-first transition", func(t *testing.T) {
		allocator := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 1))
		lease, err := allocator.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.release(); err != nil {
			t.Fatal(err)
		}
		journal, err := readTestScannerIdentityJournal(allocator)
		if err != nil {
			t.Fatal(err)
		}
		journal.PIDNamespace = 18
		if err := writeTestScannerIdentityJournal(allocator, journal); err != nil {
			t.Fatal(err)
		}

		restarted := newScannerIdentityAllocatorForTest(allocator.directory, allocator.uidStart, allocator.count, testScannerBootID, 18)
		usePrivateScannerRuntime(restarted)
		next, err := restarted.acquire(context.Background())
		if err != nil {
			t.Fatalf("complete empty journal-first transition: %v", err)
		}
		markerData, err := os.ReadFile(filepath.Join(restarted.markerDir, scannerIdentityMarker))
		if err != nil {
			t.Fatal(err)
		}
		var marker scannerIdentityScope
		if err := json.Unmarshal(markerData, &marker); err != nil {
			t.Fatal(err)
		}
		if marker.PIDNamespace != 18 || !marker.PrivateRuntime {
			t.Fatalf("completed marker = %+v", marker)
		}
		if err := next.release(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestScannerIdentityAllocatorReusesAttestedScopeFromNonPID1(t *testing.T) {
	t.Run("same private namespace reuses PID1 attestation and finishes leases", func(t *testing.T) {
		bootstrap := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 2))
		initial, err := bootstrap.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := initial.release(); err != nil {
			t.Fatal(err)
		}

		cli := useAttestedPrivateScannerScope(newScannerIdentityAllocatorForTest(bootstrap.directory, bootstrap.uidStart, bootstrap.count, testScannerBootID, 17), 17)
		reused, err := cli.acquire(context.Background())
		if err != nil {
			t.Fatalf("reuse PID1-established private scope from non-PID1 caller: %v", err)
		}
		if !reused.privateRuntime {
			t.Fatal("non-PID1 lease lost the validated private-runtime scope")
		}
		if err := reused.release(); err != nil {
			t.Fatalf("release non-PID1 lease in its attested scope: %v", err)
		}

		quarantined, err := cli.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := quarantined.quarantine(); err != nil {
			t.Fatalf("quarantine non-PID1 lease in its attested scope: %v", err)
		}
		journal, err := readTestScannerIdentityJournal(cli)
		if err != nil {
			t.Fatal(err)
		}
		if !journal.PrivateRuntime || journal.PIDNamespace != 17 || journal.Leases[quarantined.uid].State != "quarantined" {
			t.Fatalf("non-PID1 scope or quarantine was not preserved: %+v", journal)
		}
	})

	t.Run("private marker does not attest a native caller without matching temp scope", func(t *testing.T) {
		bootstrap := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 1))
		initial, err := bootstrap.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := initial.release(); err != nil {
			t.Fatal(err)
		}

		native := newScannerIdentityAllocatorForTest(bootstrap.directory, bootstrap.uidStart, bootstrap.count, testScannerBootID, 17)
		if _, err := native.acquire(context.Background()); err == nil {
			t.Fatal("native caller without the attested private /tmp scope reused a private journal")
		}
		journal, err := readTestScannerIdentityJournal(bootstrap)
		if err != nil {
			t.Fatal(err)
		}
		if !journal.PrivateRuntime || len(journal.Leases) != 0 {
			t.Fatalf("failed native reuse changed private scope: %+v", journal)
		}
	})

	t.Run("non-PID1 caller cannot transition a changed namespace", func(t *testing.T) {
		bootstrap := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 1))
		initial, err := bootstrap.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := initial.release(); err != nil {
			t.Fatal(err)
		}

		changed := useAttestedPrivateScannerScope(newScannerIdentityAllocatorForTest(bootstrap.directory, bootstrap.uidStart, bootstrap.count, testScannerBootID, 18), 18)
		if _, err := changed.acquire(context.Background()); err == nil {
			t.Fatal("non-PID1 caller established a new private namespace scope")
		}
		journal, err := readTestScannerIdentityJournal(bootstrap)
		if err != nil {
			t.Fatal(err)
		}
		if !journal.PrivateRuntime || journal.PIDNamespace != 17 || len(journal.Leases) != 0 {
			t.Fatalf("failed namespace transition changed the attested scope: %+v", journal)
		}
	})
}

func TestHasPrivateScannerTemporaryMount(t *testing.T) {
	for _, test := range []struct {
		name string
		info string
		want bool
	}{
		{name: "private tmpfs", info: "40 30 0:35 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw,size=131072k\n", want: true},
		{name: "shared mount", info: "40 30 0:35 / /tmp rw shared:1 - tmpfs tmpfs rw\n"},
		{name: "slave mount", info: "40 30 0:35 / /tmp rw master:1 - tmpfs tmpfs rw\n"},
		{name: "not tmpfs", info: "40 30 0:35 / /tmp rw - ext4 /dev/sda rw\n"},
		{name: "subpath root", info: "40 30 0:35 /sub /tmp rw - tmpfs tmpfs rw\n"},
		{name: "duplicate mountpoint", info: "40 30 0:35 / /tmp rw - tmpfs tmpfs rw\n41 30 0:36 / /tmp rw - tmpfs tmpfs rw\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := hasPrivateScannerTemporaryMount([]byte(test.info)); got != test.want {
				t.Fatalf("hasPrivateScannerTemporaryMount() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestScannerIdentityAllocatorConcurrentInstancesReserveUniqueSlots(t *testing.T) {
	const count = 12
	allocator := newTestScannerIdentityAllocator(t, count)
	var wait sync.WaitGroup
	results := make(chan *scannerIdentityLease, count)
	errorsSeen := make(chan error, count)
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			instance := newScannerIdentityAllocatorForTest(allocator.directory, allocator.uidStart, allocator.count, testScannerBootID, 17)
			lease, err := instance.acquire(context.Background())
			if err != nil {
				errorsSeen <- err
				return
			}
			results <- lease
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Errorf("concurrent acquire: %v", err)
	}
	seen := make(map[int]bool)
	leases := make([]*scannerIdentityLease, 0, count)
	for lease := range results {
		uid, _, ok := lease.identity()
		if !ok || seen[uid] {
			t.Errorf("duplicate/invalid leased UID %d (valid=%v)", uid, ok)
		}
		seen[uid] = true
		leases = append(leases, lease)
	}
	if len(leases) != count {
		t.Fatalf("obtained %d leases, want %d", len(leases), count)
	}
	for _, lease := range leases {
		if err := lease.release(); err != nil {
			t.Errorf("release concurrent lease: %v", err)
		}
	}
}

func TestScannerIdentityAllocatorRejectsCorruptOrUnsafeState(t *testing.T) {
	t.Run("corrupt journal", func(t *testing.T) {
		allocator := newTestScannerIdentityAllocator(t, 1)
		lease, err := allocator.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(allocator.directory, scannerIdentityJournalName), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := allocator.acquire(context.Background()); err == nil {
			t.Fatal("corrupt same-boot journal was accepted")
		}
		if err := lease.quarantine(); err == nil {
			t.Fatal("quarantine accepted a corrupt journal")
		}
	})

	t.Run("unexpected JSON fields and trailing data", func(t *testing.T) {
		for _, value := range []string{
			`{"version":1,"boot_id":"` + testScannerBootID + `","pid_namespace_inode":17,"leases":{},"extra":true}`,
			`{"version":1,"boot_id":"` + testScannerBootID + `","pid_namespace_inode":17,"leases":{}} {}`,
		} {
			var journal scannerIdentityJournal
			if err := decodeScannerIdentityJSON([]byte(value), &journal); err == nil {
				t.Errorf("accepted noncanonical journal JSON %s", value)
			}
		}
	})

	t.Run("symlinked state directory", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "real")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "leases")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		allocator := newScannerIdentityAllocatorForTest(link, 61000, 1, testScannerBootID, 17)
		if _, err := allocator.acquire(context.Background()); err == nil {
			t.Fatal("symlinked private directory was followed")
		}
	})
}

func TestScannerIdentityIDMapAndAccountRangeValidation(t *testing.T) {
	ranges := []idMapRange{{inside: 0, outside: 60000, length: 100}}
	if !idMapped(ranges, 0) || !idMapped(ranges, 99) || idMapped(ranges, 100) {
		t.Fatalf("idMapped boundary check failed for %+v", ranges)
	}
	for _, value := range []string{"", "0 0 0\n", "0 0 4294967296\n", "x 0 1\n", "0 0 1 extra\n"} {
		path := filepath.Join(t.TempDir(), "id_map")
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readIDMap(path); err == nil {
			t.Errorf("accepted malformed ID map %q", value)
		}
	}
	accountDir := t.TempDir()
	passwdPath := filepath.Join(accountDir, "passwd")
	groupPath := filepath.Join(accountDir, "group")
	if err := os.WriteFile(passwdPath, []byte("edgewatch:x:61001:61000::/nonexistent:/sbin/nologin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(groupPath, []byte("edgewatch:x:61003:scanner\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	used := make(map[uint32]struct{})
	if err := addScannerLocalAccountsInUse(passwdPath, groupPath, 61000, 4, used); err != nil {
		t.Fatal(err)
	}
	if _, ok := used[61001]; !ok {
		t.Fatal("existing account UID was not excluded")
	}
	if _, ok := used[61003]; !ok {
		t.Fatal("existing group GID from the third field was not excluded")
	}
	if err := os.WriteFile(passwdPath, []byte("malformed:account\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := addScannerAccountsInUse(passwdPath, 3, 61000, 2, make(map[uint32]struct{})); err == nil {
		t.Fatal("malformed account database did not fail closed")
	}
}

func readTestScannerIdentityJournal(allocator *scannerIdentityAllocator) (scannerIdentityJournal, error) {
	data, err := os.ReadFile(filepath.Join(allocator.directory, scannerIdentityJournalName))
	if err != nil {
		return scannerIdentityJournal{}, err
	}
	var journal scannerIdentityJournal
	err = json.Unmarshal(data, &journal)
	return journal, err
}

func writeTestScannerIdentityJournal(allocator *scannerIdentityAllocator, journal scannerIdentityJournal) error {
	if err := os.MkdirAll(allocator.directory, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	path := filepath.Join(allocator.directory, scannerIdentityJournalName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
