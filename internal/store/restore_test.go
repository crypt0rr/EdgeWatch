package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreflightRestoreReportsEverySQLiteSidecarWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "destination.db")
	createRestoreFixture(t, source, "source")
	createRestoreFixture(t, destination, "destination")
	before, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		path := destination + suffix
		if err := os.WriteFile(path, []byte("stale-"+suffix), 0o600); err != nil {
			t.Fatal(err)
		}
		// A future timestamp is diagnostic evidence that the sidecar is newer,
		// but it must not be the only reason the preflight refuses the restore.
		if err := os.Chtimes(path, time.Now().Add(time.Minute), time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}

	preflight, err := PreflightRestore(context.Background(), source, destination)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if preflight.Safe || len(preflight.DestinationSidecars) != 3 || len(preflight.SourceSidecars) != 0 {
		t.Fatalf("preflight = %#v", preflight)
	}
	for _, sidecar := range preflight.DestinationSidecars {
		if !sidecar.NewerThanDatabase {
			t.Fatalf("sidecar %s was not marked newer than the database", sidecar.Path)
		}
	}
	after, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("preflight changed destination digest from %s to %s", before, after)
	}
}

func TestRestoreRejectsAmbiguousSidecarsAndCopiesExactSnapshot(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "destination.db")
	createRestoreFixture(t, source, "source")
	createRestoreFixture(t, destination, "destination")
	if err := os.WriteFile(destination+"-wal", []byte("stale WAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Restore(context.Background(), source, destination, RestoreOptions{})
	if !errors.Is(err, ErrRestoreSidecars) {
		t.Fatalf("restore error = %v, want ErrRestoreSidecars", err)
	}
	after, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("refused restore changed destination digest from %s to %s", before, after)
	}
	if _, err := os.Stat(destination + "-wal"); err != nil {
		t.Fatalf("refused restore removed sidecar: %v", err)
	}

	if err := os.Remove(destination + "-wal"); err != nil {
		t.Fatal(err)
	}
	result, err := Restore(context.Background(), source, destination, RestoreOptions{})
	if err != nil {
		t.Fatalf("restore after sidecar removal: %v", err)
	}
	if result.Bytes == 0 || result.SidecarsWarning != "" {
		t.Fatalf("restore result = %#v", result)
	}
	got, err := readRestoreValue(destination)
	if err != nil {
		t.Fatal(err)
	}
	if got != "source" {
		t.Fatalf("restored value = %q, want source", got)
	}
}

func TestPreflightRestoreDetectsDanglingSidecarsWhenDatabaseWasMoved(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "destination.db")
	createRestoreFixture(t, source, "source")
	if err := os.WriteFile(destination+"-wal", []byte("dangling stale WAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	preflight, err := PreflightRestore(context.Background(), source, destination)
	if err != nil {
		t.Fatalf("preflight dangling sidecar: %v", err)
	}
	if preflight.Safe || preflight.DestinationExists || len(preflight.DestinationSidecars) != 1 {
		t.Fatalf("dangling-sidecar preflight = %#v", preflight)
	}
	if _, err := Restore(context.Background(), source, destination, RestoreOptions{}); !errors.Is(err, ErrRestoreSidecars) {
		t.Fatalf("dangling-sidecar restore error = %v, want ErrRestoreSidecars", err)
	}
}

func TestRestoreAllowsExplicitCrashRecoverySidecarReplay(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "destination.db")
	createRestoreFixture(t, source, "source")
	createRestoreFixture(t, destination, "destination")
	if err := os.WriteFile(destination+"-shm", []byte("intentional recovery set"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Restore(context.Background(), source, destination, RestoreOptions{AllowSidecarReplay: true})
	if err != nil {
		t.Fatalf("explicit recovery restore: %v", err)
	}
	if result.SidecarsWarning == "" || len(result.SidecarsPresent) != 1 {
		t.Fatalf("explicit recovery result = %#v", result)
	}
	if _, err := os.Stat(destination + "-shm"); err != nil {
		t.Fatalf("explicit recovery removed sidecar: %v", err)
	}
}

func TestRestoreQuarantinesPendingDeliveriesByDefault(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "destination.db")
	createRestoreFixture(t, source, "source")
	createRestoreFixture(t, destination, "destination")
	addRestorePendingDelivery(t, source, "managed:alerts:1")

	result, err := Restore(context.Background(), source, destination, RestoreOptions{})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if result.PendingDeliveriesPolicy != PendingDeliveriesQuarantine || result.PendingDeliveriesAffected != 1 || result.RestoreEpoch == "" {
		t.Fatalf("restore result = %#v", result)
	}
	reader, err := OpenReadOnlyExisting(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var pending, quarantined, epochs int
	if err := reader.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := reader.DB.QueryRow(`SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE restore_epoch=?`, result.RestoreEpoch).Scan(&quarantined); err != nil {
		t.Fatal(err)
	}
	if err := reader.DB.QueryRow(`SELECT COUNT(*) FROM restore_epochs WHERE epoch=? AND pending_delivery_policy=? AND pending_delivery_count=1`, result.RestoreEpoch, PendingDeliveriesQuarantine).Scan(&epochs); err != nil {
		t.Fatal(err)
	}
	if pending != 0 || quarantined != 1 || epochs != 1 {
		t.Fatalf("pending/quarantined/epoch rows = %d/%d/%d", pending, quarantined, epochs)
	}
	var detail, actor string
	if err := reader.DB.QueryRow(`SELECT detail,actor_username FROM security_audit WHERE action='database.restore.pending_deliveries' ORDER BY id DESC LIMIT 1`).Scan(&detail, &actor); err != nil {
		t.Fatal(err)
	}
	if actor != "host-cli" || !strings.Contains(detail, "pending_deliveries=quarantine") || strings.Contains(detail, source) || strings.Contains(detail, "stale") {
		t.Fatalf("restore audit detail leaked data: actor=%q detail=%q", actor, detail)
	}
}

func TestRestorePendingDeliveryPoliciesAreExplicit(t *testing.T) {
	for _, test := range []struct {
		name   string
		policy PendingDeliveryPolicy
		outbox int
		stash  int
	}{
		{name: "discard", policy: PendingDeliveriesDiscard, outbox: 0, stash: 0},
		{name: "preserve", policy: PendingDeliveriesPreserve, outbox: 1, stash: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "source.db")
			destination := filepath.Join(dir, "destination.db")
			createRestoreFixture(t, source, "source")
			createRestoreFixture(t, destination, "destination")
			addRestorePendingDelivery(t, source, "managed:alerts:1")
			result, err := Restore(context.Background(), source, destination, RestoreOptions{PendingDeliveries: test.policy})
			if err != nil {
				t.Fatalf("restore: %v", err)
			}
			if result.PendingDeliveriesPolicy != test.policy || result.PendingDeliveriesAffected != 1 {
				t.Fatalf("restore result = %#v", result)
			}
			reader, err := OpenReadOnlyExisting(destination)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			var outbox, stash int
			if err := reader.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL`).Scan(&outbox); err != nil {
				t.Fatal(err)
			}
			if err := reader.DB.QueryRow(`SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE restore_epoch=?`, result.RestoreEpoch).Scan(&stash); err != nil {
				t.Fatal(err)
			}
			if outbox != test.outbox || stash != test.stash {
				t.Fatalf("outbox/quarantine rows = %d/%d, want %d/%d", outbox, stash, test.outbox, test.stash)
			}
		})
	}
}

func TestParsePendingDeliveryPolicy(t *testing.T) {
	if policy, err := ParsePendingDeliveryPolicy(""); err != nil || policy != PendingDeliveriesQuarantine {
		t.Fatalf("empty policy = %q, %v", policy, err)
	}
	if policy, err := ParsePendingDeliveryPolicy(" PRESERVE "); err != nil || policy != PendingDeliveriesPreserve {
		t.Fatalf("normalized policy = %q, %v", policy, err)
	}
	if _, err := ParsePendingDeliveryPolicy("replay"); err == nil {
		t.Fatal("invalid policy unexpectedly accepted")
	}
}

func TestRestoreRefusesLiveDaemonLeaseUnlessExplicitlyOverridden(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "destination.db")
	createRestoreFixture(t, source, "source")
	createRestoreFixture(t, destination, "destination")
	ownerStore, err := Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerStore.AcquireDaemonLease(context.Background(), "live-daemon"); err != nil {
		ownerStore.Close()
		t.Fatal(err)
	}
	if err := ownerStore.Close(); err != nil {
		t.Fatal(err)
	}

	before, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), source, destination, RestoreOptions{}); !errors.Is(err, ErrRestoreDaemonLive) {
		t.Fatalf("live-daemon restore error = %v, want ErrRestoreDaemonLive", err)
	}
	after, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("refused live-daemon restore changed destination digest from %s to %s", before, after)
	}

	// The read-only liveness probe may leave SQLite WAL/SHM companions on a
	// WAL-mode database. Override both independent safety checks explicitly so
	// this assertion exercises the daemon guard rather than sidecar handling.
	if _, err := Restore(context.Background(), source, destination, RestoreOptions{AllowActiveDaemon: true, AllowSidecarReplay: true}); err != nil {
		t.Fatalf("explicit live-daemon recovery override: %v", err)
	}
	if got, err := readRestoreValue(destination); err != nil || got != "source" {
		t.Fatalf("overridden restore value = %q, %v; want source", got, err)
	}
}

func TestVerifyDoesNotChangeReadOnlyDatabaseBytesOrMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "readonly.db")
	createRestoreFixture(t, path, "read-only")
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	digestBefore, err := fileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	modeBefore, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Verify(context.Background()); err != nil {
		reader.Close()
		t.Fatalf("verify: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	digestAfter, err := fileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	modeAfter, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if digestBefore != digestAfter {
		t.Fatalf("verify changed digest from %s to %s", digestBefore, digestAfter)
	}
	if modeBefore.Mode().Perm() != modeAfter.Mode().Perm() {
		t.Fatalf("verify changed permissions from %04o to %04o", modeBefore.Mode().Perm(), modeAfter.Mode().Perm())
	}
}

func TestPreflightRestoreAcceptsReadOnlySource(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "readonly-source.db")
	destination := filepath.Join(dir, "restored.db")
	createRestoreFixture(t, source, "read-only source")
	if err := os.Chmod(source, 0o400); err != nil {
		t.Fatal(err)
	}
	preflight, err := PreflightRestore(context.Background(), source, destination)
	if err != nil {
		t.Fatalf("preflight read-only source: %v", err)
	}
	if !preflight.Safe || !preflight.SourceExists || preflight.DestinationExists {
		t.Fatalf("read-only preflight = %#v", preflight)
	}
}

func TestPreflightRestoreRejectsNonSQLiteSource(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "not-a-database.db")
	destination := filepath.Join(dir, "destination.db")
	if err := os.WriteFile(source, []byte("not SQLite"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := PreflightRestore(context.Background(), source, destination); err == nil {
		t.Fatal("non-SQLite source was accepted")
	}
}

func createRestoreFixture(t *testing.T, path, value string) {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TABLE restore_fixture (value TEXT NOT NULL); INSERT INTO restore_fixture(value) VALUES (?)`, value); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func addRestorePendingDelivery(t *testing.T, path, destination string) {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB.Exec(`INSERT INTO outbox(destination,payload_json,attempts,next_at) VALUES(?,?,0,?)`, destination, []byte(`{"type":"stale","message":"stale"}`), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func readRestoreValue(path string) (string, error) {
	s, err := OpenReadOnlyExisting(path)
	if err != nil {
		return "", err
	}
	defer s.Close()
	var value string
	err = s.DB.QueryRow(`SELECT value FROM restore_fixture`).Scan(&value)
	return value, err
}

func fileDigest(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(contents)), nil
}
