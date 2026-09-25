package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	if result.SidecarsWarning == "" || len(result.SidecarsPresent) != 0 || len(result.SidecarsRemoved) != 1 {
		t.Fatalf("explicit recovery result = %#v", result)
	}
	if _, err := os.Stat(destination + "-shm"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit recovery left destination sidecar: %v", err)
	}
}

func TestRestoreSidecarReplayIncludesSourceWALAndRemovesDestinationSidecars(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "destination.db")
	sourceStore, err := Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceStore.Close()
	createRestoreFixture(t, destination, "destination")
	if _, err := sourceStore.DB.Exec(`PRAGMA wal_autocheckpoint=0; CREATE TABLE wal_only(value TEXT NOT NULL); INSERT INTO wal_only(value) VALUES('from WAL');`); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(source + "-wal"); err != nil {
		t.Fatalf("source WAL was not created: %v", err)
	}
	if err := os.WriteFile(destination+"-shm", []byte("stale destination sidecar"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Restore(context.Background(), source, destination, RestoreOptions{AllowSidecarReplay: true})
	if err != nil {
		t.Fatalf("WAL replay restore: %v", err)
	}
	if len(result.SidecarsPresent) == 0 || len(result.SidecarsRemoved) != 1 {
		t.Fatalf("WAL replay sidecars = %#v", result)
	}
	if _, err := os.Stat(destination + "-shm"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old destination sidecar remains before opening restored database: %v", err)
	}
	reader, err := OpenReadOnlyExisting(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var value string
	if err := reader.DB.QueryRow(`SELECT value FROM wal_only`).Scan(&value); err != nil {
		t.Fatalf("WAL-only row was lost: %v", err)
	}
	if value != "from WAL" {
		t.Fatalf("WAL-only row = %q", value)
	}
}

func TestRestoreRejectsForeignAndNewerSchemaBeforeReplacement(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "destination.db")
	createRestoreFixture(t, destination, "destination")
	before, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}

	foreign := filepath.Join(dir, "foreign.db")
	raw, err := sql.Open("sqlite", foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE unrelated(id INTEGER PRIMARY KEY, value TEXT)`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), foreign, destination, RestoreOptions{}); err == nil || !strings.Contains(err.Error(), "not an EdgeWatch database") {
		t.Fatalf("foreign restore error = %v", err)
	}
	after, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("foreign restore changed destination")
	}

	newer := filepath.Join(dir, "newer.db")
	createRestoreFixture(t, newer, "newer")
	raw, err = sql.Open("sqlite", newer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`PRAGMA user_version = 999`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), newer, destination, RestoreOptions{}); err == nil || !strings.Contains(err.Error(), "unsupported schema version") {
		t.Fatalf("newer-schema restore error = %v", err)
	}
	after, err = fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("newer-schema restore changed destination")
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

func TestRestoreInvalidatesSessionsCopiedFromBackup(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "destination.db")
	createRestoreFixture(t, source, "source")
	createRestoreFixture(t, destination, "destination")
	sourceStore, err := Open(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceStore.CreateSession(context.Background(), "restored-session", "csrf", time.Now().UTC(), time.Now().UTC().Add(time.Hour)); err != nil {
		sourceStore.Close()
		t.Fatal(err)
	}
	if err := sourceStore.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), source, destination, RestoreOptions{}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restored, err := OpenReadOnlyExisting(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if _, err := restored.GetSession(context.Background(), "restored-session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("restored bearer session = %v, want ErrNotFound", err)
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

// A backup taken from a running daemon carries that daemon's fresh heartbeat
// and its scan leases. The restored file has no process attached, so none of
// those claims may survive: the next daemon must start at once, a repeat
// restore onto the stopped destination must not see a live daemon, and copied
// scan leases must not block scans. The destination's own live lease is still
// refused.
func TestRestoreClearsLeasesCopiedFromLiveDaemonBackup(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	live := filepath.Join(dir, "live.db")
	createRestoreFixture(t, live, "source")
	liveStore, err := Open(live)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	if _, err := liveStore.AcquireDaemonLease(ctx, "old-daemon"); err != nil {
		liveStore.Close()
		t.Fatal(err)
	}
	for job, owner := range map[string]string{"daemon-job": "daemon/old-daemon/scan-1", "cli-job": "cli-scan-2"} {
		if err := liveStore.AcquireJobLease(ctx, job, owner, expires); err != nil {
			liveStore.Close()
			t.Fatal(err)
		}
	}
	backup, err := liveStore.Backup(ctx, filepath.Join(dir, "backup.db"))
	if err != nil {
		liveStore.Close()
		t.Fatal(err)
	}
	if err := liveStore.Close(); err != nil {
		t.Fatal(err)
	}

	destination := filepath.Join(dir, "restored.db")
	options := RestoreOptions{PendingDeliveries: PendingDeliveriesDiscard}
	if _, err := Restore(ctx, backup, destination, options); err != nil {
		t.Fatalf("first restore: %v", err)
	}
	// The operator restored and immediately retries, for example with another
	// backup. Nothing runs on the destination, so the retry must not be refused.
	if dryRun, err := DryRunRestore(ctx, backup, destination, options); err != nil || !dryRun.Safe {
		t.Fatalf("repeat restore dry run = %#v, %v; want safe", dryRun, err)
	}
	if _, err := Restore(ctx, backup, destination, options); err != nil {
		t.Fatalf("repeat restore onto a stopped destination: %v", err)
	}
	if got, err := readRestoreValue(destination); err != nil || got != "source" {
		t.Fatalf("restored value = %q, %v; want source", got, err)
	}

	if err := CheckDaemonLeaseBeforeStartup(ctx, destination); err != nil {
		t.Fatalf("startup lease check after restore: %v", err)
	}
	restored, err := Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restored.AcquireDaemonLease(ctx, "new-daemon"); err != nil {
		restored.Close()
		t.Fatalf("new daemon lease after restore: %v", err)
	}
	for _, job := range []string{"daemon-job", "cli-job"} {
		if active, err := restored.JobActive(ctx, job); err != nil || active {
			restored.Close()
			t.Fatalf("restored job %s active = %v, %v; want copied lease cleared", job, active, err)
		}
		if err := restored.AcquireJobLease(ctx, job, "daemon/new-daemon/"+job, expires); err != nil {
			restored.Close()
			t.Fatalf("scan lease for %s after restore: %v", job, err)
		}
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}

	// The daemon started on the restored database now holds a fresh lease of
	// its own. That lease still protects the destination.
	before, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, backup, destination, options); !errors.Is(err, ErrRestoreDaemonLive) {
		t.Fatalf("restore over the restored daemon = %v, want ErrRestoreDaemonLive", err)
	}
	if after, err := fileDigest(destination); err != nil || after != before {
		t.Fatalf("refused restore changed the destination: %v", err)
	}

	// Restore reads the backup and never changes it.
	source, err := OpenReadOnlyExisting(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	status, err := source.DaemonLeaseStatus(ctx)
	if err != nil || status.Owner != "old-daemon" {
		t.Fatalf("backup daemon lease = %#v, %v; want old-daemon kept in the backup", status, err)
	}
}

// Clearing the copied leases is part of the staged sanitization. When it
// fails, both the dry run and the restore refuse, and the destination is not
// replaced.
func TestRestoreLeaseCleanupFailureLeavesDestinationUnchanged(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "destination.db")
	createRestoreFixture(t, source, "source")
	createRestoreFixture(t, destination, "destination")
	raw, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO daemon_lease(id,owner,heartbeat) VALUES(1,'old-daemon',?);
CREATE TRIGGER keep_daemon_lease BEFORE DELETE ON daemon_lease BEGIN SELECT RAISE(ABORT, 'lease row is protected'); END`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DryRunRestore(ctx, source, destination, RestoreOptions{}); err == nil || !strings.Contains(err.Error(), "clear restored daemon_lease") {
		t.Fatalf("dry run error = %v, want the lease cleanup failure", err)
	}
	if _, err := Restore(ctx, source, destination, RestoreOptions{}); err == nil || !strings.Contains(err.Error(), "clear restored daemon_lease") {
		t.Fatalf("restore error = %v, want the lease cleanup failure", err)
	}
	if after, err := fileDigest(destination); err != nil || after != before {
		t.Fatalf("failed lease cleanup changed the destination: %v", err)
	}
}

func TestClearRestoredLeasesSkipsMissingTablesAndReportsErrors(t *testing.T) {
	ctx := context.Background()
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "no-leases.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tx, err := raw.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := clearRestoredLeasesTx(ctx, tx); err != nil {
		t.Fatalf("clear leases without lease tables: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := clearRestoredLeasesTx(ctx, tx); err == nil {
		t.Fatal("clearing leases in a finished transaction succeeded")
	}
}

func TestRestoreCanReplaceUnreadableDestinationAfterExplicitConfirmation(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "damaged.db")
	createRestoreFixture(t, source, "source")
	if err := os.WriteFile(destination, []byte("not a usable EdgeWatch database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), source, destination, RestoreOptions{}); !errors.Is(err, ErrRestoreDestinationUnreadable) {
		t.Fatalf("damaged destination error = %v, want ErrRestoreDestinationUnreadable", err)
	}
	if got, err := os.ReadFile(destination); err != nil || string(got) != "not a usable EdgeWatch database" {
		t.Fatalf("refused restore changed damaged destination: %q, %v", got, err)
	}
	result, err := Restore(context.Background(), source, destination, RestoreOptions{AllowUnreadableDestination: true})
	if err != nil {
		t.Fatalf("explicit damaged-destination recovery: %v", err)
	}
	if result.Bytes == 0 {
		t.Fatal("recovery copied no database bytes")
	}
	if got, err := readRestoreValue(destination); err != nil || got != "source" {
		t.Fatalf("recovered destination value = %q, %v; want source", got, err)
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

func TestReadOnlyVerificationCleansProbeSidecarsForSafeRestore(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("probe sidecar cleanup needs Linux open file description locks; other systems keep the sidecars")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "destination.db")
	createRestoreFixture(t, source, "source")
	createRestoreFixture(t, destination, "destination")

	reader, err := OpenReadOnlyExisting(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Verify(context.Background()); err != nil {
		_ = reader.Close()
		t.Fatalf("verify: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close read-only verifier: %v", err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(source + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read-only verifier left %s: %v", suffix, err)
		}
	}

	preflight, err := PreflightRestore(context.Background(), source, destination)
	if err != nil {
		t.Fatal(err)
	}
	if !preflight.Safe || len(preflight.SourceSidecars) != 0 || len(preflight.DestinationSidecars) != 0 {
		t.Fatalf("preflight after read-only verification = %#v", preflight)
	}
	if _, err := Restore(context.Background(), source, destination, RestoreOptions{}); err != nil {
		t.Fatalf("restore after read-only verification: %v", err)
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

func TestRestoreSidecarErrorPathsAreRecoverable(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing-wal")
	if _, err := moveDestinationSidecars([]RestoreSidecar{{Kind: "wal", Path: missing}}, dir); err == nil {
		t.Fatal("missing destination sidecar was staged")
	}

	original := filepath.Join(dir, "original")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(dir, "moved")
	if err := os.WriteFile(moved, []byte("sidecar"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreDestinationSidecars([]movedRestoreSidecar{{original: original, moved: moved}}); err == nil {
		t.Fatal("sidecar restore over a directory unexpectedly succeeded")
	}
	pending := true
	restoreSidecarsOnFailure(&pending, []movedRestoreSidecar{{original: filepath.Join(dir, "not-there"), moved: filepath.Join(dir, "also-not-there")}})
	pending = false
	restoreSidecarsOnFailure(&pending, nil)

	if _, err := validateStagedRestore(context.Background(), filepath.Join(dir, "does-not-exist.db")); err == nil {
		t.Fatal("missing staged restore database was accepted")
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
