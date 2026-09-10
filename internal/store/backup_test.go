package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestBackupCreatesVerifiableSnapshotWhileWritesContinue(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	job, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "backup-job", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.10"},
		TCP: &config.Protocol{Ports: "443", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced",
	}))
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		for index := 0; index < 8; index++ {
			when := time.Unix(int64(index+1), 0).UTC()
			scan := model.Scan{ID: "backup-scan-" + string(rune('a'+index)), JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: when, FinishedAt: when, Status: "success", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{Units: []model.Unit{{Target: "198.51.100.10", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}}}}
			if saveErr := s.SaveScan(ctx, scan); saveErr != nil {
				writeDone <- saveErr
				return
			}
		}
		writeDone <- nil
	}()
	backupPath, err := s.Backup(ctx, filepath.Join(dir, "backups", "snapshot.db"))
	if err == nil {
		// The destination directory is intentionally required to exist; create it
		// above would hide deployment mistakes. This first call documents that
		// behavior and the retry below exercises the normal path.
		t.Fatalf("backup unexpectedly succeeded without output directory: %s", backupPath)
	}
	if err := os.Mkdir(filepath.Join(dir, "backups"), 0o750); err != nil {
		t.Fatal(err)
	}
	backupPath, err = s.Backup(ctx, filepath.Join(dir, "backups", "snapshot.db"))
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("concurrent write: %v", err)
	}
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %04o, want 0600", info.Mode().Perm())
	}
	copyStore, err := Open(backupPath)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer copyStore.Close()
	verification, err := copyStore.Verify(ctx)
	if err != nil {
		t.Fatalf("verify backup: %v (%#v)", err, verification)
	}
	if verification.IntegrityCheck != "ok" || len(verification.ForeignKeyViolations) != 0 {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestBackupRejectsUnsafeDestinations(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Backup(context.Background(), database); err == nil {
		t.Fatal("database path was accepted as backup destination")
	}
	if err := os.WriteFile(filepath.Join(dir, "existing.db"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Backup(context.Background(), filepath.Join(dir, "existing.db")); err == nil {
		t.Fatal("existing backup was overwritten")
	}
	if _, err := s.Backup(context.Background(), filepath.Join(dir, "missing", "snapshot.db")); err == nil {
		t.Fatal("missing parent directory was silently created")
	}
}

func TestBackupSupportsMemoryStore(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dir := t.TempDir()
	path, err := s.Backup(context.Background(), filepath.Join(dir, "memory.db"))
	if err != nil {
		t.Fatalf("memory backup: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyReturnsHealthyResult(t *testing.T) {
	s := openTestStore(t)
	result, err := s.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.IntegrityCheck != "ok" || len(result.ForeignKeyViolations) != 0 {
		t.Fatalf("verify result = %#v", result)
	}
	var verificationErr *VerificationError
	if errors.As(err, &verificationErr) {
		t.Fatalf("healthy database returned verification error: %v", verificationErr)
	}
}

func TestVerifyReportsForeignKeyViolations(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.DB.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES('orphan','{}','now')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	result, err := s.Verify(ctx)
	if err == nil {
		t.Fatalf("foreign-key violation was not reported: %#v", result)
	}
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || len(result.ForeignKeyViolations) != 1 {
		t.Fatalf("verification error = %v, result = %#v", err, result)
	}
}
