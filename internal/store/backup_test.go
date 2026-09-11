package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestBackupCreatesVerifiableSnapshotsWithIndependentConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	writer, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	backupStore, err := OpenExistingContext(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer backupStore.Close()
	job, err := writer.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "backup-job", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"198.51.100.10"},
		TCP: &config.Protocol{Ports: "443", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "backups"), 0o750); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	stop := make(chan struct{})
	writeDone := make(chan error, 1)
	var writes atomic.Int64
	go func() {
		defer close(writeDone)
		for index := 0; ; index++ {
			select {
			case <-stop:
				writeDone <- nil
				return
			default:
			}
			when := time.Unix(int64(index+1), 0).UTC()
			scan := model.Scan{ID: "backup-scan-" + string(rune('a'+index)), JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: when, FinishedAt: when, Status: "success", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{Units: []model.Unit{{Target: "198.51.100.10", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}}}}
			if saveErr := writer.SaveScan(ctx, scan); saveErr != nil {
				writeDone <- saveErr
				return
			}
			if writes.Add(1) == 1 {
				close(started)
			}
		}
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("writer did not commit before the backup pass")
	}
	backupPaths := make([]string, 0, 3)
	for index := 0; index < 3; index++ {
		backupPath := filepath.Join(dir, "backups", fmt.Sprintf("snapshot-%d.db", index))
		backupPath, err = backupStore.Backup(ctx, backupPath)
		if err != nil {
			close(stop)
			<-writeDone
			t.Fatalf("backup %d: %v", index, err)
		}
		backupPaths = append(backupPaths, backupPath)
	}
	close(stop)
	if err := <-writeDone; err != nil {
		t.Fatalf("concurrent write: %v", err)
	}
	if writes.Load() < 1 {
		t.Fatal("writer did not commit representative scan data")
	}
	for index, backupPath := range backupPaths {
		info, err := os.Stat(backupPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("backup %d mode = %04o, want 0600", index, info.Mode().Perm())
		}
		copyStore, err := OpenReadOnlyExisting(backupPath)
		if err != nil {
			t.Fatalf("open backup %d: %v", index, err)
		}
		verification, verifyErr := copyStore.Verify(ctx)
		closeErr := copyStore.Close()
		if verifyErr != nil {
			t.Fatalf("verify backup %d: %v (%#v)", index, verifyErr, verification)
		}
		if closeErr != nil {
			t.Fatalf("close backup %d: %v", index, closeErr)
		}
		if verification.IntegrityCheck != "ok" || len(verification.ForeignKeyViolations) != 0 {
			t.Fatalf("verification %d = %#v", index, verification)
		}
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
