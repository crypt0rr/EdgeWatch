package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenEnforcesPrivateSQLiteModes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edgewatch.db")
	if err := os.WriteFile(path, []byte{}, 0o666); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.DB.Ping(); err != nil {
		t.Fatal(err)
	}
	if err := assertPrivateMode(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(context.Background(), `CREATE TABLE IF NOT EXISTS permission_probe (id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		if _, statErr := os.Lstat(sidecar); statErr == nil {
			if err := assertPrivateMode(sidecar); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Existing database files are repaired on every startup, not only when
	// SQLite creates a new file.
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := assertPrivateMode(path); err != nil {
		t.Fatal(err)
	}
}

func TestOpenEnforcesPrivateModeForSQLiteURI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uri.db")
	dsn := "file:" + path + "?mode=rwc"
	s, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.DB.Ping(); err != nil {
		t.Fatal(err)
	}
	if err := assertPrivateMode(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dsn); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("SQLite URI was treated as a literal filename: stat=%v", err)
	}
}

func TestOpenSupportsLocalhostSQLiteURI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "localhost.db")
	s, err := Open("file://localhost" + path + "?mode=rwc")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := assertPrivateMode(path); err != nil {
		t.Fatal(err)
	}
}

func TestOpenSupportsSQLiteMemoryURI(t *testing.T) {
	s, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.authKeyPath != "" {
		t.Fatalf("memory database unexpectedly selected auth key path %q", s.authKeyPath)
	}
}

func TestOpenRejectsSQLiteSidecarSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "symlink.db")
	if err := os.WriteFile(path+"-wal", []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + "-wal"); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "outside-wal")
	if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+"-wal"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("sidecar symlink was accepted: %v", err)
	}
}

func TestSQLiteMemoryPathDetectionDoesNotSkipFilesystemNames(t *testing.T) {
	if !isSQLiteMemoryPath(":memory:") || !isSQLiteMemoryPath("file:shared?mode=memory&cache=shared") {
		t.Fatal("memory SQLite paths were not recognized")
	}
	for _, path := range []string{"/tmp/mode=memory.db", "file:disk.db?mode=rwc"} {
		if isSQLiteMemoryPath(path) {
			t.Fatalf("filesystem SQLite path was misclassified as memory: %s", path)
		}
	}
}

func assertPrivateMode(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 || mode&0o700 != 0o600 {
		return fmt.Errorf("%s mode is %o, want 0600", path, mode)
	}
	return nil
}

func TestScanStateAndEventPersistence(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	scan := model.Scan{ID: "scan-1", Job: "job", StartedAt: time.Now(), FinishedAt: time.Now(), Status: "success", ConfigHash: "hash", Snapshot: model.Snapshot{}}
	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetScan(ctx, "scan-1")
	if err != nil || got.Job != "job" {
		t.Fatalf("scan: %#v %v", got, err)
	}
	events, err := s.UpdateState(ctx, "job", func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "scan-1"
		return []model.Event{{Type: "test", Job: "job", ScanID: "scan-1", CreatedAt: time.Now()}}, nil
	})
	if err != nil || len(events) != 1 {
		t.Fatal(err)
	}
	history, err := s.ListEvents(ctx, "job", 10)
	if err != nil || len(history) != 1 {
		t.Fatalf("events: %#v %v", history, err)
	}
}

func TestScanComparisonMetadataRoundTrips(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	wantChange := model.Change{Key: "port|127.0.0.1|tcp|443", Kind: "port", Severity: "critical", Target: "127.0.0.1", Protocol: "tcp", Port: 443, Old: "closed", New: "open"}
	want := model.Scan{ID: "comparison-scan", Job: "job", StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: "scope-hash", BaselineScanID: "baseline-scan", BaselineConfigHash: "baseline-hash", Changes: []model.Change{wantChange}, Snapshot: model.Snapshot{}}
	if err := s.SaveScan(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetScan(ctx, want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.BaselineScanID != want.BaselineScanID || got.BaselineConfigHash != want.BaselineConfigHash || len(got.Changes) != 1 || got.Changes[0] != wantChange {
		t.Fatalf("comparison metadata did not round-trip: %#v", got)
	}
}

func TestScanComparisonQueryDoesNotLoadSnapshot(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	large := model.Snapshot{Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp", Ports: make([]model.PortState, 4096)}}}
	for i := range large.Units[0].Ports {
		large.Units[0].Ports[i] = model.PortState{Port: i + 1, State: "open", Evidence: []string{"127.0.0.1"}}
	}
	scan := model.Scan{ID: "metadata-only", JobID: "job", Job: "job", StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: "scope", BaselineScanID: "baseline", BaselineConfigHash: "scope", Changes: []model.Change{{Key: "port|127.0.0.1|tcp|1", Kind: "port", Severity: "critical", Target: "127.0.0.1", Protocol: "tcp", Port: 1, Old: "closed", New: "open"}}, Snapshot: large}
	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	summary, changes, err := s.GetScanComparison(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ID != scan.ID || summary.BaselineScanID != scan.BaselineScanID || len(changes) != 1 {
		t.Fatalf("unexpected metadata comparison: %#v %#v", summary, changes)
	}
}

func TestScanChangesPagePaginatesWithoutLoadingSnapshot(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	changes := []model.Change{
		{Key: "port|127.0.0.1|tcp|1", Kind: "port", Severity: "critical", Target: "127.0.0.1", Protocol: "tcp", Port: 1, Old: "closed", New: "open"},
		{Key: "port|127.0.0.1|tcp|2", Kind: "port", Severity: "critical", Target: "127.0.0.1", Protocol: "tcp", Port: 2, Old: "closed", New: "open"},
		{Key: "port|127.0.0.1|tcp|3", Kind: "port", Severity: "critical", Target: "127.0.0.1", Protocol: "tcp", Port: 3, Old: "closed", New: "open"},
	}
	large := model.Snapshot{Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp", Ports: make([]model.PortState, 8192)}}}
	if err := s.SaveScan(ctx, model.Scan{ID: "paged-changes", JobID: "job", Job: "job", StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: "scope", BaselineScanID: "baseline", BaselineConfigHash: "scope", Changes: changes, Snapshot: large}); err != nil {
		t.Fatal(err)
	}
	page, err := s.ListScanChangesPage(ctx, "paged-changes", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != len(changes) || len(page.Items) != 1 || page.Items[0].Port != 2 {
		t.Fatalf("unexpected paged changes: %#v", page)
	}
}

func TestScanResultsPagePaginatesSnapshotUnits(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	units := []model.Unit{
		{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}},
		{Target: "192.0.2.2", Protocol: "tcp", Ports: []model.PortState{{Port: 2, State: "open"}}},
	}
	if err := s.SaveScan(ctx, model.Scan{ID: "paged-results", JobID: "job", Job: "job", StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: "scope", Snapshot: model.Snapshot{Units: units}}); err != nil {
		t.Fatal(err)
	}
	page, err := s.ListScanResultsPage(ctx, "paged-results", 1, 1)
	if err != nil || page.Total != len(units) || len(page.Items) != 1 || page.Items[0].Target != "192.0.2.2" {
		t.Fatalf("unexpected paged results: %#v, err=%v", page, err)
	}
}

func TestRuntimeAndNotificationIntentCommitTogether(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("job"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateManagedNotification(ctx, "destination-b", "Test destination", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	destinations := []string{"destination-a", "managed:destination-b:2"}
	events, err := s.UpdateRuntimeWithOutbox(ctx, record.ID, destinations, func(state *model.JobState) ([]model.Event, error) {
		state.ConsecutiveFailures = 3
		return []model.Event{{Type: "alert", Job: "job", ScanID: "scan", Message: "changed", CreatedAt: time.Now().UTC()}}, nil
	})
	if err != nil || len(events) != 1 {
		t.Fatalf("runtime transition: %#v %v", events, err)
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("notification intent rows = %d, want one valid row", count)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil || state.ConsecutiveFailures != 3 {
		t.Fatalf("runtime state: %#v %v", state, err)
	}
}

func TestEventPayloadsAreBoundedWithOverflowSummary(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("bounded-event"))
	if err != nil {
		t.Fatal(err)
	}
	changes := make([]model.Change, 5000)
	for i := range changes {
		changes[i] = model.Change{Key: "port|127.0.0.1|tcp|" + strconv.Itoa(i+1), Kind: "port", Severity: "critical", Target: "127.0.0.1", Protocol: "tcp", Port: i + 1, Old: "closed", New: "open"}
	}
	events, err := s.UpdateRuntimeWithOutbox(ctx, record.ID, []string{"destination"}, func(state *model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "changes-detected", Job: record.Job.Name, Changes: changes, CreatedAt: time.Now().UTC()}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || !events[0].ChangesTruncated || events[0].ChangesCount != len(changes) || len(events[0].Changes) != 0 {
		t.Fatalf("event was not summarized: %#v", events[0])
	}
	var eventPayload, outboxPayload []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT payload_json FROM events WHERE job_id=?`, record.ID).Scan(&eventPayload); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT payload_json FROM outbox WHERE destination=?`, "destination").Scan(&outboxPayload); err != nil {
		t.Fatal(err)
	}
	if len(eventPayload) > model.EventPayloadLimit || len(outboxPayload) > model.EventPayloadLimit {
		t.Fatalf("payload exceeds limit: event=%d outbox=%d", len(eventPayload), len(outboxPayload))
	}
	var stored model.Event
	if err := json.Unmarshal(eventPayload, &stored); err != nil {
		t.Fatal(err)
	}
	if !stored.ChangesTruncated || stored.ChangesCount != len(changes) {
		t.Fatalf("stored overflow summary missing: %#v", stored)
	}
}

func TestDeleteExpiredSessionsKeepsActiveSessions(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.CreateSession(ctx, "expired", "csrf-expired", now.Add(-2*time.Hour), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, "active", "csrf-active", now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	removed, err := s.DeleteExpiredSessions(ctx, now)
	if err != nil || removed != 1 {
		t.Fatalf("removed sessions = %d, err=%v", removed, err)
	}
	if _, err := s.GetSession(ctx, "expired"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session still exists: %v", err)
	}
	if _, err := s.GetSession(ctx, "active"); err != nil {
		t.Fatalf("active session was removed: %v", err)
	}
}

func TestIncidentPagesUseSQLiteJSONPagination(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	first, err := s.CreateJob(ctx, testJob("incident-a"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateJob(ctx, testJob("incident-b"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	makeState := func(jobID string, port int) error {
		_, err := s.UpdateRuntime(ctx, jobID, func(state *model.JobState) ([]model.Event, error) {
			state.Incidents[fmt.Sprintf("port|127.0.0.1|tcp|%d", port)] = model.Incident{Change: model.Change{Key: fmt.Sprintf("port|127.0.0.1|tcp|%d", port), Target: "127.0.0.1", Protocol: "tcp", Port: port, Old: "closed", New: "open", Severity: "critical"}, OpenedAt: now, LastSeenAt: now}
			return nil, nil
		})
		return err
	}
	if err := makeState(first.ID, 1); err != nil {
		t.Fatal(err)
	}
	if err := makeState(second.ID, 2); err != nil {
		t.Fatal(err)
	}
	jobPage, err := s.ListJobIncidentsPage(ctx, first.ID, 1, 0)
	if err != nil || jobPage.Total != 1 || len(jobPage.Items) != 1 || jobPage.Items[0].Change.Port != 1 {
		t.Fatalf("job incident page = %#v, err=%v", jobPage, err)
	}
	globalPage, err := s.ListIncidentsPage(ctx, 1, 1)
	if err != nil || globalPage.Total != 2 || len(globalPage.Items) != 1 || globalPage.Items[0].Job != "incident-b" {
		t.Fatalf("global incident page = %#v, err=%v", globalPage, err)
	}
}

func TestSessionAuditFailureRollsBackAuthenticationMutation(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_session_audit BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	err := s.CreateSessionWithAudit(ctx, "session", "csrf", time.Now().UTC(), time.Now().UTC().Add(time.Hour), "admin.login", "successful login")
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("expected audit failure, got %v", err)
	}
	if _, err := s.GetSession(ctx, "session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session committed despite audit failure: %v", err)
	}
}

func TestFinalizeManagedScanCommitsScanAndRuntimeTogether(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("finalize"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{
		ID: "finalize-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: record.Job.SecurityHash(),
		Snapshot: model.Snapshot{},
	}
	events, err := s.FinalizeManagedScan(ctx, &scan, record.ID, scan.ConfigHash, nil, func(state *model.JobState, current *model.Scan) ([]model.Event, error) {
		state.BaselineScanID = current.ID
		return []model.Event{{Type: "finalized", Job: current.Job, ScanID: current.ID, Message: "finalized", CreatedAt: now}}, nil
	})
	if err != nil || len(events) != 1 {
		t.Fatalf("finalization: %#v %v", events, err)
	}
	if _, err := s.GetScan(ctx, scan.ID); err != nil {
		t.Fatalf("scan was not persisted: %v", err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != scan.ID {
		t.Fatalf("runtime state was not persisted with scan: %#v", state)
	}
	history, err := s.ListJobEvents(ctx, record.ID, 10)
	if err != nil || len(history) != 1 || history[0].JobID != record.ID {
		t.Fatalf("event was not persisted with scan: %#v %v", history, err)
	}
}

func TestFinalizeManagedScanRetainsSupersededScan(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("superseded-finalize"))
	if err != nil {
		t.Fatal(err)
	}
	oldHash := record.Job.SecurityHash()
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, true); err != nil {
		t.Fatal(err)
	}
	scan := model.Scan{
		ID: "superseded-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "success",
		ConfigHash: oldHash, Snapshot: model.Snapshot{},
	}
	_, err = s.FinalizeManagedScan(ctx, &scan, record.ID, oldHash, nil, func(state *model.JobState, current *model.Scan) ([]model.Event, error) {
		t.Fatal("superseded scan mutated runtime")
		return nil, nil
	})
	if !errors.Is(err, ErrJobRevisionChanged) {
		t.Fatalf("expected superseded revision error, got %v", err)
	}
	if _, err := s.GetScan(ctx, scan.ID); err != nil {
		t.Fatalf("superseded scan was not retained: %v", err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "" {
		t.Fatalf("superseded scan mutated runtime state: %#v", state)
	}
}

func TestFinalizeManagedScanSerializesWithBaselineReset(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("finalize-reset"))
	if err != nil {
		t.Fatal(err)
	}
	scan := model.Scan{
		ID: "finalize-reset-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "success",
		ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{},
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	finalizeDone := make(chan error, 1)
	go func() {
		_, finalizeErr := s.FinalizeManagedScan(ctx, &scan, record.ID, scan.ConfigHash, nil, func(state *model.JobState, current *model.Scan) ([]model.Event, error) {
			close(entered)
			<-release
			state.BaselineScanID = current.ID
			return nil, nil
		})
		finalizeDone <- finalizeErr
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("finalization callback did not start")
	}
	resetDone := make(chan error, 1)
	go func() {
		_, resetErr := s.ResetRuntime(ctx, record.ID, record.Job.Name)
		resetDone <- resetErr
	}()
	select {
	case err := <-resetDone:
		t.Fatalf("baseline reset interleaved with finalization: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-finalizeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-resetDone; err != nil {
		t.Fatal(err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "" {
		t.Fatalf("reset did not apply after serialized finalization: %#v", state)
	}
	if _, err := s.GetScan(ctx, scan.ID); err != nil {
		t.Fatalf("scan was not persisted: %v", err)
	}
}

func TestSaveAdminSecurityRollsBackCredentialAndSessionsTogether(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	oldHash := "old-password-hash"
	newHash := "new-password-hash"
	admin := Admin{Username: "admin", PasswordHash: oldHash, CreatedAt: now, UpdatedAt: now}
	if err := s.SaveAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, "session-hash", "csrf", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_security_audit BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	admin.PasswordHash, admin.UpdatedAt = newHash, now.Add(time.Minute)
	if err := s.SaveAdminSecurity(ctx, admin, nil, false, true, "admin.password_changed", "password changed"); err == nil {
		t.Fatal("security mutation unexpectedly committed with a failing audit insert")
	}
	var sessions int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("session revocation was not rolled back: %d", sessions)
	}
	got, err := s.GetAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != oldHash {
		t.Fatal("administrator password changed despite transaction rollback")
	}
}

func TestSaveAdminSecurityRollsBackTOTPWhenRecoveryCodesFail(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	hash := "original-password-hash"
	admin := Admin{Username: "admin", PasswordHash: hash, CreatedAt: now, UpdatedAt: now}
	if err := s.SaveAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_recovery_codes BEFORE INSERT ON recovery_codes BEGIN SELECT RAISE(ABORT, 'recovery codes unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	admin.TOTPSecret, admin.TOTPEnabled, admin.UpdatedAt = "JBSWY3DPEHPK3PXP", true, now.Add(time.Minute)
	if err := s.SaveAdminSecurity(ctx, admin, []string{"code-hash"}, true, false, "admin.totp_enabled", "TOTP enabled"); err == nil {
		t.Fatal("TOTP mutation unexpectedly committed with a failing recovery-code insert")
	}
	got, err := s.GetAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.TOTPEnabled || got.TOTPSecret != "" {
		t.Fatalf("TOTP state changed despite transaction rollback: %#v", got)
	}
	count, err := s.RecoveryCodeCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("recovery codes changed despite transaction rollback: %d", count)
	}
}

func TestSaveAdminSecurityRevokesSessionsOnSuccessfulTOTPChange(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	admin := Admin{Username: "admin", PasswordHash: "password-hash", CreatedAt: now, UpdatedAt: now}
	if err := s.SaveAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, "session-hash", "csrf", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	admin.TOTPSecret, admin.TOTPEnabled, admin.UpdatedAt = "JBSWY3DPEHPK3PXP", true, now.Add(time.Minute)
	if err := s.SaveAdminSecurity(ctx, admin, []string{"code-hash"}, true, true, "admin.totp_enabled", "TOTP enabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "session-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session remained after TOTP change: %v", err)
	}
	if count, err := s.RecoveryCodeCount(ctx); err != nil || count != 1 {
		t.Fatalf("recovery code count = %d, err=%v", count, err)
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action=?`, "admin.totp_enabled")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("audit count query returned no row")
	}
	var audits int
	if err := rows.Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("audit rows = %d, want one", audits)
	}
}

func TestStaleManagedDestinationIntentIsSkipped(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, testJob("stale-destination"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateManagedNotification(ctx, "destination-c", "Test destination", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateManagedNotification(ctx, "destination-c", 1, "Test destination", "generic", []byte{3}, []byte{4}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateRuntimeWithOutbox(ctx, job.ID, []string{"managed:destination-c:1"}, func(state *model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "alert", Job: job.Job.Name, CreatedAt: time.Now().UTC()}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=?`, "managed:destination-c:1").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("stale managed destination was queued: %d", count)
	}
}

func TestBaselineActionsPersistNotificationIntent(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, testJob("baseline-actions"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateManagedNotification(ctx, "baseline-destination", "Test destination", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetRuntimeWithOutbox(ctx, job.ID, job.Job.Name, []string{"managed:baseline-destination:1"}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=?`, "managed:baseline-destination:1").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("reset notification intent rows = %d, want 1", count)
	}
	scan := model.Scan{ID: "baseline-approval-scan", JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "success", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}
	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveRuntimeWithOutbox(ctx, job.ID, job.Job.Name, scan, []string{"managed:baseline-destination:1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=?`, "managed:baseline-destination:1").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("approval notification intent rows = %d, want 2", count)
	}
}

func TestLeaseCanBeReleased(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.AcquireLease(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireLease(ctx, "two"); err == nil {
		t.Fatal("second lease acquired")
	}
	if err := s.ReleaseLease(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireLease(ctx, "two"); err != nil {
		t.Fatal(err)
	}
}

func TestJobLeasePreventsConcurrentRunsAndExpires(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.AcquireJobLease(ctx, "job", "one", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireJobLease(ctx, "job", "two", time.Now().Add(time.Hour)); !errors.Is(err, ErrJobBusy) {
		t.Fatalf("expected busy, got %v", err)
	}
	if _, err := s.DB.Exec(`UPDATE job_leases SET expires_at=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireJobLease(ctx, "job", "two", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("expired lease not replaced: %v", err)
	}
}

func TestOutboxRetriesAndCompletes(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	event := model.Event{Type: "test", Job: "job", CreatedAt: time.Now()}
	if err := s.QueueEvent(ctx, "destination", event); err != nil {
		t.Fatal(err)
	}
	due, err := s.DueDeliveries(ctx, 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due %#v %v", due, err)
	}
	if err := s.DeliveryResult(ctx, due[0].ID, errors.New("failed")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE outbox SET next_at=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	due, err = s.DueDeliveries(ctx, 10)
	if err != nil || len(due) != 1 || due[0].Attempts != 1 {
		t.Fatalf("retry %#v %v", due, err)
	}
	if err := s.DeliveryResult(ctx, due[0].ID, nil); err != nil {
		t.Fatal(err)
	}
	due, _ = s.DueDeliveries(ctx, 10)
	if len(due) != 0 {
		t.Fatal("sent delivery remained due")
	}
}

func TestOutboxClaimsAreExclusiveAndRequireOwner(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.QueueEvent(ctx, "destination", model.Event{Type: "claim", Job: "job", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	first, err := s.ClaimDueDeliveries(ctx, 10, "owner-one")
	if err != nil || len(first) != 1 || first[0].ClaimToken != "owner-one" {
		t.Fatalf("first claim %#v %v", first, err)
	}
	second, err := s.ClaimDueDeliveries(ctx, 10, "owner-two")
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("active claim was handed to another owner: %#v", second)
	}
	if err := s.DeliveryResultClaim(ctx, first[0].ID, "wrong-owner", nil); !errors.Is(err, ErrDeliveryClaimLost) {
		t.Fatalf("wrong owner result = %v, want claim lost", err)
	}
	if err := s.DeliveryResultClaim(ctx, first[0].ID, first[0].ClaimToken, nil); err != nil {
		t.Fatal(err)
	}
	third, err := s.ClaimDueDeliveries(ctx, 10, "owner-three")
	if err != nil {
		t.Fatal(err)
	}
	if len(third) != 0 {
		t.Fatalf("completed delivery remained claimable: %#v", third)
	}
}

func TestDeferredDeliveryDoesNotConsumeAttempts(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.CreateManagedNotification(ctx, "destination", "Test destination", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueEvent(ctx, "managed:destination:1", model.Event{Type: "defer", Job: "job", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	due, err := s.ClaimDueDeliveries(ctx, 1, "owner")
	if err != nil || len(due) != 1 {
		t.Fatalf("claim %#v %v", due, err)
	}
	if err := s.DeferDelivery(ctx, due[0].ID, due[0].ClaimToken, "key unavailable", time.Minute); err != nil {
		t.Fatal(err)
	}
	var attempts int
	if err := s.DB.QueryRowContext(ctx, `SELECT attempts FROM outbox WHERE id=?`, due[0].ID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("deferred attempts = %d, want 0", attempts)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE id=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), due[0].ID); err != nil {
		t.Fatal(err)
	}
	if retry, err := s.ClaimDueDeliveries(ctx, 1, "retry-owner"); err != nil || len(retry) != 1 {
		t.Fatalf("deferred row was not retryable: %#v %v", retry, err)
	}
}

func TestPrunePreservesLegacyAndManagedBaselines(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	old := time.Now().UTC().Add(-48 * time.Hour)
	for _, id := range []string{"legacy-baseline", "managed-baseline", "discard"} {
		if err := s.SaveScan(ctx, model.Scan{ID: id, Job: "legacy", StartedAt: old, FinishedAt: old, Status: "success", Snapshot: model.Snapshot{}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.UpdateState(ctx, "legacy", func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "legacy-baseline"
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	managed, err := s.CreateJob(ctx, testJob("managed"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateRuntime(ctx, managed.ID, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "managed-baseline"
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prune(ctx, time.Now().UTC().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"legacy-baseline", "managed-baseline"} {
		if _, err := s.GetScan(ctx, id); err != nil {
			t.Fatalf("baseline scan %s was pruned: %v", id, err)
		}
	}
	if _, err := s.GetScan(ctx, "discard"); err == nil {
		t.Fatal("unreferenced old scan was not pruned")
	}
}

func TestPruneRetentionClassesAndAuditPolicy(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	old := time.Now().UTC().Add(-48 * time.Hour)
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	oldText := old.Format(time.RFC3339Nano)

	job, err := s.CreateJob(ctx, testJob("retention"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobEnabledWithRevision(ctx, job.ID, false, job.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_revisions SET created_at=? WHERE job_id=? AND revision=1`, oldText, job.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.DB.ExecContext(ctx, `INSERT INTO events(type,job,payload_json,created_at) VALUES(?,?,?,?)`, "old-event", "retention", []byte(`{}`), oldText); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO security_audit(action,detail,created_at) VALUES(?,?,?)`, "old-audit", "keep", oldText); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueEvent(ctx, "sent", model.Event{Type: "sent", Job: "retention", CreatedAt: old}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET sent_at=? WHERE destination=?`, oldText, "sent"); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueEvent(ctx, "failed", model.Event{Type: "failed", Job: "retention", CreatedAt: old}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET attempts=3,next_at=? WHERE destination=?`, oldText, "failed"); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueEvent(ctx, "pending", model.Event{Type: "pending", Job: "retention", CreatedAt: old}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE destination=?`, oldText, "pending"); err != nil {
		t.Fatal(err)
	}

	stats, err := s.PruneWithStats(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Events != 1 || stats.SentOutbox != 1 || stats.FailedOutbox != 1 || stats.Revisions != 1 {
		t.Fatalf("unexpected prune stats: %#v", stats)
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=?`, "pending").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("pending delivery was pruned")
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action=?`, "old-audit").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("security audit record was pruned")
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_revisions WHERE job_id=?`, job.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("current job revision was pruned; rows=%d", count)
	}
}

func TestPruneRetainsRevisionsReferencedByScans(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, testJob("revision-reference"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobEnabledWithRevision(ctx, job.ID, false, job.Revision); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_revisions SET created_at=? WHERE job_id=? AND revision=1`, old, job.ID); err != nil {
		t.Fatal(err)
	}
	scan := model.Scan{ID: "retained-revision-scan", JobID: job.ID, Job: job.Job.Name, JobRevision: 1, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "success", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}
	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	stats, err := s.PruneWithStats(ctx, time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Revisions != 0 {
		t.Fatalf("referenced revision was pruned: %#v", stats)
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_revisions WHERE job_id=? AND revision=1`, job.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("revision referenced by retained scan was removed")
	}
}

func TestHistoryPagesHaveStableMetadataAndOrdering(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("paged"))
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := s.SaveScan(ctx, model.Scan{ID: string(rune('a' + i)), JobID: record.ID, JobRevision: 1, Job: record.Job.Name, StartedAt: when, FinishedAt: when, Status: "success", Snapshot: model.Snapshot{}}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
			return []model.Event{{Type: "page", Job: record.Job.Name, CreatedAt: when}}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ListJobScansPage(ctx, record.ID, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || len(page.Items) != 2 || page.Items[0].ID != "b" || page.Items[1].ID != "a" {
		t.Fatalf("unexpected scan page: total=%d items=%#v", page.Total, page.Items)
	}
	summaryPage, err := s.ListJobScanSummariesPage(ctx, record.ID, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if summaryPage.Total != 3 || len(summaryPage.Items) != 2 || summaryPage.Items[0].ID != "b" || summaryPage.Items[1].ID != "a" {
		t.Fatalf("unexpected scan summary page: total=%d items=%#v", summaryPage.Total, summaryPage.Items)
	}
	rawSummary, err := json.Marshal(summaryPage.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawSummary, []byte(`"snapshot"`)) {
		t.Fatal("scan summary unexpectedly contains a snapshot")
	}
	events, err := s.ListJobEventsPage(ctx, record.ID, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if events.Total != 3 || len(events.Items) != 2 {
		t.Fatalf("unexpected event page: total=%d items=%#v", events.Total, events.Items)
	}
}
