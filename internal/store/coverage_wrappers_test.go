package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestAtomicWriteJSONAndOpenExistingGuards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.json")
	got, err := AtomicWriteJSON(path, ".edgewatch-json-", func(w io.Writer) error {
		_, err := io.WriteString(w, `{"ok":true}`)
		return err
	})
	if err != nil || got != path {
		t.Fatalf("AtomicWriteJSON = %q, %v", got, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != `{"ok":true}` {
		t.Fatalf("JSON output = %q, %v", raw, err)
	}
	if _, err := AtomicWriteJSON(filepath.Join(dir, "nil.json"), "", nil); err == nil {
		t.Fatal("nil JSON marshaler was accepted")
	}
	if _, err := OpenExisting(filepath.Join(dir, "missing.db")); err == nil {
		t.Fatal("OpenExisting accepted a missing database")
	}
	dbPath := filepath.Join(dir, "existing.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	existing, err := OpenExisting(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := existing.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryCodeTextConsumptionSupportsLegacyAndSaltedForms(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	userID := LegacyAdminUserID
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	legacyCode := "LEGACY-CODE"
	legacySum := sha256.Sum256([]byte(legacyCode))
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO recovery_codes(id_hash,user_id) VALUES(?,?)`, hex.EncodeToString(legacySum[:]), userID); err != nil {
		t.Fatal(err)
	}
	if matched, err := s.ConsumeRecoveryCodeTextForUser(ctx, userID, "wrong", now); err != nil || matched {
		t.Fatalf("wrong legacy code = %t, %v", matched, err)
	}
	if matched, err := s.ConsumeRecoveryCodeTextForUser(ctx, userID, legacyCode, now); err != nil || !matched {
		t.Fatalf("legacy code = %t, %v", matched, err)
	}
	if matched, err := s.ConsumeRecoveryCodeTextForUser(ctx, userID, legacyCode, now); err != nil || matched {
		t.Fatalf("consumed legacy code = %t, %v", matched, err)
	}
	if matched, err := s.ConsumeRecoveryCodeTextForUser(ctx, userID, "", now); err != nil || matched {
		t.Fatalf("empty recovery code = %t, %v", matched, err)
	}

	salt := []byte("0123456789abcdef")
	h := sha256.New()
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte("SALTED-CODE"))
	value := "v2$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + hex.EncodeToString(h.Sum(nil))
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO recovery_codes(id_hash,user_id) VALUES(?,?)`, value, userID); err != nil {
		t.Fatal(err)
	}
	if matched, err := s.ConsumeRecoveryCodeTextForUser(ctx, userID, "salted-code", now); err != nil || !matched {
		t.Fatalf("salted code = %t, %v", matched, err)
	}
	if matched, err := s.ConsumeRecoveryCodeTextForUser(ctx, "other-user", "SALTED-CODE", now); err != nil || matched {
		t.Fatalf("wrong user code = %t, %v", matched, err)
	}
}

func TestBaselineRuntimeAndCycleProjectionWrappers(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	if exists, err := s.BaselineHostProjectionExists(ctx, job.ID); err != nil || exists {
		t.Fatalf("empty baseline projection = %t, %v", exists, err)
	}
	snapshot := model.Snapshot{Hosts: []model.HostObservation{{Address: "192.0.2.1", AddressFamily: "ipv4", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}}}
	if err := s.ReplaceBaselineHostProjection(ctx, job.ID, snapshot); err != nil {
		t.Fatal(err)
	}
	if exists, err := s.BaselineHostProjectionExists(ctx, job.ID); err != nil || !exists {
		t.Fatalf("populated baseline projection = %t, %v", exists, err)
	}
	if host, err := s.GetBaselineHost(ctx, job.ID, "192.0.2.1"); err != nil || host.Host.Address != "192.0.2.1" {
		t.Fatalf("baseline host = %#v, %v", host, err)
	}

	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.ListScanCycleUnitSummariesPage(ctx, cycle.ID, 1, 0)
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Protocol != "tcp" || page.Items[0].Addresses != 1 {
		t.Fatalf("cycle unit page = %#v, %v", page, err)
	}
	if modified, err := s.RuntimeBaselineModified(ctx, "missing-job"); err != nil || modified {
		t.Fatalf("missing runtime marker = %t, %v", modified, err)
	}
	for i, raw := range []string{`{}`, `{"baseline_modified":null}`, `{"baseline_modified":0}`, `{"baseline_modified":1}`} {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET state_json=excluded.state_json`, job.ID, raw, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		modified, err := s.RuntimeBaselineModified(ctx, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := i < 2 || i == 3
		if modified != want {
			t.Fatalf("runtime marker %q = %t, want %t", raw, modified, want)
		}
	}
}

func TestLatestHostLegacyAndLeaseWrappers(t *testing.T) {
	ctx, s, job, _ := cycleFixture(t)
	now := time.Now().UTC()
	scan := model.Scan{ID: "legacy-wrapper-scan", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", NmapVersion: "7.99", Snapshot: model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: []model.PortState{{Port: 22, State: "open"}}}}}}
	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if legacy, err := s.LegacySuccessfulScanExists(ctx); err != nil || !legacy {
		t.Fatalf("legacy successful scan = %t, %v", legacy, err)
	}
	if hosts, err := s.ListLatestScanHosts(ctx); err != nil || len(hosts) != 0 {
		t.Fatalf("latest host projection without observations = %#v, %v", hosts, err)
	}
	hostScan := scan
	hostScan.ID = "indexed-wrapper-scan"
	hostScan.Snapshot.Hosts = []model.HostObservation{{Address: "192.0.2.1", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 22, State: "open"}}}}}}
	if err := s.SaveScan(ctx, hostScan); err != nil {
		t.Fatal(err)
	}
	hosts, err := s.ListLatestScanHosts(ctx)
	if err != nil || len(hosts) != 1 || hosts[0].Host.Address != "192.0.2.1" {
		t.Fatalf("latest hosts = %#v, %v", hosts, err)
	}

	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_leases(job,owner,expires_at) VALUES(?,?,?),(?,?,?)`, "expired", "owner-a", now.Add(-time.Minute).Format(time.RFC3339Nano), "active", "owner-b", now.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if released, err := s.ReleaseAllJobLeases(ctx); err != nil || released != 1 {
		t.Fatalf("expired lease release = %d, %v", released, err)
	}
}

func TestDeliveryExclusionAndReleaseNotModified(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	for _, destination := range []string{"healthy", "skip"} {
		if err := s.QueueEvent(ctx, destination, model.Event{Type: "test", Message: destination, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	due, err := s.ClaimDueDeliveriesExcluding(ctx, 10, "owner", []string{"skip", ""})
	if err != nil || len(due) != 1 || due[0].Destination != "healthy" {
		t.Fatalf("excluded delivery claim = %#v, %v", due, err)
	}
	if due, err := s.ClaimDueDeliveriesExcluding(ctx, 0, "owner", nil); err != nil || len(due) != 0 {
		t.Fatalf("zero-limit claim = %#v, %v", due, err)
	}
	if _, err := s.RecordReleaseCheck(ctx, "v1.0.0", "v1.1.0", "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.1.0", "1.1", "2026-09-11T12:00:00Z", "etag", false, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordReleaseNotModified(ctx, "new-etag"); err != nil {
		t.Fatal(err)
	}
	state, err := s.GetApplicationUpdateState(ctx)
	if err != nil || state.LatestVersion != "v1.1.0" || state.ETag != "new-etag" || state.CheckStatus != "ok" || state.LastSuccessfulCheckAt.IsZero() {
		t.Fatalf("not-modified state = %#v, %v", state, err)
	}
}
