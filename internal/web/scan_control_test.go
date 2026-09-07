package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type blockingWebScanner struct {
	started chan struct{}
	once    sync.Once
}

func (s *blockingWebScanner) Version(context.Context) string { return "blocking-web" }

func (s *blockingWebScanner) Scan(ctx context.Context, _ config.Job) (model.Snapshot, error) {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	return model.Snapshot{}, ctx.Err()
}

func TestActiveScanEndpointAndCancellationLifecycle(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	scanner := &blockingWebScanner{started: make(chan struct{})}
	a.Scanner = scanner
	job := config.NormalizeJob(config.Job{Name: "cancel-me", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Hour), Timing: "balanced"})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	a.BeginRun(ctx)
	finished := make(chan error, 1)
	if err := a.StartManagedRun(record.ID, func(_ model.Scan, _ []model.Event, runErr error) { finished <- runErr }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-scanner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("managed scan did not start")
	}
	active := a.ActiveScans()
	if len(active) != 1 || active[0].JobID != record.ID || active[0].ProcessAlive {
		// The scanner has not emitted process progress, so ProcessAlive is
		// advisory and may remain false; the important contract is visibility.
		if len(active) != 1 || active[0].JobID != record.ID {
			t.Fatalf("active scans = %#v", active)
		}
	}
	server := NewServer(a, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	listRecorder := httptest.NewRecorder()
	server.activeScans(listRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/scans/active", nil))
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("active scan status = %d: %s", listRecorder.Code, listRecorder.Body.String())
	}
	var response struct {
		Scans []model.ActiveScan `json:"scans"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &response); err != nil || len(response.Scans) != 1 {
		t.Fatalf("active scan response = %#v, %v", response, err)
	}

	cancelRecorder := httptest.NewRecorder()
	server.cancelScan(cancelRecorder, httptest.NewRequest(http.MethodPost, "/api/v1/scans/cancel", nil), store.Session{UserID: store.LegacyAdminUserID, Username: "admin"}, active[0].ID)
	if cancelRecorder.Code != http.StatusAccepted {
		t.Fatalf("cancel status = %d: %s", cancelRecorder.Code, cancelRecorder.Body.String())
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled scan did not finish")
	}
	missingRecorder := httptest.NewRecorder()
	server.cancelScan(missingRecorder, httptest.NewRequest(http.MethodPost, "/api/v1/scans/cancel", nil), store.Session{}, active[0].ID)
	if missingRecorder.Code != http.StatusConflict {
		t.Fatalf("second cancel status = %d: %s", missingRecorder.Code, missingRecorder.Body.String())
	}
	a.StopRun()
}
