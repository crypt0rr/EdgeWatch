package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestScheduleSuggestionUsesNearestActiveJobAndSafeMinuteShift(t *testing.T) {
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
	if _, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "nightly", Schedule: "0 */6 * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced"})); err != nil {
		t.Fatal(err)
	}
	server := NewServer(a, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/schedule-suggestion?schedule=0+%2A%2F6+%2A+%2A+%2A&timezone=UTC", nil)
	server.scheduleSuggestion(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	var response scheduleSuggestionResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Suggested || response.SuggestedSchedule != "30 */6 * * *" || response.OffsetMinutes != 30 || response.Nearest == nil || response.Nearest.Name != "nightly" || response.GapMinutes != 0 {
		t.Fatalf("unexpected suggestion: %#v", response)
	}
}

func TestShiftCronMinuteLeavesCompositeMinuteExpressionsUntouched(t *testing.T) {
	if shifted, ok := shiftCronMinute("*/15 * * * *", 30); ok || shifted != "" {
		t.Fatalf("step expression should not be rewritten: %q, %v", shifted, ok)
	}
	if shifted, ok := shiftCronMinute("45 3 * * *", 30); !ok || shifted != "15 3 * * *" {
		t.Fatalf("unexpected wrapped shift: %q, %v", shifted, ok)
	}
}
