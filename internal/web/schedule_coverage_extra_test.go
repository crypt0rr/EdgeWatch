package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/robfig/cron/v3"
)

func TestScheduleSuggestionValidationAndFiltering(t *testing.T) {
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
	server := NewServer(a, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	call := func(query string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.scheduleSuggestion(rec, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/schedule-suggestion?"+query, nil))
		return rec
	}
	if rec := call("timezone=UTC"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "schedule") {
		t.Fatalf("missing schedule response = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("schedule=0+*+*+*+*&timezone="); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "timezone") {
		t.Fatalf("missing timezone response = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("schedule=0+*+*+*+*&timezone=Not%2FAZone"); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid timezone response = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("schedule=not-a-cron&timezone=UTC"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "schedule") {
		t.Fatalf("invalid schedule response = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("schedule=TZ%3DEurope%2FAmsterdam+0+*+*+*+*&timezone=UTC"); rec.Code != http.StatusBadRequest {
		t.Fatalf("embedded timezone response = %d: %s", rec.Code, rec.Body.String())
	}

	// No active jobs produces a valid response without a suggestion.
	if rec := call("schedule=0+*+*+*+*&timezone=UTC"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"suggested":false`) {
		t.Fatalf("empty schedule response = %d: %s", rec.Code, rec.Body.String())
	}
	job := config.NormalizeJob(config.Job{Name: "active", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}})
	if _, err := db.CreateJobWithEnabled(ctx, job, true); err != nil {
		t.Fatal(err)
	}
	archived := job
	archived.Name = "archived"
	archivedRecord, err := db.CreateJobWithEnabled(ctx, archived, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetJobArchived(ctx, archivedRecord.ID, true); err != nil {
		t.Fatal(err)
	}
	paused := job
	paused.Name = "paused"
	if _, err := db.CreateJobWithEnabled(ctx, paused, false); err != nil {
		t.Fatal(err)
	}
	malformed := job
	malformed.Name = "malformed"
	malformedRecord, err := db.CreateJobWithEnabled(ctx, malformed, true)
	if err != nil {
		t.Fatal(err)
	}
	malformed.Schedule = "not cron"
	definition, err := json.Marshal(malformed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=?`, definition, malformedRecord.ID); err != nil {
		t.Fatal(err)
	}
	// The active job is more than thirty minutes from this draft in the next
	// occurrence, so it is reported as the nearest reference without a shift.
	if rec := call("schedule=30+*+*+*+*&timezone=UTC"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"nearest"`) {
		t.Fatalf("nearest schedule response = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestParseNextRunAndShiftCronMinuteBoundaries(t *testing.T) {
	parser := cronParserForCoverage()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, schedule, timezone string
		wantErr                  string
	}{
		{"embedded TZ", "TZ=UTC 0 * * * *", "UTC", "five cron fields"},
		{"bad timezone", "0 * * * *", "Not/AZone", "invalid timezone"},
		{"bad schedule", "invalid", "UTC", "invalid schedule"},
		{"never fires", "0 0 30 2 *", "UTC", "schedule never fires"},
	} {
		if _, err := parseNextRun(parser, test.schedule, test.timezone, now); err == nil || !strings.Contains(err.Error(), test.wantErr) {
			t.Errorf("%s error = %v", test.name, err)
		}
	}
	if _, err := parseNextRun(parser, "0 * * * *", "UTC", now); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		schedule string
		offset   int
		ok       bool
	}{
		{"", 30, false},
		{"0 0 * *", 30, false},
		{"*/15 * * * *", 30, false},
		{"bad * * * *", 30, false},
		{"60 * * * *", 30, false},
		{"0 * * * *", 0, false},
		{"0 * * * *", -30, true},
	} {
		if _, ok := shiftCronMinute(test.schedule, test.offset); ok != test.ok {
			t.Errorf("shiftCronMinute(%q,%d) ok mismatch", test.schedule, test.offset)
		}
	}
}

// Keep the parser construction local to this test file so all parser flags
// used by the schedule helper remain explicit in the test.
func cronParserForCoverage() cron.Parser {
	return cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
}
