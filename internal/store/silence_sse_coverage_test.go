package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSilenceDecisionHelpersAndEventCursorMinimum(t *testing.T) {
	if !isMissingSilenceState(errors.New("no such table: job_silence_state")) || isMissingSilenceState(errors.New("other failure")) || isMissingSilenceState(nil) {
		t.Fatal("silence-state error classification is incorrect")
	}
	for value, want := range map[time.Duration]string{0: "0s", time.Minute: "1m", 2 * time.Hour: "2h", 48 * time.Hour: "2d", 90 * time.Second: "1m30s"} {
		if got := humanSilenceDuration(value); got != want {
			t.Errorf("human silence duration %s = %q, want %q", value, got, want)
		}
	}
	if got := silenceRepeatDelay(-time.Minute, -1); got != time.Hour {
		t.Fatalf("non-positive silence delay = %s", got)
	}
	if got := silenceRepeatDelay(24*time.Hour, maxSilenceBackoffLevel+10); got != 30*24*time.Hour {
		t.Fatalf("silence delay cap = %s", got)
	}

	ctx := context.Background()
	s := openTestStore(t)
	if due, err := s.JobSilenceDue(ctx, "", time.Time{}, time.Now(), time.Hour); err != nil || due {
		t.Fatalf("empty silence check = %t, %v", due, err)
	}
	if due, err := s.JobSilenceDue(ctx, "missing", time.Now().Add(-time.Hour), time.Now(), 0); err != nil || due {
		t.Fatalf("zero-threshold silence check = %t, %v", due, err)
	}
	if max, err := s.MaxEventID(ctx); err != nil || max != 0 {
		t.Fatalf("empty event high-water mark = %d, %v", max, err)
	}
	start, end, err := s.ReserveSSEEventIDsAfter(ctx, 2, 50)
	if err != nil || start != 51 || end != 52 {
		t.Fatalf("minimum SSE range = %d-%d, %v", start, end, err)
	}
	if start, end, err := s.ReserveSSEEventIDsAfter(ctx, 1, 1); err != nil || start != 53 || end != 53 {
		t.Fatalf("cursor-following SSE range = %d-%d, %v", start, end, err)
	}
}
