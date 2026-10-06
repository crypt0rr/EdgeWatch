package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestFormatEventPreservesTrustedNotificationText(t *testing.T) {
	event := model.Event{
		Type:    "changes-detected",
		Message: "1 baseline change confirmed",
		Job:     "edge_[prod]",
		ScanID:  "scan-1",
		Changes: []model.Change{{
			Severity: "critical",
			Kind:     "port",
			Target:   "2001:db8::1",
			Protocol: "tcp",
			Port:     443,
			Old:      "open|filtered",
			New:      "open",
		}},
	}

	got := FormatEvent(event)
	want := "🔴 EdgeWatch: 1 baseline change confirmed\n" +
		"Job: edge_[prod]\n" +
		"Scan: scan-1\n" +
		"- [critical] 2001:db8::1 tcp/443: open|filtered -> open"
	if got != want {
		t.Fatalf("FormatEvent() = %q, want %q", got, want)
	}
}

func TestFormatEventNormalizesQueuedLegacyChangeMessages(t *testing.T) {
	cases := []struct {
		typeName string
		message  string
		count    int
		want     string
	}{
		{typeName: "changes-detected", message: "1 baseline change(s) confirmed", want: "1 baseline change confirmed"},
		{typeName: "changes-recovered", message: "1 baseline change(s) recovered", want: "1 baseline change recovered"},
		{typeName: "changes-reminder", message: "Reminder: 1 baseline change(s) remain open", want: "Reminder: 1 baseline change remains open"},
		{typeName: "changes-detected", message: "3 baseline change(s) confirmed", count: 3, want: "3 baseline changes confirmed"},
	}
	for _, tc := range cases {
		t.Run(tc.typeName, func(t *testing.T) {
			event := model.Event{
				Type:         tc.typeName,
				Message:      tc.message,
				ChangesCount: tc.count,
				Changes:      []model.Change{{Severity: "warning", Kind: "port", Target: "192.0.2.1", Protocol: "tcp", Port: 443, Old: "not-open", New: "open"}},
			}
			if got := FormatEvent(event); !strings.Contains(got, "EdgeWatch: "+tc.want) {
				t.Fatalf("FormatEvent(legacy event) = %q, want summary %q", got, tc.want)
			}
		})
	}
}

func TestFormatEventSanitizesOnlyScanDerivedServiceText(t *testing.T) {
	event := model.Event{
		Type:    "changes-detected",
		Message: "1 baseline change confirmed",
		Job:     "edge_[prod]",
		Changes: []model.Change{{
			Severity: "warning",
			Kind:     "service",
			Target:   "192.0.2.1",
			Protocol: "tcp",
			Port:     443,
			Old:      "https | old",
			New:      "http | nginx*<@everyone>\u202Ehidden",
		}},
	}

	got := FormatEvent(event)
	for _, trusted := range []string{"1 baseline change confirmed", "Job: edge_[prod]", "https ｜ old -> http ｜ nginx＊‹＠everyone› hidden"} {
		if !strings.Contains(got, trusted) {
			t.Errorf("notification %q does not preserve/neutralize expected text %q", got, trusted)
		}
	}
	for _, unsafe := range []string{"<@everyone>", "\u202E", "http | nginx*"} {
		if strings.Contains(got, unsafe) {
			t.Errorf("notification retained unsafe scan-derived text %q: %q", unsafe, got)
		}
	}
}

func TestFormatEventPreservesTruncationAndCriticalIndicators(t *testing.T) {
	changes := make([]model.Change, 500)
	for i := range changes {
		target := fmt.Sprintf("192.0.2.%d", i%250)
		port := 1000 + i
		changes[i] = model.Change{
			Key:      fmt.Sprintf("port|%s|tcp|%d", target, port),
			Kind:     "port",
			Target:   target,
			Protocol: "tcp",
			Port:     port,
			New:      "open",
			Severity: "critical",
		}
	}
	cases := []struct {
		typeName string
		message  string
		prefix   string
	}{
		{typeName: "changes-detected", message: baselineChangeMessage(len(changes), "confirmed"), prefix: "🔴 EdgeWatch:"},
		{typeName: "changes-reminder", message: persistentIncidentReminderMessage(len(changes)), prefix: "🔴 EdgeWatch:"},
		{typeName: "changes-recovered", message: baselineChangeMessage(len(changes), "recovered"), prefix: "🟢 EdgeWatch:"},
	}
	for _, tc := range cases {
		t.Run(tc.typeName, func(t *testing.T) {
			event := model.Event{Type: tc.typeName, Job: "edge", ScanID: "scan-1", Message: tc.message, Changes: changes}
			bounded, payload, err := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
			if err != nil {
				t.Fatalf("bound oversized event: %v", err)
			}
			if !bounded.ChangesTruncated || len(bounded.Changes) != 0 {
				t.Fatalf("event was not truncated: %#v", bounded)
			}
			var queued model.Event
			if err := json.Unmarshal(payload, &queued); err != nil {
				t.Fatalf("decode queued event: %v", err)
			}
			got := FormatEvent(queued)
			if !strings.HasPrefix(got, tc.prefix) {
				t.Errorf("FormatEvent() = %q, want prefix %q", got, tc.prefix)
			}
			if !strings.Contains(got, "(details truncated)") {
				t.Errorf("FormatEvent() = %q, want truncation notice", got)
			}
		})
	}
}

func TestBaselineChangeNotificationGrammar(t *testing.T) {
	cases := []struct {
		count     int
		detected  string
		recovered string
		reminder  string
	}{
		{count: 1, detected: "1 baseline change confirmed", recovered: "1 baseline change recovered", reminder: "Reminder: 1 baseline change remains open"},
		{count: 3, detected: "3 baseline changes confirmed", recovered: "3 baseline changes recovered", reminder: "Reminder: 3 baseline changes remain open"},
	}
	for _, tc := range cases {
		t.Run(tc.detected, func(t *testing.T) {
			if got := baselineChangeMessage(tc.count, "confirmed"); got != tc.detected {
				t.Errorf("detection message = %q, want %q", got, tc.detected)
			}
			if got := baselineChangeMessage(tc.count, "recovered"); got != tc.recovered {
				t.Errorf("recovery message = %q, want %q", got, tc.recovered)
			}
			if got := persistentIncidentReminderMessage(tc.count); got != tc.reminder {
				t.Errorf("reminder message = %q, want %q", got, tc.reminder)
			}
		})
	}
}

func TestScanOutcomeMessageSanitizesUntrustedErrorText(t *testing.T) {
	got := scanOutcomeMessage(model.Scan{Status: "failed", Error: "Nmap: probe <@everyone>\u202Ehidden"})
	want := "Scan failed: Nmap: probe ‹＠everyone› hidden"
	if got != want {
		t.Fatalf("scanOutcomeMessage() = %q, want %q", got, want)
	}
}
