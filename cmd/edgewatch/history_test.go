package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type historyReaderStub struct {
	lookupErr error
	scanErr   error
	eventErr  error
	calls     []string
}

func (s *historyReaderStub) GetJobByName(context.Context, string) (store.JobRecord, error) {
	s.calls = append(s.calls, "lookup")
	return store.JobRecord{ID: "stable-job-id"}, s.lookupErr
}

func (s *historyReaderStub) ListJobScans(context.Context, string, int) ([]model.Scan, error) {
	s.calls = append(s.calls, "job-scans")
	return []model.Scan{{ID: "managed-scan"}}, s.scanErr
}

func (s *historyReaderStub) ListJobEvents(context.Context, string, int) ([]model.Event, error) {
	s.calls = append(s.calls, "job-events")
	return []model.Event{{Message: "managed-event"}}, s.eventErr
}

func (s *historyReaderStub) ListScans(context.Context, string, int) ([]model.Scan, error) {
	s.calls = append(s.calls, "legacy-scans")
	return []model.Scan{{ID: "legacy-scan"}}, s.scanErr
}

func (s *historyReaderStub) ListEvents(context.Context, string, int) ([]model.Event, error) {
	s.calls = append(s.calls, "legacy-events")
	return []model.Event{{Message: "legacy-event"}}, s.eventErr
}

func TestListHistoryUsesStableIdentityAndLegacyFallback(t *testing.T) {
	for _, tc := range []struct {
		name       string
		jobName    string
		lookupErr  error
		wantCalls  []string
		wantScanID string
		wantEvent  string
	}{
		{name: "managed", jobName: "renamed", wantCalls: []string{"lookup", "job-scans", "job-events"}, wantScanID: "managed-scan", wantEvent: "managed-event"},
		{name: "legacy YAML", jobName: "legacy", lookupErr: store.ErrNotFound, wantCalls: []string{"lookup", "legacy-scans", "legacy-events"}, wantScanID: "legacy-scan", wantEvent: "legacy-event"},
		{name: "all history", wantCalls: []string{"legacy-scans", "legacy-events"}, wantScanID: "legacy-scan", wantEvent: "legacy-event"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &historyReaderStub{lookupErr: tc.lookupErr}
			scans, events, err := listHistory(context.Background(), reader, tc.jobName, 50)
			if err != nil {
				t.Fatalf("listHistory() error = %v", err)
			}
			if !reflect.DeepEqual(reader.calls, tc.wantCalls) {
				t.Fatalf("history calls = %v, want %v", reader.calls, tc.wantCalls)
			}
			if len(scans) != 1 || scans[0].ID != tc.wantScanID || len(events) != 1 || events[0].Message != tc.wantEvent {
				t.Fatalf("history = scans %v events %v", scans, events)
			}
		})
	}
}

func TestListHistoryPropagatesLookupAndReadFailures(t *testing.T) {
	readFailure := errors.New("history read failed")
	lookupFailure := errors.New("job lookup failed")
	for _, tc := range []struct {
		name      string
		jobName   string
		lookupErr error
		scanErr   error
		eventErr  error
		wantCalls []string
		wantErr   error
	}{
		{name: "lookup", jobName: "managed", lookupErr: lookupFailure, wantCalls: []string{"lookup"}, wantErr: lookupFailure},
		{name: "managed scans", jobName: "managed", scanErr: readFailure, wantCalls: []string{"lookup", "job-scans"}, wantErr: readFailure},
		{name: "managed events", jobName: "managed", eventErr: readFailure, wantCalls: []string{"lookup", "job-scans", "job-events"}, wantErr: readFailure},
		{name: "legacy scans", jobName: "legacy", lookupErr: store.ErrNotFound, scanErr: readFailure, wantCalls: []string{"lookup", "legacy-scans"}, wantErr: readFailure},
		{name: "legacy events", jobName: "legacy", lookupErr: store.ErrNotFound, eventErr: readFailure, wantCalls: []string{"lookup", "legacy-scans", "legacy-events"}, wantErr: readFailure},
		{name: "all scans", scanErr: readFailure, wantCalls: []string{"legacy-scans"}, wantErr: readFailure},
		{name: "all events", eventErr: readFailure, wantCalls: []string{"legacy-scans", "legacy-events"}, wantErr: readFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &historyReaderStub{lookupErr: tc.lookupErr, scanErr: tc.scanErr, eventErr: tc.eventErr}
			_, _, err := listHistory(context.Background(), reader, tc.jobName, 50)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("listHistory() error = %v, want %v", err, tc.wantErr)
			}
			if !reflect.DeepEqual(reader.calls, tc.wantCalls) {
				t.Fatalf("history calls = %v, want %v", reader.calls, tc.wantCalls)
			}
		})
	}
}
