package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// liveStream is a live-update stream that a test opened through the API
// router, as a browser's EventSource does.
type liveStream struct {
	writer *deadlineTrackingWriter
	cancel context.CancelFunc
	done   chan struct{}
}

// startLiveStream opens /stream through the API router as the fixture's
// signed-in account, replaying after lastEventID when it is not zero. The
// stream is closed when the test ends.
func (f tenantAccountsFixture) startLiveStream(t *testing.T, account string, lastEventID uint64) *liveStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil).WithContext(ctx)
	request.RemoteAddr = "127.0.0.1:9000"
	request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: f.cookies[account]})
	if lastEventID > 0 {
		request.Header.Set("Last-Event-ID", strconv.FormatUint(lastEventID, 10))
	}
	stream := &liveStream{writer: &deadlineTrackingWriter{header: make(http.Header)}, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(stream.done)
		f.server.api(stream.writer, request)
	}()
	t.Cleanup(func() { stream.close(t) })
	return stream
}

// openLiveStream opens a stream and waits until the server has registered
// it.
func (f tenantAccountsFixture) openLiveStream(t *testing.T, account string, lastEventID uint64) *liveStream {
	t.Helper()
	stream := f.startLiveStream(t, account, lastEventID)
	waitForSSEBody(t, stream.writer, ": connected")
	return stream
}

// close ends the stream and waits for its handler to return.
func (stream *liveStream) close(t *testing.T) {
	t.Helper()
	stream.cancel()
	select {
	case <-stream.done:
	case <-time.After(5 * time.Second):
		t.Error("live-update stream did not close")
	}
}

// ended reports whether the stream's handler returns within the wait.
func (stream *liveStream) ended(wait time.Duration) bool {
	select {
	case <-stream.done:
		return true
	case <-time.After(wait):
		return false
	}
}

func (stream *liveStream) body() string {
	stream.writer.mu.Lock()
	defer stream.writer.mu.Unlock()
	return stream.writer.body.String()
}

// events returns the decoded data of every message the stream received.
func (stream *liveStream) events(t *testing.T) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(stream.body(), "\n") {
		payload, found := strings.CutPrefix(line, "data: ")
		if !found {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			t.Fatalf("stream data %q: %v", payload, err)
		}
		events = append(events, event)
	}
	return events
}

// eventTypes returns the type of each message the stream received.
func (stream *liveStream) eventTypes(t *testing.T) []string {
	t.Helper()
	var types []string
	for _, event := range stream.events(t) {
		eventType, _ := event["type"].(string)
		types = append(types, eventType)
	}
	return types
}

// lastEventID returns the ID of the newest live update.
func (s *Server) lastEventID() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextEventID
}

// createdID returns the ID in a 201 response, or fails the test.
func createdID(t *testing.T, what string, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var created struct {
		ID string `json:"id"`
	}
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &created) != nil || created.ID == "" {
		t.Fatalf("create %s = %d: %s", what, rec.Code, rec.Body.String())
	}
	return created.ID
}

// unitJobBody is a job that sets its baseline with one scan and opens an
// incident on the first change.
const unitJobBody = `{"name":"edge","schedule":"0 * * * *","timezone":"UTC","targets":["127.0.0.1"],"tcp":{"ports":"1-2","mode":"connect","engine":"nmap"},"timeout":"1m","baseline_samples":1,"change_confirmations":1}`

// Each business unit's live-update streams receive only that unit's
// events. Unit B's job, its scans through the application, the incident
// they open and its acceptance, and B's scanner profile, destination and
// account changes all reach B's stream, and none of them reaches unit A's
// stream. A stream that replays from before them leaves them out for A and
// has them for B. A's own event reaches A and not B.
func TestLiveUpdatesReachOnlyTheirBusinessUnit(t *testing.T) {
	ctx := context.Background()
	f := newTenantAccountsFixture(t)
	// The replays below start after this message, which the live streams,
	// opened later, do not receive.
	f.server.broadcast(map[string]any{"type": "test.before"})
	before := f.server.lastEventID()
	streamA := f.openLiveStream(t, "own", 0)
	streamB := f.openLiveStream(t, "other", 0)

	jobB := createdID(t, "unit B's job", f.call("other", http.MethodPost, "/api/v1/jobs", unitJobBody))
	profileB := createdID(t, "unit B's profile", f.call("other", http.MethodPost, "/api/v1/scanner-profiles", `{"name":"Unit profile","engine":"nmap","password":"administrator password"}`))
	destinationB := createdID(t, "unit B's destination", f.call("other", http.MethodPost, "/api/v1/notifications/destinations", `{"name":"Unit destination","url":"generic://127.0.0.1:9/unit-b?disabletls=yes&template=json","password":"administrator password"}`))
	if rec := f.call("other", http.MethodPatch, "/api/v1/users/"+f.viewerB.ID, `{"display_name":"Viewer B"}`); rec.Code != http.StatusOK {
		t.Fatalf("rename unit B's viewer = %d: %s", rec.Code, rec.Body.String())
	}
	// Two scans of B's job through the application: the first sets the
	// baseline, and the second finds a new open port.
	scope := []model.Scope{{Target: "127.0.0.1", Protocol: "tcp", Ports: "1-2"}}
	f.server.App.Scanner = &sequenceScanner{snapshots: []model.Snapshot{
		{Scopes: scope, Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}},
		{Scopes: scope, Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}, {Port: 2, State: "open"}}}}},
	}}
	record, err := f.other.GetJob(ctx, jobB)
	if err != nil {
		t.Fatal(err)
	}
	var scansB []string
	for range 2 {
		scan, _, err := f.server.App.RunJobRecord(ctx, record)
		if err != nil || scan.Status != "success" {
			t.Fatalf("scan of unit B's job = %+v, %v", scan, err)
		}
		scansB = append(scansB, scan.ID)
	}
	state, err := f.other.RuntimeState(ctx, jobB)
	if err != nil || len(state.Incidents) != 1 {
		t.Fatalf("unit B's incidents = %+v, %v", state.Incidents, err)
	}
	for key, incident := range state.Incidents {
		body, err := json.Marshal(map[string]any{"key": key, "expected_change": incident.Change})
		if err != nil {
			t.Fatal(err)
		}
		if rec := f.call("other", http.MethodPost, "/api/v1/jobs/"+jobB+"/incidents/accept", string(body)); rec.Code != http.StatusNoContent {
			t.Fatalf("accept unit B's incident = %d: %s", rec.Code, rec.Body.String())
		}
	}
	for _, want := range []string{`"job_id":"` + jobB + `","type":"job.created"`, `"profile_id":"` + profileB, `"notification_id":"` + destinationB, `"type":"changes-detected"`, `"type":"incident-accepted"`} {
		waitForSSEBody(t, streamB.writer, want)
	}
	for _, eventType := range []string{"scan.started", "baseline-complete", "scan.completed"} {
		waitForSSEBody(t, streamB.writer, `"type":"`+eventType+`"`)
	}

	// A's own event comes last. Each stream receives its messages in order,
	// so once A has it, any of B's events meant for A would have arrived.
	jobA := createdID(t, "unit A's job", f.call("own", http.MethodPost, "/api/v1/jobs", unitJobBody))
	waitForSSEBody(t, streamA.writer, jobA)
	markersB := append([]string{jobB, profileB, destinationB, f.viewerB.ID}, scansB...)
	assertOnlyEvent := func(name string, stream *liveStream, wantType, wantJob string) {
		t.Helper()
		events := stream.events(t)
		if len(events) != 1 || events[0]["type"] != wantType || events[0]["job_id"] != wantJob {
			t.Errorf("%s received %v, want only its own %s", name, stream.eventTypes(t), wantType)
		}
		for _, marker := range markersB {
			if strings.Contains(stream.body(), marker) {
				t.Errorf("%s received unit B's %s: %s", name, marker, stream.body())
			}
		}
	}
	assertOnlyEvent("unit A's stream", streamA, "job.created", jobA)
	if strings.Contains(streamB.body(), jobA) {
		t.Errorf("unit B's stream received unit A's job: %s", streamB.body())
	}

	// A replay from before B's events has only A's event for A, and B's
	// events for B.
	replayA := f.openLiveStream(t, "own", before)
	waitForSSEBody(t, replayA.writer, jobA)
	assertOnlyEvent("unit A's replay", replayA, "job.created", jobA)
	replayB := f.openLiveStream(t, "other", before)
	for _, marker := range []string{jobB, profileB, destinationB, `"type":"incident-accepted"`} {
		waitForSSEBody(t, replayB.writer, marker)
	}
	if strings.Contains(replayB.body(), jobA) {
		t.Errorf("unit B's replay has unit A's job: %s", replayB.body())
	}
}

// Disabling a business unit ends its open live-update streams at once, not
// at their next heartbeat, and leaves the other unit's streams open and
// receiving.
func TestDisablingABusinessUnitEndsOnlyItsLiveUpdateStreams(t *testing.T) {
	ctx := context.Background()
	f := newTenantAccountsFixture(t)
	streamA := f.openLiveStream(t, "own", 0)
	operatorA := f.openLiveStream(t, "operator", 0)
	streamsB := []*liveStream{f.openLiveStream(t, "other", 0), f.openLiveStream(t, "other", 0)}
	unitB, err := f.db.Platform().GetTenant(ctx, tenantAccountsOtherID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.server.App.DisableUnit(ctx, tenantAccountsOtherID, unitB.Revision, store.AuditEntry{ActorKind: store.AuditActorHost}); err != nil {
		t.Fatal(err)
	}
	for index, stream := range streamsB {
		if !stream.ended(2 * time.Second) {
			t.Fatalf("unit B's stream %d is still open after the unit was disabled", index)
		}
	}
	for name, stream := range map[string]*liveStream{"administrator": streamA, "operator": operatorA} {
		if stream.ended(0) {
			t.Fatalf("unit A's %s stream ended when unit B was disabled", name)
		}
	}
	jobA := createdID(t, "unit A's job", f.call("own", http.MethodPost, "/api/v1/jobs", unitJobBody))
	waitForSSEBody(t, streamA.writer, jobA)
	waitForSSEBody(t, operatorA.writer, jobA)
}
