package web

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
)

// broadcast sends a live update to every stream. The package's stream tests
// predate audiences and keep using it. Production code has no audience-less
// broadcast: every call site passes an audience to broadcastTo.
func (s *Server) broadcast(value map[string]any) {
	s.broadcastTo(context.Background(), audienceEveryone(), value)
}

func messageIDs(messages []sseMessage) []uint64 {
	ids := make([]uint64, 0, len(messages))
	for _, message := range messages {
		ids = append(ids, message.id)
	}
	return ids
}

func TestBroadcastToDropsAMessageWithoutAnAudience(t *testing.T) {
	var logs bytes.Buffer
	server := &Server{subscribers: map[chan sseMessage]struct{}{}, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	bare := make(chan sseMessage, 4)
	registered := make(chan sseMessage, 4)
	server.subscribers[bare] = struct{}{}
	server.subscribers[registered] = struct{}{}
	server.sseIdentity = map[chan sseMessage]sseSubscriber{registered: {}}

	server.broadcastTo(context.Background(), sseAudience{}, map[string]any{"type": "job.updated", "token": "no-audience"})
	if len(server.history) != 0 || server.historyBytes != 0 || server.nextEventID != 0 {
		t.Fatalf("dropped message was kept: history=%d bytes=%d next=%d", len(server.history), server.historyBytes, server.nextEventID)
	}
	for name, ch := range map[string]chan sseMessage{"bare": bare, "registered": registered} {
		select {
		case message := <-ch:
			t.Fatalf("%s stream received a message without an audience: %s", name, message.payload)
		default:
		}
	}
	if !strings.Contains(logs.String(), "live update dropped because it has no audience") || !strings.Contains(logs.String(), "type=job.updated") || strings.Contains(logs.String(), "no-audience") {
		t.Fatalf("dropped message log = %q", logs.String())
	}

	// The dropped message consumed no event ID, and everyone still receives
	// the next message.
	server.broadcastTo(context.Background(), audienceEveryone(), map[string]any{"type": "job.updated", "token": "everyone"})
	for name, ch := range map[string]chan sseMessage{"bare": bare, "registered": registered} {
		select {
		case message := <-ch:
			if message.id != 1 || message.audience != audienceEveryone() || !strings.Contains(string(message.payload), "everyone") {
				t.Fatalf("%s stream received %d %+v %s", name, message.id, message.audience, message.payload)
			}
		default:
			t.Fatalf("%s stream did not receive the message for everyone", name)
		}
	}
	if len(server.history) != 1 || server.history[0].audience != audienceEveryone() {
		t.Fatalf("history = %+v", server.history)
	}
}

func TestSSEAudienceMatching(t *testing.T) {
	if (sseAudience{}).valid() || !audienceEveryone().valid() {
		t.Fatal("only a non-empty audience is valid")
	}
	if (sseSubscriber{}).matches(sseAudience{}) || !(sseSubscriber{}).matches(audienceEveryone()) {
		t.Fatal("a subscriber must match everyone and never the empty audience")
	}
}

func TestReplayForSubscriberFiltersByAudience(t *testing.T) {
	everyone := func(id uint64, token string) sseMessage {
		return sseMessage{id: id, payload: []byte(`{"type":"test","token":"` + token + `"}`), audience: audienceEveryone()}
	}
	// broadcastTo never stores a message without an audience, so an empty
	// audience here stands in for one this subscriber does not match.
	unmatched := sseMessage{id: 11, payload: []byte(`{"type":"test","token":"unmatched"}`)}
	server := &Server{history: []sseMessage{everyone(10, "first"), unmatched, everyone(12, "last")}, nextEventID: 12}

	// A browser behind the retained window gets the refresh marker, then only
	// the messages meant for it, with their original IDs.
	all := server.replayLocked(1)
	replay := server.replayForLocked(1, sseSubscriber{})
	if got := messageIDs(all); len(got) != 4 || got[0] != 9 || got[2] != 11 {
		t.Fatalf("unfiltered replay IDs = %v", got)
	}
	if got := messageIDs(replay); len(got) != 3 || got[0] != 9 || got[1] != 10 || got[2] != 12 {
		t.Fatalf("filtered replay IDs = %v", got)
	}
	if !strings.Contains(string(replay[0].payload), `"refresh_required"`) || replay[0].audience != audienceEveryone() {
		t.Fatalf("replay gap marker = %s %+v", replay[0].payload, replay[0].audience)
	}
	for _, message := range replay {
		if strings.Contains(string(message.payload), "unmatched") {
			t.Fatalf("replay included a message for another audience: %s", message.payload)
		}
	}

	// Inside the window no marker is needed, and a stream that is only
	// missing the unmatched message replays nothing.
	if got := messageIDs(server.replayForLocked(10, sseSubscriber{})); len(got) != 1 || got[0] != 12 {
		t.Fatalf("in-window replay IDs = %v", got)
	}
	server.history = server.history[:2]
	server.nextEventID = 11
	if got := server.replayForLocked(10, sseSubscriber{}); len(got) != 0 {
		t.Fatalf("replay of only an unmatched message = %v", messageIDs(got))
	}

	// After a restart the history is empty, and the restart marker still
	// reaches everyone.
	restarted := &Server{nextEventID: 20}
	restart := restarted.replayForLocked(5, sseSubscriber{})
	if len(restart) != 1 || restart[0].id != 20 || !strings.Contains(string(restart[0].payload), "event_history_restarted") {
		t.Fatalf("restart replay = %v", messageIDs(restart))
	}
}

func TestSSEStreamReplaysAndDeliversOnlyItsAudience(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	ctx := context.Background()
	raw, _, err := server.Auth.LoginAs(ctx, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil), "admin", "administrator password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	authRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	authRequest.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
	session, ok := server.Auth.AuthenticateReadOnly(ctx, authRequest)
	if !ok {
		t.Fatal("login session was not authenticated")
	}

	server.broadcastTo(ctx, audienceEveryone(), map[string]any{"type": "test", "token": "already-seen"})
	server.mu.Lock()
	lastSeen := server.nextEventID
	server.mu.Unlock()
	server.broadcastTo(ctx, audienceEveryone(), map[string]any{"type": "test", "token": "replayed-first"})
	server.mu.Lock()
	server.nextEventID++
	server.history = append(server.history, sseMessage{id: server.nextEventID, payload: []byte(`{"type":"test","token":"not-for-this-stream"}`)})
	server.mu.Unlock()
	server.broadcastTo(ctx, audienceEveryone(), map[string]any{"type": "test", "token": "replayed-last"})

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil).WithContext(streamCtx)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
	request.Header.Set("Last-Event-ID", strconv.FormatUint(lastSeen, 10))
	writer := &deadlineTrackingWriter{header: make(http.Header)}
	done := make(chan struct{})
	go func() {
		server.stream(writer, request, session)
		close(done)
	}()
	waitForSSEBody(t, writer, "replayed-last")
	waitForSSESubscribers(t, server, 1)

	server.broadcastTo(ctx, sseAudience{}, map[string]any{"type": "test", "token": "dropped-live"})
	server.broadcastTo(ctx, audienceEveryone(), map[string]any{"type": "test", "token": "delivered-live"})
	waitForSSEBody(t, writer, "delivered-live")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SSE stream did not close")
	}

	writer.mu.Lock()
	body := writer.body.String()
	writer.mu.Unlock()
	if !strings.Contains(body, "replayed-first") {
		t.Fatalf("stream did not replay the first message: %s", body)
	}
	for _, token := range []string{"already-seen", "not-for-this-stream", "dropped-live"} {
		if strings.Contains(body, token) {
			t.Fatalf("stream received %q: %s", token, body)
		}
	}
	var events []string
	for _, line := range strings.Split(body, "\n") {
		if payload, found := strings.CutPrefix(line, "data: "); found {
			var decoded map[string]any
			if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
				t.Fatalf("stream data %q: %v", payload, err)
			}
			events = append(events, decoded["token"].(string))
		}
	}
	if strings.Join(events, ",") != "replayed-first,replayed-last,delivered-live" {
		t.Fatalf("stream events = %v", events)
	}
}
