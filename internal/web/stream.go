package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/webui"
)

func (s *Server) stream(w http.ResponseWriter, r *http.Request, session store.Session) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, 500, "stream_unsupported", "streaming is unavailable", nil)
		return
	}
	streamCtx, streamCancel := context.WithCancel(r.Context())
	defer streamCancel()
	// http.Server.WriteTimeout protects every ordinary response. SSE is the
	// one intentional exception: it stays open and sends periodic heartbeats,
	// so remove the per-request deadline only after the handler has established
	// that the writer supports streaming.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	maxSubscribers := s.sseMaxSubscribers
	if maxSubscribers <= 0 {
		maxSubscribers = defaultMaxSSESubscribers
	}
	maxSubscribersPerUser := s.sseMaxSubscribersPerUser
	if maxSubscribersPerUser <= 0 {
		maxSubscribersPerUser = defaultMaxSSESubscribersPerUser
	}
	subscriberKey := strings.TrimSpace(session.IDHash)
	if subscriberKey == "" {
		subscriberKey = "user:" + strings.TrimSpace(session.UserID)
	}
	if subscriberKey == "user:" {
		subscriberKey = "unknown"
	}
	lastID, _ := strconv.ParseUint(strings.TrimSpace(r.Header.Get("Last-Event-ID")), 10, 64)
	ch := make(chan sseMessage, 64)
	s.mu.Lock()
	if s.shutdown == nil {
		s.shutdown = make(chan struct{})
	}
	shutdown := s.shutdown
	if s.subscribers == nil {
		s.subscribers = map[chan sseMessage]struct{}{}
	}
	if s.subscriberKey == nil {
		s.subscriberKey = map[chan sseMessage]string{}
	}
	if s.subscriberUse == nil {
		s.subscriberUse = map[string]int{}
	}
	if s.sseCancels == nil {
		s.sseCancels = map[chan sseMessage]context.CancelFunc{}
	}
	if channelClosed(shutdown) {
		s.mu.Unlock()
		return
	}
	if len(s.subscribers) >= maxSubscribers {
		s.mu.Unlock()
		writeSSELimit(w, flusher, "too many live streams")
		return
	}
	if s.subscriberUse[subscriberKey] >= maxSubscribersPerUser {
		s.mu.Unlock()
		writeSSELimit(w, flusher, "too many live streams for this session")
		return
	}
	replay := s.replayLocked(lastID)
	s.subscribers[ch] = struct{}{}
	s.subscriberKey[ch] = subscriberKey
	s.subscriberUse[subscriberKey]++
	s.sseCancels[ch] = streamCancel
	s.sseWG.Add(1)
	s.mu.Unlock()
	s.sseAuthMu.Lock()
	if s.sseAuthCache == nil {
		s.sseAuthCache = map[string]sseAuthCacheEntry{}
	}
	s.sseAuthCache[subscriberKey] = sseAuthCacheEntry{session: session, checked: s.streamNow()}
	s.sseAuthMu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subscribers, ch)
		delete(s.subscriberKey, ch)
		delete(s.sseCancels, ch)
		if use := s.subscriberUse[subscriberKey]; use <= 1 {
			delete(s.subscriberUse, subscriberKey)
		} else {
			s.subscriberUse[subscriberKey] = use - 1
		}
		close(ch)
		s.mu.Unlock()
		s.sseAuthMu.Lock()
		delete(s.sseAuthCache, subscriberKey)
		s.sseAuthMu.Unlock()
		s.sseWG.Done()
	}()
	if _, err := w.Write([]byte(": connected\nretry: 5000\n\n")); err != nil {
		return
	}
	flusher.Flush()
	for _, message := range replay {
		if !writeSSEMessage(w, message) {
			return
		}
	}
	if len(replay) > 0 {
		flusher.Flush()
	}
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-streamCtx.Done():
			return
		case <-shutdown:
			return
		case message, ok := <-ch:
			if !ok {
				return
			}
			// Sessions and roles can be revoked while a browser keeps its
			// EventSource open. The short authorization cache bounds exposure for
			// a disabled or demoted principal, and the heartbeat below refreshes
			// that decision when the stream is otherwise quiet.
			if !s.streamAuthorized(streamCtx, r, subscriberKey) {
				return
			}
			if !writeSSEMessage(w, message) {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			if !s.streamAuthorized(streamCtx, r, subscriberKey) {
				return
			}
			if _, err := w.Write([]byte(": heartbeat\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// writeSSELimit deliberately returns a successful event-stream response. A
// browser EventSource retries a cleanly closed 200 stream, whereas a JSON 503
// is treated as a permanent connection failure by many clients. The retry
// hint and in-band marker let the console back off while subscriber pressure
// remains high without requiring a page reload.
func writeSSELimit(w http.ResponseWriter, flusher http.Flusher, reason string) {
	w.Header().Set("Retry-After", "5")
	_, _ = fmt.Fprintf(w, "retry: 5000\ndata: {\"type\":\"stream_limit\",\"reason\":%q,\"retry_after\":5}\n\n", reason)
	flusher.Flush()
}

func channelClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// signalShutdown closes the server-wide stream signal exactly once. The
// mutex makes closing the signal and admitting a new subscriber atomic, so a
// shutdown wait cannot race a late registration.
func (s *Server) signalShutdown() {
	var cancels []context.CancelFunc
	s.mu.Lock()
	if s.shutdown == nil {
		s.shutdown = make(chan struct{})
	}
	s.shutdownOnce.Do(func() {
		close(s.shutdown)
		for _, cancel := range s.sseCancels {
			cancels = append(cancels, cancel)
		}
	})
	s.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (s *Server) waitForSSEShutdown(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		s.sseWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		if s.Log != nil {
			s.Log.Warn("SSE handlers did not drain before shutdown deadline")
		}
	}
}

// streamAuthorized avoids a storage read for every event while bounding the
// time a revoked or demoted account can continue receiving updates. The
// initial authenticated request seeds the cache; subsequent checks refresh it
// at most once per TTL (two seconds in production).
func (s *Server) streamAuthorized(ctx context.Context, r *http.Request, key string) bool {
	now := s.streamNow()
	ttl := s.sseAuthTTL
	if ttl <= 0 {
		ttl = defaultSSEAuthCacheTTL
	}
	s.sseAuthMu.Lock()
	if entry, ok := s.sseAuthCache[key]; ok && now.Sub(entry.checked) < ttl {
		s.sseAuthMu.Unlock()
		return auth.HasPermission(entry.session, auth.PermissionStreamRead)
	}
	s.sseAuthMu.Unlock()
	if s.Auth == nil {
		return false
	}
	current, authorized := s.Auth.AuthenticateReadOnly(ctx, r)
	if !authorized || !auth.HasPermission(current, auth.PermissionStreamRead) {
		s.sseAuthMu.Lock()
		delete(s.sseAuthCache, key)
		s.sseAuthMu.Unlock()
		return false
	}
	s.sseAuthMu.Lock()
	if s.sseAuthCache == nil {
		s.sseAuthCache = map[string]sseAuthCacheEntry{}
	}
	s.sseAuthCache[key] = sseAuthCacheEntry{session: current, checked: now}
	s.sseAuthMu.Unlock()
	return true
}

func (s *Server) streamNow() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Server) broadcast(value map[string]any) {
	payload := boundedSSEPayload(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subscribers == nil {
		s.subscribers = map[chan sseMessage]struct{}{}
	}
	if s.eventIDLimit == 0 && s.Store == nil {
		// Servers assembled directly in tests or embedded callers do not have a
		// migrated store. Keep their in-memory cursor useful without requiring
		// database setup.
		s.eventIDLimit = ^uint64(0)
	}
	if s.nextEventID >= s.eventIDLimit && s.Store != nil {
		if start, end, err := s.Store.ReserveSSEEventIDsAfter(context.Background(), sseEventIDBlockSize, s.nextEventID); err == nil {
			s.nextEventID = start - 1
			s.eventIDLimit = end
		} else if s.Log != nil {
			s.Log.Warn("SSE event cursor reservation failed", "error", err)
		}
	}
	if s.nextEventID == ^uint64(0) {
		if s.Log != nil {
			s.Log.Error("SSE event cursor exhausted")
		}
		return
	}
	s.nextEventID++
	message := sseMessage{id: s.nextEventID, payload: payload}
	s.history = append(s.history, message)
	s.historyBytes += len(payload)
	const maxHistory = 256
	const maxHistoryBytes = 1 << 20
	for len(s.history) > maxHistory || s.historyBytes > maxHistoryBytes {
		s.historyBytes -= len(s.history[0].payload)
		s.history = s.history[1:]
	}
	for ch := range s.subscribers {
		select {
		case ch <- message:
		default:
			// Never silently lose a live update. Replace one queued item with a
			// refresh marker; the browser will invalidate all views and the next
			// reconnect can replay any durable events it missed by ID.
			s.dropped++
			select {
			case <-ch:
			default:
			}
			refresh := boundedSSEPayload(map[string]any{"type": "refresh_required", "after": message.id - 1})
			select {
			case ch <- sseMessage{id: message.id, payload: refresh}:
			default:
				s.dropped++
			}
		}
	}
}

const maxSSEPayloadBytes = 64 << 10

func boundedSSEPayload(value map[string]any) []byte {
	payload, err := json.Marshal(value)
	if err == nil && len(payload) <= maxSSEPayloadBytes {
		return payload
	}
	// Live updates are invalidation hints, not a second results API. A bounded
	// refresh marker keeps oversized messages from exhausting subscriber
	// buffers while the browser can fetch the durable, paginated resource.
	marker, markerErr := json.Marshal(map[string]any{"type": "refresh_required", "reason": "live_update_too_large"})
	if markerErr != nil {
		return []byte(`{"type":"refresh_required"}`)
	}
	return marker
}

func (s *Server) replayLocked(lastID uint64) []sseMessage {
	if lastID > s.nextEventID {
		payload, _ := json.Marshal(map[string]any{"type": "refresh_required", "after": lastID, "reason": "event_history_restarted"})
		// Keep the retry marker strictly newer than the client's cursor. This
		// matters when a client reconnects with an ID from a previous process
		// lifetime or from a non-durable invalidation event.
		markerID := lastID
		if markerID < ^uint64(0) {
			markerID++
		}
		if markerID > s.nextEventID {
			s.nextEventID = markerID
		}
		return []sseMessage{{id: markerID, payload: payload}}
	}
	if lastID == 0 {
		return nil
	}
	if len(s.history) == 0 {
		// There is no in-memory replay window after a restart. If durable event
		// IDs show that the browser is behind, force a cache refresh instead of
		// silently leaving it on stale data.
		if lastID < s.nextEventID {
			payload, _ := json.Marshal(map[string]any{"type": "refresh_required", "after": lastID, "reason": "event_history_restarted"})
			return []sseMessage{{id: s.nextEventID, payload: payload}}
		}
		return nil
	}
	oldest := s.history[0].id
	var replay []sseMessage
	if lastID+1 < oldest {
		payload, _ := json.Marshal(map[string]any{"type": "refresh_required", "after": lastID})
		replay = append(replay, sseMessage{id: oldest - 1, payload: payload})
	}
	for _, message := range s.history {
		if message.id > lastID {
			replay = append(replay, message)
		}
	}
	return replay
}

func writeSSEMessage(w io.Writer, message sseMessage) bool {
	if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", message.id, message.payload); err != nil {
		return false
	}
	return true
}

func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(webui.Files(), "dist")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" || !strings.HasPrefix(name, "assets/") {
		http.NotFound(w, r)
		return
	}
	info, err := fs.Stat(sub, name)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	// Vite emits content-hashed asset names. They are immutable for a given
	// build and can safely be cached for a year; the SPA shell remains
	// explicitly revalidated in spa below.
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.FileServer(http.FS(sub)).ServeHTTP(w, r)
}
func (s *Server) spa(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	// The shell and stable auxiliary paths (such as the favicon) must be
	// revalidated after an upgrade so a browser never keeps a shell pointing
	// at bundles that no longer exist.
	w.Header().Set("Cache-Control", "no-cache")
	if r.URL.Path != "/" {
		sub, err := fs.Sub(webui.Files(), "dist")
		if err == nil {
			if _, statErr := fs.Stat(sub, strings.TrimPrefix(r.URL.Path, "/")); statErr == nil {
				http.FileServer(http.FS(sub)).ServeHTTP(w, r)
				return
			}
		}
	}
	data, err := fs.ReadFile(webui.Files(), "dist/index.html")
	if err != nil {
		data = []byte(fallbackHTML)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

const fallbackHTML = `<!doctype html><html><head><meta charset="utf-8"><title>EdgeWatch</title></head><body><main><h1>EdgeWatch</h1><p>The web assets have not been built into this binary yet.</p></main></body></html>`
