package web

import (
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
	if s.subscribers == nil {
		s.subscribers = map[chan sseMessage]struct{}{}
	}
	if s.subscriberKey == nil {
		s.subscriberKey = map[chan sseMessage]string{}
	}
	if s.subscriberUse == nil {
		s.subscriberUse = map[string]int{}
	}
	if len(s.subscribers) >= maxSubscribers {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "stream_limit", "too many live streams", nil)
		return
	}
	if s.subscriberUse[subscriberKey] >= maxSubscribersPerUser {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "stream_limit", "too many live streams for this session", nil)
		return
	}
	replay := s.replayLocked(lastID)
	s.subscribers[ch] = struct{}{}
	s.subscriberKey[ch] = subscriberKey
	s.subscriberUse[subscriberKey]++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subscribers, ch)
		delete(s.subscriberKey, ch)
		if use := s.subscriberUse[subscriberKey]; use <= 1 {
			delete(s.subscriberUse, subscriberKey)
		} else {
			s.subscriberUse[subscriberKey] = use - 1
		}
		close(ch)
		s.mu.Unlock()
	}()
	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()
	for _, message := range replay {
		writeSSEMessage(w, message)
	}
	if len(replay) > 0 {
		flusher.Flush()
	}
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case message, ok := <-ch:
			if !ok {
				return
			}
			// Sessions and roles can be revoked while a browser keeps its
			// EventSource open. Re-check before delivering every event so a
			// disabled or demoted principal cannot receive the next change, and
			// the heartbeat below bounds exposure when the stream is otherwise
			// quiet.
			if s.Auth == nil {
				return
			}
			current, authorized := s.Auth.Authenticate(r.Context(), r)
			if !authorized || !auth.HasPermission(current, auth.PermissionStreamRead) {
				return
			}
			writeSSEMessage(w, message)
			flusher.Flush()
		case <-heartbeat.C:
			if s.Auth == nil {
				return
			}
			current, authorized := s.Auth.Authenticate(r.Context(), r)
			if !authorized || !auth.HasPermission(current, auth.PermissionStreamRead) {
				return
			}
			_, _ = w.Write([]byte(": heartbeat\n\n"))
			flusher.Flush()
		}
	}
}

func (s *Server) broadcast(value map[string]any) {
	payload := boundedSSEPayload(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subscribers == nil {
		s.subscribers = map[chan sseMessage]struct{}{}
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
		return []sseMessage{{id: s.nextEventID, payload: payload}}
	}
	if lastID == 0 || len(s.history) == 0 {
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

func writeSSEMessage(w io.Writer, message sseMessage) {
	_, _ = fmt.Fprintf(w, "id: %d\ndata: %s\n\n", message.id, message.payload)
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
