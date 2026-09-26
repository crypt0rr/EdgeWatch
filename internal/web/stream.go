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
	// one intentional exception: it stays open and sends periodic heartbeats.
	// Remove the server deadline, then apply a fresh bounded deadline to every
	// individual write and flush below. The cancellation hook makes shutdown
	// and request cancellation interrupt a write immediately.
	responseController := http.NewResponseController(w)
	_ = responseController.SetWriteDeadline(time.Time{})
	writeCancellationDone := make(chan struct{})
	stopWriteCancellation := context.AfterFunc(streamCtx, func() {
		defer close(writeCancellationDone)
		_ = responseController.SetWriteDeadline(time.Now())
	})
	defer func() {
		if !stopWriteCancellation() {
			// Stop does not wait when the callback has already started. Do so
			// before returning the handler so the response controller cannot be
			// used after ServeHTTP has ended.
			<-writeCancellationDone
		}
	}()
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
	// Per-user limits must be keyed by the stable account identity, not by a
	// session hash. Otherwise one account can consume the entire nominal limit
	// simply by opening several browser sessions (or bypass it by rotating
	// sessions). Anonymous/future service sessions retain a hash fallback.
	subscriberKey := "user:" + strings.TrimSpace(session.UserID)
	if strings.TrimSpace(session.UserID) == "" {
		subscriberKey = "session:" + strings.TrimSpace(session.IDHash)
		if subscriberKey == "session:" {
			subscriberKey = "unknown"
		}
	}
	authKey := sseAuthorizationCacheKey(session)
	lastID := parseSSELastEventID(r.Header.Get("Last-Event-ID"))
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
	if s.sseSessionKey == nil {
		s.sseSessionKey = map[chan sseMessage]string{}
	}
	if s.sseUserKey == nil {
		s.sseUserKey = map[chan sseMessage]string{}
	}
	if s.sseIdentity == nil {
		s.sseIdentity = map[chan sseMessage]sseSubscriber{}
	}
	if channelClosed(shutdown) {
		s.mu.Unlock()
		return
	}
	if len(s.subscribers) >= maxSubscribers {
		s.mu.Unlock()
		s.setSSEWriteDeadline(w)
		writeSSELimit(w, flusher, "too many live streams")
		return
	}
	if s.subscriberUse[subscriberKey] >= maxSubscribersPerUser {
		s.mu.Unlock()
		s.setSSEWriteDeadline(w)
		writeSSELimit(w, flusher, "too many live streams for this session")
		return
	}
	// Every stream is in the everyone audience today. A narrower audience
	// derives the stream's viewer attributes from its session here.
	subscriber := sseSubscriber{}
	replay := s.replayForLocked(lastID, subscriber)
	s.subscribers[ch] = struct{}{}
	s.sseIdentity[ch] = subscriber
	s.subscriberKey[ch] = subscriberKey
	s.subscriberUse[subscriberKey]++
	s.sseCancels[ch] = streamCancel
	s.sseSessionKey[ch] = strings.TrimSpace(session.IDHash)
	s.sseUserKey[ch] = strings.TrimSpace(session.UserID)
	s.sseWG.Add(1)
	s.mu.Unlock()
	s.sseAuthMu.Lock()
	if authKey != "" {
		if s.sseAuthCache == nil {
			s.sseAuthCache = map[string]sseAuthCacheEntry{}
		}
		s.sseAuthCache[authKey] = sseAuthCacheEntry{session: session, checked: s.streamNow()}
	}
	s.sseAuthMu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subscribers, ch)
		delete(s.sseIdentity, ch)
		delete(s.subscriberKey, ch)
		delete(s.sseCancels, ch)
		delete(s.sseSessionKey, ch)
		delete(s.sseUserKey, ch)
		if use := s.subscriberUse[subscriberKey]; use <= 1 {
			delete(s.subscriberUse, subscriberKey)
		} else {
			s.subscriberUse[subscriberKey] = use - 1
		}
		close(ch)
		s.mu.Unlock()
		s.sseAuthMu.Lock()
		if authKey != "" {
			delete(s.sseAuthCache, authKey)
		}
		s.sseAuthMu.Unlock()
		s.sseWG.Done()
	}()
	// The API authenticates the request before registering the subscriber. A
	// revocation can still race that check while the replay is being prepared,
	// so perform one fresh read-only authorization before sending any bytes.
	// Direct stream fixtures without a cookie retain their existing behavior;
	// network requests always carry the cookie validated by api.
	if _, err := r.Cookie(auth.SessionCookie); err == nil && !s.streamAuthorizedFresh(streamCtx, r, authKey) {
		return
	}
	if !s.writeSSE(streamCtx, w, []byte(": connected\nretry: 5000\n\n")) {
		return
	}
	if !s.flushSSE(streamCtx, w, flusher) {
		return
	}
	for _, message := range replay {
		if !s.writeSSEMessage(streamCtx, w, message) {
			return
		}
	}
	if len(replay) > 0 {
		if !s.flushSSE(streamCtx, w, flusher) {
			return
		}
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
			if !s.streamAuthorized(streamCtx, r, authKey) {
				return
			}
			if !s.writeSSEMessage(streamCtx, w, message) {
				return
			}
			if !s.flushSSE(streamCtx, w, flusher) {
				return
			}
		case <-heartbeat.C:
			if !s.streamAuthorized(streamCtx, r, authKey) {
				return
			}
			if !s.writeSSE(streamCtx, w, []byte(": heartbeat\n\n")) {
				return
			}
			if !s.flushSSE(streamCtx, w, flusher) {
				return
			}
		}
	}
}

// revokeSSEStreams immediately withdraws in-process authorization after a
// session or account mutation commits. The store remains the source of truth;
// this index only makes already-open handlers react without waiting for the
// next heartbeat or the short authorization-cache TTL. Cancellation callbacks
// are collected while the subscriber mutex is held and invoked afterwards so
// the stream defer can safely remove its own indexes.
func (s *Server) revokeSSEStreams(sessionID, userID, exceptSessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	userID = strings.TrimSpace(userID)
	exceptSessionID = strings.TrimSpace(exceptSessionID)
	if sessionID == "" && userID == "" {
		return
	}

	s.sseAuthMu.Lock()
	for key, entry := range s.sseAuthCache {
		matchesSession := sessionID != "" && strings.TrimSpace(entry.session.IDHash) == sessionID
		matchesUser := userID != "" && strings.TrimSpace(entry.session.UserID) == userID
		if !matchesSession && !matchesUser {
			continue
		}
		if exceptSessionID != "" && strings.TrimSpace(entry.session.IDHash) == exceptSessionID {
			continue
		}
		delete(s.sseAuthCache, key)
	}
	s.sseAuthMu.Unlock()

	s.mu.Lock()
	cancels := make([]context.CancelFunc, 0)
	for ch, cancel := range s.sseCancels {
		streamSession := strings.TrimSpace(s.sseSessionKey[ch])
		streamUser := strings.TrimSpace(s.sseUserKey[ch])
		matchesSession := sessionID != "" && streamSession == sessionID
		matchesUser := userID != "" && streamUser == userID
		if !matchesSession && !matchesUser {
			continue
		}
		if exceptSessionID != "" && streamSession == exceptSessionID {
			continue
		}
		cancels = append(cancels, cancel)
	}
	s.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (s *Server) revokeSSESession(sessionID string) {
	s.revokeSSEStreams(sessionID, "", "")
}

func (s *Server) revokeSSEUser(userID string) {
	s.revokeSSEStreams("", userID, "")
}

func (s *Server) revokeSSEUserExcept(userID, exceptSessionID string) {
	s.revokeSSEStreams("", userID, exceptSessionID)
}

func (s *Server) sseWriteTimeoutValue() time.Duration {
	if s.sseWriteTimeout > 0 {
		return s.sseWriteTimeout
	}
	return defaultSSEWriteTimeout
}

func (s *Server) setSSEWriteDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(s.sseWriteTimeoutValue()))
}

func (s *Server) prepareSSEWrite(ctx context.Context, w http.ResponseWriter) bool {
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	s.setSSEWriteDeadline(w)
	if ctx != nil && ctx.Err() != nil {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now())
		return false
	}
	return true
}

func (s *Server) writeSSE(ctx context.Context, w http.ResponseWriter, data []byte) bool {
	if !s.prepareSSEWrite(ctx, w) {
		return false
	}
	_, err := w.Write(data)
	return err == nil
}

func (s *Server) writeSSEMessage(ctx context.Context, w http.ResponseWriter, message sseMessage) bool {
	if !s.prepareSSEWrite(ctx, w) {
		return false
	}
	return writeSSEMessage(w, message)
}

func (s *Server) flushSSE(ctx context.Context, w http.ResponseWriter, flusher http.Flusher) bool {
	if !s.prepareSSEWrite(ctx, w) {
		return false
	}
	flusher.Flush()
	return true
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
// initial authenticated request seeds a cache entry tied to that session;
// subsequent checks refresh it at most once per TTL (two seconds in production).
func (s *Server) streamAuthorized(ctx context.Context, r *http.Request, key string) bool {
	return s.streamAuthorizedWithCache(ctx, r, key, false)
}

// streamAuthorizedFresh performs the same session and permission validation as
// streamAuthorized but deliberately bypasses the short-lived cache. It is used
// once before the initial connection/replay so a revocation that races stream
// registration cannot grant the replay to a session that is no longer valid.
func (s *Server) streamAuthorizedFresh(ctx context.Context, r *http.Request, key string) bool {
	return s.streamAuthorizedWithCache(ctx, r, key, true)
}

func (s *Server) streamAuthorizedWithCache(ctx context.Context, r *http.Request, key string, force bool) bool {
	now := s.streamNow()
	ttl := s.sseAuthTTL
	if ttl <= 0 {
		ttl = defaultSSEAuthCacheTTL
	}
	if !force && key != "" {
		s.sseAuthMu.Lock()
		entry, ok := s.sseAuthCache[key]
		s.sseAuthMu.Unlock()
		if ok && now.Sub(entry.checked) < ttl {
			return auth.HasPermission(entry.session, auth.PermissionStreamRead)
		}
	}
	if s.Auth == nil {
		return false
	}
	current, authorized := s.Auth.AuthenticateReadOnly(ctx, r)
	if !authorized || !auth.HasPermission(current, auth.PermissionStreamRead) {
		if key != "" {
			s.sseAuthMu.Lock()
			delete(s.sseAuthCache, key)
			s.sseAuthMu.Unlock()
		}
		return false
	}
	if key != "" {
		s.sseAuthMu.Lock()
		if s.sseAuthCache == nil {
			s.sseAuthCache = map[string]sseAuthCacheEntry{}
		}
		s.sseAuthCache[key] = sseAuthCacheEntry{session: current, checked: now}
		s.sseAuthMu.Unlock()
	}
	return true
}

func sseAuthorizationCacheKey(session store.Session) string {
	if idHash := strings.TrimSpace(session.IDHash); idHash != "" {
		return "session:" + idHash
	}
	// A missing stable session identity must never fall back to a shared account
	// key: re-authenticate each time instead of reusing another stream's grant.
	return ""
}

func (s *Server) streamNow() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// seedSSEFallbackCursor keeps live updates useful while the durable cursor is
// temporarily unavailable. It is only a fallback: every later reservation is
// made with ReserveSSEEventIDsAfter(minimum=current) so durable IDs cannot
// overlap IDs emitted during the outage.
func (s *Server) seedSSEFallbackCursor(ctx context.Context) {
	if s.Store != nil {
		if id, err := s.Store.MaxEventID(ctx); err == nil && id > s.nextEventID {
			s.nextEventID = id
		}
	}
	if seed := uint64(s.streamNow().UnixNano()); seed > s.nextEventID {
		s.nextEventID = seed
	}
	s.eventIDLimit = ^uint64(0)
}

// retrySSEReservation attempts to recover a durable range after a startup or
// range-exhaustion failure using a background context. Broadcasts use this
// wrapper so a caller cannot accidentally cancel a reservation after it has
// started; the listener-owned retry loop passes its lifecycle context below.
func (s *Server) retrySSEReservation() {
	s.retrySSEReservationContext(context.Background())
}

// retrySSEReservationContext attempts to recover a durable range after a
// startup or range-exhaustion failure. SQLite is contacted without holding mu,
// so a slow or unavailable database cannot block subscriber registration,
// replay, or delivery of an already-reserved range. The reservation mutex
// prevents a concurrent broadcaster from emitting IDs while the minimum is
// being advanced and the durable range is switched in.
func (s *Server) retrySSEReservationContext(parent context.Context) {
	if s.Store == nil {
		return
	}
	s.sseReservationMu.Lock()
	defer s.sseReservationMu.Unlock()
	now := s.streamNow()
	s.mu.Lock()
	durable := s.sseDurable
	needsRange := s.nextEventID >= s.eventIDLimit
	retryAt := s.sseRetryAt
	minimum := s.nextEventID
	s.mu.Unlock()
	if durable && !needsRange {
		return
	}
	if !durable && !retryAt.IsZero() && now.Before(retryAt) {
		return
	}
	reserveCtx, cancel := context.WithTimeout(parent, 2*time.Second)
	start, end, err := s.Store.ReserveSSEEventIDsAfter(reserveCtx, sseEventIDBlockSize, minimum)
	cancel()
	if err != nil {
		s.mu.Lock()
		delay := s.sseRetryDelay
		if delay <= 0 {
			delay = defaultSSEReservationRetry
		}
		if delay < maxSSEReservationRetry {
			delay *= 2
			if delay > maxSSEReservationRetry {
				delay = maxSSEReservationRetry
			}
		}
		s.sseRetryDelay = delay
		s.sseRetryAt = now.Add(delay)
		// Keep fallback allocation available if a previously reserved range
		// just ended while SQLite was unavailable.
		if s.nextEventID >= s.eventIDLimit {
			if seed := uint64(now.UnixNano()); seed > s.nextEventID {
				s.nextEventID = seed
			}
			s.eventIDLimit = ^uint64(0)
		}
		s.sseDurable = false
		s.mu.Unlock()
		if s.Log != nil {
			s.Log.Warn("SSE event cursor reservation failed", "error", err, "retry_at", now.Add(delay))
		}
		return
	}
	s.mu.Lock()
	// All broadcasters take sseReservationMu before this point, so the
	// minimum used above includes every emitted fallback ID. Keep the check
	// defensive for embedded callers that mutate the fields directly.
	if s.nextEventID >= start {
		start = s.nextEventID + 1
		if start > end {
			s.mu.Unlock()
			return
		}
	}
	s.nextEventID = start - 1
	s.eventIDLimit = end
	s.sseDurable = true
	s.sseRetryAt = time.Time{}
	s.sseRetryDelay = 0
	s.mu.Unlock()
	if s.Log != nil {
		s.Log.Info("SSE event cursor reservation recovered", "range_start", start, "range_end", end)
	}
}

// runSSEReservationRetry keeps a startup outage recoverable even when no
// browser is currently connected. Broadcasts also call retrySSEReservation so
// a server assembled without a listener still heals on its next event.
func (s *Server) runSSEReservationRetry(ctx context.Context) {
	ticker := time.NewTicker(defaultSSEReservationRetry)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.retrySSEReservationContext(ctx)
		}
	}
}

// sseAudience names the live-update streams that may receive a message. The
// zero value names no stream: broadcastTo drops such a message rather than
// sending it to everyone. Narrower audiences, such as one unit or the
// platform administrators, add fields here and a matching rule to
// sseSubscriber.matches.
type sseAudience struct {
	everyone bool
}

// audienceEveryone addresses every authorized live-update stream.
func audienceEveryone() sseAudience {
	return sseAudience{everyone: true}
}

// valid reports whether the audience names any stream at all.
func (a sseAudience) valid() bool {
	return a.everyone
}

// sseSubscriber is the stream side of audience matching. Each stream
// registers one next to its channel, and both live delivery and replay ask it
// whether a message is meant for the stream. It has no fields while every
// audience is everyone; narrower audiences add the viewer attributes they
// match against.
type sseSubscriber struct{}

// matches reports whether a stream may receive a message for audience.
func (sseSubscriber) matches(audience sseAudience) bool {
	return audience.everyone
}

// broadcastTo sends a live update to the streams in audience and keeps it for
// their replay. A message without an audience is dropped and never widened to
// every stream. ctx bounds only the recovery of a durable event-ID range. A
// handler passes its request context, or context.WithoutCancel of it when a
// client that disconnects must not cut that recovery short; daemon callbacks
// and work that outlives a request pass a background context.
func (s *Server) broadcastTo(ctx context.Context, audience sseAudience, value map[string]any) {
	if !audience.valid() {
		if s.Log != nil {
			s.Log.Error("live update dropped because it has no audience", "type", value["type"])
		}
		return
	}
	payload := boundedSSEPayload(value)
	// Reserve/recover outside the subscriber mutex. The reservation mutex also
	// serializes ID allocation, preventing fallback IDs from racing a durable
	// range switch and making overlap impossible after an outage.
	s.retrySSEReservationContext(ctx)
	s.sseReservationMu.Lock()
	defer s.sseReservationMu.Unlock()
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
		// retrySSEReservation normally handles this before mu is acquired. If a
		// caller constructed a server with a zero range, seed a temporary cursor
		// rather than emitting duplicate zero IDs while the next retry is pending.
		if seed := uint64(s.streamNow().UnixNano()); seed > s.nextEventID {
			s.nextEventID = seed
		}
		s.eventIDLimit = ^uint64(0)
		s.sseDurable = false
		if s.sseRetryDelay <= 0 {
			s.sseRetryDelay = defaultSSEReservationRetry
		}
		if s.sseRetryAt.IsZero() {
			s.sseRetryAt = s.streamNow().Add(s.sseRetryDelay)
		}
	}
	if s.nextEventID == ^uint64(0) {
		if s.Log != nil {
			s.Log.Error("SSE event cursor exhausted")
		}
		return
	}
	s.nextEventID++
	message := sseMessage{id: s.nextEventID, payload: payload, audience: audience}
	s.history = append(s.history, message)
	s.historyBytes += len(payload)
	const maxHistory = 256
	const maxHistoryBytes = 1 << 20
	for len(s.history) > maxHistory || s.historyBytes > maxHistoryBytes {
		s.historyBytes -= len(s.history[0].payload)
		s.history = s.history[1:]
	}
	for ch := range s.subscribers {
		// A channel registered without an identity is matched as the zero
		// subscriber, which receives only messages for everyone.
		if !s.sseIdentity[ch].matches(audience) {
			continue
		}
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
			case ch <- sseMessage{id: message.id, payload: refresh, audience: audience}:
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

// replayForLocked returns what one stream replays after lastID: the refresh
// markers, which are meant for everyone, and the retained messages whose
// audience the subscriber matches.
func (s *Server) replayForLocked(lastID uint64, subscriber sseSubscriber) []sseMessage {
	var replay []sseMessage
	for _, message := range s.replayLocked(lastID) {
		if subscriber.matches(message.audience) {
			replay = append(replay, message)
		}
	}
	return replay
}

// replayLocked returns every retained message after lastID, preceded by a
// refresh marker when the history cannot cover the gap. Streams replay
// through replayForLocked, which applies their audience.
func (s *Server) replayLocked(lastID uint64) []sseMessage {
	if lastID > s.nextEventID {
		// Last-Event-ID is an untrusted replay request. A future marker can be
		// stale, malformed, or deliberately fabricated; it must never advance
		// the process cursor (or the next durable reservation). There is no
		// replayable server event in this case, so let the next live event use the
		// normal server-owned ID sequence.
		return nil
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
			return []sseMessage{{id: s.nextEventID, payload: payload, audience: audienceEveryone()}}
		}
		return nil
	}
	oldest := s.history[0].id
	var replay []sseMessage
	if oldest > 0 && lastID < oldest-1 {
		payload, _ := json.Marshal(map[string]any{"type": "refresh_required", "after": lastID})
		replay = append(replay, sseMessage{id: oldest - 1, payload: payload, audience: audienceEveryone()})
	}
	for _, message := range s.history {
		if message.id > lastID {
			replay = append(replay, message)
		}
	}
	return replay
}

const maxSSELastEventIDLength = 20 // max decimal representation of uint64

func parseSSELastEventID(value string) uint64 {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxSSELastEventIDLength {
		return 0
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return 0
		}
	}
	id, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return id
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
