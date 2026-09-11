package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

const maxPaginationOffset = 10_000_000

func queryLimit(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 {
		n = 50
	}
	if n > 1000 {
		n = 1000
	}
	return n
}

func queryOffset(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if n < 0 {
		return 0
	}
	// Keep offsets bounded so an accidental huge value cannot turn into an
	// expensive SQLite scan. Clients can continue walking pages from zero.
	if n > maxPaginationOffset {
		return maxPaginationOffset
	}
	return n
}

func paginationJSON(offset, limit, total int) map[string]any {
	// Only add offset and limit after proving both values are in a range where
	// the addition cannot wrap. Paginated handlers normally normalize these
	// values, but this helper is also used by compatibility paths and tests.
	hasMore := false
	var next any
	if offset >= 0 && limit > 0 && total >= 0 && offset < total && limit < total-offset {
		hasMore = true
		next = offset + limit
	}
	return map[string]any{"limit": limit, "offset": offset, "total": total, "has_more": hasMore, "next_offset": next}
}

func pageSlice[T any](items []T, offset, limit int) ([]T, map[string]any) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	total := len(items)
	if offset >= total {
		return []T{}, paginationJSON(offset, limit, total)
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return items[offset:end], paginationJSON(offset, limit, total)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "request content type must be application/json", nil)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid", map[string]any{"reason": jsonDecodeReason(err)})
		return false
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = errors.New("request body must contain one JSON value")
		}
		writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid", map[string]any{"reason": jsonDecodeReason(err)})
		return false
	}
	return true
}

// jsonDecodeReason intentionally exposes only a small stable category. The
// decoder's raw error may echo unknown field names or fragments of a request
// body, which can disclose secrets submitted to a write-only endpoint.
func jsonDecodeReason(err error) string {
	if err == nil {
		return "invalid JSON"
	}
	if errors.As(err, new(*http.MaxBytesError)) {
		return "request body is too large"
	}
	if errors.Is(err, io.EOF) {
		return "request body is empty"
	}
	return "malformed or unsupported JSON"
}

func (s *Server) currentTime() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func (s *Server) storePendingTOTP(key, secret string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingTOTP == nil {
		s.pendingTOTP = make(map[string]pendingTOTP)
	}
	// Replacing an enrolment for the same session should not evict an
	// unrelated enrolment merely because the map is at capacity.
	delete(s.pendingTOTP, key)
	s.prunePendingTOTPLocked(now)
	for len(s.pendingTOTP) >= pendingTOTPMaxEntries {
		oldestKey := ""
		var oldestExpiry time.Time
		for candidate, pending := range s.pendingTOTP {
			if oldestKey == "" || pending.Expires.Before(oldestExpiry) {
				oldestKey, oldestExpiry = candidate, pending.Expires
			}
		}
		if oldestKey == "" {
			break
		}
		delete(s.pendingTOTP, oldestKey)
	}
	s.pendingTOTP[key] = pendingTOTP{Secret: secret, Expires: now.Add(10 * time.Minute)}
}

func (s *Server) prunePendingTOTPLocked(now time.Time) {
	if s.pendingTOTP == nil {
		s.pendingTOTP = make(map[string]pendingTOTP)
		return
	}
	for key, pending := range s.pendingTOTP {
		if !now.Before(pending.Expires) {
			delete(s.pendingTOTP, key)
		}
	}
}
func writeValidationError(w http.ResponseWriter, err error) {
	message := err.Error()
	details := map[string]string{}
	lower := strings.ToLower(message)
	// Keep validation responses useful to form clients without exposing an
	// implementation-specific error type. The API returns a stable field name
	// when the validator can identify one, while preserving the full message.
	fields := []string{"schedule", "timezone", "target", "tcp", "udp", "ports", "timeout", "resume_window", "timing", "baseline", "confirmations", "max_expanded_hosts", "name", "engine", "profile", "naabu", "scan_type", "rate", "workers", "retries", "warm_up_seconds", "address_batch_size", "operator_adjustable", "operator_bounds", "nse"}
	for _, field := range fields {
		if strings.Contains(lower, field) {
			details[field] = message
		}
	}
	if len(details) == 0 {
		details["job"] = message
	}
	writeError(w, http.StatusBadRequest, "validation_failed", message, details)
}

// auditFailure logs only the action and storage error; callers must not echo
// credential-bearing details when an audit insert fails. Sensitive handlers
// use this before writing their success response and fail closed.
func (s *Server) auditFailure(err error, action string) {
	s.Log.Error("security audit write failed", "action", action, "error", err)
}

func (s *Server) auditOptional(ctx context.Context, action, detail string) {
	s.auditOptionalEntry(ctx, store.AuditEntry{Action: action, Detail: detail})
}

func actorAudit(session store.Session, action, detail string) store.AuditEntry {
	return store.AuditEntry{Action: action, Detail: detail, ActorUserID: session.UserID, ActorUsername: session.Username, SourceIP: session.SourceIP}
}

func (s *Server) auditOptionalEntry(ctx context.Context, entry store.AuditEntry) {
	if err := s.Store.AuditEntry(ctx, entry); err != nil {
		s.auditFailure(err, entry.Action)
	}
}

func (s *Server) writeAuditUnavailable(w http.ResponseWriter, err error, action string) bool {
	if !errors.Is(err, store.ErrAuditUnavailable) {
		return false
	}
	s.auditFailure(err, action)
	writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the action was not committed because the security audit could not be recorded", nil)
	return true
}

// writeSecurityMutationError maps storage failures from account/security
// mutations to stable API contracts. In particular, never echo SQLite,
// encryption, or other implementation details back to a browser: those
// messages can contain schema details and, for credential-bearing paths,
// sensitive context. Callers should handle audit-unavailable errors before
// using this helper.
func writeSecurityMutationError(w http.ResponseWriter, err error, fallbackCode, fallbackMessage string) {
	switch {
	case errors.Is(err, store.ErrTOTPSecretLocked):
		writeError(w, http.StatusServiceUnavailable, "totp_locked", "TOTP credentials are unavailable; restore the encryption key before changing account security settings", nil)
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "account was modified; reload and try again", nil)
	case errors.Is(err, store.ErrLastAdministrator):
		writeError(w, http.StatusBadRequest, "last_admin", "EdgeWatch must keep one enabled administrator", nil)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "account was not found", nil)
	default:
		if fallbackCode == "" {
			fallbackCode = "save_failed"
		}
		if fallbackMessage == "" {
			fallbackMessage = "account security could not be saved"
		}
		writeError(w, http.StatusInternalServerError, fallbackCode, fallbackMessage, nil)
	}
}

func (s *Server) requireAudit(ctx context.Context, w http.ResponseWriter, action, detail string) bool {
	return s.requireAuditEntry(ctx, w, store.AuditEntry{Action: action, Detail: detail})
}

func (s *Server) requireAuditEntry(ctx context.Context, w http.ResponseWriter, entry store.AuditEntry) bool {
	if err := s.Store.AuditEntry(ctx, entry); err != nil {
		s.auditFailure(err, entry.Action)
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the action completed but its security audit record could not be written; verify the state before retrying", nil)
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, status int, code, message string, details any) {
	// The request middleware exposes X-Request-ID on every response, including
	// errors, so clients can correlate this payload without changing the stable
	// error JSON contract.
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "details": details}})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if status != http.StatusNoContent && value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}
func digest(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
