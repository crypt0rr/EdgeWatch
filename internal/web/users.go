package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type userCreatePayload struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

type userUpdatePayload struct {
	DisplayName *string `json:"display_name"`
	Role        *string `json:"role"`
	Enabled     *bool   `json:"enabled"`
}

func (s *Server) usersRoute(w http.ResponseWriter, r *http.Request, session store.Session, rest string) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		if r.Method == http.MethodGet {
			s.listUsers(w, r)
			return
		}
		if r.Method == http.MethodPost {
			s.createUser(w, r, session)
			return
		}
	}
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		s.getUser(w, r, id)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodPatch {
		s.updateUser(w, r, session, id)
		return
	}
	if len(parts) == 2 && parts[1] == "activation" && r.Method == http.MethodPost {
		s.issueActivation(w, r, session, id, "user.activation_issued")
		return
	}
	if len(parts) == 2 && parts[1] == "activation" && r.Method == http.MethodDelete {
		s.revokeActivation(w, r, session, id)
		return
	}
	if len(parts) == 2 && parts[1] == "password-reset" && r.Method == http.MethodPost {
		s.issueActivation(w, r, session, id, "user.password_reset_issued")
		return
	}
	if len(parts) == 2 && parts[1] == "sessions" && r.Method == http.MethodDelete {
		if _, err := s.Store.GetUser(r.Context(), id); errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, "store", "user could not be loaded", nil)
			return
		}
		if err := s.Store.DeleteUserSessionsWithAudit(r.Context(), id, store.AuditEntry{Action: "user.sessions_revoked", Detail: "user sessions revoked", ActorUserID: session.UserID, ActorUsername: session.Username}); err != nil {
			if s.writeAuditUnavailable(w, err, "user.sessions_revoked") {
				return
			}
			writeError(w, http.StatusInternalServerError, "store", "user sessions could not be revoked", nil)
			return
		}
		writeJSON(w, http.StatusNoContent, nil)
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	users, err := s.Store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", "users could not be loaded", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	user, err := s.Store.GetUser(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", "user could not be loaded", nil)
		return
	}
	writeJSON(w, http.StatusOK, user.Summary())
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, session store.Session) {
	w.Header().Set("Cache-Control", "no-store")
	var input userCreatePayload
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if input.Username == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "username is required", map[string]string{"username": "username is required"})
		return
	}
	if input.DisplayName == "" {
		// The username is a safe, useful default for API clients that do not
		// need a separate presentation label. The UI still asks for one so an
		// administrator can make the account recognizable at a glance.
		input.DisplayName = input.Username
	}
	if displayName, validationErr := validateDisplayName(input.DisplayName); validationErr != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", validationErr.Error(), map[string]string{"display_name": validationErr.Error()})
		return
	} else {
		input.DisplayName = displayName
	}
	if input.Role == "" {
		input.Role = store.RoleViewer
	}
	if err := store.ValidateUserRole(input.Role); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), map[string]string{"role": err.Error()})
		return
	}
	// A pending account deliberately has no usable password. Activation sets
	// the Argon2id hash after the invite token is redeemed.
	user := store.User{Username: input.Username, DisplayName: input.DisplayName, Role: input.Role, PasswordHash: "!pending", Enabled: false}
	plain, digest, err := auth.NewOpaqueToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invite_failed", "activation token could not be generated", nil)
		return
	}
	createdAt := time.Now().UTC()
	created, err := s.Store.CreateUserWithInvite(r.Context(), user, digest, createdAt, createdAt.Add(30*time.Minute), store.AuditEntry{Action: "user.created", Detail: fmt.Sprintf("user %s created by %s", input.Username, session.Username), ActorUserID: session.UserID, ActorUsername: session.Username})
	if err != nil {
		if isUnique(err) {
			writeError(w, http.StatusConflict, "conflict", "username is already in use", map[string]string{"username": "username is already in use"})
			return
		}
		if errors.Is(err, store.ErrAuditUnavailable) {
			s.writeAuditUnavailable(w, err, "user.created")
			return
		}
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": created.Summary(), "activation_token": plain, "activation_path": "/activate?token=" + plain})
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, actor store.Session, id string) {
	w.Header().Set("Cache-Control", "no-store")
	user, err := s.Store.GetUser(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", "user could not be loaded", nil)
		return
	}
	var input userUpdatePayload
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.DisplayName != nil {
		name, validationErr := validateDisplayName(*input.DisplayName)
		if validationErr != nil {
			writeError(w, http.StatusBadRequest, "validation_failed", validationErr.Error(), map[string]string{"display_name": validationErr.Error()})
			return
		}
		user.DisplayName = name
	}
	if input.Role != nil {
		if validationErr := store.ValidateUserRole(*input.Role); validationErr != nil {
			writeError(w, http.StatusBadRequest, "validation_failed", validationErr.Error(), map[string]string{"role": validationErr.Error()})
			return
		}
		user.Role = *input.Role
	}
	if input.Enabled != nil {
		if *input.Enabled && strings.HasPrefix(user.PasswordHash, "!pending") {
			writeError(w, http.StatusBadRequest, "pending_activation", "the user must redeem the activation token before the account can be enabled", nil)
			return
		}
		user.Enabled = *input.Enabled
	}
	wasSelf := actor.UserID == user.ID
	if wasSelf && ((input.Role != nil && user.Role != store.RoleAdministrator) || (input.Enabled != nil && !user.Enabled)) {
		writeError(w, http.StatusBadRequest, "self_admin_change", "you cannot demote or disable your own account", nil)
		return
	}
	if user.Role != store.RoleAdministrator || !user.Enabled {
		count, countErr := s.Store.CountEnabledAdministrators(r.Context())
		if countErr != nil {
			writeError(w, http.StatusInternalServerError, "store", "administrator count could not be checked", nil)
			return
		}
		if user.Role == store.RoleAdministrator && user.Enabled {
			// This branch is retained for clarity; the final-admin check below is
			// the relevant invariant when demoting or disabling an administrator.
			_ = count
		}
		if count <= 1 && (user.Role != store.RoleAdministrator || !user.Enabled) {
			wasAdmin, wasEnabled := false, false
			current, getErr := s.Store.GetUser(r.Context(), id)
			if getErr == nil {
				wasAdmin, wasEnabled = current.Role == store.RoleAdministrator, current.Enabled
			}
			if wasAdmin && wasEnabled {
				writeError(w, http.StatusBadRequest, "last_admin", "EdgeWatch must keep one enabled administrator", nil)
				return
			}
		}
	}
	user.UpdatedAt = time.Now().UTC()
	if err := s.Store.UpdateUser(r.Context(), user, true, store.AuditEntry{Action: "user.updated", Detail: fmt.Sprintf("user %s updated by %s", user.Username, actor.Username), ActorUserID: actor.UserID, ActorUsername: actor.Username}); err != nil {
		if s.writeAuditUnavailable(w, err, "user.updated") {
			return
		}
		if errors.Is(err, store.ErrLastAdministrator) {
			writeError(w, http.StatusBadRequest, "last_admin", "EdgeWatch must keep one enabled administrator", nil)
			return
		}
		if isUnique(err) {
			writeError(w, http.StatusConflict, "conflict", "username is already in use", nil)
			return
		}
		writeError(w, http.StatusBadRequest, "save_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, user.Summary())
}

func (s *Server) issueActivation(w http.ResponseWriter, r *http.Request, actor store.Session, id, action string) {
	w.Header().Set("Cache-Control", "no-store")
	user, err := s.Store.GetUser(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", "user could not be loaded", nil)
		return
	}
	plain, digest, err := auth.NewOpaqueToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invite_failed", "activation token could not be generated", nil)
		return
	}
	createdAt := time.Now().UTC()
	if strings.TrimSpace(action) == "" {
		action = "user.activation_issued"
	}
	if err := s.Store.CreateUserInviteWithAudit(r.Context(), digest, user.ID, createdAt, createdAt.Add(30*time.Minute), store.AuditEntry{Action: action, Detail: fmt.Sprintf("activation issued for %s", user.Username), ActorUserID: actor.UserID, ActorUsername: actor.Username}); err != nil {
		if errors.Is(err, store.ErrAuditUnavailable) {
			s.writeAuditUnavailable(w, err, action)
			return
		}
		writeError(w, http.StatusInternalServerError, "invite_failed", "activation token could not be stored", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"activation_token": plain, "activation_path": "/activate?token=" + plain, "expires_at": createdAt.Add(30 * time.Minute)})
}

func (s *Server) revokeActivation(w http.ResponseWriter, r *http.Request, actor store.Session, id string) {
	w.Header().Set("Cache-Control", "no-store")
	user, err := s.Store.GetUser(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", "user could not be loaded", nil)
		return
	}
	affected, err := s.Store.RevokeUserInvitesWithAudit(r.Context(), user.ID, time.Now().UTC(), store.AuditEntry{Action: "user.activation_revoked", Detail: fmt.Sprintf("activation links revoked for %s", user.Username), ActorUserID: actor.UserID, ActorUsername: actor.Username})
	if err != nil {
		if s.writeAuditUnavailable(w, err, "user.activation_revoked") {
			return
		}
		writeError(w, http.StatusInternalServerError, "revoke_failed", "activation link could not be revoked", nil)
		return
	}
	if affected == 0 {
		writeError(w, http.StatusNotFound, "no_active_activation", "no active activation link exists for this user", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) activateUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Token) == "" {
		writeError(w, http.StatusBadRequest, "activation_failed", "activation token is required", nil)
		return
	}
	if err := s.Auth.ActivateRequest(r.Context(), r, input.Token, input.Password); err != nil {
		if errors.Is(err, auth.ErrRateLimited) {
			w.Header().Set("Retry-After", "300")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many activation attempts; try again later", nil)
			return
		}
		if errors.Is(err, store.ErrAuditUnavailable) {
			s.auditFailure(err, "user.activated")
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "activation could not be completed because the security audit is unavailable", nil)
			return
		}
		writeError(w, http.StatusBadRequest, "activation_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"activated": true})
}
