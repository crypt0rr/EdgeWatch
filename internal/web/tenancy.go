package web

import (
	"errors"
	"net/http"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// requestTenant returns the store bound to the signed-in account's tenant.
// The API router calls it once per request, after authorization, and passes
// the result to the handlers that read tenant data. The scope always comes
// from the session: handlers never choose a tenant, and a test keeps this
// package from using the host and daemon scopes. An account without an
// active tenant is refused like a route it may not use.
func (s *Server) requestTenant(w http.ResponseWriter, r *http.Request, session store.Session) (*store.TenantStore, bool) {
	scope, err := s.Store.TenantScopeForSession(r.Context(), session)
	if errors.Is(err, store.ErrNoTenantScope) {
		writeError(w, http.StatusForbidden, "forbidden", "your account is not allowed to perform this action", map[string]string{"permission": "route"})
		return nil, false
	}
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return nil, false
	}
	return s.Store.Tenant(scope), true
}
