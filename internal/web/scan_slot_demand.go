package web

import (
	"net/http"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func (s *Server) scanSlotDemand(w http.ResponseWriter, r *http.Request, ts *store.TenantStore) {
	demand, err := s.App.ScanSlotDemand(r.Context(), ts)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	writeJSON(w, http.StatusOK, demand)
}
