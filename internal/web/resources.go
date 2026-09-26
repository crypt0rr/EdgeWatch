package web

import (
	"net/http"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The /jobs/{id}/* and /scans/{id}/* routes load the job or scan named in the
// path once, through the resolvers below, and pass the record to the handler.
// jobRoute does this for jobs; for scans, the API router calls getScan,
// getScanSummary and the scan*Route functions, which resolve the scan and,
// when it records one, its owning job. Scan cancellation is the exception: it
// acts on the in-memory active scan and never loads a stored record.
//
// Handlers never look the resource up again by its path ID, so these
// resolvers are the one place where a per-object check can later apply to
// every route of a resource.
//
// Before they shared these resolvers, the routes answered a failed lookup in
// slightly different ways. Each route now names its historical response
// explicitly, so none of them changes.

// jobLookupFailure selects the response for a job that could not be loaded.
// A missing job is always 404 "job not found"; the modes differ only in how
// they report any other store error.
type jobLookupFailure uint8

const (
	// jobMissingOnAnyError reports every lookup failure as a missing job.
	jobMissingOnAnyError jobLookupFailure = iota
	// jobStoreErrorInternal reports a store error as a correlated internal error.
	jobStoreErrorInternal
	// jobStoreErrorJobDetail reports a store error as an unavailable job detail.
	jobStoreErrorJobDetail
	// jobStoreErrorHostDetail reports a store error as an unavailable host detail.
	jobStoreErrorHostDetail
)

// scanLookupFailure selects the response for a scan summary that could not
// be loaded. A missing scan is always 404 "scan not found".
type scanLookupFailure uint8

const (
	// scanStoreErrorInternal reports a store error as a correlated internal error.
	scanStoreErrorInternal scanLookupFailure = iota
	// scanStoreErrorDetail reports a store error as an unavailable scan detail.
	scanStoreErrorDetail
)

// resolveJob loads the job with the given ID. When the job cannot be loaded it
// writes the response selected by failure and returns false.
func (s *Server) resolveJob(w http.ResponseWriter, r *http.Request, id string, failure jobLookupFailure) (store.JobRecord, bool) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err == nil {
		return record, true
	}
	switch {
	case failure == jobMissingOnAnyError || hostStoreNotFound(err):
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
	case failure == jobStoreErrorJobDetail:
		writeError(w, http.StatusInternalServerError, "store", "job detail could not be loaded", nil)
	case failure == jobStoreErrorHostDetail:
		writeError(w, http.StatusInternalServerError, "store", "host detail could not be loaded", nil)
	default:
		s.writeInternalError(w, r, "store", err)
	}
	return store.JobRecord{}, false
}

// resolveScanSummary loads a scan's metadata without its snapshot or change
// payloads. When the scan cannot be loaded it writes the response selected by
// failure and returns false.
func (s *Server) resolveScanSummary(w http.ResponseWriter, r *http.Request, id string, failure scanLookupFailure) (model.ScanSummary, bool) {
	summary, err := s.Store.GetScanSummary(r.Context(), id)
	if err == nil {
		return summary, true
	}
	switch {
	case hostStoreNotFound(err):
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
	case failure == scanStoreErrorDetail:
		writeError(w, http.StatusInternalServerError, "store", "scan detail could not be loaded", nil)
	default:
		s.writeInternalError(w, r, "store", err)
	}
	return model.ScanSummary{}, false
}

// resolveJobAndScan loads the job and then the scan named by a
// /jobs/{id}/scans/{scan}/* route. A scan that belongs to another job, or to
// no job, is reported as not found.
func (s *Server) resolveJobAndScan(w http.ResponseWriter, r *http.Request, jobID string, jobFailure jobLookupFailure, scanID string, scanFailure scanLookupFailure) (store.JobRecord, model.ScanSummary, bool) {
	job, ok := s.resolveJob(w, r, jobID, jobFailure)
	if !ok {
		return store.JobRecord{}, model.ScanSummary{}, false
	}
	summary, ok := s.resolveScanSummary(w, r, scanID, scanFailure)
	if !ok {
		return store.JobRecord{}, model.ScanSummary{}, false
	}
	if summary.JobID != job.ID {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return store.JobRecord{}, model.ScanSummary{}, false
	}
	return job, summary, true
}

// resolveScan loads the complete scan, including its snapshot and change
// list, for the full-result /scans/{id} endpoint. Every failure is reported
// as a missing scan.
func (s *Server) resolveScan(w http.ResponseWriter, r *http.Request, id string) (model.Scan, bool) {
	scan, err := s.Store.GetScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return model.Scan{}, false
	}
	return scan, true
}
