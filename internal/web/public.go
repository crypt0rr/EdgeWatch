package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/rdap"
	"github.com/crypt0rr/edgewatch/internal/store"
)

const (
	// Public dashboards are deliberately cached only in memory. The cache is
	// short-lived so an administrator's publication changes become visible
	// quickly, while repeated anonymous requests cannot repeatedly walk legacy
	// scan history.
	publicDashboardCacheTTL     = 5 * time.Second
	publicDashboardBuildTimeout = 5 * time.Second
	// publicDashboardReadAttempts bounds how often one anonymous request
	// re-reads the publication after concurrent saves invalidated it.
	publicDashboardReadAttempts = 3
)

// errPublicDashboardChanged reports that a save invalidated the publication
// a request had read. The request reads the dashboard again rather than
// building or returning a payload from the withdrawn state.
var errPublicDashboardChanged = errors.New("public dashboard changed while it was loading")

// publicDashboardCache holds one rendered payload. generation is the
// publication generation of its page that it was built under; a save of the
// page bumps the generation, and an entry from an older generation is never
// served.
type publicDashboardCache struct {
	key        string
	generation uint64
	expiresAt  time.Time
	payload    []byte
}

// publicPageCache is the cache of one tenant's public page: the rendered
// payload, the shared build in flight, a recent build failure, and the
// page's publication generation. A save of the page bumps publicGen, so
// neither an entry nor a build from before the save is served. Each page has
// its own generation: a save of one tenant's page leaves the cache and the
// builds of every other page in place.
type publicPageCache struct {
	publicCache   *publicDashboardCache
	publicBuild   *publicDashboardBuild
	publicFailure *publicDashboardFailure
	publicGen     uint64
}

// publicPage returns the cache of the scope's page. The default tenant's page
// keeps the server's own cache, so with one tenant there is one cache, as
// before tenants. The caller holds publicCacheMu.
func (s *Server) publicPage(scope store.PublicScope) *publicPageCache {
	if scope == store.DefaultPublicScope() {
		return &s.publicPageCache
	}
	page := s.publicPages[scope.TenantID()]
	if page == nil {
		if s.publicPages == nil {
			s.publicPages = map[string]*publicPageCache{}
		}
		page = &publicPageCache{}
		s.publicPages[scope.TenantID()] = page
	}
	return page
}

// publicDashboardRateLimit is the rate-limit namespace of the legacy public
// URL. Each slug page has its own; see publicPageRateLimit.
const publicDashboardRateLimit = "public-dashboard"

// publicAPI is intentionally separate from /api/v1. It has no session
// middleware and exposes one fixed, sanitized projection without resource
// selectors that could be used to enumerate jobs or hosts. The legacy URL
// serves the default tenant's page, and /api/public/v1/dashboard/<slug> the
// page of the business unit with that slug. Both accept one trailing slash.
func (s *Server) publicAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	if r.Method == http.MethodGet && path == "/api/public/v1/dashboard" {
		s.servePublicPage(w, r, publicDashboardRateLimit, func(context.Context) (store.PublicScope, error) {
			return store.DefaultPublicScope(), nil
		})
		return
	}
	if r.Method == http.MethodGet && strings.HasPrefix(path, "/api/public/v1/dashboard/") {
		if slug := strings.TrimPrefix(path, "/api/public/v1/dashboard/"); slug != "" {
			s.servePublicPage(w, r, publicPageRateLimit(slug), func(ctx context.Context) (store.PublicScope, error) {
				return s.publicScopeForSlug(ctx, slug)
			})
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "endpoint not found", nil)
}

// publicSlugWellFormed reports whether slug can name a business unit: it
// has the form of a unit's slug and is not reserved.
func publicSlugWellFormed(slug string) bool {
	valid, err := store.ValidateTenantSlug(slug)
	return err == nil && valid == slug
}

// publicPageRateLimit returns the rate-limit namespace of the page at
// /api/public/v1/dashboard/<slug>. Each well-formed slug has its own,
// whether or not a unit publishes a page under it, so a busy page does not
// throttle another, and a slug without a page is limited exactly as a slug
// whose page is withdrawn. Addresses that cannot name a unit share one
// namespace, so they cannot add limiter keys without bound.
func publicPageRateLimit(slug string) string {
	if !publicSlugWellFormed(slug) {
		return publicDashboardRateLimit + "/*"
	}
	return publicDashboardRateLimit + "/" + slug
}

// publicSlugPagesEnabled reports whether business units may publish pages
// under their slugs. While experimental.business_units is off, every slug
// page answers as a page that is not enabled.
func (s *Server) publicSlugPagesEnabled() bool {
	return s.App != nil && s.App.Config != nil && s.App.Config.BusinessUnitsEnabled()
}

// publicScopeForSlug returns the public scope of the page at
// /api/public/v1/dashboard/<slug>. It returns the zero scope while business
// units are off, and for a slug that cannot name a unit, an unknown slug, a
// unit that is not active, and a page that is not enabled. servePublicPage
// answers the zero scope exactly as the default tenant's page when that page
// is not enabled, so the answer never tells whether a unit has the slug.
func (s *Server) publicScopeForSlug(ctx context.Context, slug string) (store.PublicScope, error) {
	if !s.publicSlugPagesEnabled() || !publicSlugWellFormed(slug) {
		return store.PublicScope{}, nil
	}
	scope, err := s.Store.PublicScopeBySlug(ctx, slug)
	if errors.Is(err, store.ErrNotFound) {
		return store.PublicScope{}, nil
	}
	return scope, err
}

// writePublicDisabled answers a request for a page that is not published.
func writePublicDisabled(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "public_disabled", "public status is not enabled", nil)
}

// servePublicPage answers an anonymous request for a published page. It
// counts the request in namespace, the page's rate-limit namespace, and then
// resolves the scope of the page's tenant; the zero scope names no page.
// Every read goes through the scope's PublicStore, and the payload is cached
// for that scope only.
func (s *Server) servePublicPage(w http.ResponseWriter, r *http.Request, namespace string, resolve func(context.Context) (store.PublicScope, error)) {
	if !s.allowAnonymousRequest(r, namespace) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "public status requests are temporarily rate limited", nil)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	ctx, cancel := context.WithTimeout(r.Context(), publicDashboardBuildTimeout)
	defer cancel()
	scope, err := resolve(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusGatewayTimeout, "public_dashboard_timeout", "public status took too long to load", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "public_dashboard", "public status could not be loaded", nil)
		return
	}
	if scope.TenantID() == "" {
		writePublicDisabled(w)
		return
	}
	if payload, ok := s.cachedPublicPageResponse(scope); ok {
		writeJSON(w, http.StatusOK, json.RawMessage(payload))
		return
	}
	public := s.Store.Public(scope)
	for attempt := 1; ; attempt++ {
		// Capture the page's generation before the read. A save of the page
		// that commits after this point bumps it, so a payload from the
		// dashboard read below can neither be cached nor returned once the
		// save has invalidated it.
		generation := s.publicPageGeneration(scope)
		// The read finds no page unless the tenant is active and its page
		// is enabled.
		dashboard, err := public.GetPublicDashboard(ctx)
		if errors.Is(err, store.ErrNotFound) {
			writePublicDisabled(w)
			return
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				writeError(w, http.StatusGatewayTimeout, "public_dashboard_timeout", "public status took too long to load", nil)
				return
			}
			writeError(w, http.StatusInternalServerError, "public_dashboard", "public status could not be loaded", nil)
			return
		}
		if !dashboard.Enabled {
			writePublicDisabled(w)
			return
		}
		payload, err := s.cachedPublicPagePayload(ctx, scope, generation, dashboard)
		if errors.Is(err, errPublicDashboardChanged) {
			if attempt < publicDashboardReadAttempts {
				continue
			}
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusServiceUnavailable, "public_dashboard_changed", "public status is being updated; try again shortly", nil)
			return
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				writeError(w, http.StatusGatewayTimeout, "public_dashboard_timeout", "public status took too long to load", nil)
				return
			}
			writeError(w, http.StatusInternalServerError, "public_dashboard", "public status could not be loaded", nil)
			return
		}
		writeJSON(w, http.StatusOK, json.RawMessage(payload))
		return
	}
}

// publicPageGeneration returns the publication generation of the scope's
// page.
func (s *Server) publicPageGeneration(scope store.PublicScope) uint64 {
	s.publicCacheMu.Lock()
	defer s.publicCacheMu.Unlock()
	return s.publicPage(scope).publicGen
}

func publicDashboardCacheKey(dashboard store.PublicDashboard) string {
	raw, err := json.Marshal(dashboard)
	if err != nil {
		return ""
	}
	return string(raw)
}

// cachedPublicPagePayload returns the rendered payload for dashboard, the
// scope's page, which the caller read under generation. It returns
// errPublicDashboardChanged as soon as a save of the page has bumped its
// generation, so the caller re-reads the publication instead of building,
// caching, or returning content that the save withdrew.
func (s *Server) cachedPublicPagePayload(ctx context.Context, scope store.PublicScope, generation uint64, dashboard store.PublicDashboard) ([]byte, error) {
	key := publicDashboardCacheKey(dashboard)
	for {
		now := s.currentTime()
		s.publicCacheMu.Lock()
		page := s.publicPage(scope)
		if generation != page.publicGen {
			s.publicCacheMu.Unlock()
			return nil, errPublicDashboardChanged
		}
		if cached := page.publicCache; cached != nil && cached.generation == generation && cached.key == key && now.Before(cached.expiresAt) {
			payload := append([]byte(nil), cached.payload...)
			s.publicCacheMu.Unlock()
			return payload, nil
		}
		if failure := page.publicFailure; failure != nil && now.Before(failure.retryAt) {
			err := failure.err
			s.publicCacheMu.Unlock()
			return nil, err
		}
		if building := page.publicBuild; building != nil {
			s.publicCacheMu.Unlock()
			select {
			case <-building.done:
				// A build started under an older generation may have failed only
				// because it read the withdrawn publication; do not adopt its error.
				if building.err != nil && building.generation == generation {
					return nil, building.err
				}
				// The builder either populated a matching cache or completed while
				// a concurrent dashboard update invalidated its generation. Recheck
				// under the lock so an obsolete payload is never returned.
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		building := &publicDashboardBuild{done: make(chan struct{}), generation: generation}
		page.publicBuild = building
		s.publicCacheMu.Unlock()
		// Strip cancellation and deadlines so this shared work outlives a
		// disconnected requester. The helper applies its own bounded timeout.
		go s.buildPublicDashboardPayload(context.WithoutCancel(ctx), scope, page, building, generation, key, dashboard)
		select {
		case <-building.done:
			if building.err != nil {
				return nil, building.err
			}
			continue
		case <-ctx.Done():
			// The shared build intentionally continues with its own bounded
			// service context. This requester may stop waiting independently.
			return nil, ctx.Err()
		}
	}
}

// buildPublicDashboardPayload renders the scope's page from the scope's
// PublicStore and caches the result in page, the scope's cache.
func (s *Server) buildPublicDashboardPayload(parent context.Context, scope store.PublicScope, page *publicPageCache, building *publicDashboardBuild, generation uint64, key string, dashboard store.PublicDashboard) {
	buildCtx, cancel := context.WithTimeout(parent, publicDashboardBuildTimeout)
	defer cancel()
	var response publicDashboardResponse
	var err error
	if s.publicDashboardBuildFunc != nil {
		response, err = s.publicDashboardBuildFunc(buildCtx, dashboard)
	} else {
		response, err = s.publicPageResponse(buildCtx, s.Store.Public(scope), dashboard)
	}
	var payload []byte
	if err == nil {
		payload, err = json.Marshal(response)
	}
	now := s.currentTime()

	s.publicCacheMu.Lock()
	building.err = err
	if err == nil && generation == page.publicGen {
		page.publicCache = &publicDashboardCache{key: key, generation: generation, expiresAt: now.Add(publicDashboardCacheTTL), payload: append([]byte(nil), payload...)}
		page.publicFailure = nil
	} else if err != nil && generation == page.publicGen {
		// Short negative caching prevents a broken legacy snapshot or slow store
		// from being rebuilt for every anonymous request. It expires quickly so a
		// transient failure does not hide a recovered dashboard.
		page.publicFailure = &publicDashboardFailure{retryAt: now.Add(time.Second), err: err}
	}
	if page.publicBuild == building {
		page.publicBuild = nil
		close(building.done)
	}
	s.publicCacheMu.Unlock()
}

// invalidatePublicPage drops the cached page of the scope's tenant after a
// save of that page. It bumps the page's generation, so a build of the page
// already in flight neither caches nor returns its result. The other
// tenants' pages keep their cache.
func (s *Server) invalidatePublicPage(scope store.PublicScope) {
	s.publicCacheMu.Lock()
	page := s.publicPage(scope)
	page.publicGen++
	page.publicCache = nil
	page.publicFailure = nil
	s.publicCacheMu.Unlock()
}

// cachedPublicPageResponse is the anonymous fast path. It serves only an
// unexpired entry of the scope's page built under the page's current
// generation.
func (s *Server) cachedPublicPageResponse(scope store.PublicScope) ([]byte, bool) {
	now := s.currentTime()
	s.publicCacheMu.Lock()
	defer s.publicCacheMu.Unlock()
	page := s.publicPage(scope)
	cached := page.publicCache
	if cached == nil || cached.generation != page.publicGen || !now.Before(cached.expiresAt) {
		return nil, false
	}
	return append([]byte(nil), cached.payload...), true
}

func (s *Server) allowAnonymousRequest(r *http.Request, namespace string) bool {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		namespace = "anonymous"
	}
	key := namespace + ":" + s.clientIP(r)
	now := time.Now().UTC()
	cutoff := now.Add(-time.Minute)
	s.publicMu.Lock()
	defer s.publicMu.Unlock()
	if s.publicHits == nil {
		s.publicHits = map[string][]time.Time{}
	}
	hits := s.publicHits[key][:0]
	for _, hit := range s.publicHits[key] {
		if hit.After(cutoff) {
			hits = append(hits, hit)
		}
	}
	if len(hits) >= 120 {
		s.publicHits[key] = hits
		return false
	}
	s.publicHits[key] = append(hits, now)
	if len(s.publicHits) > 4096 {
		for candidate, values := range s.publicHits {
			if len(values) == 0 || !values[len(values)-1].After(cutoff) {
				delete(s.publicHits, candidate)
			}
		}
		// A burst of distinct source addresses can otherwise keep the map above
		// its bound when all entries are still fresh. Evict the oldest buckets
		// until the memory bound is restored.
		for len(s.publicHits) > 4096 {
			oldestKey := ""
			var oldest time.Time
			for candidate, values := range s.publicHits {
				if len(values) == 0 {
					oldestKey = candidate
					break
				}
				last := values[len(values)-1]
				if oldestKey == "" || last.Before(oldest) {
					oldestKey, oldest = candidate, last
				}
			}
			if oldestKey == "" {
				break
			}
			delete(s.publicHits, oldestKey)
		}
	}
	return true
}

// publicDashboardPayload replaces the whole publication. UpdatedAt is the
// concurrency token: the updated_at value from the GET response the editor
// loaded. A save based on an older value is rejected with 409.
type publicDashboardPayload struct {
	Enabled      bool                         `json:"enabled"`
	Title        string                       `json:"title"`
	Introduction string                       `json:"introduction"`
	Hosts        []publicDashboardHostPayload `json:"hosts"`
	UpdatedAt    *string                      `json:"updated_at"`
}

// publicDashboardHostPayload contains only the writable host selection. The
// GET response includes created_at as read-only metadata, so accept that
// field when a client round-trips a response but never require it (or decode
// it as time.Time). Older console builds sent an empty created_at string,
// which strict JSON decoding correctly rejected as an invalid timestamp.
type publicDashboardHostPayload struct {
	JobID     string  `json:"job_id"`
	Address   string  `json:"address"`
	CreatedAt *string `json:"created_at,omitempty"`
}

// publicDashboardTextError explains why the public-status title or
// introduction is rejected, naming only the fields that fail. Both are shown
// as single lines, so neither may contain a line break. It returns an empty
// message when both are valid.
func publicDashboardTextError(title, introduction string) (string, map[string]string) {
	details := map[string]string{}
	var reasons []string
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{{"title", title, 120}, {"introduction", introduction, 500}} {
		var problems []string
		if utf8.RuneCountInString(field.value) > field.limit {
			problems = append(problems, fmt.Sprintf("must be at most %d characters", field.limit))
		}
		if strings.ContainsAny(field.value, "\r\n") {
			problems = append(problems, "cannot contain line breaks")
		}
		if len(problems) == 0 {
			continue
		}
		reason := "the public status " + field.name + " " + strings.Join(problems, " and ")
		details[field.name] = reason
		reasons = append(reasons, reason)
	}
	if len(reasons) == 0 {
		return "", nil
	}
	return strings.Join(reasons, "; "), details
}

// publicDashboardRoute reads and saves the public page of the session's
// tenant. A selection is checked through that tenant's public scope, the
// reads its public page renders with, so only a host of the tenant's own jobs
// can be published.
func (s *Server) publicDashboardRoute(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	dashboard, err := ts.GetPublicDashboard(r.Context())
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "store", "public dashboard could not be loaded", nil)
		return
	}
	if r.Method == http.MethodGet {
		if errors.Is(err, store.ErrNotFound) {
			dashboard = store.PublicDashboard{Title: "EdgeWatch public status", Hosts: []store.PublicDashboardHost{}}
		}
		writeJSON(w, http.StatusOK, dashboard)
		return
	}
	var input publicDashboardPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.UpdatedAt == nil || strings.TrimSpace(*input.UpdatedAt) == "" {
		writeError(w, http.StatusBadRequest, "revision_required", "the updated_at value of the loaded public status is required", map[string]string{"updated_at": "send the updated_at value from the public status you loaded"})
		return
	}
	expectedUpdatedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(*input.UpdatedAt))
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "updated_at must be an RFC 3339 timestamp", map[string]string{"updated_at": "send the updated_at value from the public status you loaded"})
		return
	}
	input.Title = strings.TrimSpace(input.Title)
	input.Introduction = strings.TrimSpace(input.Introduction)
	if input.Title == "" {
		input.Title = "EdgeWatch public status"
	}
	if message, details := publicDashboardTextError(input.Title, input.Introduction); message != "" {
		writeError(w, http.StatusBadRequest, "validation_failed", message, details)
		return
	}
	if len(input.Hosts) > 1000 {
		writeError(w, http.StatusBadRequest, "validation_failed", "at most 1000 hosts may be published", nil)
		return
	}
	selections := make([]store.PublicDashboardHost, 0, len(input.Hosts))
	for _, selection := range input.Hosts {
		if strings.TrimSpace(selection.JobID) == "" || net.ParseIP(strings.TrimSpace(selection.Address)) == nil {
			writeError(w, http.StatusBadRequest, "validation_failed", fmt.Sprintf("host %s is not present in a successful scan for this job", selection.Address), map[string]string{"hosts": "each published host must belong to a successful scan"})
			return
		}
		selections = append(selections, store.PublicDashboardHost{JobID: strings.TrimSpace(selection.JobID), Address: canonicalHostAddress(selection.Address)})
	}
	// Validate against retained history even when a job is archived. Archived
	// selections remain visible in the admin picker so they can be removed (or
	// become publishable again if the job is restored), while the public
	// response below deliberately omits them.
	scope, err := ts.PublicScope()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", "published hosts could not be checked", nil)
		return
	}
	published, err := s.loadPublishedHosts(r.Context(), s.Store.Public(scope), selections, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", "published hosts could not be checked", nil)
		return
	}
	hosts := make([]store.PublicDashboardHost, 0, len(selections))
	for _, selection := range selections {
		key := publicSelectionKey(selection.JobID, selection.Address)
		if _, ok := published[key]; !ok {
			writeError(w, http.StatusBadRequest, "validation_failed", fmt.Sprintf("host %s is not present in a successful scan for this job", selection.Address), map[string]string{"hosts": "each published host must belong to a successful scan"})
			return
		}
		hosts = append(hosts, selection)
	}
	dashboard.Enabled, dashboard.Title, dashboard.Introduction = input.Enabled, input.Title, input.Introduction
	if err := ts.SavePublicDashboardIfCurrent(r.Context(), expectedUpdatedAt, dashboard, hosts, store.AuditEntry{Action: "public_dashboard.updated", Detail: fmt.Sprintf("dashboard updated by %s; enabled=%t; hosts=%d", session.Username, input.Enabled, len(hosts)), ActorUserID: session.UserID, ActorUsername: session.Username}); err != nil {
		if s.writeAuditUnavailable(w, err, "public_dashboard.updated") {
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "public status was changed by another administrator; reload before saving", nil)
			return
		}
		s.writeInternalError(w, r, "save_failed", err)
		return
	}
	s.invalidatePublicPage(scope)
	result, err := ts.GetPublicDashboard(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", "public dashboard could not be loaded after saving", nil)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type publicHostLookup struct {
	Job     store.JobRecord
	Host    store.ScanHost
	Summary model.ScanSummary
}

func publicSelectionKey(jobID, address string) string {
	return strings.TrimSpace(jobID) + "\x00" + canonicalHostAddress(address)
}

// loadPublishedHosts resolves all selected addresses through bounded set-based
// reads of one tenant's public scope: the anonymous page passes its scope's
// store, and the administrator's route the store of the session tenant's
// scope. A selection of another tenant's job resolves to nothing. Indexed
// observations are loaded in one query; only selections absent from that
// projection use the bounded legacy fallback.
func (s *Server) loadPublishedHosts(ctx context.Context, public *store.PublicStore, selections []store.PublicDashboardHost, includeArchived bool) (map[string]publicHostLookup, error) {
	lookup := map[string]publicHostLookup{}
	if len(selections) == 0 {
		return lookup, nil
	}
	jobs, err := public.ListJobs(ctx, true)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]store.JobRecord, len(jobs))
	for _, job := range jobs {
		byID[job.ID] = job
	}
	normalized := make([]store.PublicDashboardHost, 0, len(selections))
	seen := make(map[string]struct{}, len(selections))
	for _, selection := range selections {
		selection.JobID = strings.TrimSpace(selection.JobID)
		selection.Address = canonicalHostAddress(selection.Address)
		key := publicSelectionKey(selection.JobID, selection.Address)
		if selection.JobID == "" || net.ParseIP(selection.Address) == nil {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, selection)
	}
	indexed, err := public.GetLatestSuccessfulJobHosts(ctx, normalized)
	if err != nil {
		return nil, err
	}
	for _, item := range indexed {
		job, ok := byID[item.Selection.JobID]
		if !ok || (!includeArchived && job.Archived) {
			continue
		}
		lookup[publicSelectionKey(item.Selection.JobID, item.Selection.Address)] = publicHostLookup{Job: job, Host: item.Host, Summary: item.Summary}
	}
	missing := make([]store.PublicDashboardHost, 0)
	for _, selection := range normalized {
		if _, ok := lookup[publicSelectionKey(selection.JobID, selection.Address)]; ok {
			continue
		}
		job, ok := byID[selection.JobID]
		if ok && (includeArchived || !job.Archived) {
			missing = append(missing, selection)
		}
	}
	legacy, err := legacyPublicHosts(ctx, public, missing)
	if err != nil {
		return nil, err
	}
	for _, item := range legacy {
		job, ok := byID[item.Selection.JobID]
		if !ok || (!includeArchived && job.Archived) {
			continue
		}
		lookup[publicSelectionKey(item.Selection.JobID, item.Selection.Address)] = publicHostLookup{Job: job, Host: item.Host, Summary: item.Summary}
	}
	return lookup, nil
}

type publicDashboardResponse struct {
	Title        string               `json:"title"`
	Introduction string               `json:"introduction,omitempty"`
	UpdatedAt    interface{}          `json:"updated_at"`
	Hosts        []publicHostResponse `json:"hosts"`
}

type publicHostResponse struct {
	Job            string               `json:"job"`
	Address        string               `json:"address"`
	AddressFamily  string               `json:"address_family,omitempty"`
	Public         bool                 `json:"public"`
	Private        bool                 `json:"private"`
	LastSuccessful interface{}          `json:"last_successful_scan,omitempty"`
	OpenPorts      []publicPortResponse `json:"open_ports,omitempty"`
	OpenFiltered   []publicPortResponse `json:"open_filtered_ports,omitempty"`
	Rdap           *publicRdapResponse  `json:"rdap,omitempty"`
}

type publicPortResponse struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Service  string `json:"service,omitempty"`
}

type publicRdapResponse struct {
	Status       string      `json:"status"`
	NetworkName  string      `json:"network_name,omitempty"`
	Country      string      `json:"country,omitempty"`
	Registry     string      `json:"registry,omitempty"`
	Organization []string    `json:"organizations,omitempty"`
	Prefix       string      `json:"prefix,omitempty"`
	SourceURL    string      `json:"source_url,omitempty"`
	FetchedAt    interface{} `json:"fetched_at,omitempty"`
	Stale        bool        `json:"stale,omitempty"`
	Message      string      `json:"message,omitempty"`
}

// publicPageResponse renders the published page from the reads of its
// tenant's public scope.
func (s *Server) publicPageResponse(ctx context.Context, public *store.PublicStore, dashboard store.PublicDashboard) (publicDashboardResponse, error) {
	response := publicDashboardResponse{Title: dashboard.Title, Introduction: dashboard.Introduction, UpdatedAt: dashboard.UpdatedAt, Hosts: []publicHostResponse{}}
	lookup, err := s.loadPublishedHosts(ctx, public, dashboard.Hosts, false)
	if err != nil {
		return response, err
	}
	for _, selection := range dashboard.Hosts {
		item, ok := lookup[publicSelectionKey(selection.JobID, selection.Address)]
		if !ok {
			continue
		}
		response.Hosts = append(response.Hosts, s.publicHostFromObservation(ctx, item.Job.Job.Name, item.Host.Host, item.Summary))
	}
	return response, nil
}

const legacyPublicScanLimit = 1000

// legacyPublicHosts resolves selections from the legacy scans, which predate
// the host index, of the public scope's jobs.
func legacyPublicHosts(ctx context.Context, public *store.PublicStore, selections []store.PublicDashboardHost) (map[string]store.PublicDashboardHostResult, error) {
	wanted := make(map[string]store.PublicDashboardHost, len(selections))
	jobIDs := make([]string, 0, len(selections))
	seenJobs := map[string]struct{}{}
	for _, selection := range selections {
		selection.JobID = strings.TrimSpace(selection.JobID)
		selection.Address = canonicalHostAddress(selection.Address)
		if selection.JobID == "" || net.ParseIP(selection.Address) == nil {
			continue
		}
		key := publicSelectionKey(selection.JobID, selection.Address)
		wanted[key] = selection
		if _, ok := seenJobs[selection.JobID]; !ok {
			seenJobs[selection.JobID] = struct{}{}
			jobIDs = append(jobIDs, selection.JobID)
		}
	}
	results := make(map[string]store.PublicDashboardHostResult, len(wanted))
	if len(wanted) == 0 {
		return results, nil
	}
	// Query each job independently. A single LIMIT across all jobs lets a
	// high-volume job consume the entire window and starve a low-volume job's
	// published host.
	for _, requestedJobID := range jobIDs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		scans, err := public.ListLegacyPublicScans(ctx, requestedJobID, legacyPublicScanLimit)
		if err != nil {
			return nil, err
		}
		for _, legacyScan := range scans {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			raw := legacyScan.Snapshot
			if len(raw) > 8<<20 {
				continue
			}
			page, err := observationsForSnapshotBytes(raw)
			if err != nil {
				// A malformed historical payload must not make an otherwise
				// healthy public dashboard unavailable. It cannot produce a
				// trustworthy host result, so skip it and continue to older rows.
				continue
			}
			for _, host := range page.Items {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				key := publicSelectionKey(legacyScan.JobID, host.Address)
				selection, ok := wanted[key]
				if !ok {
					continue
				}
				if _, already := results[key]; already {
					continue
				}
				summary := model.ScanSummary{ID: legacyScan.ID, JobID: legacyScan.JobID, Job: legacyScan.Job, Status: legacyScan.Status, Error: legacyScan.Error, NmapVersion: legacyScan.NmapVersion, ConfigHash: legacyScan.ConfigHash, StartedAt: parsePublicTime(legacyScan.StartedAt), FinishedAt: parsePublicTime(legacyScan.FinishedAt), JobRevision: legacyScan.JobRevision}
				results[key] = store.PublicDashboardHostResult{Selection: selection, Host: store.ScanHost{ScanID: legacyScan.ID, DataQuality: page.DataQuality, Host: host}, Summary: summary}
				if len(results) == len(wanted) {
					break
				}
			}
			if len(results) == len(wanted) {
				break
			}
		}
		if len(results) == len(wanted) {
			break
		}
	}
	return results, nil
}

func observationsForSnapshotBytes(raw []byte) (hostPage, error) {
	var snapshot model.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return hostPage{}, err
	}
	return observationsForSnapshot(snapshot)
}

func parsePublicTime(raw string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"} {
		if value, err := time.ParseInLocation(layout, strings.TrimSpace(raw), time.UTC); err == nil {
			return value
		}
	}
	return time.Time{}
}

func (s *Server) publicHostFromObservation(ctx context.Context, job string, host model.HostObservation, scan model.ScanSummary) publicHostResponse {
	address := canonicalHostAddress(host.Address)
	ip := net.ParseIP(address)
	result := publicHostResponse{Job: job, Address: address, AddressFamily: host.AddressFamily, LastSuccessful: scan.FinishedAt}
	if ip != nil {
		result.Private = isPrivateAddress(ip)
		result.Public = !result.Private
	}
	for _, protocol := range host.Protocols {
		for _, port := range protocol.Ports {
			entry := publicPortResponse{Protocol: protocol.Protocol, Port: port.Port}
			if port.Service != nil {
				entry.Service = port.Service.Name
			}
			switch port.State {
			case "open":
				result.OpenPorts = append(result.OpenPorts, entry)
			case "open|filtered":
				result.OpenFiltered = append(result.OpenFiltered, entry)
			}
		}
	}
	// RDAP is deliberately cache-only for guests. Opening the public page must
	// not turn an unauthenticated request into an outbound registry proxy.
	if result.Public && s.App != nil && s.App.Config != nil && s.App.Config.RDAPEnabled() {
		if cached, err := s.Store.GetRDAPCache(ctx, address); err == nil {
			if payload, decodeErr := decodeCachedPublicRDAP(cached.Payload); decodeErr == nil {
				payload.FetchedAt = cached.FetchedAt
				now := time.Now().UTC()
				if s.now != nil {
					now = s.now().UTC()
				}
				// Guests may receive a stale cache entry only during the
				// bounded seven-day fallback window. Once stale_until passes,
				// omit registration data rather than publishing indefinitely old
				// ownership information.
				if cached.StaleUntil.IsZero() || !now.Before(cached.StaleUntil) {
					return result
				}
				if !now.Before(cached.ExpiresAt) {
					payload.Status, payload.Stale = "stale", true
				} else if payload.Status == "" {
					payload.Status = "cached"
				}
				result.Rdap = payload
			}
		}
	}
	return result
}

func isPrivateAddress(ip net.IP) bool {
	return rdap.IsPrivateAddress(ip)
}

func publicRdapFromResult(result rdap.Result) *publicRdapResponse {
	return &publicRdapResponse{Status: result.Status, NetworkName: result.NetworkName, Country: result.Country, Registry: result.Registry, Organization: append([]string(nil), result.Organizations...), Prefix: result.Prefix, SourceURL: result.SourceURL, FetchedAt: result.FetchedAt, Stale: result.Stale, Message: result.Message}
}

func decodeCachedPublicRDAP(raw []byte) (*publicRdapResponse, error) {
	var result rdap.Result
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return publicRdapFromResult(result), nil
}
