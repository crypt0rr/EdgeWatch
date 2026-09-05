// Package rdap provides deliberately small, on-demand RDAP enrichment for
// effective host addresses. It keeps only normalized registration metadata in
// SQLite; raw registry responses and contact records are never persisted.
package rdap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

const (
	defaultIPv4Bootstrap = "https://data.iana.org/rdap/ipv4.json"
	defaultIPv6Bootstrap = "https://data.iana.org/rdap/ipv6.json"
	maxResponseBytes     = 1 << 20
	lookupTimeout        = 8 * time.Second
	cacheFreshFor        = 24 * time.Hour
	cacheStaleFor        = 7 * 24 * time.Hour
	bootstrapFreshFor    = 24 * time.Hour
	cacheWriteTimeout    = time.Second
)

// Event is a normalized RDAP registration event. Only the event action and
// date are retained; contact and postal details are intentionally discarded.
type Event struct {
	Action string    `json:"action"`
	Date   time.Time `json:"date,omitempty"`
}

// Result is the safe subset of a registry response shown by the host pages.
// Status is one of success, cached, stale, private, disabled, or unavailable.
type Result struct {
	Status         string    `json:"status"`
	Address        string    `json:"address"`
	Registry       string    `json:"registry,omitempty"`
	NetworkName    string    `json:"network_name,omitempty"`
	Handle         string    `json:"handle,omitempty"`
	StartAddress   string    `json:"start_address,omitempty"`
	EndAddress     string    `json:"end_address,omitempty"`
	Prefix         string    `json:"prefix,omitempty"`
	Country        string    `json:"country,omitempty"`
	AllocationType string    `json:"allocation_type,omitempty"`
	Statuses       []string  `json:"statuses,omitempty"`
	Organizations  []string  `json:"organizations,omitempty"`
	Events         []Event   `json:"events,omitempty"`
	SourceURL      string    `json:"source_url,omitempty"`
	FetchedAt      time.Time `json:"fetched_at,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	Stale          bool      `json:"stale,omitempty"`
	Message        string    `json:"message,omitempty"`
}

type bootstrapService struct {
	Network *net.IPNet
	URL     string
	Origin  string
}

type lookupCall struct {
	done   chan struct{}
	result Result
	err    error
}

type bootstrapCall struct {
	done        chan struct{}
	services    []bootstrapService
	authorities map[string]struct{}
	err         error
}

// AddressResolver is deliberately small so tests can provide deterministic
// DNS answers. Production uses net.DefaultResolver.
type AddressResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// Client performs safe registry lookups and caches their normalized result.
// Bootstrap URLs are exported primarily to make deterministic local tests
// possible; production defaults always use the fixed IANA registries.
type Client struct {
	Store             *store.Store
	Enabled           bool
	HTTPClient        *http.Client
	BootstrapIPv4URL  string
	BootstrapIPv6URL  string
	Now               func() time.Time
	Resolver          AddressResolver
	BootstrapTTL      time.Duration
	AllowPrivateHosts bool // test-only escape hatch for local HTTPS fixtures
	// OnCacheWriteError is optional observability for best-effort cache writes.
	// The callback receives only the operation error, never registry payloads.
	OnCacheWriteError func(error)

	mu                sync.Mutex
	services          map[int][]bootstrapService
	authorities       map[int]map[string]struct{}
	bootstrapFetched  map[int]time.Time
	bootstrapInflight map[int]*bootstrapCall
	inflight          map[string]*lookupCall
	sem               chan struct{}
}

func New(s *store.Store, enabled bool) *Client {
	transport := &http.Transport{}
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = defaultTransport.Clone()
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12} // #nosec G402 -- registry endpoints require modern TLS.
	return &Client{
		Store:             s,
		Enabled:           enabled,
		HTTPClient:        &http.Client{Transport: transport, Timeout: lookupTimeout},
		BootstrapIPv4URL:  defaultIPv4Bootstrap,
		BootstrapIPv6URL:  defaultIPv6Bootstrap,
		Now:               time.Now,
		Resolver:          net.DefaultResolver,
		BootstrapTTL:      bootstrapFreshFor,
		services:          map[int][]bootstrapService{},
		authorities:       map[int]map[string]struct{}{},
		bootstrapFetched:  map[int]time.Time{},
		bootstrapInflight: map[int]*bootstrapCall{},
		inflight:          map[string]*lookupCall{},
		sem:               make(chan struct{}, 4),
	}
}

// Lookup returns a normalized registration result. Upstream failures are
// represented as unavailable/stale results so a registry outage never blocks
// the local host page; the error is retained for logs and callers that need
// diagnostics.
func (c *Client) Lookup(ctx context.Context, rawAddress string) (Result, error) {
	ip := net.ParseIP(strings.TrimSpace(rawAddress))
	if ip == nil {
		return Result{Status: "unavailable", Address: strings.TrimSpace(rawAddress), Message: "address is not a valid IP"}, errors.New("invalid IP address")
	}
	address := ip.String()
	if !c.Enabled {
		return Result{Status: "disabled", Address: address, Message: "RDAP lookups are disabled by deployment configuration"}, nil
	}
	if isPrivate(ip) {
		return Result{Status: "private", Address: address, Message: "private or special-use addresses are not queried"}, nil
	}

	c.mu.Lock()
	if c.inflight == nil {
		c.inflight = map[string]*lookupCall{}
	}
	if c.services == nil {
		c.services = map[int][]bootstrapService{}
	}
	if c.sem == nil {
		c.sem = make(chan struct{}, 4)
	}
	if call := c.inflight[address]; call != nil {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.result, call.err
		case <-ctx.Done():
			return Result{Status: "unavailable", Address: address, Message: ctx.Err().Error()}, ctx.Err()
		}
	}
	call := &lookupCall{done: make(chan struct{})}
	c.inflight[address] = call
	c.mu.Unlock()

	call.result, call.err = c.lookup(ctx, ip)
	c.mu.Lock()
	delete(c.inflight, address)
	close(call.done)
	c.mu.Unlock()
	return call.result, call.err
}

func (c *Client) lookup(ctx context.Context, ip net.IP) (Result, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	now := c.now()
	var cached store.RDAPCacheEntry
	var cacheErr error
	if c.Store != nil {
		cached, cacheErr = c.Store.GetRDAPCache(lookupCtx, ip.String())
		if cacheErr == nil && now.Before(cached.ExpiresAt) {
			result, err := decodeCached(cached.Payload)
			if err == nil {
				result.Status, result.Address, result.FetchedAt, result.ExpiresAt, result.Stale = "cached", ip.String(), cached.FetchedAt, cached.ExpiresAt, false
				return result, nil
			}
			cacheErr = err
		}
	}

	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-lookupCtx.Done():
		return Result{Status: "unavailable", Address: ip.String(), Message: lookupCtx.Err().Error()}, lookupCtx.Err()
	}
	service, err := c.serviceFor(lookupCtx, ip)
	if err == nil {
		result, fetchErr := c.fetch(lookupCtx, ip, service)
		if fetchErr == nil {
			result.Status, result.Address = "success", ip.String()
			result.FetchedAt, result.ExpiresAt = now, now.Add(cacheFreshFor)
			if c.Store != nil {
				payload, marshalErr := json.Marshal(cachePayload(result))
				if marshalErr == nil {
					writeCtx, writeCancel := context.WithTimeout(lookupCtx, cacheWriteTimeout)
					writeErr := c.Store.PutRDAPCache(writeCtx, store.RDAPCacheEntry{Address: ip.String(), Payload: payload, FetchedAt: now, ExpiresAt: now.Add(cacheFreshFor), StaleUntil: now.Add(cacheFreshFor + cacheStaleFor)})
					writeCancel()
					if writeErr != nil && c.OnCacheWriteError != nil {
						// Cache persistence is best effort. Do not let an operator
						// callback turn a bounded lookup into an unbounded request.
						callback := c.OnCacheWriteError
						cacheErr := fmt.Errorf("RDAP cache write: %w", writeErr)
						go callback(cacheErr)
					}
				}
			}
			return result, nil
		}
		err = fetchErr
	}
	if cacheErr == nil && now.Before(cached.StaleUntil) {
		if result, decodeErr := decodeCached(cached.Payload); decodeErr == nil {
			result.Status, result.Address, result.FetchedAt, result.ExpiresAt, result.Stale, result.Message = "stale", ip.String(), cached.FetchedAt, cached.ExpiresAt, true, "Registry unavailable; showing cached data"
			return result, nil
		}
	}
	return Result{Status: "unavailable", Address: ip.String(), Message: unavailableMessage(err)}, err
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func cachePayload(result Result) Result {
	result.Status, result.FetchedAt, result.ExpiresAt, result.Stale, result.Message = "", time.Time{}, time.Time{}, false, ""
	return result
}

func decodeCached(payload []byte) (Result, error) {
	var result Result
	if err := json.Unmarshal(payload, &result); err != nil {
		return Result{}, err
	}
	return result, nil
}

func unavailableMessage(err error) string {
	if err == nil {
		return "registry data is unavailable"
	}
	return "registry lookup unavailable: " + err.Error()
}

func isPrivate(ip net.IP) bool {
	// Normalize IPv4-mapped IPv6 values before applying the special-use checks.
	// Resolver implementations are allowed to return either representation,
	// and treating ::ffff:127.0.0.1 differently from 127.0.0.1 would make the
	// endpoint allowlist bypassable.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func (c *Client) serviceFor(ctx context.Context, ip net.IP) (bootstrapService, error) {
	family := 6
	if ip.To4() != nil {
		family = 4
	}
	now := c.now()
	ttl := c.BootstrapTTL
	if ttl <= 0 {
		ttl = bootstrapFreshFor
	}
	c.mu.Lock()
	services := append([]bootstrapService(nil), c.services[family]...)
	fetchedAt := c.bootstrapFetched[family]
	c.mu.Unlock()
	if len(services) == 0 || fetchedAt.IsZero() || now.Sub(fetchedAt) >= ttl {
		bootstrapURL := c.BootstrapIPv6URL
		if family == 4 {
			bootstrapURL = c.BootstrapIPv4URL
		}
		loaded, err := c.loadBootstrap(ctx, family, bootstrapURL)
		if err != nil {
			return bootstrapService{}, err
		}
		services = loaded
	}
	var selected bootstrapService
	best := -1
	for _, service := range services {
		if service.Network.Contains(ip) {
			if ones, _ := service.Network.Mask.Size(); ones > best {
				selected, best = service, ones
			}
		}
	}
	if best < 0 {
		return bootstrapService{}, fmt.Errorf("no RDAP service covers %s", ip)
	}
	return selected, nil
}

func (c *Client) loadBootstrap(ctx context.Context, family int, endpoint string) ([]bootstrapService, error) {
	c.mu.Lock()
	if c.bootstrapInflight == nil {
		c.bootstrapInflight = map[int]*bootstrapCall{}
	}
	if call := c.bootstrapInflight[family]; call != nil {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.services, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &bootstrapCall{done: make(chan struct{})}
	previous := append([]bootstrapService(nil), c.services[family]...)
	previousAuthorities := cloneAuthorities(c.authorities[family])
	c.bootstrapInflight[family] = call
	c.mu.Unlock()

	services, err := c.loadBootstrapOnce(ctx, family, endpoint)
	c.mu.Lock()
	if err == nil {
		call.services = append([]bootstrapService(nil), services...)
		call.authorities = cloneAuthorities(c.authorities[family])
	} else if len(previous) > 0 {
		// Keep the last-known-good delegation usable during a transient IANA
		// outage. Mark the attempt time so concurrent host pages do not turn an
		// outage into a bootstrap request storm.
		call.services = previous
		call.authorities = previousAuthorities
		c.bootstrapFetched[family] = c.now()
		call.err = nil
	} else {
		call.err = err
	}
	delete(c.bootstrapInflight, family)
	close(call.done)
	c.mu.Unlock()
	return call.services, call.err
}

func (c *Client) loadBootstrapOnce(ctx context.Context, family int, endpoint string) ([]bootstrapService, error) {
	if !strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		return nil, errors.New("RDAP bootstrap endpoint must use HTTPS")
	}
	requestCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse RDAP bootstrap endpoint: %w", err)
	}
	origin, err := canonicalAuthority(parsedEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parse RDAP bootstrap endpoint: %w", err)
	}
	body, err := c.getLimited(requestCtx, endpoint, map[string]struct{}{origin: {}})
	if err != nil {
		return nil, fmt.Errorf("load RDAP bootstrap: %w", err)
	}
	var document struct {
		Services [][]json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("parse RDAP bootstrap: %w", err)
	}
	services := make([]bootstrapService, 0)
	authorities := make(map[string]struct{})
	for _, service := range document.Services {
		if len(service) != 2 {
			continue
		}
		var prefixes []string
		var urls []string
		if json.Unmarshal(service[0], &prefixes) != nil || json.Unmarshal(service[1], &urls) != nil {
			continue
		}
		base := ""
		baseOrigin := ""
		for _, candidate := range urls {
			candidateURL, parseErr := url.Parse(candidate)
			if parseErr != nil {
				continue
			}
			candidateOrigin, originErr := canonicalAuthority(candidateURL)
			if originErr != nil {
				continue
			}
			base = candidate
			baseOrigin = candidateOrigin
			break
		}
		if base == "" {
			continue
		}
		for _, prefix := range prefixes {
			_, network, parseErr := net.ParseCIDR(prefix)
			if parseErr != nil || (family == 4) != (network.IP.To4() != nil) {
				continue
			}
			services = append(services, bootstrapService{Network: network, URL: strings.TrimRight(base, "/") + "/", Origin: baseOrigin})
			authorities[baseOrigin] = struct{}{}
		}
	}
	if len(services) == 0 {
		return nil, errors.New("RDAP bootstrap contains no HTTPS service for address family")
	}
	sort.Slice(services, func(i, j int) bool {
		a, _ := services[i].Network.Mask.Size()
		b, _ := services[j].Network.Mask.Size()
		return a > b
	})
	c.mu.Lock()
	if c.services == nil {
		c.services = map[int][]bootstrapService{}
	}
	if c.authorities == nil {
		c.authorities = map[int]map[string]struct{}{}
	}
	if c.bootstrapFetched == nil {
		c.bootstrapFetched = map[int]time.Time{}
	}
	c.services[family] = services
	c.authorities[family] = authorities
	c.bootstrapFetched[family] = c.now()
	c.mu.Unlock()
	return services, nil
}

func cloneAuthorities(values map[string]struct{}) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]struct{}, len(values))
	for value := range values {
		cloned[value] = struct{}{}
	}
	return cloned
}

func (c *Client) fetch(ctx context.Context, ip net.IP, service bootstrapService) (Result, error) {
	base, err := url.Parse(service.URL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return Result{}, errors.New("invalid authoritative RDAP HTTPS endpoint")
	}
	origin := service.Origin
	if origin == "" {
		origin, err = canonicalAuthority(base)
		if err != nil {
			return Result{}, fmt.Errorf("invalid authoritative RDAP HTTPS endpoint: %w", err)
		}
	}
	endpoint := *base
	endpoint.Path = path.Join(base.Path, "ip", ip.String())
	endpoint.RawPath = ""
	allowed := map[string]struct{}{origin: {}}
	body, err := c.getLimited(ctx, endpoint.String(), allowed)
	if err != nil {
		return Result{}, fmt.Errorf("query authoritative RDAP: %w", err)
	}
	return parseResponse(body, endpoint.String(), allowed)
}

func (c *Client) getLimited(ctx context.Context, endpoint string, allowlists ...map[string]struct{}) ([]byte, error) {
	var allowed map[string]struct{}
	if len(allowlists) > 0 {
		allowed = allowlists[0]
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("RDAP requests require an HTTPS endpoint")
	}
	origin, addresses, err := c.validateEndpoint(ctx, parsed, allowed)
	if err != nil {
		return nil, err
	}
	if origin == "" {
		return nil, errors.New("RDAP requests require an HTTPS endpoint")
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: lookupTimeout}
	}
	baseClient := *client
	pinned := map[string][]net.IPAddr{}
	if len(addresses) > 0 {
		pinned[origin] = append([]net.IPAddr(nil), addresses...)
	}
	transport, err := c.safeTransport(baseClient.Transport, pinned)
	if err != nil {
		return nil, err
	}
	baseClient.Transport = transport
	redirects := 0
	baseClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		redirects++
		if redirects > 3 {
			return errors.New("too many redirects")
		}
		redirectOrigin, redirectAddresses, err := c.validateEndpoint(req.Context(), req.URL, allowed)
		if err != nil {
			return fmt.Errorf("redirect target is not an allowed HTTPS endpoint: %w", err)
		}
		// Keep the first validated answer for an authority. Re-resolving a
		// redirect on every dial would allow DNS rebinding between validation and
		// the TLS connection.
		if len(redirectAddresses) > 0 {
			if _, exists := pinned[redirectOrigin]; !exists {
				pinned[redirectOrigin] = append([]net.IPAddr(nil), redirectAddresses...)
			}
		}
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/rdap+json, application/json")
	response, err := baseClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("registry returned HTTP %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("registry response exceeds 1 MiB")
	}
	return body, nil
}

func (c *Client) validateEndpoint(ctx context.Context, parsed *url.URL, allowed map[string]struct{}) (string, []net.IPAddr, error) {
	if parsed == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", nil, errors.New("RDAP requests require an HTTPS endpoint without credentials or fragments")
	}
	origin, err := canonicalAuthority(parsed)
	if err != nil {
		return "", nil, err
	}
	if len(allowed) > 0 {
		if _, ok := allowed[origin]; !ok {
			return "", nil, fmt.Errorf("RDAP endpoint %s is not selected by the registry", origin)
		}
	}
	if c.AllowPrivateHosts {
		return origin, nil, nil
	}
	addresses, err := c.lookupIPAddr(ctx, parsed.Hostname())
	if err != nil {
		return "", nil, fmt.Errorf("resolve RDAP endpoint %s: %w", parsed.Hostname(), err)
	}
	if len(addresses) == 0 {
		return "", nil, fmt.Errorf("resolve RDAP endpoint %s: no addresses", parsed.Hostname())
	}
	for _, address := range addresses {
		if isPrivate(address.IP) {
			return "", nil, fmt.Errorf("RDAP endpoint %s resolves to a private or special-use address", parsed.Hostname())
		}
	}
	return origin, addresses, nil
}

func canonicalAuthority(parsed *url.URL) (string, error) {
	if parsed == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", errors.New("RDAP authority must be HTTPS without credentials")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" || strings.Contains(host, "%") {
		return "", errors.New("RDAP authority has an invalid hostname")
	}
	port := parsed.Port()
	if port == "" || port == "443" {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			host = "[" + ip.String() + "]"
		}
		return "https://" + host, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

func (c *Client) lookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}
	resolver := c.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupIPAddr(ctx, host)
}

func (c *Client) safeTransport(raw http.RoundTripper, pinSets ...map[string][]net.IPAddr) (http.RoundTripper, error) {
	var pinned map[string][]net.IPAddr
	if len(pinSets) > 0 {
		pinned = pinSets[0]
	}
	transport := raw
	if transport == nil {
		transport = http.DefaultTransport
	}
	base, ok := transport.(*http.Transport)
	if !ok {
		return nil, errors.New("RDAP HTTP client must use a net/http transport")
	}
	cloned := base.Clone()
	// Proxies receive the original hostname and can bypass the endpoint
	// validation/pinned dialer. RDAP deliberately uses direct HTTPS only.
	cloned.Proxy = nil
	// A custom DialTLSContext would bypass the guarded DialContext below (and
	// could resolve or connect to an unvalidated address), so force net/http to
	// perform TLS after our pinned TCP dial.
	cloned.DialTLSContext = nil
	baseDial := cloned.DialContext
	if baseDial == nil {
		dialer := &net.Dialer{}
		baseDial = dialer.DialContext
	}
	cloned.DialContext = c.safeDialContext(baseDial, pinned)
	return cloned, nil
}

func (c *Client) safeDialContext(base func(context.Context, string, string) (net.Conn, error), pinSets ...map[string][]net.IPAddr) func(context.Context, string, string) (net.Conn, error) {
	var pinned map[string][]net.IPAddr
	if len(pinSets) > 0 {
		pinned = pinSets[0]
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		cleanHost := strings.Trim(host, "[]")
		var addresses []net.IPAddr
		if origin, originErr := canonicalAuthority(&url.URL{Scheme: "https", Host: address}); originErr == nil {
			addresses = append(addresses, pinned[origin]...)
		}
		if len(addresses) == 0 {
			addresses, err = c.lookupIPAddr(ctx, cleanHost)
			if err != nil {
				return nil, err
			}
		}
		if len(addresses) == 0 {
			return nil, errors.New("RDAP endpoint has no dialable addresses")
		}
		var lastErr error
		for _, candidate := range addresses {
			if !c.AllowPrivateHosts && isPrivate(candidate.IP) {
				return nil, errors.New("RDAP endpoint resolved to a private or special-use address")
			}
			conn, dialErr := base(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
}

type rawResponse struct {
	Name         string   `json:"name"`
	Handle       string   `json:"handle"`
	StartAddress string   `json:"startAddress"`
	EndAddress   string   `json:"endAddress"`
	IPVersion    string   `json:"ipVersion"`
	Country      string   `json:"country"`
	Type         string   `json:"type"`
	Status       []string `json:"status"`
	CIDRs        []struct {
		V4       int    `json:"v4prefix-length"`
		V6       int    `json:"v6prefix-length"`
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles      []string        `json:"roles"`
		Handle     string          `json:"handle"`
		VCardArray json.RawMessage `json:"vcardArray"`
	} `json:"entities"`
	Links []struct {
		Href string `json:"href"`
		Rel  string `json:"rel"`
	} `json:"links"`
}

func parseResponse(body []byte, source string, allowlists ...map[string]struct{}) (Result, error) {
	var allowed map[string]struct{}
	if len(allowlists) > 0 {
		allowed = allowlists[0]
	}
	var raw rawResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return Result{}, fmt.Errorf("parse RDAP response: %w", err)
	}
	result := Result{NetworkName: strings.TrimSpace(raw.Name), Handle: strings.TrimSpace(raw.Handle), StartAddress: strings.TrimSpace(raw.StartAddress), EndAddress: strings.TrimSpace(raw.EndAddress), Country: strings.TrimSpace(raw.Country), AllocationType: strings.TrimSpace(raw.Type), Statuses: uniqueSorted(raw.Status), SourceURL: source}
	if parsedSource, err := url.Parse(source); err == nil {
		result.Registry = parsedSource.Hostname()
	}
	if raw.IPVersion != "" {
		if result.Registry == "" {
			result.Registry = "IPv" + strings.TrimSpace(raw.IPVersion)
		}
	}
	for _, cidr := range raw.CIDRs {
		if cidr.V4 > 0 {
			result.Prefix = fmt.Sprintf("%s/%d", result.StartAddress, cidr.V4)
			break
		}
		if cidr.V6 > 0 {
			result.Prefix = fmt.Sprintf("%s/%d", result.StartAddress, cidr.V6)
			break
		}
		// RIR responses in the wild use both the RFC 9224 bootstrap-style
		// v4prefix-length fields and the common v4prefix/length form.
		if cidr.Length > 0 && (cidr.V4Prefix != "" || cidr.V6Prefix != "") {
			prefix := cidr.V4Prefix
			if prefix == "" {
				prefix = cidr.V6Prefix
			}
			result.Prefix = fmt.Sprintf("%s/%d", prefix, cidr.Length)
			break
		}
	}
	for _, event := range raw.Events {
		if strings.TrimSpace(event.Action) == "" {
			continue
		}
		parsedDate, _ := time.Parse(time.RFC3339, event.Date)
		result.Events = append(result.Events, Event{Action: strings.TrimSpace(event.Action), Date: parsedDate})
	}
	for _, entity := range raw.Entities {
		if len(entity.Roles) > 0 {
			name := extractVCardOrganization(entity.VCardArray)
			if name != "" {
				result.Organizations = append(result.Organizations, name)
			}
		}
	}
	result.Organizations = uniqueSorted(result.Organizations)
	sort.Slice(result.Events, func(i, j int) bool {
		return result.Events[i].Action+result.Events[i].Date.String() < result.Events[j].Action+result.Events[j].Date.String()
	})
	for _, link := range raw.Links {
		if link.Rel == "self" && strings.HasPrefix(strings.ToLower(link.Href), "https://") {
			if parsedLink, parseErr := url.Parse(link.Href); parseErr == nil {
				if origin, originErr := canonicalAuthority(parsedLink); originErr == nil {
					if len(allowed) == 0 {
						result.SourceURL = link.Href
						break
					}
					if _, selected := allowed[origin]; selected {
						result.SourceURL = link.Href
						break
					}
				}
			}
		}
	}
	return result, nil
}

func extractVCardOrganization(raw json.RawMessage) string {
	var value []json.RawMessage
	if json.Unmarshal(raw, &value) != nil || len(value) != 2 {
		return ""
	}
	var fields []json.RawMessage
	if json.Unmarshal(value[1], &fields) != nil {
		return ""
	}
	for _, fieldRaw := range fields {
		var field []json.RawMessage
		if json.Unmarshal(fieldRaw, &field) != nil || len(field) < 4 {
			continue
		}
		var name string
		if json.Unmarshal(field[0], &name) == nil && name == "org" {
			if json.Unmarshal(field[3], &name) == nil {
				return strings.TrimSpace(name)
			}
			var values []string
			if json.Unmarshal(field[3], &values) == nil {
				return strings.TrimSpace(strings.Join(values, ", "))
			}
		}
	}
	return ""
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
