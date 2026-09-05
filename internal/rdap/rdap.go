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
}

type lookupCall struct {
	done   chan struct{}
	result Result
	err    error
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
	AllowPrivateHosts bool // test-only escape hatch for local HTTPS fixtures

	mu       sync.Mutex
	services map[int][]bootstrapService
	inflight map[string]*lookupCall
	sem      chan struct{}
}

func New(s *store.Store, enabled bool) *Client {
	transport := &http.Transport{}
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = defaultTransport.Clone()
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12} // #nosec G402 -- registry endpoints require modern TLS.
	return &Client{
		Store:            s,
		Enabled:          enabled,
		HTTPClient:       &http.Client{Transport: transport, Timeout: lookupTimeout},
		BootstrapIPv4URL: defaultIPv4Bootstrap,
		BootstrapIPv6URL: defaultIPv6Bootstrap,
		Now:              time.Now,
		services:         map[int][]bootstrapService{},
		inflight:         map[string]*lookupCall{},
		sem:              make(chan struct{}, 4),
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
	now := c.now()
	var cached store.RDAPCacheEntry
	var cacheErr error
	if c.Store != nil {
		cached, cacheErr = c.Store.GetRDAPCache(ctx, ip.String())
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
	case <-ctx.Done():
		return Result{Status: "unavailable", Address: ip.String(), Message: ctx.Err().Error()}, ctx.Err()
	}
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	service, err := c.serviceFor(lookupCtx, ip)
	if err == nil {
		result, fetchErr := c.fetch(lookupCtx, ip, service)
		if fetchErr == nil {
			result.Status, result.Address = "success", ip.String()
			result.FetchedAt, result.ExpiresAt = now, now.Add(cacheFreshFor)
			if c.Store != nil {
				payload, marshalErr := json.Marshal(cachePayload(result))
				if marshalErr == nil {
					_ = c.Store.PutRDAPCache(context.Background(), store.RDAPCacheEntry{Address: ip.String(), Payload: payload, FetchedAt: now, ExpiresAt: now.Add(cacheFreshFor), StaleUntil: now.Add(cacheFreshFor + cacheStaleFor)})
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
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func (c *Client) serviceFor(ctx context.Context, ip net.IP) (bootstrapService, error) {
	family := 6
	if ip.To4() != nil {
		family = 4
	}
	c.mu.Lock()
	services := append([]bootstrapService(nil), c.services[family]...)
	c.mu.Unlock()
	if len(services) == 0 {
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
	if !strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		return nil, errors.New("RDAP bootstrap endpoint must use HTTPS")
	}
	requestCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	body, err := c.getLimited(requestCtx, endpoint)
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
		for _, candidate := range urls {
			if strings.HasPrefix(strings.ToLower(candidate), "https://") {
				base = candidate
				break
			}
		}
		if base == "" {
			continue
		}
		for _, prefix := range prefixes {
			_, network, parseErr := net.ParseCIDR(prefix)
			if parseErr != nil || (family == 4) != (network.IP.To4() != nil) {
				continue
			}
			services = append(services, bootstrapService{Network: network, URL: strings.TrimRight(base, "/") + "/"})
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
	c.services[family] = services
	c.mu.Unlock()
	return services, nil
}

func (c *Client) fetch(ctx context.Context, ip net.IP, service bootstrapService) (Result, error) {
	base, err := url.Parse(service.URL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return Result{}, errors.New("invalid authoritative RDAP HTTPS endpoint")
	}
	endpoint := *base
	endpoint.Path = path.Join(base.Path, "ip", ip.String())
	endpoint.RawPath = ""
	body, err := c.getLimited(ctx, endpoint.String())
	if err != nil {
		return Result{}, fmt.Errorf("query authoritative RDAP: %w", err)
	}
	return parseResponse(body, endpoint.String())
}

func (c *Client) getLimited(ctx context.Context, endpoint string) ([]byte, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("RDAP requests require an HTTPS endpoint")
	}
	if !c.AllowPrivateHosts && isPrivateHost(parsed.Hostname()) {
		return nil, errors.New("RDAP endpoint is not an allowed public host")
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: lookupTimeout}
	}
	baseClient := *client
	redirects := 0
	baseClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		redirects++
		if redirects > 3 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" || (!c.AllowPrivateHosts && isPrivateHost(req.URL.Hostname())) {
			return errors.New("redirect target is not an allowed HTTPS endpoint")
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

func isPrivateHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return isPrivate(ip)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal"
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

func parseResponse(body []byte, source string) (Result, error) {
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
			name := extractVCardName(entity.VCardArray)
			if name == "" {
				name = strings.TrimSpace(entity.Handle)
			}
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
			result.SourceURL = link.Href
			break
		}
	}
	return result, nil
}

func extractVCardName(raw json.RawMessage) string {
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
		if json.Unmarshal(field[0], &name) == nil && name == "fn" {
			if json.Unmarshal(field[3], &name) == nil {
				return strings.TrimSpace(name)
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
