package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestLookupUsesLongestBootstrapPrefixAndCachesNormalizedData(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var lookups atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ipv4.json":
			_, _ = w.Write([]byte(`{"services":[[["0.0.0.0/0"],["https://wrong.example/"]],[["198.51.100.0/24"],["` + "PLACEHOLDER" + `/rdap/"]]]}`))
		case "/rdap/ip/198.51.100.10":
			lookups.Add(1)
			_, _ = w.Write([]byte(`{"name":"Example Net","handle":"EX-1","startAddress":"198.51.100.0","endAddress":"198.51.100.255","ipVersion":"4","country":"NL","type":"ALLOCATED PA","status":["active"],"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Individual Contact"],["org",{},"text","Example Org"]]]}],"events":[{"eventAction":"last changed","eventDate":"2024-01-02T00:00:00Z"}],"links":[{"rel":"self","href":"https://registry.example/record"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	// Substitute the fixture endpoint into the bootstrap document without
	// weakening the production HTTPS requirement.
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ipv4.json" {
			_, _ = w.Write([]byte(`{"services":[[["0.0.0.0/0"],["https://wrong.example/"]],[["198.51.100.0/24"],["` + server.URL + `/rdap/"]]]}`))
			return
		}
		if r.URL.Path == "/rdap/ip/198.51.100.10" {
			lookups.Add(1)
			_, _ = w.Write([]byte(`{"name":"Example Net","handle":"EX-1","startAddress":"198.51.100.0","endAddress":"198.51.100.255","ipVersion":"4","country":"NL","type":"ALLOCATED PA","status":["active"],"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Individual Contact"],["org",{},"text","Example Org"]]]}],"events":[{"eventAction":"last changed","eventDate":"2024-01-02T00:00:00Z"}],"links":[{"rel":"self","href":"https://registry.example/record"}]}`))
			return
		}
		http.NotFound(w, r)
	})
	client := New(db, true)
	client.HTTPClient = server.Client()
	client.AllowPrivateHosts = true
	client.BootstrapIPv4URL = server.URL + "/ipv4.json"
	first, err := client.Lookup(context.Background(), "198.51.100.10")
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "success" || first.NetworkName != "Example Net" || len(first.Organizations) != 1 || first.Organizations[0] != "Example Org" || first.SourceURL != server.URL+"/rdap/ip/198.51.100.10" {
		t.Fatalf("unexpected result: %#v", first)
	}
	for _, organization := range first.Organizations {
		if organization == "Individual Contact" {
			t.Fatal("personal vCard fn was retained as an organization")
		}
	}
	second, err := client.Lookup(context.Background(), "198.51.100.10")
	if err != nil || second.Status != "cached" {
		t.Fatalf("cache lookup = %#v, %v", second, err)
	}
	if lookups.Load() != 1 {
		t.Fatalf("authoritative lookups = %d, want one", lookups.Load())
	}
	var raw map[string]any
	entry, err := db.GetRDAPCache(context.Background(), "198.51.100.10")
	if err != nil || json.Unmarshal(entry.Payload, &raw) != nil {
		t.Fatalf("cache entry unavailable: %v", err)
	}
	if _, found := raw["entities"]; found {
		t.Fatal("raw entities were retained")
	}
	_ = time.Now() // keep this test explicit about wall-clock cache semantics
}

type staticResolver map[string][]net.IPAddr

func (r staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return append([]net.IPAddr(nil), r["registry.example"]...), nil
}

func TestRDAPRejectsUnlistedRedirectAndPrivateDNSResolution(t *testing.T) {
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"unexpected"}`))
	}))
	defer other.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer server.Close()
	client := New(nil, true)
	client.AllowPrivateHosts = true
	client.HTTPClient = server.Client()
	origin, err := canonicalAuthority(mustURL(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.getLimited(context.Background(), server.URL, map[string]struct{}{origin: {}})
	if err == nil || !strings.Contains(err.Error(), "not selected") {
		t.Fatalf("unlisted redirect error = %v", err)
	}

	client.AllowPrivateHosts = false
	client.Resolver = staticResolver{"registry.example": {{IP: net.ParseIP("127.0.0.1")}}}
	_, err = client.getLimited(context.Background(), "https://registry.example/", map[string]struct{}{"https://registry.example": {}})
	if err == nil || !strings.Contains(err.Error(), "private or special-use") {
		t.Fatalf("private DNS error = %v", err)
	}
}

type sequenceResolver struct {
	answers [][]net.IPAddr
	count   atomic.Int32
}

func (r *sequenceResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	index := int(r.count.Add(1)) - 1
	if index >= len(r.answers) {
		index = len(r.answers) - 1
	}
	if index < 0 {
		return nil, nil
	}
	return append([]net.IPAddr(nil), r.answers[index]...), nil
}

func TestRDAPPinsValidatedDNSAnswersAndNormalizesMappedSpecialUse(t *testing.T) {
	client := New(nil, true)
	client.AllowPrivateHosts = false
	resolver := &sequenceResolver{answers: [][]net.IPAddr{
		{{IP: net.ParseIP("198.51.100.20")}},
		{{IP: net.ParseIP("127.0.0.1")}}, // A rebinding must not be consulted for the dial.
	}}
	client.Resolver = resolver
	origin, addresses, err := client.validateEndpoint(context.Background(), mustURL(t, "https://registry.example/"), map[string]struct{}{"https://registry.example": {}})
	if err != nil || origin != "https://registry.example" || len(addresses) != 1 {
		t.Fatalf("validated endpoint = %q %#v, %v", origin, addresses, err)
	}
	var dialed string
	dial := client.safeDialContext(func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		return nil, errors.New("expected test dial failure")
	}, map[string][]net.IPAddr{origin: addresses})
	_, err = dial(context.Background(), "tcp", "registry.example:443")
	if err == nil || dialed != "198.51.100.20:443" || resolver.count.Load() != 1 {
		t.Fatalf("pinned dial = address %q error %v resolver calls %d", dialed, err, resolver.count.Load())
	}
	for _, raw := range []string{"::ffff:127.0.0.1", "::ffff:169.254.1.1", "::ffff:192.168.1.1"} {
		if !isPrivate(net.ParseIP(raw)) {
			t.Fatalf("mapped special-use address %s was not rejected", raw)
		}
	}
}

func TestRDAPBootstrapRefreshIsSingleflightAndKeepsLastKnownGood(t *testing.T) {
	var bootstrapRequests atomic.Int32
	var authorityRequests atomic.Int32
	var failBootstrap atomic.Bool
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/ipv4.json":
			bootstrapRequests.Add(1)
			if failBootstrap.Load() {
				http.Error(w, "temporary outage", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"services":[[["198.51.100.0/24"],["` + server.URL + `/rdap/"]]]}`))
		case strings.HasPrefix(r.URL.Path, "/rdap/ip/"):
			authorityRequests.Add(1)
			_, _ = w.Write([]byte(`{"name":"Example Net","links":[{"rel":"self","href":"` + server.URL + r.URL.Path + `"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(nil, true)
	client.AllowPrivateHosts = true
	client.HTTPClient = server.Client()
	client.BootstrapIPv4URL = server.URL + "/ipv4.json"
	client.BootstrapTTL = time.Hour
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	client.Now = func() time.Time { return now }

	var group sync.WaitGroup
	results := make(chan Result, 2)
	for _, address := range []string{"198.51.100.10", "198.51.100.11"} {
		group.Add(1)
		go func(address string) {
			defer group.Done()
			result, err := client.Lookup(context.Background(), address)
			if err != nil {
				t.Errorf("lookup %s: %v", address, err)
				return
			}
			results <- result
		}(address)
	}
	group.Wait()
	close(results)
	if len(results) != 2 || bootstrapRequests.Load() != 1 {
		t.Fatalf("concurrent bootstrap requests=%d results=%d", bootstrapRequests.Load(), len(results))
	}

	failBootstrap.Store(true)
	now = now.Add(2 * time.Hour)
	result, err := client.Lookup(context.Background(), "198.51.100.12")
	if err != nil || result.Status != "success" {
		t.Fatalf("last-known-good lookup = %#v, %v", result, err)
	}
	if bootstrapRequests.Load() != 2 || authorityRequests.Load() != 3 {
		t.Fatalf("refresh requests bootstrap=%d authority=%d", bootstrapRequests.Load(), authorityRequests.Load())
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestLookupSuppressesPrivateAndDisabledAddresses(t *testing.T) {
	client := New(nil, true)
	for _, address := range []string{"192.168.1.1", "127.0.0.1", "::1", "fe80::1", "ff02::1"} {
		result, err := client.Lookup(context.Background(), address)
		if err != nil || result.Status != "private" {
			t.Fatalf("private %s = %#v, %v", address, result, err)
		}
	}
	client.Enabled = false
	result, err := client.Lookup(context.Background(), "8.8.8.8")
	if err != nil || result.Status != "disabled" {
		t.Fatalf("disabled lookup = %#v, %v", result, err)
	}
}
