package rdap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
			_, _ = w.Write([]byte(`{"name":"Example Net","handle":"EX-1","startAddress":"198.51.100.0","endAddress":"198.51.100.255","ipVersion":"4","country":"NL","type":"ALLOCATED PA","status":["active"],"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Example Org"]]]}],"events":[{"eventAction":"last changed","eventDate":"2024-01-02T00:00:00Z"}],"links":[{"rel":"self","href":"https://registry.example/record"}]}`))
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
			_, _ = w.Write([]byte(`{"name":"Example Net","handle":"EX-1","startAddress":"198.51.100.0","endAddress":"198.51.100.255","ipVersion":"4","country":"NL","type":"ALLOCATED PA","status":["active"],"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Example Org"]]]}],"events":[{"eventAction":"last changed","eventDate":"2024-01-02T00:00:00Z"}],"links":[{"rel":"self","href":"https://registry.example/record"}]}`))
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
	if first.Status != "success" || first.NetworkName != "Example Net" || first.Organizations[0] != "Example Org" || first.SourceURL != "https://registry.example/record" {
		t.Fatalf("unexpected result: %#v", first)
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
