package rdap

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRDAPResponseParsingAndVCardVariants(t *testing.T) {
	if _, err := parseResponse([]byte("not-json"), "https://registry.example/rdap"); err == nil {
		t.Fatal("malformed RDAP response was accepted")
	}
	body := []byte(`{"name":" Net ","handle":" H ","startAddress":"198.51.100.0","endAddress":"198.51.100.255","ipVersion":"4","country":"NL","type":"ALLOCATED","status":["active","active",""],"cidr0_cidrs":[{"v4prefix-length":0,"v6prefix-length":0,"v4prefix":"198.51.100.0","length":24}],"events":[{"eventAction":"updated","eventDate":"bad"},{"eventAction":"","eventDate":"2024-01-01T00:00:00Z"},{"eventAction":"created","eventDate":"2024-01-01T00:00:00Z"}],"entities":[{"roles":[],"vcardArray":[]},{"roles":["registrant"],"vcardArray":["vcard",[["org",{},"text","Example Org"]]]},{"roles":["technical"],"vcardArray":["vcard",[["org",{},"text",["Org A","Org B"]]]]}],"links":[{"rel":"self","href":"http://registry.example/record"},{"rel":"self","href":"https://unselected.example/record"}]}`)
	result, err := parseResponse(body, "https://registry.example/rdap", map[string]struct{}{"https://registry.example": {}})
	if err != nil {
		t.Fatal(err)
	}
	if result.NetworkName != "Net" || result.Handle != "H" || result.Registry != "registry.example" || result.Prefix != "198.51.100.0/24" || len(result.Statuses) != 1 || len(result.Events) != 2 || len(result.Organizations) != 2 {
		t.Fatalf("parsed RDAP result = %#v", result)
	}
	if result.SourceURL != "https://registry.example/rdap" {
		t.Fatalf("unselected source link changed source URL: %q", result.SourceURL)
	}
	if got := extractVCardOrganization([]byte(`['vcard']`)); got != "" {
		t.Fatalf("malformed vCard = %q", got)
	}
	for _, raw := range []string{`["vcard",[]]`, `["vcard",[["fn",{},"text","name"]]]`, `["vcard",[["org",{},"text",[" A ","B"]]]]`, `["vcard",[["org",{},"text",123]]]`} {
		_ = extractVCardOrganization([]byte(raw))
	}
	if got := extractVCardOrganization([]byte(`["vcard",[["org",{},"text",[" A ","B"]]]]`)); got != "A , B" {
		t.Fatalf("array organization = %q", got)
	}
	if got := uniqueSorted([]string{" z ", "", "a", "z", "a"}); len(got) != 2 || got[0] != "a" || got[1] != "z" {
		t.Fatalf("unique sorted = %#v", got)
	}
}

func TestRDAPAuthorityAndDialValidationBranches(t *testing.T) {
	for _, raw := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/%zz", "https://"} {
		parsed, _ := url.Parse(raw)
		if _, err := canonicalAuthority(parsed); err == nil {
			t.Errorf("invalid authority %q was accepted", raw)
		}
	}
	if got, err := canonicalAuthority(mustURLForCoverage(t, "https://[2001:db8::1]/")); err != nil || got != "https://[2001:db8::1]" {
		t.Fatalf("IPv6 authority = %q, %v", got, err)
	}
	if got, err := canonicalAuthority(mustURLForCoverage(t, "https://Example.COM:8443/")); err != nil || got != "https://example.com:8443" {
		t.Fatalf("port authority = %q, %v", got, err)
	}
	client := New(nil, true)
	if _, err := client.safeTransport(http.DefaultTransport, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := client.safeTransport(roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, nil })); err == nil {
		t.Fatal("non-net/http transport was accepted")
	}
	if ips, err := client.lookupIPAddr(context.Background(), "192.0.2.1"); err != nil || len(ips) != 1 || !ips[0].IP.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("literal lookup = %#v, %v", ips, err)
	}
	client.Resolver = nil
	if _, err := client.lookupIPAddr(context.Background(), "registry.example"); err == nil {
		t.Fatal("nil resolver unexpectedly resolved test name")
	}
	dial := client.safeDialContext(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("dial failed") }, map[string][]net.IPAddr{})
	if _, err := dial(context.Background(), "tcp", "not-a-host-port"); err == nil {
		t.Fatal("malformed dial address was accepted")
	}
	client.Resolver = staticResolver{}
	if _, err := dial(context.Background(), "tcp", "registry.example:443"); err == nil || !strings.Contains(err.Error(), "no dialable") {
		t.Fatalf("empty dial set error = %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mustURLForCoverage(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
