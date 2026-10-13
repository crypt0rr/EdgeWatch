package notify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containrrr/shoutrrr/pkg/router"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"golang.org/x/net/dns/dnsmessage"
)

func useDestinationSendHooks(t *testing.T, lookup func(context.Context, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()
	previousLookup, previousDial, previousProxy := destinationLookup, destinationTargetDial, destinationProxyLookup
	destinationLookup, destinationTargetDial = lookup, dial
	destinationProxyLookup = func(*http.Request) (*url.URL, error) { return nil, nil }
	t.Cleanup(func() {
		destinationLookup, destinationTargetDial, destinationProxyLookup = previousLookup, previousDial, previousProxy
	})
}

func destinationTestPolicy(t *testing.T, cidrs ...string) *destinationPolicy {
	t.Helper()
	if len(cidrs) == 0 {
		cidrs = config.DefaultTargetExclusions()
	}
	exclusions, err := config.ParseTargetExclusions(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	return &destinationPolicy{exclusions: exclusions}
}

type destinationOpaqueRoundTripper struct{}

func (destinationOpaqueRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("test transport must not be used")
}

type destinationTestHTTPService struct{ client *http.Client }

func (s destinationTestHTTPService) GetHTTPClient() *http.Client { return s.client }

func sameDestinationTestFunc(left, right any) bool {
	leftValue, rightValue := reflect.ValueOf(left), reflect.ValueOf(right)
	if !leftValue.IsValid() || !rightValue.IsValid() {
		return !leftValue.IsValid() && !rightValue.IsValid()
	}
	if leftValue.IsNil() || rightValue.IsNil() {
		return leftValue.IsNil() && rightValue.IsNil()
	}
	return leftValue.Pointer() == rightValue.Pointer()
}

func testDestinationCertificate(t *testing.T, hosts ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: hosts[0]},
		DNSNames:              hosts,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func TestDestinationPolicyRechecksDNSAtTheActualHTTPDial(t *testing.T) {
	var lookups atomic.Int32
	var dials atomic.Int32
	useDestinationSendHooks(t, func(context.Context, string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("203.0.113.11")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}, func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("the refused address must never be dialed")
	})

	err := sendInProcessWithPolicy(context.Background(), "generic+http://rebound.example/hook?template=json", "test", destinationTestPolicy(t))
	if !errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("send error = %v, want destination excluded after DNS rebinding", err)
	}
	if got := lookups.Load(); got != 2 {
		t.Fatalf("destination lookups = %d, want preflight and actual-dial checks", got)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("unsafe final target was dialed %d times", got)
	}
}

func TestSendAppliesDestinationPolicyInTestBinary(t *testing.T) {
	previousIsTestBinary := notificationIsTestBinary
	notificationIsTestBinary = func() bool { return true }
	t.Cleanup(func() { notificationIsTestBinary = previousIsTestBinary })
	var dials atomic.Int32
	useDestinationSendHooks(t, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}, func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("excluded destination must not be dialed")
	})

	err := send(withDestinationPolicy(context.Background(), destinationTestPolicy(t)), "generic+http://hooks.example/hook", "test")
	if !errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("send error = %v, want destination excluded", err)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("test-binary send dialed an excluded target %d times", got)
	}
}

func TestDestinationAddressDialerPreservesSafeDialErrorsAndAddressFamily(t *testing.T) {
	var dials atomic.Int32
	dialErr := errors.New("controlled safe-target dial failure")
	useDestinationSendHooks(t, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.19")}, nil
	}, func(_ context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp4" || address != "203.0.113.19:25" {
			t.Errorf("dial target = %s %s, want tcp4 203.0.113.19:25", network, address)
		}
		return nil, dialErr
	})
	dialer := destinationAddressDialer{policy: destinationTestPolicy(t)}
	if _, err := dialer.DialContext(context.Background(), "tcp4", "hooks.example:25"); !errors.Is(err, dialErr) || errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("safe-target dial error = %v, want original retryable dial error", err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("safe IPv4 target dial count = %d, want 1", got)
	}
	if _, err := dialer.DialContext(context.Background(), "tcp6", "hooks.example:25"); err == nil || errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("IPv4-only tcp6 result = %v, want retryable address-family failure", err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("IPv4 address was dialed for tcp6 %d times, want no additional dial", got-1)
	}
}

func TestPolicyRedirectKeepsTheRedirectLimit(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://hooks.example/start", nil)
	checkRedirect := policyRedirect(destinationTestPolicy(t), nil)
	if err := checkRedirect(request, make([]*http.Request, 10)); err == nil || err.Error() != "stopped after 10 redirects" {
		t.Fatalf("redirect check = %v, want ten-redirect limit", err)
	}
}

func TestInstallDestinationGuardsWithoutPolicyIsNoOp(t *testing.T) {
	oldResolver, oldClient, oldTransport := net.DefaultResolver, http.DefaultClient, http.DefaultTransport
	restore, err := installDestinationGuards(nil, nil, nil)
	if err != nil || restore == nil {
		t.Fatalf("policy-free guard install returned restore=%t, error=%v; want no-op restore", restore != nil, err)
	}
	restore()
	if net.DefaultResolver != oldResolver || http.DefaultClient != oldClient || http.DefaultTransport != oldTransport {
		t.Fatal("policy-free guard install changed process network globals")
	}
}

func TestCanceledUnitSendDoesNotStartProvider(t *testing.T) {
	var lookups, dials atomic.Int32
	useDestinationSendHooks(t, func(context.Context, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return []netip.Addr{netip.MustParseAddr("203.0.113.2")}, nil
	}, func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("a canceled send must not dial")
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := sendInProcessWithPolicy(ctx, "generic+http://203.0.113.1/hook?template=json", "test", destinationTestPolicy(t))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("send error = %v, want context.Canceled", err)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("canceled send attempted %d provider dial(s)", got)
	}
	if got := lookups.Load(); got != 0 {
		t.Fatalf("canceled literal send performed %d DNS lookup(s)", got)
	}
}

func TestDestinationPolicyChecksEveryHTTPRedirect(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "http://redirect.example/finish", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serverAddress := server.Listener.Addr().String()
	var safeLookups, redirectLookups atomic.Int32
	var dials atomic.Int32
	useDestinationSendHooks(t, func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "safe.example":
			safeLookups.Add(1)
		case "redirect.example":
			redirectLookups.Add(1)
		default:
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.12")}, nil
	}, func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	})

	err := sendInProcessWithPolicy(context.Background(), "generic+http://safe.example/start?template=json", "test", destinationTestPolicy(t))
	if err != nil {
		t.Fatalf("safe redirect failed: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("HTTP requests = %d, want the initial request and one safe redirect", got)
	}
	if got := redirectLookups.Load(); got != 2 {
		t.Fatalf("redirect destination lookups = %d, want one redirect check and one final-dial check", got)
	}
	if got := safeLookups.Load(); got != 2 {
		t.Fatalf("initial destination lookups = %d, want child preflight and initial-dial checks", got)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("HTTP dials = %d, want one for each safe hop", got)
	}
}

func TestDestinationPolicyStopsAnExcludedHTTPRedirect(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, "http://blocked.example/metadata", http.StatusFound)
	}))
	defer server.Close()
	serverAddress := server.Listener.Addr().String()
	var blockedLookups atomic.Int32
	var dials atomic.Int32
	useDestinationSendHooks(t, func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "blocked.example" {
			blockedLookups.Add(1)
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.13")}, nil
	}, func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	})

	err := sendInProcessWithPolicy(context.Background(), "generic+http://safe.example/start?template=json", "test", destinationTestPolicy(t))
	if !errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("send error = %v, want excluded redirect target", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("HTTP requests = %d, want the redirect target never reached", got)
	}
	if got := blockedLookups.Load(); got != 1 {
		t.Fatalf("excluded redirect checks = %d, want exactly one before following", got)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("HTTP dials = %d, want only the initial allowed hop", got)
	}
}

func TestDestinationGuardPreservesTLSHostnameAndTelegramCapturedClient(t *testing.T) {
	var mu sync.Mutex
	var names []string
	var paths []string
	var methods []string
	var bodies []string
	var customHeaders []string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		if r.TLS != nil {
			names = append(names, r.TLS.ServerName)
		}
		paths = append(paths, r.URL.Path)
		methods = append(methods, r.Method)
		bodies = append(bodies, string(body))
		customHeaders = append(customHeaders, r.Header.Get("X-Request-Source"))
		mu.Unlock()
		if strings.Contains(r.URL.Path, "/sendMessage") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1,"text":"test"}}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	certificate, roots := testDestinationCertificate(t, "sni.example", "api.telegram.org")
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()
	serverAddress := server.Listener.Addr().String()

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("default HTTP transport is not an *http.Transport")
	}
	oldTLSConfig := defaultTransport.TLSClientConfig
	defaultTransport.TLSClientConfig = &tls.Config{RootCAs: roots}
	t.Cleanup(func() { defaultTransport.TLSClientConfig = oldTLSConfig })
	useDestinationSendHooks(t, func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "sni.example" && host != "api.telegram.org" {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.14")}, nil
	}, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	})
	port := server.Listener.Addr().(*net.TCPAddr).Port
	policy := destinationTestPolicy(t)

	if err := sendInProcessWithPolicy(context.Background(), "generic://sni.example:"+strconv.Itoa(port)+"/hook?method=PUT&template=json&%40X-Request-Source=unit-test", "generic test", policy); err != nil {
		t.Fatalf("guarded HTTPS provider send: %v", err)
	}
	// Shoutrrr v0.8.0's Telegram jsonclient.DefaultClient captured the
	// original http.DefaultClient pointer during package initialization.
	// Sending through Telegram proves the guard updates that captured client's
	// transport without replacing the pointer.
	if err := sendInProcessWithPolicy(context.Background(), "telegram://12345:abcdefghijk@telegram?chats=@edgewatch", "telegram test", policy); err != nil {
		t.Fatalf("guarded Telegram send through its captured client: %v", err)
	}
	mu.Lock()
	gotNames := append([]string(nil), names...)
	gotPaths := append([]string(nil), paths...)
	gotMethods := append([]string(nil), methods...)
	gotBodies := append([]string(nil), bodies...)
	gotCustomHeaders := append([]string(nil), customHeaders...)
	mu.Unlock()
	if len(gotNames) != 2 || gotNames[0] != "sni.example" || gotNames[1] != "api.telegram.org" {
		t.Fatalf("TLS server names = %v, want the provider hosts", gotNames)
	}
	if len(gotPaths) != 2 || gotPaths[0] != "/hook" || !strings.HasSuffix(gotPaths[1], "/sendMessage") {
		t.Fatalf("TLS request paths = %v, want generic webhook and Telegram sendMessage", gotPaths)
	}
	if len(gotMethods) != 2 || gotMethods[0] != http.MethodPut || gotMethods[1] != http.MethodPost {
		t.Fatalf("provider methods = %v, want configured generic PUT and Telegram POST", gotMethods)
	}
	var genericPayload map[string]string
	if err := json.Unmarshal([]byte(gotBodies[0]), &genericPayload); err != nil {
		t.Fatalf("generic JSON payload %q is invalid: %v", gotBodies[0], err)
	}
	if genericPayload["title"] != "EdgeWatch" || genericPayload["message"] != "generic test" {
		t.Fatalf("generic runtime title/message = %v, want the normal Shoutrrr params", genericPayload)
	}
	if len(gotCustomHeaders) != 2 || gotCustomHeaders[0] != "unit-test" {
		t.Fatalf("provider custom headers = %v, want the configured generic header", gotCustomHeaders)
	}
}

func TestDestinationProviderInventoryMatchesPinnedShoutrrr(t *testing.T) {
	// Adding a Shoutrrr provider or changing how an existing provider parses
	// its URL must trigger an explicit host-policy review. The maintainer guide
	// lists the current transport inventory and the source-audit steps for a
	// dependency upgrade.
	urlHostProviders := map[string]struct{}{
		"bark": {}, "generic": {}, "googlechat": {}, "gotify": {}, "hangouts": {},
		"matrix": {}, "mattermost": {}, "ntfy": {}, "opsgenie": {}, "rocketchat": {},
		"smtp": {}, "zulip": {},
	}
	names := (&router.ServiceRouter{}).ListServices()
	sort.Strings(names)
	seenURLHostProviders := make(map[string]struct{}, len(urlHostProviders))
	for _, provider := range names {
		switch {
		case fixedHostProviders[provider]:
			rawURL := provider + "://token@target.example/path"
			if got := destinationHosts(rawURL); len(got) != 0 {
				t.Errorf("fixed-host provider %q was classified by its URL host: %v", provider, got)
			}
		case provider == "teams":
			rawURL := "teams://group@tenant/alt/owner?host=target.example"
			if got := destinationHosts(rawURL); !reflect.DeepEqual(got, []string{"target.example"}) {
				t.Errorf("Teams destination host = %v, want host query", got)
			}
		case hasURLHostProvider(urlHostProviders, provider):
			seenURLHostProviders[provider] = struct{}{}
			rawURL := provider + "://user:password@target.example/path"
			if got := destinationHosts(rawURL); !reflect.DeepEqual(got, []string{"target.example"}) {
				t.Errorf("URL-host provider %q destination = %v, want URL hostname", provider, got)
			}
		default:
			t.Errorf("new Shoutrrr provider %q has no destination-policy inventory entry", provider)
		}
	}
	for provider := range urlHostProviders {
		if _, ok := seenURLHostProviders[provider]; !ok {
			t.Errorf("destination-policy inventory provider %q is absent from the pinned Shoutrrr router", provider)
		}
	}
}

func hasURLHostProvider(providers map[string]struct{}, provider string) bool {
	_, ok := providers[provider]
	return ok
}

func TestGotifyPolicyKeepsItsOriginallyDirectPrivateTransport(t *testing.T) {
	var plainRequests, tlsRequests atomic.Int32
	var tlsPort int
	plainServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainRequests.Add(1)
		w.Header().Set("Location", "https://gotify.example:"+strconv.Itoa(tlsPort)+"/message?token=A123456789abcde")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer plainServer.Close()
	plainPort := plainServer.Listener.Addr().(*net.TCPAddr).Port
	certificate, _ := testDestinationCertificate(t, "gotify.example")
	var serverName string
	var serverNameMu sync.Mutex
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsRequests.Add(1)
		if r.TLS != nil {
			serverNameMu.Lock()
			serverName = r.TLS.ServerName
			serverNameMu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":1,"appid":1}`))
	}))
	tlsServer.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	tlsServer.StartTLS()
	defer tlsServer.Close()
	tlsPort = tlsServer.Listener.Addr().(*net.TCPAddr).Port
	var proxyCalls atomic.Int32
	useDestinationSendHooks(t, func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "gotify.example" {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.15")}, nil
	}, func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		serverAddress := plainServer.Listener.Addr().String()
		if port == strconv.Itoa(tlsPort) {
			serverAddress = tlsServer.Listener.Addr().String()
		} else if port != strconv.Itoa(plainPort) {
			return nil, errors.New("unexpected Gotify test port")
		}
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	})
	destinationProxyLookup = func(*http.Request) (*url.URL, error) {
		proxyCalls.Add(1)
		return &url.URL{Scheme: "http", Host: "proxy.invalid:3128"}, nil
	}

	rawURL := "gotify://gotify.example:" + strconv.Itoa(plainPort) + "/A123456789abcde?disabletls=yes"
	if err := sendInProcessWithPolicy(context.Background(), rawURL, "gotify test", destinationTestPolicy(t)); err != nil {
		t.Fatalf("Gotify send with its direct private transport: %v", err)
	}
	if got := plainRequests.Load(); got != 1 {
		t.Fatalf("Gotify cleartext requests = %d, want one redirect response", got)
	}
	if got := tlsRequests.Load(); got != 1 {
		t.Fatalf("Gotify TLS requests = %d, want one redirected request", got)
	}
	serverNameMu.Lock()
	gotServerName := serverName
	serverNameMu.Unlock()
	if gotServerName != "gotify.example" {
		t.Fatalf("Gotify TLS server name = %q, want original provider hostname", gotServerName)
	}
	if got := proxyCalls.Load(); got != 0 {
		t.Fatalf("Gotify proxy selection ran %d times; its originally nil Proxy must remain direct", got)
	}
}

func TestDestinationProxyPolicyRefusesSelectedProxiesAndPreservesDirectPaths(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "https://hooks.example/notify", nil)
	if err != nil {
		t.Fatal(err)
	}
	originalLookup := destinationProxyLookup
	t.Cleanup(func() { destinationProxyLookup = originalLookup })

	if destinationProxyPolicy(nil) != nil {
		t.Fatal("an originally direct transport was opted into proxy selection")
	}
	destinationProxyLookup = func(*http.Request) (*url.URL, error) { return nil, nil }
	if proxy, err := guardedProxy(request); err != nil || proxy != nil {
		t.Fatalf("NO_PROXY direct path = %v, %v; want direct", proxy, err)
	}

	const proxyCredential = "proxy-secret-value"
	destinationProxyLookup = func(*http.Request) (*url.URL, error) {
		return &url.URL{Scheme: "http", User: url.UserPassword("user", proxyCredential), Host: "proxy.example:3128"}, nil
	}
	proxy, err := destinationProxyPolicy(http.ProxyFromEnvironment)(request)
	if err == nil || proxy != nil {
		t.Fatalf("selected proxy = %v, %v; want refusal", proxy, err)
	}
	if strings.Contains(err.Error(), proxyCredential) {
		t.Fatalf("proxy refusal exposed proxy credentials: %v", err)
	}
	var failure *store.DeliveryFailure
	if !errors.As(err, &failure) || failure.Class != store.DeliveryClassProvider {
		t.Fatalf("proxy refusal = %#v, want a redacted provider failure", err)
	}
	customProxy := func(*http.Request) (*url.URL, error) { return nil, nil }
	if _, err := destinationProxyPolicy(customProxy)(request); err == nil {
		t.Fatal("an uninspectable custom proxy function was silently allowed")
	}
	destinationProxyLookup = func(*http.Request) (*url.URL, error) { return nil, errors.New("proxy configuration error") }
	if _, err := guardedProxy(request); err == nil {
		t.Fatal("proxy lookup failure was silently allowed")
	}
}

func TestInstallDestinationGuardsRestoresGlobalsForUnsupportedProviderTransport(t *testing.T) {
	oldResolver := net.DefaultResolver
	oldHTTPClient := http.DefaultClient
	oldDefaultTransport := http.DefaultTransport
	oldClientTransport := http.DefaultClient.Transport
	oldClientRedirect := http.DefaultClient.CheckRedirect
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("default transport is not an HTTP transport")
	}
	oldProxy, oldDial := defaultTransport.Proxy, defaultTransport.DialContext
	serviceClient := &http.Client{Transport: destinationOpaqueRoundTripper{}}

	restore, err := installDestinationGuards(destinationTestPolicy(t), destinationTestHTTPService{client: serviceClient}, &blockedDNSNames{})
	if err == nil || restore != nil || err.Error() != "notification provider transport is unavailable" {
		t.Fatalf("installDestinationGuards returned restore=%t, error=%v; want a sanitized transport error and no restore function", restore != nil, err)
	}
	if net.DefaultResolver != oldResolver || http.DefaultClient != oldHTTPClient || http.DefaultTransport != oldDefaultTransport || http.DefaultClient.Transport != oldClientTransport {
		t.Fatal("failed guard installation did not restore resolver and HTTP transport globals")
	}
	if !sameDestinationTestFunc(http.DefaultClient.CheckRedirect, oldClientRedirect) || !sameDestinationTestFunc(defaultTransport.Proxy, oldProxy) || !sameDestinationTestFunc(defaultTransport.DialContext, oldDial) {
		t.Fatal("failed guard installation did not restore redirect, proxy, and dial hooks")
	}
	if _, ok := serviceClient.Transport.(destinationOpaqueRoundTripper); !ok {
		t.Fatal("failed guard installation mutated the provider's unsupported transport")
	}
}

func TestSMTPExclusionClassificationRequiresTheFinalBlockedLookup(t *testing.T) {
	policy := testDestinationPolicy(t)
	blocked := &blockedDNSNames{}
	guard := &destinationResolverDial{policy: policy, blocked: blocked}
	rawURL := "smtp://user:password@smtp.example:25/?from=a@example.com&to=b@example.com"
	dnsError := &net.DNSError{Err: "no such host", Name: "smtp.example", IsNotFound: true}

	queryName := "smtp.example."
	query, request := testDNSQuery(t, 991, queryName, dnsmessage.TypeA)
	private := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, testARecord(t, queryName, "10.2.3.4"))
	if _, err := guard.filter(request, private, nil); err != nil {
		t.Fatal(err)
	}
	if !smtpDestinationWasRefused(dnsError, rawURL, blocked) {
		t.Fatal("an all-blocked SMTP DNS lookup was not classified as excluded")
	}

	// A safe fallback of the same qtype clears the blocked result. A later
	// DNS-class or provider error must retain its real, retryable class.
	safe := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, testARecord(t, queryName, "203.0.113.16"))
	if _, err := guard.filter(request, safe, nil); err != nil {
		t.Fatal(err)
	}
	if smtpDestinationWasRefused(dnsError, rawURL, blocked) {
		t.Fatal("a successful safe fallback left a stale permanent-exclusion marker")
	}
	if smtpDestinationWasRefused(errors.New("smtp provider rejected the request"), rawURL, blocked) {
		t.Fatal("a later provider failure was classified as a refused destination")
	}

	// Success for another address family cannot erase a blocked answer whose
	// lookup made the overall StrictErrors result fail.
	blocked.reset()
	if _, err := guard.filter(request, private, nil); err != nil {
		t.Fatal(err)
	}
	queryAAAA, requestAAAA := testDNSQuery(t, 992, queryName, dnsmessage.TypeAAAA)
	safeAAAA := testDNSResponse(t, queryAAAA, dnsmessage.RCodeSuccess, false, testAAAARecord(t, queryName, "2001:db8::16"))
	if _, err := guard.filter(requestAAAA, safeAAAA, nil); err != nil {
		t.Fatal(err)
	}
	if !smtpDestinationWasRefused(dnsError, rawURL, blocked) {
		t.Fatal("a safe AAAA result erased a blocked A result")
	}
}

func TestDestinationResolverMismatchKeepsSMTPFailureRetryable(t *testing.T) {
	policy := destinationTestPolicy(t)
	blocked := &blockedDNSNames{}
	blocked.addForType("smtp.example.", dnsmessage.TypeA)
	guard := &destinationResolverDial{policy: policy, blocked: blocked}
	query, request := testDNSQuery(t, 993, "smtp.example.", dnsmessage.TypeA)
	response := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, testARecord(t, "smtp.example.", "10.2.3.4"))
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		t.Fatal(err)
	}
	message.ID++ // The Go resolver ignores this UDP datagram or rejects it on TCP.
	response, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	attempt := &blockedDNSNames{}
	attempt.addForType("smtp.example.", dnsmessage.TypeA)
	if _, err := guard.filterForNetwork(request, response, attempt, "tcp"); err != nil {
		t.Fatal(err)
	}
	dnsFailure := &net.DNSError{Err: "server misbehaving", Name: "smtp.example", IsTemporary: true}
	if blocked.definitelyContains("smtp.example") || smtpDestinationWasRefused(dnsFailure, "smtp://user@smtp.example:25/?from=a@example.com&to=b@example.com", blocked) {
		t.Fatal("a mismatched DNS response left SMTP's prior refusal as permanent")
	}
	if attempt.definitelyContains("smtp.example") {
		t.Fatal("mismatched DNS response did not mark the current lookup uncertain")
	}
}

func TestDestinationPolicyDNSFailuresFailClosedAndRemainRetryable(t *testing.T) {
	notifier, db, _ := queuedManagedDelivery(t, "generic://dns-outage.example/hook")
	if err := notifier.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	previousLookup := destinationLookup
	destinationLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		return nil, &net.DNSError{Err: "private resolver detail", Name: host, IsTemporary: true}
	}
	t.Cleanup(func() { destinationLookup = previousLookup })
	var sends atomic.Int32
	previousSend := notificationProviderSend
	notificationProviderSend = func(context.Context, string, string) error {
		sends.Add(1)
		return nil
	}
	t.Cleanup(func() { notificationProviderSend = previousSend })

	err := notifier.Drain(context.Background())
	var failure *store.DeliveryFailure
	if !errors.As(err, &failure) || failure.Class != store.DeliveryClassDNS {
		t.Fatalf("DNS-outage delivery error = %#v, want a retryable DNS failure", err)
	}
	if strings.Contains(err.Error(), "dns-outage.example") || strings.Contains(err.Error(), "private resolver detail") {
		t.Fatalf("DNS-outage failure exposed destination or resolver details: %v", err)
	}
	if got := sends.Load(); got != 0 {
		t.Fatalf("provider was contacted %d times after DNS preflight failed", got)
	}
	row := onlyOutboxRow(t, db)
	if row.code != "delivery_failed" || row.terminal != "" || row.sent != "" {
		t.Fatalf("DNS-outage row = %+v, want a nonterminal unsent retry", row)
	}
}

func TestDestinationPolicyContextReachesUnitSendsOnly(t *testing.T) {
	ctx := context.Background()
	notifier, db, created := queuedManagedDelivery(t, "generic://unit.example/hook")
	if err := notifier.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	useFakeDNS(t, map[string]string{"unit.example": "203.0.113.17"})
	var mu sync.Mutex
	policies := make(map[string]bool)
	previousSend := notificationProviderSend
	notificationProviderSend = func(ctx context.Context, rawURL, _ string) error {
		mu.Lock()
		policies[rawURL] = destinationPolicyFromContext(ctx) != nil
		mu.Unlock()
		return nil
	}
	t.Cleanup(func() { notificationProviderSend = previousSend })

	if err := notifier.Drain(ctx); err != nil {
		t.Fatalf("queued unit delivery: %v", err)
	}
	if err := defaultNotifier(notifier).TestDestination(ctx, created.ID); err != nil {
		t.Fatalf("unit test destination: %v", err)
	}
	if summary, err := defaultNotifier(notifier).TestSummary(ctx); err != nil || summary.Tested != 1 {
		t.Fatalf("unit test summary = %+v, %v", summary, err)
	}
	unitURL := "generic://unit.example/hook"
	mu.Lock()
	if !policies[unitURL] {
		t.Errorf("queued or test sends for the unit destination did not carry the active policy: %v", policies)
	}
	mu.Unlock()

	// The bulk test path treats deployment-file and operator-imported targets
	// as daemon-owned. Neither gets a unit policy in the child context.
	fileURL := "generic://127.0.0.1/file?disabletls=yes"
	importedURL := "generic://127.0.0.1/imported?disabletls=yes"
	unitCheckedURL := "generic://unit.example/checked"
	set := destinationSet{
		policy:   destinationTestPolicy(t),
		fileURLs: map[string]string{"file": fileURL},
		managed: map[string]managedDestination{
			"imported": {url: importedURL, record: store.ManagedNotification{ID: "imported", Enabled: true, ConfigImported: true, TenantID: store.DefaultTenantID}},
			"unit":     {url: unitCheckedURL, record: store.ManagedNotification{ID: "unit", Enabled: true, TenantID: store.DefaultTenantID}},
		},
	}
	mu.Lock()
	delete(policies, fileURL)
	delete(policies, importedURL)
	delete(policies, unitCheckedURL)
	mu.Unlock()
	if summary, err := testSet(ctx, set); err != nil || summary.Tested != 3 {
		t.Fatalf("mixed bulk test = %+v, %v", summary, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if policies[fileURL] || policies[importedURL] {
		t.Fatalf("daemon-owned destinations received unit policy context: %v", policies)
	}
	if !policies[unitCheckedURL] {
		t.Fatalf("unit bulk test did not receive policy context: %v", policies)
	}
	if row := onlyOutboxRow(t, db); row.sent == "" {
		t.Fatalf("unit queued delivery was not recorded as sent: %+v", row)
	}
}

func TestNotificationChildSerializesOnlyTheDestinationPolicy(t *testing.T) {
	tmp := t.TempDir()
	payloadPath := tmp + "/child-request.json"
	originalExecutable, originalCommand := notificationExecutable, notificationCommandContext
	notificationExecutable = func() (string, error) { return "/usr/local/bin/edgewatch", nil }
	notificationCommandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/usr/bin/tee", payloadPath)
	}
	t.Cleanup(func() {
		notificationExecutable, notificationCommandContext = originalExecutable, originalCommand
	})
	policy := destinationTestPolicy(t, "198.51.100.0/24")
	if err := runNotificationProcess(withDestinationPolicy(context.Background(), policy), "generic://hook.example/path", "test"); err != nil {
		t.Fatalf("run child with policy: %v", err)
	}
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]json.RawMessage
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}
	var cidrs []string
	if err := json.Unmarshal(request["target_exclusions"], &cidrs); err != nil || !reflect.DeepEqual(cidrs, []string{"198.51.100.0/24"}) {
		t.Fatalf("child target policy = %v, %v", cidrs, err)
	}
	if err := runNotificationProcess(context.Background(), "generic://hook.example/path", "test"); err != nil {
		t.Fatalf("run child without policy: %v", err)
	}
	payload, err = os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	request = nil
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}
	if _, ok := request["target_exclusions"]; ok {
		t.Fatalf("policy-free child request unexpectedly carries a unit policy: %s", payload)
	}
}

func TestRunSendChildEnforcesSerializedConfiguredExclusions(t *testing.T) {
	previousLookup, previousDial := destinationLookup, destinationTargetDial
	destinationLookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.21")}, nil
	}
	var dials atomic.Int32
	destinationTargetDial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("configured excluded address must not be dialed")
	}
	t.Cleanup(func() { destinationLookup, destinationTargetDial = previousLookup, previousDial })
	payload, err := json.Marshal(notificationProcessRequest{
		URL:              "generic+http://configured.example/hook?template=json",
		Message:          "test",
		TargetExclusions: []string{"198.51.100.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = RunSendChild(strings.NewReader(string(payload)))
	var childErr *ChildExitError
	if !errors.As(err, &childErr) || childErr.ExitCode() != childExitExcluded || !errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("active-policy child error = %v, want destination-excluded child status", err)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("child dialed configured excluded destination %d times", got)
	}
}

func TestRunSendChildSMTPRefusesReboundAddressBeforeDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()

	var aQueries atomic.Int32
	dns := startDestinationDNSTestServer(t, func(query []byte, _ string) []byte {
		var request dnsmessage.Message
		if err := request.Unpack(query); err != nil || len(request.Questions) != 1 {
			return nil
		}
		question := request.Questions[0]
		response := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:                 request.ID,
				Response:           true,
				OpCode:             request.OpCode,
				Authoritative:      true,
				RecursionDesired:   request.RecursionDesired,
				RecursionAvailable: true,
				RCode:              dnsmessage.RCodeSuccess,
			},
			Questions: request.Questions,
		}
		if question.Type == dnsmessage.TypeA {
			address := netip.MustParseAddr("203.0.113.27").As4()
			if aQueries.Add(1) > 1 {
				address = netip.MustParseAddr("127.0.0.1").As4()
			}
			response.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1},
				Body:   &dnsmessage.AResource{A: address},
			}}
		}
		packed, err := response.Pack()
		if err != nil {
			return nil
		}
		return packed
	})
	previousUpstreamDial := destinationResolverUpstreamDial
	destinationResolverUpstreamDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, dns.address)
	}
	t.Cleanup(func() { destinationResolverUpstreamDial = previousUpstreamDial })

	port := listener.Addr().(*net.TCPAddr).Port
	rawURL := "smtp://user:password@smtp.example.:" + strconv.Itoa(port) + "/?from=a@example.com&to=b@example.com"
	payload, err := json.Marshal(notificationProcessRequest{
		URL:              rawURL,
		Message:          "controlled SMTP test",
		TargetExclusions: config.DefaultTargetExclusions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = RunSendChild(strings.NewReader(string(payload)))
	var childErr *ChildExitError
	if !errors.As(err, &childErr) || childErr.ExitCode() != childExitExcluded || !errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("active-policy SMTP child error = %v, want excluded after provider DNS rebound", err)
	}
	if got := aQueries.Load(); got < 2 {
		t.Fatalf("controlled DNS A queries = %d, want preflight plus provider resolution", got)
	}
	if got := accepted.Load(); got != 0 {
		t.Fatalf("SMTP connected to the refused loopback target %d times", got)
	}
	_ = listener.Close()
	<-acceptDone
}
