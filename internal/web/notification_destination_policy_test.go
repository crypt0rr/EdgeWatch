package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"golang.org/x/net/dns/dnsmessage"
)

// TestDestinationSaveResolutionFailuresAreSanitizedValidationErrors keeps
// DNS entirely inside the test process. The test is intentionally not
// parallel because net.DefaultResolver is process-global.
func TestDestinationSaveResolutionFailuresAreSanitizedValidationErrors(t *testing.T) {
	dns := newSavePolicyTestDNS(t)
	previousResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, dns.conn.LocalAddr().String())
		},
	}
	t.Cleanup(func() { net.DefaultResolver = previousResolver })

	f := newPlatformFixture(t)
	if err := f.server.App.Notifier.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	existing, err := f.server.App.Notifier.Tenant(f.a).Destination(context.Background(), f.destinationA)
	if err != nil {
		t.Fatal(err)
	}
	initialViews, err := f.server.App.Notifier.Tenant(f.a).Destinations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertUnchanged := func(t *testing.T) {
		t.Helper()
		current, err := f.server.App.Notifier.Tenant(f.a).Destinations(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(current, initialViews) {
			t.Fatalf("rejected destination save changed stored destinations: before=%+v after=%+v", initialViews, current)
		}
	}

	badHosts := []string{
		"nxdomain.edgewatch.test",
		"empty.edgewatch.test",
		"timeout.edgewatch.test",
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, host := range badHosts {
			t.Run(method+"/"+strings.Split(host, ".")[0], func(t *testing.T) {
				url := "generic://" + host + "/hook"
				var response *httptest.ResponseRecorder
				if method == http.MethodPost {
					body := confirmBody(fmt.Sprintf(`"name":"unresolved","url":%q`, url))
					response = f.call(t, actorAdminA, method, "/notifications/destinations", body)
				} else {
					body := confirmBody(fmt.Sprintf(`"name":"alpha-destination","revision":%d,"url":%q`, existing.Revision, url))
					response = f.call(t, actorAdminA, method, "/notifications/destinations/"+existing.ID, body)
				}
				if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"validation_failed"`) {
					t.Fatalf("save %s = %d: %s", host, response.Code, response.Body.String())
				}
				for _, secret := range []string{host, "no such host", "i/o timeout", "server misbehaving"} {
					if strings.Contains(strings.ToLower(response.Body.String()), strings.ToLower(secret)) {
						t.Fatalf("save response leaked %q: %s", secret, response.Body.String())
					}
				}
				assertUnchanged(t)
			})
		}
	}

	if err := f.server.App.Notifier.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	response := f.call(t, actorAdminA, http.MethodPost, "/notifications/destinations", confirmBody(`"name":"empty policy","url":"generic://nxdomain.edgewatch.test/hook"`))
	if response.Code != http.StatusCreated {
		t.Fatalf("explicit empty policy refused unresolved host: %d %s", response.Code, response.Body.String())
	}
	response = f.call(t, actorAdminA, http.MethodPut, "/notifications/destinations/"+existing.ID, confirmBody(fmt.Sprintf(`"name":"alpha-destination","revision":%d,"url":"generic://nxdomain.edgewatch.test/hook"`, existing.Revision)))
	if response.Code != http.StatusOK {
		t.Fatalf("explicit empty policy refused unresolved host update: %d %s", response.Code, response.Body.String())
	}
}

type savePolicyTestDNS struct {
	conn net.PacketConn
}

func newSavePolicyTestDNS(t *testing.T) *savePolicyTestDNS {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dns := &savePolicyTestDNS{conn: conn}
	t.Cleanup(func() { _ = conn.Close() })
	go dns.serve()
	return dns
}

func (dns *savePolicyTestDNS) serve() {
	buffer := make([]byte, 2048)
	for {
		n, address, err := dns.conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		response, drop := savePolicyDNSResponse(buffer[:n])
		if !drop && len(response) != 0 {
			_, _ = dns.conn.WriteTo(response, address)
		}
	}
}

func savePolicyDNSResponse(query []byte) ([]byte, bool) {
	var request dnsmessage.Message
	if err := request.Unpack(query); err != nil || len(request.Questions) == 0 {
		return nil, false
	}
	question := request.Questions[0]
	host := strings.TrimSuffix(strings.ToLower(question.Name.String()), ".")
	if host == "timeout.edgewatch.test" {
		return nil, true
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{
		ID:                 request.ID,
		Response:           true,
		Authoritative:      true,
		RecursionDesired:   request.RecursionDesired,
		RecursionAvailable: true,
	}, Questions: request.Questions}
	if host == "nxdomain.edgewatch.test" {
		response.RCode = dnsmessage.RCodeNameError
	} else if host != "empty.edgewatch.test" {
		response.RCode = dnsmessage.RCodeNameError
	}
	packed, err := response.Pack()
	if err != nil {
		return nil, false
	}
	return packed, false
}
