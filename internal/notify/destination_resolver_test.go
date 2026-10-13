package notify

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"golang.org/x/net/dns/dnsmessage"
)

type destinationDNSTestHandler func(query []byte, network string) []byte

type destinationDNSTestServer struct {
	packet    net.PacketConn
	tcp       net.Listener
	address   string
	handler   destinationDNSTestHandler
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// dialDestinationTestAddress always receives an IP literal. Use an explicit
// resolver so these controlled dials never read the mutable DefaultResolver
// installed by guarded notification sends.
func dialDestinationTestAddress(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{Resolver: &net.Resolver{PreferGo: true}}).DialContext(ctx, network, address)
}

type destinationPacketTestConn struct {
	read       []byte
	readAddr   net.Addr
	readErr    error
	writeErr   error
	writeN     int
	shortWrite bool
	written    []byte
	writeAddr  net.Addr
}

func (c *destinationPacketTestConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.readErr != nil {
		return 0, c.readAddr, c.readErr
	}
	return copy(p, c.read), c.readAddr, nil
}

func (c *destinationPacketTestConn) WriteTo(p []byte, address net.Addr) (int, error) {
	c.written = append(c.written[:0], p...)
	c.writeAddr = address
	n := len(p)
	if c.shortWrite {
		n = c.writeN
	}
	return n, c.writeErr
}

func (*destinationPacketTestConn) Close() error { return nil }

func (*destinationPacketTestConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func (*destinationPacketTestConn) SetDeadline(time.Time) error      { return nil }
func (*destinationPacketTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*destinationPacketTestConn) SetWriteDeadline(time.Time) error { return nil }

func startDestinationDNSTestServer(t *testing.T, handler destinationDNSTestHandler) *destinationDNSTestServer {
	t.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpAddress := packet.LocalAddr().(*net.UDPAddr)
	tcp, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(udpAddress.Port)))
	if err != nil {
		_ = packet.Close()
		t.Fatal(err)
	}
	server := &destinationDNSTestServer{
		packet:  packet,
		tcp:     tcp,
		address: tcp.Addr().String(),
		handler: handler,
		conns:   make(map[net.Conn]struct{}),
	}
	server.wg.Add(2)
	go server.serveUDP()
	go server.serveTCP()
	t.Cleanup(server.close)
	return server
}

func (s *destinationDNSTestServer) close() {
	s.closeOnce.Do(func() {
		_ = s.packet.Close()
		_ = s.tcp.Close()
		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
}

func (s *destinationDNSTestServer) serveUDP() {
	defer s.wg.Done()
	buffer := make([]byte, 64*1024)
	for {
		n, address, err := s.packet.ReadFrom(buffer)
		if err != nil {
			return
		}
		response := s.handler(append([]byte(nil), buffer[:n]...), "udp")
		if len(response) != 0 {
			if _, err := s.packet.WriteTo(response, address); err != nil {
				return
			}
		}
	}
}

func (s *destinationDNSTestServer) serveTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
				_ = conn.Close()
			}()
			var length [2]byte
			if _, err := io.ReadFull(conn, length[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(length[:]))
			if len(query) == 0 {
				return
			}
			if _, err := io.ReadFull(conn, query); err != nil {
				return
			}
			response := s.handler(query, "tcp")
			if len(response) == 0 || len(response) > 0xffff {
				return
			}
			binary.BigEndian.PutUint16(length[:], uint16(len(response)))
			if _, err := conn.Write(length[:]); err != nil {
				return
			}
			_, _ = conn.Write(response)
		}()
	}
}

func (s *destinationDNSTestServer) resolver(policy *destinationPolicy) *net.Resolver {
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialDestinationTestAddress(ctx, network, s.address)
	}
	return newDestinationResolver(policy, nil, dial)
}

func useDestinationResolver(t *testing.T, resolver *net.Resolver) {
	t.Helper()
	previous := destinationLookup
	destinationLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return resolver.LookupNetIP(ctx, "ip", host)
	}
	t.Cleanup(func() { destinationLookup = previous })
}

func testDNSName(t *testing.T, name string) dnsmessage.Name {
	t.Helper()
	result, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testDNSQuery(t *testing.T, id uint16, name string, recordType dnsmessage.Type) ([]byte, dnsRequest) {
	t.Helper()
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  testDNSName(t, name),
			Type:  recordType,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	request, err := parseDNSRequest(packed)
	if err != nil {
		t.Fatal(err)
	}
	return packed, request
}

func testDNSResponse(t *testing.T, query []byte, rcode dnsmessage.RCode, truncated bool, answers ...dnsmessage.Resource) []byte {
	t.Helper()
	var request dnsmessage.Message
	if err := request.Unpack(query); err != nil {
		t.Fatal(err)
	}
	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 request.ID,
			Response:           true,
			OpCode:             request.OpCode,
			Authoritative:      true,
			Truncated:          truncated,
			RecursionDesired:   request.RecursionDesired,
			RecursionAvailable: true,
			RCode:              rcode,
		},
		Questions: request.Questions,
		Answers:   answers,
	}
	packed, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

func testARecord(t *testing.T, owner, address string) dnsmessage.Resource {
	t.Helper()
	parsed := netip.MustParseAddr(address).Unmap()
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: testDNSName(t, owner), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
		Body:   &dnsmessage.AResource{A: parsed.As4()},
	}
}

func testAAAARecord(t *testing.T, owner, address string) dnsmessage.Resource {
	t.Helper()
	parsed := netip.MustParseAddr(address)
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: testDNSName(t, owner), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 30},
		Body:   &dnsmessage.AAAAResource{AAAA: parsed.As16()},
	}
}

func testCNAMERecord(t *testing.T, owner, target string) dnsmessage.Resource {
	t.Helper()
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: testDNSName(t, owner), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30},
		Body:   &dnsmessage.CNAMEResource{CNAME: testDNSName(t, target)},
	}
}

func testDestinationPolicy(t *testing.T) *destinationPolicy {
	t.Helper()
	_, network, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	return &destinationPolicy{exclusions: []*net.IPNet{network}}
}

func TestDefaultDestinationDialersConnectToNumericEndpoints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	tcpConn, err := destinationTargetDial(ctx, "tcp", tcpListener.Addr().String())
	if err != nil {
		t.Fatalf("checked target dial to local numeric address: %v", err)
	}
	defer tcpConn.Close()
	accepted, err := tcpListener.Accept()
	if err != nil {
		t.Fatalf("accept checked target dial: %v", err)
	}
	defer accepted.Close()

	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	resolverConn, err := destinationResolverUpstreamDial(ctx, "udp", upstream.LocalAddr().String())
	if err != nil {
		t.Fatalf("resolver upstream dial to local numeric address: %v", err)
	}
	defer resolverConn.Close()
	if _, err := resolverConn.Write([]byte("query")); err != nil {
		t.Fatalf("write through resolver upstream dial: %v", err)
	}
	if err := upstream.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("query"))
	if _, _, err := upstream.ReadFrom(buffer); err != nil {
		t.Fatalf("receive through resolver upstream dial: %v", err)
	}
}

func TestDestinationResolverFiltersPrivateAddressesAndCNAMEs(t *testing.T) {
	t.Parallel()
	policy := testDestinationPolicy(t)
	blocked := &blockedDNSNames{}
	guard := &destinationResolverDial{policy: policy, blocked: blocked}
	tests := []struct {
		name        string
		queryName   string
		queryType   dnsmessage.Type
		answers     func() []dnsmessage.Resource
		wantBlocked string
	}{
		{
			name:      "mixed A records fail closed",
			queryName: "mixed.example.",
			queryType: dnsmessage.TypeA,
			answers: func() []dnsmessage.Resource {
				return []dnsmessage.Resource{testARecord(t, "mixed.example.", "203.0.113.8"), testARecord(t, "mixed.example.", "10.2.3.4")}
			},
			wantBlocked: "mixed.example",
		},
		{
			name:      "private AAAA answer fails closed",
			queryName: "private-v6.example.",
			queryType: dnsmessage.TypeAAAA,
			answers: func() []dnsmessage.Resource {
				return []dnsmessage.Resource{testAAAARecord(t, "private-v6.example.", "::1")}
			},
			wantBlocked: "private-v6.example",
		},
		{
			name:      "CNAME target address fails closed",
			queryName: "hook.example.",
			queryType: dnsmessage.TypeA,
			answers: func() []dnsmessage.Resource {
				return []dnsmessage.Resource{
					testCNAMERecord(t, "hook.example.", "internal.example."),
					testARecord(t, "internal.example.", "10.4.5.6"),
				}
			},
			wantBlocked: "hook.example",
		},
	}

	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query, request := testDNSQuery(t, uint16(100+index), test.queryName, test.queryType)
			attempt := &blockedDNSNames{}
			response := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, test.answers()...)
			filtered, err := guard.filter(request, response, attempt)
			if err != nil {
				t.Fatalf("filter returned error: %v", err)
			}
			var message dnsmessage.Message
			if err := message.Unpack(filtered); err != nil {
				t.Fatalf("filtered response is malformed: %v", err)
			}
			if message.RCode != dnsmessage.RCodeServerFailure {
				t.Fatalf("filtered response rcode = %v, want SERVFAIL", message.RCode)
			}
			if !attempt.contains(test.wantBlocked) || !blocked.contains(test.wantBlocked) {
				t.Fatalf("refused answer did not mark %q (attempt=%v, child=%v)", test.wantBlocked, attempt.any(), blocked.any())
			}
		})
	}
}

func TestDestinationResolverFiltersEveryAddressGoReturns(t *testing.T) {
	t.Parallel()
	policy := testDestinationPolicy(t)
	guard := &destinationResolverDial{policy: policy}
	query, request := testDNSQuery(t, 218, "hook.example.", dnsmessage.TypeA)
	tests := []struct {
		name   string
		unsafe dnsmessage.Resource
	}{
		{
			name:   "private A at an unrelated answer owner",
			unsafe: testARecord(t, "unrelated.example.", "10.7.8.9"),
		},
		{
			name:   "private AAAA in an A response",
			unsafe: testAAAARecord(t, "unrelated.example.", "::1"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attempt := &blockedDNSNames{}
			response := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false,
				testARecord(t, "hook.example.", "203.0.113.18"), test.unsafe,
			)
			filtered, err := guard.filterForNetwork(request, response, attempt, "tcp")
			if err != nil {
				t.Fatal(err)
			}
			var message dnsmessage.Message
			if err := message.Unpack(filtered); err != nil {
				t.Fatalf("filtered response is malformed: %v", err)
			}
			if message.RCode != dnsmessage.RCodeServerFailure {
				t.Fatalf("filtered response rcode = %v, want SERVFAIL", message.RCode)
			}
			if !attempt.definitelyContains("hook.example") {
				t.Fatal("forbidden address did not mark the queried destination as refused")
			}
		})
	}
}

func TestDestinationResolverRejectsPrivateAddressAfterLongCNAMEChain(t *testing.T) {
	t.Parallel()
	policy := testDestinationPolicy(t)
	guard := &destinationResolverDial{policy: policy}
	query, request := testDNSQuery(t, 219, "deep.example.", dnsmessage.TypeA)
	answers := make([]dnsmessage.Resource, 0, 18)
	current := "deep.example."
	for index := 0; index < 17; index++ {
		next := "node" + strconv.Itoa(index) + ".deep.example."
		answers = append(answers, testCNAMERecord(t, current, next))
		current = next
	}
	answers = append(answers, testARecord(t, current, "10.8.9.10"))
	response := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, answers...)
	filtered, err := guard.filterForNetwork(request, response, &blockedDNSNames{}, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	var message dnsmessage.Message
	if err := message.Unpack(filtered); err != nil {
		t.Fatalf("filtered response is malformed: %v", err)
	}
	if message.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("filtered response rcode = %v, want SERVFAIL", message.RCode)
	}
}

func TestDestinationResolverFiltersLargeCNAMEResponseInBoundedTime(t *testing.T) {
	t.Parallel()
	policy := testDestinationPolicy(t)
	guard := &destinationResolverDial{policy: policy, blocked: &blockedDNSNames{}}
	query, request := testDNSQuery(t, 221, "large.example.", dnsmessage.TypeA)
	const chainLength = 1600
	answers := make([]dnsmessage.Resource, 0, chainLength+1)
	current := "large.example."
	for index := 0; index < chainLength; index++ {
		next := "c" + strconv.Itoa(index) + ".x."
		answers = append(answers, testCNAMERecord(t, current, next))
		current = next
	}
	answers = append(answers, testARecord(t, current, "203.0.113.20"))
	response := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, answers...)
	if len(response) < 32*1024 || len(response) > 0xffff {
		t.Fatalf("test DNS response size = %d bytes, want between 32 KiB and 65,535 bytes", len(response))
	}
	attempt := &blockedDNSNames{}
	filtered, err := guard.filterForNetwork(request, response, attempt, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(filtered, response) {
		t.Fatal("safe large CNAME response was unexpectedly rewritten")
	}
	if attempt.any() || guard.blocked.any() {
		t.Fatal("safe large CNAME response left a stale refusal marker")
	}
}

func TestDestinationResolverOnlyRetriesTruncatedUDPOverTCP(t *testing.T) {
	t.Parallel()
	policy := testDestinationPolicy(t)
	blocked := &blockedDNSNames{}
	attempt := &blockedDNSNames{}
	guard := &destinationResolverDial{policy: policy, blocked: blocked}
	query, request := testDNSQuery(t, 220, "truncated.example.", dnsmessage.TypeA)
	private := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, testARecord(t, "truncated.example.", "10.9.10.11"))
	if _, err := guard.filterForNetwork(request, private, attempt, "udp"); err != nil {
		t.Fatal(err)
	}
	if !attempt.definitelyContains("truncated.example") {
		t.Fatal("private answer did not establish the initial refusal marker")
	}
	truncated := testDNSResponse(t, query, dnsmessage.RCodeSuccess, true, testARecord(t, "truncated.example.", "10.9.10.11"))
	udp, err := guard.filterForNetwork(request, truncated, attempt, "udp")
	if err != nil {
		t.Fatal(err)
	}
	var udpMessage dnsmessage.Message
	if err := udpMessage.Unpack(udp); err != nil {
		t.Fatalf("UDP response is malformed: %v", err)
	}
	if !udpMessage.Truncated || !attempt.definitelyContains("truncated.example") {
		t.Fatal("truncated UDP response was not passed through for the TCP retry")
	}
	tcp, err := guard.filterForNetwork(request, truncated, attempt, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	var tcpMessage dnsmessage.Message
	if err := tcpMessage.Unpack(tcp); err != nil {
		t.Fatalf("TCP replacement response is malformed: %v", err)
	}
	if tcpMessage.RCode != dnsmessage.RCodeServerFailure || len(tcpMessage.Answers) != 0 {
		t.Fatalf("TCP replacement response = rcode %v with %d answers, want empty SERVFAIL", tcpMessage.RCode, len(tcpMessage.Answers))
	}
	if attempt.definitelyContains("truncated.example") {
		t.Fatal("truncated TCP response did not mark the earlier refusal uncertain")
	}
}

func TestDestinationResolverDoesNotClassifyNonAnswersAsRefused(t *testing.T) {
	t.Parallel()
	guard := &destinationResolverDial{policy: testDestinationPolicy(t)}
	query, request := testDNSQuery(t, 211, "hook.example.", dnsmessage.TypeA)
	private := testARecord(t, "hook.example.", "10.1.2.3")
	for _, test := range []struct {
		name      string
		response  []byte
		wantRCode dnsmessage.RCode
	}{
		{
			name:      "SERVFAIL containing stale answer data",
			response:  testDNSResponse(t, query, dnsmessage.RCodeServerFailure, false, private),
			wantRCode: dnsmessage.RCodeServerFailure,
		},
		{
			name:      "truncated UDP answer",
			response:  testDNSResponse(t, query, dnsmessage.RCodeSuccess, true, private),
			wantRCode: dnsmessage.RCodeSuccess,
		},
		{
			name:      "malformed response",
			response:  []byte{0, 1, 2},
			wantRCode: dnsmessage.RCodeServerFailure,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			attempt := &blockedDNSNames{}
			filtered, err := guard.filter(request, test.response, attempt)
			if err != nil {
				t.Fatalf("filter returned error: %v", err)
			}
			var message dnsmessage.Message
			if err := message.Unpack(filtered); err != nil {
				t.Fatalf("response is malformed: %v", err)
			}
			if message.RCode != test.wantRCode {
				t.Fatalf("rcode = %v, want %v", message.RCode, test.wantRCode)
			}
			if attempt.any() {
				t.Fatal("a non-answer was recorded as a refused destination")
			}
		})
	}
}

func TestDestinationDNSRefusalMarkersAreScopedToQueryType(t *testing.T) {
	t.Parallel()
	policy := testDestinationPolicy(t)
	blocked := &blockedDNSNames{}
	guard := &destinationResolverDial{policy: policy, blocked: blocked}

	queryA, requestA := testDNSQuery(t, 212, "families.example.", dnsmessage.TypeA)
	privateA := testDNSResponse(t, queryA, dnsmessage.RCodeSuccess, false, testARecord(t, "families.example.", "10.3.4.5"))
	if _, err := guard.filter(requestA, privateA, nil); err != nil {
		t.Fatal(err)
	}
	if !blocked.definitelyContains("families.example") {
		t.Fatal("private A response did not create a refusal marker")
	}

	queryAAAA, requestAAAA := testDNSQuery(t, 213, "families.example.", dnsmessage.TypeAAAA)
	safeAAAA := testDNSResponse(t, queryAAAA, dnsmessage.RCodeSuccess, false, testAAAARecord(t, "families.example.", "2001:db8::45"))
	if _, err := guard.filter(requestAAAA, safeAAAA, nil); err != nil {
		t.Fatal(err)
	}
	if !blocked.definitelyContains("families.example") {
		t.Fatal("safe AAAA response cleared a refused A response")
	}
}

func TestDestinationDNSFallbackClearsOnlySameQueryType(t *testing.T) {
	t.Parallel()
	policy := testDestinationPolicy(t)
	blocked := &blockedDNSNames{}
	guard := &destinationResolverDial{policy: policy, blocked: blocked}
	query, request := testDNSQuery(t, 214, "fallback.example.", dnsmessage.TypeA)
	private := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, testARecord(t, "fallback.example.", "10.4.5.6"))
	if _, err := guard.filter(request, private, nil); err != nil {
		t.Fatal(err)
	}
	if !blocked.definitelyContains("fallback.example") {
		t.Fatal("private A response did not create a refusal marker")
	}
	safe := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, testARecord(t, "fallback.example.", "203.0.113.46"))
	if _, err := guard.filter(request, safe, nil); err != nil {
		t.Fatal(err)
	}
	if blocked.definitelyContains("fallback.example") || blocked.contains("fallback.example") {
		t.Fatal("safe same-type fallback retained the refusal marker")
	}
}

func TestDestinationDNSUncertaintyKeepsSMTPFailureRetryable(t *testing.T) {
	t.Parallel()
	policy := testDestinationPolicy(t)
	dnsFailure := &net.DNSError{Err: "server misbehaving", Name: "mx.example", IsTemporary: true}
	for _, test := range []struct {
		name string
		run  func(*testing.T, *blockedDNSNames) error
	}{
		{
			name: "resolver connection error",
			run: func(_ *testing.T, blocked *blockedDNSNames) error {
				guard := &destinationResolverDial{
					policy:  policy,
					blocked: blocked,
					dial: func(context.Context, string, string) (net.Conn, error) {
						return nil, errors.New("controlled DNS dial failure")
					},
				}
				_, err := guard.DialContext(context.Background(), "udp", "127.0.0.1:53")
				return err
			},
		},
		{
			name: "resolver stream read error",
			run: func(t *testing.T, blocked *blockedDNSNames) error {
				client, server := net.Pipe()
				_ = server.Close()
				_, request := testDNSQuery(t, 215, "mx.example.", dnsmessage.TypeA)
				stream := &destinationDNSStreamConn{
					Conn:      client,
					closeConn: client.Close,
					guard:     &destinationResolverDial{policy: policy, blocked: blocked},
					network:   "tcp",
					request:   request,
				}
				_, err := stream.Read(make([]byte, 128))
				_ = client.Close()
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			blocked := &blockedDNSNames{}
			blocked.addForType("mx.example.", dnsmessage.TypeA)
			if !smtpDestinationWasRefused(dnsFailure, "smtp://user@mx.example:25/?from=a@example.com&to=b@example.com", blocked) {
				t.Fatal("known refusal did not classify the SMTP DNS failure as excluded")
			}
			if err := test.run(t, blocked); err == nil {
				t.Fatal("controlled DNS transport did not fail")
			}
			if smtpDestinationWasRefused(dnsFailure, "smtp://user@mx.example:25/?from=a@example.com&to=b@example.com", blocked) {
				t.Fatal("DNS transport uncertainty was classified as a permanent exclusion")
			}
		})
	}
}

func TestDestinationDNSCNAMEUncertaintyKeepsAliasSMTPFailureRetryable(t *testing.T) {
	t.Parallel()
	policy := testDestinationPolicy(t)
	blocked := &blockedDNSNames{}
	guard := &destinationResolverDial{policy: policy, blocked: blocked}
	query, request := testDNSQuery(t, 216, "alias.example.", dnsmessage.TypeA)
	privateAliasAnswer := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false,
		testCNAMERecord(t, "alias.example.", "target.example."),
		testARecord(t, "target.example.", "10.6.7.8"),
	)
	if _, err := guard.filter(request, privateAliasAnswer, nil); err != nil {
		t.Fatal(err)
	}
	if !blocked.definitelyContains("alias.example") {
		t.Fatal("private CNAME target did not create an alias refusal marker")
	}

	// A later lookup of the canonical CNAME target can fail transiently after
	// the resolver has observed the refused target. That uncertainty must also
	// qualify the original alias, or SMTP could misreport the provider failure
	// as a permanent destination exclusion.
	_, targetRequest := testDNSQuery(t, 217, "target.example.", dnsmessage.TypeA)
	client, server := net.Pipe()
	_ = server.Close()
	stream := &destinationDNSStreamConn{
		Conn:      client,
		closeConn: client.Close,
		guard:     &destinationResolverDial{policy: policy, blocked: blocked},
		network:   "tcp",
		request:   targetRequest,
	}
	_, readErr := stream.Read(make([]byte, 128))
	_ = client.Close()
	if readErr == nil {
		t.Fatal("closed DNS stream did not report a transient read failure")
	}
	if blocked.definitelyContains("alias.example") {
		t.Fatal("canonical target read uncertainty left the CNAME alias as a permanent refusal")
	}
	dnsFailure := &net.DNSError{Err: "server misbehaving", Name: "alias.example", IsTemporary: true}
	if smtpDestinationWasRefused(dnsFailure, "smtp://user@alias.example:25/?from=a@example.com&to=b@example.com", blocked) {
		t.Fatal("transient canonical target lookup failure was classified as a permanent alias exclusion")
	}
}

func TestDestinationResolverAllBlockedAnswersAreExcluded(t *testing.T) {
	server := startDestinationDNSTestServer(t, func(query []byte, network string) []byte {
		var message dnsmessage.Message
		if err := message.Unpack(query); err != nil {
			return nil
		}
		question := message.Questions[0]
		var answers []dnsmessage.Resource
		switch question.Type {
		case dnsmessage.TypeA:
			answers = []dnsmessage.Resource{testARecord(t, question.Name.String(), "10.5.6.7")}
		case dnsmessage.TypeAAAA:
			answers = []dnsmessage.Resource{testAAAARecord(t, question.Name.String(), "::1")}
		}
		return testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, answers...)
	})
	useDestinationResolver(t, server.resolver(testDestinationPolicy(t)))
	_, err := resolveDestination(context.Background(), "blocked.example.", testDestinationPolicy(t))
	if !errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("resolveDestination error = %v, want excluded", err)
	}
}

func TestDestinationDNSPacketConnReadFromFiltersAndPreservesPeer(t *testing.T) {
	query, request := testDNSQuery(t, 404, "blocked-packet.example.", dnsmessage.TypeA)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5300}
	response := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, testARecord(t, "blocked-packet.example.", "10.5.6.7"))
	packet := &destinationPacketTestConn{read: response, readAddr: peer}
	blocked := &blockedDNSNames{}
	attempt := &blockedDNSNames{}
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	conn := &destinationDNSPacketConn{
		Conn:      left,
		packet:    packet,
		closeConn: left.Close,
		guard:     &destinationResolverDial{policy: testDestinationPolicy(t), blocked: blocked},
		attempt:   attempt,
		network:   "udp",
		request:   request,
	}
	buffer := make([]byte, 4096)
	n, address, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if address != peer {
		t.Fatalf("ReadFrom peer = %v, want %v", address, peer)
	}
	var filtered dnsmessage.Message
	if err := filtered.Unpack(buffer[:n]); err != nil {
		t.Fatal(err)
	}
	if filtered.RCode != dnsmessage.RCodeServerFailure || len(filtered.Answers) != 0 {
		t.Fatalf("filtered packet response = rcode %v with %d answers, want empty SERVFAIL", filtered.RCode, len(filtered.Answers))
	}
	if !blocked.definitelyContains("blocked-packet.example") || !attempt.definitelyContains("blocked-packet.example") {
		t.Fatal("blocked packet answer did not retain its refusal classification")
	}
}

func TestDestinationDNSPacketConnReadFromPassesSafeResponseThrough(t *testing.T) {
	query, request := testDNSQuery(t, 407, "safe-packet.example.", dnsmessage.TypeA)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5303}
	response := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, testARecord(t, "safe-packet.example.", "203.0.113.53"))
	packet := &destinationPacketTestConn{read: response, readAddr: peer}
	blocked := &blockedDNSNames{}
	attempt := &blockedDNSNames{}
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	conn := &destinationDNSPacketConn{
		Conn:      left,
		packet:    packet,
		closeConn: left.Close,
		guard:     &destinationResolverDial{policy: testDestinationPolicy(t), blocked: blocked},
		attempt:   attempt,
		network:   "udp",
		request:   request,
	}
	buffer := make([]byte, 4096)
	n, address, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if address != peer || !bytes.Equal(buffer[:n], response) {
		t.Fatalf("ReadFrom = %d bytes from %v, want the original %d-byte response from %v", n, address, len(response), peer)
	}
	if blocked.any() || attempt.any() {
		t.Fatal("safe packet answer acquired a destination refusal")
	}
}

func TestDestinationDNSPacketConnReadFromMarksTransportUncertainty(t *testing.T) {
	_, request := testDNSQuery(t, 405, "uncertain-packet.example.", dnsmessage.TypeA)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5301}
	readErr := errors.New("controlled packet read failure")
	packet := &destinationPacketTestConn{readAddr: peer, readErr: readErr}
	blocked := &blockedDNSNames{}
	blocked.addForType(request.question.Name.String(), request.question.Type)
	attempt := &blockedDNSNames{}
	attempt.addForType(request.question.Name.String(), request.question.Type)
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	conn := &destinationDNSPacketConn{
		Conn:      left,
		packet:    packet,
		closeConn: left.Close,
		guard:     &destinationResolverDial{policy: testDestinationPolicy(t), blocked: blocked},
		attempt:   attempt,
		network:   "udp",
		request:   request,
	}
	if n, address, err := conn.ReadFrom(make([]byte, 512)); n != 0 || address != peer || !errors.Is(err, readErr) {
		t.Fatalf("ReadFrom = %d, %v, %v; want 0, %v, read error", n, address, err, peer)
	}
	if blocked.definitelyContains("uncertain-packet.example") || attempt.definitelyContains("uncertain-packet.example") {
		t.Fatal("packet read error remained classified as a permanent destination refusal")
	}
	if !blocked.contains("uncertain-packet.example") || !attempt.contains("uncertain-packet.example") {
		t.Fatal("packet read error did not retain uncertainty for the refused query")
	}
}

func TestDestinationDNSPacketConnWriteToTracksQueryAndUncertainty(t *testing.T) {
	query, request := testDNSQuery(t, 406, "write-packet.example.", dnsmessage.TypeA)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5302}
	packet := &destinationPacketTestConn{}
	blocked := &blockedDNSNames{}
	attempt := &blockedDNSNames{}
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	conn := &destinationDNSPacketConn{
		Conn:      left,
		packet:    packet,
		closeConn: left.Close,
		guard:     &destinationResolverDial{policy: testDestinationPolicy(t), blocked: blocked},
		attempt:   attempt,
		network:   "udp",
	}
	if n, err := conn.WriteTo(query, peer); err != nil || n != len(query) {
		t.Fatalf("WriteTo = %d, %v; want %d, nil", n, err, len(query))
	}
	if !bytes.Equal(packet.written, query) || packet.writeAddr != peer || conn.getRequest() != request {
		t.Fatal("WriteTo did not preserve the query, upstream address, and request state")
	}

	for _, test := range []struct {
		name string
		conn *destinationPacketTestConn
	}{
		{name: "write error", conn: &destinationPacketTestConn{writeErr: errors.New("controlled packet write failure")}},
		{name: "short write", conn: &destinationPacketTestConn{shortWrite: true, writeN: len(query) - 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			blocked := &blockedDNSNames{}
			blocked.addForType(request.question.Name.String(), request.question.Type)
			attempt := &blockedDNSNames{}
			attempt.addForType(request.question.Name.String(), request.question.Type)
			left, right := net.Pipe()
			t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
			conn := &destinationDNSPacketConn{
				Conn:      left,
				packet:    test.conn,
				closeConn: left.Close,
				guard:     &destinationResolverDial{policy: testDestinationPolicy(t), blocked: blocked},
				attempt:   attempt,
				network:   "udp",
			}
			_, _ = conn.WriteTo(query, peer)
			if blocked.definitelyContains("write-packet.example") || attempt.definitelyContains("write-packet.example") {
				t.Fatal("packet write failure remained classified as a permanent destination refusal")
			}
			if !blocked.contains("write-packet.example") || !attempt.contains("write-packet.example") {
				t.Fatal("packet write failure did not retain uncertainty for the refused query")
			}
		})
	}
}

func TestExtendedRCodeReadsOPTRecordTTL(t *testing.T) {
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 408, Response: true},
		Additionals: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  testDNSName(t, "."),
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(1232),
				TTL:   0x5a000000,
			},
			Body: &dnsmessage.OPTResource{},
		}},
	}
	packed, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var decoded dnsmessage.Message
	if err := decoded.Unpack(packed); err != nil {
		t.Fatal(err)
	}
	if got := extendedRCode(decoded); got != 0x5a {
		t.Fatalf("extendedRCode = 0x%x, want 0x5a from the OPT TTL", got)
	}
	if got := extendedRCode(dnsmessage.Message{}); got != 0 {
		t.Fatalf("extendedRCode without OPT = %d, want zero", got)
	}
}

func TestResolverReadErrorPreservesOperationAddressAndCause(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 53}
	cause := errors.New("controlled DNS read failure")
	err := resolverReadError("udp", peer, cause)
	var operationError *net.OpError
	if !errors.As(err, &operationError) {
		t.Fatalf("resolverReadError = %T, want *net.OpError", err)
	}
	if operationError.Op != "read" || operationError.Net != "udp" || operationError.Addr != peer {
		t.Fatalf("resolverReadError fields = op %q net %q addr %v, want read udp %v", operationError.Op, operationError.Net, operationError.Addr, peer)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("resolverReadError %v does not preserve cause %v", err, cause)
	}
}

func TestDestinationResolverStopsReboundSMTPDialBeforeLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		conn, err := listener.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	var aQueries atomic.Int32
	server := startDestinationDNSTestServer(t, func(query []byte, _ string) []byte {
		var message dnsmessage.Message
		if err := message.Unpack(query); err != nil || len(message.Questions) != 1 {
			return nil
		}
		question := message.Questions[0]
		var answers []dnsmessage.Resource
		switch question.Type {
		case dnsmessage.TypeA:
			if aQueries.Add(1) == 1 {
				answers = []dnsmessage.Resource{testARecord(t, question.Name.String(), "203.0.113.31")}
			} else {
				// Go returns A records from the answer section even when the
				// owner is unrelated to the question. This simulates a DNS
				// rebinding response during SMTP's final net.Dial lookup.
				answers = []dnsmessage.Resource{testARecord(t, "unrelated.example.", "127.0.0.1")}
			}
		case dnsmessage.TypeAAAA:
			answers = []dnsmessage.Resource{testAAAARecord(t, question.Name.String(), "2001:db8::31")}
		}
		return testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, answers...)
	})
	policy := testDestinationPolicy(t)
	resolver := server.resolver(policy)
	previousResolver := net.DefaultResolver
	net.DefaultResolver = resolver
	t.Cleanup(func() { net.DefaultResolver = previousResolver })

	port := listener.Addr().(*net.TCPAddr).Port
	rawURL := "smtp://user@rebound.example:" + strconv.Itoa(port) + "/?from=a@example.com&to=b@example.com"
	if err := policy.check(context.Background(), rawURL); err != nil {
		t.Fatalf("safe destination preflight failed: %v", err)
	}
	if aQueries.Load() != 1 {
		t.Fatalf("preflight A DNS queries = %d, want one", aQueries.Load())
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, dialErr := (&net.Dialer{Resolver: resolver}).DialContext(dialCtx, "tcp4", net.JoinHostPort("rebound.example", strconv.Itoa(port)))
	if conn != nil {
		_ = conn.Close()
	}
	if dialErr == nil {
		t.Fatal("SMTP-style dial succeeded after DNS rebound to a forbidden unrelated-owner answer")
	}
	select {
	case <-accepted:
		t.Fatal("forbidden rebound DNS answer reached the controlled local listener")
	case <-time.After(50 * time.Millisecond):
	}
	_ = listener.Close()
	<-acceptDone
}

func TestDestinationResolverUsesTCPAfterTruncatedUDP(t *testing.T) {
	var udpQueries atomic.Int32
	var tcpQueries atomic.Int32
	server := startDestinationDNSTestServer(t, func(query []byte, network string) []byte {
		var message dnsmessage.Message
		if err := message.Unpack(query); err != nil {
			return nil
		}
		if network == "udp" {
			udpQueries.Add(1)
			return testDNSResponse(t, query, dnsmessage.RCodeSuccess, true)
		}
		tcpQueries.Add(1)
		question := message.Questions[0]
		var answers []dnsmessage.Resource
		switch question.Type {
		case dnsmessage.TypeA:
			answers = []dnsmessage.Resource{testARecord(t, question.Name.String(), "203.0.113.15")}
		case dnsmessage.TypeAAAA:
			answers = []dnsmessage.Resource{testAAAARecord(t, question.Name.String(), "2001:db8::15")}
		}
		return testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, answers...)
	})
	resolver := server.resolver(testDestinationPolicy(t))
	useDestinationResolver(t, resolver)

	addresses, err := resolveDestination(context.Background(), "webhook.example.", testDestinationPolicy(t))
	if err != nil {
		t.Fatalf("resolveDestination returned %v", err)
	}
	want := map[netip.Addr]bool{netip.MustParseAddr("203.0.113.15"): true, netip.MustParseAddr("2001:db8::15"): true}
	for _, address := range addresses {
		delete(want, address)
	}
	if len(want) != 0 {
		t.Fatalf("resolved addresses did not include both TCP answers: %v", want)
	}
	if udpQueries.Load() == 0 || tcpQueries.Load() == 0 {
		t.Fatalf("DNS queries used UDP %d times and TCP %d times, want truncation fallback", udpQueries.Load(), tcpQueries.Load())
	}
}

func TestDestinationResolverMalformedRepliesStayRetryable(t *testing.T) {
	for _, malformedOn := range []string{"udp", "tcp"} {
		t.Run(malformedOn, func(t *testing.T) {
			var tcpQueries atomic.Int32
			server := startDestinationDNSTestServer(t, func(query []byte, network string) []byte {
				if network == "tcp" {
					tcpQueries.Add(1)
					if malformedOn == "tcp" {
						return []byte{0, 1, 2}
					}
				}
				if network == malformedOn {
					return []byte{0, 1, 2}
				}
				return testDNSResponse(t, query, dnsmessage.RCodeSuccess, true)
			})
			useDestinationResolver(t, server.resolver(testDestinationPolicy(t)))
			_, err := resolveDestination(context.Background(), "bad-reply.example.", testDestinationPolicy(t))
			if err == nil || errors.Is(err, ErrDestinationExcluded) {
				t.Fatalf("resolveDestination error = %v, want retryable DNS failure", err)
			}
			var failure *store.DeliveryFailure
			if !errors.As(err, &failure) || failure.Class != store.DeliveryClassDNS {
				t.Fatalf("resolveDestination error = %#v, want DNS-classified failure", err)
			}
			if malformedOn == "tcp" && tcpQueries.Load() == 0 {
				t.Fatal("truncated UDP response did not exercise malformed TCP fallback")
			}
		})
	}
}

func TestDestinationResolverHonorsCancellation(t *testing.T) {
	var requests atomic.Int32
	server := startDestinationDNSTestServer(t, func(_ []byte, network string) []byte {
		if network == "udp" {
			requests.Add(1)
		}
		return nil
	})
	useDestinationResolver(t, server.resolver(testDestinationPolicy(t)))
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	_, err := resolveDestination(ctx, "cancel.example.", testDestinationPolicy(t))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("resolveDestination error = %v, want context deadline", err)
	}
	if requests.Load() == 0 {
		t.Fatal("lookup did not reach the controlled DNS server")
	}
}

func TestResolveDestinationDoesNotTurnSafeFallbackIntoExclusion(t *testing.T) {
	policy := testDestinationPolicy(t)
	previous := destinationLookup
	destinationLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		// Simulate an earlier refused DNS answer before the resolver finishes
		// with a valid public fallback answer in the same lookup attempt.
		attempt := destinationDNSAttempt(ctx)
		queryName := strings.TrimSuffix(host, ".") + "."
		query, request := testDNSQuery(t, 245, queryName, dnsmessage.TypeA)
		guard := &destinationResolverDial{policy: policy, blocked: &blockedDNSNames{}}
		privateAnswer := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, testARecord(t, queryName, "10.2.3.4"))
		filtered, err := guard.filter(request, privateAnswer, attempt)
		if err != nil {
			return nil, err
		}
		var blockedResponse dnsmessage.Message
		if err := blockedResponse.Unpack(filtered); err != nil || blockedResponse.RCode != dnsmessage.RCodeServerFailure || !attempt.any() {
			return nil, errors.New("private fallback answer was not refused")
		}
		publicAnswer := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, testARecord(t, queryName, "203.0.113.21"))
		fallback, err := guard.filter(request, publicAnswer, attempt)
		if err != nil {
			return nil, err
		}
		var fallbackMessage dnsmessage.Message
		if err := fallbackMessage.Unpack(fallback); err != nil || fallbackMessage.RCode != dnsmessage.RCodeSuccess {
			return nil, errors.New("public fallback answer was not accepted")
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.21")}, nil
	}
	t.Cleanup(func() { destinationLookup = previous })
	addresses, err := resolveDestination(context.Background(), "hook.example.", testDestinationPolicy(t))
	if err != nil {
		t.Fatalf("safe fallback was classified as refused: %v", err)
	}
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("203.0.113.21") {
		t.Fatalf("safe fallback addresses = %v", addresses)
	}
}

func TestDestinationDNSStreamConnRejectsBadFramingAndHandlesShortReads(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	stream := &destinationDNSStreamConn{
		Conn:      client,
		closeConn: client.Close,
		guard:     &destinationResolverDial{policy: testDestinationPolicy(t)},
		network:   "tcp",
	}
	if _, err := stream.Write([]byte{0, 0}); err == nil {
		t.Fatal("zero-length DNS query frame was accepted")
	}
	query, request := testDNSQuery(t, 244, "stream.example.", dnsmessage.TypeA)
	response := testDNSResponse(t, query, dnsmessage.RCodeSuccess, false, testARecord(t, "stream.example.", "203.0.113.22"))
	stream.request = request
	go func() {
		var frame [2]byte
		binary.BigEndian.PutUint16(frame[:], uint16(len(response)))
		_, _ = server.Write(frame[:])
		_, _ = server.Write(response)
	}()
	buffer := make([]byte, 1)
	var collected []byte
	for {
		n, err := stream.Read(buffer)
		if err != nil {
			t.Fatalf("stream read: %v", err)
		}
		collected = append(collected, buffer[:n]...)
		if len(collected) >= 2 && len(collected) == int(binary.BigEndian.Uint16(collected[:2]))+2 {
			break
		}
	}
	if len(collected) < 3 {
		t.Fatalf("stream response frame is too short: %v", collected)
	}
	if got := int(binary.BigEndian.Uint16(collected[:2])); got != len(collected)-2 {
		t.Fatalf("stream frame length = %d, payload length %d", got, len(collected)-2)
	}
	var message dnsmessage.Message
	if err := message.Unpack(collected[2:]); err != nil {
		t.Fatalf("stream response DNS packet is malformed: %v", err)
	}
	if message.RCode != dnsmessage.RCodeSuccess || len(message.Answers) != 1 {
		t.Fatalf("stream response = rcode %v, answers %v", message.RCode, message.Answers)
	}
	answer, ok := message.Answers[0].Body.(*dnsmessage.AResource)
	if !ok || netip.AddrFrom4(answer.A) != netip.MustParseAddr("203.0.113.22") {
		t.Fatalf("stream answer = %#v, want 203.0.113.22", message.Answers[0].Body)
	}
}
