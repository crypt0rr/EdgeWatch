package notify

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"golang.org/x/net/dns/dnsmessage"
)

// blockedDNSNames records only names for which the resolver received an
// answer containing an address that this send's policy refuses. It is scoped
// to one child send and is used only to classify an SMTP DNS failure for its
// actual configured server; a stale blocked answer never overrides success
// or a later error after a successful resolution.
type blockedDNSNames struct {
	mu        sync.RWMutex
	names     map[string]struct{}
	uncertain map[string]struct{}
	aliases   map[string]map[string]struct{} // target -> aliases
	targets   map[string]map[string]struct{} // alias -> targets
}

func dnsMarkerKey(name string, qtype dnsmessage.Type) string {
	return normalizeDNSName(name) + "\x00" + strconv.Itoa(int(qtype))
}

func (b *blockedDNSNames) addForType(name string, qtype dnsmessage.Type) {
	if b == nil {
		return
	}
	name = dnsMarkerKey(name, qtype)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.names == nil {
		b.names = make(map[string]struct{})
	}
	queue := []string{name}
	seen := make(map[string]struct{})
	for len(queue) != 0 {
		current := queue[0]
		queue = queue[1:]
		if _, exists := seen[current]; exists {
			continue
		}
		seen[current] = struct{}{}
		b.names[current] = struct{}{}
		for alias := range b.aliases[current] {
			queue = append(queue, alias)
		}
	}
}

func (b *blockedDNSNames) markUncertainForType(name string, qtype dnsmessage.Type) {
	if b == nil {
		return
	}
	name = dnsMarkerKey(name, qtype)
	if strings.HasPrefix(name, "\x00") {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.uncertain == nil {
		b.uncertain = make(map[string]struct{})
	}
	queue := []string{name}
	seen := make(map[string]struct{})
	for len(queue) != 0 {
		current := queue[0]
		queue = queue[1:]
		if _, exists := seen[current]; exists {
			continue
		}
		seen[current] = struct{}{}
		b.uncertain[current] = struct{}{}
		for alias := range b.aliases[current] {
			queue = append(queue, alias)
		}
		for target := range b.targets[current] {
			queue = append(queue, target)
		}
	}
}

func (b *blockedDNSNames) markUncertainAll() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.names) == 0 {
		return
	}
	if b.uncertain == nil {
		b.uncertain = make(map[string]struct{})
	}
	for name := range b.names {
		b.uncertain[name] = struct{}{}
	}
}

func (b *blockedDNSNames) clearForType(name string, qtype dnsmessage.Type) {
	if b == nil {
		return
	}
	name = dnsMarkerKey(name, qtype)
	b.mu.Lock()
	defer b.mu.Unlock()
	queue := []string{name}
	seen := make(map[string]struct{})
	for len(queue) != 0 {
		current := queue[0]
		queue = queue[1:]
		if current == "" {
			continue
		}
		if _, exists := seen[current]; exists {
			continue
		}
		seen[current] = struct{}{}
		delete(b.names, current)
		delete(b.uncertain, current)
		for alias := range b.aliases[current] {
			queue = append(queue, alias)
		}
		for target := range b.targets[current] {
			queue = append(queue, target)
		}
	}
}

func (b *blockedDNSNames) reset() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.names = nil
	b.uncertain = nil
	b.aliases = nil
	b.targets = nil
	b.mu.Unlock()
}

func (b *blockedDNSNames) contains(host string) bool {
	if b == nil {
		return false
	}
	name := normalizeDNSName(host) + "\x00"
	b.mu.RLock()
	ok := false
	for key := range b.names {
		if strings.HasPrefix(key, name) {
			ok = true
			break
		}
	}
	b.mu.RUnlock()
	return ok
}

func (b *blockedDNSNames) definitelyContains(host string) bool {
	if b == nil {
		return false
	}
	name := normalizeDNSName(host) + "\x00"
	b.mu.RLock()
	blocked := false
	for key := range b.names {
		if strings.HasPrefix(key, name) {
			if _, uncertain := b.uncertain[key]; !uncertain {
				blocked = true
				break
			}
		}
	}
	b.mu.RUnlock()
	return blocked
}

func (b *blockedDNSNames) any() bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	ok := len(b.names) != 0
	b.mu.RUnlock()
	return ok
}

func (b *blockedDNSNames) noteAliases(question dnsmessage.Question, answers []dnsmessage.Resource) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.aliases == nil {
		b.aliases = make(map[string]map[string]struct{})
	}
	if b.targets == nil {
		b.targets = make(map[string]map[string]struct{})
	}
	for _, answer := range answers {
		alias, ok := answer.Body.(*dnsmessage.CNAMEResource)
		if !ok {
			continue
		}
		target := dnsMarkerKey(alias.CNAME.String(), question.Type)
		owner := dnsMarkerKey(answer.Header.Name.String(), question.Type)
		if owner == "" || target == "" || owner == target {
			continue
		}
		if b.aliases[target] == nil {
			b.aliases[target] = make(map[string]struct{})
		}
		b.aliases[target][owner] = struct{}{}
		if b.targets[owner] == nil {
			b.targets[owner] = make(map[string]struct{})
		}
		b.targets[owner][target] = struct{}{}
	}
}

type destinationDNSAttemptKey struct{}

var destinationGuardMu sync.Mutex

func destinationDNSAttempt(ctx context.Context) *blockedDNSNames {
	if ctx == nil {
		return nil
	}
	attempt, _ := ctx.Value(destinationDNSAttemptKey{}).(*blockedDNSNames)
	return attempt
}

func resolveDestination(ctx context.Context, host string, policy *destinationPolicy) ([]netip.Addr, error) {
	attempt := &blockedDNSNames{}
	if ctx == nil {
		return nil, destinationDNSFailure()
	}
	lookupCtx := context.WithValue(ctx, destinationDNSAttemptKey{}, attempt)
	addresses, err := destinationLookup(lookupCtx, host)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt.definitelyContains(host) {
			return nil, ErrDestinationExcluded
		}
		return nil, destinationDNSFailure()
	}
	if len(addresses) == 0 {
		return nil, destinationDNSFailure()
	}
	for _, address := range addresses {
		if policy.refuses(address) {
			return nil, ErrDestinationExcluded
		}
	}
	return addresses, nil
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

type destinationResolverDial struct {
	policy  *destinationPolicy
	blocked *blockedDNSNames
	dial    func(context.Context, string, string) (net.Conn, error)
}

var destinationResolverUpstreamDial = func(ctx context.Context, network, address string) (net.Conn, error) {
	// Resolver-provided DNS server addresses are numeric. Supplying an
	// explicit resolver keeps this upstream dial independent of
	// net.DefaultResolver, which the one-shot notification child installs.
	dialer := &net.Dialer{Resolver: &net.Resolver{PreferGo: true}}
	return dialer.DialContext(ctx, network, address)
}

func newDestinationResolver(policy *destinationPolicy, blocked *blockedDNSNames, dial func(context.Context, string, string) (net.Conn, error)) *net.Resolver {
	guard := &destinationResolverDial{policy: policy, blocked: blocked, dial: dial}
	if guard.dial == nil {
		guard.dial = destinationResolverUpstreamDial
	}
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial:         guard.DialContext,
	}
}

func (d *destinationResolverDial) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dial(ctx, network, address)
	if err != nil {
		d.blocked.markUncertainAll()
		if attempt := destinationDNSAttempt(ctx); attempt != d.blocked {
			attempt.markUncertainAll()
		}
		return nil, err
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	closeConn := func() error {
		stopCancel()
		return conn.Close()
	}
	attempt := destinationDNSAttempt(ctx)
	switch network {
	case "udp", "udp4", "udp6":
		packet, ok := conn.(net.PacketConn)
		if !ok {
			_ = closeConn()
			return nil, errors.New("notification DNS packet connection is unavailable")
		}
		return &destinationDNSPacketConn{Conn: conn, packet: packet, closeConn: closeConn, guard: d, attempt: attempt, network: network}, nil
	case "tcp", "tcp4", "tcp6":
		return &destinationDNSStreamConn{Conn: conn, closeConn: closeConn, guard: d, attempt: attempt, network: network}, nil
	default:
		_ = closeConn()
		return nil, errors.New("notification DNS network is unsupported")
	}
}

type dnsRequest struct {
	id       uint16
	header   dnsmessage.Header
	question dnsmessage.Question
}

func parseDNSRequest(message []byte) (dnsRequest, error) {
	var request dnsmessage.Message
	if err := request.Unpack(message); err != nil || request.Response || len(request.Questions) != 1 {
		return dnsRequest{}, errors.New("notification DNS query is invalid")
	}
	return dnsRequest{id: request.ID, header: request.Header, question: request.Questions[0]}, nil
}

func sameDNSQuestion(left, right dnsmessage.Question) bool {
	return normalizeDNSName(left.Name.String()) == normalizeDNSName(right.Name.String()) && left.Type == right.Type && left.Class == right.Class
}

func serverFailure(request dnsRequest) ([]byte, error) {
	header := dnsmessage.Header{ID: request.id, Response: true, RecursionDesired: request.header.RecursionDesired, RCode: dnsmessage.RCodeServerFailure}
	message := dnsmessage.Message{Header: header, Questions: []dnsmessage.Question{request.question}}
	return message.Pack()
}

func extendedRCode(message dnsmessage.Message) uint8 {
	for _, additional := range message.Additionals {
		if additional.Header.Type == dnsmessage.TypeOPT {
			return uint8(additional.Header.TTL >> 24)
		}
	}
	return 0
}

func (d *destinationResolverDial) filter(request dnsRequest, response []byte, attempt *blockedDNSNames) ([]byte, error) {
	return d.filterForNetwork(request, response, attempt, "udp")
}

func (d *destinationResolverDial) filterForNetwork(request dnsRequest, response []byte, attempt *blockedDNSNames, network string) ([]byte, error) {
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		d.blocked.markUncertainForType(request.question.Name.String(), request.question.Type)
		attempt.markUncertainForType(request.question.Name.String(), request.question.Type)
		return serverFailure(request)
	}
	if !message.Response || message.ID != request.id || len(message.Questions) != 1 || !sameDNSQuestion(request.question, message.Questions[0]) {
		// The Go resolver ignores mismatched UDP replies and rejects mismatched
		// TCP replies. Do not classify their contents as a refused answer, and
		// keep any earlier refusal from becoming permanent after this uncertain
		// resolver result.
		d.blocked.markUncertainForType(request.question.Name.String(), request.question.Type)
		attempt.markUncertainForType(request.question.Name.String(), request.question.Type)
		return response, nil
	}
	if message.Truncated {
		// Only successful, complete answers can establish that the destination
		// itself resolved to a refused address. Go retries truncated UDP over
		// TCP, but accepts a truncated TCP response; replace that response so
		// partial A/AAAA records can never reach net.Dial.
		if strings.HasPrefix(network, "tcp") {
			d.blocked.markUncertainForType(request.question.Name.String(), request.question.Type)
			attempt.markUncertainForType(request.question.Name.String(), request.question.Type)
			return serverFailure(request)
		}
		return response, nil
	}
	if message.RCode != dnsmessage.RCodeSuccess || extendedRCode(message) != 0 {
		// A DNS error is not evidence of an excluded target. Mark it uncertain
		// so a preceding blocked reply cannot become a permanent classification.
		d.blocked.markUncertainForType(request.question.Name.String(), request.question.Type)
		attempt.markUncertainForType(request.question.Name.String(), request.question.Type)
		return response, nil
	}
	if d.blocked != nil {
		d.blocked.noteAliases(request.question, message.Answers)
	}
	if attempt != nil {
		attempt.noteAliases(request.question, message.Answers)
	}
	// Build the CNAME owner map once, then walk only the queried chain. This
	// keeps filtering bounded by the answer size even for a maximum-size DNS
	// message. Conflicting CNAME targets for one owner are malformed and fail
	// closed because Go's resolver could select either record.
	cnameTargets := make(map[string]string)
	for _, answer := range message.Answers {
		alias, ok := answer.Body.(*dnsmessage.CNAMEResource)
		if !ok {
			continue
		}
		owner := dnsMarkerKey(answer.Header.Name.String(), request.question.Type)
		target := dnsMarkerKey(alias.CNAME.String(), request.question.Type)
		if previous, exists := cnameTargets[owner]; exists && previous != target {
			d.blocked.markUncertainForType(request.question.Name.String(), request.question.Type)
			attempt.markUncertainForType(request.question.Name.String(), request.question.Type)
			return serverFailure(request)
		}
		cnameTargets[owner] = target
	}
	chainNames := map[string]struct{}{dnsMarkerKey(request.question.Name.String(), request.question.Type): {}}
	current := dnsMarkerKey(request.question.Name.String(), request.question.Type)
	for range len(cnameTargets) + 1 {
		next, exists := cnameTargets[current]
		if !exists {
			break
		}
		if _, exists := chainNames[next]; exists {
			d.blocked.markUncertainForType(request.question.Name.String(), request.question.Type)
			attempt.markUncertainForType(request.question.Name.String(), request.question.Type)
			return serverFailure(request)
		}
		chainNames[next] = struct{}{}
		current = next
	}
	forbidden := false
	for _, answer := range message.Answers {
		// Go 1.27's resolver appends every A and AAAA RR in the answer section,
		// including records outside the CNAME chain and the other qtype's
		// response. Inspect every address the resolver can return.
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			if d.policy.refuses(netip.AddrFrom4(body.A)) {
				forbidden = true
			}
		case *dnsmessage.AAAAResource:
			if d.policy.refuses(netip.AddrFrom16(body.AAAA)) {
				forbidden = true
			}
		}
	}
	if !forbidden {
		d.blocked.clearForType(request.question.Name.String(), request.question.Type)
		attempt.clearForType(request.question.Name.String(), request.question.Type)
		return response, nil
	}
	d.blocked.addForType(request.question.Name.String(), request.question.Type)
	if attempt != nil {
		attempt.addForType(request.question.Name.String(), request.question.Type)
	}
	return serverFailure(request)
}

func resolverReadError(network string, address net.Addr, err error) error {
	return &net.OpError{Op: "read", Net: network, Addr: address, Err: err}
}

type destinationDNSPacketConn struct {
	net.Conn
	packet    net.PacketConn
	closeConn func() error
	guard     *destinationResolverDial
	attempt   *blockedDNSNames
	network   string
	mu        sync.RWMutex
	request   dnsRequest
}

func (c *destinationDNSPacketConn) setRequest(message []byte) error {
	request, err := parseDNSRequest(message)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.request = request
	c.mu.Unlock()
	return nil
}

func (c *destinationDNSPacketConn) getRequest() dnsRequest {
	c.mu.RLock()
	request := c.request
	c.mu.RUnlock()
	return request
}

func (c *destinationDNSPacketConn) Write(message []byte) (int, error) {
	if err := c.setRequest(message); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(message)
	if err != nil || n != len(message) {
		request := c.getRequest()
		c.guard.blocked.markUncertainForType(request.question.Name.String(), request.question.Type)
		c.attempt.markUncertainForType(request.question.Name.String(), request.question.Type)
	}
	return n, err
}

func (c *destinationDNSPacketConn) Read(message []byte) (int, error) {
	n, err := c.Conn.Read(message)
	if err != nil {
		request := c.getRequest()
		c.guard.blocked.markUncertainForType(request.question.Name.String(), request.question.Type)
		c.attempt.markUncertainForType(request.question.Name.String(), request.question.Type)
		return n, err
	}
	filtered, err := c.guard.filterForNetwork(c.getRequest(), message[:n], c.attempt, c.network)
	if err != nil {
		return 0, resolverReadError(c.network, c.RemoteAddr(), err)
	}
	return copy(message, filtered), nil
}

func (c *destinationDNSPacketConn) ReadFrom(message []byte) (int, net.Addr, error) {
	n, address, err := c.packet.ReadFrom(message)
	if err != nil {
		request := c.getRequest()
		c.guard.blocked.markUncertainForType(request.question.Name.String(), request.question.Type)
		c.attempt.markUncertainForType(request.question.Name.String(), request.question.Type)
		return n, address, err
	}
	filtered, err := c.guard.filterForNetwork(c.getRequest(), message[:n], c.attempt, c.network)
	if err != nil {
		return 0, address, resolverReadError(c.network, address, err)
	}
	return copy(message, filtered), address, nil
}

func (c *destinationDNSPacketConn) WriteTo(message []byte, address net.Addr) (int, error) {
	if err := c.setRequest(message); err != nil {
		return 0, err
	}
	n, err := c.packet.WriteTo(message, address)
	if err != nil || n != len(message) {
		request := c.getRequest()
		c.guard.blocked.markUncertainForType(request.question.Name.String(), request.question.Type)
		c.attempt.markUncertainForType(request.question.Name.String(), request.question.Type)
	}
	return n, err
}

func (c *destinationDNSPacketConn) Close() error { return c.closeConn() }

type destinationDNSStreamConn struct {
	net.Conn
	closeConn func() error
	guard     *destinationResolverDial
	attempt   *blockedDNSNames
	network   string
	mu        sync.Mutex
	request   dnsRequest
	buffer    []byte
}

func (c *destinationDNSStreamConn) Write(message []byte) (int, error) {
	if len(message) < 2 {
		return 0, errors.New("notification DNS stream query is invalid")
	}
	length := int(binary.BigEndian.Uint16(message[:2]))
	if length == 0 || length != len(message)-2 {
		return 0, errors.New("notification DNS stream query is invalid")
	}
	request, err := parseDNSRequest(message[2:])
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	c.request = request
	c.mu.Unlock()
	n, err := c.Conn.Write(message)
	if err != nil || n != len(message) {
		c.guard.blocked.markUncertainForType(request.question.Name.String(), request.question.Type)
		c.attempt.markUncertainForType(request.question.Name.String(), request.question.Type)
	}
	return n, err
}

func (c *destinationDNSStreamConn) Read(message []byte) (int, error) {
	if len(message) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.buffer) == 0 {
		var lengthBytes [2]byte
		if _, err := io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
			c.guard.blocked.markUncertainForType(c.request.question.Name.String(), c.request.question.Type)
			c.attempt.markUncertainForType(c.request.question.Name.String(), c.request.question.Type)
			return 0, err
		}
		length := int(binary.BigEndian.Uint16(lengthBytes[:]))
		if length == 0 {
			c.guard.blocked.markUncertainForType(c.request.question.Name.String(), c.request.question.Type)
			c.attempt.markUncertainForType(c.request.question.Name.String(), c.request.question.Type)
			return 0, resolverReadError(c.network, c.RemoteAddr(), errors.New("notification DNS stream response is empty"))
		}
		packet := make([]byte, length)
		if _, err := io.ReadFull(c.Conn, packet); err != nil {
			c.guard.blocked.markUncertainForType(c.request.question.Name.String(), c.request.question.Type)
			c.attempt.markUncertainForType(c.request.question.Name.String(), c.request.question.Type)
			return 0, err
		}
		filtered, err := c.guard.filterForNetwork(c.request, packet, c.attempt, c.network)
		if err != nil {
			return 0, resolverReadError(c.network, c.RemoteAddr(), err)
		}
		c.buffer = make([]byte, 2, 2+len(filtered))
		binary.BigEndian.PutUint16(c.buffer, uint16(len(filtered)))
		c.buffer = append(c.buffer, filtered...)
	}
	n := copy(message, c.buffer)
	c.buffer = c.buffer[n:]
	return n, nil
}

func (c *destinationDNSStreamConn) Close() error { return c.closeConn() }

type destinationAddressDialer struct {
	policy *destinationPolicy
	dial   func(context.Context, string, string) (net.Conn, error)
}

const destinationAddressDialAttemptFloor = 250 * time.Millisecond

var destinationTargetDial = func(ctx context.Context, network, address string) (net.Conn, error) {
	// destinationAddressDialer passes only IPs that were already resolved and
	// checked against the tenant policy. Do not let this final dial consult the
	// mutable process DefaultResolver while a guarded child is active.
	dialer := &net.Dialer{Resolver: &net.Resolver{PreferGo: true}}
	return dialer.DialContext(ctx, network, address)
}

func (d destinationAddressDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, destinationDNSFailure()
	}
	addresses, err := resolveDestination(ctx, host, d.policy)
	if err != nil {
		return nil, err
	}
	dial := d.dial
	if dial == nil {
		dial = destinationTargetDial
	}
	candidates := make([]netip.Addr, 0, len(addresses))
	for _, resolved := range addresses {
		if strings.HasSuffix(network, "4") && !resolved.Is4() || strings.HasSuffix(network, "6") && !resolved.Is6() {
			continue
		}
		candidates = append(candidates, resolved)
	}
	if len(candidates) == 0 {
		return nil, destinationDNSFailure()
	}
	var lastErr error
	for index, resolved := range candidates {
		available := notificationProviderTimeout
		if deadline, ok := ctx.Deadline(); ok {
			available = time.Until(deadline)
		}
		if available <= 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, context.DeadlineExceeded
		}
		attemptBudget := available / time.Duration(len(candidates)-index)
		if attemptBudget < destinationAddressDialAttemptFloor {
			attemptBudget = destinationAddressDialAttemptFloor
		}
		if attemptBudget > available {
			attemptBudget = available
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attemptBudget)
		conn, dialErr := dial(attemptCtx, network, net.JoinHostPort(resolved.String(), port))
		cancel()
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, destinationDNSFailure()
}

func destinationProxyError() error {
	return &store.DeliveryFailure{Err: store.ErrDeliveryProvider, Class: store.DeliveryClassProvider}
}

var destinationProxyLookup = http.ProxyFromEnvironment

func guardedProxy(request *http.Request) (*url.URL, error) {
	proxy, err := destinationProxyLookup(request)
	if err != nil {
		return nil, destinationProxyError()
	}
	if proxy != nil {
		return nil, destinationProxyError()
	}
	return nil, nil
}

func destinationProxyPolicy(original func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	if original == nil {
		// A transport with no proxy function is direct by design. Preserve
		// that provider behavior instead of opting it into environment proxies.
		return nil
	}
	if reflect.ValueOf(original).Pointer() == reflect.ValueOf(http.ProxyFromEnvironment).Pointer() {
		return guardedProxy
	}
	// A custom proxy cannot be inspected or safely dialed through the unit
	// destination policy, so refuse it without revealing its configuration.
	return func(*http.Request) (*url.URL, error) { return nil, destinationProxyError() }
}

func policyRedirect(policy *destinationPolicy, previous func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if previous != nil {
			if err := previous(request, via); err != nil {
				return err
			}
		} else if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if err := policy.check(request.Context(), request.URL.String()); err != nil {
			return err
		}
		return nil
	}
}

type guardedHTTPClient interface {
	GetHTTPClient() *http.Client
}

// installDestinationGuards confines policy-bearing provider code to checked
// destinations and returns a cleanup for callers that run inside a longer-
// lived process. The one-request production child uses
// installDestinationGuardsForProcessExit instead.
func installDestinationGuards(policy *destinationPolicy, service guardedHTTPClient, blocked *blockedDNSNames) (func(), error) {
	return installDestinationGuardsWithLifetime(policy, service, blocked, false)
}

// installDestinationGuardsForProcessExit installs the destination policy for
// the one-request notification child. The child deliberately keeps these
// process globals until exit, so an in-flight provider dial cannot race with
// restoration to the parent defaults.
func installDestinationGuardsForProcessExit(policy *destinationPolicy, service guardedHTTPClient, blocked *blockedDNSNames) error {
	_, err := installDestinationGuardsWithLifetime(policy, service, blocked, true)
	return err
}

func installDestinationGuardsWithLifetime(policy *destinationPolicy, service guardedHTTPClient, blocked *blockedDNSNames, processOwnsGlobalsUntilExit bool) (func(), error) {
	if policy == nil {
		return func() {}, nil
	}
	destinationGuardMu.Lock()
	oldResolver := net.DefaultResolver
	net.DefaultResolver = newDestinationResolver(policy, blocked, nil)
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		net.DefaultResolver = oldResolver
		destinationGuardMu.Unlock()
		return nil, errors.New("notification HTTP transport is unavailable")
	}
	oldDefaultClientTransport := http.DefaultClient.Transport
	oldDefaultClientRedirect := http.DefaultClient.CheckRedirect
	oldDefaultTransportProxy := defaultTransport.Proxy
	oldDefaultTransportDial := defaultTransport.DialContext
	guardedDial := destinationAddressDialer{policy: policy}.DialContext
	defaultTransport.Proxy = destinationProxyPolicy(oldDefaultTransportProxy)
	defaultTransport.DialContext = guardedDial
	if oldDefaultClientTransport == nil || oldDefaultClientTransport == defaultTransport {
		http.DefaultClient.Transport = defaultTransport
	} else if clientTransport, custom := oldDefaultClientTransport.(*http.Transport); custom {
		cloned := clientTransport.Clone()
		cloned.Proxy = destinationProxyPolicy(clientTransport.Proxy)
		cloned.DialContext = guardedDial
		http.DefaultClient.Transport = cloned
	} else {
		http.DefaultClient.Transport = oldDefaultClientTransport
		http.DefaultClient.CheckRedirect = oldDefaultClientRedirect
		defaultTransport.Proxy = oldDefaultTransportProxy
		defaultTransport.DialContext = oldDefaultTransportDial
		net.DefaultResolver = oldResolver
		destinationGuardMu.Unlock()
		return nil, errors.New("notification HTTP transport is unavailable")
	}
	http.DefaultClient.CheckRedirect = policyRedirect(policy, oldDefaultClientRedirect)

	var serviceClient *http.Client
	var serviceTransport *http.Transport
	var oldServiceTransport http.RoundTripper
	var oldServiceRedirect func(*http.Request, []*http.Request) error
	if service != nil {
		serviceClient = service.GetHTTPClient()
		if serviceClient != nil && serviceClient != http.DefaultClient {
			oldServiceTransport = serviceClient.Transport
			if serviceClient.Transport == nil {
				serviceTransport = defaultTransport
			} else {
				serviceTransport, ok = serviceClient.Transport.(*http.Transport)
			}
			if !ok {
				http.DefaultClient.Transport = oldDefaultClientTransport
				http.DefaultClient.CheckRedirect = oldDefaultClientRedirect
				defaultTransport.Proxy = oldDefaultTransportProxy
				defaultTransport.DialContext = oldDefaultTransportDial
				net.DefaultResolver = oldResolver
				destinationGuardMu.Unlock()
				return nil, errors.New("notification provider transport is unavailable")
			}
			cloned := serviceTransport.Clone()
			cloned.Proxy = destinationProxyPolicy(serviceTransport.Proxy)
			cloned.DialContext = guardedDial
			serviceClient.Transport = cloned
			oldServiceRedirect = serviceClient.CheckRedirect
			serviceClient.CheckRedirect = policyRedirect(policy, oldServiceRedirect)
		}
	}
	restore := func() {
		if serviceClient != nil && serviceClient != http.DefaultClient {
			serviceClient.Transport = oldServiceTransport
			serviceClient.CheckRedirect = oldServiceRedirect
		}
		http.DefaultClient.Transport = oldDefaultClientTransport
		http.DefaultClient.CheckRedirect = oldDefaultClientRedirect
		defaultTransport.Proxy = oldDefaultTransportProxy
		defaultTransport.DialContext = oldDefaultTransportDial
		net.DefaultResolver = oldResolver
		destinationGuardMu.Unlock()
	}
	if processOwnsGlobalsUntilExit {
		// RunSendChild is a single-request process entry point. After the
		// guarded globals are installed, it has no second send to serialize;
		// release the setup lock while retaining the guards until process exit.
		destinationGuardMu.Unlock()
		return nil, nil
	}
	return restore, nil
}
