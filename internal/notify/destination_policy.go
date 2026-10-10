package notify

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// ErrDestinationExcluded reports a unit's destination whose host is, or
// resolves to, an address that the deployment's target policy refuses. Its
// text is fixed and never names the URL or the address.
var ErrDestinationExcluded = store.ErrDeliveryDestinationExcluded

// destinationLookupTimeout bounds each lookup of a destination host.
const destinationLookupTimeout = 5 * time.Second

// destinationLookup resolves a destination host as the notification child
// does, with the daemon's resolver. Tests replace it with fixed answers.
var destinationLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// destinationPolicy keeps the destinations that a unit owns away from the
// addresses that the scanner refuses to scan: the networks of
// scanner.target_exclusions and every unspecified, loopback, and link-local
// address. The bundled deployment runs in the host's network namespace, and
// a unit administrator must not be able to make the daemon send requests to
// the host's own services or to a link-local metadata service. A nil policy
// refuses nothing: that is the policy without configuration, for embedded
// callers, and that of an explicitly empty scanner.target_exclusions, the
// operator's one override.
type destinationPolicy struct {
	exclusions []*net.IPNet
}

// SetTargetExclusions installs scanner.target_exclusions as the address
// policy of the destinations that units own, as the scanner and the store
// use it. A nil list, for embedded callers, and an explicitly empty list,
// the operator's override, refuse nothing; any other list refuses its
// networks and every unspecified, loopback, and link-local address. The
// policy does not apply to the platform's destinations, to the URLs that
// config.yaml lists, or to a destination imported from config.yaml until
// its URL is replaced: the platform administrators and the host operator
// configure those.
func (n *Notifier) SetTargetExclusions(exclusions []string) error {
	if len(exclusions) == 0 {
		n.policy.Store(nil)
		return nil
	}
	parsed, err := config.ParseTargetExclusions(exclusions)
	if err != nil {
		return err
	}
	n.policy.Store(&destinationPolicy{exclusions: parsed})
	return nil
}

// refuses reports whether the policy refuses an address, with the CIDR
// matching that the scanner uses.
func (p *destinationPolicy) refuses(addr netip.Addr) bool {
	addr = addr.WithZone("").Unmap()
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() {
		return true
	}
	ip := net.IP(addr.AsSlice())
	for _, network := range p.exclusions {
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// check refuses a destination URL with ErrDestinationExcluded when a host
// that its provider connects to is, or resolves to, an address that the
// policy refuses. A name that does not resolve is not refused here: the
// provider cannot reach it either, and its own lookup reports the failure.
// The check runs when a unit's destination is saved and again before each
// send, so a name whose answer changed since it was saved is refused too.
func (p *destinationPolicy) check(ctx context.Context, rawURL string) error {
	if p == nil {
		return nil
	}
	for _, host := range destinationHosts(rawURL) {
		if addr, err := netip.ParseAddr(host); err == nil {
			if p.refuses(addr) {
				return ErrDestinationExcluded
			}
			continue
		}
		lookupCtx, cancel := context.WithTimeout(ctx, destinationLookupTimeout)
		addresses, err := destinationLookup(lookupCtx, host)
		cancel()
		if err != nil {
			continue
		}
		for _, addr := range addresses {
			if p.refuses(addr) {
				return ErrDestinationExcluded
			}
		}
	}
	return nil
}

// fixedHostProviders are the Shoutrrr services that always connect to their
// public API host, such as discord.com, and use the host part of their URL
// for a token or an ID instead. logger connects to nothing.
var fixedHostProviders = map[string]bool{
	"discord": true, "ifttt": true, "join": true, "logger": true, "pushbullet": true,
	"pushover": true, "slack": true, "telegram": true,
}

// destinationHosts returns the hosts that the provider of a Shoutrrr URL
// connects to. Teams takes its host from the host query parameter and
// otherwise connects to its public default; every other provider, including
// one that a later Shoutrrr release adds, and every custom URL such as
// generic+https://, connects to the host of the URL.
func destinationHosts(rawURL string) []string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil
	}
	scheme := strings.ToLower(parsed.Scheme)
	var host string
	switch {
	case strings.Contains(scheme, "+"):
		host = parsed.Hostname()
	case scheme == "teams":
		for key, values := range parsed.Query() {
			if strings.EqualFold(key, "host") && len(values) > 0 {
				host = values[0]
			}
		}
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
	case fixedHostProviders[scheme]:
		return nil
	default:
		host = parsed.Hostname()
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return nil
	}
	return []string{host}
}

// destinationPolicy returns the policy for the destinations that units own.
func (n *Notifier) destinationPolicy() *destinationPolicy {
	if n == nil {
		return nil
	}
	return n.policy.Load()
}
