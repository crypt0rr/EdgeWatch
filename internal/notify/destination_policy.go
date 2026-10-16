package notify

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// ErrDestinationExcluded reports a unit's destination whose host is, or
// resolves to, an address that the deployment's target policy refuses. Its
// text is fixed and never names the URL or the address.
var ErrDestinationExcluded = store.ErrDeliveryDestinationExcluded

// ErrDestinationUnresolved reports that a destination could not be resolved
// while it was being saved under an active address policy. Its text is fixed
// so resolver details and destination names never reach the API.
var ErrDestinationUnresolved = errors.New("notification destination host could not be resolved")

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

type destinationPolicyContextKey struct{}

func withDestinationPolicy(ctx context.Context, policy *destinationPolicy) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if policy == nil {
		return ctx
	}
	return context.WithValue(ctx, destinationPolicyContextKey{}, policy)
}

func destinationPolicyFromContext(ctx context.Context) *destinationPolicy {
	if ctx == nil {
		return nil
	}
	policy, _ := ctx.Value(destinationPolicyContextKey{}).(*destinationPolicy)
	return policy
}

// exclusionCIDRs returns the immutable policy as the small, nonsecret part
// of the notification child's stdin request.
func (p *destinationPolicy) exclusionCIDRs() []string {
	if p == nil || len(p.exclusions) == 0 {
		return nil
	}
	cidrs := make([]string, 0, len(p.exclusions))
	for _, exclusion := range p.exclusions {
		if exclusion != nil {
			cidrs = append(cidrs, exclusion.String())
		}
	}
	return cidrs
}

func destinationPolicyFromCIDRs(cidrs []string) (*destinationPolicy, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	exclusions, err := config.ParseTargetExclusions(cidrs)
	if err != nil {
		return nil, err
	}
	return &destinationPolicy{exclusions: exclusions}, nil
}

// SetTargetExclusions installs scanner.target_exclusions as the address
// policy of the destinations that units own, as the scanner and the store
// use it. A nil list, for embedded callers, and an explicitly empty list,
// the operator's override, refuse nothing; any other list refuses its
// networks and every unspecified, loopback, and link-local address, plus
// interface-local multicast. The policy does not apply to the platform's
// destinations, to the URLs that config.yaml lists, or to a destination
// imported from config.yaml until its URL is replaced: the platform
// administrators and the host operator configure those.
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
// policy refuses. An address that cannot be resolved is refused as well: the
// active policy must verify a destination before allowing it to be contacted.
// The check runs when a unit's destination is saved and again in the
// notification child immediately before a send.
func (p *destinationPolicy) check(ctx context.Context, rawURL string) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, host := range destinationHosts(rawURL) {
		if addr, err := netip.ParseAddr(host); err == nil {
			if p.refuses(addr) {
				return ErrDestinationExcluded
			}
			continue
		}
		lookupCtx, cancel := context.WithTimeout(ctx, destinationLookupTimeout)
		_, err := resolveDestination(lookupCtx, host, p)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
	}
	return nil
}

// checkDestinationForSave keeps save-time resolution failures distinct from
// provider delivery failures. Delivery still uses check directly and retains
// its retryable DNS error classification. If the caller itself has been
// canceled, preserve that cancellation instead of reporting a validation
// error.
func checkDestinationForSave(ctx context.Context, policy *destinationPolicy, rawURL string) error {
	if err := policy.check(ctx, rawURL); err != nil {
		if errors.Is(err, ErrDestinationExcluded) {
			return err
		}
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrDestinationUnresolved
	}
	return nil
}

func destinationDNSFailure() error {
	return &store.DeliveryFailure{Err: store.ErrDeliveryProvider, Class: store.DeliveryClassDNS}
}

// fixedHostProviders are the Shoutrrr services that always connect to their
// public API host, such as discord.com, and use the host part of their URL
// for a token or an ID instead. logger connects to nothing.
var fixedHostProviders = map[string]bool{
	"discord": true, "ifttt": true, "join": true, "logger": true, "pushbullet": true,
	"pushover": true, "slack": true, "telegram": true,
}

const teamsDefaultHost = "outlook.office.com"

// destinationHosts returns the hosts that the provider of a Shoutrrr URL
// connects to. Teams takes its host from the host query parameter and
// otherwise connects to its public default; every other provider, including
// one that a later Shoutrrr release adds, and every custom URL such as
// generic+https://, connects to the host of the URL. Teams query keys are
// case-insensitive in Shoutrrr; if differently-cased keys conflict, every
// candidate is checked because map iteration makes the provider's winner
// nondeterministic.
func destinationHosts(rawURL string) []string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil
	}
	scheme := strings.ToLower(parsed.Scheme)
	provider := scheme
	if separator := strings.IndexByte(provider, '+'); separator >= 0 {
		provider = provider[:separator]
	}
	var hosts []string
	switch {
	case provider == "teams":
		hasHostOverride := false
		for key, values := range parsed.Query() {
			if strings.EqualFold(key, "host") && len(values) > 0 {
				hasHostOverride = true
				host := providerHostname(values[0])
				if host == "" {
					// Shoutrrr's Teams provider uses LegacyHost when the host
					// parameter is explicitly empty.
					host = teamsDefaultHost
				}
				hosts = append(hosts, host)
			}
		}
		if !hasHostOverride {
			if provider != scheme {
				hosts = append(hosts, parsed.Hostname())
			} else {
				hosts = append(hosts, teamsDefaultHost)
			}
		}
	case strings.Contains(scheme, "+"):
		hosts = append(hosts, parsed.Hostname())
	case fixedHostProviders[scheme]:
		return nil
	default:
		hosts = append(hosts, parsed.Hostname())
	}
	result := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if host == "" {
			continue
		}
		key := strings.ToLower(host)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, host)
	}
	sort.Strings(result)
	return result
}

func providerHostname(value string) string {
	value = strings.TrimSpace(value)
	if address, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return address.String()
	}
	if parsed, err := url.Parse("//" + value); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(strings.TrimSpace(host), "[]")
	}
	return strings.Trim(value, "[]")
}

// destinationPolicy returns the policy for the destinations that units own.
func (n *Notifier) destinationPolicy() *destinationPolicy {
	if n == nil {
		return nil
	}
	return n.policy.Load()
}
