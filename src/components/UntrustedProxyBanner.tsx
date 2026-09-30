import { AlertTriangle } from 'lucide-react'
import type { UntrustedProxy } from '../api'
import { formatDateTime } from '../format'

/**
 * Warns that requests reach EdgeWatch through a proxy that web.trusted_proxies
 * does not list: every client behind it then shares the proxy's address, and
 * with it one sign-in budget, the setup and activation limits, and the
 * address in the audit. A client can send the forwarding header itself, so
 * the banner asks the administrator to trust the address only when it is a
 * proxy that they run. Renders nothing when no such proxy was seen.
 */
export function UntrustedProxyBanner({ proxy }: { proxy?: UntrustedProxy }) {
  if (!proxy) return null
  return <div className="legacy-banner" role="status">
    <AlertTriangle size={17} />
    <span><strong>Requests arrive through a proxy that EdgeWatch does not trust.</strong> {proxy.peer} sends {proxy.header}, but web.trusted_proxies does not list it, so every client behind it shares one sign-in budget and one audit address. If {proxy.peer} is a proxy that you run, add it to web.trusted_proxies in config.yaml and restart EdgeWatch. Last seen {formatDateTime(proxy.last_seen_at)}.</span>
  </div>
}
