import { Landmark, LogOut, Wifi } from 'lucide-react'

/**
 * The console of a platform administrator while business units are turned
 * off in config.yaml. The platform console's routes do not exist then, and
 * the session holds only its own account's self-service, so this shell
 * states why and offers sign-out. It has no routes and mounts no page of a
 * unit's console, so every address shows the same notice and nothing
 * redirects.
 */
export function PlatformUnavailableShell({ displayName, onLogout }: { displayName: string; onLogout: () => void }) {
  return <div className="enrollment-shell">
    <header className="enrollment-topbar">
      <div className="brand"><span className="brand-mark"><Wifi size={19} /></span><span>EdgeWatch</span></div>
      <div className="enrollment-account"><span className="enrollment-user">{displayName}</span><button type="button" className="button ghost" onClick={onLogout}><LogOut size={16} /> Sign out</button></div>
    </header>
    <main className="content enrollment-content">
      <section className="page narrow">
        <div className="page-heading"><div><p className="eyebrow">Platform console</p><h1>Business units are turned off</h1><p className="muted">This deployment&apos;s configuration turns business units off, so the platform console is not available. The business units and your account are unchanged. The console returns when an operator sets <code>business_units: true</code> in the <code>experimental</code> section of config.yaml again.</p></div><Landmark className="muted-icon" size={24} aria-hidden="true" /></div>
      </section>
    </main>
  </div>
}
