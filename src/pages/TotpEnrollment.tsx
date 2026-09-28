import { LogOut, Wifi } from 'lucide-react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { useActivityHeartbeat } from '../components/navigation'
import { Security } from './Security'

/**
 * The console of an administrator who must enrol an authenticator first.
 * Once more than one business unit exists, every unit administrator and
 * platform administrator needs TOTP, and until they enrol their session holds
 * only their own account's self-service. This shell therefore mounts no page
 * that reads a unit's or the platform's data: every path shows the
 * enrolment, which also offers a password change, and the header offers
 * sign-out.
 */
export function TotpEnrollmentShell({ displayName, onLogout }: { displayName: string; onLogout: () => void }) {
  useActivityHeartbeat()
  return <div className="enrollment-shell">
    <header className="enrollment-topbar">
      <div className="brand"><span className="brand-mark"><Wifi size={19} /></span><span>EdgeWatch</span></div>
      <div className="enrollment-account"><span className="enrollment-user">{displayName}</span><button type="button" className="button ghost" onClick={onLogout}><LogOut size={16} /> Sign out</button></div>
    </header>
    <main className="content enrollment-content">
      <Routes>
        <Route path="/security" element={<Security enrollment />} />
        <Route path="*" element={<Navigate to="/security" replace />} />
      </Routes>
    </main>
  </div>
}
