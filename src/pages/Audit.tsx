import { useQuery } from '@tanstack/react-query'
import { ScrollText } from 'lucide-react'
import { getSession, unitAudit } from '../api'
import { AuditLog } from '../components/AuditLog'

/**
 * The unit administrator's read-only audit trail. It includes actions that
 * EdgeWatch main administrators and host commands took on this unit and its
 * accounts, so a password reset by a main administrator is always visible here.
 */
export function Audit() {
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const unit = session.data?.unit?.name
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Administration</p><h1>Audit</h1><p className="muted">A read-only record of sign-ins, account changes, and configuration changes{unit ? ` in ${unit}` : ''}. It includes actions by EdgeWatch main administrators on your accounts and commands run on the EdgeWatch host.</p></div><ScrollText className="muted-icon" size={24} /></div>
    <div className="audit-legend" aria-label="Actor scopes"><span><span className="pill blue">Unit</span> A member of this unit</span><span><span className="pill amber">Platform</span> An EdgeWatch main administrator</span><span><span className="pill gray">Host</span> A command run on the EdgeWatch host</span></div>
    <AuditLog queryKey={['unit-audit']} load={before => unitAudit({ before })} emptyMessage="No audit entries have been recorded for this unit yet." />
  </section>
}
