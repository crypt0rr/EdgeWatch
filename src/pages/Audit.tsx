import { useQuery } from '@tanstack/react-query'
import { ScrollText } from 'lucide-react'
import { getSession, unitAudit } from '../api'
import { AuditLog } from '../components/AuditLog'

/**
 * The unit administrators' read-only audit. It includes what platform
 * administrators and host commands did to the unit and its accounts, so a
 * password reset by a platform administrator is always visible here; the
 * source address of a platform administrator's action is left out.
 */
export function Audit() {
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const unit = session.data?.multi_unit ? session.data.unit?.name : undefined
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Administration</p><h1>Audit</h1><p className="muted">A read-only record of sign-ins, account changes, and configuration changes{unit ? ` in ${unit}` : ''}, including what platform administrators did to your accounts and what commands on the EdgeWatch host did.</p></div><ScrollText className="muted-icon" size={24} /></div>
    <div className="audit-legend" aria-label="Actors"><span><span className="pill blue">Unit</span> A member of this unit</span><span><span className="pill amber">Platform</span> A platform administrator</span><span><span className="pill gray">Host</span> A command on the EdgeWatch host</span></div>
    <AuditLog queryKey={['unit-audit']} load={before => unitAudit({ before })} emptyMessage="No audit entries have been recorded yet." />
  </section>
}
