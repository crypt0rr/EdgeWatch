import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { BellRing, LockKeyhole } from 'lucide-react'
import { listDeploymentNotifications } from '../../api'
import { Loading } from './common'

/** Deployment (config.yaml) destinations and the units each one is assigned to. */
export function DeploymentNotifications() {
  const destinations = useQuery({ queryKey: ['platform-deployment-notifications'], queryFn: listDeploymentNotifications })
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Deployment notifications</h1><p className="muted">Destinations defined under notifications in config.yaml. Assign them to units from each unit’s Notifications tab; units also manage destinations of their own.</p></div><BellRing className="muted-icon" size={24} /></div>
    <div className="legacy-banner"><LockKeyhole size={17} /><span><strong>URLs stay on the host.</strong> Deployment destination URLs are never shown in the console or returned by the API.</span></div>
    {destinations.isLoading ? <Loading label="Loading deployment destinations…" /> : !destinations.data ? <div className="error-card" role="alert">Could not load deployment destinations.</div> : destinations.data.destinations.length ? <div className="panel"><div className="user-list">{destinations.data.destinations.map(item => <div className="user-row destination-row" key={item.id}>
      <div><strong>{item.name}</strong><span>{item.provider} · {item.enabled ? 'enabled' : 'disabled in config.yaml'}</span></div>
      <div className="destination-units" aria-label={`Units assigned to ${item.name}`}>{item.units.length ? item.units.map(unit => <Link key={unit.id} className="pill blue" to={`/platform/units/${encodeURIComponent(unit.id)}/notifications`}>{unit.name}</Link>) : <span className="muted">Not assigned to any unit</span>}</div>
    </div>)}</div></div> : <div className="inline-empty">config.yaml defines no deployment destinations.</div>}
  </section>
}
