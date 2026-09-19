import type { Unit } from '../types'

type SurfaceUnitListProps = {
  units: Unit[]
  emptyLabel?: string
}

function positivePorts(unit: Unit) {
  return (unit.ports ?? []).filter((port) => port.state === 'open' || port.state === 'open|filtered')
}

function addressSummary(addresses: string[] | undefined) {
  const values = (addresses ?? []).filter(Boolean)
  if (values.length === 0) return 'No effective address reported'
  if (values.length <= 3) return values.join(', ')
  return `${values.slice(0, 3).join(', ')} +${values.length - 3} more`
}

function evidenceSummary(addresses: string[] | undefined) {
  const values = (addresses ?? []).filter(Boolean)
  if (values.length === 0) return ''
  return values.length <= 2 ? `on ${values.join(', ')}` : `on ${values.slice(0, 2).join(', ')} +${values.length - 2} more`
}

/**
 * Compact, responsive rendering of the positive surface represented by Unit
 * records. It is shared by the expected-baseline and latest-scan panels so
 * those views use identical target, address, protocol, and service language.
 */
export function SurfaceUnitList({ units, emptyLabel = 'No expected results.' }: SurfaceUnitListProps) {
  if (units.length === 0) return <div className="inline-empty">{emptyLabel}</div>

  return (
    <div className="surface-unit-list" role="list">
      {units.map((unit, index) => {
        const ports = positivePorts(unit)
        const key = `${unit.target}-${unit.protocol}-${index}`
        return (
          <article className="surface-unit-row" role="listitem" key={key}>
            <div className="surface-unit-header">
              <div className="surface-unit-title">
                <strong>{unit.target}</strong>
                <span className="pill blue">{unit.protocol.toUpperCase()}</span>
              </div>
              <span className="surface-unit-addresses" title={(unit.addresses ?? []).join(', ')}>{addressSummary(unit.addresses)}</span>
            </div>
            <div className="surface-unit-evidence">
              {ports.length > 0 ? (
                <div className="surface-port-list" aria-label={`${ports.length} positive port${ports.length === 1 ? '' : 's'}`}>
                  {ports.map((port) => (
                    <span className="surface-port" key={`${port.port}-${port.state}`}>
                      <code>{port.port}/{unit.protocol.toLowerCase()}</code>
                      <span>{port.state}</span>
                      {port.service && <small>{port.service}</small>}
                      {port.evidence?.length && <small className="surface-port-evidence">{evidenceSummary(port.evidence)}</small>}
                    </span>
                  ))}
                </div>
              ) : <span className="surface-no-positive">No positive ports</span>}
            </div>
          </article>
        )
      })}
    </div>
  )
}
