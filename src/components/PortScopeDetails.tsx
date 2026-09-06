export type PortScopeItem = {
  protocol: string
  ports: string
  portCount?: number
}

/** Keep long custom expressions out of compact cards while preserving access
 * to the exact configured scope on the expandable detail view. */
export function compactPortExpression(expression: string) {
  const value = expression.trim()
  if (!value) return 'no ports'
  if (value.length > 48 || value.split(',').length >= 8) return 'custom ports in use'
  return value
}

export function PortScopeDetails({ items }: { items: PortScopeItem[] }) {
  const visible = items.filter(item => item.ports.trim())
  if (!visible.length) return null
  return <div className="scope-details-list">
    {visible.map(item => {
      const protocol = item.protocol.toUpperCase()
      const summary = item.portCount ? `${item.portCount.toLocaleString()} ports` : compactPortExpression(item.ports)
      return <details className="scope-details" key={`${item.protocol}-${item.ports}`}>
        <summary>{protocol} · {summary}</summary>
        <code className="scope-expression">{item.ports}</code>
      </details>
    })}
  </div>
}
