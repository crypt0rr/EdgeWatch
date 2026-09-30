/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { SurfaceUnitList } from './SurfaceUnitList'

describe('SurfaceUnitList', () => {
  let root: Root
  let container: HTMLDivElement

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  it('shows compact target, address, protocol, state, and service evidence', () => {
    act(() => root.render(<SurfaceUnitList units={[{
      target: 'router.example',
      protocol: 'tcp',
      addresses: ['198.51.100.10', '198.51.100.11'],
      ports: [
        // This mirrors the backend wire shape: model.PortState.Evidence is
        // emitted under the JSON key `addresses`.
        { port: 443, state: 'open', service: 'https', addresses: ['reason ttl 64', 'nmap', 'verified'] },
        { port: 8443, state: 'open|filtered', addresses: ['udp-response'] },
        { port: 22, state: 'closed' },
      ],
    }]} />))

    expect(container.textContent).toContain('router.example')
    expect(container.textContent).toContain('TCP')
    expect(container.textContent).toContain('198.51.100.10, 198.51.100.11')
    expect(container.textContent).toContain('443/tcp')
    expect(container.textContent).toContain('https')
    expect(container.textContent).toContain('on reason ttl 64, nmap +1 more')
    expect(container.textContent).toContain('8443/tcp')
    expect(container.textContent).toContain('on udp-response')
    expect(container.textContent).not.toContain('22/tcp')
  })

  it('makes an empty positive surface explicit', () => {
    act(() => root.render(<SurfaceUnitList units={[{ target: 'silent.example', protocol: 'udp', addresses: ['192.0.2.1'], ports: [] }]} />))
    expect(container.textContent).toContain('No positive ports')
  })

  it('keeps long targets and every effective address available', () => {
    const target = `${'edgewatch'.repeat(12)}.example.test`
    const addresses = ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4']
    act(() => root.render(<SurfaceUnitList units={[{ target, protocol: 'tcp', addresses, ports: [] }]} />))

    const targetLabel = container.querySelector('.surface-unit-title strong')
    expect(targetLabel).toHaveTextContent(target)
    expect(targetLabel).toHaveAttribute('title', target)
    const disclosure = container.querySelector<HTMLDetailsElement>('.surface-unit-address-details')
    expect(disclosure?.querySelector('summary')).toHaveTextContent('+1 more')
    expect(disclosure?.open).toBe(false)
    act(() => { if (disclosure) disclosure.open = true })
    expect(disclosure?.querySelectorAll('li')).toHaveLength(addresses.length)
    expect(disclosure?.querySelector('li:last-child')).toHaveTextContent(addresses[3])
  })

  it('renders a useful empty-list message', () => {
    act(() => root.render(<SurfaceUnitList units={[]} emptyLabel="No current baseline results." />))
    expect(container.textContent).toContain('No current baseline results.')
  })
})
