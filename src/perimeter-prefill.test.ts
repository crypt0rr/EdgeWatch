import { describe, expect, it } from 'vitest'
import type { PerimeterSuggestion } from './generated/api-types'
import { buildPerimeterPrefill, isPerimeterMode, perimeterModeLabel, perimeterModes, perimeterMonitorName, readPerimeterPrefill, type PerimeterPrefill } from './perimeter-prefill'

const fullTCP: PerimeterSuggestion = {
  mode: 'full_tcp',
  targets: ['203.0.113.0/24'],
  addresses: 256,
  estimated_probes: 16_776_960,
  protocol: { protocol: 'tcp', engine: 'naabu_nmap', ports: '1-65535', mode: 'connect', service_detection: false, profile_id: '00000000-0000-0000-0000-000000000014' },
}

const udp: PerimeterSuggestion = {
  mode: 'udp',
  targets: ['198.51.100.0/24', '198.51.100.0/27', '192.0.2.7'],
  addresses: 289,
  estimated_probes: 3468,
  protocol: { protocol: 'udp', engine: 'nmap', ports: '53,123,161,500,1194,4500', service_detection: true },
}

describe('perimeter prefill', () => {
  it('names the modes and recognizes only them', () => {
    expect(perimeterModes).toEqual(['full_tcp', 'selected_tcp', 'udp'])
    expect(perimeterModes.map(perimeterModeLabel)).toEqual(['full TCP', 'selected TCP ports', 'UDP'])
    for (const mode of perimeterModes) expect(isPerimeterMode(mode)).toBe(true)
    for (const value of ['any_tcp', 'FULL_TCP', '', undefined, null, 1, {}]) expect(isPerimeterMode(value)).toBe(false)
  })

  it('names a monitor after its first target, the number of others, and its mode', () => {
    expect(perimeterMonitorName(['203.0.113.0/24'], 'full_tcp')).toBe('Perimeter 203.0.113.0/24 · full TCP')
    expect(perimeterMonitorName(['198.51.100.0/24', '198.51.100.0/27', '192.0.2.7'], 'udp')).toBe('Perimeter 198.51.100.0/24 +2 more · UDP')
    expect(perimeterMonitorName(['192.0.2.0/25', '192.0.2.128/26'], 'selected_tcp')).toBe('Perimeter 192.0.2.0/25 +1 more · selected TCP ports')
  })

  it('cuts a long name to the 200 runes a job name holds', () => {
    const long = `${'é'.repeat(250)}`
    const name = perimeterMonitorName([long], 'udp')
    expect(Array.from(name)).toHaveLength(200)
    expect(name.startsWith('Perimeter ééé')).toBe(true)
    // A cut that ends on a space leaves no trailing whitespace.
    const spaced = perimeterMonitorName([`${'a'.repeat(189)} b`], 'udp')
    expect(spaced).toBe(`Perimeter ${'a'.repeat(189)}`)
  })

  it('builds the prefill from a suggestion with its protocol settings unchanged', () => {
    const prefill = buildPerimeterPrefill(fullTCP, '203.0.113.0/24', 0, 1)
    expect(prefill).toEqual({
      name: 'Perimeter 203.0.113.0/24 · full TCP',
      targets: ['203.0.113.0/24'],
      mode: 'full_tcp',
      protocol: fullTCP.protocol,
      addresses: 256,
      source: '203.0.113.0/24',
    })
    // The prefill holds copies, so later changes to the report do not reach it.
    expect(prefill.protocol).not.toBe(fullTCP.protocol)
    expect(prefill.targets).not.toBe(fullTCP.targets)

    const fromUDP = buildPerimeterPrefill(udp, '198.51.100.0/22', 2, 3)
    expect(fromUDP.name).toBe('Perimeter 198.51.100.0/24 +2 more · UDP')
    expect(fromUDP.source).toBe('198.51.100.0/22')
    expect(fromUDP.protocol).toEqual({ protocol: 'udp', engine: 'nmap', ports: '53,123,161,500,1194,4500', service_detection: true })
    expect('mode' in fromUDP.protocol).toBe(false)
    expect(readPerimeterPrefill({ perimeterPrefill: fromUDP })).toEqual(fromUDP)
  })

  it('refuses to build a prefill for an unknown mode', () => {
    expect(() => buildPerimeterPrefill({ ...fullTCP, mode: 'any_tcp' }, '203.0.113.0/24', 0, 1)).toThrow(TypeError)
  })

  it('reads a prefill from router state or as itself', () => {
    const prefill = buildPerimeterPrefill(fullTCP, '203.0.113.0/24', 0, 1)
    expect(readPerimeterPrefill({ perimeterPrefill: prefill })).toEqual(prefill)
    expect(readPerimeterPrefill(prefill)).toEqual(prefill)
    expect(readPerimeterPrefill({ perimeterPrefill: prefill })).not.toBe(prefill)
  })

  it('rejects state that is not a well-formed prefill', () => {
    const valid: PerimeterPrefill = buildPerimeterPrefill(fullTCP, '203.0.113.0/24', 0, 1)
    const invalid: unknown[] = [
      undefined,
      null,
      'perimeter',
      [],
      { perimeterPrefill: null },
      { perimeterPrefill: [] },
      { startFirstScanToken: 'token' },
      { ...valid, name: '' },
      { ...valid, name: 'a'.repeat(201) },
      { ...valid, name: 'tab\tname' },
      { ...valid, name: 7 },
      { ...valid, targets: [] },
      { ...valid, targets: 'a' },
      { ...valid, targets: ['203.0.113.0/24', ''] },
      { ...valid, targets: ['203.0.113.0/24', 4] },
      { ...valid, mode: 'any_tcp' },
      { ...valid, addresses: 0 },
      { ...valid, addresses: 1.5 },
      { ...valid, addresses: '256' },
      { ...valid, source: '' },
      { ...valid, source: undefined },
      { ...valid, protocol: null },
      { ...valid, protocol: { ...valid.protocol, protocol: 'udp' } },
      { ...valid, mode: 'udp' },
      { ...valid, protocol: { ...valid.protocol, engine: '' } },
      { ...valid, protocol: { ...valid.protocol, ports: 443 } },
      { ...valid, protocol: { ...valid.protocol, service_detection: 'false' } },
      { ...valid, protocol: { ...valid.protocol, mode: 1 } },
      { ...valid, protocol: { ...valid.protocol, profile_id: false } },
    ]
    for (const state of invalid) expect(readPerimeterPrefill(state), JSON.stringify(state)).toBeNull()
  })

  it('keeps only the protocol keys the server sent', () => {
    const state = { perimeterPrefill: { ...buildPerimeterPrefill(udp, '198.51.100.0/22', 0, 1), extra: true, protocol: { ...udp.protocol, extra: 'ignored' } } }
    const read = readPerimeterPrefill(state)
    expect(read).not.toBeNull()
    expect(read?.protocol).toEqual(udp.protocol)
    expect(read).not.toHaveProperty('extra')
  })
})
