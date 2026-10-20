import type { PerimeterProtocol, PerimeterSuggestion } from './generated/api-types'

/**
 * The suggestion modes of the perimeter report. Each fills the gaps of one
 * coverage bucket with the protocol settings that the server returns.
 */
export const perimeterModes = ['full_tcp', 'selected_tcp', 'udp'] as const
export type PerimeterMode = typeof perimeterModes[number]

/**
 * What Create monitor on the Perimeter range page hands the guided setup, in
 * the router state as `{ perimeterPrefill }`. The guided setup applies it
 * once to a fresh draft; it creates nothing by itself, and a person still
 * reviews and saves the monitor through the job API.
 */
export type PerimeterPrefill = {
  /** The new monitor's name, by the rule of perimeterMonitorName. */
  name: string
  /** The suggestion's CIDR blocks and addresses. */
  targets: string[]
  mode: PerimeterMode
  /** The suggestion's protocol settings, applied verbatim. */
  protocol: PerimeterProtocol
  /** The addresses the targets hold; the expansion limit is raised to at least this. */
  addresses: number
  /** The declared range the suggestion fills, as the server returns its value. */
  source: string
}

/** The most runes in a job name, as config.MaxJobNameRunes allows. */
const maxNameRunes = 200

const modeLabels: Record<PerimeterMode, string> = {
  full_tcp: 'full TCP',
  selected_tcp: 'selected TCP ports',
  udp: 'UDP',
}

/** Reports whether value is one of the perimeter suggestion modes. */
export function isPerimeterMode(value: unknown): value is PerimeterMode {
  return typeof value === 'string' && (perimeterModes as readonly string[]).includes(value)
}

/** The lower-case label of a mode, as a monitor name uses it: "full TCP". */
export function perimeterModeLabel(mode: PerimeterMode): string {
  return modeLabels[mode]
}

/**
 * The name of a monitor that a suggestion prefills:
 * `Perimeter <first target>[ +<n> more] · <mode label>`, cut to the 200 runes
 * a job name may hold. Each suggestion of a mode starts at another address,
 * so the names of one range's suggestions never clash. A clash with an
 * existing job is answered by the job API when the monitor is saved.
 */
export function perimeterMonitorName(targets: readonly string[], mode: PerimeterMode): string {
  const more = targets.length > 1 ? ` +${targets.length - 1} more` : ''
  const name = `Perimeter ${targets[0] ?? ''}${more} · ${modeLabels[mode]}`
  return Array.from(name).slice(0, maxNameRunes).join('').trimEnd()
}

/**
 * Builds the prefill for one suggestion of the declared range rangeValue.
 * index and total, the suggestion's place among the suggestions of its mode,
 * do not change the prefill: the name rule needs neither, because each
 * suggestion's first target already sets it apart. The protocol settings are
 * copied as the server returned them, so the console holds no copy of the
 * perimeter presets. A suggestion of an unknown mode throws; callers check the
 * mode with isPerimeterMode first.
 */
export function buildPerimeterPrefill(suggestion: PerimeterSuggestion, rangeValue: string, index: number, total: number): PerimeterPrefill {
  if (!isPerimeterMode(suggestion.mode)) throw new TypeError(`unknown perimeter suggestion mode ${JSON.stringify(suggestion.mode)}`)
  const targets = [...(suggestion.targets ?? [])]
  return {
    name: perimeterMonitorName(targets, suggestion.mode),
    targets,
    mode: suggestion.mode,
    protocol: { ...suggestion.protocol },
    addresses: suggestion.addresses,
    source: rangeValue,
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim() !== ''
}

// A job name holds 1 to 200 runes and no control characters.
function validName(value: unknown): value is string {
  return nonEmptyString(value) && Array.from(value).length <= maxNameRunes && !/\p{Cc}/u.test(value)
}

// The protocol must match the mode: UDP for udp, TCP for the TCP modes. Only
// the keys that the server sends are copied, so an absent optional key stays
// absent.
function readProtocol(value: unknown, mode: PerimeterMode): PerimeterProtocol | null {
  if (!isRecord(value)) return null
  const { protocol, engine, ports, mode: scanMode, service_detection: serviceDetection, profile_id: profileID } = value
  const expected = mode === 'udp' ? 'udp' : 'tcp'
  if (protocol !== expected) return null
  if (!nonEmptyString(engine) || !nonEmptyString(ports) || typeof serviceDetection !== 'boolean') return null
  if (scanMode !== undefined && typeof scanMode !== 'string') return null
  if (profileID !== undefined && typeof profileID !== 'string') return null
  return {
    protocol: expected,
    engine,
    ports,
    ...(scanMode !== undefined ? { mode: scanMode } : {}),
    service_detection: serviceDetection,
    ...(profileID !== undefined ? { profile_id: profileID } : {}),
  }
}

/**
 * Reads a perimeter prefill from router state: the `{ perimeterPrefill }`
 * object that Create monitor sends, or the prefill itself. It returns null
 * for anything else, including a prefill with a field of the wrong shape, an
 * empty target list, a protocol that does not match its mode, or a name that
 * is not a valid job name, so state from elsewhere is never applied.
 */
export function readPerimeterPrefill(state: unknown): PerimeterPrefill | null {
  const candidate = isRecord(state) && 'perimeterPrefill' in state ? state.perimeterPrefill : state
  if (!isRecord(candidate)) return null
  const { name, targets, mode, protocol, addresses, source } = candidate
  if (!validName(name) || !isPerimeterMode(mode) || !nonEmptyString(source)) return null
  if (!Array.isArray(targets) || targets.length === 0 || !targets.every(nonEmptyString)) return null
  if (typeof addresses !== 'number' || !Number.isSafeInteger(addresses) || addresses < 1) return null
  const parsedProtocol = readProtocol(protocol, mode)
  if (!parsedProtocol) return null
  return { name, targets: [...targets], mode, protocol: parsedProtocol, addresses, source }
}
