import { z } from 'zod'
import { BUILTIN_NAABU_PROFILE_ID } from './api'
import type { JobForm, Protocol } from './types'
import { getDisplayTimeZone } from './format'

export const blankJobForm = (): Omit<JobForm, 'timezone'> => ({
  name: '',
  schedule: '0 */6 * * *',
  run_on_start: false,
  assume_alive: true,
  dns_comparison_mode: 'address_sensitive',
  targets: [''],
  max_expanded_hosts: 256,
  timing: 'balanced',
  timeout: '1h',
  resume_window: '8d',
  baseline_samples: 2,
  change_confirmations: 1,
  allow_high_cost: false,
  enabled: true,
})

// Resolve the configured display timezone only after the signed-in session
// has supplied it; fall back to the browser and then UTC.
export function newJobDefaults(): JobForm {
  return {
    ...blankJobForm(),
    timezone: getDisplayTimeZone() || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
  }
}

export const defaultTCP = (): Protocol => ({
  ports: '1-65535',
  mode: 'connect',
  service_detection: false,
  engine: 'naabu_nmap',
  profile_id: BUILTIN_NAABU_PROFILE_ID,
})

export const defaultUDP = (): Protocol => ({
  ports: '53',
  service_detection: true,
  engine: 'nmap',
})

export const jobFormSchema = z.object({
  name: z.string().trim().min(1, 'A name is required.').refine((value) => Array.from(value).length <= 200, 'Use at most 200 characters.').refine((value) => !/\p{Cc}/u.test(value), 'Remove control characters such as tabs or line breaks.'), // Mirrors the server's job-name rule (config.MaxJobNameRunes).
  schedule: z.string().trim().min(1, 'A cron schedule is required.'),
  timezone: z.string().trim().min(1, 'A timezone is required.'),
  run_on_start: z.boolean().optional(),
  assume_alive: z.boolean().optional(),
  dns_comparison_mode: z.enum(['address_sensitive', 'aggregate']),
  max_expanded_hosts: z.number().int('Use a whole number of hosts.').min(1, 'Use at least one host.').max(1_000_000, 'The expansion limit is too high.'),
  timing: z.string().refine((value) => ['conservative', 'balanced', 'fast'].includes(value), 'Choose a valid timing profile.'),
  timeout: z.string().trim().min(1, 'A scan timeout is required.'),
  resume_window: z.string().trim().min(1, 'A resume window is required.'),
  baseline_samples: z.number().int('Use a whole number of samples.').min(1, 'Use at least one baseline sample.').max(100, 'Use no more than 100 baseline samples.'),
  change_confirmations: z.number().int('Use a whole number of confirmations.').min(1, 'Use at least one confirmation.').max(100, 'Use no more than 100 confirmations.'),
  allow_high_cost: z.boolean().optional(),
  enabled: z.boolean().optional(),
})

export type JobFormFields = z.infer<typeof jobFormSchema>

/**
 * The complete non-secret creation draft shared by guided and advanced modes.
 * Optional notification routing intentionally distinguishes an omitted
 * selection from an explicitly empty selection.
 */
export type JobCreationDraft = {
  fields: JobFormFields
  targets: string[]
  tcp?: Protocol
  udp?: Protocol
  lastTCP?: Protocol
  lastUDP?: Protocol
  tcpFullSnapshot?: Protocol
  tcpSelectedSnapshot?: Protocol
  notificationIDs: string[]
  notificationSelectionTouched: boolean
  scheduleEnabled: boolean
}

export function newJobCreationDraft(): JobCreationDraft {
  const defaults = newJobDefaults()
  return {
    fields: {
      name: defaults.name,
      schedule: defaults.schedule,
      timezone: defaults.timezone,
      run_on_start: defaults.run_on_start,
      assume_alive: defaults.assume_alive,
      dns_comparison_mode: defaults.dns_comparison_mode ?? 'address_sensitive',
      max_expanded_hosts: defaults.max_expanded_hosts,
      timing: defaults.timing,
      timeout: defaults.timeout,
      resume_window: defaults.resume_window ?? '8d',
      baseline_samples: defaults.baseline_samples,
      change_confirmations: defaults.change_confirmations,
      allow_high_cost: defaults.allow_high_cost,
      enabled: defaults.enabled,
    },
    targets: [...defaults.targets],
    tcp: defaultTCP(),
    udp: undefined,
    lastTCP: undefined,
    lastUDP: undefined,
    tcpFullSnapshot: defaultTCP(),
    tcpSelectedSnapshot: undefined,
    notificationIDs: [],
    notificationSelectionTouched: false,
    scheduleEnabled: defaults.enabled ?? true,
  }
}

export function cloneJobCreationDraft(draft: JobCreationDraft): JobCreationDraft {
  return {
    fields: { ...draft.fields },
    targets: [...draft.targets],
    tcp: cloneProtocol(draft.tcp),
    udp: cloneProtocol(draft.udp),
    lastTCP: cloneProtocol(draft.lastTCP),
    lastUDP: cloneProtocol(draft.lastUDP),
    tcpFullSnapshot: cloneProtocol(draft.tcpFullSnapshot),
    tcpSelectedSnapshot: cloneProtocol(draft.tcpSelectedSnapshot),
    notificationIDs: [...draft.notificationIDs],
    notificationSelectionTouched: draft.notificationSelectionTouched,
    scheduleEnabled: draft.scheduleEnabled,
  }
}

export function cloneProtocol(protocol: Protocol | undefined): Protocol | undefined {
  if (!protocol) return undefined
  return {
    ...protocol,
    naabu: protocol.naabu ? { ...protocol.naabu } : undefined,
    naabu_args: protocol.naabu_args ? [...protocol.naabu_args] : undefined,
    nmap_args: protocol.nmap_args ? [...protocol.nmap_args] : undefined,
    enrichment_args: protocol.enrichment_args ? [...protocol.enrichment_args] : undefined,
    nse_args: protocol.nse_args ? { ...protocol.nse_args } : undefined,
  }
}

/** Convert either creation mode or the saved-job editor to the API shape. */
export function toJobFormPayload(
  fields: JobFormFields,
  options: {
    targets: string[]
    tcp?: Protocol
    udp?: Protocol
    scheduleEnabled: boolean
    notificationIDs: string[]
    notificationSelectionTouched: boolean
    notificationsLoaded: boolean
    availableNotificationIDs?: Iterable<string>
  },
): JobForm {
  const available = options.availableNotificationIDs ? new Set(options.availableNotificationIDs) : undefined
  const notificationDestinations = options.notificationSelectionTouched
    ? options.notificationIDs.filter(id => !available || available.has(id))
    : options.notificationsLoaded
      ? options.notificationIDs.filter(id => !available || available.has(id))
      : undefined
  return {
    ...fields,
    enabled: options.scheduleEnabled,
    targets: options.targets.map(value => value.trim()).filter(Boolean),
    tcp: cloneProtocol(options.tcp),
    udp: cloneProtocol(options.udp),
    notification_destinations: notificationDestinations,
  }
}

export function payloadFromCreationDraft(draft: JobCreationDraft, notificationsLoaded: boolean, availableNotificationIDs?: Iterable<string>): JobForm {
  return toJobFormPayload(draft.fields, {
    targets: draft.targets,
    tcp: draft.tcp,
    udp: draft.udp,
    scheduleEnabled: draft.scheduleEnabled,
    notificationIDs: draft.notificationIDs,
    notificationSelectionTouched: draft.notificationSelectionTouched,
    notificationsLoaded,
    availableNotificationIDs,
  })
}

export function presetFor(schedule: string) {
  return ['0 */6 * * *', '0 * * * *', '0 3 * * *', '0 3 * * 0'].includes(schedule) ? schedule : 'custom'
}

export function optionalNumber(value: string): number | undefined {
  return value.trim() === '' ? undefined : Number(value)
}
