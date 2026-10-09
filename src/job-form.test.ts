import { afterEach, describe, expect, it } from 'vitest'
import { setDisplayTimeZone } from './format'
import { cloneJobCreationDraft, defaultTCP, jobFormSchema, newJobCreationDraft, payloadFromCreationDraft, toJobFormPayload } from './job-form'

describe('shared job form defaults and payload conversion', () => {
  afterEach(() => setDisplayTimeZone(''))

  it('creates independent default drafts with the current full-range TCP profile and two baseline samples', () => {
    setDisplayTimeZone('Europe/Amsterdam')
    const first = newJobCreationDraft()
    const second = newJobCreationDraft()

    expect(first.fields).toMatchObject({ timezone: 'Europe/Amsterdam', baseline_samples: 2, change_confirmations: 1, allow_high_cost: false })
    expect(first.tcp).toEqual(defaultTCP())
    expect(first.tcp?.profile_revision).toBeUndefined()
    expect(first.fields).not.toBe(second.fields)
    expect(first.tcp).not.toBe(second.tcp)

    first.fields.name = 'Mutated first draft'
    first.tcp!.naabu = { rate: 400 }
    first.targets.push('198.51.100.1')
    expect(second.fields.name).toBe('')
    expect(second.tcp?.naabu).toBeUndefined()
    expect(second.targets).toEqual([''])
  })

  it('keeps an omitted routing selection distinct from an explicit empty selection', () => {
    const draft = newJobCreationDraft()
    draft.targets = [' 198.51.100.10 ']
    expect(payloadFromCreationDraft(draft, false).notification_destinations).toBeUndefined()
    draft.notificationSelectionTouched = true
    draft.notificationIDs = []
    expect(payloadFromCreationDraft(draft, true).notification_destinations).toEqual([])
    expect(payloadFromCreationDraft(draft, true, []).notification_destinations).toEqual([])
  })

  it('preserves selected profiles, revisions, protocols, and advanced job fields in payload conversion', () => {
    const fields = jobFormSchema.parse({ ...newJobCreationDraft().fields, name: ' Edge ', max_expanded_hosts: 512, allow_high_cost: true })
    const payload = toJobFormPayload(fields, {
      targets: [' 198.51.100.10 ', ''],
      tcp: { ports: '22,443', mode: 'syn', service_detection: true, engine: 'nmap', profile_id: 'profile-1', profile_revision: 7, nmap_args: ['-sV'] },
      udp: { ports: '53', service_detection: true, engine: 'nmap' },
      scheduleEnabled: false,
      notificationIDs: ['notify-1', 'gone'],
      notificationSelectionTouched: true,
      notificationsLoaded: true,
      availableNotificationIDs: ['notify-1'],
    })

    expect(payload).toMatchObject({
      name: 'Edge',
      targets: ['198.51.100.10'],
      max_expanded_hosts: 512,
      allow_high_cost: true,
      enabled: false,
      tcp: { ports: '22,443', profile_id: 'profile-1', profile_revision: 7, nmap_args: ['-sV'] },
      udp: { ports: '53' },
      notification_destinations: ['notify-1'],
    })
  })

  it('clones nested protocol data when a draft crosses creation modes', () => {
    const draft = newJobCreationDraft()
    draft.tcp!.naabu = { rate: 2000 }
    draft.tcp!.nmap_args = ['-sV']
    const switched = cloneJobCreationDraft(draft)
    switched.tcp!.naabu!.rate = 3000
    switched.tcp!.nmap_args!.push('-O')

    expect(draft.tcp?.naabu?.rate).toBe(2000)
    expect(draft.tcp?.nmap_args).toEqual(['-sV'])
  })
})
