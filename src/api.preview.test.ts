import { afterEach, describe, expect, it, vi } from 'vitest'
import { previewJob, setCSRF } from './api'
import type { JobForm, JobPreview } from './types'

const draft: JobForm = {
  name: 'edge inventory',
  schedule: '0 * * * *',
  timezone: 'UTC',
  targets: ['198.51.100.10'],
  max_expanded_hosts: 256,
  tcp: { ports: '443', mode: 'connect', service_detection: false, engine: 'nmap' },
  timing: 'balanced',
  timeout: '1m',
  baseline_samples: 2,
  change_confirmations: 2,
  notification_destinations: ['destination-1'],
}

const response: JobPreview = {
  job: draft,
  scan_estimate: { hosts: 1, tcp_ports: 1, udp_ports: 0, probes: 1, nmap_invocations: 1, unknown_dns: 0 },
  scan_budget: { exceeded: false },
  warnings: [{ code: 'elapsed_time_unknown', message: 'Elapsed time depends on scanner behavior and target responses.' }],
}

afterEach(() => {
  vi.restoreAllMocks()
  setCSRF('')
})

describe('job preview API', () => {
  it('posts the draft with CSRF protection and returns the typed preview', async () => {
    setCSRF('csrf-token')
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify(response), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(previewJob(draft)).resolves.toEqual(response)

    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/jobs/preview')
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect(init.method).toBe('POST')
    expect(init.credentials).toBe('same-origin')
    expect(new Headers(init.headers).get('Content-Type')).toBe('application/json')
    expect(new Headers(init.headers).get('X-CSRF-Token')).toBe('csrf-token')
    const body = JSON.parse(String(init.body)) as Record<string, unknown>
    expect(body).toEqual(draft)
    expect(JSON.stringify(body)).not.toMatch(/password|notification_url|generic:\/\//i)
  })

  it('forwards an AbortSignal so stale previews can be canceled', async () => {
    let observedSignal: AbortSignal | null | undefined
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      observedSignal = init?.signal
      init?.signal?.addEventListener('abort', () => reject(new DOMException('The operation was aborted.', 'AbortError')), { once: true })
    }))
    vi.stubGlobal('fetch', fetchMock)
    const controller = new AbortController()

    const pending = previewJob(draft, controller.signal)
    controller.abort()

    await expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    expect(observedSignal).toBe(controller.signal)
    expect(controller.signal.aborted).toBe(true)
  })

  it.each([
    [400, 'validation_failed', { targets: 'target is invalid' }],
    [409, 'profile_conflict', undefined],
    [503, 'preview_unavailable', { reason: 'scan_budget_unavailable' }],
  ] as const)('preserves structured %s %s errors', async (status, code, details) => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ error: { code, message: 'preview failed', details } }), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(previewJob(draft)).rejects.toMatchObject({ status, code, details })
  })
})
