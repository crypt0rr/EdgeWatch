/** @vitest-environment jsdom */

import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { ScheduledBackupStatus } from '../api'
import { ScheduledBackupBanner } from './ScheduledBackupBanner'

const healthy: ScheduledBackupStatus = { directory: '/var/lib/edgewatch/backups', schedule: '0 3 * * *', keep: 7, last_success_at: '2026-10-01T03:00:00Z', last_backup: 'edgewatch-scheduled-20261001T030000Z.db', consecutive_failures: 0 }

describe('ScheduledBackupBanner', () => {
  it('renders nothing while scheduled backups are off or succeed', () => {
    const { container } = render(<><ScheduledBackupBanner /><ScheduledBackupBanner backups={healthy} /></>)
    expect(container).toBeEmptyDOMElement()
  })

  it('names the failure, its reason, and the newest good backup', () => {
    render(<ScheduledBackupBanner backups={{ ...healthy, consecutive_failures: 1, last_failure_at: '2026-10-02T03:00:00Z', last_error: 'output directory: no space left on device' }} />)
    const banner = screen.getByRole('status')
    expect(banner).toHaveTextContent('Scheduled backups are failing.')
    expect(banner).toHaveTextContent('The latest scheduled backup failed, last at')
    expect(banner).toHaveTextContent(': output directory: no space left on device.')
    expect(banner).toHaveTextContent('The newest good backup, edgewatch-scheduled-20261001T030000Z.db, is from')
    expect(banner).toHaveTextContent('Check /var/lib/edgewatch/backups on the EdgeWatch host')
  })

  it('counts repeated failures and says when no backup has succeeded', () => {
    render(<ScheduledBackupBanner backups={{ directory: '/backups', schedule: '0 3 * * *', keep: 7, consecutive_failures: 3 }} />)
    const banner = screen.getByRole('status')
    expect(banner).toHaveTextContent('The last 3 scheduled backups failed. No scheduled backup has succeeded yet.')
  })

  it('names an unnamed newest backup', () => {
    render(<ScheduledBackupBanner backups={{ directory: '/backups', schedule: '0 3 * * *', keep: 7, consecutive_failures: 1, last_success_at: '2026-10-01T03:00:00Z' }} />)
    expect(screen.getByRole('status')).toHaveTextContent('The newest good backup, unnamed, is from')
  })
})
