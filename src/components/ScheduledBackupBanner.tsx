import { AlertTriangle } from 'lucide-react'
import type { ScheduledBackupStatus } from '../api'
import { formatDateTime } from '../format'

/**
 * Warns that the daemon's latest scheduled backup failed, with its reason and
 * the newest good backup, which the failure leaves in the backup directory.
 * Renders nothing while scheduled backups are off or the latest one
 * succeeded.
 */
export function ScheduledBackupBanner({ backups }: { backups?: ScheduledBackupStatus }) {
  if (!backups || backups.consecutive_failures < 1) return null
  const failed = backups.consecutive_failures === 1 ? 'The latest scheduled backup failed' : `The last ${backups.consecutive_failures} scheduled backups failed`
  const when = backups.last_failure_at ? `, last at ${formatDateTime(backups.last_failure_at)}` : ''
  const reason = backups.last_error ? `: ${backups.last_error}` : ''
  const newest = backups.last_success_at ? `The newest good backup, ${backups.last_backup ?? 'unnamed'}, is from ${formatDateTime(backups.last_success_at)}.` : 'No scheduled backup has succeeded yet.'
  return <div className="legacy-banner" role="status">
    <AlertTriangle size={17} />
    <span><strong>Scheduled backups are failing.</strong> {failed}{when}{reason}. {newest} Check {backups.directory} on the EdgeWatch host; edgewatch health reports the same status.</span>
  </div>
}
