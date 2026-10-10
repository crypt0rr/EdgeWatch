import { createPlatformNotification, deletePlatformNotification, listPlatformNotifications, togglePlatformDeploymentAlert, togglePlatformNotificationUpdateAlert, togglePlatformSecurityAlert, updatePlatformNotification } from '../../api'
import { NotificationsView, type NotificationScope } from '../Notifications'

// The platform's own destinations. They receive the platform's copy of each
// application update alert, the platform's security alerts, and the
// deployment-health alerts, through the routings chosen here; a unit's
// destinations belong to the unit and are never listed or selectable here.
const platformNotifications: NotificationScope = {
  queryKey: ['platform-notifications'],
  list: () => listPlatformNotifications(),
  create: (name, url, password, enabled) => createPlatformNotification(name, url, password, enabled),
  update: (id, revision, name, password, options) => updatePlatformNotification(id, revision, name, password, options),
  remove: (id, revision, password) => deletePlatformNotification(id, revision, password),
  toggleRouting: (destinationID, enabled, password) => togglePlatformNotificationUpdateAlert(destinationID, enabled, password),
  alertRoutings: [
    { field: 'security_routing', label: 'Security alerts', description: 'rate-limited sign-ins, second-factor lockouts, and recovery-code sign-ins of platform administrators and of usernames that no account has', toggle: (destinationID, enabled, password) => togglePlatformSecurityAlert(destinationID, enabled, password) },
    { field: 'health_routing', label: 'Deployment alerts', description: 'sandbox degradation, version rollbacks, and alerts that failed for good', toggle: (destinationID, enabled, password) => togglePlatformDeploymentAlert(destinationID, enabled, password) },
  ],
  routingDefaultsToAllDestinations: false,
  configImport: false,
  eyebrow: 'Platform',
  description: 'The platform’s own Shoutrrr destinations. Each business unit manages its own destinations, which are not shown here.',
  listDescription: 'Destinations are identified by name and provider; their URLs are never shown again. Use each destination’s toggles to choose where the platform’s update alerts, security alerts, and deployment alerts go. With none selected, the platform receives none of them.',
}

/** The platform administrator's notification destinations and their alert routing. */
export function PlatformNotifications() {
  return <NotificationsView scope={platformNotifications} canManage />
}
