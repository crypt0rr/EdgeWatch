import { createPlatformNotification, deletePlatformNotification, listPlatformNotifications, togglePlatformNotificationUpdateAlert, updatePlatformNotification } from '../../api'
import { NotificationsView, type NotificationScope } from '../Notifications'

// The platform's own destinations. They receive the platform's copy of each
// application update alert, through the update routing chosen here; a unit's
// destinations belong to the unit and are never listed or selectable here.
const platformNotifications: NotificationScope = {
  queryKey: ['platform-notifications'],
  list: () => listPlatformNotifications(),
  create: (name, url, password, enabled) => createPlatformNotification(name, url, password, enabled),
  update: (id, revision, name, password, options) => updatePlatformNotification(id, revision, name, password, options),
  remove: (id, revision, password) => deletePlatformNotification(id, revision, password),
  toggleRouting: (destinationID, enabled, password) => togglePlatformNotificationUpdateAlert(destinationID, enabled, password),
  routingDefaultsToEnabled: false,
  configImport: false,
  eyebrow: 'Platform',
  description: 'The platform’s own Shoutrrr destinations. Each business unit manages its own destinations, which are not shown here.',
  listDescription: 'Destinations are identified by name and provider; their URLs are never shown again. Use each destination’s Update alerts toggle to choose where the platform’s application update alerts go. With none selected, the platform receives no update alerts.',
}

/** The platform administrator's notification destinations and update routing. */
export function PlatformNotifications() {
  return <NotificationsView scope={platformNotifications} canManage />
}
