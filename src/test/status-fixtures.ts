import type { ApplicationUpdateStatus, ScannerSandboxStatus } from '../generated/api-types'

// Fixtures for the status responses, shaped as the server writes them.

/** The update status of a development build. Every status carries one. */
export const developmentBuildUpdates: ApplicationUpdateStatus = { available: false, current_version: 'dev', enabled: true, stale: false, status: 'development_build' }

/** An update status with the given fields; the others are a development build's. */
export const updateStatus = (fields: Partial<ApplicationUpdateStatus>): ApplicationUpdateStatus => ({ ...developmentBuildUpdates, ...fields })

/**
 * A sandbox status without the Landlock or seccomp layer. The server always
 * reports both, but the console leaves out a layer that a daemon does not
 * report, and these fixtures test that.
 */
export const sandboxWithoutLayers = (status: Omit<ScannerSandboxStatus, 'landlock' | 'seccomp'> & Partial<Pick<ScannerSandboxStatus, 'landlock' | 'seccomp'>>) => status as ScannerSandboxStatus
