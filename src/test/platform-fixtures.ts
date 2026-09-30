import type { BusinessUnit, DeploymentLimits, SessionUser, UnitAccount, UnitCapacity } from '../api'

// Fixtures for the business units console tests, shaped like the platform
// API's responses.

export const deploymentLimits: DeploymentLimits = { max_concurrent_scans: 4, max_probe_count: 5_000_000, max_naabu_probe_count: 20_000_000, max_probe_count_limit: 100_000_000 }

export const platformPermissions = ['account.self', 'platform_audit.read', 'platform_notifications.manage', 'platform_status.read', 'unit_accounts.manage', 'units.manage']

export function businessUnit(overrides: Partial<BusinessUnit> = {}): BusinessUnit {
  return { id: 'unit-retail', name: 'Retail', slug: 'retail', status: 'active', is_default: false, revision: 3, created_at: '2026-08-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z', state_changed_at: '2026-08-01T00:00:00Z', accounts: 5, administrators: 2, jobs: 7, stored_scans: 1234, slots: { in_use: 1, queued: 2 }, ...overrides }
}

export function unitAccount(overrides: Partial<UnitAccount> & Pick<UnitAccount, 'id' | 'username' | 'role'>): UnitAccount {
  return { display_name: overrides.username, enabled: true, pending: false, totp_enabled: false, created_at: '2026-08-01T00:00:00Z', updated_at: '2026-08-01T00:00:00Z', revision: 1, ...overrides }
}

export function unitCapacity(overrides: Partial<UnitCapacity> = {}): UnitCapacity {
  return { unit_id: 'unit-retail', revision: 3, capacity: { max_concurrent_scans: 2, max_probe_count: null, max_naabu_probe_count: 1_000_000, high_cost_ceiling: 1_000_000 }, limits: deploymentLimits, slots: { in_use: 1, queued: 2, limit: 2 }, ...overrides }
}

export function platformSession(overrides: Partial<SessionUser> = {}): SessionUser {
  return { user_id: 'acct-morgan', username: 'morgan', display_name: 'Morgan Reyes', role: 'platform_admin', permissions: platformPermissions, csrf_token: 'csrf', totp_enabled: true, password_requirements: { minimum_length: 12 }, scope: 'platform', unit: null, multi_unit: true, ...overrides }
}
