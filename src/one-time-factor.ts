/** Remove grouping whitespace from an authenticator or recovery factor. */
export function compactFactor(value: string) {
  return value.replace(/\s+/gu, '')
}

/** Recovery codes are case-insensitive and are displayed without grouping. */
export function normalizeRecoveryCode(value: string) {
  return compactFactor(value).toUpperCase()
}

/** Format the API payload shared by TOTP confirmation and recovery flows. */
export function factorPayload(value: string) {
  const code = compactFactor(value)
  return /^\d{6}$/.test(code)
    ? { code, recovery_code: '' }
    : { code: '', recovery_code: normalizeRecoveryCode(value) }
}
