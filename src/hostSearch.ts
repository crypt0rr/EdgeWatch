export const MIN_HOST_SEARCH_RUNES = 3
export const MAX_HOST_SEARCH_RUNES = 256

export function hostSearchValidationMessage(value: string): string | null {
  const query = value.trim()
  if (!query) return null
  const length = Array.from(query).length
  if (length < MIN_HOST_SEARCH_RUNES) return 'Type at least 3 characters to search.'
  if (length > MAX_HOST_SEARCH_RUNES) return 'Search is limited to 256 characters.'
  return null
}
