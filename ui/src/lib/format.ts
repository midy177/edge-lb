//! 通用格式化:时间、发现方式文本。

export function formatTime(value?: number | null) {
  if (!value) return '—'
  return new Date(value * 1000).toLocaleString()
}

export function formatDiscovery(mode?: string | null, source?: string | null) {
  const parts = [mode, source].map((part) => String(part ?? '').trim()).filter(Boolean)
  return parts.length ? parts.join(' / ') : '—'
}

export function valueText(value: unknown) {
  if (value === null || value === undefined || value === '') return '—'
  return String(value)
}

export function boolText(value?: boolean | null) {
  return value ? 'true' : 'false'
}

export function unknownItems(value: unknown) {
  if (value === null || value === undefined) return []
  const items = Array.isArray(value) ? value : [value]
  return items.map((item) => {
    if (item === null || item === undefined) return '—'
    if (typeof item !== 'object') return String(item)
    const entries = Object.entries(item as Record<string, unknown>)
      .map(([key, val]) => `${key}=${valueText(val)}`)
    return entries.length ? entries.join(', ') : '—'
  })
}
