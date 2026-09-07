//! 纯校验与数值工具:无 Vue、无业务依赖,可单测。

export function isBlankNumber(value: unknown) {
  return value === null || value === undefined || value === ''
}

export function boundedInt(value: unknown, min: number, max: number) {
  const n = Number(value)
  return Number.isInteger(n) && n >= min && n <= max
}

export function optionalBoundedInt(value: unknown, min: number, max: number) {
  return isBlankNumber(value) || boundedInt(value, min, max)
}

export function requiredPort(value: unknown) {
  return boundedInt(value, 1, 65535)
}

export function optionalPort(value: unknown) {
  return optionalBoundedInt(value, 1, 65535)
}

export function optionalPositiveInt(value: unknown) {
  return optionalBoundedInt(value, 1, 65535)
}

export function numberOrDefault(value: unknown, fallback: number) {
  return isBlankNumber(value) ? fallback : Number(value)
}

export function isIPv4(value: string) {
  const parts = value.split('.')
  return (
    parts.length === 4 &&
    parts.every(
      (part) =>
        /^\d{1,3}$/.test(part) && (part === '0' || !part.startsWith('0')) && Number(part) <= 255,
    )
  )
}
