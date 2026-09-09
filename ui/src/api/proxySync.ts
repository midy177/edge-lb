export interface ProxySyncVersion {
  sequence: number
  source: string
  pairing_id: string
  content_hash: string
}

export interface ProxySyncCursor extends ProxySyncVersion {
  pending: boolean
  last_error: string | null
}

export interface ProxyWriteAcceptance {
  state: 'accepted'
  authority: string
  authority_committed: true
  replica_confirmed: false
  barrier?: ProxySyncVersion
}

export type ProxyWriteResult<T> = T & { sync?: ProxyWriteAcceptance }

export function writeAcceptance(result: unknown): ProxyWriteAcceptance | null {
  if (!result || typeof result !== 'object' || !('sync' in result)) return null
  const sync = result.sync as Partial<ProxyWriteAcceptance> | null
  return sync?.state === 'accepted' && sync.authority_committed === true && typeof sync.authority === 'string'
    ? sync as ProxyWriteAcceptance : null
}

export type ProxySyncOutcome = 'waiting' | 'visible' | 'confirmed' | 'changed' | 'unconfirmed'

export function compareProxySync(expected: ProxySyncVersion, cursor: ProxySyncCursor, localNode: string): ProxySyncOutcome {
  // An empty replica has not received its first snapshot yet.
  if (!cursor.sequence && !cursor.pairing_id) return 'waiting'
  if (cursor.pairing_id !== expected.pairing_id) return 'changed'
  if (!Number.isSafeInteger(cursor.sequence) || !Number.isSafeInteger(expected.sequence)) return 'unconfirmed'
  if (cursor.sequence < expected.sequence) return 'waiting'
  if (cursor.sequence === expected.sequence &&
      (cursor.content_hash !== expected.content_hash || cursor.source !== expected.source)) return 'changed'
  if (cursor.source !== localNode) return 'visible'
  return cursor.pending ? 'waiting' : 'confirmed'
}

export async function waitForProxySync(
  expected: ProxySyncVersion,
  localNode: string,
  read: (signal: AbortSignal) => Promise<ProxySyncCursor>,
  signal: AbortSignal,
  options: { intervalMs?: number; timeoutMs?: number } = {},
): Promise<ProxySyncOutcome> {
  const deadline = AbortSignal.timeout(options.timeoutMs ?? 30_000)
  const combined = AbortSignal.any([signal, deadline])
  while (!combined.aborted) {
    try {
      const outcome = compareProxySync(expected, await read(combined), localNode)
      if (outcome !== 'waiting') return outcome
    } catch {
      // A status read failure says nothing about whether the write committed.
    }
    if (combined.aborted) break
    await new Promise<void>((resolve) => {
      const done = () => { clearTimeout(timer); combined.removeEventListener('abort', done); resolve() }
      const timer = setTimeout(done, options.intervalMs ?? 1000)
      combined.addEventListener('abort', done, { once: true })
    })
  }
  return 'unconfirmed'
}
