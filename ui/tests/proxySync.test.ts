import { describe, expect, test } from 'bun:test'
import { compareProxySync, waitForProxySync, writeAcceptance, type ProxySyncCursor } from '../src/api/proxySync'

const version = { sequence: 7, source: 'gateway-a', pairing_id: 'pair-1', content_hash: 'hash-7' }
const cursor: ProxySyncCursor = { ...version, pending: false, last_error: null }

describe('HA write visibility barrier', () => {
  test('only explicit committed acceptance starts tracking', () => {
    expect(writeAcceptance({ name: 'tcp-80' })).toBeNull()
    expect(writeAcceptance({ sync: { state: 'accepted', authority_committed: false } })).toBeNull()
    expect(writeAcceptance({ sync: { state: 'accepted', authority: 'gateway-a', authority_committed: true } })?.authority).toBe('gateway-a')
  })

  test('pending=false on an older or empty replica is not confirmation', () => {
    expect(compareProxySync(version, { ...cursor, sequence: 6 }, 'gateway-b')).toBe('waiting')
    expect(compareProxySync(version, { ...cursor, sequence: 0, pairing_id: '' }, 'gateway-b')).toBe('waiting')
  })

  test('backup visibility is distinct from master receipt confirmation', () => {
    expect(compareProxySync(version, cursor, 'gateway-b')).toBe('visible')
    expect(compareProxySync(version, { ...cursor, pending: true }, 'gateway-a')).toBe('waiting')
    expect(compareProxySync(version, cursor, 'gateway-a')).toBe('confirmed')
  })

  test('newer version can satisfy the barrier but other pair or equal-version conflict cannot', () => {
    expect(compareProxySync(version, { ...cursor, sequence: 8, content_hash: 'hash-8' }, 'gateway-b')).toBe('visible')
    expect(compareProxySync(version, { ...cursor, pairing_id: 'pair-2' }, 'gateway-b')).toBe('changed')
    expect(compareProxySync(version, { ...cursor, content_hash: 'wrong' }, 'gateway-b')).toBe('changed')
    expect(compareProxySync(version, { ...cursor, source: 'other' }, 'gateway-b')).toBe('changed')
    expect(compareProxySync(version, { ...cursor, sequence: Number.MAX_SAFE_INTEGER + 1 }, 'gateway-b')).toBe('unconfirmed')
  })

  test('polls through transient read failure and older cursor without retrying the write', async () => {
    let reads = 0
    const result = await waitForProxySync(version, 'gateway-b', async () => {
      reads++
      if (reads === 1) throw new Error('offline')
      return { ...cursor, sequence: reads === 2 ? 6 : 7 }
    }, new AbortController().signal, { intervalMs: 1, timeoutMs: 1000 })
    expect(result).toBe('visible')
    expect(reads).toBe(3)
  })

  test('deadline aborts an in-flight status read', async () => {
    let aborted = false
    const result = await waitForProxySync(version, 'gateway-b', (signal) => new Promise((_, reject) => {
      signal.addEventListener('abort', () => { aborted = true; reject(new Error('aborted')) }, { once: true })
    }), new AbortController().signal, { timeoutMs: 10 })
    expect(result).toBe('unconfirmed')
    expect(aborted).toBe(true)
  })

  test('cancellation stops polling', async () => {
    const controller = new AbortController()
    controller.abort()
    let reads = 0
    expect(await waitForProxySync(version, 'gateway-b', async () => { reads++; return cursor }, controller.signal)).toBe('unconfirmed')
    expect(reads).toBe(0)
  })
})
