import { afterAll, beforeEach, describe, expect, spyOn, test } from 'bun:test'
import type { Status, TargetGroup, ListenerConfig } from '../src/api/types'
import type { ProxySyncCursor } from '../src/api/proxySync'

// The data composable only needs storage and hash routing, not a DOM renderer.
const savedGlobals = {
  window: globalThis.window,
  localStorage: globalThis.localStorage,
  sessionStorage: globalThis.sessionStorage,
}
function storage() {
  const values = new Map<string, string>()
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value) },
    removeItem: (key: string) => { values.delete(key) },
  } as Storage
}
Object.assign(globalThis, {
  window: {
    location: { hash: '', pathname: '/', search: '' },
    history: { replaceState() {} },
    addEventListener() {},
  },
  localStorage: storage(),
  sessionStorage: storage(),
})

const { api, AuthError } = await import('../src/api')
const { run, busy, error, tab, cancelProxySync, proxyWriteStatus, logout, targetGroups, listeners, authenticated } = await import('../src/composables/useNodeData')
const { listenerForm, listenerFormOpen, submitListener, resetListenerForm } = await import('../src/components/listeners/listenerForm')
const refresh = spyOn(api, 'status')
const sync = spyOn(api, 'proxyConfigSync')
const createListener = spyOn(api, 'createListenerConfig')
const readListeners = spyOn(api, 'listenerConfigs')
const readGroups = spyOn(api, 'targetGroups')
const readNodes = spyOn(api, 'backendNodes')
const version = { sequence: 7, source: 'gateway-a', pairing_id: 'pair-1', content_hash: 'hash-7' }
const accepted = { sync: { state: 'accepted', authority: 'gateway-a', authority_committed: true, replica_confirmed: false, barrier: version } }

beforeEach(() => {
  cancelProxySync()
  busy.value = ''
  error.value = ''
  tab.value = 'overview'
  refresh.mockReset()
  refresh.mockResolvedValue({ node_role: 'backend' } as Status)
  sync.mockReset()
  createListener.mockReset()
  readListeners.mockReset().mockResolvedValue([])
  readGroups.mockReset().mockResolvedValue([])
  readNodes.mockReset().mockResolvedValue([])
})
afterAll(() => {
  cancelProxySync()
  sync.mockRestore()
  createListener.mockRestore()
  readListeners.mockRestore()
  readGroups.mockRestore()
  readNodes.mockRestore()
  refresh.mockRestore()
  Object.assign(globalThis, savedGlobals)
})

describe('command result used by save dialogs', () => {
  test('failed writes report failure without refreshing or closing the editor', async () => {
    let open = true
    const saved = await run('save', async () => { throw new Error('write rejected') })
    if (saved) open = false
    expect(saved).toBe(false)
    expect(open).toBe(true)
    expect(error.value).toBe('write rejected')
    expect(busy.value).toBe('')
    expect(refresh).not.toHaveBeenCalled()
  })

  test('successful writes report success and refresh once', async () => {
    expect(await run('save', async () => {})).toBe(true)
    expect(refresh).toHaveBeenCalledTimes(1)
    expect(error.value).toBe('')
    expect(busy.value).toBe('')
  })

  test('refresh failure does not turn a committed write into a failed write', async () => {
    refresh.mockRejectedValue(new Error('refresh unavailable'))
    expect(await run('save', async () => {})).toBe(true)
    expect(error.value).toBe('refresh unavailable')
    expect(busy.value).toBe('')
  })

  test('accepted writes return success immediately, then refresh when this backup receives the version', async () => {
    tab.value = 'listeners'
    refresh.mockResolvedValue({ node_role: 'gateway', node_name: 'gateway-b' } as Status)
    const listener = { name: 'tcp-80', port: 80, protocols: ['tcp'] } as ListenerConfig
    readListeners.mockResolvedValueOnce([]).mockResolvedValue([listener])
    let receive!: (value: ProxySyncCursor) => void
    sync.mockImplementation(() => new Promise((resolve) => { receive = resolve }))
    expect(await run('save', async () => accepted)).toBe(true)
    expect(proxyWriteStatus.value?.state).toBe('waiting')
    expect(busy.value).toBe('')
    expect(listeners.value).toEqual([])
    receive({ ...version, pending: false, last_error: null })
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(proxyWriteStatus.value?.state).toBe('visible')
    expect(listeners.value).toEqual([listener])
    expect(readListeners).toHaveBeenCalledTimes(2)
    expect(refresh).toHaveBeenCalledTimes(1)
  })

  test('logout aborts status polling and ignores the late response', async () => {
    refresh.mockResolvedValue({ node_role: 'backend', node_name: 'gateway-b' } as Status)
    let signal!: AbortSignal
    let receive!: (value: ProxySyncCursor) => void
    sync.mockImplementation((s) => { signal = s!; return new Promise((resolve) => { receive = resolve }) })
    expect(await run('save', async () => accepted)).toBe(true)
    logout()
    expect(signal.aborted).toBe(true)
    receive({ ...version, pending: false, last_error: null })
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(proxyWriteStatus.value).toBeNull()
  })

  test('acceptance without a barrier remains committed but unconfirmed', async () => {
    const response = { sync: { ...accepted.sync, barrier: undefined } }
    expect(await run('save', async () => response)).toBe(true)
    expect(proxyWriteStatus.value?.state).toBe('unconfirmed')
    expect(sync).not.toHaveBeenCalled()
  })

  test('authentication failure stops tracking without reporting write failure', async () => {
    refresh.mockResolvedValue({ node_role: 'backend', node_name: 'gateway-b' } as Status)
    sync.mockRejectedValue(new AuthError('token revoked'))
    expect(await run('save', async () => accepted)).toBe(true)
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(authenticated.value).toBe(false)
    expect(proxyWriteStatus.value).toBeNull()
    expect(sync).toHaveBeenCalledTimes(1)
  })

  test('a later accepted write cancels earlier polling and ignores its response', async () => {
    refresh.mockResolvedValue({ node_role: 'backend', node_name: 'gateway-b' } as Status)
    const requests: { signal: AbortSignal; resolve: (value: ProxySyncCursor) => void }[] = []
    sync.mockImplementation((signal) => new Promise((resolve) => { requests.push({ signal: signal!, resolve }) }))
    await run('save', async () => accepted)
    await run('save', async () => ({ sync: { ...accepted.sync, barrier: { ...version, sequence: 8 } } }))
    expect(requests[0]!.signal.aborted).toBe(true)
    requests[0]!.resolve({ ...version, pending: false, last_error: null })
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(proxyWriteStatus.value?.state).toBe('waiting')
    requests[1]!.resolve({ ...version, sequence: 8, pending: false, last_error: null })
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(proxyWriteStatus.value?.state).toBe('visible')
  })

  test('logout while the write is in flight cannot restart polling or refresh', async () => {
    let accept!: (value: unknown) => void
    const result = run('save', () => new Promise((resolve) => { accept = resolve }))
    logout()
    accept(accepted)
    expect(await result).toBe(true)
    expect(sync).not.toHaveBeenCalled()
    expect(refresh).not.toHaveBeenCalled()
    expect(proxyWriteStatus.value).toBeNull()
  })

  test('listener validation/write failure preserves the editor and input', async () => {
    resetListenerForm()
    targetGroups.value = [{ name: 'web', targets: [] } as unknown as TargetGroup]
    Object.assign(listenerForm, { port: 80, target_port: 8080, target_group: 'web' })
    listenerFormOpen.value = true
    createListener.mockRejectedValue(new Error('write rejected'))
    await submitListener()
    expect(createListener).toHaveBeenCalledTimes(1)
    expect(listenerFormOpen.value).toBe(true)
    expect(listenerForm.port).toBe(80)
    expect(error.value).toBe('write rejected')
    createListener.mockResolvedValue({} as never)
    await submitListener()
    expect(listenerFormOpen.value).toBe(false)
    expect(listenerForm.port).toBe('')
  })
})
