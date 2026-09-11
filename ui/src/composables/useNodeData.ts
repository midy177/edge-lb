//! 共享数据状态(模块级单例)与加载逻辑:status/nodes/listeners 等
//! 所有页面组件直接 import;不渲染 UI。`run` 是操作包装(busy + 刷新)。

import { computed, reactive, ref, watch } from 'vue'
import { AuthError, api, clearToken, getToken, setToken } from '@/api'
import type {
  BackendNode,
  BackendSubscription,
  AutomationTemplate,
  GatewayHaConfig,
  GatewayHaStatus,
  GatewayNode,
  ListenerConfig,
  NotificationChannelSummary,
  NotificationList,
  Status,
  TargetGroup,
} from '@/api/types'
import { t } from '@/lib/i18n'
import { waitForProxySync, writeAcceptance, type ProxyWriteAcceptance, type ProxySyncOutcome } from '@/api/proxySync'

export type Tab =
  | 'overview'
  | 'nodes'
  | 'target-groups'
  | 'listeners'
  | 'automations'
  | 'ha'
  | 'notifications'

const TABS: Tab[] = [
  'overview',
  'nodes',
  'target-groups',
  'listeners',
  'automations',
  'ha',
  'notifications',
]

export const tab = ref<Tab>('overview')

// ---- hash 路由(tab ↔ location.hash 双向同步)----
// 平级 tab 的嵌入式面板不需要 vue-router:hash 片段不经过服务端,刷新/
// 分享/浏览器后退都能恢复到对应页面。手写同步保持零依赖。
function tabFromHash(): Tab | null {
  const value = window.location.hash.replace(/^#\/?/, '').split(/[/?#]/)[0] as Tab
  return TABS.includes(value) ? value : null
}

// 登录 gate 阶段模块加载即执行:先恢复 hash 中的 tab,再监听双向变化。
const initialTab = tabFromHash()
if (initialTab) {
  tab.value = initialTab
} else if (window.location.hash) {
  // 非法 hash 清理,避免 URL 与实际页面不一致。
  window.history.replaceState(null, '', window.location.pathname + window.location.search)
}

window.addEventListener('hashchange', () => {
  const next = tabFromHash()
  if (next && next !== tab.value) {
    tab.value = next
  }
})

watch(tab, (next) => {
  const target = `#/${next}`
  if (window.location.hash !== target) {
    window.location.hash = target
  }
})

export const failoverTarget = ref('')

export const status = ref<Status | null>(null)
export const targetGroups = ref<TargetGroup[]>([])
export const listeners = ref<ListenerConfig[]>([])
export const gatewayNodes = ref<GatewayNode[]>([])
export const backendNodes = ref<BackendNode[]>([])
export const targetGroupPage = reactive(pageState<TargetGroup>())
export const targetGroupOptionPage = reactive(pageState<TargetGroup>())
export const listenerPage = reactive(pageState<ListenerConfig>())
export const backendNodePage = reactive(pageState<BackendNode>())
export const automationTemplatePage = reactive(pageState<AutomationTemplate>())
export const backendSubscriptions = ref<Record<string, BackendSubscription>>({})
export const haConfig = ref<GatewayHaConfig | null>(null)
export const haStatus = ref<GatewayHaStatus | null>(null)
export const notifications = ref<NotificationChannelSummary[]>([])
export const notificationEvents = ref<string[]>([])
export const automationsError = ref('')
export const notificationsError = ref('')
export const haStatusError = ref('')
export const backendSubscriptionsError = ref('')
export const error = ref('')
export const authRequired = ref(false)
export const authenticated = ref(false)
export const busy = ref('')
export const token = ref(getToken())
export const proxyWriteStatus = ref<{ authority: string; state: ProxySyncOutcome } | null>(null)
let proxySyncController: AbortController | null = null
let pendingAcceptance: ProxyWriteAcceptance | null = null
let dataSession = 0

function pageState<T>() {
  return {
    items: [] as T[],
    total: 0,
    page: 1,
    per_page: 20,
    q: '',
  }
}

function pageParams(state: { page: number; per_page: number; q: string }) {
  return {
    page: state.page,
    per_page: state.per_page,
    q: state.q.trim() || undefined,
  }
}

function applyPage<T>(
  state: { items: T[]; total: number; page: number; per_page: number; q: string },
  value: { items: T[]; total: number; page: number; per_page: number },
) {
  state.items = value.items
  state.total = value.total
  state.page = value.page
  state.per_page = value.per_page
}

export function cancelProxySync() {
  proxySyncController?.abort()
  proxySyncController = null
  pendingAcceptance = null
  proxyWriteStatus.value = null
}

export function retryProxySync() {
  const acceptance = pendingAcceptance
  if (!acceptance) return
  proxySyncController?.abort()
  const controller = new AbortController()
  proxySyncController = controller
  const localName = status.value?.node_name
  if (!acceptance.barrier || !localName) {
    proxyWriteStatus.value = { authority: acceptance.authority, state: 'unconfirmed' }
    return
  }
  proxyWriteStatus.value = { authority: acceptance.authority, state: 'waiting' }
  const read = async (signal: AbortSignal) => {
    try {
      return await api.proxyConfigSync(signal)
    } catch (e) {
      if (e instanceof AuthError && !signal.aborted) {
        authRequired.value = true
        authenticated.value = false
        status.value = null
        cancelProxySync()
      }
      throw e
    }
  }
  void waitForProxySync(acceptance.barrier, localName, read, controller.signal)
    .then(async (state) => {
      if (controller.signal.aborted) return
      proxyWriteStatus.value = { authority: acceptance.authority, state }
      if (state === 'visible' || state === 'confirmed') await refreshForTab(tab.value)
    })
}

watch(authenticated, (value) => {
  if (!value) {
    dataSession++
    cancelProxySync()
  }
}, { flush: 'sync' })

export const isGateway = computed(() => status.value?.node_role === 'gateway')

export const localNode = computed(() => {
  const current = status.value
  if (!current) return null
  return {
    name: current.node_name,
    public_ip: current.public_ip,
    underlay_ip: current.underlay_ip,
    overlay_ip: current.overlay_ip,
  }
})

export const activeGatewayNode = computed(() => {
  const current = status.value
  if (!current?.active_gateway) return null
  return gatewayNodes.value.find((node) => node.name === current.active_gateway) ?? null
})

export const backendRegistrations = computed(() =>
  Object.entries(backendSubscriptions.value).sort(([a], [b]) => a.localeCompare(b)),
)

export async function refreshTabData(currentTab: Tab) {
  if (!status.value) return
  switch (currentTab) {
    case 'overview':
      await refreshOverviewData()
      break
    case 'nodes':
      await refreshNodeData()
      break
    case 'target-groups':
      await refreshTargetGroupData()
      break
    case 'listeners':
      await refreshListenerData()
      break
    case 'automations':
      await refreshAutomationData()
      break
    case 'ha':
      await refreshHaData()
      break
    case 'notifications':
      await refreshNotificationData()
      break
  }
}

export async function refreshOverviewData() {
  if (!isGateway.value) return
  await Promise.all([refreshGatewayNodes(), refreshSubscriptions()])
}

export async function refreshNodeData() {
  await Promise.all([refreshBackendNodes(), refreshBackendNodePage(), refreshSubscriptions()])
}

export async function refreshTargetGroupData() {
  await Promise.all([refreshBackendNodes(), refreshTargetGroups(), refreshTargetGroupPage()])
}

export async function refreshListenerData() {
  await Promise.all([
    refreshBackendNodes(),
    refreshTargetGroups(),
    refreshTargetGroupOptions(),
    refreshListeners(),
    refreshListenerPage(),
  ])
}

export async function refreshGatewayNodes() {
  gatewayNodes.value = await api.gatewayNodes()
}

export async function refreshBackendNodes() {
  const session = dataSession
  const value = await api.backendNodesPage({ page: 1, per_page: 200 })
  if (session === dataSession) backendNodes.value = value.items
}

export async function refreshBackendNodePage() {
  const session = dataSession
  const value = await api.backendNodesPage(pageParams(backendNodePage))
  if (session !== dataSession) return
  applyPage(backendNodePage, value)
}

export async function refreshTargetGroups() {
  const session = dataSession
  const value = await api.targetGroupsPage({ page: 1, per_page: 200 })
  if (session === dataSession) targetGroups.value = value.items
}

export async function refreshTargetGroupPage() {
  const session = dataSession
  const value = await api.targetGroupsPage(pageParams(targetGroupPage))
  if (session === dataSession) applyPage(targetGroupPage, value)
}

export async function refreshTargetGroupOptions() {
  const session = dataSession
  const value = await api.targetGroupsPage(pageParams(targetGroupOptionPage))
  if (session === dataSession) applyPage(targetGroupOptionPage, value)
}

export async function refreshListeners() {
  const session = dataSession
  const value = await api.listenerConfigsPage({ page: 1, per_page: 200 })
  if (session === dataSession) listeners.value = value.items
}

export async function refreshListenerPage() {
  const session = dataSession
  const value = await api.listenerConfigsPage(pageParams(listenerPage))
  if (session === dataSession) applyPage(listenerPage, value)
}

export async function refreshSubscriptions() {
  backendSubscriptionsError.value = ''
  try {
    backendSubscriptions.value = await api.backendSubscriptions()
  } catch (e) {
    backendSubscriptionsError.value = e instanceof Error ? e.message : String(e)
    backendSubscriptions.value = {}
  }
}

export async function refreshHaData() {
  haStatusError.value = ''
  if (!isGateway.value) {
    haConfig.value = null
    haStatus.value = null
    return
  }
  try {
    const [config, currentStatus, gateways] = await Promise.all([
      api.haConfig(),
      api.haStatus(),
      api.gatewayNodes(),
    ])
    haConfig.value = config
    haStatus.value = currentStatus
    gatewayNodes.value = gateways
  } catch (e) {
    haStatusError.value = e instanceof Error ? e.message : String(e)
  }
}

export async function refreshNotificationData() {
  notificationsError.value = ''
  if (!isGateway.value) {
    notifications.value = []
    notificationEvents.value = []
    return
  }
  try {
    const result: NotificationList = await api.notifications()
    notifications.value = result.channels
    notificationEvents.value = result.events
  } catch (e) {
    notificationsError.value = e instanceof Error ? e.message : String(e)
  }
}

export async function refreshAutomationData() {
  automationsError.value = ''
  if (!isGateway.value) {
    automationTemplatePage.items = []
    automationTemplatePage.total = 0
    return
  }
  try {
    const [page] = await Promise.all([
      api.automationTemplatesPage(pageParams(automationTemplatePage)),
      refreshBackendNodes(),
    ])
    applyPage(automationTemplatePage, page)
  } catch (e) {
    automationsError.value = e instanceof Error ? e.message : String(e)
    automationTemplatePage.items = []
    automationTemplatePage.total = 0
  }
}

export async function refreshAutomationPage() {
  const session = dataSession
  automationsError.value = ''
  if (!isGateway.value) {
    automationTemplatePage.items = []
    automationTemplatePage.total = 0
    return
  }
  try {
    const value = await api.automationTemplatesPage(pageParams(automationTemplatePage))
    if (session === dataSession) applyPage(automationTemplatePage, value)
  } catch (e) {
    if (session === dataSession) {
      automationsError.value = e instanceof Error ? e.message : String(e)
      automationTemplatePage.items = []
      automationTemplatePage.total = 0
    }
  }
}

export async function run(label: string, fn: () => Promise<unknown>): Promise<boolean> {
  const session = dataSession
  busy.value = label
  error.value = ''
  try {
    const result = await fn()
    if (session !== dataSession) return true
    await refreshAll(tab.value)
    const acceptance = writeAcceptance(result)
    if (acceptance && session === dataSession) {
      pendingAcceptance = acceptance
      retryProxySync()
    }
    return true
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
    return false
  } finally {
    busy.value = ''
  }
}

export async function login() {
  setToken(token.value)
  await refreshAll(tab.value)
  if (!authenticated.value) {
    throw new Error(t('tokenInvalid'))
  }
}

export function logout() {
  dataSession++
  cancelProxySync()
  clearToken()
  token.value = ''
  authenticated.value = false
  authRequired.value = true
  status.value = null
  listeners.value = []
  targetGroups.value = []
  listenerPage.items = []
  targetGroupPage.items = []
  targetGroupOptionPage.items = []
  backendNodePage.items = []
  automationTemplatePage.items = []
}

//! 切 tab 时只刷新当前页需要的数据;status 已加载则复用,不重复拉取。
//! 首次加载(status 为空)或认证失效时退回完整 refreshAll。
export async function refreshForTab(currentTab: Tab) {
  const session = dataSession
  if (!status.value) {
    await refreshAll(currentTab)
    return
  }
  try {
    await refreshTabData(currentTab)
    if (session !== dataSession) return
    error.value = ''
  } catch (e) {
    if (session !== dataSession) return
    if (e instanceof AuthError) {
      authRequired.value = true
      authenticated.value = false
      status.value = null
      error.value = ''
    } else {
      error.value = e instanceof Error ? e.message : String(e)
    }
  }
}

//! 拉取 status 并按当前 tab 刷新;认证/错误状态在此收敛。
//! 页面局部副作用(表单默认值回填等)由调用方的包装 refresh 处理。
export async function refreshAll(currentTab: Tab) {
  const session = dataSession
  try {
    const currentStatus = await api.status()
    if (session !== dataSession) return
    status.value = currentStatus
    await refreshTabData(currentTab)
    if (session !== dataSession) return
    error.value = ''
    authRequired.value = false
    authenticated.value = true
  } catch (e) {
    if (session !== dataSession) return
    if (e instanceof AuthError) {
      authRequired.value = true
      authenticated.value = false
      status.value = null
      error.value = ''
    } else {
      error.value = e instanceof Error ? e.message : String(e)
    }
  }
}
