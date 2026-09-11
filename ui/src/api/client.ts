// HTTP client:request 基础设施 + 按资源分组的 api 对象。

import { AuthError, getToken } from './auth'
import type { ProxySyncCursor, ProxyWriteResult } from './proxySync'
import type {
  BackendNode,
  BackendSubscription,
  PublicIpDiscovery,
  AutomationTemplate,
  AutomationImportRequest,
  AutomationImportResult,
  AutomationTemplateExport,
  AutomationTemplateTestResult,
  TargetGroup,
  TargetGroupExport,
  ListenerConfig,
  GatewayHaConfig,
  GatewayHaFailoverResult,
  GatewayHaPairRequest,
  GatewayHaPairResult,
  GatewayHaSaveResult,
  GatewayHaStatus,
  GatewayHaUnpairResult,
  GatewayNode,
  NotificationChannel,
  NotificationDelivery,
  NotificationList,
  PageQuery,
  PageResult,
  Status,
} from './types'
async function request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const res = await fetch(path, {
    method,
    signal,
    cache: 'no-store',
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await res.text()
  let data: unknown = text
  try {
    data = JSON.parse(text)
  } catch {
    /* keep as text */
  }
  if (!res.ok) {
    const msg =
      typeof data === 'object' && data !== null && 'error' in data
        ? String((data as { error: unknown }).error)
        : `${res.status} ${res.statusText}`
    if (res.status === 401) {
      throw new AuthError(msg)
    }
    throw new Error(msg)
  }
  return data as T
}

function withQuery(path: string, params?: PageQuery): string {
  if (!params) return path
  const query = new URLSearchParams()
  if (params.page !== undefined) query.set('page', String(params.page))
  if (params.per_page !== undefined) query.set('per_page', String(params.per_page))
  if (params.q) query.set('q', params.q)
  const value = query.toString()
  return value ? `${path}?${value}` : path
}

export const api = {
  proxyConfigSync: (signal?: AbortSignal) =>
    request<ProxySyncCursor>('GET', '/api/v1/ha/proxy-config-sync', undefined, signal),
  status: () => request<Status>('GET', '/api/v1/status'),
  targetGroupsPage: (params: PageQuery) =>
    request<PageResult<TargetGroup>>('GET', withQuery('/api/v1/target-groups', params)),
  exportTargetGroups: () => request<TargetGroupExport>('GET', '/api/v1/target-groups/export'),
  importTargetGroups: (payload: TargetGroupExport | TargetGroup[]) =>
    request<ProxyWriteResult<{ status: string; count: number }>>('POST', '/api/v1/target-groups/import', payload),
  createTargetGroup: (group: TargetGroup) => request<ProxyWriteResult<TargetGroup>>('POST', '/api/v1/target-groups', group),
  updateTargetGroup: (name: string, group: TargetGroup) =>
    request<ProxyWriteResult<TargetGroup>>('PUT', `/api/v1/target-groups/${encodeURIComponent(name)}`, group),
  deleteTargetGroup: (name: string) =>
    request<ProxyWriteResult<{ status: string; name: string }>>('DELETE', `/api/v1/target-groups/${encodeURIComponent(name)}`),
  listenerConfigsPage: (params: PageQuery) =>
    request<PageResult<ListenerConfig>>('GET', withQuery('/api/v1/listener-configs', params)),
  exportListenerConfigs: () => request<{ version: number; listeners: ListenerConfig[] }>('GET', '/api/v1/listener-configs/export'),
  importListenerConfigs: (payload: { version?: number; listeners: ListenerConfig[] } | ListenerConfig[]) =>
    request<ProxyWriteResult<{ status: string; count: number }>>('POST', '/api/v1/listener-configs/import', payload),
  createListenerConfig: (listener: ListenerConfig) =>
    request<ProxyWriteResult<ListenerConfig>>('POST', '/api/v1/listener-configs', listener),
  updateListenerConfig: (name: string, listener: ListenerConfig) =>
    request<ProxyWriteResult<ListenerConfig>>('PUT', `/api/v1/listener-configs/${encodeURIComponent(name)}`, listener),
  deleteListenerConfig: (name: string) =>
    request<ProxyWriteResult<{ status: string; name: string }>>('DELETE', `/api/v1/listener-configs/${encodeURIComponent(name)}`),
  gatewayNodes: () => request<GatewayNode[]>('GET', '/api/v1/nodes/gateways'),
  backendNodesPage: (params: PageQuery) =>
    request<PageResult<BackendNode>>('GET', withQuery('/api/v1/nodes/backends', params)),
  discoverPublicIp: () =>
    request<PublicIpDiscovery>('POST', '/api/v1/nodes/public-ip/discover'),
  backendSubscriptions: () =>
    request<Record<string, BackendSubscription>>('GET', '/api/v1/nodes/backend-subscriptions'),
  apply: () => request<{ status: string }>('POST', '/api/v1/operations/apply'),
  cleanup: () => request<{ status: string }>('POST', '/api/v1/operations/cleanup'),
  haFailover: (gateway: string) =>
    request<GatewayHaFailoverResult>('POST', '/api/v1/ha/failover', { gateway }),
  haConfig: () => request<GatewayHaConfig>('GET', '/api/v1/ha/config'),
  saveHaConfig: (cfg: GatewayHaConfig) => request<GatewayHaSaveResult>('PUT', '/api/v1/ha/config', cfg),
  pairHaGateway: (payload: GatewayHaPairRequest) => request<GatewayHaPairResult>('POST', '/api/v1/ha/pair', payload),
  unpairHaGateway: () => request<GatewayHaUnpairResult>('DELETE', '/api/v1/ha/pair'),
  haStatus: () => request<GatewayHaStatus>('GET', '/api/v1/ha/status'),
  notifications: () => request<NotificationList>('GET', '/api/v1/notifications'),
  notification: (id: string) =>
    request<NotificationChannel>('GET', `/api/v1/notifications/${encodeURIComponent(id)}`),
  saveNotification: (channel: NotificationChannel) =>
    request<ProxyWriteResult<NotificationChannel>>('POST', '/api/v1/notifications', channel),
  deleteNotification: (id: string) =>
    request<ProxyWriteResult<{ status: string; id: string }>>('DELETE', `/api/v1/notifications/${encodeURIComponent(id)}`),
  testNotification: (id: string) =>
    request<NotificationDelivery>('POST', `/api/v1/notifications/${encodeURIComponent(id)}/test`),
  automationTemplatesPage: (params: PageQuery) =>
    request<PageResult<AutomationTemplate>>('GET', withQuery('/api/v1/automations', params)),
  saveAutomationTemplate: (template: AutomationTemplate, oldName?: string) =>
    oldName
      ? request<ProxyWriteResult<AutomationTemplate>>(
          'PUT',
          `/api/v1/automations/${encodeURIComponent(oldName)}`,
          template,
        )
      : request<ProxyWriteResult<AutomationTemplate>>('POST', '/api/v1/automations', template),
  deleteAutomationTemplate: (name: string) =>
    request<ProxyWriteResult<{ status: string; name: string }>>(
      'DELETE',
      `/api/v1/automations/${encodeURIComponent(name)}`,
    ),
  testAutomationTemplate: (name: string, template?: AutomationTemplate) =>
    request<AutomationTemplateTestResult>(
      'POST',
      `/api/v1/automations/${encodeURIComponent(name)}/test`,
      template,
    ),
  exportAutomationTemplates: () =>
    request<AutomationTemplateExport>(
      'GET',
      '/api/v1/automations/export',
    ),
  importAutomationTemplates: (payload: AutomationImportRequest) =>
    request<AutomationImportResult>('POST', '/api/v1/automations/import', payload),
}
