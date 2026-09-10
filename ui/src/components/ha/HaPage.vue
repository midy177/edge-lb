<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Loader2, Save, ShieldAlert, Trash2 } from 'lucide-vue-next'
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Label,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui'
import { api } from '@/api'
import type { GatewayHaConfig, GatewayHaPeer } from '@/api/types'
import {
  busy,
  failoverTarget,
  gatewayNodes,
  haConfig,
  haStatus,
  haStatusError,
  localNode,
  refreshHaData,
  run,
} from '@/composables/useNodeData'
import { t as text } from '@/lib/i18n'

const form = ref<GatewayHaConfig>(defaultConfig())
const saveResult = ref('')
const failoverResult = ref('')
const failoverArmed = ref(false)
const pairEndpoint = ref('')
const pairToken = ref('')
const pairResult = ref('')
const unpairArmed = ref(false)
const managedHookPaths = {
  promote: '/usr/local/bin/edge-lb-promote',
  demote: '/usr/local/bin/edge-lb-demote',
  verify: '/usr/local/bin/edge-lb-verify-vip',
}

watch(
  haConfig,
  (value) => {
    if (value) {
      form.value = cloneConfig(value)
      saveResult.value = ''
    }
  },
  { immediate: true },
)

const ciStateRows = computed(() => {
  const native = haStatus.value?.native
  if (!native) return []
  return [{
    instance: native.node || 'edge-lb',
    state: native.state,
    vip: form.value.vip.private_vip || '-',
    sync: haStatus.value?.xsync?.state || '-',
  }]
})
const bfdRows = computed(() => {
  const value = haStatus.value?.bfd
  if (!value) return []
  return [{
    instance: 'edge-lb',
    remoteIp: value.peer_ip || '-',
    sourceIP: value.source_ip || '-',
    state: value.state,
  }]
})
const ciStateCount = computed(() => haStatus.value?.native.state || '-')
const bfdCount = computed(() => haStatus.value?.bfd?.state || '-')
const conntrackCount = computed(() => haStatus.value?.xsync?.state || '-')
const ciStateError = computed(() => '')
const bfdError = computed(() => haStatus.value?.bfd?.last_error || '')
const conntrackError = computed(() => '')
const sessionToken = computed(() => haStatus.value?.session_token)
const peerLimitError = computed(() => (form.value.peers.length > 1 ? text('haSinglePeerLimit') : ''))
const peerRequiredError = computed(() => (form.value.enabled && form.value.peers.length !== 1 ? text('haSinglePeerRequired') : ''))
const garpError = computed(() => {
  if (form.value.vip.provider !== 'l2') return ''
  const garp = form.value.vip.garp
  if (garp.count < 1 || garp.interval_ms < 1 || garp.interval_ms > 60000) return text('haGarpRange')
  if (garp.repeat_after_ms < 0 || garp.repeat_after_ms > 60000) return text('haGarpRange')
  if (garp.repeat_count < 0 || garp.repeat_count > 10) return text('haGarpRange')
  return ''
})
const haFormError = computed(
  () => peerLimitError.value || peerRequiredError.value || garpError.value,
)
const failoverGatewayNodes = computed(() => {
  const nodes = new Map<string, { name: string; underlay_ip: string }>()
  for (const node of gatewayNodes.value) {
    nodes.set(node.name, node)
  }
  if (localNode.value?.name && !nodes.has(localNode.value.name)) {
    nodes.set(localNode.value.name, localNode.value)
  }
  const peer = form.value.peers[0]
  if (peer?.name && !nodes.has(peer.name)) {
    nodes.set(peer.name, {
      name: peer.name,
      underlay_ip: peer.underlay_ip,
    })
  }
  if (!form.value.enabled || form.value.peers.length !== 1) {
    return Array.from(nodes.values())
  }
  const allowed = new Set<string>()
  if (localNode.value?.name) allowed.add(localNode.value.name)
  allowed.add(form.value.peers[0].name)
  return Array.from(nodes.values()).filter((node) => allowed.has(node.name))
})
const localHaState = computed(() => haStatus.value?.native.state || '')
const inferredMaster = computed(() => {
  if (localHaState.value.toLowerCase() === 'master') {
    return localNode.value?.name || ''
  }
  if (localHaState.value.toLowerCase() === 'backup') {
    return form.value.peers[0]?.name || ''
  }
  return ''
})
const activeGateway = computed(() => haStatus.value?.native.active_gateway || inferredMaster.value || '')
const failoverSummary = computed(() => {
  const gw = failoverGatewayNodes.value.find((g) => g.name === failoverTarget.value)
  if (!gw) return ''
  return text('haSwitchSummary')
    .replace('{name}', gw.name)
    .replace('{underlay}', gw.underlay_ip)
    .replace('{current}', activeGateway.value || text('unknown'))
})
const failoverCandidates = computed(() => {
  const active = activeGateway.value
  return failoverGatewayNodes.value.filter((node) => !active || node.name !== active)
})
const failoverIsNoop = computed(() => !failoverTarget.value || failoverTarget.value === activeGateway.value)
watch(
  failoverCandidates,
  (nodes) => {
    if (!nodes.length) {
      failoverTarget.value = ''
      return
    }
    if (!nodes.some((node) => node.name === failoverTarget.value)) {
      failoverTarget.value = nodes[0].name
    }
  },
  { immediate: true },
)

function cloneConfig(value: GatewayHaConfig): GatewayHaConfig {
  const defaults = defaultConfig()
  const cloned = JSON.parse(JSON.stringify(value)) as GatewayHaConfig
  return {
    ...defaults,
    ...cloned,
    vip: {
      ...defaults.vip,
      ...cloned.vip,
      garp: {
        ...defaults.vip.garp,
        ...(cloned.vip?.garp || {}),
      },
    },
    bgp: {
      ...defaults.bgp,
      ...cloned.bgp,
      peers: cloned.bgp?.peers || [],
    },
  }
}

function defaultConfig(): GatewayHaConfig {
  return {
    enabled: false,
    mode: 'active_backup',
    self_index: 0,
    preferred_active: null,
    connection_sync: true,
    xsync_rpc: 'grpc',
    failover: 'bfd_auto',
    peers: [],
    vip: {
      provider: 'hook',
      owner: 'edge_lb',
      bind_device: 'loopback',
      garp_device: null,
      private_vip: null,
      bind_timeout_secs: 15,
      verify_timeout_secs: 10,
      garp: {
        count: 10,
        interval_ms: 100,
        repeat_after_ms: 1000,
        repeat_count: 1,
      },
      promote_hook: null,
      demote_hook: null,
      verify_hook: null,
    },
    bgp: {
      local_as: null,
      router_id: 'auto',
      peers: [],
      hold_time_secs: 90,
      keepalive_secs: 30,
    },
  }
}

function normalizedConfig(options: { pairing?: boolean } = {}): GatewayHaConfig {
  const next = cloneConfig(form.value)
  next.mode = 'active_backup'
  next.connection_sync = true
  next.xsync_rpc = 'grpc'
  next.failover = 'bfd_auto'
  next.vip.owner = 'edge_lb'
  if (options.pairing && localNode.value?.name) {
    next.preferred_active = localNode.value.name
  }
  if (options.pairing) {
    next.self_index = 0
  }
  if (next.vip.provider !== 'l2') {
    next.vip.private_vip = null
  }
  if (next.vip.provider !== 'hook') {
    next.vip.promote_hook = null
    next.vip.demote_hook = null
    next.vip.verify_hook = null
  } else {
    next.vip.promote_hook = managedHookPaths.promote
    next.vip.demote_hook = managedHookPaths.demote
    next.vip.verify_hook = managedHookPaths.verify
  }
  return next
}

function peerKey(peer: GatewayHaPeer, index: number) {
  return `${peer.name || 'peer'}-${peer.underlay_ip || index}`
}

function statusVariant(value?: string) {
  const normalized = (value || '').toLowerCase()
  if (normalized === 'master' || normalized === 'bfdup' || normalized === 'up') {
    return 'success'
  }
  if (normalized === 'backup' || normalized === 'not_defined' || normalized === 'down' || normalized === 'disabled') {
    return 'outline'
  }
  return 'secondary'
}

async function saveHa() {
  const result = await api.saveHaConfig(normalizedConfig())
  saveResult.value = result.datapath_refresh_required ? text('haRestartRequired') : text('saved')
  await refreshHaData()
}

async function pairGateway() {
  const result = await api.pairHaGateway({
    endpoint: pairEndpoint.value,
    bootstrap_token: pairToken.value,
    config: normalizedConfig({ pairing: true }),
  })
  pairResult.value = text('haPairResult').replace('{name}', result.peer.name).replace('{underlay}', result.peer.underlay_ip)
  pairToken.value = ''
  await refreshHaData()
}

async function unpairGateway() {
  const result = await api.unpairHaGateway()
  pairResult.value = result.secret_deleted ? text('haUnpairResult') : text('haUnpairResultNoSecret')
  unpairArmed.value = false
  await refreshHaData()
}

async function switchActiveGateway() {
  const result = await api.haFailover(failoverTarget.value)
  failoverResult.value = text('haSwitchResult').replace('{name}', result.gateway).replace('{vip}', result.vip)
  failoverArmed.value = false
  await refreshHaData()
}
</script>

<template>
  <div class="space-y-4">
    <div class="grid gap-4" :class="form.enabled ? 'xl:grid-cols-[minmax(0,3fr)_minmax(320px,2fr)]' : 'xl:grid-cols-1'">
      <Card>
        <CardHeader>
          <CardTitle>{{ text('navHa') }}</CardTitle>
          <CardDescription>{{ text('haConfigDesc') }}</CardDescription>
        </CardHeader>
        <CardContent class="space-y-6">
          <div class="grid gap-4" :class="form.enabled ? 'md:grid-cols-2' : 'md:grid-cols-1'">
            <div class="flex items-center justify-between gap-4 rounded-md border p-3">
              <div class="space-y-1">
                <Label>{{ text('haEnabled') }}</Label>
                <p class="text-xs text-muted-foreground">{{ text('haEnabledDesc') }}</p>
              </div>
              <Switch v-model="form.enabled" />
            </div>
            <div v-if="form.enabled" class="space-y-1.5">
              <Label>{{ text('haVipProvider') }}</Label>
              <Select v-model="form.vip.provider">
                <SelectTrigger class="w-full">
                  <SelectValue :placeholder="text('haVipProvider')" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="hook">hook</SelectItem>
                  <SelectItem value="l2">l2</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <template v-if="form.enabled">
          <div v-if="form.vip.provider === 'l2'" class="space-y-3 rounded-md border p-4">
            <div class="flex items-center justify-between gap-3">
              <div>
                <h3 class="text-sm font-semibold">{{ text('haL2Advanced') }}</h3>
                <p class="text-xs text-muted-foreground">{{ text('haL2AdvancedDesc') }}</p>
              </div>
            </div>
            <div class="grid gap-4 md:grid-cols-3">
              <div class="space-y-1.5">
                <Label>{{ text('haPrivateVip') }}</Label>
                <Input v-model="form.vip.private_vip" placeholder="192.168.0.6" />
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('haVipBindDevice') }}</Label>
                <Select v-model="form.vip.bind_device">
                  <SelectTrigger class="w-full">
                    <SelectValue :placeholder="text('haVipBindDevice')" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="underlay">underlay_dev</SelectItem>
                    <SelectItem value="loopback">lo</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('haGarpDevice') }}</Label>
                <Input v-model="form.vip.garp_device" :placeholder="status?.vxlan?.underlay_dev || 'auto'" />
                <p class="text-xs text-muted-foreground">{{ text('haGarpDeviceDesc') }}</p>
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('haBindTimeout') }}</Label>
                <Input v-model.number="form.vip.bind_timeout_secs" type="number" min="1" />
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('haVerifyTimeout') }}</Label>
                <Input v-model.number="form.vip.verify_timeout_secs" type="number" min="1" />
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('haGarpCount') }}</Label>
                <Input v-model.number="form.vip.garp.count" type="number" min="1" />
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('haGarpInterval') }}</Label>
                <Input v-model.number="form.vip.garp.interval_ms" type="number" min="1" />
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('haGarpRepeatAfter') }}</Label>
                <Input v-model.number="form.vip.garp.repeat_after_ms" type="number" min="0" />
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('haGarpRepeatCount') }}</Label>
                <Input v-model.number="form.vip.garp.repeat_count" type="number" min="0" max="10" />
              </div>
            </div>
          </div>

          <div v-if="form.vip.provider === 'hook'" class="grid gap-4 md:grid-cols-3">
            <div class="space-y-1.5">
              <Label>{{ text('haPromoteHook') }}</Label>
              <div class="rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs">{{ managedHookPaths.promote }}</div>
            </div>
            <div class="space-y-1.5">
              <Label>{{ text('haDemoteHook') }}</Label>
              <div class="rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs">{{ managedHookPaths.demote }}</div>
            </div>
            <div class="space-y-1.5">
              <Label>{{ text('haVerifyHook') }}</Label>
              <div class="rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs">{{ managedHookPaths.verify }}</div>
            </div>
          </div>

          <div class="space-y-3 rounded-md border p-4">
            <div>
              <h3 class="text-sm font-semibold">{{ text('haPairing') }}</h3>
              <p class="text-xs text-muted-foreground">{{ text('haPairingDesc') }}</p>
            </div>
            <div class="grid gap-4 md:grid-cols-2">
              <div class="space-y-1.5">
                <Label>{{ text('haPeerXdsEndpoint') }}</Label>
                <Input v-model="pairEndpoint" placeholder="192.168.0.16:22222" />
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('haBootstrapToken') }}</Label>
                <Input v-model="pairToken" type="password" autocomplete="off" />
              </div>
            </div>
            <div class="flex flex-wrap items-center gap-3">
              <Button
                variant="outline"
                :disabled="!!busy || !pairEndpoint || !pairToken"
                @click="
                  run('ha-pair', async () => {
                    await pairGateway()
                  })
                "
              >
                <Loader2 v-if="busy === 'ha-pair'" class="animate-spin" />
                <ShieldAlert v-else class="size-4" />
                {{ text('haStartPairing') }}
              </Button>
              <Badge v-if="pairResult" variant="outline">{{ pairResult }}</Badge>
            </div>
          </div>

          <div class="space-y-3">
            <div class="flex items-center justify-between gap-3">
              <div>
                <h3 class="text-sm font-semibold">{{ text('haPeers') }}</h3>
                <p class="text-xs text-muted-foreground">{{ text('haPeersDesc') }}</p>
              </div>
            </div>
            <p v-if="haFormError" class="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {{ haFormError }}
            </p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{{ text('name') }}</TableHead>
                  <TableHead>{{ text('underlayIp') }}</TableHead>
                  <TableHead>API</TableHead>
                  <TableHead>xDS</TableHead>
                  <TableHead>overlay</TableHead>
                  <TableHead>DSCP</TableHead>
                  <TableHead>version</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow v-for="(peer, index) in form.peers" :key="peerKey(peer, index)">
                  <TableCell class="font-medium">{{ peer.name || '-' }}</TableCell>
                  <TableCell class="font-mono text-xs">{{ peer.underlay_ip || '-' }}</TableCell>
                  <TableCell class="font-mono text-xs">{{ peer.api_addr || '-' }}</TableCell>
                  <TableCell class="font-mono text-xs">{{ peer.xds_addr || '-' }}</TableCell>
                  <TableCell class="font-mono text-xs">
                    <div>{{ peer.overlay_ip || '-' }}</div>
                    <div class="text-muted-foreground">{{ peer.overlay_cidr || '-' }}</div>
                  </TableCell>
                  <TableCell class="font-mono">{{ peer.dscp ?? '-' }}</TableCell>
                  <TableCell class="font-mono text-xs">{{ peer.version || '-' }}</TableCell>
                </TableRow>
                <TableRow v-if="!form.peers.length">
                  <TableCell colspan="7" class="text-muted-foreground">{{ text('haNoPeers') }}</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </div>
          </template>

          <div class="flex items-center gap-3">
            <Button
              :disabled="!!busy || !!haFormError"
              @click="
                run('ha-save', async () => {
                  await saveHa()
                })
              "
            >
              <Loader2 v-if="busy === 'ha-save'" class="animate-spin" />
              <Save v-else class="size-4" />
              {{ text('save') }}
            </Button>
            <Badge v-if="saveResult" variant="outline">{{ saveResult }}</Badge>
            <p class="text-xs text-muted-foreground">{{ text('haConfigPersistDesc') }}</p>
          </div>
        </CardContent>
      </Card>

      <Card v-if="form.enabled">
        <CardHeader>
          <CardTitle>{{ text('haStatus') }}</CardTitle>
          <CardDescription>{{ text('haStatusDesc') }}</CardDescription>
        </CardHeader>
        <CardContent class="space-y-3 text-sm">
          <div v-if="haStatusError" class="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-destructive">
            {{ haStatusError }}
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div class="rounded-md border bg-muted/30 p-3">
              <div class="text-xs text-muted-foreground">{{ text('haCiState') }}</div>
              <Badge class="mt-1" :variant="statusVariant(localHaState)">{{ ciStateCount }}</Badge>
            </div>
            <div class="rounded-md border bg-muted/30 p-3">
              <div class="text-xs text-muted-foreground">{{ text('haBfdSessions') }}</div>
              <Badge class="mt-1" :variant="statusVariant(haStatus?.bfd?.state)">{{ bfdCount }}</Badge>
            </div>
            <div class="rounded-md border bg-muted/30 p-3">
              <div class="text-xs text-muted-foreground">{{ text('haConnectionSync') }}</div>
              <Badge class="mt-1" :variant="statusVariant(haStatus?.xsync?.state)">{{ conntrackCount }}</Badge>
            </div>
            <div class="rounded-md border bg-muted/30 p-3">
              <div class="text-xs text-muted-foreground">{{ text('haDatapath') }}</div>
              <div class="mt-1 font-semibold">{{ form.enabled ? text('enabled') : text('disabled') }}</div>
            </div>
          </div>
          <div class="rounded-md border p-3">
            <div class="flex items-center justify-between gap-3">
              <div>
                <div class="text-sm font-medium">{{ text('haPeerToken') }}</div>
                <p class="text-xs text-muted-foreground">{{ text('haPeerTokenDesc') }}</p>
              </div>
              <Badge :variant="sessionToken?.present ? 'success' : 'secondary'">
                {{ sessionToken?.present ? text('present') : text('missing') }}
              </Badge>
            </div>
            <div v-if="sessionToken?.present" class="mt-3 grid gap-2 text-xs md:grid-cols-2">
              <div class="truncate">
                <span class="text-muted-foreground">{{ text('haPeer') }}</span>
                <span class="ml-2 font-mono">{{ sessionToken.peer_name || '-' }} / {{ sessionToken.peer_underlay_ip || '-' }}</span>
              </div>
              <div class="truncate">
                <span class="text-muted-foreground">{{ text('updatedAt') }}</span>
                <span class="ml-2 font-mono">{{ sessionToken.updated_at_unix || '-' }}</span>
              </div>
              <div class="truncate">
                <span class="text-muted-foreground">{{ text('haSessionTokenId') }}</span>
                <span class="ml-2 font-mono">{{ sessionToken.session_token_id || '-' }}</span>
              </div>
            </div>
            <div v-if="sessionToken?.error" class="mt-3 rounded-md bg-muted p-2 text-xs text-muted-foreground">
              {{ sessionToken.error }}
            </div>
            <div class="mt-3 flex flex-wrap gap-2">
              <Button
                v-if="!unpairArmed"
                variant="outline"
                size="sm"
                :disabled="!!busy || !sessionToken?.present"
                @click="unpairArmed = true"
              >
                <Trash2 class="size-4" /> {{ text('haUnpair') }}
              </Button>
              <template v-else>
                <Button
                  variant="destructive"
                  size="sm"
                  :disabled="!!busy"
                  @click="
                    run('ha-unpair', async () => {
                      await unpairGateway()
                    })
                  "
                >
                  <Loader2 v-if="busy === 'ha-unpair'" class="animate-spin" /> {{ text('haConfirmUnpair') }}
                </Button>
                <Button variant="outline" size="sm" @click="unpairArmed = false">{{ text('cancel') }}</Button>
              </template>
            </div>
          </div>
          <div v-if="ciStateError" class="rounded-md bg-muted p-3 text-xs text-muted-foreground">cistate: {{ ciStateError }}</div>
          <div v-if="bfdError" class="rounded-md bg-muted p-3 text-xs text-muted-foreground">bfd: {{ bfdError }}</div>
          <div v-if="conntrackError" class="rounded-md bg-muted p-3 text-xs text-muted-foreground">
            conntrack: {{ conntrackError }}
          </div>
          <div class="space-y-3 rounded-md border p-3">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div class="text-sm font-medium">{{ text('haSwitchover') }}</div>
                <p class="text-xs text-muted-foreground">{{ text('haSwitchoverDesc') }}</p>
              </div>
              <Badge :variant="statusVariant(localHaState)">{{ localHaState || '-' }}</Badge>
            </div>
            <div class="grid gap-2 sm:grid-cols-3">
              <div class="rounded-md bg-muted p-3">
                <div class="text-xs text-muted-foreground">{{ text('haCurrentMaster') }}</div>
                <div class="mt-1 truncate font-medium">{{ activeGateway || '-' }}</div>
              </div>
              <div class="rounded-md bg-muted p-3">
                <div class="text-xs text-muted-foreground">{{ text('node') }}</div>
                <div class="mt-1 truncate font-medium">{{ localNode?.name || '-' }}</div>
              </div>
              <div class="rounded-md bg-muted p-3">
                <div class="text-xs text-muted-foreground">VIP</div>
                <div class="mt-1 truncate font-medium">{{ form.vip.private_vip || '-' }}</div>
              </div>
            </div>
            <div class="space-y-1.5">
              <Label>{{ text('targetGateway') }}</Label>
              <Select v-model="failoverTarget">
                <SelectTrigger class="w-full">
                  <SelectValue :placeholder="text('targetGateway')" />
                </SelectTrigger>
                <SelectContent>
                <SelectItem v-for="gw in failoverCandidates" :key="gw.name" :value="gw.name">
                    {{ gw.name }} (underlay {{ gw.underlay_ip }})
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <p v-if="failoverSummary" class="rounded-md bg-muted p-3 text-xs text-muted-foreground">
              <ShieldAlert class="mr-1 inline size-3.5" /> {{ failoverSummary }}
            </p>
            <Badge v-if="failoverResult" variant="outline">{{ failoverResult }}</Badge>
            <div v-if="failoverCandidates.length" class="flex flex-wrap gap-2">
              <Button v-if="!failoverArmed" variant="destructive" :disabled="failoverIsNoop" @click="failoverArmed = true">
                {{ text('switchTo') }} {{ failoverTarget }}
              </Button>
              <template v-else>
                <Button
                  variant="destructive"
                  :disabled="!!busy"
                  @click="
                    run('failover', async () => {
                      await switchActiveGateway()
                    })
                  "
                >
                  <Loader2 v-if="busy === 'failover'" class="animate-spin" /> {{ text('confirmFailover') }}
                </Button>
                <Button variant="outline" @click="failoverArmed = false">{{ text('cancel') }}</Button>
              </template>
            </div>
          </div>
          <div class="space-y-2">
            <div class="text-sm font-medium">{{ text('haCiState') }}</div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{{ text('haInstance') }}</TableHead>
                  <TableHead>{{ text('haState') }}</TableHead>
                  <TableHead>VIP</TableHead>
                  <TableHead>sync</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow v-for="row in ciStateRows" :key="`${row.instance || 'ci'}-${row.vip || row.state || ''}`">
                  <TableCell>{{ row.instance || '-' }}</TableCell>
                  <TableCell>
                    <Badge :variant="statusVariant(row.state)">{{ row.state || '-' }}</Badge>
                  </TableCell>
                  <TableCell>{{ row.vip || '-' }}</TableCell>
                  <TableCell>{{ row.sync ?? '-' }}</TableCell>
                </TableRow>
                <TableRow v-if="!ciStateRows.length && !ciStateError">
                  <TableCell colspan="4" class="text-muted-foreground">{{ text('empty') }}</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </div>
          <div class="space-y-2">
            <div class="text-sm font-medium">{{ text('haBfdSessions') }}</div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{{ text('haInstance') }}</TableHead>
                  <TableHead>{{ text('remoteIp') }}</TableHead>
                  <TableHead>{{ text('sourceIp') }}</TableHead>
                  <TableHead>{{ text('haState') }}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow v-for="row in bfdRows" :key="`${row.instance || 'bfd'}-${row.remoteIp || row.sourceIP || ''}`">
                  <TableCell>{{ row.instance || '-' }}</TableCell>
                  <TableCell>{{ row.remoteIp || '-' }}</TableCell>
                  <TableCell>{{ row.sourceIP || '-' }}</TableCell>
                  <TableCell>
                    <Badge :variant="statusVariant(row.state)">{{ row.state || '-' }}</Badge>
                  </TableCell>
                </TableRow>
                <TableRow v-if="!bfdRows.length && !bfdError">
                  <TableCell colspan="4" class="text-muted-foreground">{{ text('empty') }}</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
