<script setup lang="ts">
import { computed, ref } from 'vue'
import { Activity, Globe2, Loader2, RadioTower, Server, ShieldAlert } from 'lucide-vue-next'
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui'
import { api } from '@/api'
import { t as text } from '@/lib/i18n'
import { formatDiscovery, formatTime } from '@/lib/format'
import {
  backendRegistrations,
  backendSubscriptionsError,
  busy,
  gatewayNodes,
  isGateway,
  localNode,
  run,
  status,
} from '@/composables/useNodeData'

const applySummary = computed(() =>
  isGateway.value
    ? text('applyGatewaySummary').replace('{dev}', status.value?.vxlan?.dev ?? 'VXLAN')
    : text('applyBackendSummary').replace('{dev}', status.value?.vxlan?.dev ?? 'VXLAN'),
)

const cleanupSummary = computed(() =>
  isGateway.value
    ? text('cleanupGatewaySummary').replace('{dev}', status.value?.vxlan?.dev ?? 'VXLAN')
    : text('cleanupBackendSummary').replace('{dev}', status.value?.vxlan?.dev ?? 'VXLAN'),
)

const publicIpResult = ref('')
const publicIpError = ref('')
const discoveringPublicIp = ref(false)

async function discoverPublicIp() {
  publicIpResult.value = ''
  publicIpError.value = ''
  discoveringPublicIp.value = true
  try {
    const result = await api.discoverPublicIp()
    publicIpResult.value = result.value
      ? `${result.value} (${formatDiscovery(result.mode, result.source)})`
      : text('publicIpUnresolved')
  } catch (error) {
    publicIpError.value = error instanceof Error ? error.message : String(error)
  } finally {
    discoveringPublicIp.value = false
  }
}
</script>

<template>
        <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <Card>
            <CardHeader>
              <div class="flex items-start justify-between gap-3">
                <div>
                  <CardTitle class="flex items-center gap-2"><Server class="size-4" /> {{ text('node') }}</CardTitle>
                  <CardDescription>{{ status?.node_name ?? text('loading') }}</CardDescription>
                </div>
                <Button size="sm" variant="outline" :disabled="discoveringPublicIp" @click="discoverPublicIp">
                  <Loader2 v-if="discoveringPublicIp" class="animate-spin" />
                  <Globe2 v-else class="size-4" />
                  {{ text('discoverPublicIp') }}
                </Button>
              </div>
            </CardHeader>
            <CardContent class="space-y-2 text-sm">
              <div v-if="publicIpResult" class="flex justify-between gap-3">
                <span class="text-muted-foreground">{{ text('publicIp') }}</span>
                <span class="truncate font-mono">{{ publicIpResult }}</span>
              </div>
              <p v-if="publicIpError" class="rounded-md bg-destructive/10 p-2 text-xs text-destructive">
                {{ publicIpError }}
              </p>
              <div class="flex justify-between"><span class="text-muted-foreground">{{ text('role') }}</span><span>{{ status?.node_role }}</span></div>
              <div class="flex justify-between"><span class="text-muted-foreground">{{ text('underlayIp') }}</span><span class="font-mono">{{ localNode?.underlay_ip ?? '—' }}</span></div>
              <div class="flex justify-between text-xs"><span class="text-muted-foreground">{{ text('underlayIp') }} {{ text('discoveryMode') }}</span><span>{{ formatDiscovery(status?.discovery?.underlay_ip?.mode, status?.discovery?.underlay_ip?.source) }}</span></div>
              <div class="flex justify-between"><span class="text-muted-foreground">{{ text('overlayIp') }}</span><span class="font-mono">{{ localNode?.overlay_ip ?? '—' }}</span></div>
            </CardContent>
          </Card>

          <Card v-if="status">
            <CardHeader>
              <CardTitle class="flex items-center gap-2"><Activity class="size-4" /> VXLAN</CardTitle>
              <CardDescription>{{ status.vxlan?.dev ?? text('loading') }}</CardDescription>
            </CardHeader>
            <CardContent class="space-y-3 text-sm">
              <div class="space-y-2">
                <div class="flex items-center justify-between">
                  <span class="text-muted-foreground">{{ text('device') }}</span>
                  <Badge :variant="status.vxlan?.present && status.vxlan?.up ? 'success' : 'destructive'">
                    {{ status.vxlan?.present ? (status.vxlan?.up ? 'UP' : 'DOWN') : text('missing') }}
                  </Badge>
                </div>
                <div class="flex justify-between"><span class="text-muted-foreground">{{ text('name') }}</span><span class="font-mono">{{ status.vxlan?.dev ?? '—' }}</span></div>
                <div class="flex justify-between"><span class="text-muted-foreground">underlay dev</span><span class="font-mono">{{ status.vxlan?.underlay_dev ?? '—' }}</span></div>
              </div>
              <div class="grid grid-cols-4 gap-2 self-start text-center text-xs">
                <div class="rounded-md border px-2 py-2"><div class="font-semibold">{{ status.vxlan?.vni ?? '—' }}</div><div class="text-muted-foreground">VNI</div></div>
                <div class="rounded-md border px-2 py-2"><div class="font-semibold">{{ status.vxlan?.vxlan_port ?? '—' }}</div><div class="text-muted-foreground">port</div></div>
                <div class="rounded-md border px-2 py-2"><div class="font-semibold">{{ status.vxlan?.mtu ?? '—' }}</div><div class="text-muted-foreground">MTU</div></div>
                <div class="rounded-md border px-2 py-2"><div class="font-semibold">{{ status.vxlan?.dscp ?? '—' }}</div><div class="text-muted-foreground">DSCP</div></div>
              </div>
            </CardContent>
          </Card>

          <Card v-if="status && isGateway">
            <CardHeader>
              <CardTitle class="flex items-center gap-2"><Activity class="size-4" /> {{ text('gatewayDatapath') }}</CardTitle>
              <CardDescription>native DNAT / DSCP</CardDescription>
            </CardHeader>
            <CardContent class="space-y-2 text-sm">
                <div class="text-xs font-medium text-muted-foreground">{{ text('gatewayDatapath') }}</div>
                <div class="flex items-center justify-between"><span>{{ text('nativeDatapath') }}</span><Badge :variant="status.native_datapath_attached ? 'success' : 'destructive'">{{ status.native_datapath_attached ? text('mounted') : text('missing') }}</Badge></div>
                <div class="flex items-center justify-between"><span>DSCP filter</span><Badge :variant="status.dscp_attached ? 'success' : 'destructive'">{{ status.dscp_attached ? text('mounted') : text('missing') }}</Badge></div>
                <div v-if="status.underlay_xdp_attachment" class="flex items-center justify-between gap-3"><span>XDP firewall</span><Badge variant="secondary" class="font-mono">{{ status.underlay_xdp_attachment }}</Badge></div>
                <div v-if="status.dscp_stats" class="truncate text-xs text-muted-foreground">{{ text('dscpCount') }}: <span class="font-mono">matched {{ status.dscp_stats.matched }} · changed {{ status.dscp_stats.changed }}</span></div>
                <div class="flex flex-wrap gap-2 border-t pt-2">
                  <Button size="sm" :disabled="!!busy" @click="run('apply', () => api.apply())"><Loader2 v-if="busy === 'apply'" class="animate-spin" /> Apply</Button>
                  <Button size="sm" variant="destructive" :disabled="!!busy" @click="run('cleanup', () => api.cleanup())"><Loader2 v-if="busy === 'cleanup'" class="animate-spin" /> Cleanup</Button>
                </div>
                <p class="rounded-md bg-muted p-2 text-[11px] leading-4 text-muted-foreground">Apply：{{ applySummary }}<br />Cleanup：{{ cleanupSummary }}</p>
            </CardContent>
          </Card>

          <Card v-if="status && !isGateway">
            <CardHeader>
              <CardTitle>{{ text('backendReturnPath') }}</CardTitle>
              <CardDescription>{{ status.vxlan?.dev ?? 'VXLAN' }}</CardDescription>
            </CardHeader>
            <CardContent class="space-y-2 text-sm">
              <div class="flex items-center justify-between"><span>{{ text('nftTable') }}</span><Badge :variant="status.nft_table_present ? 'success' : 'destructive'">{{ status.nft_table_present ? text('present') : text('missing') }}</Badge></div>
              <div class="flex items-center justify-between"><span>{{ text('fwmarkRule') }}</span><Badge :variant="status.policy_rule_present ? 'success' : 'destructive'">{{ status.policy_rule_present ? text('present') : text('missing') }}</Badge></div>
            </CardContent>
          </Card>

          <Card v-if="status && isGateway" class="md:col-span-2 xl:col-span-3">
            <CardHeader>
              <CardTitle class="flex items-center gap-2"><RadioTower class="size-4" /> {{ text('xdsSubscriptions') }}</CardTitle>
              <CardDescription>{{ text('xdsSubscriptionsDesc') }}</CardDescription>
            </CardHeader>
            <CardContent class="space-y-2 text-sm">
              <div
                v-for="[name, reg] in backendRegistrations"
                :key="name"
                class="grid gap-2 rounded-md border px-3 py-2 md:grid-cols-[1fr_auto]"
              >
                <div>
                  <div class="font-medium">{{ name }}</div>
                  <div class="font-mono text-xs text-muted-foreground">
                    underlay {{ reg.underlay_ip }} ({{ formatDiscovery(reg.underlay_ip_mode, reg.underlay_ip_source) }})<span v-if="reg.peer"> · peer {{ reg.peer }}</span>
                  </div>
                  <div class="truncate font-mono text-[11px] text-muted-foreground">
                    version {{ reg.last_version || '-' }}
                  </div>
                </div>
                <div class="text-xs text-muted-foreground md:text-right">
                  <div>last {{ formatTime(reg.last_seen) }}</div>
                  <div>connected {{ formatTime(reg.connected_at) }}</div>
                </div>
              </div>
              <p v-if="!backendRegistrations.length" class="rounded-md border px-3 py-2 text-xs text-muted-foreground">
                {{ text('noSubscriptions') }}
              </p>
              <p v-if="backendSubscriptionsError" class="rounded-md bg-destructive/10 p-2 text-xs text-destructive">
                {{ backendSubscriptionsError }}
              </p>
            </CardContent>
          </Card>
        </div>

        <Card v-if="!isGateway">
          <CardHeader>
            <CardTitle>{{ text('operations') }}</CardTitle>
            <CardDescription>{{ text('operationsDesc') }}</CardDescription>
          </CardHeader>
          <CardContent class="space-y-3">
            <div class="flex flex-wrap items-center gap-2">
              <Button :disabled="!!busy" @click="run('apply', () => api.apply())">
                <Loader2 v-if="busy === 'apply'" class="animate-spin" /> Apply
              </Button>
              <Button
                variant="destructive"
                :disabled="!!busy"
                @click="run('cleanup', () => api.cleanup())"
              >
                <Loader2 v-if="busy === 'cleanup'" class="animate-spin" /> Cleanup
              </Button>
            </div>
            <p class="rounded-md bg-muted p-3 text-xs text-muted-foreground">
              <ShieldAlert class="mr-1 inline size-3.5" />
              Apply：{{ applySummary }}
              <br />
              Cleanup：{{ cleanupSummary }}
            </p>
          </CardContent>
        </Card></template>
