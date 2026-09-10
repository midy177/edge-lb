<script setup lang="ts">
import { ref } from 'vue'
import { Globe2, Loader2 } from 'lucide-vue-next'
import { api } from '@/api'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Badge,
  Button,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui'
import { t as text } from '@/lib/i18n'
import { formatDiscovery } from '@/lib/format'
import { backendNodes } from '@/composables/useNodeData'

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
        <Card>
          <CardHeader>
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <CardTitle>{{ text('backendNode') }}（{{ backendNodes.length }}）</CardTitle>
                <CardDescription>{{ text('backendNodesDesc') }}</CardDescription>
              </div>
              <div class="flex flex-wrap items-center justify-end gap-2">
                <Badge v-if="publicIpResult" variant="outline" class="font-mono">{{ publicIpResult }}</Badge>
                <Button size="sm" variant="outline" :disabled="discoveringPublicIp" @click="discoverPublicIp">
                  <Loader2 v-if="discoveringPublicIp" class="animate-spin" />
                  <Globe2 v-else class="size-4" />
                  {{ text('discoverPublicIp') }}
                </Button>
              </div>
            </div>
            <p v-if="publicIpError" class="mt-2 rounded-md bg-destructive/10 p-2 text-xs text-destructive">
              {{ publicIpError }}
            </p>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow class="hover:bg-transparent">
                  <TableHead>{{ text('name') }}</TableHead>
                  <TableHead>{{ text('underlayIp') }} / {{ text('discoveryMode') }}</TableHead>
                  <TableHead>{{ text('overlayIp') }}</TableHead>
                  <TableHead>{{ text('conflicts') }}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow v-for="node in backendNodes" :key="node.name">
                  <TableCell class="font-medium">{{ node.name }}</TableCell>
                  <TableCell>
                    <div class="font-mono">{{ node.underlay_ip }}</div>
                    <div class="text-xs text-muted-foreground">
                      {{ formatDiscovery(node.underlay_ip_mode, node.underlay_ip_source) }}
                    </div>
                  </TableCell>
                  <TableCell class="font-mono">{{ node.overlay_ip }}</TableCell>
                  <TableCell>
                    <div v-if="node.conflicts?.length" class="space-y-1">
                      <Badge variant="destructive">{{ node.conflicts.length }}</Badge>
                      <div
                        v-for="conflict in node.conflicts"
                        :key="`${conflict.kind}-${conflict.subject}-${conflict.detail}`"
                        class="max-w-[28rem] text-xs text-muted-foreground"
                      >
                        <span class="font-medium text-foreground">{{ conflict.kind }}</span>
                        <span v-if="conflict.subject"> · {{ conflict.subject }}</span>
                        <div class="break-words">{{ conflict.detail }}</div>
                      </div>
                    </div>
                    <span v-else class="text-muted-foreground">—</span>
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </CardContent>
        </Card></template>
