<script setup lang="ts">
import { onMounted, watch } from 'vue'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Badge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui'
import PaginationBar from '@/components/common/PaginationBar.vue'
import { t as text } from '@/lib/i18n'
import { formatDiscovery } from '@/lib/format'
import { backendNodePage, backendSubscriptionsError, refreshBackendNodePage } from '@/composables/useNodeData'

watch(
  () => [backendNodePage.page, backendNodePage.q],
  () => { void refreshBackendNodePage() },
)
onMounted(() => {
  void refreshBackendNodePage()
})
</script>

<template>
        <Card>
          <CardHeader>
            <CardTitle>{{ text('backendNode') }}（{{ backendNodePage.total }}）</CardTitle>
            <CardDescription>{{ text('backendNodesDesc') }}</CardDescription>
          </CardHeader>
          <CardContent>
            <p v-if="backendSubscriptionsError" class="mb-3 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {{ backendSubscriptionsError }}
            </p>
            <PaginationBar
              v-model:page="backendNodePage.page"
              v-model:q="backendNodePage.q"
              :total="backendNodePage.total"
              :per-page="backendNodePage.per_page"
              @refresh="refreshBackendNodePage"
            />
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
                <TableRow v-for="node in backendNodePage.items" :key="node.name">
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
                <TableRow v-if="!backendNodePage.items.length">
                  <TableCell colspan="4" class="text-muted-foreground">{{ text('empty') }}</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </CardContent>
        </Card></template>
