<script setup lang="ts">
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
import { t as text } from '@/lib/i18n'
import { formatDiscovery } from '@/lib/format'
import { backendNodes } from '@/composables/useNodeData'
</script>

<template>
        <Card>
          <CardHeader>
            <CardTitle>{{ text('backendNode') }}（{{ backendNodes.length }}）</CardTitle>
            <CardDescription>{{ text('backendNodesDesc') }}</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow class="hover:bg-transparent">
                  <TableHead>{{ text('name') }}</TableHead>
                  <TableHead>{{ text('publicIp') }} / {{ text('discoveryMode') }}</TableHead>
                  <TableHead>{{ text('underlayIp') }} / {{ text('discoveryMode') }}</TableHead>
                  <TableHead>{{ text('overlayIp') }}</TableHead>
                  <TableHead>{{ text('conflicts') }}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow v-for="node in backendNodes" :key="node.name">
                  <TableCell class="font-medium">{{ node.name }}</TableCell>
                  <TableCell>
                    <div class="font-mono">{{ node.public_ip }}</div>
                    <div class="text-xs text-muted-foreground">
                      {{ formatDiscovery(node.public_ip_mode, node.public_ip_source) }}
                    </div>
                  </TableCell>
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
