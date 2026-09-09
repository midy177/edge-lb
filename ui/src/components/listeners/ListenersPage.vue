<script setup lang="ts">
import { Download, Eye, Loader2, Pencil, Plus, Save, Trash2, Upload } from 'lucide-vue-next'
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Checkbox,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  Input,
  Label,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui'
import { ref } from 'vue'
import { api, type ListenerConfig } from '@/api'
import { t as text } from '@/lib/i18n'
import { listenerSelectOptions } from '@/lib/lb'
import { busy, listeners, run, status, targetGroups } from '@/composables/useNodeData'
import {
  canSubmitListener,
  applyListenerTargetGroup,
  editListener,
  editingListener,
  generatedListenerName,
  listenerErrors,
  listenerForm,
  listenerFormOpen,
  openNewListener,
  resetListenerForm,
  submitListener,
  toggleListenerProtocol,
} from './listenerForm'

function protocolLabel(listener: ListenerConfig) {
  return listener.protocols.length ? listener.protocols.join('+') : 'tcp'
}

function externalIps(listener: ListenerConfig) {
  if (listener.vip_ips?.length) return listener.vip_ips.join(', ')
  return status.value?.underlay_ip || text('unknown')
}

function inactiveTimeoutDisplay(listener: ListenerConfig) {
  return listener.select === 'persist' ? 10800 : listener.inactive_timeout ?? 60
}

const listenerImportInput = ref<HTMLInputElement | null>(null)
function downloadListeners(value: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }))
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'edge-lb-listeners.json'; anchor.click(); URL.revokeObjectURL(url)
}
async function exportListeners() { downloadListeners(await api.exportListenerConfigs()) }
function importListeners() { listenerImportInput.value?.click() }
async function onListenerImport(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (!file) return
  await run(text('import'), async () => api.importListenerConfigs(JSON.parse(await file.text())))
  ;(event.target as HTMLInputElement).value = ''
}
</script>

<template>
        <Card>
          <CardHeader>
            <div class="flex items-start justify-between gap-3">
              <div>
                <CardTitle>{{ text('navListeners') }}（{{ listeners.length }}）</CardTitle>
                <CardDescription>{{ text('listenerDesc') }}</CardDescription>
              </div>
              <div class="flex flex-wrap justify-end gap-2">
                <input ref="listenerImportInput" type="file" accept="application/json" class="hidden" @change="onListenerImport" />
                <Button size="icon" variant="outline" :title="text('import')" @click="importListeners"><Upload /></Button>
                <Button size="icon" variant="outline" :title="text('export')" @click="run(text('export'), exportListeners)"><Download /></Button>
                <Button size="sm" @click="openNewListener"><Plus /> {{ text('newListener') }}</Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow class="hover:bg-transparent">
                  <TableHead>{{ text('name') }}</TableHead>
                  <TableHead>{{ text('externalIp') }}</TableHead>
                  <TableHead>{{ text('vipPort') }}</TableHead>
                  <TableHead>{{ text('protocol') }}</TableHead>
                  <TableHead>{{ text('policy') }}</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow v-for="listener in listeners" :key="listener.name" class="align-top">
                  <TableCell class="font-medium">{{ listener.name }}</TableCell>
                  <TableCell class="font-mono text-xs">{{ externalIps(listener) }}</TableCell>
                  <TableCell class="font-mono">{{ listener.port }}</TableCell>
                  <TableCell>
                    <Badge variant="secondary">{{ protocolLabel(listener) }}</Badge>
                  </TableCell>
                  <TableCell>
                    <div class="flex flex-wrap gap-1">
                      <Badge variant="outline">default</Badge>
                      <Badge variant="outline">{{ listener.select ?? 'rr' }}</Badge>
                    </div>
                  </TableCell>
                  <TableCell class="text-right">
                    <Dialog>
                      <DialogTrigger as-child>
                        <Button variant="ghost" size="icon" class="mr-1 size-8" :title="text('details')">
                          <Eye />
                        </Button>
                      </DialogTrigger>
                      <DialogContent class="w-[92vw] !max-w-[92vw] lg:w-[60vw] lg:!max-w-[60vw]">
                        <DialogHeader>
                          <DialogTitle>{{ text('listenerDetails') }} {{ listener.name }}</DialogTitle>
                          <DialogDescription>{{ text('listenerDetailsDesc') }}</DialogDescription>
                        </DialogHeader>
                        <div class="max-h-[66vh] space-y-5 overflow-auto pr-1 text-sm">
                          <section class="space-y-2">
                            <h3 class="text-sm font-semibold">{{ text('navListeners') }}</h3>
                            <div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                              <div class="rounded-md border p-2">
                                <div class="text-xs text-muted-foreground">{{ text('externalIp') }}</div>
                                <div class="font-mono">{{ externalIps(listener) }}</div>
                              </div>
                              <div class="rounded-md border p-2">
                                <div class="text-xs text-muted-foreground">{{ text('vipPort') }}</div>
                                <div class="font-mono">{{ listener.port }}</div>
                              </div>
                              <div class="rounded-md border p-2">
                                <div class="text-xs text-muted-foreground">{{ text('targetPort') }}</div>
                                <div class="font-mono">{{ listener.target_port }}</div>
                              </div>
                              <div class="rounded-md border p-2">
                                <div class="text-xs text-muted-foreground">{{ text('protocol') }}</div>
                                <div class="font-mono">{{ protocolLabel(listener) }}</div>
                              </div>
                              <div class="rounded-md border p-2">
                                <div class="text-xs text-muted-foreground">{{ text('targetGroup') }}</div>
                                <div class="font-mono">{{ listener.target_group }}</div>
                              </div>
                              <div class="rounded-md border p-2">
                                <div class="text-xs text-muted-foreground">{{ text('policy') }}</div>
                                <div class="font-mono">default / {{ listener.select ?? 'rr' }}</div>
                              </div>
                              <div class="rounded-md border p-2">
                                <div class="text-xs text-muted-foreground">{{ text('inactiveTimeout') }}</div>
                                <div class="font-mono">{{ inactiveTimeoutDisplay(listener) }}</div>
                              </div>
                            </div>
                          </section>

                        </div>
                      </DialogContent>
                    </Dialog>
                    <Button variant="ghost" size="icon" class="mr-1 size-8" :title="text('edit')" @click="editListener(listener)">
                      <Pencil />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      class="size-8 text-destructive"
                      :title="text('delete')"
                      @click="run(text('delete') + ' ' + listener.name, () => api.deleteListenerConfig(listener.name))"
                    >
                      <Trash2 />
                    </Button>
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Dialog v-model:open="listenerFormOpen">
          <DialogContent class="w-[92vw] !max-w-[92vw] lg:w-[60vw] lg:!max-w-[60vw]">
            <DialogHeader>
              <DialogTitle>{{ editingListener ? text('editListener') + ' ' + editingListener : text('newListener') }}</DialogTitle>
              <DialogDescription>{{ text('listenerPersistDesc') }}</DialogDescription>
            </DialogHeader>
            <div class="max-h-[72vh] overflow-auto pr-1">
            <div class="grid gap-4 md:grid-cols-[1.2fr_140px_180px]">
              <div class="space-y-1.5">
                <Label>{{ text('name') }}</Label>
                <Input :model-value="generatedListenerName" disabled />
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('vipPort') }} <span class="text-destructive">*</span></Label>
                <Input v-model.number="listenerForm.port" type="number" min="1" max="65535" step="1" required />
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('targetPort') }} <span class="text-destructive">*</span></Label>
                <Input v-model.number="listenerForm.target_port" type="number" min="1" max="65535" step="1" required />
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('protocol') }} <span class="text-destructive">*</span></Label>
                <div class="flex h-9 items-center gap-4 rounded-md border px-3">
                  <label class="flex items-center gap-2 text-sm font-normal">
                    <Checkbox
                      :model-value="listenerForm.protocols.includes('tcp')"
                      @update:model-value="(checked) => toggleListenerProtocol('tcp', checked)"
                    />
                    TCP
                  </label>
                  <label class="flex items-center gap-2 text-sm font-normal">
                    <Checkbox
                      :model-value="listenerForm.protocols.includes('udp')"
                      @update:model-value="(checked) => toggleListenerProtocol('udp', checked)"
                    />
                    UDP
                  </label>
                </div>
              </div>
            </div>

            <div class="mt-5 border-t pt-4">
              <div class="space-y-1.5">
                <Label>{{ text('targetGroup') }} <span class="text-destructive">*</span></Label>
                <Select :model-value="listenerForm.target_group" @update:model-value="applyListenerTargetGroup">
                  <SelectTrigger class="w-full">
                    <SelectValue :placeholder="text('targetGroup')" />
                  </SelectTrigger>
                  <SelectContent disable-portal>
                    <SelectItem v-for="group in targetGroups" :key="group.name" :value="group.name">
                      {{ group.name }}
                    </SelectItem>
                  </SelectContent>
                </Select>
                <p class="text-xs leading-5 text-muted-foreground">{{ text('listenerTargetGroupHint') }}</p>
              </div>
            </div>

            <div class="mt-5 border-t pt-4">
              <div class="mb-3 text-sm font-medium">{{ text('advancedOptions') }}</div>
              <div class="grid gap-4 md:grid-cols-3">
              <div class="space-y-1.5">
                <Label>{{ text('selectPolicy') }}</Label>
                <Select v-model="listenerForm.select">
                  <SelectTrigger class="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent disable-portal class="min-w-(--reka-select-trigger-width) w-max max-w-[85vw]">
                    <SelectItem v-for="option in listenerSelectOptions" :key="option.value" :value="option.value">
                      {{ option.value }}
                      <template #hint>
                        <span class="flex-1 text-xs leading-5 text-muted-foreground">{{ text(option.descKey) }}</span>
                      </template>
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('lbMode') }}</Label>
                <Input model-value="default" disabled />
                <p class="text-xs leading-5 text-muted-foreground">{{ text('modeDefaultDesc') }}</p>
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('inactiveTimeout') }}</Label>
                <Input
                  v-model.number="listenerForm.inactive_timeout"
                  type="number"
                  min="1"
                  step="1"
                  placeholder="60"
                  :disabled="listenerForm.select === 'persist'"
                />
                <p class="text-xs leading-5 text-muted-foreground">
                  {{ listenerForm.select === 'persist' ? text('inactiveTimeoutPersistHint') : text('inactiveTimeoutHint') }}
                </p>
              </div>
            </div>
            </div>
            <div v-if="listenerErrors.length" class="mt-4 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive">
              <div v-for="item in listenerErrors" :key="item">{{ item }}</div>
            </div>
            <div class="mt-4 flex gap-2">
              <Button
                :disabled="!canSubmitListener || !!busy"
                @click="submitListener"
              >
                <Loader2 v-if="busy" class="animate-spin" />
                <Save v-else-if="editingListener" />
                <Plus v-else />
                {{ editingListener ? text('save') : text('create') }}
              </Button>
              <Button
                variant="outline"
                @click="listenerFormOpen = false; resetListenerForm()"
              >
                {{ text('cancel') }}
              </Button>
            </div>
            </div>
          </DialogContent>
        </Dialog></template>
