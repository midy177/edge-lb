<script setup lang="ts">
import { computed, ref } from 'vue'
import { Loader2, Plus, Save, Send, Trash2 } from 'lucide-vue-next'
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
import type { NotificationChannel, NotificationKind } from '@/api/types'
import { busy, notificationEvents, notifications, notificationsError, refreshNotificationData, run } from '@/composables/useNodeData'
import { t as text } from '@/lib/i18n'

const channelKinds: NotificationKind[] = [
  'webhook',
  'dingtalk',
  'feishu',
  'wecom',
  'telegram',
  'slack',
  'pushplus',
  'lanxin',
]

const selectedId = ref('')
const form = ref<NotificationChannel>(defaultChannel())
const eventsText = ref('*')
const configText = ref(defaultConfigText('webhook'))
const result = ref('')

const formError = computed(() => {
  if (!form.value.name.trim()) return text('notificationNameRequired')
  try {
    JSON.parse(configText.value || '{}')
  } catch {
    return text('notificationConfigInvalid')
  }
  return ''
})

function defaultChannel(): NotificationChannel {
  return {
    id: '',
    name: '',
    kind: 'webhook',
    enabled: true,
    events: ['*'],
    lang: 'zh',
    config: {},
    created_at_unix: 0,
    updated_at_unix: 0,
  }
}

function defaultConfigText(kind: NotificationKind) {
  switch (kind) {
    case 'dingtalk':
      return '{\n  "access_token": "",\n  "secret": ""\n}'
    case 'telegram':
      return '{\n  "bot_token": "",\n  "chat_id": ""\n}'
    case 'pushplus':
      return '{\n  "token": "",\n  "topic": ""\n}'
    default:
      return '{\n  "url": "",\n  "secret": ""\n}'
  }
}

function newChannel() {
  selectedId.value = ''
  form.value = defaultChannel()
  eventsText.value = '*'
  configText.value = defaultConfigText(form.value.kind)
  result.value = ''
}

async function editChannel(id: string) {
  const channel = await api.notification(id)
  selectedId.value = id
  form.value = channel
  eventsText.value = channel.events.join(', ')
  configText.value = JSON.stringify(channel.config || {}, null, 2)
  result.value = ''
}

function updateKind(kind: NotificationKind) {
  form.value.kind = kind
  if (!selectedId.value) {
    configText.value = defaultConfigText(kind)
  }
}

async function saveChannel() {
  const channel: NotificationChannel = {
    ...form.value,
    events: eventsText.value
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean),
    config: JSON.parse(configText.value || '{}') as Record<string, unknown>,
  }
  const saved = await api.saveNotification(channel)
  selectedId.value = saved.id
  form.value = saved
  eventsText.value = saved.events.join(', ')
  configText.value = JSON.stringify(saved.config || {}, null, 2)
  result.value = text('saved')
  await refreshNotificationData()
}

async function deleteChannel(id: string) {
  await api.deleteNotification(id)
  if (selectedId.value === id) {
    newChannel()
  }
  await refreshNotificationData()
}

async function testChannel() {
  if (!selectedId.value) return
  const delivery = await api.testNotification(selectedId.value)
  result.value = delivery.ok
    ? text('notificationTestOk')
    : `${text('notificationTestFailed')}: ${delivery.response}`
}
</script>

<template>
  <div class="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(420px,1fr)]">
    <Card>
      <CardHeader>
        <div class="flex items-center justify-between gap-3">
          <div>
            <CardTitle>{{ text('navNotifications') }}</CardTitle>
            <CardDescription>{{ text('notificationsDesc') }}</CardDescription>
          </div>
          <Button variant="outline" @click="newChannel">
            <Plus class="size-4" />
            {{ text('newNotification') }}
          </Button>
        </div>
      </CardHeader>
      <CardContent class="space-y-3">
        <div v-if="notificationsError" class="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
          {{ notificationsError }}
        </div>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{{ text('name') }}</TableHead>
              <TableHead>{{ text('type') }}</TableHead>
              <TableHead>{{ text('status') }}</TableHead>
              <TableHead>{{ text('events') }}</TableHead>
              <TableHead class="w-24"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="channel in notifications" :key="channel.id">
              <TableCell>
                <button class="text-left font-medium hover:underline" @click="editChannel(channel.id)">
                  {{ channel.name }}
                </button>
              </TableCell>
              <TableCell>{{ channel.kind }}</TableCell>
              <TableCell>
                <Badge :variant="channel.enabled ? 'success' : 'outline'">
                  {{ channel.enabled ? text('enabled') : text('disabled') }}
                </Badge>
              </TableCell>
              <TableCell class="max-w-[320px] truncate">{{ channel.events.join(', ') || '*' }}</TableCell>
              <TableCell>
                <div class="flex justify-end gap-1">
                  <Button variant="ghost" size="sm" @click="editChannel(channel.id)">{{ text('edit') }}</Button>
                  <Button variant="ghost" size="icon" :title="text('delete')" @click="deleteChannel(channel.id)">
                    <Trash2 class="size-4" />
                  </Button>
                </div>
              </TableCell>
            </TableRow>
            <TableRow v-if="!notifications.length">
              <TableCell colspan="5" class="text-muted-foreground">{{ text('empty') }}</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </CardContent>
    </Card>

    <Card>
      <CardHeader>
        <CardTitle>{{ selectedId ? text('editNotification') : text('newNotification') }}</CardTitle>
        <CardDescription>{{ text('notificationFormDesc') }}</CardDescription>
      </CardHeader>
      <CardContent class="space-y-4">
        <div class="flex items-center justify-between gap-3 rounded-md border p-3">
          <div class="space-y-1">
            <Label>{{ text('enabled') }}</Label>
            <p class="text-xs text-muted-foreground">{{ text('notificationEnabledDesc') }}</p>
          </div>
          <Switch v-model="form.enabled" />
        </div>

        <div class="space-y-1.5">
          <Label>{{ text('name') }}</Label>
          <Input v-model="form.name" :placeholder="text('required')" />
        </div>

        <div class="grid gap-4 md:grid-cols-2">
          <div class="space-y-1.5">
            <Label>{{ text('type') }}</Label>
            <Select :model-value="form.kind" @update:model-value="(value) => updateKind(value as NotificationKind)">
              <SelectTrigger class="w-full">
                <SelectValue :placeholder="text('type')" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem v-for="kind in channelKinds" :key="kind" :value="kind">{{ kind }}</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div class="space-y-1.5">
            <Label>{{ text('language') }}</Label>
            <Select v-model="form.lang">
              <SelectTrigger class="w-full">
                <SelectValue :placeholder="text('language')" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="zh">中文</SelectItem>
                <SelectItem value="en">English</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <div class="space-y-1.5">
          <Label>{{ text('events') }}</Label>
          <Input v-model="eventsText" placeholder="*, ha_switchover_succeeded" />
          <p class="text-xs leading-5 text-muted-foreground">
            {{ text('notificationEventsHint') }} {{ notificationEvents.join(', ') }}
          </p>
        </div>

        <div class="space-y-1.5">
          <Label>{{ text('configJson') }}</Label>
          <textarea
            v-model="configText"
            class="min-h-[180px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring"
            spellcheck="false"
          />
          <p class="text-xs text-muted-foreground">{{ text('notificationConfigHint') }}</p>
        </div>

        <p v-if="formError" class="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
          {{ formError }}
        </p>
        <p v-if="result" class="rounded-md border bg-muted/40 p-3 text-sm">{{ result }}</p>

        <div class="flex flex-wrap items-center gap-2">
          <Button
            :disabled="!!busy || !!formError"
            @click="
              run('notification-save', async () => {
                await saveChannel()
              })
            "
          >
            <Loader2 v-if="busy === 'notification-save'" class="animate-spin" />
            <Save v-else class="size-4" />
            {{ text('save') }}
          </Button>
          <Button
            variant="outline"
            :disabled="!!busy || !selectedId"
            @click="
              run('notification-test', async () => {
                await testChannel()
              })
            "
          >
            <Loader2 v-if="busy === 'notification-test'" class="animate-spin" />
            <Send v-else class="size-4" />
            {{ text('test') }}
          </Button>
        </div>
      </CardContent>
    </Card>
  </div>
</template>
