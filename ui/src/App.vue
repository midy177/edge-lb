<script setup lang="ts">
import { computed, onMounted, onUnmounted, watch } from 'vue'
import { AlertTriangle, Loader2, LogIn, RefreshCw, X } from 'lucide-vue-next'
import faviconUrl from '../favicon.svg?url'
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
  Tabs,
} from '@/components/ui'
import AppHeader from '@/components/layout/AppHeader.vue'
import AutomationsPage from '@/components/automations/AutomationsPage.vue'
import TargetGroupsPage from '@/components/target-groups/TargetGroupsPage.vue'
import HaPage from '@/components/ha/HaPage.vue'
import ListenersPage from '@/components/listeners/ListenersPage.vue'
import NodesPage from '@/components/nodes/NodesPage.vue'
import NotificationsPage from '@/components/notifications/NotificationsPage.vue'
import OverviewPage from '@/components/overview/OverviewPage.vue'
import { lang, setLanguage, t as text } from '@/lib/i18n'
import {
  authRequired,
  authenticated,
  busy,
  cancelProxySync,
  error,
  failoverTarget,
  login,
  proxyWriteStatus,
  retryProxySync,
  refreshAll,
  refreshForTab,
  run,
  status,
  tab,
  token,
  type Tab,
} from '@/composables/useNodeData'

// reka-ui 的 modelValue 是 string，tab 是字面量联合，用 computed 收窄回写类型。
const tabModel = computed({
  get: () => tab.value,
  set: (value: string) => {
    tab.value = value as Tab
  },
})

// status + 当前 tab 数据;认证与错误状态在 refreshAll 内收敛。
async function refresh() {
  await refreshAll(tab.value)
  if (!failoverTarget.value && status.value?.active_gateway) {
    failoverTarget.value = status.value.active_gateway
  }
}

onMounted(() => {
  refresh()
})
onUnmounted(cancelProxySync)
watch(tab, () => {
  refreshForTab(tab.value)
})
</script>

<template>
  <div class="min-h-screen bg-muted/40">
    <main
      v-if="authRequired && !authenticated"
      class="mx-auto grid min-h-screen w-full place-items-center px-6 py-10 md:w-[80vw]"
    >
      <Card class="w-full max-w-105 border-border/70 shadow-lg shadow-black/5">
        <CardHeader class="space-y-5 pb-4">
          <div class="flex items-center justify-between gap-3">
            <Badge variant="outline">{{ text('consoleBadge') }}</Badge>
            <div class="flex items-center rounded-md border bg-muted/40 p-0.5">
              <Button
                variant="ghost"
                size="sm"
                :class="lang === 'zh' ? 'h-7 bg-background px-2 shadow-xs' : 'h-7 px-2'"
                title="中文"
                @click="setLanguage('zh')"
              >
                中文
              </Button>
              <Button
                variant="ghost"
                size="sm"
                :class="lang === 'en' ? 'h-7 bg-background px-2 shadow-xs' : 'h-7 px-2'"
                title="English"
                @click="setLanguage('en')"
              >
                EN
              </Button>
            </div>
          </div>
          <div class="flex items-start gap-3">
            <div class="flex size-12 shrink-0 items-center justify-center rounded-md border bg-background p-0">
              <img :src="faviconUrl" class="size-full" alt="Edge LB" />
            </div>
            <div class="min-w-0 space-y-1">
              <CardTitle class="text-xl leading-7">{{ text('loginTitle') }}</CardTitle>
              <CardDescription class="text-sm leading-5">{{ text('loginDesc') }}</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent class="space-y-4 pt-0">
          <form
            class="space-y-4"
            @submit.prevent="
              run('login', async () => {
                await login()
              })
            "
          >
            <div class="space-y-2">
              <div class="flex items-center justify-between gap-3">
                <Label>{{ text('apiToken') }}</Label>
                <span class="text-xs text-muted-foreground">{{ text('secureAccess') }}</span>
              </div>
              <Input
                v-model="token"
                class="h-10 font-mono text-sm"
                type="password"
                placeholder="Bearer token"
                autocomplete="current-password"
                autofocus
              />
              <p class="text-xs leading-5 text-muted-foreground">{{ text('tokenHelp') }}</p>
            </div>
            <Button class="h-10 w-full" type="submit" :disabled="!token || !!busy">
              <Loader2 v-if="busy === 'login'" class="animate-spin" />
              <LogIn v-else />
              {{ text('login') }}
            </Button>
          </form>
          <p v-if="error" class="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {{ error }}
          </p>
        </CardContent>
      </Card>
    </main>

    <template v-else>
      <Tabs v-model="tabModel">
        <AppHeader @refresh="refresh" />

        <main class="mx-auto w-full space-y-4 px-6 py-6 md:w-[80vw]">
          <div v-if="proxyWriteStatus" role="status" aria-live="polite"
            class="flex flex-wrap items-center gap-2 border-l-2 border-primary bg-muted px-4 py-2 text-sm">
            <Loader2 v-if="proxyWriteStatus.state === 'waiting'" class="size-4 shrink-0 animate-spin" />
            <span class="min-w-0 flex-1 break-words">
              {{ text('proxyWriteSaved') }} {{ proxyWriteStatus.authority }}.
              {{ text(`proxySync_${proxyWriteStatus.state}`) }}
            </span>
            <Button v-if="proxyWriteStatus.state === 'unconfirmed'" variant="ghost" size="icon"
              :title="text('proxySyncCheck')" @click="retryProxySync"><RefreshCw /></Button>
            <Button variant="ghost" size="icon" :title="text('close')" @click="cancelProxySync"><X /></Button>
          </div>
          <div
            v-if="error"
            class="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-2 text-sm text-destructive"
          >
            <AlertTriangle class="size-4" /> {{ error }}
          </div>

          <section v-if="tab === 'overview'" role="tabpanel" class="flex-1 outline-none">
            <OverviewPage />
          </section>

          <section v-if="tab === 'nodes'" role="tabpanel" class="flex-1 outline-none">
            <NodesPage />
          </section>

          <section v-if="tab === 'target-groups'" role="tabpanel" class="flex-1 outline-none">
            <TargetGroupsPage />
          </section>

          <section v-if="tab === 'listeners'" role="tabpanel" class="flex-1 outline-none">
            <ListenersPage />
          </section>

          <section v-if="tab === 'automations'" role="tabpanel" class="flex-1 outline-none">
            <AutomationsPage />
          </section>

          <section v-if="tab === 'ha'" role="tabpanel" class="flex-1 outline-none">
            <HaPage />
          </section>

          <section v-if="tab === 'notifications'" role="tabpanel" class="flex-1 outline-none">
            <NotificationsPage />
          </section>
        </main>
      </Tabs>
    </template>
  </div>
</template>
