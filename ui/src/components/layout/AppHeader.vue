<script setup lang="ts">
import { computed } from 'vue'
import { Languages, LogOut, RefreshCw } from 'lucide-vue-next'
import { Badge, Button, TabsList, TabsTrigger } from '@/components/ui'
import { lang, setLanguage, t as text } from '@/lib/i18n'
import { busy, isGateway, status, token, logout, type Tab } from '@/composables/useNodeData'

defineEmits<{ (e: 'refresh'): void }>()

const navItems = computed<{ id: Tab; label: string }[]>(() => [
  { id: 'overview', label: text('navOverview') },
  { id: 'nodes', label: text('navNodes') },
  ...(isGateway.value ? [{ id: 'automations' as Tab, label: text('navAutomations') }] : []),
  { id: 'listeners', label: text('navListeners') },
  { id: 'target-groups', label: text('navTargetGroups') },
  ...(isGateway.value ? [{ id: 'ha' as Tab, label: text('navHa') }] : []),
  ...(isGateway.value ? [{ id: 'notifications' as Tab, label: text('navNotifications') }] : []),
])
</script>

<template>
  <header class="border-b bg-background">
    <div class="mx-auto flex h-14 w-full items-center gap-4 px-6 md:w-[80vw]">
      <h1 class="text-lg font-semibold">Edge LB</h1>
      <Badge v-if="status" :variant="isGateway ? 'default' : 'secondary'">
        {{ isGateway ? text('gatewayNode') : text('backendNode') }} · {{ status.node_name }}
      </Badge>
      <Badge v-if="status" variant="outline">
        active: {{ status.active_gateway ?? text('unknown') }}
      </Badge>
      <div class="ml-auto flex items-center gap-2">
        <div class="flex items-center rounded-md border bg-muted/40 p-0.5">
          <Button
            variant="ghost"
            size="sm"
            :class="lang === 'zh' ? 'bg-background shadow-xs' : ''"
            title="中文"
            @click="setLanguage('zh')"
          >
            <Languages class="size-4" /> 中文
          </Button>
          <Button
            variant="ghost"
            size="sm"
            :class="lang === 'en' ? 'bg-background shadow-xs' : ''"
            title="English"
            @click="setLanguage('en')"
          >
            EN
          </Button>
        </div>
        <Button v-if="token" variant="ghost" size="sm" :title="text('logoutTitle')" @click="logout">
          <LogOut class="size-4" /> {{ text('logout') }}
        </Button>
        <Button variant="ghost" size="icon" :title="text('refreshTitle')" @click="$emit('refresh')">
          <RefreshCw :class="['size-4', busy ? 'animate-spin' : '']" />
        </Button>
      </div>
    </div>
    <nav class="mx-auto w-full px-6 py-2 md:w-[80vw]">
      <TabsList class="w-full justify-start">
        <TabsTrigger v-for="item in navItems" :key="item.id" :value="item.id">
          {{ item.label }}
        </TabsTrigger>
      </TabsList>
    </nav>
  </header>
</template>
