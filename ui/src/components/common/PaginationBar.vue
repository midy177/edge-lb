<script setup lang="ts">
import { computed } from 'vue'
import { Button, Input } from '@/components/ui'

const props = defineProps<{
  total: number
  page: number
  perPage: number
  q: string
}>()

const emit = defineEmits<{
  'update:page': [value: number]
  'update:q': [value: string]
  refresh: []
}>()

const pageCount = computed(() => Math.max(1, Math.ceil(props.total / Math.max(1, props.perPage))))
const canPrev = computed(() => props.page > 1)
const canNext = computed(() => props.page < pageCount.value)

function setQuery(value: string) {
  emit('update:q', value)
  emit('update:page', 1)
}

function prev() {
  if (canPrev.value) emit('update:page', props.page - 1)
}

function next() {
  if (canNext.value) emit('update:page', props.page + 1)
}
</script>

<template>
  <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
    <div class="flex w-full gap-2 sm:w-auto">
      <Input
        :model-value="q"
        class="h-9 w-full sm:w-72"
        placeholder="搜索"
        @update:model-value="(value) => setQuery(String(value))"
        @keyup.enter="emit('refresh')"
      />
      <Button size="sm" variant="outline" @click="emit('refresh')">搜索</Button>
    </div>
    <div class="flex items-center gap-2 text-sm text-muted-foreground">
      <span>共 {{ total }} 条 · 第 {{ page }} / {{ pageCount }} 页</span>
      <Button size="sm" variant="outline" :disabled="!canPrev" @click="prev">上一页</Button>
      <Button size="sm" variant="outline" :disabled="!canNext" @click="next">下一页</Button>
    </div>
  </div>
</template>
