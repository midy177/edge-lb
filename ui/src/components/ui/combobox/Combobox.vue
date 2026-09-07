<script setup lang="ts">
import type { HTMLAttributes } from 'vue'
import {
  ComboboxAnchor,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxItemIndicator,
  ComboboxPortal,
  ComboboxRoot,
  ComboboxTrigger,
  ComboboxViewport,
  type AcceptableValue,
} from 'reka-ui'
import { Check, ChevronDown } from 'lucide-vue-next'
import { cn } from '@/lib/utils'
import type { ComboboxSuggestion } from './types'

// Free-text combobox: the input holds the value (typed or picked), the
// suggestion list is a convenience for known values. Unknown text stays in
// the model as-is, so callers validate it themselves (`invalid` only paints).

const props = withDefaults(
  defineProps<{
    modelValue?: string
    suggestions?: ComboboxSuggestion[]
    placeholder?: string
    emptyText?: string
    invalid?: boolean
    class?: HTMLAttributes['class']
  }>(),
  {
    modelValue: '',
    suggestions: () => [],
  },
)

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void
}>()

// Picked values display their suggestion label (e.g. "IP (node name)");
// free-typed text displays as-is.
function displayValue(value: AcceptableValue) {
  const key = String(value)
  return props.suggestions.find((item) => item.value === key)?.label ?? key
}

// Typing goes through the native input event so picking a suggestion (which
// reka-ui reflects into the input programmatically) is not double-emitted.
function onInput(event: Event) {
  emit('update:modelValue', (event.target as HTMLInputElement).value)
}
</script>

<template>
  <ComboboxRoot
    :model-value="props.modelValue"
    :display-value="displayValue"
    :ignore-filter="true"
    @update:model-value="(value: AcceptableValue) => emit('update:modelValue', String(value))"
  >
    <ComboboxAnchor
      :class="
        cn(
          'border-input dark:bg-input/30 flex h-9 w-full min-w-0 items-center rounded-md border bg-transparent shadow-xs transition-[color,box-shadow] outline-none focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50',
          props.invalid && 'border-destructive focus-within:ring-destructive/20',
          props.class,
        )
      "
    >
      <ComboboxInput
        class="h-full w-full bg-transparent px-3 py-1 text-base outline-none placeholder:text-muted-foreground md:text-sm"
        :placeholder="props.placeholder"
        @input="onInput"
      />
      <ComboboxTrigger
        class="flex h-full w-9 shrink-0 items-center justify-center text-muted-foreground transition-colors hover:text-foreground"
        aria-label="toggle suggestions"
      >
        <ChevronDown class="size-4" />
      </ComboboxTrigger>
    </ComboboxAnchor>
    <ComboboxPortal>
      <ComboboxContent
        position="popper"
        class="bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 relative z-50 max-h-(--reka-combobox-content-available-height) w-(--reka-combobox-trigger-width) min-w-[8rem] overflow-y-auto rounded-md border shadow-md data-[side=bottom]:translate-y-1 data-[side=left]:-translate-x-1 data-[side=right]:translate-x-1 data-[side=top]:-translate-y-1"
      >
        <ComboboxViewport class="p-1">
          <ComboboxItem
            v-for="item in props.suggestions"
            :key="item.value"
            :value="item.value"
            class="focus:bg-accent focus:text-accent-foreground relative flex w-full cursor-default items-center gap-2 rounded-sm py-1.5 pr-8 pl-2 text-sm outline-hidden select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50"
          >
            <span class="absolute right-2 flex size-3.5 items-center justify-center">
              <ComboboxItemIndicator>
                <Check class="size-4" />
              </ComboboxItemIndicator>
            </span>
            {{ item.label }}
          </ComboboxItem>
          <ComboboxEmpty class="px-2 py-4 text-center text-sm text-muted-foreground">
            {{ props.emptyText }}
          </ComboboxEmpty>
        </ComboboxViewport>
      </ComboboxContent>
    </ComboboxPortal>
  </ComboboxRoot>
</template>
