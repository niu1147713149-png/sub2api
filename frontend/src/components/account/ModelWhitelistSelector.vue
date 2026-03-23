<template>
  <div>
    <!-- Multi-select Dropdown -->
    <div class="relative mb-3">
      <div
        @click="toggleDropdown"
        class="cursor-pointer rounded-lg border border-gray-300 bg-white px-3 py-2 dark:border-dark-500 dark:bg-dark-700"
      >
        <div class="grid grid-cols-2 gap-1.5">
          <span
            v-for="model in modelValue"
            :key="model"
            class="inline-flex items-center justify-between gap-1 rounded bg-gray-100 px-2 py-1 text-xs text-gray-700 dark:bg-dark-600 dark:text-gray-300"
          >
            <span class="flex items-center gap-1 truncate">
              <ModelIcon :model="model" size="14px" />
              {{ model }}
            </span>
            <button type="button" @click.stop="removeModel(model)" class="text-gray-400 hover:text-red-500">
              <svg class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </span>
        </div>
        <div v-if="modelValue.length === 0" class="py-1 text-sm text-gray-400">
          {{ t('admin.accounts.selectModels') }}
        </div>
        <div class="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
          <svg class="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>
      <!-- Dropdown List -->
      <div
        v-if="showDropdown"
        class="absolute left-0 right-0 top-full z-50 mt-1 rounded-lg border border-gray-200 bg-white shadow-lg dark:border-dark-600 dark:bg-dark-700"
      >
        <div class="sticky top-0 border-b border-gray-200 bg-white p-2 dark:border-dark-600 dark:bg-dark-700">
          <input
            v-model="searchQuery"
            type="text"
            class="input w-full text-sm"
            :placeholder="t('admin.accounts.searchModels')"
          />
        </div>
        <div class="max-h-60 overflow-y-auto p-1">
          <button
            v-for="model in filteredModels"
            :key="model.value"
            type="button"
            @click="toggleModel(model.value)"
            class="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-gray-100 dark:hover:bg-dark-600"
          >
            <span
              :class="[
                'flex h-4 w-4 shrink-0 items-center justify-center rounded border',
                modelValue.includes(model.value)
                  ? 'border-primary-500 bg-primary-500 text-white'
                  : 'border-gray-300 dark:border-dark-500'
              ]"
            >
              <svg v-if="modelValue.includes(model.value)" class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7" />
              </svg>
            </span>
            <ModelIcon :model="model.value" size="18px" />
            <span class="truncate text-gray-900 dark:text-white">{{ model.value }}</span>
          </button>
          <div v-if="filteredModels.length === 0" class="px-3 py-4 text-center text-sm text-gray-500">
            {{ t('admin.accounts.noMatchingModels') }}
          </div>
        </div>
      </div>
    </div>

    <!-- Quick Actions -->
    <div class="mb-4 flex flex-wrap gap-2">
      <button
        type="button"
        @click="fillRelated"
        class="rounded-lg border border-blue-200 px-3 py-1.5 text-sm text-blue-600 hover:bg-blue-50 dark:border-blue-800 dark:text-blue-400 dark:hover:bg-blue-900/30"
      >
        {{ t('admin.accounts.fillRelatedModels') }}
      </button>
      <button
        type="button"
        @click="clearAll"
        class="rounded-lg border border-red-200 px-3 py-1.5 text-sm text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-900/30"
      >
        {{ t('admin.accounts.clearAllModels') }}
      </button>
      <button
        v-if="accountId"
        type="button"
        @click="fetchUpstream"
        :disabled="fetchingUpstream"
        class="rounded-lg border border-green-200 px-3 py-1.5 text-sm text-green-600 hover:bg-green-50 disabled:opacity-50 dark:border-green-800 dark:text-green-400 dark:hover:bg-green-900/30"
      >
        <Icon v-if="fetchingUpstream" name="sync" class="mr-1 inline h-3 w-3 animate-spin" />
        {{ t('admin.accounts.fetchUpstreamModels') }}
      </button>
    </div>

    <!-- Upstream Model Picker Modal -->
    <Teleport to="body">
      <div v-if="showUpstreamPicker" class="fixed inset-0 z-[9999] flex items-center justify-center">
        <!-- Backdrop -->
        <div class="absolute inset-0 bg-black/50" @click="showUpstreamPicker = false"></div>
        <!-- Modal -->
        <div class="relative mx-4 w-full max-w-lg rounded-xl bg-white p-6 shadow-2xl dark:bg-dark-800">
          <div class="mb-4 flex items-center justify-between">
            <h3 class="text-lg font-medium text-gray-900 dark:text-white">
              {{ t('admin.accounts.selectModelProvider') }}
            </h3>
            <button type="button" @click="showUpstreamPicker = false" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
              <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <p class="mb-4 text-sm text-gray-500 dark:text-gray-400">
            {{ t('admin.accounts.upstreamModelsTotal', { count: upstreamModels.length }) }}
          </p>
          <!-- Select / Deselect All -->
          <div class="mb-3 flex gap-3">
            <button type="button" @click="selectAllProviders" class="text-sm text-green-600 hover:underline dark:text-green-400">
              {{ t('admin.accounts.selectAll') }}
            </button>
            <button type="button" @click="selectedProviders.clear()" class="text-sm text-gray-500 hover:underline dark:text-gray-400">
              {{ t('admin.accounts.deselectAll') }}
            </button>
          </div>
          <!-- Provider Grid -->
          <div class="mb-5 grid grid-cols-2 gap-2 sm:grid-cols-3">
            <button
              v-for="provider in upstreamProviders"
              :key="provider.name"
              type="button"
              @click="toggleProvider(provider.name)"
              class="flex items-center justify-between rounded-lg border px-3 py-2 text-sm transition-colors"
              :class="selectedProviders.has(provider.name)
                ? 'border-green-500 bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300'
                : 'border-gray-200 text-gray-700 hover:border-green-300 dark:border-dark-500 dark:text-gray-300'"
            >
              <span class="truncate">{{ provider.name }}</span>
              <span class="ml-1 shrink-0 rounded-full bg-gray-200 px-1.5 py-0.5 text-xs dark:bg-dark-500">
                {{ provider.count }}
              </span>
            </button>
          </div>
          <!-- Footer -->
          <div class="flex justify-end gap-3">
            <button type="button" @click="showUpstreamPicker = false"
              class="rounded-lg border border-gray-300 px-4 py-2 text-sm text-gray-600 hover:bg-gray-100 dark:border-dark-500 dark:text-gray-400 dark:hover:bg-dark-600">
              {{ t('common.cancel') }}
            </button>
            <button type="button" @click="addSelectedProviderModels" :disabled="selectedProviders.size === 0"
              class="rounded-lg bg-green-600 px-4 py-2 text-sm text-white hover:bg-green-700 disabled:opacity-50">
              {{ t('admin.accounts.addSelectedModels') }}
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Custom Model Input -->
    <div>
      <div class="flex gap-2">
        <input
          v-model="customModel"
          type="text"
          class="input flex-1"
          :placeholder="t('admin.accounts.enterCustomModelName')"
          @keydown.enter.prevent="handleEnter"
          @compositionstart="isComposing = true"
          @compositionend="isComposing = false"
        />
        <button
          type="button"
          @click="addCustom"
          class="rounded-lg bg-primary-50 px-4 py-2 text-sm font-medium text-primary-600 hover:bg-primary-100 dark:bg-primary-900/30 dark:text-primary-400 dark:hover:bg-primary-900/50"
        >
          {{ t('admin.accounts.addModel') }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAppStore } from '@/stores/app'
import ModelIcon from '@/components/common/ModelIcon.vue'
import Icon from '@/components/icons/Icon.vue'
import { getModelsByPlatform } from '@/composables/useModelWhitelist'
import { fetchUpstreamModels } from '@/api/admin/accounts'

const { t } = useI18n()
const appStore = useAppStore()

const props = defineProps<{
  modelValue: string[]
  platform: string
  accountId?: number
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: string[]): void
}>()

const showDropdown = ref(false)
const searchQuery = ref('')
const customModel = ref('')
const isComposing = ref(false)

const toggleDropdown = () => { showDropdown.value = !showDropdown.value }

const platformModels = computed(() => {
  const models = getModelsByPlatform(props.platform)
  return models.map(m => ({ value: m, label: m }))
})

const filteredModels = computed(() => {
  if (!searchQuery.value) return platformModels.value
  const q = searchQuery.value.toLowerCase()
  return platformModels.value.filter(m => m.value.toLowerCase().includes(q))
})

const toggleModel = (model: string) => {
  const newModels = [...props.modelValue]
  const idx = newModels.indexOf(model)
  if (idx >= 0) newModels.splice(idx, 1)
  else newModels.push(model)
  emit('update:modelValue', newModels)
}

const removeModel = (model: string) => {
  emit('update:modelValue', props.modelValue.filter(m => m !== model))
}

const addCustom = () => {
  const model = customModel.value.trim()
  if (!model) return
  if (!props.modelValue.includes(model)) {
    emit('update:modelValue', [...props.modelValue, model])
  }
  customModel.value = ''
}

const handleEnter = () => {
  if (isComposing.value) return
  addCustom()
}

const fillRelated = () => {
  const models = getModelsByPlatform(props.platform)
  const newModels = [...props.modelValue]
  for (const model of models) {
    if (!newModels.includes(model)) newModels.push(model)
  }
  emit('update:modelValue', newModels)
}

const clearAll = () => {
  emit('update:modelValue', [])
}

// --- Upstream model picker ---
const fetchingUpstream = ref(false)
const showUpstreamPicker = ref(false)
const upstreamModels = ref<{ id: string; display_name?: string }[]>([])
const selectedProviders = ref(new Set<string>())

function getProviderFromModel(modelId: string): string {
  const lower = modelId.toLowerCase()
  if (lower.startsWith('gpt-') || lower.startsWith('o1-') || lower.startsWith('o3-') || lower.startsWith('o4-') || lower.startsWith('dall-e') || lower.startsWith('tts-') || lower.startsWith('whisper')) return 'OpenAI'
  if (lower.startsWith('claude-')) return 'Anthropic'
  if (lower.startsWith('gemini-') || lower.startsWith('gemma-')) return 'Google'
  if (lower.startsWith('llama') || lower.startsWith('meta-llama')) return 'Meta'
  if (lower.startsWith('mistral') || lower.startsWith('mixtral') || lower.startsWith('codestral') || lower.startsWith('pixtral')) return 'Mistral'
  if (lower.startsWith('qwen')) return 'Qwen'
  if (lower.startsWith('deepseek')) return 'DeepSeek'
  if (lower.startsWith('yi-')) return 'Yi'
  if (lower.startsWith('glm') || lower.startsWith('chatglm')) return 'GLM'
  if (lower.startsWith('command-') || lower.startsWith('embed-')) return 'Cohere'
  if (lower.startsWith('phi-')) return 'Microsoft'
  if (lower.startsWith('jamba')) return 'AI21'
  const sep = modelId.indexOf('/')
  if (sep > 0) return modelId.substring(0, sep)
  return 'Other'
}

const upstreamProviders = computed(() => {
  const map = new Map<string, number>()
  for (const m of upstreamModels.value) {
    const p = getProviderFromModel(m.id)
    map.set(p, (map.get(p) || 0) + 1)
  }
  return Array.from(map.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
})

const toggleProvider = (provider: string) => {
  if (selectedProviders.value.has(provider)) {
    selectedProviders.value.delete(provider)
  } else {
    selectedProviders.value.add(provider)
  }
}

const selectAllProviders = () => {
  for (const p of upstreamProviders.value) {
    selectedProviders.value.add(p.name)
  }
}

const addSelectedProviderModels = () => {
  const newModels = [...props.modelValue]
  for (const m of upstreamModels.value) {
    if (selectedProviders.value.has(getProviderFromModel(m.id)) && !newModels.includes(m.id)) {
      newModels.push(m.id)
    }
  }
  const added = newModels.length - props.modelValue.length
  emit('update:modelValue', newModels)
  appStore.showSuccess(t('admin.accounts.fetchUpstreamModelsSuccess', { count: added }))
  showUpstreamPicker.value = false
  selectedProviders.value.clear()
}

const fetchUpstream = async () => {
  if (!props.accountId) return
  fetchingUpstream.value = true
  try {
    const models = await fetchUpstreamModels(props.accountId)
    upstreamModels.value = models
    selectedProviders.value.clear()
    showUpstreamPicker.value = true
  } catch {
    appStore.showError(t('admin.accounts.fetchUpstreamModelsFailed'))
  } finally {
    fetchingUpstream.value = false
  }
}
</script>
