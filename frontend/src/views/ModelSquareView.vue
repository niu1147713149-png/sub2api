<template>
  <AppLayout>
    <div class="model-table-section px-2 md:px-6 py-6 max-w-[1400px] mx-auto">
      <!-- Hero Section with Animated Gradient -->
      <div class="hero-section relative mb-8 overflow-hidden rounded-2xl p-8 border border-primary-200/50 dark:border-primary-800/50">
        <!-- Animated gradient background -->
        <div class="hero-gradient absolute inset-0"></div>
        <!-- Grid pattern -->
        <div class="absolute inset-0 bg-grid-pattern opacity-5"></div>
        <!-- Floating orbs -->
        <div class="hero-orb hero-orb-1"></div>
        <div class="hero-orb hero-orb-2"></div>
        <div class="hero-orb hero-orb-3"></div>
        <div class="relative">
          <h1 class="text-3xl font-bold text-gray-900 dark:text-white mb-2 flex items-center gap-3">
            <span class="hero-icon inline-flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-primary-500 to-purple-600 text-white shadow-lg">
              <svg class="w-6 h-6 hero-sparkle" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z" />
              </svg>
            </span>
            {{ t('modelSquare.title') }}
          </h1>
          <p class="text-gray-600 dark:text-gray-400">{{ t('modelSquare.subtitle') }}</p>
        </div>
      </div>

      <!-- Loading Skeleton -->
      <div v-if="loading" class="space-y-4">
        <div class="flex gap-2 animate-pulse">
          <div class="h-10 bg-gray-200 dark:bg-dark-700 rounded-lg flex-1"></div>
          <div class="h-10 bg-gray-200 dark:bg-dark-700 rounded-lg w-32"></div>
          <div class="h-10 bg-gray-200 dark:bg-dark-700 rounded-lg w-32"></div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <div v-for="i in 6" :key="i" class="h-48 bg-gray-200 dark:bg-dark-700 rounded-xl animate-pulse"></div>
        </div>
      </div>

      <template v-else>
        <!-- Toolbar: Search + Filters + View Toggle -->
        <div class="mb-6">
          <div class="flex flex-wrap items-center gap-2">
            <!-- Search Input -->
            <div class="relative flex-1 min-w-[200px]">
              <svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 dark:text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <circle cx="11" cy="11" r="8" />
                <path d="m21 21-4.3-4.3" stroke-linecap="round" />
              </svg>
              <input
                v-model="searchQuery"
                type="text"
                :placeholder="t('modelSquare.searchPlaceholder')"
                class="w-full pl-9 pr-4 py-2 rounded-lg text-sm bg-white dark:bg-dark-800 border border-gray-200 dark:border-dark-600 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500/30 transition-all"
              />
            </div>

            <!-- Group Filter Dropdown -->
            <div class="relative" ref="groupDropdownRef">
              <button
                @click="showGroupDropdown = !showGroupDropdown"
                class="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all bg-white dark:bg-dark-800 text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white border border-gray-200 dark:border-dark-600 hover:border-gray-300 dark:hover:border-dark-500"
                :class="{ '!border-primary-500 !text-primary-600 dark:!text-primary-400': selectedGroupID !== null }"
              >
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="M18 21a8 8 0 0 0-16 0" /><circle cx="10" cy="8" r="5" /><path d="M22 20c0-3.37-2-6.5-4-8a5 5 0 0 0-.45-8.3" />
                </svg>
                {{ selectedGroupName }}
                <svg class="w-3.5 h-3.5 transition-transform" :class="{ 'rotate-180': showGroupDropdown }" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="m6 9 6 6 6-6" />
                </svg>
              </button>
              <transition name="dropdown">
                <div v-if="showGroupDropdown" class="absolute top-full left-0 mt-1 z-50 w-56 max-h-72 overflow-y-auto bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 shadow-lg py-1">
                  <button
                    @click="selectedGroupID = null; showGroupDropdown = false"
                    class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
                    :class="selectedGroupID === null ? 'text-primary-600 dark:text-primary-400 font-medium' : 'text-gray-700 dark:text-gray-300'"
                  >
                    {{ t('modelSquare.allGroups') }}
                  </button>
                  <button
                    v-for="group in groups"
                    :key="group.id"
                    @click="selectedGroupID = group.id; showGroupDropdown = false"
                    class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors flex items-center justify-between"
                    :class="selectedGroupID === group.id ? 'text-primary-600 dark:text-primary-400 font-medium' : 'text-gray-700 dark:text-gray-300'"
                  >
                    <span class="flex items-center gap-1.5">
                      {{ group.name }}
                      <span v-if="group.rate_multiplier && group.rate_multiplier !== 1" class="text-[10px] px-1 py-0.5 rounded bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">{{ formatRate(group.rate_multiplier) }}</span>
                    </span>
                    <span class="text-xs text-gray-400 dark:text-gray-500">{{ group.platform }}</span>
                  </button>
                </div>
              </transition>
            </div>

            <!-- Provider Filter Dropdown -->
            <div class="relative" ref="providerDropdownRef">
              <button
                @click="showProviderDropdown = !showProviderDropdown"
                class="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all bg-white dark:bg-dark-800 text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white border border-gray-200 dark:border-dark-600 hover:border-gray-300 dark:hover:border-dark-500"
                :class="{ '!border-primary-500 !text-primary-600 dark:!text-primary-400': selectedProvider }"
              >
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
                </svg>
                {{ selectedProvider || t('modelSquare.provider') }}
                <svg class="w-3.5 h-3.5 transition-transform" :class="{ 'rotate-180': showProviderDropdown }" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="m6 9 6 6 6-6" />
                </svg>
              </button>
              <transition name="dropdown">
                <div v-if="showProviderDropdown" class="absolute top-full left-0 mt-1 z-50 w-56 max-h-72 overflow-y-auto bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 shadow-lg py-1">
                  <button
                    @click="selectedProvider = ''; showProviderDropdown = false"
                    class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
                    :class="selectedProvider === '' ? 'text-primary-600 dark:text-primary-400 font-medium' : 'text-gray-700 dark:text-gray-300'"
                  >
                    {{ t('modelSquare.allProviders') }}
                  </button>
                  <button
                    v-for="provider in providerList"
                    :key="provider.name"
                    @click="selectedProvider = provider.name; showProviderDropdown = false"
                    class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors flex items-center justify-between"
                    :class="selectedProvider === provider.name ? 'text-primary-600 dark:text-primary-400 font-medium' : 'text-gray-700 dark:text-gray-300'"
                  >
                    <span class="flex items-center gap-2">
                      <span class="w-2 h-2 rounded-full flex-shrink-0" :style="{ backgroundColor: providerDotColor(provider.name) }"></span>
                      {{ provider.name }}
                    </span>
                    <span class="text-xs text-gray-400 dark:text-gray-500">{{ provider.count }}</span>
                  </button>
                </div>
              </transition>
            </div>

            <!-- Type Filter Dropdown -->
            <div class="relative" ref="modeDropdownRef">
              <button
                @click="showModeDropdown = !showModeDropdown"
                class="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all bg-white dark:bg-dark-800 text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white border border-gray-200 dark:border-dark-600 hover:border-gray-300 dark:hover:border-dark-500"
                :class="{ '!border-primary-500 !text-primary-600 dark:!text-primary-400': selectedMode }"
              >
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z" />
                  <path d="M20 3v4" /><path d="M22 5h-4" />
                  <path d="M4 17v2" /><path d="M5 18H3" />
                </svg>
                {{ selectedMode ? modeBadgeLabel(selectedMode) : t('modelSquare.type') }}
                <svg class="w-3.5 h-3.5 transition-transform" :class="{ 'rotate-180': showModeDropdown }" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="m6 9 6 6 6-6" />
                </svg>
              </button>
              <transition name="dropdown">
                <div v-if="showModeDropdown" class="absolute top-full left-0 mt-1 z-50 w-48 bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 shadow-lg py-1">
                  <button
                    @click="selectedMode = ''; showModeDropdown = false"
                    class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
                    :class="selectedMode === '' ? 'text-primary-600 dark:text-primary-400 font-medium' : 'text-gray-700 dark:text-gray-300'"
                  >
                    {{ t('modelSquare.filterByType') }}
                  </button>
                  <button
                    v-for="mode in modeList"
                    :key="mode.name"
                    @click="selectedMode = mode.name; showModeDropdown = false"
                    class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors flex items-center justify-between"
                    :class="selectedMode === mode.name ? 'text-primary-600 dark:text-primary-400 font-medium' : 'text-gray-700 dark:text-gray-300'"
                  >
                    <span>{{ modeBadgeLabel(mode.name) }}</span>
                    <span class="text-xs text-gray-400 dark:text-gray-500">{{ mode.count }}</span>
                  </button>
                </div>
              </transition>
            </div>

            <!-- Sort Dropdown -->
            <div class="relative" ref="sortDropdownRef">
              <button
                @click="showSortDropdown = !showSortDropdown"
                class="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all bg-white dark:bg-dark-800 text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white border border-gray-200 dark:border-dark-600 hover:border-gray-300 dark:hover:border-dark-500"
              >
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="m21 16-4 4-4-4" /><path d="M17 20V4" />
                  <path d="m3 8 4-4 4 4" /><path d="M7 4v16" />
                </svg>
                {{ sortLabels[sortKey] || t('modelSquare.modelName') }}
                <svg class="w-3.5 h-3.5 transition-transform" :class="{ 'rotate-180': showSortDropdown }" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="m6 9 6 6 6-6" />
                </svg>
              </button>
              <transition name="dropdown">
                <div v-if="showSortDropdown" class="absolute top-full left-0 mt-1 z-50 w-48 bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 shadow-lg py-1">
                  <button
                    v-for="(label, key) in sortLabels"
                    :key="key"
                    @click="toggleSort(key); showSortDropdown = false"
                    class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors flex items-center justify-between"
                    :class="sortKey === key ? 'text-primary-600 dark:text-primary-400 font-medium' : 'text-gray-700 dark:text-gray-300'"
                  >
                    <span>{{ label }}</span>
                    <svg v-if="sortKey === key" class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                      <path v-if="sortDir === 'asc'" d="m3 8 4-4 4 4" /><path v-if="sortDir === 'asc'" d="M7 4v16" />
                      <path v-if="sortDir === 'desc'" d="m21 16-4 4-4-4" /><path v-if="sortDir === 'desc'" d="M17 20V4" />
                    </svg>
                  </button>
                </div>
              </transition>
            </div>

            <!-- View Toggle -->
            <div class="flex items-center gap-1 p-1 rounded-lg bg-gray-100 dark:bg-dark-800 border border-gray-200 dark:border-dark-600">
              <button
                @click="viewMode = 'grid'"
                class="p-2 rounded-md transition-all"
                :class="viewMode === 'grid' ? 'bg-white dark:bg-dark-700 text-primary-600 dark:text-primary-400 shadow-sm' : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'"
                title="Grid View"
              >
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <rect width="7" height="7" x="3" y="3" rx="1" />
                  <rect width="7" height="7" x="14" y="3" rx="1" />
                  <rect width="7" height="7" x="14" y="14" rx="1" />
                  <rect width="7" height="7" x="3" y="14" rx="1" />
                </svg>
              </button>
              <button
                @click="viewMode = 'table'"
                class="p-2 rounded-md transition-all"
                :class="viewMode === 'table' ? 'bg-white dark:bg-dark-700 text-primary-600 dark:text-primary-400 shadow-sm' : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'"
                title="Table View"
              >
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="M3 6h18" /><path d="M3 12h18" /><path d="M3 18h18" />
                </svg>
              </button>
            </div>

            <!-- Model Count -->
            <div class="ml-auto text-sm font-medium">
              <span class="text-gray-900 dark:text-white tabular-nums">{{ animatedModelCount.toLocaleString() }}</span>
              <span class="text-gray-500 dark:text-gray-400 ml-1">{{ t('modelSquare.modelsAvailable') }}</span>
            </div>
          </div>
        </div>

        <!-- Grid View -->
        <TransitionGroup
          v-if="viewMode === 'grid' && filteredModels.length > 0"
          tag="div"
          name="card-list"
          class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"
          appear
        >
          <div
            v-for="(model, index) in paginatedModels"
            :key="model.id"
            class="model-card group relative rounded-xl border border-gray-200 dark:border-dark-700 bg-white dark:bg-dark-800/50 p-5 cursor-pointer overflow-hidden"
            :class="{ 'opacity-60': !model.available }"
            :style="{ '--card-delay': `${index * 50}ms` }"
            @click="copyModelName(model.id)"
            @mouseenter="handleCardHover($event, true)"
            @mouseleave="handleCardHover($event, false)"
          >
            <!-- Shimmer effect on hover -->
            <div class="card-shimmer absolute inset-0 pointer-events-none"></div>
            <!-- Gradient Overlay on Hover -->
            <div class="absolute inset-0 bg-gradient-to-br from-primary-500/5 via-purple-500/5 to-pink-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>

            <!-- Content -->
            <div class="relative space-y-3">
              <!-- Header -->
              <div class="flex items-start justify-between gap-2">
                <div class="flex-1 min-w-0">
                  <div class="flex items-center gap-2 mb-1">
                    <span class="w-2 h-2 rounded-full flex-shrink-0" :style="{ backgroundColor: providerDotColor(model.provider) }"></span>
                    <span class="text-xs font-medium text-gray-600 dark:text-gray-400">{{ model.provider || '—' }}</span>
                  </div>
                  <h3 class="font-semibold text-gray-900 dark:text-white text-sm truncate group-hover:text-primary-600 dark:group-hover:text-primary-400 transition-colors">
                    {{ model.id }}
                  </h3>
                </div>
                <div class="flex-shrink-0">
                  <span v-if="model.available" class="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-medium bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 blink-dot"></span>
                    {{ t('modelSquare.available') }}
                  </span>
                  <span v-else class="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-medium bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-500">
                    <span class="w-1.5 h-1.5 rounded-full bg-gray-400"></span>
                    {{ t('modelSquare.unavailable') }}
                  </span>
                </div>
              </div>

              <!-- Pricing Grid -->
              <div class="grid grid-cols-2 gap-2">
                <div class="rounded-lg bg-gray-50 dark:bg-dark-900/50 p-2.5 border border-gray-100 dark:border-dark-700">
                  <div class="text-[10px] text-gray-500 dark:text-gray-400 mb-0.5">{{ t('modelSquare.input') }}</div>
                  <div class="font-mono text-sm font-semibold text-gray-900 dark:text-white">{{ formatPrice(model.input_price, getModelRate(model)) }}</div>
                  <div class="text-[9px] text-gray-400 dark:text-gray-500">$/M tokens</div>
                </div>
                <div class="rounded-lg bg-gray-50 dark:bg-dark-900/50 p-2.5 border border-gray-100 dark:border-dark-700">
                  <div class="text-[10px] text-gray-500 dark:text-gray-400 mb-0.5">{{ t('modelSquare.output') }}</div>
                  <div class="font-mono text-sm font-semibold text-gray-900 dark:text-white">{{ formatPrice(model.output_price, getModelRate(model)) }}</div>
                  <div class="text-[9px] text-gray-400 dark:text-gray-500">$/M tokens</div>
                </div>
              </div>

              <!-- Cache Pricing (if available) -->
              <div v-if="model.cache_read_price != null || model.cache_create_price != null" class="grid grid-cols-2 gap-2">
                <div v-if="model.cache_read_price != null" class="rounded-lg bg-blue-50 dark:bg-blue-900/20 p-2 border border-blue-100 dark:border-blue-800">
                  <div class="text-[9px] text-blue-600 dark:text-blue-400 mb-0.5">Cache Read</div>
                  <div class="font-mono text-xs font-semibold text-blue-700 dark:text-blue-300">{{ formatPrice(model.cache_read_price, getModelRate(model)) }}</div>
                </div>
                <div v-if="model.cache_create_price != null" class="rounded-lg bg-purple-50 dark:bg-purple-900/20 p-2 border border-purple-100 dark:border-purple-800">
                  <div class="text-[9px] text-purple-600 dark:text-purple-400 mb-0.5">Cache Write</div>
                  <div class="font-mono text-xs font-semibold text-purple-700 dark:text-purple-300">{{ formatPrice(model.cache_create_price, getModelRate(model)) }}</div>
                </div>
              </div>

              <!-- Per-Usage Pricing (Sora / Image Generation) -->
              <div v-if="getModelPerUsagePricing(model)" class="rounded-lg bg-amber-50 dark:bg-amber-900/15 p-2.5 border border-amber-200 dark:border-amber-800/50">
                <div class="flex items-center gap-1.5 mb-2">
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-semibold bg-amber-200 text-amber-800 dark:bg-amber-800/40 dark:text-amber-300">{{ t('modelSquare.perUsage') }}</span>
                  <span class="text-[9px] text-amber-600 dark:text-amber-400">{{ getModelPerUsagePricing(model)!.type === 'sora' ? 'Sora' : t('modelSquare.perImage') }}</span>
                </div>
                <div class="grid grid-cols-2 gap-1.5">
                  <div v-for="item in getModelPerUsagePricing(model)!.items" :key="item.label" class="flex items-center justify-between gap-1 rounded bg-amber-100/60 dark:bg-amber-900/20 px-2 py-1">
                    <span class="text-[9px] text-amber-700 dark:text-amber-400">{{ item.label }}</span>
                    <span class="font-mono text-[11px] font-semibold text-amber-800 dark:text-amber-300">{{ formatPerUsagePrice(item.price) }}</span>
                  </div>
                </div>
              </div>

              <!-- Footer -->
              <div class="flex items-center justify-between pt-2 border-t border-gray-100 dark:border-dark-700">
                <span v-if="model.mode" class="inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-medium" :class="modeBadgeClass(model.mode)">
                  {{ modeBadgeLabel(model.mode) }}
                </span>
                <div class="flex items-center gap-1">
                  <span
                    v-for="gid in model.group_ids?.slice(0, 2)"
                    :key="gid"
                    class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-medium bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-400"
                  >
                    {{ groupNameMap[gid] || gid }}
                    <span v-if="groupRateMap[gid] && groupRateMap[gid] !== 1" class="text-amber-600 dark:text-amber-400">{{ formatRate(groupRateMap[gid]) }}</span>
                  </span>
                  <span v-if="model.group_ids && model.group_ids.length > 2" class="text-[9px] text-gray-400">+{{ model.group_ids.length - 2 }}</span>
                </div>
              </div>

              <!-- Copy Indicator -->
              <transition name="fade">
                <div
                  v-if="copiedModel === model.id"
                  class="absolute inset-0 flex items-center justify-center bg-white/90 dark:bg-dark-800/90 backdrop-blur-sm rounded-xl"
                >
                  <div class="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-100 text-emerald-700 dark:bg-emerald-900/50 dark:text-emerald-400 shadow-lg">
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                    </svg>
                    <span class="text-sm font-medium">{{ t('modelSquare.copied') }}</span>
                  </div>
                </div>
              </transition>
            </div>

            <!-- Hover Effect Border -->
            <div class="absolute inset-0 rounded-xl border-2 border-primary-500/0 group-hover:border-primary-500 transition-all duration-300 pointer-events-none"></div>
            <!-- Corner glow on hover -->
            <div class="card-glow absolute -top-20 -right-20 w-40 h-40 rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none bg-primary-400/10 dark:bg-primary-400/5 blur-2xl"></div>
          </div>
        </TransitionGroup>

        <!-- Table View -->
        <div v-else-if="viewMode === 'table' && filteredModels.length > 0" class="rounded-xl border border-gray-200 dark:border-dark-700 overflow-hidden bg-white dark:bg-dark-800/50 shadow-sm">
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="bg-gray-50/80 dark:bg-dark-800/80">
                  <th class="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 whitespace-nowrap w-20">
                    {{ t('modelSquare.availability') }}
                  </th>
                  <th
                    @click="toggleSort('provider')"
                    class="cursor-pointer hover:bg-gray-100 dark:hover:bg-dark-700 transition-colors px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 whitespace-nowrap"
                  >
                    <div class="flex items-center gap-1.5">
                      {{ t('modelSquare.provider') }}
                      <svg class="w-3 h-3" :class="sortKey === 'provider' ? 'opacity-100 text-primary-500' : 'opacity-30'" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path d="m21 16-4 4-4-4" /><path d="M17 20V4" />
                        <path d="m3 8 4-4 4 4" /><path d="M7 4v16" />
                      </svg>
                    </div>
                  </th>
                  <th
                    @click="toggleSort('id')"
                    class="cursor-pointer hover:bg-gray-100 dark:hover:bg-dark-700 transition-colors px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 whitespace-nowrap"
                  >
                    <div class="flex items-center gap-1.5">
                      Model ID
                      <svg class="w-3 h-3" :class="sortKey === 'id' ? 'opacity-100 text-primary-500' : 'opacity-30'" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path d="m21 16-4 4-4-4" /><path d="M17 20V4" />
                        <path d="m3 8 4-4 4 4" /><path d="M7 4v16" />
                      </svg>
                    </div>
                  </th>
                  <th
                    @click="toggleSort('input_price')"
                    class="cursor-pointer hover:bg-gray-100 dark:hover:bg-dark-700 transition-colors px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 whitespace-nowrap"
                  >
                    <div class="flex items-center gap-1.5">
                      {{ t('modelSquare.input') }} $/M
                      <svg class="w-3 h-3" :class="sortKey === 'input_price' ? 'opacity-100 text-primary-500' : 'opacity-30'" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path d="m21 16-4 4-4-4" /><path d="M17 20V4" />
                        <path d="m3 8 4-4 4 4" /><path d="M7 4v16" />
                      </svg>
                    </div>
                  </th>
                  <th
                    @click="toggleSort('output_price')"
                    class="cursor-pointer hover:bg-gray-100 dark:hover:bg-dark-700 transition-colors px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 whitespace-nowrap"
                  >
                    <div class="flex items-center gap-1.5">
                      {{ t('modelSquare.output') }} $/M
                      <svg class="w-3 h-3" :class="sortKey === 'output_price' ? 'opacity-100 text-primary-500' : 'opacity-30'" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path d="m21 16-4 4-4-4" /><path d="M17 20V4" />
                        <path d="m3 8 4-4 4 4" /><path d="M7 4v16" />
                      </svg>
                    </div>
                  </th>
                  <th
                    @click="toggleSort('cache_read_price')"
                    class="cursor-pointer hover:bg-gray-100 dark:hover:bg-dark-700 transition-colors px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 whitespace-nowrap"
                  >
                    <div class="flex items-center gap-1.5">
                      {{ t('modelSquare.cacheRead') }} $/M
                      <svg class="w-3 h-3" :class="sortKey === 'cache_read_price' ? 'opacity-100 text-primary-500' : 'opacity-30'" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path d="m21 16-4 4-4-4" /><path d="M17 20V4" />
                        <path d="m3 8 4-4 4 4" /><path d="M7 4v16" />
                      </svg>
                    </div>
                  </th>
                  <th
                    @click="toggleSort('cache_create_price')"
                    class="cursor-pointer hover:bg-gray-100 dark:hover:bg-dark-700 transition-colors px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 whitespace-nowrap"
                  >
                    <div class="flex items-center gap-1.5">
                      {{ t('modelSquare.cacheCreate') }} $/M
                      <svg class="w-3 h-3" :class="sortKey === 'cache_create_price' ? 'opacity-100 text-primary-500' : 'opacity-30'" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path d="m21 16-4 4-4-4" /><path d="M17 20V4" />
                        <path d="m3 8 4-4 4 4" /><path d="M7 4v16" />
                      </svg>
                    </div>
                  </th>
                  <th class="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 whitespace-nowrap">
                    {{ t('modelSquare.type') }}
                  </th>
                  <th class="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 whitespace-nowrap">
                    {{ t('modelSquare.perUsage') }}
                  </th>
                  <th class="px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 whitespace-nowrap">
                    {{ t('modelSquare.group') }}
                  </th>
                  <th class="w-10 px-2 py-3"></th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="model in paginatedModels"
                  :key="model.id"
                  class="group cursor-pointer border-t border-gray-100 dark:border-dark-700/50 hover:bg-gray-50 dark:hover:bg-dark-700/30 transition-colors"
                  :class="{ 'opacity-50': !model.available }"
                  @click="copyModelName(model.id)"
                >
                  <!-- Availability -->
                  <td class="px-4 py-2.5 whitespace-nowrap">
                    <span v-if="model.available" class="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-600 dark:text-emerald-400">
                      <span class="w-2 h-2 rounded-full bg-emerald-500 blink-dot"></span>
                      {{ t('modelSquare.available') }}
                    </span>
                    <span v-else class="inline-flex items-center gap-1.5 text-xs font-medium text-gray-400 dark:text-gray-500">
                      <span class="w-2 h-2 rounded-full bg-gray-300 dark:bg-gray-600"></span>
                      {{ t('modelSquare.unavailable') }}
                    </span>
                  </td>
                  <!-- Provider -->
                  <td class="px-4 py-2.5 whitespace-nowrap">
                    <div class="flex items-center gap-2">
                      <span class="w-2 h-2 rounded-full flex-shrink-0" :style="{ backgroundColor: providerDotColor(model.provider) }"></span>
                      <span class="text-gray-600 dark:text-gray-300 text-sm">{{ model.provider || '—' }}</span>
                    </div>
                  </td>
                  <!-- Model ID -->
                  <td class="px-4 py-2.5">
                    <div class="flex items-center gap-2">
                      <span class="font-medium text-gray-900 dark:text-white text-sm">{{ model.id }}</span>
                      <transition name="fade">
                        <span
                          v-if="copiedModel === model.id"
                          class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
                        >
                          {{ t('modelSquare.copied') }}
                        </span>
                      </transition>
                    </div>
                  </td>
                  <!-- Input Price -->
                  <td class="px-4 py-2.5 font-mono whitespace-nowrap">
                    <span class="text-gray-900 dark:text-gray-100">{{ formatPrice(model.input_price, getModelRate(model)) }}</span>
                  </td>
                  <!-- Output Price -->
                  <td class="px-4 py-2.5 font-mono whitespace-nowrap">
                    <span class="text-gray-900 dark:text-gray-100">{{ formatPrice(model.output_price, getModelRate(model)) }}</span>
                  </td>
                  <!-- Cache Read -->
                  <td class="px-4 py-2.5 font-mono whitespace-nowrap">
                    <span v-if="model.cache_read_price != null" class="text-gray-900 dark:text-gray-100">{{ formatPrice(model.cache_read_price, getModelRate(model)) }}</span>
                    <span v-else class="text-gray-300 dark:text-gray-600">&mdash;</span>
                  </td>
                  <!-- Cache Create -->
                  <td class="px-4 py-2.5 font-mono whitespace-nowrap">
                    <span v-if="model.cache_create_price != null" class="text-gray-900 dark:text-gray-100">{{ formatPrice(model.cache_create_price, getModelRate(model)) }}</span>
                    <span v-else class="text-gray-300 dark:text-gray-600">&mdash;</span>
                  </td>
                  <!-- Type -->
                  <td class="px-4 py-2.5 whitespace-nowrap">
                    <span v-if="model.mode" class="inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium" :class="modeBadgeClass(model.mode)">
                      {{ modeBadgeLabel(model.mode) }}
                    </span>
                    <span v-else class="text-gray-300 dark:text-gray-600">&mdash;</span>
                  </td>
                  <!-- Per-Usage Pricing -->
                  <td class="px-4 py-2.5 whitespace-nowrap">
                    <template v-if="getModelPerUsagePricing(model)">
                      <div class="flex flex-wrap gap-1">
                        <span
                          v-for="item in getModelPerUsagePricing(model)!.items"
                          :key="item.label"
                          class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400"
                        >
                          {{ item.label }}: <span class="font-mono">{{ formatPerUsagePrice(item.price) }}</span>
                        </span>
                      </div>
                    </template>
                    <span v-else class="text-gray-300 dark:text-gray-600">&mdash;</span>
                  </td>
                  <!-- Groups -->
                  <td class="px-4 py-2.5 whitespace-nowrap">
                    <div class="flex flex-wrap gap-1">
                      <span
                        v-for="gid in model.group_ids"
                        :key="gid"
                        class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-400"
                      >
                        {{ groupNameMap[gid] || gid }}
                        <span v-if="groupRateMap[gid] && groupRateMap[gid] !== 1" class="text-amber-600 dark:text-amber-400">{{ formatRate(groupRateMap[gid]) }}</span>
                      </span>
                    </div>
                  </td>
                  <!-- Copy Button -->
                  <td class="px-2 py-2.5 text-center">
                    <button
                      class="p-1.5 rounded-md hover:bg-gray-200 dark:hover:bg-dark-600 text-gray-400 dark:text-gray-500 hover:text-gray-700 dark:hover:text-gray-200 transition-all opacity-0 group-hover:opacity-100"
                      :title="t('modelSquare.copied')"
                      @click.stop="copyModelName(model.id)"
                    >
                      <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <rect width="14" height="14" x="8" y="8" rx="2" ry="2" />
                        <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
                      </svg>
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Pagination (shared by grid and table views) -->
        <div v-if="filteredModels.length > 0" class="mt-4 flex items-center justify-between gap-4 px-4 py-3 rounded-xl border border-gray-200 dark:border-dark-700 bg-white dark:bg-dark-800/50">
            <div class="text-sm text-gray-500 dark:text-gray-400">
              {{ t('modelSquare.showing', { count: Math.min(currentPage * pageSize, filteredModels.length), total: filteredModels.length }) }}
              <span class="text-xs text-gray-400 dark:text-gray-500 ml-2">{{ t('modelSquare.priceUnit') }}</span>
            </div>
            <div v-if="totalPages > 1" class="flex items-center gap-1">
              <!-- First Page -->
              <button
                @click="currentPage = 1"
                :disabled="currentPage === 1"
                class="p-2 rounded-md border border-gray-200 dark:border-dark-600 bg-white dark:bg-dark-800 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-dark-700 hover:text-gray-900 dark:hover:text-white disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-white dark:disabled:hover:bg-dark-800 disabled:hover:text-gray-600 dark:disabled:hover:text-gray-300 transition-all"
                :title="t('modelSquare.prev')"
              >
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="m11 17-5-5 5-5" /><path d="m18 17-5-5 5-5" />
                </svg>
              </button>
              <!-- Prev Page -->
              <button
                @click="currentPage = Math.max(1, currentPage - 1)"
                :disabled="currentPage === 1"
                class="p-2 rounded-md border border-gray-200 dark:border-dark-600 bg-white dark:bg-dark-800 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-dark-700 hover:text-gray-900 dark:hover:text-white disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-white dark:disabled:hover:bg-dark-800 disabled:hover:text-gray-600 dark:disabled:hover:text-gray-300 transition-all"
                :title="t('modelSquare.prev')"
              >
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="m15 18-6-6 6-6" />
                </svg>
              </button>
              <!-- Page Numbers -->
              <div class="flex items-center gap-1 mx-2">
                <template v-for="page in visiblePages" :key="page">
                  <button
                    v-if="page !== '...'"
                    @click="currentPage = page as number"
                    class="min-w-[36px] h-9 px-3 rounded-md text-sm font-medium transition-all"
                    :class="currentPage === page
                      ? 'bg-primary-500 text-white shadow-sm'
                      : 'border border-gray-200 dark:border-dark-600 bg-white dark:bg-dark-800 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-dark-700 hover:text-gray-900 dark:hover:text-white'"
                  >
                    {{ page }}
                  </button>
                  <span v-else class="px-2 text-gray-400 dark:text-gray-500">...</span>
                </template>
              </div>
              <!-- Next Page -->
              <button
                @click="currentPage = Math.min(totalPages, currentPage + 1)"
                :disabled="currentPage === totalPages"
                class="p-2 rounded-md border border-gray-200 dark:border-dark-600 bg-white dark:bg-dark-800 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-dark-700 hover:text-gray-900 dark:hover:text-white disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-white dark:disabled:hover:bg-dark-800 disabled:hover:text-gray-600 dark:disabled:hover:text-gray-300 transition-all"
                :title="t('modelSquare.next')"
              >
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="m9 18 6-6-6-6" />
                </svg>
              </button>
              <!-- Last Page -->
              <button
                @click="currentPage = totalPages"
                :disabled="currentPage === totalPages"
                class="p-2 rounded-md border border-gray-200 dark:border-dark-600 bg-white dark:bg-dark-800 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-dark-700 hover:text-gray-900 dark:hover:text-white disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-white dark:disabled:hover:bg-dark-800 disabled:hover:text-gray-600 dark:disabled:hover:text-gray-300 transition-all"
                :title="t('modelSquare.next')"
              >
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="m6 17 5-5-5-5" /><path d="m13 17 5-5-5-5" />
                </svg>
              </button>
            </div>
          </div>

        <!-- Empty State -->
        <div v-else class="rounded-xl border border-gray-200 dark:border-dark-700 bg-white dark:bg-dark-800/50 py-16 text-center">
          <svg class="mx-auto h-12 w-12 text-gray-300 dark:text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1">
            <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <p class="mt-4 text-sm text-gray-500 dark:text-gray-400">{{ t('modelSquare.noModels') }}</p>
        </div>
      </template>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import { getModelSquare, type ModelSquareItem, type ModelSquareGroup } from '@/api/models'

const { t } = useI18n()

const loading = ref(true)
const models = ref<ModelSquareItem[]>([])
const groups = ref<ModelSquareGroup[]>([])
const updatedAt = ref('')
const searchQuery = ref('')
const selectedProvider = ref('')
const selectedMode = ref('')
const selectedGroupID = ref<number | null>(null)
const copiedModel = ref('')
const currentPage = ref(1)
const pageSize = 24
const viewMode = ref<'grid' | 'table'>('grid')

// Dropdowns
const showProviderDropdown = ref(false)
const showModeDropdown = ref(false)
const showSortDropdown = ref(false)
const showGroupDropdown = ref(false)
const providerDropdownRef = ref<HTMLElement>()
const modeDropdownRef = ref<HTMLElement>()
const sortDropdownRef = ref<HTMLElement>()
const groupDropdownRef = ref<HTMLElement>()

// Sorting
const sortKey = ref<string>('')
const sortDir = ref<'asc' | 'desc'>('asc')

const sortLabels: Record<string, string> = {
  provider: 'Provider',
  id: 'Model ID',
  input_price: 'Input $/M',
  output_price: 'Output $/M',
  cache_read_price: 'Cache Read $/M',
  cache_create_price: 'Cache Write $/M',
}

let copyTimer: ReturnType<typeof setTimeout> | null = null

// Animated model count
const animatedModelCount = ref(0)
let countAnimFrame: number | null = null

watch(() => filteredModels.value.length, (newVal) => {
  const start = animatedModelCount.value
  const diff = newVal - start
  if (diff === 0) return
  const duration = 400
  const startTime = performance.now()
  const animate = (now: number) => {
    const elapsed = now - startTime
    const progress = Math.min(elapsed / duration, 1)
    const eased = 1 - Math.pow(1 - progress, 3) // easeOutCubic
    animatedModelCount.value = Math.round(start + diff * eased)
    if (progress < 1) {
      countAnimFrame = requestAnimationFrame(animate)
    }
  }
  if (countAnimFrame) cancelAnimationFrame(countAnimFrame)
  countAnimFrame = requestAnimationFrame(animate)
})

// Card hover tilt effect
function handleCardHover(e: MouseEvent, entering: boolean) {
  const card = e.currentTarget as HTMLElement
  if (!entering) {
    card.style.transform = ''
    return
  }
  const onMove = (ev: MouseEvent) => {
    const rect = card.getBoundingClientRect()
    const x = (ev.clientX - rect.left) / rect.width - 0.5
    const y = (ev.clientY - rect.top) / rect.height - 0.5
    card.style.transform = `perspective(800px) rotateY(${x * 6}deg) rotateX(${-y * 6}deg) scale(1.02)`
  }
  const onLeave = () => {
    card.style.transform = ''
    card.removeEventListener('mousemove', onMove)
    card.removeEventListener('mouseleave', onLeave)
  }
  card.addEventListener('mousemove', onMove)
  card.addEventListener('mouseleave', onLeave)
}

// Group name map for display
const groupNameMap = computed(() => {
  const map: Record<number, string> = {}
  for (const g of groups.value) {
    map[g.id] = g.name
  }
  return map
})

// Group rate multiplier map
const groupRateMap = computed(() => {
  const map: Record<number, number> = {}
  for (const g of groups.value) {
    map[g.id] = g.rate_multiplier || 1
  }
  return map
})

// Group map for quick lookup
const groupMap = computed(() => {
  const map: Record<number, ModelSquareGroup> = {}
  for (const g of groups.value) {
    map[g.id] = g
  }
  return map
})

// Per-usage pricing info for a model
interface PerUsagePricing {
  type: 'sora' | 'image'
  items: { label: string; price: number }[]
}

function getModelPerUsagePricing(model: ModelSquareItem): PerUsagePricing | null {
  const gids = selectedGroupID.value !== null
    ? [selectedGroupID.value]
    : (model.group_ids || [])

  for (const gid of gids) {
    const g = groupMap.value[gid]
    if (!g) continue

    // Sora pricing
    const soraItems: { label: string; price: number }[] = []
    if (g.sora_image_price_360 != null) soraItems.push({ label: t('modelSquare.imageSize360'), price: g.sora_image_price_360 })
    if (g.sora_image_price_540 != null) soraItems.push({ label: t('modelSquare.imageSize540'), price: g.sora_image_price_540 })
    if (g.sora_video_price_per_request != null) soraItems.push({ label: t('modelSquare.perVideo'), price: g.sora_video_price_per_request })
    if (g.sora_video_price_per_request_hd != null) soraItems.push({ label: t('modelSquare.perVideoHd'), price: g.sora_video_price_per_request_hd })
    if (soraItems.length > 0) return { type: 'sora', items: soraItems }

    // Image generation pricing
    const imgItems: { label: string; price: number }[] = []
    if (g.image_price_1k != null) imgItems.push({ label: t('modelSquare.imageSize1k'), price: g.image_price_1k })
    if (g.image_price_2k != null) imgItems.push({ label: t('modelSquare.imageSize2k'), price: g.image_price_2k })
    if (g.image_price_4k != null) imgItems.push({ label: t('modelSquare.imageSize4k'), price: g.image_price_4k })
    if (imgItems.length > 0) return { type: 'image', items: imgItems }
  }

  return null
}

function formatPerUsagePrice(price: number): string {
  if (price === 0) return '$0'
  if (price < 0.001) return `$${price.toFixed(5)}`
  if (price < 0.01) return `$${price.toFixed(4)}`
  if (price < 1) return `$${price.toFixed(3)}`
  return `$${price.toFixed(2)}`
}

// Get the effective rate multiplier for a model (use the max rate among its groups, or selected group's rate)
const getModelRate = (model: ModelSquareItem): number => {
  if (selectedGroupID.value !== null) {
    return groupRateMap.value[selectedGroupID.value] || 1
  }
  // When showing all groups, use the first group's rate
  if (model.group_ids && model.group_ids.length > 0) {
    return groupRateMap.value[model.group_ids[0]] || 1
  }
  return 1
}

// Format rate multiplier for display
const formatRate = (rate: number): string => {
  if (rate === 1) return '1x'
  // Remove trailing zeros: 0.50 -> 0.5, 2.00 -> 2, 0.001 -> 0.001
  const s = parseFloat(rate.toPrecision(10)).toString()
  return `${s}x`
}

// Selected group display name
const selectedGroupName = computed(() => {
  if (selectedGroupID.value === null) return t('modelSquare.allGroups')
  return groupNameMap.value[selectedGroupID.value] || t('modelSquare.allGroups')
})

// Close dropdowns when clicking outside
function handleClickOutside(e: MouseEvent) {
  const target = e.target as Node
  if (providerDropdownRef.value && !providerDropdownRef.value.contains(target)) {
    showProviderDropdown.value = false
  }
  if (modeDropdownRef.value && !modeDropdownRef.value.contains(target)) {
    showModeDropdown.value = false
  }
  if (sortDropdownRef.value && !sortDropdownRef.value.contains(target)) {
    showSortDropdown.value = false
  }
  if (groupDropdownRef.value && !groupDropdownRef.value.contains(target)) {
    showGroupDropdown.value = false
  }
}

onMounted(async () => {
  document.addEventListener('click', handleClickOutside)
  try {
    const res = await getModelSquare()
    models.value = res.models || []
    groups.value = res.groups || []
    updatedAt.value = res.updated_at || ''
  } catch (e) {
    console.error('Failed to fetch model square data:', e)
  } finally {
    loading.value = false
  }
})

onUnmounted(() => {
  document.removeEventListener('click', handleClickOutside)
})

const providerList = computed(() => {
  const map = new Map<string, number>()
  for (const m of models.value) {
    if (m.provider) {
      map.set(m.provider, (map.get(m.provider) || 0) + 1)
    }
  }
  return Array.from(map.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
})

const modeList = computed(() => {
  const map = new Map<string, number>()
  for (const m of models.value) {
    const mode = m.mode || 'chat'
    map.set(mode, (map.get(mode) || 0) + 1)
  }
  return Array.from(map.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
})

const filteredModels = computed(() => {
  let list = models.value

  // Filter by group
  if (selectedGroupID.value !== null) {
    const gid = selectedGroupID.value
    list = list.filter((m) => m.group_ids && m.group_ids.includes(gid))
  }

  if (selectedProvider.value) {
    list = list.filter((m) => m.provider === selectedProvider.value)
  }
  if (selectedMode.value) {
    list = list.filter((m) => (m.mode || 'chat') === selectedMode.value)
  }
  if (searchQuery.value.trim()) {
    const q = searchQuery.value.trim().toLowerCase()
    list = list.filter((m) => m.id.toLowerCase().includes(q) || (m.provider && m.provider.toLowerCase().includes(q)))
  }

  // Default sort: available models first, then by id
  list = [...list].sort((a, b) => {
    // Available first
    if (a.available !== b.available) return a.available ? -1 : 1
    // Then by explicit sort
    if (sortKey.value) {
      const key = sortKey.value
      const dir = sortDir.value === 'asc' ? 1 : -1
      const av = (a as any)[key]
      const bv = (b as any)[key]
      if (av == null && bv == null) return 0
      if (av == null) return 1
      if (bv == null) return -1
      if (typeof av === 'string') return av.localeCompare(bv) * dir
      return (av - bv) * dir
    }
    // Default: sort by id
    return a.id.localeCompare(b.id)
  })

  return list
})

const totalPages = computed(() => Math.max(1, Math.ceil(filteredModels.value.length / pageSize)))

const paginatedModels = computed(() => {
  const start = (currentPage.value - 1) * pageSize
  return filteredModels.value.slice(start, start + pageSize)
})

// Generate visible page numbers with ellipsis
const visiblePages = computed(() => {
  const total = totalPages.value
  const current = currentPage.value
  const pages: (number | string)[] = []

  if (total <= 7) {
    for (let i = 1; i <= total; i++) pages.push(i)
  } else {
    pages.push(1)
    if (current > 3) pages.push('...')
    const start = Math.max(2, current - 1)
    const end = Math.min(total - 1, current + 1)
    for (let i = start; i <= end; i++) pages.push(i)
    if (current < total - 2) pages.push('...')
    pages.push(total)
  }

  return pages
})

// Reset page when filters change
watch([searchQuery, selectedProvider, selectedMode, selectedGroupID, sortKey, sortDir], () => {
  currentPage.value = 1
})

function toggleSort(key: string) {
  if (sortKey.value === key) {
    if (sortDir.value === 'asc') {
      sortDir.value = 'desc'
    } else {
      sortKey.value = ''
      sortDir.value = 'asc'
    }
  } else {
    sortKey.value = key
    sortDir.value = 'asc'
  }
}

function formatPrice(price: number, rate: number = 1): string {
  const p = price * rate
  if (p === 0) return '$0'
  if (p < 0.001) return `$${p.toFixed(5)}`
  if (p < 0.01) return `$${p.toFixed(4)}`
  if (p < 1) return `$${p.toFixed(3)}`
  return `$${p.toFixed(2)}`
}

function modeBadgeLabel(mode: string): string {
  const labels: Record<string, string> = {
    chat: 'Chat',
    completion: 'Completion',
    embedding: 'Embedding',
    image_generation: 'Image',
    audio_transcription: 'Audio',
    audio_speech: 'TTS',
    moderation: 'Moderation',
    rerank: 'Rerank',
  }
  return labels[mode] || mode
}

function modeBadgeClass(mode: string): string {
  const classes: Record<string, string> = {
    chat: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
    completion: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
    embedding: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
    image_generation: 'bg-pink-100 text-pink-700 dark:bg-pink-900/30 dark:text-pink-400',
    audio_transcription: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400',
    audio_speech: 'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-400',
    moderation: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
    rerank: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400',
  }
  return classes[mode] || 'bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-400'
}

const providerDotColors: Record<string, string> = {
  OpenAI: '#10B981',
  Anthropic: '#D4A574',
  Google: '#4285F4',
  DeepSeek: '#6366F1',
  Mistral: '#F59E0B',
  Meta: '#0EA5E9',
  Cohere: '#A855F7',
  Qwen: '#14B8A6',
  xAI: '#EF4444',
  Groq: '#F97316',
}

function providerDotColor(provider: string): string {
  return providerDotColors[provider] || '#9CA3AF'
}

async function copyModelName(modelId: string) {
  try {
    await navigator.clipboard.writeText(modelId)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = modelId
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
  }
  copiedModel.value = modelId
  if (copyTimer) clearTimeout(copyTimer)
  copyTimer = setTimeout(() => { copiedModel.value = '' }, 2000)
}
</script>

<style scoped>
/* ===== Blink Dot ===== */
.blink-dot {
  animation: blinkDot 1.4s ease-in-out infinite;
}

@keyframes blinkDot {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.2; }
}

/* ===== Hero Section Animations ===== */
.hero-section {
  position: relative;
}

.hero-gradient {
  background: linear-gradient(
    135deg,
    rgba(var(--primary-rgb, 99, 102, 241), 0.08) 0%,
    rgba(168, 85, 247, 0.08) 35%,
    rgba(236, 72, 153, 0.08) 65%,
    rgba(var(--primary-rgb, 99, 102, 241), 0.08) 100%
  );
  background-size: 300% 300%;
  animation: gradientShift 8s ease-in-out infinite;
}

:root.dark .hero-gradient {
  background: linear-gradient(
    135deg,
    rgba(var(--primary-rgb, 99, 102, 241), 0.15) 0%,
    rgba(168, 85, 247, 0.15) 35%,
    rgba(236, 72, 153, 0.15) 65%,
    rgba(var(--primary-rgb, 99, 102, 241), 0.15) 100%
  );
  background-size: 300% 300%;
  animation: gradientShift 8s ease-in-out infinite;
}

@keyframes gradientShift {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}

/* Floating orbs */
.hero-orb {
  position: absolute;
  border-radius: 50%;
  filter: blur(40px);
  pointer-events: none;
  will-change: transform;
}

.hero-orb-1 {
  width: 120px;
  height: 120px;
  background: rgba(var(--primary-rgb, 99, 102, 241), 0.15);
  top: -30px;
  right: 10%;
  animation: floatOrb1 6s ease-in-out infinite;
}

.hero-orb-2 {
  width: 80px;
  height: 80px;
  background: rgba(168, 85, 247, 0.12);
  bottom: -20px;
  left: 15%;
  animation: floatOrb2 8s ease-in-out infinite;
}

.hero-orb-3 {
  width: 60px;
  height: 60px;
  background: rgba(236, 72, 153, 0.1);
  top: 50%;
  right: 30%;
  animation: floatOrb3 7s ease-in-out infinite;
}

@keyframes floatOrb1 {
  0%, 100% { transform: translate(0, 0) scale(1); }
  33% { transform: translate(-20px, 15px) scale(1.1); }
  66% { transform: translate(10px, -10px) scale(0.95); }
}

@keyframes floatOrb2 {
  0%, 100% { transform: translate(0, 0) scale(1); }
  50% { transform: translate(25px, -15px) scale(1.15); }
}

@keyframes floatOrb3 {
  0%, 100% { transform: translate(0, 0); }
  25% { transform: translate(-15px, 10px); }
  75% { transform: translate(15px, -8px); }
}

/* Hero icon animation */
.hero-icon {
  animation: iconFloat 3s ease-in-out infinite;
}

@keyframes iconFloat {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-4px); }
}

/* Sparkle SVG rotation */
.hero-sparkle {
  animation: sparkleRotate 4s linear infinite;
}

@keyframes sparkleRotate {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* ===== Card Animations ===== */

/* TransitionGroup staggered entrance */
.card-list-enter-active {
  transition: all 0.5s cubic-bezier(0.22, 1, 0.36, 1);
  transition-delay: var(--card-delay, 0ms);
}

.card-list-leave-active {
  transition: all 0.3s cubic-bezier(0.22, 1, 0.36, 1);
}

.card-list-enter-from {
  opacity: 0;
  transform: translateY(30px) scale(0.95);
}

.card-list-leave-to {
  opacity: 0;
  transform: scale(0.95);
}

.card-list-move {
  transition: transform 0.4s cubic-bezier(0.22, 1, 0.36, 1);
}

/* Model card base */
.model-card {
  transition: box-shadow 0.3s ease, border-color 0.3s ease;
  will-change: transform;
  transform-style: preserve-3d;
}

.model-card:hover {
  box-shadow:
    0 20px 40px -12px rgba(0, 0, 0, 0.12),
    0 0 20px rgba(var(--primary-rgb, 99, 102, 241), 0.08);
  border-color: rgba(var(--primary-rgb, 99, 102, 241), 0.3);
}

:root.dark .model-card:hover {
  box-shadow:
    0 20px 40px -12px rgba(0, 0, 0, 0.4),
    0 0 20px rgba(var(--primary-rgb, 99, 102, 241), 0.15);
}

/* Card shimmer */
.card-shimmer {
  background: linear-gradient(
    110deg,
    transparent 25%,
    rgba(255, 255, 255, 0.08) 37%,
    transparent 63%
  );
  background-size: 200% 100%;
  opacity: 0;
  transition: opacity 0.3s ease;
}

.model-card:hover .card-shimmer {
  opacity: 1;
  animation: shimmer 1.5s ease-in-out infinite;
}

@keyframes shimmer {
  0% { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}

/* ===== Fade / Dropdown Transitions ===== */
.fade-enter-active, .fade-leave-active {
  transition: opacity 0.3s ease;
}
.fade-enter-from, .fade-leave-to {
  opacity: 0;
}

.dropdown-enter-active {
  transition: opacity 0.15s ease, transform 0.15s ease;
}
.dropdown-leave-active {
  transition: opacity 0.1s ease, transform 0.1s ease;
}
.dropdown-enter-from, .dropdown-leave-to {
  opacity: 0;
  transform: translateY(-4px) scale(0.98);
}

/* Grid pattern background */
.bg-grid-pattern {
  background-image:
    linear-gradient(to right, currentColor 1px, transparent 1px),
    linear-gradient(to bottom, currentColor 1px, transparent 1px);
  background-size: 24px 24px;
}

/* Tabular nums for counter */
.tabular-nums {
  font-variant-numeric: tabular-nums;
}

/* Availability dot glow */
.model-card .animate-pulse {
  animation: dotPulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

@keyframes dotPulse {
  0%, 100% {
    opacity: 1;
    box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4);
  }
  50% {
    opacity: 0.7;
    box-shadow: 0 0 0 4px rgba(16, 185, 129, 0);
  }
}

/* Table row hover animation */
tr.group {
  animation: none;
}

tr.group:hover td {
  transition: background-color 0.2s ease;
}

/* ===== Responsive: reduce motion ===== */
@media (prefers-reduced-motion: reduce) {
  .hero-gradient,
  .hero-orb,
  .hero-icon,
  .hero-sparkle,
  .model-card,
  .card-shimmer {
    animation: none !important;
  }
  .card-list-enter-active,
  .card-list-leave-active {
    transition: none !important;
  }
}
</style>
