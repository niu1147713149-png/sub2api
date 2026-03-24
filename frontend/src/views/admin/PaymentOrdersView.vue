<template>
  <AppLayout>
    <!-- Stats Section -->
    <div class="mb-6 space-y-4">
      <!-- Stats Cards -->
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <!-- Today Revenue -->
        <div class="rounded-2xl bg-white p-5 shadow-sm ring-1 ring-gray-900/5 dark:bg-dark-800 dark:ring-dark-700">
          <div class="flex items-center justify-between">
            <span class="text-sm font-medium text-gray-500 dark:text-gray-400">{{ t('admin.paymentOrders.todayRevenue') }}</span>
            <span class="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-50 dark:bg-emerald-900/20">
              <svg class="h-4 w-4 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            </span>
          </div>
          <div class="mt-3">
            <span class="text-2xl font-bold tabular-nums text-gray-900 dark:text-white">¥{{ animatedToday.toFixed(2) }}</span>
            <span class="ml-2 text-xs text-gray-400">{{ stats?.today_count ?? 0 }} {{ t('admin.paymentOrders.orders') }}</span>
          </div>
          <div v-if="stats" class="mt-2 flex items-center text-xs">
            <template v-if="stats.yesterday_amount > 0">
              <span v-if="stats.today_amount >= stats.yesterday_amount" class="flex items-center text-emerald-500">
                <svg class="mr-0.5 h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M5 15l7-7 7 7" /></svg>
                {{ ((stats.today_amount - stats.yesterday_amount) / stats.yesterday_amount * 100).toFixed(1) }}%
              </span>
              <span v-else class="flex items-center text-red-500">
                <svg class="mr-0.5 h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
                {{ ((stats.yesterday_amount - stats.today_amount) / stats.yesterday_amount * 100).toFixed(1) }}%
              </span>
              <span class="ml-1 text-gray-400">{{ t('admin.paymentOrders.vsYesterday') }}</span>
            </template>
          </div>
        </div>

        <!-- Yesterday Revenue -->
        <div class="rounded-2xl bg-white p-5 shadow-sm ring-1 ring-gray-900/5 dark:bg-dark-800 dark:ring-dark-700">
          <div class="flex items-center justify-between">
            <span class="text-sm font-medium text-gray-500 dark:text-gray-400">{{ t('admin.paymentOrders.yesterdayRevenue') }}</span>
            <span class="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-blue-50 dark:bg-blue-900/20">
              <svg class="h-4 w-4 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
            </span>
          </div>
          <div class="mt-3">
            <span class="text-2xl font-bold tabular-nums text-gray-900 dark:text-white">¥{{ animatedYesterday.toFixed(2) }}</span>
            <span class="ml-2 text-xs text-gray-400">{{ stats?.yesterday_count ?? 0 }} {{ t('admin.paymentOrders.orders') }}</span>
          </div>
        </div>

        <!-- Week Revenue -->
        <div class="rounded-2xl bg-white p-5 shadow-sm ring-1 ring-gray-900/5 dark:bg-dark-800 dark:ring-dark-700">
          <div class="flex items-center justify-between">
            <span class="text-sm font-medium text-gray-500 dark:text-gray-400">{{ t('admin.paymentOrders.weekRevenue') }}</span>
            <span class="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-violet-50 dark:bg-violet-900/20">
              <svg class="h-4 w-4 text-violet-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg>
            </span>
          </div>
          <div class="mt-3">
            <span class="text-2xl font-bold tabular-nums text-gray-900 dark:text-white">¥{{ animatedWeek.toFixed(2) }}</span>
            <span class="ml-2 text-xs text-gray-400">{{ stats?.week_count ?? 0 }} {{ t('admin.paymentOrders.orders') }}</span>
          </div>
        </div>

        <!-- Total Revenue -->
        <div class="rounded-2xl bg-white p-5 shadow-sm ring-1 ring-gray-900/5 dark:bg-dark-800 dark:ring-dark-700">
          <div class="flex items-center justify-between">
            <span class="text-sm font-medium text-gray-500 dark:text-gray-400">{{ t('admin.paymentOrders.totalRevenue') }}</span>
            <span class="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-amber-50 dark:bg-amber-900/20">
              <svg class="h-4 w-4 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 9V7a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2m2 4h10a2 2 0 002-2v-6a2 2 0 00-2-2H9a2 2 0 00-2 2v6a2 2 0 002 2zm7-5a2 2 0 11-4 0 2 2 0 014 0z" /></svg>
            </span>
          </div>
          <div class="mt-3">
            <span class="text-2xl font-bold tabular-nums text-gray-900 dark:text-white">¥{{ animatedTotal.toFixed(2) }}</span>
            <span class="ml-2 text-xs text-gray-400">{{ stats?.total_count ?? 0 }} {{ t('admin.paymentOrders.orders') }}</span>
          </div>
        </div>
      </div>

      <!-- Charts -->
      <div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <!-- Revenue Trend -->
        <div class="lg:col-span-2 rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-900/5 dark:bg-dark-800 dark:ring-dark-700">
          <div class="mb-4 flex items-center justify-between">
            <h3 class="text-sm font-bold text-gray-900 dark:text-white">{{ t('admin.paymentOrders.revenueTrend') }}</h3>
            <div class="flex items-center gap-1">
              <button
                v-for="d in dayOptions"
                :key="d"
                @click="changeDays(d)"
                class="rounded-lg px-2.5 py-1 text-xs font-medium transition-colors"
                :class="selectedDays === d
                  ? 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400'
                  : 'text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-dark-700'"
              >
                {{ t(`admin.paymentOrders.days${d}`) }}
              </button>
            </div>
          </div>
          <div class="h-64">
            <Line v-if="trendChartData" :data="trendChartData" :options="trendChartOptions" />
            <div v-else class="flex h-full items-center justify-center text-sm text-gray-400">
              <template v-if="statsLoading">{{ t('common.loading') }}</template>
              <template v-else>{{ t('common.noData') }}</template>
            </div>
          </div>
        </div>

        <!-- Payment Method Breakdown -->
        <div class="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-900/5 dark:bg-dark-800 dark:ring-dark-700">
          <h3 class="mb-4 text-sm font-bold text-gray-900 dark:text-white">{{ t('admin.paymentOrders.methodBreakdown') }}</h3>
          <div class="flex h-64 items-center justify-center">
            <div v-if="doughnutChartData" class="relative h-full w-full">
              <Doughnut :data="doughnutChartData" :options="doughnutChartOptions" />
              <div class="pointer-events-none absolute inset-0 flex items-center justify-center">
                <div class="text-center">
                  <div class="text-lg font-bold tabular-nums text-gray-900 dark:text-white">¥{{ stats?.total_amount?.toFixed(0) ?? '0' }}</div>
                </div>
              </div>
            </div>
            <div v-else class="text-sm text-gray-400">
              <template v-if="statsLoading">{{ t('common.loading') }}</template>
              <template v-else>{{ t('common.noData') }}</template>
            </div>
          </div>
        </div>
      </div>
    </div>

    <TablePageLayout>
      <!-- Filters -->
      <template #filters>
        <div class="flex flex-wrap items-center gap-3">
          <div class="flex flex-1 flex-wrap items-center gap-3">
            <!-- Search -->
            <div class="relative w-full md:w-64">
              <Icon
                name="search"
                size="md"
                class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"
              />
              <input
                v-model="searchQuery"
                type="text"
                :placeholder="t('admin.paymentOrders.searchPlaceholder')"
                class="input pl-10"
                @input="handleSearch"
              />
            </div>

            <!-- Status Filter -->
            <div class="w-full sm:w-36">
              <Select
                v-model="filters.status"
                :options="statusOptions"
                @change="applyFilter"
              />
            </div>

            <!-- Start Date -->
            <div class="w-full sm:w-40">
              <input
                v-model="filters.start_date"
                type="date"
                class="input"
                :placeholder="t('admin.paymentOrders.startDate')"
                @change="applyFilter"
              />
            </div>

            <!-- End Date -->
            <div class="w-full sm:w-40">
              <input
                v-model="filters.end_date"
                type="date"
                class="input"
                :placeholder="t('admin.paymentOrders.endDate')"
                @change="applyFilter"
              />
            </div>
          </div>

          <!-- Refresh -->
          <div class="flex items-center gap-2">
            <button
              @click="loadOrders"
              :disabled="loading"
              class="btn btn-secondary px-2 md:px-3"
              :title="t('common.refresh')"
            >
              <Icon name="refresh" size="md" :class="loading ? 'animate-spin' : ''" />
            </button>
          </div>
        </div>
      </template>

      <!-- Table -->
      <template #table>
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>{{ t('admin.paymentOrders.orderNo') }}</th>
                <th>{{ t('admin.paymentOrders.userId') }}</th>
                <th>{{ t('admin.paymentOrders.userEmail') }}</th>
                <th>{{ t('admin.paymentOrders.amount') }}</th>
                <th>{{ t('admin.paymentOrders.credit') }}</th>
                <th>{{ t('admin.paymentOrders.paymentMethod') }}</th>
                <th>{{ t('admin.paymentOrders.status') }}</th>
                <th>{{ t('admin.paymentOrders.createdAt') }}</th>
                <th>{{ t('admin.paymentOrders.paidAt') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="loading && orders.length === 0">
                <td colspan="9" class="text-center py-8 text-gray-500">
                  <Icon name="refresh" size="md" class="animate-spin inline-block mr-2" />
                  {{ t('common.loading') }}
                </td>
              </tr>
              <tr v-else-if="orders.length === 0">
                <td colspan="9" class="text-center py-8 text-gray-500">
                  {{ t('admin.paymentOrders.noOrders') }}
                </td>
              </tr>
              <tr v-for="order in orders" :key="order.id">
                <td class="font-mono text-xs">{{ order.order_no }}</td>
                <td>{{ order.user_id }}</td>
                <td>{{ order.user_email || '-' }}</td>
                <td>{{ order.amount.toFixed(2) }}</td>
                <td>{{ order.credit.toFixed(2) }}</td>
                <td>
                  <span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium bg-gray-100 text-gray-700 dark:bg-dark-700 dark:text-gray-300">
                    {{ formatPaymentMethod(order.payment_method) }}
                  </span>
                </td>
                <td>
                  <span
                    class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium"
                    :class="statusClass(order.status)"
                  >
                    {{ statusLabel(order.status) }}
                  </span>
                </td>
                <td class="whitespace-nowrap">{{ formatTime(order.created_at) }}</td>
                <td class="whitespace-nowrap">{{ order.paid_at ? formatTime(order.paid_at) : '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>

      <!-- Pagination -->
      <template #pagination>
        <Pagination
          v-if="pagination.total > 0"
          :page="pagination.page"
          :total="pagination.total"
          :page-size="pagination.page_size"
          @update:page="handlePageChange"
          @update:pageSize="handlePageSizeChange"
        />
      </template>
    </TablePageLayout>
  </AppLayout>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Filler,
  Legend,
  Title,
  Tooltip
} from 'chart.js'
import { Line, Doughnut } from 'vue-chartjs'
import AppLayout from '@/components/layout/AppLayout.vue'
import TablePageLayout from '@/components/layout/TablePageLayout.vue'
import Pagination from '@/components/common/Pagination.vue'
import Select from '@/components/common/Select.vue'
import Icon from '@/components/icons/Icon.vue'
import { paymentOrdersAPI } from '@/api/admin'
import type { AdminPaymentOrder, PaymentStats } from '@/api/admin/paymentOrders'

ChartJS.register(Title, Tooltip, Legend, LineElement, LinearScale, PointElement, CategoryScale, Filler, ArcElement)

const { t } = useI18n()

// --- Stats ---
const stats = ref<PaymentStats | null>(null)
const statsLoading = ref(false)
const selectedDays = ref(30)
const dayOptions = [7, 30, 90] as const

// Animated numbers
const animatedToday = ref(0)
const animatedYesterday = ref(0)
const animatedWeek = ref(0)
const animatedTotal = ref(0)

function animateValue(from: number, to: number, setter: (v: number) => void, duration = 600) {
  const start = performance.now()
  const tick = (now: number) => {
    const elapsed = now - start
    const progress = Math.min(elapsed / duration, 1)
    const eased = 1 - Math.pow(1 - progress, 3)
    setter(from + (to - from) * eased)
    if (progress < 1) requestAnimationFrame(tick)
  }
  requestAnimationFrame(tick)
}

watch(stats, (s) => {
  if (!s) return
  animateValue(animatedToday.value, s.today_amount, (v) => (animatedToday.value = v))
  animateValue(animatedYesterday.value, s.yesterday_amount, (v) => (animatedYesterday.value = v))
  animateValue(animatedWeek.value, s.week_amount, (v) => (animatedWeek.value = v))
  animateValue(animatedTotal.value, s.total_amount, (v) => (animatedTotal.value = v))
})

const isDarkMode = computed(() => document.documentElement.classList.contains('dark'))

// Revenue Trend chart
const trendChartData = computed(() => {
  if (!stats.value?.trend_points?.length) return null
  const pts = stats.value.trend_points
  const ctx = document.createElement('canvas').getContext('2d')
  let gradient: CanvasGradient | string = '#6366f120'
  if (ctx) {
    gradient = ctx.createLinearGradient(0, 0, 0, 256)
    gradient.addColorStop(0, 'rgba(99,102,241,0.2)')
    gradient.addColorStop(1, 'rgba(99,102,241,0)')
  }
  return {
    labels: pts.map((p) => p.date.slice(5)),
    datasets: [
      {
        label: t('admin.paymentOrders.amount'),
        data: pts.map((p) => p.amount),
        borderColor: '#6366f1',
        backgroundColor: gradient,
        fill: true,
        tension: 0.35,
        pointRadius: 0,
        pointHitRadius: 10,
        borderWidth: 2,
        yAxisID: 'y'
      },
      {
        label: t('admin.paymentOrders.orders'),
        data: pts.map((p) => p.count),
        borderColor: '#f59e0b',
        backgroundColor: 'transparent',
        borderDash: [5, 5],
        fill: false,
        tension: 0.35,
        pointRadius: 0,
        pointHitRadius: 10,
        borderWidth: 1.5,
        yAxisID: 'y1'
      }
    ]
  }
})

const trendChartOptions = computed(() => {
  const dark = isDarkMode.value
  const textColor = dark ? '#9ca3af' : '#6b7280'
  const gridColor = dark ? '#374151' : '#f3f4f6'
  return {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { intersect: false, mode: 'index' as const },
    plugins: {
      legend: {
        position: 'top' as const,
        align: 'end' as const,
        labels: { color: textColor, usePointStyle: true, boxWidth: 6, font: { size: 10 } }
      },
      tooltip: {
        backgroundColor: dark ? '#1f2937' : '#fff',
        titleColor: dark ? '#f3f4f6' : '#111827',
        bodyColor: dark ? '#d1d5db' : '#4b5563',
        borderColor: gridColor,
        borderWidth: 1,
        padding: 10,
        displayColors: true,
        callbacks: {
          label(ctx: any) {
            if (ctx.datasetIndex === 0) return ` ¥${ctx.parsed.y.toFixed(2)}`
            return ` ${ctx.parsed.y} ${t('admin.paymentOrders.orders')}`
          }
        }
      }
    },
    scales: {
      x: {
        type: 'category' as const,
        grid: { display: false },
        ticks: { color: textColor, font: { size: 10 }, maxTicksLimit: 10, autoSkip: true }
      },
      y: {
        type: 'linear' as const,
        display: true,
        position: 'left' as const,
        grid: { color: gridColor, borderDash: [4, 4] },
        ticks: { color: textColor, font: { size: 10 }, callback: (v: any) => `¥${v}` }
      },
      y1: {
        type: 'linear' as const,
        display: true,
        position: 'right' as const,
        grid: { drawOnChartArea: false },
        ticks: { color: textColor, font: { size: 10 }, precision: 0 }
      }
    }
  }
})

// Doughnut chart
const methodColors = ['#6366f1', '#f59e0b', '#10b981', '#ef4444', '#8b5cf6', '#ec4899']

const doughnutChartData = computed(() => {
  if (!stats.value?.method_breakdown?.length) return null
  const mb = stats.value.method_breakdown
  return {
    labels: mb.map((m) => formatPaymentMethod(m.method)),
    datasets: [
      {
        data: mb.map((m) => m.amount),
        backgroundColor: mb.map((_, i) => methodColors[i % methodColors.length]),
        borderWidth: 0,
        hoverOffset: 6
      }
    ]
  }
})

const doughnutChartOptions = computed(() => {
  const dark = isDarkMode.value
  const textColor = dark ? '#9ca3af' : '#6b7280'
  return {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '65%',
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: { color: textColor, usePointStyle: true, boxWidth: 8, font: { size: 10 }, padding: 12 }
      },
      tooltip: {
        backgroundColor: dark ? '#1f2937' : '#fff',
        titleColor: dark ? '#f3f4f6' : '#111827',
        bodyColor: dark ? '#d1d5db' : '#4b5563',
        borderColor: dark ? '#374151' : '#f3f4f6',
        borderWidth: 1,
        padding: 10,
        callbacks: {
          label(ctx: any) {
            return ` ¥${ctx.parsed.toFixed(2)}`
          }
        }
      }
    }
  }
})

async function loadStats() {
  statsLoading.value = true
  try {
    stats.value = await paymentOrdersAPI.getStats(selectedDays.value)
  } catch (e) {
    console.error('Failed to load payment stats:', e)
  } finally {
    statsLoading.value = false
  }
}

function changeDays(d: number) {
  selectedDays.value = d
  loadStats()
}

// --- Orders Table ---
const loading = ref(false)
const orders = ref<AdminPaymentOrder[]>([])
const searchQuery = ref('')
let searchTimeout: ReturnType<typeof setTimeout> | null = null

const filters = reactive({
  status: '',
  start_date: `${new Date().getFullYear()}-${String(new Date().getMonth()+1).padStart(2,"0")}-${String(new Date().getDate()).padStart(2,"0")}`,
  end_date: `${new Date().getFullYear()}-${String(new Date().getMonth()+1).padStart(2,"0")}-${String(new Date().getDate()).padStart(2,"0")}`
})

const pagination = reactive({
  page: 1,
  page_size: 20,
  total: 0
})

const statusOptions = computed(() => [
  { value: '', label: t('admin.paymentOrders.allStatus') },
  { value: 'pending', label: t('admin.paymentOrders.pending') },
  { value: 'paid', label: t('admin.paymentOrders.paid') },
  { value: 'expired', label: t('admin.paymentOrders.expired') },
  { value: 'failed', label: t('admin.paymentOrders.failed') }
])

function statusClass(status: string): string {
  switch (status) {
    case 'paid':
      return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
    case 'pending':
      return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
    case 'expired':
      return 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400'
    case 'failed':
      return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
    default:
      return 'bg-gray-100 text-gray-700 dark:bg-dark-700 dark:text-gray-300'
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case 'paid':
      return t('admin.paymentOrders.paid')
    case 'pending':
      return t('admin.paymentOrders.pending')
    case 'expired':
      return t('admin.paymentOrders.expired')
    case 'failed':
      return t('admin.paymentOrders.failed')
    default:
      return status
  }
}

function formatPaymentMethod(method: string): string {
  const map: Record<string, string> = {
    alipay: '支付宝',
    alipay_f2f: '支付宝当面付',
    wechat: '微信支付',
    epay: '易支付',
    epay_alipay: '易支付-支付宝',
    epay_wechat: '易支付-微信'
  }
  return map[method] || method
}

function formatTime(dateStr: string): string {
  if (!dateStr) return '-'
  const d = new Date(dateStr)
  return d.toLocaleString()
}

async function loadOrders() {
  loading.value = true
  try {
    const res = await paymentOrdersAPI.list(pagination.page, pagination.page_size, {
      status: filters.status || undefined,
      start_date: filters.start_date || undefined,
      end_date: filters.end_date || undefined,
      search: searchQuery.value || undefined
    })
    orders.value = res.items || []
    pagination.total = res.total || 0
  } catch (e) {
    console.error('Failed to load payment orders:', e)
  } finally {
    loading.value = false
  }
}

function handleSearch() {
  if (searchTimeout) clearTimeout(searchTimeout)
  searchTimeout = setTimeout(() => {
    pagination.page = 1
    loadOrders()
  }, 300)
}

function applyFilter() {
  pagination.page = 1
  loadOrders()
}

function handlePageChange(page: number) {
  pagination.page = page
  loadOrders()
}

function handlePageSizeChange(size: number) {
  pagination.page_size = size
  pagination.page = 1
  loadOrders()
}

onMounted(() => {
  loadStats()
  loadOrders()
})
</script>
