/**
 * Admin Payment Orders API endpoints
 * Handles payment order management for administrators
 */

import { apiClient } from '../client'
import type { PaginatedResponse } from '@/types'

export interface AdminPaymentOrder {
  id: number
  order_no: string
  trade_no?: string
  user_id: number
  user_email: string
  amount: number
  credit: number
  payment_method: string
  status: string
  created_at: string
  paid_at?: string
  expired_at?: string
}

export interface PaymentStats {
  today_amount: number
  today_count: number
  yesterday_amount: number
  yesterday_count: number
  week_amount: number
  week_count: number
  month_amount: number
  month_count: number
  total_amount: number
  total_count: number
  trend_points: { date: string; amount: number; count: number }[]
  method_breakdown: { method: string; amount: number; count: number }[]
}

/**
 * List all payment orders with pagination and filters
 */
export async function list(
  page: number = 1,
  pageSize: number = 20,
  filters?: {
    status?: string
    start_date?: string
    end_date?: string
    search?: string
  }
): Promise<PaginatedResponse<AdminPaymentOrder>> {
  const params: Record<string, any> = {
    page,
    page_size: pageSize,
    status: filters?.status,
    start_date: filters?.start_date,
    end_date: filters?.end_date,
    search: filters?.search
  }

  const { data } = await apiClient.get<PaginatedResponse<AdminPaymentOrder>>(
    '/admin/payment-orders',
    { params }
  )
  return data
}

/**
 * Get payment statistics
 */
export async function getStats(days: number = 30): Promise<PaymentStats> {
  const { data } = await apiClient.get<PaymentStats>('/admin/payment-orders/stats', {
    params: { days }
  })
  return data
}

const paymentOrdersAPI = { list, getStats }

export default paymentOrdersAPI
