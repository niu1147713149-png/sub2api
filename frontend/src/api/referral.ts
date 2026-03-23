import { apiClient } from './client'

export interface ReferralInfo {
  referral_code: string
  commission_rate: number
  total_earnings: number
  total_referred: number
}

export interface CommissionRecord {
  id: number
  referred_user_id: number
  order_amount: number
  commission_rate: number
  commission_amount: number
  created_at: string
}

export interface CommissionsResponse {
  items: CommissionRecord[]
  total: number
  page: number
  page_size: number
  pages: number
}

export const referralAPI = {
  getReferralInfo: async (): Promise<ReferralInfo> => {
    const { data } = await apiClient.get<ReferralInfo>('/user/referral')
    return data
  },

  getCommissions: async (page = 1, pageSize = 20): Promise<CommissionsResponse> => {
    const { data } = await apiClient.get<CommissionsResponse>('/user/referral/commissions', {
      params: { page, page_size: pageSize }
    })
    return data
  },
}
