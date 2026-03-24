/**
 * Model Pricing API endpoints
 * Fetches model pricing data from LiteLLM pricing repository
 */

import { apiClient } from './client'

export interface ModelPricingDisplay {
  id: string
  provider: string
  input_price: number
  output_price: number
  cache_read_price: number | null
  cache_create_price: number | null
  mode: string
}

export interface ModelPricingResponse {
  models: ModelPricingDisplay[]
  updated_at: string
}

/**
 * Get all model pricing data for display
 * @returns Model pricing list with last updated timestamp
 */
export async function getModelPricing(): Promise<ModelPricingResponse> {
  const { data } = await apiClient.get<ModelPricingResponse>('/settings/model-pricing')
  return data
}

// Model Square types (user-specific available models)

export interface ModelSquareGroup {
  id: number
  name: string
  platform: string
  rate_multiplier: number
  // 图片生成按次计费
  image_price_1k: number | null
  image_price_2k: number | null
  image_price_4k: number | null
  // Sora 按次计费
  sora_image_price_360: number | null
  sora_image_price_540: number | null
  sora_video_price_per_request: number | null
  sora_video_price_per_request_hd: number | null
  // 分组按次收费
  per_request_price: number | null
  model_per_request_prices: Record<string, number> | null
}

export interface ModelSquareItem {
  id: string
  provider: string
  input_price: number
  output_price: number
  cache_read_price: number | null
  cache_create_price: number | null
  mode: string
  available: boolean
  group_ids: number[]
}

export interface ModelSquareResponse {
  groups: ModelSquareGroup[]
  models: ModelSquareItem[]
  updated_at: string
}

/**
 * Get model square data for the authenticated user
 * Returns models available in the user's groups with pricing info
 */
export async function getModelSquare(): Promise<ModelSquareResponse> {
  const { data } = await apiClient.get<ModelSquareResponse>('/model-square')
  return data
}
