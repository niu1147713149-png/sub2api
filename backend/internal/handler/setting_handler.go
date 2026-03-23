package handler

import (
	"time"

	"github.com/Wei-Shaw/sub2api/internal/handler/dto"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// SettingHandler 公开设置处理器（无需认证）
type SettingHandler struct {
	settingService *service.SettingService
	pricingService *service.PricingService
	apiKeyService  *service.APIKeyService
	gatewayService *service.GatewayService
	version        string
}

// NewSettingHandler 创建公开设置处理器
func NewSettingHandler(settingService *service.SettingService, pricingService *service.PricingService, apiKeyService *service.APIKeyService, gatewayService *service.GatewayService, version string) *SettingHandler {
	return &SettingHandler{
		settingService: settingService,
		pricingService: pricingService,
		apiKeyService:  apiKeyService,
		gatewayService: gatewayService,
		version:        version,
	}
}

// GetPublicSettings 获取公开设置
// GET /api/v1/settings/public
func (h *SettingHandler) GetPublicSettings(c *gin.Context) {
	settings, err := h.settingService.GetPublicSettings(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, dto.PublicSettings{
		RegistrationEnabled:              settings.RegistrationEnabled,
		EmailVerifyEnabled:               settings.EmailVerifyEnabled,
		RegistrationEmailSuffixWhitelist: settings.RegistrationEmailSuffixWhitelist,
		PromoCodeEnabled:                 settings.PromoCodeEnabled,
		PasswordResetEnabled:             settings.PasswordResetEnabled,
		InvitationCodeEnabled:            settings.InvitationCodeEnabled,
		TotpEnabled:                      settings.TotpEnabled,
		TurnstileEnabled:                 settings.TurnstileEnabled,
		TurnstileSiteKey:                 settings.TurnstileSiteKey,
		SiteName:                         settings.SiteName,
		SiteLogo:                         settings.SiteLogo,
		SiteSubtitle:                     settings.SiteSubtitle,
		APIBaseURL:                       settings.APIBaseURL,
		ContactInfo:                      settings.ContactInfo,
		DocURL:                           settings.DocURL,
		HomeContent:                      settings.HomeContent,
		HideCcsImportButton:              settings.HideCcsImportButton,
		PurchaseSubscriptionEnabled:      settings.PurchaseSubscriptionEnabled,
		PurchaseSubscriptionURL:          settings.PurchaseSubscriptionURL,
		CustomMenuItems:                  dto.ParseUserVisibleMenuItems(settings.CustomMenuItems),
		LinuxDoOAuthEnabled:              settings.LinuxDoOAuthEnabled,
		SoraClientEnabled:                settings.SoraClientEnabled,
		ReferralEnabled:                  settings.ReferralEnabled,
		Version:                          h.version,
	})
}

// GetModelPricing 获取模型定价列表（公开接口）
// GET /api/v1/model-pricing
func (h *SettingHandler) GetModelPricing(c *gin.Context) {
	models, updatedAt := h.pricingService.GetAllModelPricing()
	c.JSON(200, gin.H{
		"models":     models,
		"updated_at": updatedAt,
	})
}

// modelSquareGroup 模型广场分组信息
type modelSquareGroup struct {
	ID             int64   `json:"id"`
	Name           string  `json:"name"`
	Platform       string  `json:"platform"`
	RateMultiplier float64 `json:"rate_multiplier"`
	// 图片生成按次计费
	ImagePrice1K *float64 `json:"image_price_1k"`
	ImagePrice2K *float64 `json:"image_price_2k"`
	ImagePrice4K *float64 `json:"image_price_4k"`
	// Sora 按次计费
	SoraImagePrice360          *float64 `json:"sora_image_price_360"`
	SoraImagePrice540          *float64 `json:"sora_image_price_540"`
	SoraVideoPricePerRequest   *float64 `json:"sora_video_price_per_request"`
	SoraVideoPricePerRequestHD *float64 `json:"sora_video_price_per_request_hd"`
}

// modelSquareItem 模型广场模型项
type modelSquareItem struct {
	ID               string   `json:"id"`
	Provider         string   `json:"provider"`
	InputPrice       float64  `json:"input_price"`
	OutputPrice      float64  `json:"output_price"`
	CacheReadPrice   *float64 `json:"cache_read_price"`
	CacheCreatePrice *float64 `json:"cache_create_price"`
	Mode             string   `json:"mode"`
	Available        bool     `json:"available"`
	GroupIDs         []int64  `json:"group_ids"`
}

// GetModelSquare 获取用户可用模型广场数据（需认证）
// GET /api/v1/model-square
func (h *SettingHandler) GetModelSquare(c *gin.Context) {
	ctx := c.Request.Context()
	userID := getUserIDFromContext(c)
	if userID == 0 {
		response.Error(c, 401, "unauthorized")
		return
	}

	// 1. 获取用户可用分组
	groups, err := h.apiKeyService.GetAvailableGroups(ctx, userID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	// 2. 收集每个分组的可用模型
	// modelName -> []groupID
	modelGroupMap := make(map[string][]int64)
	groupList := make([]modelSquareGroup, 0, len(groups))

	for _, g := range groups {
		groupList = append(groupList, modelSquareGroup{
			ID:                         g.ID,
			Name:                       g.Name,
			Platform:                   g.Platform,
			RateMultiplier:             g.RateMultiplier,
			ImagePrice1K:               g.ImagePrice1K,
			ImagePrice2K:               g.ImagePrice2K,
			ImagePrice4K:               g.ImagePrice4K,
			SoraImagePrice360:          g.SoraImagePrice360,
			SoraImagePrice540:          g.SoraImagePrice540,
			SoraVideoPricePerRequest:   g.SoraVideoPricePerRequest,
			SoraVideoPricePerRequestHD: g.SoraVideoPricePerRequestHD,
		})

		gID := g.ID
		availableModels := h.gatewayService.GetAvailableModels(ctx, &gID, "")

		// 如果分组下没有可用账号，跳过该分组（不显示模型）
		if len(availableModels) == 0 {
			continue
		}

		for _, modelName := range availableModels {
			modelGroupMap[modelName] = append(modelGroupMap[modelName], g.ID)
		}
	}

	// 3. 获取官方定价数据
	allPricing, updatedAt := h.pricingService.GetAllModelPricing()

	// 构建定价 map（by ID）用于快速查找
	pricingMap := make(map[string]service.ModelPricingDisplayItem, len(allPricing))
	for _, p := range allPricing {
		pricingMap[p.ID] = p
	}

	// 4. 合并：为用户可用的每个模型匹配定价
	seen := make(map[string]bool)
	items := make([]modelSquareItem, 0, len(modelGroupMap))

	for modelName, groupIDs := range modelGroupMap {
		if seen[modelName] {
			continue
		}
		seen[modelName] = true

		item := modelSquareItem{
			ID:        modelName,
			Available: true,
			GroupIDs:  groupIDs,
		}

		// 先精确匹配定价
		if p, ok := pricingMap[modelName]; ok {
			item.Provider = p.Provider
			item.InputPrice = p.InputPrice
			item.OutputPrice = p.OutputPrice
			item.CacheReadPrice = p.CacheReadPrice
			item.CacheCreatePrice = p.CacheCreatePrice
			item.Mode = p.Mode
		} else {
			// 使用模糊匹配
			pricing := h.pricingService.GetModelPricing(modelName)
			if pricing != nil {
				item.InputPrice = pricing.InputCostPerToken * 1_000_000
				item.OutputPrice = pricing.OutputCostPerToken * 1_000_000
				item.Provider = pricing.LiteLLMProvider
				item.Mode = pricing.Mode
				if pricing.SupportsPromptCaching {
					cacheRead := pricing.CacheReadInputTokenCost * 1_000_000
					cacheCreate := pricing.CacheCreationInputTokenCost * 1_000_000
					item.CacheReadPrice = &cacheRead
					item.CacheCreatePrice = &cacheCreate
				}
			}
		}

		items = append(items, item)
	}

	// 5. 返回合并后的数据
	c.JSON(200, gin.H{
		"groups":     groupList,
		"models":     items,
		"updated_at": updatedAt.Format(time.RFC3339),
	})
}
