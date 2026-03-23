package admin

import (
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// PaymentOrderHandler handles admin payment order management
type PaymentOrderHandler struct {
	paymentService *service.PaymentService
}

// NewPaymentOrderHandler creates a new admin payment order handler
func NewPaymentOrderHandler(paymentService *service.PaymentService) *PaymentOrderHandler {
	return &PaymentOrderHandler{paymentService: paymentService}
}

// List handles listing all payment orders with pagination and filters
// GET /api/v1/admin/payment-orders
func (h *PaymentOrderHandler) List(c *gin.Context) {
	page, pageSize := response.ParsePagination(c)

	filters := service.AdminOrderListFilters{
		Status:    c.Query("status"),
		StartDate: c.Query("start_date"),
		EndDate:   c.Query("end_date"),
		Search:    c.Query("search"),
	}

	orders, total, err := h.paymentService.AdminListOrders(c.Request.Context(), page, pageSize, filters)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Paginated(c, orders, total, page, pageSize)
}

// Stats 获取支付统计数据
// GET /api/v1/admin/payment-orders/stats
func (h *PaymentOrderHandler) Stats(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	if days < 7 {
		days = 7
	}
	if days > 90 {
		days = 90
	}
	stats, err := h.paymentService.GetPaymentStats(c.Request.Context(), days)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, stats)
}
