package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service/payment"
)

var (
	ErrPaymentDisabled     = infraerrors.Forbidden("PAYMENT_DISABLED", "online payment is currently disabled")
	ErrPaymentMethodNotAvailable = infraerrors.BadRequest("PAYMENT_METHOD_NOT_AVAILABLE", "the selected payment method is not available")
	ErrInvalidAmount       = infraerrors.BadRequest("INVALID_AMOUNT", "payment amount is invalid")
	ErrOrderNotFound       = infraerrors.NotFound("ORDER_NOT_FOUND", "payment order not found")
	ErrOrderAlreadyPaid    = infraerrors.BadRequest("ORDER_ALREADY_PAID", "payment order has already been paid")
)

// PaymentOrder 支付订单
type PaymentOrder struct {
	ID            int64      `json:"id"`
	OrderNo       string     `json:"order_no"`
	TradeNo       string     `json:"trade_no,omitempty"`
	UserID        int64      `json:"user_id"`
	Amount        float64    `json:"amount"`
	Credit        float64    `json:"credit"`
	PaymentMethod string     `json:"payment_method"`
	Status        string     `json:"status"`
	NotifyData    string     `json:"-"`
	CreatedAt     time.Time  `json:"created_at"`
	PaidAt        *time.Time `json:"paid_at,omitempty"`
	ExpiredAt     *time.Time `json:"expired_at,omitempty"`
}

// PaymentConfig 支付配置（返回给前端）
type PaymentConfig struct {
	Enabled       bool      `json:"enabled"`
	Currency      string    `json:"currency"`
	ExchangeRate  float64   `json:"exchange_rate"`
	PresetAmounts []float64 `json:"preset_amounts"`
	MinAmount     float64   `json:"min_amount"`
	MaxAmount     float64   `json:"max_amount"`
	Methods       struct {
		Alipay      bool `json:"alipay"`
		AlipayF2F   bool `json:"alipay_f2f"`
		Wechat      bool `json:"wechat"`
		Epay        bool `json:"epay"`         // 向后兼容
		EpayAlipay  bool `json:"epay_alipay"`  // 易支付-支付宝
		EpayWechat  bool `json:"epay_wechat"`  // 易支付-微信
	} `json:"methods"`
}

// CreateOrderResult 创建订单结果
type CreateOrderResult struct {
	OrderID    int64  `json:"order_id"`
	OrderNo    string `json:"order_no"`
	PaymentURL string `json:"payment_url,omitempty"`
	QRCodeURL  string `json:"qr_code_url,omitempty"`
	FormHTML   string `json:"form_html,omitempty"`
}

// PaymentService 支付服务
type PaymentService struct {
	db                  *sql.DB
	settingRepo         SettingRepository
	settingSvc          *SettingService
	userRepo            UserRepository
	billingCacheService *BillingCacheService
}

// NewPaymentService 创建支付服务
func NewPaymentService(db *sql.DB, settingRepo SettingRepository, settingSvc *SettingService, userRepo UserRepository, billingCacheService *BillingCacheService) *PaymentService {
	return &PaymentService{
		db:                  db,
		settingRepo:         settingRepo,
		settingSvc:          settingSvc,
		userRepo:            userRepo,
		billingCacheService: billingCacheService,
	}
}

// GetPaymentConfig 获取支付配置（给前端用）
func (s *PaymentService) GetPaymentConfig(ctx context.Context) (*PaymentConfig, error) {
	keys := []string{
		SettingKeyPaymentEnabled,
		SettingKeyPaymentCurrency,
		SettingKeyPaymentExchangeRate,
		SettingKeyPaymentPresetAmounts,
		SettingKeyPaymentMinAmount,
		SettingKeyPaymentMaxAmount,
		SettingKeyAlipayEnabled,
		SettingKeyAlipayF2FEnabled,
		SettingKeyWechatEnabled,
		SettingKeyEpayEnabled,
		SettingKeyEpayType,
	}

	settings, err := s.settingRepo.GetMultiple(ctx, keys)
	if err != nil {
		return nil, fmt.Errorf("get payment settings: %w", err)
	}

	config := &PaymentConfig{
		Enabled:      settings[SettingKeyPaymentEnabled] == "true",
		Currency:     "CNY",
		ExchangeRate: 1.0,
		MinAmount:    1.0,
		MaxAmount:    10000.0,
	}

	if v := settings[SettingKeyPaymentCurrency]; v != "" {
		config.Currency = v
	}
	if v, err := strconv.ParseFloat(settings[SettingKeyPaymentExchangeRate], 64); err == nil && v > 0 {
		config.ExchangeRate = v
	}
	if v, err := strconv.ParseFloat(settings[SettingKeyPaymentMinAmount], 64); err == nil && v > 0 {
		config.MinAmount = v
	}
	if v, err := strconv.ParseFloat(settings[SettingKeyPaymentMaxAmount], 64); err == nil && v > 0 {
		config.MaxAmount = v
	}

	// 解析预设金额（支持 JSON 数组和逗号分隔两种格式）
	if raw := settings[SettingKeyPaymentPresetAmounts]; raw != "" {
		var amounts []float64
		if err := json.Unmarshal([]byte(raw), &amounts); err != nil {
			// 尝试逗号分隔格式: "10,50,100,500"
			parts := strings.Split(raw, ",")
			for _, p := range parts {
				if v, err := strconv.ParseFloat(strings.TrimSpace(p), 64); err == nil && v > 0 {
					amounts = append(amounts, v)
				}
			}
		}
		if len(amounts) > 0 {
			config.PresetAmounts = amounts
		}
	}
	if len(config.PresetAmounts) == 0 {
		config.PresetAmounts = []float64{10, 50, 100, 500}
	}

	alipayEnabled := settings[SettingKeyAlipayEnabled] == "true"
	alipayF2F := settings[SettingKeyAlipayF2FEnabled] == "true"
	// 当面付可独立于支付宝主开关使用；若二者同时开启，当面付优先
	config.Methods.AlipayF2F = alipayF2F
	config.Methods.Alipay = alipayEnabled && !alipayF2F
	config.Methods.Wechat = settings[SettingKeyWechatEnabled] == "true"

	epayEnabled := settings[SettingKeyEpayEnabled] == "true"
	epayType := settings[SettingKeyEpayType]
	if epayType == "" {
		epayType = "alipay" // 默认支付宝
	}
	config.Methods.Epay = epayEnabled
	config.Methods.EpayAlipay = epayEnabled && (epayType == "alipay" || epayType == "both")
	config.Methods.EpayWechat = epayEnabled && (epayType == "wxpay" || epayType == "both")

	return config, nil
}

// CreateOrder 创建支付订单
func (s *PaymentService) CreateOrder(ctx context.Context, userID int64, amount float64, method string) (*CreateOrderResult, error) {
	// 检查支付是否启用
	config, err := s.GetPaymentConfig(ctx)
	if err != nil {
		return nil, err
	}
	if !config.Enabled {
		return nil, ErrPaymentDisabled
	}

	// 验证金额
	if amount < config.MinAmount || amount > config.MaxAmount {
		return nil, infraerrors.BadRequest("INVALID_AMOUNT",
			fmt.Sprintf("amount must be between %.2f and %.2f", config.MinAmount, config.MaxAmount))
	}

	// 验证支付方式
	switch payment.PaymentMethod(method) {
	case payment.MethodAlipay:
		if !config.Methods.Alipay {
			return nil, ErrPaymentMethodNotAvailable
		}
	case payment.MethodAlipayF2F:
		if !config.Methods.AlipayF2F {
			return nil, ErrPaymentMethodNotAvailable
		}
	case payment.MethodWechat:
		if !config.Methods.Wechat {
			return nil, ErrPaymentMethodNotAvailable
		}
	case payment.MethodEpay:
		if !config.Methods.Epay {
			return nil, ErrPaymentMethodNotAvailable
		}
	case payment.MethodEpayAlipay:
		if !config.Methods.EpayAlipay {
			return nil, ErrPaymentMethodNotAvailable
		}
	case payment.MethodEpayWechat:
		if !config.Methods.EpayWechat {
			return nil, ErrPaymentMethodNotAvailable
		}
	default:
		return nil, ErrPaymentMethodNotAvailable
	}

	// 计算到账余额
	credit := amount * config.ExchangeRate

	// 生成订单号
	orderNo := generateOrderNo()

	// 插入订单
	var orderID int64
	err = s.db.QueryRowContext(ctx,
		`INSERT INTO payment_orders (order_no, user_id, amount, credit, payment_method, status, created_at)
		 VALUES ($1, $2, $3, $4, $5, 'pending', NOW()) RETURNING id`,
		orderNo, userID, amount, credit, method,
	).Scan(&orderID)
	if err != nil {
		return nil, fmt.Errorf("create payment order: %w", err)
	}

	// 调用支付网关
	gateway, err := s.getGateway(ctx, payment.PaymentMethod(method))
	if err != nil {
		return nil, fmt.Errorf("get payment gateway: %w", err)
	}

	payResult, err := gateway.CreatePay(&payment.CreatePayRequest{
		OrderNo: orderNo,
		Amount:  amount,
		Subject: "Balance Top-up",
	})
	if err != nil {
		// 标记订单失败
		_, _ = s.db.ExecContext(ctx, `UPDATE payment_orders SET status = 'failed' WHERE id = $1`, orderID)
		return nil, fmt.Errorf("create payment: %w", err)
	}

	return &CreateOrderResult{
		OrderID:    orderID,
		OrderNo:    orderNo,
		PaymentURL: payResult.PaymentURL,
		QRCodeURL:  payResult.QRCodeURL,
		FormHTML:   payResult.FormHTML,
	}, nil
}

// HandleNotify 处理支付回调
func (s *PaymentService) HandleNotify(ctx context.Context, channel string, params map[string]string) error {
	gateway, err := s.getGateway(ctx, payment.PaymentMethod(channel))
	if err != nil {
		return fmt.Errorf("get gateway for notify: %w", err)
	}

	result, err := gateway.VerifyNotify(params)
	if err != nil {
		return fmt.Errorf("verify notify: %w", err)
	}

	if !result.Success {
		log.Printf("payment notify: order %s not success", result.OrderNo)
		return nil
	}

	// 在事务中处理
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// 查询订单
	var order PaymentOrder
	err = tx.QueryRowContext(ctx,
		`SELECT id, order_no, user_id, amount, credit, status FROM payment_orders WHERE order_no = $1 FOR UPDATE`,
		result.OrderNo,
	).Scan(&order.ID, &order.OrderNo, &order.UserID, &order.Amount, &order.Credit, &order.Status)
	if err == sql.ErrNoRows {
		return fmt.Errorf("order not found: %s", result.OrderNo)
	}
	if err != nil {
		return fmt.Errorf("query order: %w", err)
	}

	// 检查订单状态
	if order.Status != string(payment.OrderStatusPending) {
		log.Printf("payment notify: order %s already processed (status=%s)", result.OrderNo, order.Status)
		return nil // 幂等处理
	}

	// 金额校验
	if result.Amount > 0 && fmt.Sprintf("%.2f", result.Amount) != fmt.Sprintf("%.2f", order.Amount) {
		return fmt.Errorf("amount mismatch: expected %.2f, got %.2f", order.Amount, result.Amount)
	}

	// 序列化通知数据
	notifyJSON, _ := json.Marshal(params)

	// 更新订单状态
	_, err = tx.ExecContext(ctx,
		`UPDATE payment_orders SET status = 'paid', trade_no = $1, notify_data = $2, paid_at = NOW() WHERE id = $3`,
		result.TradeNo, string(notifyJSON), order.ID,
	)
	if err != nil {
		return fmt.Errorf("update order status: %w", err)
	}

	// 增加用户余额（在同一事务内直接更新，确保原子性）
	_, err = tx.ExecContext(ctx,
		`UPDATE users SET balance = balance + $1 WHERE id = $2`,
		order.Credit, order.UserID,
	)
	if err != nil {
		return fmt.Errorf("update user balance: %w", err)
	}

	// 写入充值记录到 redeem_codes 表（用于余额变动历史展示）
	rechargeCode := make([]byte, 16)
	_, _ = rand.Read(rechargeCode)
	_, _ = tx.ExecContext(ctx,
		`INSERT INTO redeem_codes (code, type, value, status, used_by, used_at, notes) VALUES ($1, 'payment_balance', $2, 'used', $3, NOW(), $4)`,
		hex.EncodeToString(rechargeCode), order.Credit, order.UserID,
		fmt.Sprintf("在线充值 订单号:%s 支付金额:%.2f", order.OrderNo, order.Amount),
	)

	// 推荐返利（同一事务内原子操作）
	if s.settingSvc != nil && s.settingSvc.IsReferralEnabled(ctx) {
		var referrerID sql.NullInt64
		_ = tx.QueryRowContext(ctx, `SELECT referrer_id FROM users WHERE id = $1`, order.UserID).Scan(&referrerID)
		if referrerID.Valid && referrerID.Int64 > 0 {
			rate := s.settingSvc.GetReferralCommissionRate(ctx)
			if rate > 0 {
				commission := order.Credit * rate
				_, execErr := tx.ExecContext(ctx,
					`UPDATE users SET balance = balance + $1 WHERE id = $2`,
					commission, referrerID.Int64,
				)
				if execErr != nil {
					log.Printf("referral commission: failed to update referrer balance: %v", execErr)
				} else {
					_, _ = tx.ExecContext(ctx,
						`INSERT INTO referral_commissions (referrer_id, referred_user_id, order_id, order_amount, commission_rate, commission_amount) VALUES ($1,$2,$3,$4,$5,$6)`,
						referrerID.Int64, order.UserID, order.ID, order.Amount, rate, commission,
					)
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	log.Printf("payment success: order=%s user=%d amount=%.2f credit=%.8f", order.OrderNo, order.UserID, order.Amount, order.Credit)

	// 清除用户余额缓存，确保下次请求读取最新余额
	if s.billingCacheService != nil {
		cacheCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.billingCacheService.InvalidateUserBalance(cacheCtx, order.UserID); err != nil {
			log.Printf("payment: invalidate balance cache failed for user %d: %v", order.UserID, err)
		}
		// 如果有推荐人，也清除推荐人的余额缓存
		if s.settingSvc != nil && s.settingSvc.IsReferralEnabled(ctx) {
			var referrerID sql.NullInt64
			_ = s.db.QueryRowContext(cacheCtx, `SELECT referrer_id FROM users WHERE id = $1`, order.UserID).Scan(&referrerID)
			if referrerID.Valid && referrerID.Int64 > 0 {
				_ = s.billingCacheService.InvalidateUserBalance(cacheCtx, referrerID.Int64)
			}
		}
	}

	return nil
}

// GetOrderStatus 获取订单状态（支持主动查询上游支付状态）
func (s *PaymentService) GetOrderStatus(ctx context.Context, orderID int64, userID int64) (string, error) {
	var status string
	var orderNo string
	var paymentMethod string
	var amount float64
	var credit float64
	err := s.db.QueryRowContext(ctx,
		`SELECT status, order_no, payment_method, amount, credit FROM payment_orders WHERE id = $1 AND user_id = $2`,
		orderID, userID,
	).Scan(&status, &orderNo, &paymentMethod, &amount, &credit)
	if err == sql.ErrNoRows {
		return "", ErrOrderNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get order status: %w", err)
	}

	// 如果订单还是 pending，主动向支付网关查询
	if status == string(payment.OrderStatusPending) {
		if updatedStatus, err := s.activeQueryPayment(ctx, orderID, orderNo, paymentMethod, userID, amount, credit); err != nil {
			log.Printf("active query payment error: orderID=%d err=%v", orderID, err)
		} else if updatedStatus != "" {
			status = updatedStatus
		}
	}

	return status, nil
}

// activeQueryPayment 主动查询支付网关交易状态
func (s *PaymentService) activeQueryPayment(ctx context.Context, orderID int64, orderNo, paymentMethod string, userID int64, amount, credit float64) (string, error) {
	method := payment.PaymentMethod(paymentMethod)

	// 只支持支付宝和当面付的主动查询
	switch method {
	case payment.MethodAlipay, payment.MethodAlipayF2F:
		// 继续处理
	default:
		return "", nil
	}

	gateway, err := s.getGateway(ctx, method)
	if err != nil {
		return "", fmt.Errorf("get gateway: %w", err)
	}

	querier, ok := gateway.(payment.TradeQuerier)
	if !ok {
		return "", nil
	}

	result, err := querier.QueryTrade(orderNo)
	if err != nil {
		return "", fmt.Errorf("query trade: %w", err)
	}

	if !result.Success {
		return "", nil
	}

	// 交易成功，更新订单（在事务中处理）
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// 再次检查订单状态，防止并发
	var currentStatus string
	err = tx.QueryRowContext(ctx,
		`SELECT status FROM payment_orders WHERE id = $1 FOR UPDATE`,
		orderID,
	).Scan(&currentStatus)
	if err != nil {
		return "", fmt.Errorf("recheck order: %w", err)
	}
	if currentStatus != string(payment.OrderStatusPending) {
		return currentStatus, nil
	}

	// 金额校验
	if result.Amount > 0 && fmt.Sprintf("%.2f", result.Amount) != fmt.Sprintf("%.2f", amount) {
		return "", fmt.Errorf("amount mismatch: expected %.2f, got %.2f", amount, result.Amount)
	}

	// 更新订单状态
	notifyJSON, _ := json.Marshal(map[string]string{
		"source":       "active_query",
		"trade_no":     result.TradeNo,
		"trade_status": result.TradeStatus,
	})
	_, err = tx.ExecContext(ctx,
		`UPDATE payment_orders SET status = 'paid', trade_no = $1, notify_data = $2, paid_at = NOW() WHERE id = $3`,
		result.TradeNo, string(notifyJSON), orderID,
	)
	if err != nil {
		return "", fmt.Errorf("update order: %w", err)
	}

	// 增加用户余额
	_, err = tx.ExecContext(ctx,
		`UPDATE users SET balance = balance + $1 WHERE id = $2`,
		credit, userID,
	)
	if err != nil {
		return "", fmt.Errorf("update balance: %w", err)
	}

	// 写入充值记录到 redeem_codes 表（用于余额变动历史展示）
	rechargeCode2 := make([]byte, 16)
	_, _ = rand.Read(rechargeCode2)
	_, _ = tx.ExecContext(ctx,
		`INSERT INTO redeem_codes (code, type, value, status, used_by, used_at, notes) VALUES ($1, 'payment_balance', $2, 'used', $3, NOW(), $4)`,
		hex.EncodeToString(rechargeCode2), credit, userID,
		fmt.Sprintf("在线充值 订单号:%s 支付金额:%.2f", orderNo, amount),
	)

	// 推荐返利
	if s.settingSvc != nil && s.settingSvc.IsReferralEnabled(ctx) {
		var referrerID sql.NullInt64
		_ = tx.QueryRowContext(ctx, `SELECT referrer_id FROM users WHERE id = $1`, userID).Scan(&referrerID)
		if referrerID.Valid && referrerID.Int64 > 0 {
			rate := s.settingSvc.GetReferralCommissionRate(ctx)
			if rate > 0 {
				commission := credit * rate
				_, execErr := tx.ExecContext(ctx,
					`UPDATE users SET balance = balance + $1 WHERE id = $2`,
					commission, referrerID.Int64,
				)
				if execErr != nil {
					log.Printf("referral commission (active query): failed to update referrer balance: %v", execErr)
				} else {
					_, _ = tx.ExecContext(ctx,
						`INSERT INTO referral_commissions (referrer_id, referred_user_id, order_id, order_amount, commission_rate, commission_amount) VALUES ($1,$2,$3,$4,$5,$6)`,
						referrerID.Int64, userID, orderID, amount, rate, commission,
					)
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit tx: %w", err)
	}

	log.Printf("payment success (active query): order=%s user=%d amount=%.2f credit=%.8f", orderNo, userID, amount, credit)

	// 清除用户余额缓存，确保下次请求读取最新余额
	if s.billingCacheService != nil {
		cacheCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.billingCacheService.InvalidateUserBalance(cacheCtx, userID); err != nil {
			log.Printf("payment (active query): invalidate balance cache failed for user %d: %v", userID, err)
		}
		// 如果有推荐人，也清除推荐人的余额缓存
		if s.settingSvc != nil && s.settingSvc.IsReferralEnabled(ctx) {
			var referrerID sql.NullInt64
			_ = s.db.QueryRowContext(cacheCtx, `SELECT referrer_id FROM users WHERE id = $1`, userID).Scan(&referrerID)
			if referrerID.Valid && referrerID.Int64 > 0 {
				_ = s.billingCacheService.InvalidateUserBalance(cacheCtx, referrerID.Int64)
			}
		}
	}

	return string(payment.OrderStatusPaid), nil
}

// GetOrderPaymentMethod 根据订单号获取支付方式
func (s *PaymentService) GetOrderPaymentMethod(ctx context.Context, orderNo string) (string, error) {
	var method string
	err := s.db.QueryRowContext(ctx,
		`SELECT payment_method FROM payment_orders WHERE order_no = $1`,
		orderNo,
	).Scan(&method)
	if err != nil {
		return "", err
	}
	return method, nil
}

// GetUserOrders 获取用户订单列表
func (s *PaymentService) GetUserOrders(ctx context.Context, userID int64, page, pageSize int) ([]PaymentOrder, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	var total int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM payment_orders WHERE user_id = $1`, userID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count orders: %w", err)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, order_no, COALESCE(trade_no, ''), user_id, amount, credit, payment_method, status, created_at, paid_at, expired_at
		 FROM payment_orders WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		userID, pageSize, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("query orders: %w", err)
	}
	defer rows.Close()

	var orders []PaymentOrder
	for rows.Next() {
		var o PaymentOrder
		if err := rows.Scan(&o.ID, &o.OrderNo, &o.TradeNo, &o.UserID, &o.Amount, &o.Credit,
			&o.PaymentMethod, &o.Status, &o.CreatedAt, &o.PaidAt, &o.ExpiredAt); err != nil {
			return nil, 0, fmt.Errorf("scan order: %w", err)
		}
		orders = append(orders, o)
	}

	return orders, total, nil
}

// AdminPaymentOrder 管理员查看的支付订单（包含用户信息）
type AdminPaymentOrder struct {
	ID            int64      `json:"id"`
	OrderNo       string     `json:"order_no"`
	TradeNo       string     `json:"trade_no,omitempty"`
	UserID        int64      `json:"user_id"`
	UserEmail     string     `json:"user_email"`
	Amount        float64    `json:"amount"`
	Credit        float64    `json:"credit"`
	PaymentMethod string     `json:"payment_method"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	PaidAt        *time.Time `json:"paid_at,omitempty"`
	ExpiredAt     *time.Time `json:"expired_at,omitempty"`
}

// AdminOrderListFilters 管理员订单列表过滤条件
type AdminOrderListFilters struct {
	Status    string // pending/paid/expired
	StartDate string // yyyy-mm-dd
	EndDate   string // yyyy-mm-dd
	Search    string // order_no or user_id
}

// AdminListOrders 管理员查询所有订单（带分页和过滤）
func (s *PaymentService) AdminListOrders(ctx context.Context, page, pageSize int, filters AdminOrderListFilters) ([]AdminPaymentOrder, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	// 构建 WHERE 条件
	where := "1=1"
	args := []interface{}{}
	argIdx := 1

	if filters.Status != "" {
		where += fmt.Sprintf(" AND po.status = $%d", argIdx)
		args = append(args, filters.Status)
		argIdx++
	}
	if filters.StartDate != "" {
		where += fmt.Sprintf(" AND po.created_at >= $%d::date", argIdx)
		args = append(args, filters.StartDate)
		argIdx++
	}
	if filters.EndDate != "" {
		where += fmt.Sprintf(" AND po.created_at < ($%d::date + interval '1 day')", argIdx)
		args = append(args, filters.EndDate)
		argIdx++
	}
	if filters.Search != "" {
		where += fmt.Sprintf(" AND (po.order_no ILIKE $%d OR CAST(po.user_id AS TEXT) = $%d)", argIdx, argIdx+1)
		args = append(args, "%"+filters.Search+"%", filters.Search)
		argIdx += 2
	}

	// 查询总数
	var total int64
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM payment_orders po WHERE %s", where)
	err := s.db.QueryRowContext(ctx, countSQL, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count admin orders: %w", err)
	}

	// 查询列表
	querySQL := fmt.Sprintf(
		`SELECT po.id, po.order_no, COALESCE(po.trade_no, ''), po.user_id, COALESCE(u.email, ''),
		        po.amount, po.credit, po.payment_method, po.status, po.created_at, po.paid_at, po.expired_at
		 FROM payment_orders po
		 LEFT JOIN users u ON u.id = po.user_id
		 WHERE %s
		 ORDER BY po.created_at DESC
		 LIMIT $%d OFFSET $%d`, where, argIdx, argIdx+1)
	args = append(args, pageSize, offset)

	rows, err := s.db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query admin orders: %w", err)
	}
	defer rows.Close()

	var orders []AdminPaymentOrder
	for rows.Next() {
		var o AdminPaymentOrder
		if err := rows.Scan(&o.ID, &o.OrderNo, &o.TradeNo, &o.UserID, &o.UserEmail,
			&o.Amount, &o.Credit, &o.PaymentMethod, &o.Status, &o.CreatedAt, &o.PaidAt, &o.ExpiredAt); err != nil {
			return nil, 0, fmt.Errorf("scan admin order: %w", err)
		}
		orders = append(orders, o)
	}

	return orders, total, nil
}

// ExpireOrders 过期超时订单（>30分钟未支付）
func (s *PaymentService) ExpireOrders(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE payment_orders SET status = 'expired', expired_at = NOW()
		 WHERE status = 'pending' AND created_at < NOW() - INTERVAL '30 minutes'`,
	)
	if err != nil {
		return fmt.Errorf("expire orders: %w", err)
	}
	return nil
}

// getGateway 根据支付方式获取网关
func (s *PaymentService) getGateway(ctx context.Context, method payment.PaymentMethod) (payment.Gateway, error) {
	settings, err := s.settingRepo.GetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("get settings: %w", err)
	}

	// 构造回调 URL 基础
	baseURL := strings.TrimRight(settings[SettingKeyAPIBaseURL], "/")
	if baseURL == "" {
		return nil, fmt.Errorf("payment callback base URL (api_base_url) is not configured")
	}

	switch method {
	case payment.MethodAlipay:
		cfg := &payment.AlipayConfig{
			AppID:      settings[SettingKeyAlipayAppID],
			PrivateKey: settings[SettingKeyAlipayPrivateKey],
			PublicKey:  settings[SettingKeyAlipayPublicKey],
		}
		cfg.NotifyURL = baseURL + "/api/v1/payment/notify/alipay"
		cfg.ReturnURL = baseURL + "/api/v1/payment/return"
		log.Printf("alipay gateway: notify_url=%s", cfg.NotifyURL)
		return payment.NewAlipayGateway(cfg), nil

	case payment.MethodAlipayF2F:
		cfg := &payment.AlipayConfig{
			AppID:      settings[SettingKeyAlipayAppID],
			PrivateKey: settings[SettingKeyAlipayPrivateKey],
			PublicKey:  settings[SettingKeyAlipayPublicKey],
		}
		cfg.NotifyURL = baseURL + "/api/v1/payment/notify/alipay"
		log.Printf("alipay f2f gateway: notify_url=%s app_id=%q key_len=%d", cfg.NotifyURL, cfg.AppID, len(cfg.PrivateKey))
		return payment.NewAlipayF2FGateway(cfg), nil

	case payment.MethodWechat:
		cfg := &payment.WechatConfig{
			AppID:  settings[SettingKeyWechatAppID],
			MchID:  settings[SettingKeyWechatMchID],
			APIKey: settings[SettingKeyWechatAPIKey],
		}
		cfg.NotifyURL = baseURL + "/api/v1/payment/notify/wechat"
		return payment.NewWechatGateway(cfg), nil

	case payment.MethodEpay:
		cfg := &payment.EpayConfig{
			APIURL: settings[SettingKeyEpayAPIURL],
			PID:    settings[SettingKeyEpayPID],
			Key:    settings[SettingKeyEpayKey],
			Type:   settings[SettingKeyEpayType],
		}
		cfg.NotifyURL = baseURL + "/api/v1/payment/notify/epay"
		cfg.ReturnURL = baseURL + "/api/v1/payment/return"
		return payment.NewEpayGateway(cfg), nil

	case payment.MethodEpayAlipay:
		cfg := &payment.EpayConfig{
			APIURL: settings[SettingKeyEpayAPIURL],
			PID:    settings[SettingKeyEpayPID],
			Key:    settings[SettingKeyEpayKey],
			Type:   "alipay",
		}
		cfg.NotifyURL = baseURL + "/api/v1/payment/notify/epay"
		cfg.ReturnURL = baseURL + "/api/v1/payment/return"
		return payment.NewEpayGateway(cfg), nil

	case payment.MethodEpayWechat:
		cfg := &payment.EpayConfig{
			APIURL: settings[SettingKeyEpayAPIURL],
			PID:    settings[SettingKeyEpayPID],
			Key:    settings[SettingKeyEpayKey],
			Type:   "wxpay",
		}
		cfg.NotifyURL = baseURL + "/api/v1/payment/notify/epay"
		cfg.ReturnURL = baseURL + "/api/v1/payment/return"
		return payment.NewEpayGateway(cfg), nil

	default:
		return nil, fmt.Errorf("unsupported payment method: %s", method)
	}
}

// PaymentStats 支付统计数据
type PaymentStats struct {
	TodayAmount     float64             `json:"today_amount"`
	TodayCount      int64               `json:"today_count"`
	YesterdayAmount float64             `json:"yesterday_amount"`
	YesterdayCount  int64               `json:"yesterday_count"`
	WeekAmount      float64             `json:"week_amount"`
	WeekCount       int64               `json:"week_count"`
	MonthAmount     float64             `json:"month_amount"`
	MonthCount      int64               `json:"month_count"`
	TotalAmount     float64             `json:"total_amount"`
	TotalCount      int64               `json:"total_count"`
	TrendPoints     []RevenueTrendPoint `json:"trend_points"`
	MethodBreakdown []MethodStats       `json:"method_breakdown"`
}

type RevenueTrendPoint struct {
	Date   string  `json:"date"`
	Amount float64 `json:"amount"`
	Count  int64   `json:"count"`
}

type MethodStats struct {
	Method string  `json:"method"`
	Amount float64 `json:"amount"`
	Count  int64   `json:"count"`
}

// GetPaymentStats 获取支付统计数据
func (s *PaymentService) GetPaymentStats(ctx context.Context, days int) (*PaymentStats, error) {
	stats := &PaymentStats{}

	// 1. 汇总查询：today/yesterday/week/month/total
	summarySQL := `
		SELECT
			COALESCE(SUM(CASE WHEN paid_at::date = CURRENT_DATE THEN amount END), 0) AS today_amount,
			COALESCE(COUNT(CASE WHEN paid_at::date = CURRENT_DATE THEN 1 END), 0) AS today_count,
			COALESCE(SUM(CASE WHEN paid_at::date = CURRENT_DATE - 1 THEN amount END), 0) AS yesterday_amount,
			COALESCE(COUNT(CASE WHEN paid_at::date = CURRENT_DATE - 1 THEN 1 END), 0) AS yesterday_count,
			COALESCE(SUM(CASE WHEN paid_at >= CURRENT_DATE - INTERVAL '7 days' THEN amount END), 0) AS week_amount,
			COALESCE(COUNT(CASE WHEN paid_at >= CURRENT_DATE - INTERVAL '7 days' THEN 1 END), 0) AS week_count,
			COALESCE(SUM(CASE WHEN paid_at >= CURRENT_DATE - INTERVAL '30 days' THEN amount END), 0) AS month_amount,
			COALESCE(COUNT(CASE WHEN paid_at >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END), 0) AS month_count,
			COALESCE(SUM(amount), 0) AS total_amount,
			COUNT(*) AS total_count
		FROM payment_orders
		WHERE status = 'paid'
	`
	err := s.db.QueryRowContext(ctx, summarySQL).Scan(
		&stats.TodayAmount, &stats.TodayCount,
		&stats.YesterdayAmount, &stats.YesterdayCount,
		&stats.WeekAmount, &stats.WeekCount,
		&stats.MonthAmount, &stats.MonthCount,
		&stats.TotalAmount, &stats.TotalCount,
	)
	if err != nil {
		return nil, fmt.Errorf("query payment summary: %w", err)
	}

	// 2. 日趋势查询
	trendSQL := `
		SELECT paid_at::date AS day, COALESCE(SUM(amount), 0), COUNT(*)
		FROM payment_orders
		WHERE status = 'paid' AND paid_at >= CURRENT_DATE - ($1 || ' days')::interval
		GROUP BY day
		ORDER BY day
	`
	rows, err := s.db.QueryContext(ctx, trendSQL, days)
	if err != nil {
		return nil, fmt.Errorf("query payment trend: %w", err)
	}
	defer rows.Close()

	trendMap := make(map[string]RevenueTrendPoint)
	for rows.Next() {
		var p RevenueTrendPoint
		var d time.Time
		if err := rows.Scan(&d, &p.Amount, &p.Count); err != nil {
			return nil, fmt.Errorf("scan trend point: %w", err)
		}
		p.Date = d.Format("2006-01-02")
		trendMap[p.Date] = p
	}

	// 填充所有日期（确保无数据的日期也显示为0）
	now := time.Now()
	for i := days - 1; i >= 0; i-- {
		d := now.AddDate(0, 0, -i).Format("2006-01-02")
		if p, ok := trendMap[d]; ok {
			stats.TrendPoints = append(stats.TrendPoints, p)
		} else {
			stats.TrendPoints = append(stats.TrendPoints, RevenueTrendPoint{Date: d, Amount: 0, Count: 0})
		}
	}

	// 3. 支付方式分布
	methodSQL := `
		SELECT payment_method, COALESCE(SUM(amount), 0), COUNT(*)
		FROM payment_orders
		WHERE status = 'paid'
		GROUP BY payment_method
		ORDER BY SUM(amount) DESC
	`
	mRows, err := s.db.QueryContext(ctx, methodSQL)
	if err != nil {
		return nil, fmt.Errorf("query method breakdown: %w", err)
	}
	defer mRows.Close()

	for mRows.Next() {
		var m MethodStats
		if err := mRows.Scan(&m.Method, &m.Amount, &m.Count); err != nil {
			return nil, fmt.Errorf("scan method stats: %w", err)
		}
		stats.MethodBreakdown = append(stats.MethodBreakdown, m)
	}

	return stats, nil
}

func generateOrderNo() string {
	now := time.Now()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("PAY%s%s", now.Format("20060102150405"), hex.EncodeToString(b))
}
