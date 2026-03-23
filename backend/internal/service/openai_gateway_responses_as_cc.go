package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/Wei-Shaw/sub2api/internal/util/responseheaders"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// responsesNotSupportedCache caches account IDs whose upstream does not support
// the /v1/responses endpoint. This avoids sending a doomed request on every call.
var responsesNotSupportedCache sync.Map // map[int64]time.Time

// markResponsesNotSupported flags an account as not supporting /v1/responses.
func markResponsesNotSupported(accountID int64) {
	responsesNotSupportedCache.Store(accountID, time.Now())
}

// isResponsesNotSupported returns true if the account has been flagged.
// Entries expire after 10 minutes to allow re-probing.
func isResponsesNotSupported(accountID int64) bool {
	v, ok := responsesNotSupportedCache.Load(accountID)
	if !ok {
		return false
	}
	ts, ok := v.(time.Time)
	if !ok {
		return false
	}
	if time.Since(ts) > 10*time.Minute {
		responsesNotSupportedCache.Delete(accountID)
		return false
	}
	return true
}

// ForwardResponsesAsChatCompletions converts a Responses API request to Chat
// Completions format, forwards to the upstream /v1/chat/completions endpoint,
// and converts the response back to Responses format for the client.
func (s *OpenAIGatewayService) ForwardResponsesAsChatCompletions(
	ctx context.Context,
	c *gin.Context,
	account *Account,
	body []byte,
	originalModel string,
	mappedModel string,
	reqStream bool,
	startTime time.Time,
) (*OpenAIForwardResult, error) {
	logger.L().Info("openai responses→cc: converting request",
		zap.Int64("account_id", account.ID),
		zap.String("model", originalModel),
		zap.Bool("stream", reqStream),
	)

	// 1. Parse Responses request
	var responsesReq apicompat.ResponsesRequest
	if err := json.Unmarshal(body, &responsesReq); err != nil {
		return nil, fmt.Errorf("parse responses request: %w", err)
	}

	// 2. Convert to Chat Completions request
	chatReq, err := apicompat.ResponsesRequestToChatCompletions(&responsesReq)
	if err != nil {
		return nil, fmt.Errorf("convert responses to chat completions: %w", err)
	}

	// Apply mapped model
	chatReq.Model = mappedModel
	chatReq.Stream = reqStream

	// 3. Marshal CC request body
	ccBody, err := json.Marshal(chatReq)
	if err != nil {
		return nil, fmt.Errorf("marshal chat completions request: %w", err)
	}

	// 4. Get access token
	token, _, err := s.GetAccessToken(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("get access token: %w", err)
	}

	// 5. Build upstream URL using /v1/chat/completions
	targetURL := buildChatCompletionsURL(account.GetOpenAIBaseURL())
	validatedURL, err := s.validateUpstreamBaseURL(targetURL)
	if err != nil {
		return nil, fmt.Errorf("validate upstream URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", validatedURL, bytes.NewReader(ccBody))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if reqStream {
		req.Header.Set("Accept", "text/event-stream")
	}

	// Whitelist passthrough headers
	for key, values := range c.Request.Header {
		lowerKey := strings.ToLower(key)
		if openaiAllowedHeaders[lowerKey] {
			for _, v := range values {
				req.Header.Add(key, v)
			}
		}
	}

	// Apply custom User-Agent if configured
	if customUA := account.GetOpenAIUserAgent(); customUA != "" {
		req.Header.Set("User-Agent", customUA)
	}

	// 6. Send request
	proxyURL := ""
	if account.ProxyID != nil && account.Proxy != nil {
		proxyURL = account.Proxy.URL()
	}

	upstreamStart := time.Now()
	resp, err := s.httpUpstream.Do(req, proxyURL, account.ID, account.Concurrency)
	SetOpsLatencyMs(c, OpsUpstreamLatencyMsKey, time.Since(upstreamStart).Milliseconds())
	if err != nil {
		safeErr := sanitizeUpstreamErrorMessage(err.Error())
		setOpsUpstreamError(c, 0, safeErr, "")
		appendOpsUpstreamError(c, OpsUpstreamErrorEvent{
			Platform:           account.Platform,
			AccountID:          account.ID,
			AccountName:        account.Name,
			UpstreamStatusCode: 0,
			Kind:               "request_error",
			Message:            safeErr,
		})
		c.JSON(http.StatusBadGateway, gin.H{
			"error": gin.H{
				"type":    "upstream_error",
				"message": "Upstream request failed",
				"param":   nil,
				"code":    "upstream_error",
			},
		})
		return nil, fmt.Errorf("upstream request failed (cc path): %s", safeErr)
	}
	defer func() { _ = resp.Body.Close() }()

	// 7. Handle error response
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(respBody))

		upstreamMsg := strings.TrimSpace(extractUpstreamErrorMessage(respBody))
		upstreamMsg = sanitizeUpstreamErrorMessage(upstreamMsg)

		if s.shouldFailoverOpenAIUpstreamResponse(resp.StatusCode, upstreamMsg, respBody) {
			appendOpsUpstreamError(c, OpsUpstreamErrorEvent{
				Platform:           account.Platform,
				AccountID:          account.ID,
				AccountName:        account.Name,
				UpstreamStatusCode: resp.StatusCode,
				UpstreamRequestID:  resp.Header.Get("x-request-id"),
				Kind:               "failover",
				Message:            upstreamMsg,
			})
			if s.rateLimitService != nil {
				s.rateLimitService.HandleUpstreamError(ctx, account, resp.StatusCode, resp.Header, respBody)
			}
			return nil, &UpstreamFailoverError{
				StatusCode:   resp.StatusCode,
				ResponseBody: respBody,
			}
		}

		// Write error in Responses format
		errorMsg := upstreamMsg
		if errorMsg == "" {
			errorMsg = fmt.Sprintf("Upstream error: %d", resp.StatusCode)
		}
		c.JSON(resp.StatusCode, gin.H{
			"error": gin.H{
				"type":    "upstream_error",
				"message": errorMsg,
				"code":    "upstream_error",
			},
		})
		return nil, fmt.Errorf("upstream error (cc path): %d %s", resp.StatusCode, upstreamMsg)
	}

	// 8. Handle normal response — convert CC response to Responses format
	if reqStream {
		return s.handleResponsesAsCCStreaming(resp, c, originalModel, mappedModel, startTime)
	}
	return s.handleResponsesAsCCBuffered(resp, c, originalModel, mappedModel, startTime)
}

// handleResponsesAsCCBuffered reads a non-streaming CC response, converts it
// to Responses format, and writes it to the client.
func (s *OpenAIGatewayService) handleResponsesAsCCBuffered(
	resp *http.Response,
	c *gin.Context,
	originalModel string,
	mappedModel string,
	startTime time.Time,
) (*OpenAIForwardResult, error) {
	requestID := resp.Header.Get("x-request-id")

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("read upstream response: %w", err)
	}

	var chatResp apicompat.ChatCompletionsResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("parse chat completions response: %w", err)
	}

	responsesResp := apicompat.ChatCompletionsToResponsesResponse(&chatResp, originalModel)

	if s.responseHeaderFilter != nil {
		responseheaders.WriteFilteredHeaders(c.Writer.Header(), resp.Header, s.responseHeaderFilter)
	}
	c.JSON(http.StatusOK, responsesResp)

	var usage OpenAIUsage
	if chatResp.Usage != nil {
		usage = OpenAIUsage{
			InputTokens:  chatResp.Usage.PromptTokens,
			OutputTokens: chatResp.Usage.CompletionTokens,
		}
		if chatResp.Usage.PromptTokensDetails != nil {
			usage.CacheReadInputTokens = chatResp.Usage.PromptTokensDetails.CachedTokens
			usage.CacheCreationInputTokens = chatResp.Usage.PromptTokensDetails.CacheCreationInputTokens
		}
	}

	return &OpenAIForwardResult{
		RequestID:    requestID,
		Usage:        usage,
		Model:        originalModel,
		BillingModel: mappedModel,
		Stream:       false,
		Duration:     time.Since(startTime),
	}, nil
}

// handleResponsesAsCCStreaming reads CC streaming chunks from upstream,
// converts them to Responses SSE events, and writes them to the client.
func (s *OpenAIGatewayService) handleResponsesAsCCStreaming(
	resp *http.Response,
	c *gin.Context,
	originalModel string,
	mappedModel string,
	startTime time.Time,
) (*OpenAIForwardResult, error) {
	requestID := resp.Header.Get("x-request-id")

	if s.responseHeaderFilter != nil {
		responseheaders.WriteFilteredHeaders(c.Writer.Header(), resp.Header, s.responseHeaderFilter)
	}

	// Set SSE response headers
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)

	state := apicompat.NewChatToResponsesStreamState(originalModel)
	var usage OpenAIUsage
	var firstTokenMs *int

	scanner := bufio.NewScanner(resp.Body)
	maxLineSize := defaultMaxLineSize
	if s.cfg != nil && s.cfg.Gateway.MaxLineSize > 0 {
		maxLineSize = s.cfg.Gateway.MaxLineSize
	}
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	var lastFinishReason string

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[6:]
		if data == "[DONE]" {
			break
		}

		if firstTokenMs == nil {
			ms := int(time.Since(startTime).Milliseconds())
			firstTokenMs = &ms
		}

		var chunk apicompat.ChatCompletionsChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			logger.L().Warn("openai responses→cc stream: parse chunk failed",
				zap.Error(err),
				zap.String("request_id", requestID),
			)
			continue
		}

		// Extract finish_reason for finalization
		for _, choice := range chunk.Choices {
			if choice.FinishReason != nil && *choice.FinishReason != "" {
				lastFinishReason = *choice.FinishReason
			}
		}

		// Extract usage
		if chunk.Usage != nil {
			usage = OpenAIUsage{
				InputTokens:  chunk.Usage.PromptTokens,
				OutputTokens: chunk.Usage.CompletionTokens,
			}
			if chunk.Usage.PromptTokensDetails != nil {
				usage.CacheReadInputTokens = chunk.Usage.PromptTokensDetails.CachedTokens
				usage.CacheCreationInputTokens = chunk.Usage.PromptTokensDetails.CacheCreationInputTokens
			}
		}

		// Convert to Responses events and write
		events := apicompat.ChatChunkToResponsesEvents(&chunk, state)
		for _, evt := range events {
			sse, err := apicompat.ResponsesEventToSSE(evt)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprint(c.Writer, sse); err != nil {
				logger.L().Info("openai responses→cc stream: client disconnected",
					zap.String("request_id", requestID),
				)
				return &OpenAIForwardResult{
					RequestID:    requestID,
					Usage:        usage,
					Model:        originalModel,
					BillingModel: mappedModel,
					Stream:       true,
					Duration:     time.Since(startTime),
					FirstTokenMs: firstTokenMs,
				}, nil
			}
		}
		if len(events) > 0 {
			c.Writer.Flush()
		}
	}

	if err := scanner.Err(); err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			logger.L().Warn("openai responses→cc stream: read error",
				zap.Error(err),
				zap.String("request_id", requestID),
			)
		}
	}

	// Update state usage from accumulated data
	if state.Usage == nil && (usage.InputTokens > 0 || usage.OutputTokens > 0) {
		state.Usage = &apicompat.ResponsesUsage{
			InputTokens:  usage.InputTokens,
			OutputTokens: usage.OutputTokens,
			TotalTokens:  usage.InputTokens + usage.OutputTokens,
		}
	}

	// Emit finalization events
	if lastFinishReason == "" {
		lastFinishReason = "stop"
	}
	finalEvents := apicompat.FinalizeChatToResponsesStream(state, lastFinishReason)
	for _, evt := range finalEvents {
		sse, err := apicompat.ResponsesEventToSSE(evt)
		if err != nil {
			continue
		}
		fmt.Fprint(c.Writer, sse) //nolint:errcheck
	}
	c.Writer.Flush()

	return &OpenAIForwardResult{
		RequestID:    requestID,
		Usage:        usage,
		Model:        originalModel,
		BillingModel: mappedModel,
		Stream:       true,
		Duration:     time.Since(startTime),
		FirstTokenMs: firstTokenMs,
	}, nil
}

// buildChatCompletionsURL constructs the /v1/chat/completions URL from a base URL.
func buildChatCompletionsURL(base string) string {
	normalized := strings.TrimRight(strings.TrimSpace(base), "/")
	if normalized == "" {
		return "https://api.openai.com/v1/chat/completions"
	}
	if strings.HasSuffix(normalized, "/chat/completions") {
		return normalized
	}
	if strings.HasSuffix(normalized, "/v1") {
		return normalized + "/chat/completions"
	}
	return normalized + "/v1/chat/completions"
}
