package apicompat

import (
	"encoding/json"
	"fmt"
)

// ResponsesRequestToChatCompletions converts a Responses API request into a
// Chat Completions API request. This enables forwarding Responses-format
// requests to upstreams that only support the Chat Completions endpoint.
func ResponsesRequestToChatCompletions(req *ResponsesRequest) (*ChatCompletionsRequest, error) {
	messages, err := convertResponsesInputToMessages(req.Input)
	if err != nil {
		return nil, fmt.Errorf("convert input to messages: %w", err)
	}

	out := &ChatCompletionsRequest{
		Model:       req.Model,
		Messages:    messages,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stream:      req.Stream,
		ServiceTier: req.ServiceTier,
	}

	// max_output_tokens → max_completion_tokens
	if req.MaxOutputTokens != nil {
		out.MaxCompletionTokens = req.MaxOutputTokens
	}

	// reasoning.effort → reasoning_effort
	if req.Reasoning != nil && req.Reasoning.Effort != "" {
		out.ReasoningEffort = req.Reasoning.Effort
	}

	// stream_options: include_usage when streaming
	if req.Stream {
		out.StreamOptions = &ChatStreamOptions{IncludeUsage: true}
	}

	// Convert tools
	if len(req.Tools) > 0 {
		out.Tools = convertResponsesToolsToChat(req.Tools)
	}

	// tool_choice: pass through (compatible format)
	if len(req.ToolChoice) > 0 {
		out.ToolChoice = req.ToolChoice
	}

	return out, nil
}

// convertResponsesInputToMessages converts the Responses API input (which can
// be a string or an array of input items) into Chat Completions messages.
func convertResponsesInputToMessages(raw json.RawMessage) ([]ChatMessage, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("input is empty")
	}

	// Try as plain string first
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		content, _ := json.Marshal(s)
		return []ChatMessage{{Role: "user", Content: content}}, nil
	}

	// Parse as array of input items
	var items []ResponsesInputItem
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("parse input items: %w", err)
	}

	return responsesItemsToMessages(items)
}

// responsesItemsToMessages converts a slice of ResponsesInputItem into Chat
// Completions messages. function_call items are grouped as tool_calls on the
// preceding assistant message.
func responsesItemsToMessages(items []ResponsesInputItem) ([]ChatMessage, error) {
	var messages []ChatMessage

	for i := 0; i < len(items); i++ {
		item := items[i]

		switch {
		case item.Type == "function_call":
			// function_call items become tool_calls on an assistant message.
			// Collect consecutive function_call items.
			var toolCalls []ChatToolCall
			for i < len(items) && items[i].Type == "function_call" {
				fc := items[i]
				toolCalls = append(toolCalls, ChatToolCall{
					ID:   fc.CallID,
					Type: "function",
					Function: ChatFunctionCall{
						Name:      fc.Name,
						Arguments: fc.Arguments,
					},
				})
				i++
			}
			i-- // back up one since the outer loop will increment

			// Check if previous message is already an assistant message we can
			// attach tool_calls to.
			if len(messages) > 0 && messages[len(messages)-1].Role == "assistant" && len(messages[len(messages)-1].ToolCalls) == 0 {
				messages[len(messages)-1].ToolCalls = toolCalls
			} else {
				messages = append(messages, ChatMessage{
					Role:      "assistant",
					ToolCalls: toolCalls,
				})
			}

		case item.Type == "function_call_output":
			messages = append(messages, ChatMessage{
				Role:       "tool",
				Content:    mustMarshalJSON(item.Output),
				ToolCallID: item.CallID,
			})

		case item.Role == "system":
			text, err := parseResponsesInputContent(item.Content)
			if err != nil {
				return nil, fmt.Errorf("parse system content: %w", err)
			}
			messages = append(messages, ChatMessage{
				Role:    "system",
				Content: mustMarshalJSON(text),
			})

		case item.Role == "user":
			content, err := convertResponsesUserContent(item.Content)
			if err != nil {
				return nil, fmt.Errorf("parse user content: %w", err)
			}
			messages = append(messages, ChatMessage{
				Role:    "user",
				Content: content,
			})

		case item.Role == "assistant":
			text, err := parseResponsesAssistantContent(item.Content)
			if err != nil {
				return nil, fmt.Errorf("parse assistant content: %w", err)
			}
			msg := ChatMessage{Role: "assistant"}
			if text != "" {
				msg.Content = mustMarshalJSON(text)
			}
			messages = append(messages, msg)

		default:
			// Unknown item type with a role — treat as user message
			if item.Role != "" {
				text, _ := parseResponsesInputContent(item.Content)
				if text != "" {
					messages = append(messages, ChatMessage{
						Role:    item.Role,
						Content: mustMarshalJSON(text),
					})
				}
			}
		}
	}

	return messages, nil
}

// parseResponsesInputContent extracts text from a Responses content field.
// Content can be a plain string or an array of content parts.
func parseResponsesInputContent(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}

	// Try string first
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}

	// Try array of content parts
	var parts []ResponsesContentPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return "", fmt.Errorf("parse content parts: %w", err)
	}

	var text string
	for _, p := range parts {
		if (p.Type == "input_text" || p.Type == "output_text" || p.Type == "text") && p.Text != "" {
			text += p.Text
		}
	}
	return text, nil
}

// parseResponsesAssistantContent extracts text from assistant content parts.
func parseResponsesAssistantContent(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}

	// Try string first
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}

	// Try array of content parts
	var parts []ResponsesContentPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return "", fmt.Errorf("parse assistant content parts: %w", err)
	}

	var text string
	for _, p := range parts {
		if (p.Type == "output_text" || p.Type == "text") && p.Text != "" {
			text += p.Text
		}
	}
	return text, nil
}

// convertResponsesUserContent converts user content to Chat Completions format.
// Handles both plain string and multi-modal content (text + images).
func convertResponsesUserContent(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return mustMarshalJSON(""), nil
	}

	// Try plain string
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return mustMarshalJSON(s), nil
	}

	// Multi-modal: array of content parts
	var parts []ResponsesContentPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil, fmt.Errorf("parse user content parts: %w", err)
	}

	// Check if there are any images — if not, just concatenate text
	hasImage := false
	for _, p := range parts {
		if p.Type == "input_image" {
			hasImage = true
			break
		}
	}

	if !hasImage {
		var text string
		for _, p := range parts {
			if (p.Type == "input_text" || p.Type == "text") && p.Text != "" {
				text += p.Text
			}
		}
		return mustMarshalJSON(text), nil
	}

	// Multi-modal content
	var chatParts []ChatContentPart
	for _, p := range parts {
		switch p.Type {
		case "input_text", "text":
			if p.Text != "" {
				chatParts = append(chatParts, ChatContentPart{
					Type: "text",
					Text: p.Text,
				})
			}
		case "input_image":
			if p.ImageURL != "" {
				chatParts = append(chatParts, ChatContentPart{
					Type:     "image_url",
					ImageURL: &ChatImageURL{URL: p.ImageURL},
				})
			}
		}
	}

	data, err := json.Marshal(chatParts)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// convertResponsesToolsToChat converts Responses API tools to Chat Completions tools.
func convertResponsesToolsToChat(tools []ResponsesTool) []ChatTool {
	var out []ChatTool
	for _, t := range tools {
		if t.Type != "function" {
			continue
		}
		out = append(out, ChatTool{
			Type: "function",
			Function: &ChatFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
				Strict:      t.Strict,
			},
		})
	}
	return out
}

// mustMarshalJSON marshals v to JSON, panicking on error (should never fail
// for simple types like strings).
func mustMarshalJSON(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("apicompat: marshal failed: %v", err))
	}
	return data
}
