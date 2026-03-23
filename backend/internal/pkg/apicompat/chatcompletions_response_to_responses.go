package apicompat

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Non-streaming: ChatCompletionsResponse → ResponsesResponse
// ---------------------------------------------------------------------------

// ChatCompletionsToResponsesResponse converts a Chat Completions response into
// an OpenAI Responses API response.
func ChatCompletionsToResponsesResponse(resp *ChatCompletionsResponse, model string) *ResponsesResponse {
	id := resp.ID
	if id == "" {
		id = generateResponseID()
	}

	out := &ResponsesResponse{
		ID:     id,
		Object: "response",
		Model:  model,
	}

	var output []ResponsesOutput

	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		msg := choice.Message

		// Text content → message output item
		contentText := extractChatMessageText(msg)
		if contentText != "" {
			output = append(output, ResponsesOutput{
				Type: "message",
				ID:   generateItemID(),
				Role: "assistant",
				Content: []ResponsesContentPart{{
					Type:        "output_text",
					Text:        contentText,
					Annotations: json.RawMessage("[]"),
				}},
				Status: "completed",
			})
		}

		// Tool calls → function_call output items
		for _, tc := range msg.ToolCalls {
			output = append(output, ResponsesOutput{
				Type:      "function_call",
				ID:        tc.ID,
				CallID:    tc.ID,
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			})
		}

		// Map finish_reason to status
		out.Status = chatFinishReasonToResponsesStatus(choice.FinishReason)
		if choice.FinishReason == "length" {
			out.IncompleteDetails = &ResponsesIncompleteDetails{
				Reason: "max_output_tokens",
			}
		}
	} else {
		out.Status = "completed"
	}

	out.Output = output

	// Convert usage
	if resp.Usage != nil {
		out.Usage = &ResponsesUsage{
			InputTokens:  resp.Usage.PromptTokens,
			OutputTokens: resp.Usage.CompletionTokens,
			TotalTokens:  resp.Usage.TotalTokens,
		}
		if resp.Usage.PromptTokensDetails != nil && resp.Usage.PromptTokensDetails.CachedTokens > 0 {
			out.Usage.InputTokensDetails = &ResponsesInputTokensDetails{
				CachedTokens: resp.Usage.PromptTokensDetails.CachedTokens,
			}
		}
	}

	return out
}

func chatFinishReasonToResponsesStatus(finishReason string) string {
	switch finishReason {
	case "length":
		return "incomplete"
	case "content_filter":
		return "incomplete"
	default:
		return "completed"
	}
}

// extractChatMessageText extracts text content from a ChatMessage.
func extractChatMessageText(msg ChatMessage) string {
	if len(msg.Content) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(msg.Content, &s); err == nil {
		return s
	}
	return ""
}

// ---------------------------------------------------------------------------
// Streaming: ChatCompletionsChunk → []ResponsesStreamEvent (stateful converter)
// ---------------------------------------------------------------------------

// ChatToResponsesStreamState tracks state for converting a sequence of Chat
// Completions SSE chunks into Responses SSE events.
type ChatToResponsesStreamState struct {
	ResponseID  string
	Model       string
	Created     int64
	SentCreated bool
	SentMsgItem bool

	// Track ongoing text content
	ContentIndex    int
	AccumulatedText string // full text accumulated from deltas
	MsgItemID       string // ID of the message output item

	// Track tool calls
	ToolCalls     map[int]*streamingToolCall // index → tool call state
	NextSeqNumber int

	// Usage from final chunk
	Usage *ResponsesUsage
}

type streamingToolCall struct {
	ID        string
	Name      string
	Arguments string
	ItemAdded bool
}

// NewChatToResponsesStreamState returns an initialised stream state.
func NewChatToResponsesStreamState(model string) *ChatToResponsesStreamState {
	return &ChatToResponsesStreamState{
		ResponseID: generateResponseID(),
		Model:      model,
		Created:    time.Now().Unix(),
		ToolCalls:  make(map[int]*streamingToolCall),
	}
}

// ChatChunkToResponsesEvents converts a single Chat Completions streaming
// chunk into zero or more Responses SSE events.
func ChatChunkToResponsesEvents(chunk *ChatCompletionsChunk, state *ChatToResponsesStreamState) []ResponsesStreamEvent {
	var events []ResponsesStreamEvent

	if chunk.Model != "" && state.Model == "" {
		state.Model = chunk.Model
	}

	// Emit response.created on first chunk
	if !state.SentCreated {
		state.SentCreated = true
		events = append(events, ResponsesStreamEvent{
			Type: "response.created",
			Response: &ResponsesResponse{
				ID:     state.ResponseID,
				Object: "response",
				Model:  state.Model,
				Status: "in_progress",
				Output: []ResponsesOutput{},
			},
			SequenceNumber: state.nextSeq(),
		})
		events = append(events, ResponsesStreamEvent{
			Type:           "response.in_progress",
			SequenceNumber: state.nextSeq(),
			Response: &ResponsesResponse{
				ID:     state.ResponseID,
				Object: "response",
				Model:  state.Model,
				Status: "in_progress",
				Output: []ResponsesOutput{},
			},
		})
	}

	for _, choice := range chunk.Choices {
		delta := choice.Delta

		// Handle text content
		if delta.Content != nil && *delta.Content != "" {
			// Emit output_item.added for the message item on first text
			if !state.SentMsgItem {
				state.SentMsgItem = true
				state.MsgItemID = generateItemID()
				events = append(events, ResponsesStreamEvent{
					Type:        "response.output_item.added",
					OutputIndex: intPtr(0),
					Item: &ResponsesOutput{
						Type:    "message",
						ID:      state.MsgItemID,
						Role:    "assistant",
						Content: []ResponsesContentPart{},
						Status:  "in_progress",
					},
					SequenceNumber: state.nextSeq(),
				})
				events = append(events, ResponsesStreamEvent{
					Type:         "response.content_part.added",
					OutputIndex:  intPtr(0),
					ContentIndex: intPtr(0),
					ItemID:       state.MsgItemID,
					Part: &ResponsesContentPart{
						Type:        "output_text",
						Text:        "",
						Annotations: json.RawMessage("[]"),
					},
					SequenceNumber: state.nextSeq(),
				})
			}
			state.AccumulatedText += *delta.Content
			events = append(events, ResponsesStreamEvent{
				Type:           "response.output_text.delta",
				OutputIndex:    intPtr(0),
				ContentIndex:   intPtr(0),
				ItemID:         state.MsgItemID,
				Delta:          *delta.Content,
				SequenceNumber: state.nextSeq(),
			})
		}

		// Handle tool calls
		for _, tc := range delta.ToolCalls {
			idx := 0
			if tc.Index != nil {
				idx = *tc.Index
			}

			existing, ok := state.ToolCalls[idx]
			if !ok {
				existing = &streamingToolCall{}
				state.ToolCalls[idx] = existing
			}

			if tc.ID != "" {
				existing.ID = tc.ID
			}
			if tc.Function.Name != "" {
				existing.Name = tc.Function.Name
			}

			// Emit output_item.added for function_call
			if !existing.ItemAdded && existing.ID != "" {
				existing.ItemAdded = true
				// Calculate the output index: message item (if any) is 0, tool calls start after
				outputIdx := len(state.ToolCalls)
				if state.SentMsgItem {
					outputIdx++
				}
				events = append(events, ResponsesStreamEvent{
					Type:        "response.output_item.added",
					OutputIndex: intPtr(outputIdx - 1),
					Item: &ResponsesOutput{
						Type:   "function_call",
						ID:     existing.ID,
						CallID: existing.ID,
						Name:   existing.Name,
					},
					SequenceNumber: state.nextSeq(),
				})
			}

			// Emit function_call_arguments.delta
			if tc.Function.Arguments != "" {
				existing.Arguments += tc.Function.Arguments
				outputIdx := idx
				if state.SentMsgItem {
					outputIdx++
				}
				events = append(events, ResponsesStreamEvent{
					Type:           "response.function_call_arguments.delta",
					OutputIndex:    intPtr(outputIdx),
					Delta:          tc.Function.Arguments,
					CallID:         existing.ID,
					SequenceNumber: state.nextSeq(),
				})
			}
		}

		// Handle finish_reason
		if choice.FinishReason != nil && *choice.FinishReason != "" {
			// Will be handled in FinalizeChatToResponsesStream
		}
	}

	// Extract usage from chunk (some providers send it in the final chunk)
	if chunk.Usage != nil {
		state.Usage = &ResponsesUsage{
			InputTokens:  chunk.Usage.PromptTokens,
			OutputTokens: chunk.Usage.CompletionTokens,
			TotalTokens:  chunk.Usage.TotalTokens,
		}
		if chunk.Usage.PromptTokensDetails != nil && chunk.Usage.PromptTokensDetails.CachedTokens > 0 {
			state.Usage.InputTokensDetails = &ResponsesInputTokensDetails{
				CachedTokens: chunk.Usage.PromptTokensDetails.CachedTokens,
			}
		}
	}

	return events
}

// FinalizeChatToResponsesStream emits the terminal response.completed event.
func FinalizeChatToResponsesStream(state *ChatToResponsesStreamState, finishReason string) []ResponsesStreamEvent {
	var events []ResponsesStreamEvent

	status := chatFinishReasonToResponsesStatus(finishReason)

	// Build final output
	var output []ResponsesOutput
	if state.SentMsgItem {
		output = append(output, ResponsesOutput{
			Type:   "message",
			ID:     state.MsgItemID,
			Role:   "assistant",
			Status: "completed",
			Content: []ResponsesContentPart{{
				Type:        "output_text",
				Text:        state.AccumulatedText,
				Annotations: json.RawMessage("[]"),
			}},
		})
	}
	for _, tc := range state.ToolCalls {
		output = append(output, ResponsesOutput{
			Type:      "function_call",
			ID:        tc.ID,
			CallID:    tc.ID,
			Name:      tc.Name,
			Arguments: tc.Arguments,
		})
	}

	// Close content part and message item if we had text
	if state.SentMsgItem {
		// Emit output_text.done with full accumulated text
		events = append(events, ResponsesStreamEvent{
			Type:         "response.output_text.done",
			OutputIndex:  intPtr(0),
			ContentIndex: intPtr(0),
			ItemID:       state.MsgItemID,
			Text:         state.AccumulatedText,
			SequenceNumber: state.nextSeq(),
		})
		// Emit content_part.done with part containing full text
		events = append(events, ResponsesStreamEvent{
			Type:         "response.content_part.done",
			OutputIndex:  intPtr(0),
			ContentIndex: intPtr(0),
			ItemID:       state.MsgItemID,
			Part: &ResponsesContentPart{
				Type:        "output_text",
				Text:        state.AccumulatedText,
				Annotations: json.RawMessage("[]"),
			},
			SequenceNumber: state.nextSeq(),
		})
		// Emit output_item.done with full message item including content
		events = append(events, ResponsesStreamEvent{
			Type:        "response.output_item.done",
			OutputIndex: intPtr(0),
			SequenceNumber: state.nextSeq(),
			Item: &ResponsesOutput{
				Type:   "message",
				ID:     state.MsgItemID,
				Role:   "assistant",
				Status: "completed",
				Content: []ResponsesContentPart{{
					Type:        "output_text",
					Text:        state.AccumulatedText,
					Annotations: json.RawMessage("[]"),
				}},
			},
		})
	}

	// Close function_call items
	for _, tc := range state.ToolCalls {
		events = append(events, ResponsesStreamEvent{
			Type:           "response.function_call_arguments.done",
			SequenceNumber: state.nextSeq(),
			CallID:         tc.ID,
			Arguments:      tc.Arguments,
		})
		events = append(events, ResponsesStreamEvent{
			Type:           "response.output_item.done",
			SequenceNumber: state.nextSeq(),
			Item: &ResponsesOutput{
				Type:      "function_call",
				ID:        tc.ID,
				CallID:    tc.ID,
				Name:      tc.Name,
				Arguments: tc.Arguments,
			},
		})
	}

	// Emit response.completed
	finalResp := &ResponsesResponse{
		ID:     state.ResponseID,
		Object: "response",
		Model:  state.Model,
		Status: status,
		Output: output,
		Usage:  state.Usage,
	}
	if status == "incomplete" {
		finalResp.IncompleteDetails = &ResponsesIncompleteDetails{
			Reason: "max_output_tokens",
		}
	}

	events = append(events, ResponsesStreamEvent{
		Type:           "response.completed",
		Response:       finalResp,
		SequenceNumber: state.nextSeq(),
	})

	return events
}

// ResponsesEventToSSE formats a ResponsesStreamEvent as an SSE data line.
func ResponsesEventToSSE(event ResponsesStreamEvent) (string, error) {
	data, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("data: %s\n\n", data), nil
}

func (s *ChatToResponsesStreamState) nextSeq() int {
	s.NextSeqNumber++
	return s.NextSeqNumber
}

// generateResponseID returns a "resp_" prefixed random hex ID.
func generateResponseID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "resp_" + hex.EncodeToString(b)
}

// generateItemID returns a "item_" prefixed random hex ID.
func generateItemID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "item_" + hex.EncodeToString(b)
}
