package rules

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// Shims stand in for the SDKs (openai-go, anthropic-sdk-go) so the fixture
// stays stdlib-only; the rules match call shapes, not imports. The MCP cases
// call the go-sdk (mcp.) and mcp-go (server.) constructors as written in real
// code — opengrep parses this file, it is never compiled.
type llmMessage struct{ Content string }
type llmChoice struct{ Message llmMessage }
type llmResponse struct{ Choices []llmChoice }
type llmBlock struct{ Text string }
type llmAnthropicMessage struct{ Content []llmBlock }

type llmCompletions struct{}

func (llmCompletions) New(context.Context, any) (*llmResponse, error) { return nil, nil }

type llmChat struct{ Completions llmCompletions }
type llmMessages struct{}

func (llmMessages) New(context.Context, any) (*llmAnthropicMessage, error) { return nil, nil }

type llmClient struct {
	Chat     llmChat
	Messages llmMessages
}

var llmShimClient llmClient

func llmRunSuggestion(ctx context.Context, question string) error {
	resp, err := llmShimClient.Chat.Completions.New(ctx, question)
	if err != nil {
		return err
	}
	command := resp.Choices[0].Message.Content
	// ruleid: traust-go-llm-application-output-to-exec-taint
	cmd := exec.Command(command)

	// ok: traust-go-llm-application-output-to-exec-taint
	uptime := exec.Command("uptime")
	_, _ = cmd, uptime
	return nil
}

func llmAskDatabase(ctx context.Context, db *sql.DB, question string) error {
	resp, err := llmShimClient.Chat.Completions.New(ctx, question)
	if err != nil {
		return err
	}
	query := strings.TrimSpace(resp.Choices[0].Message.Content)
	// ruleid: traust-go-llm-application-output-to-sql-taint
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	// ok: traust-go-llm-application-output-to-sql-taint
	_, err = db.ExecContext(ctx, "INSERT INTO audit (question) VALUES ($1)", query)
	return err
}

func llmSaveSummary(ctx context.Context, question string) error {
	msg, err := llmShimClient.Messages.New(ctx, question)
	if err != nil {
		return err
	}
	name := msg.Content[0].Text
	// ruleid: traust-go-llm-application-output-to-path-taint
	if err := os.WriteFile(name, []byte("summary"), 0o600); err != nil {
		return err
	}

	// ok: traust-go-llm-application-output-to-path-taint
	return os.WriteFile("summary.txt", []byte(name), 0o600)
}

func llmServeHTTP(s any) http.Handler {
	// ruleid: traust-go-llm-application-mcp-http-without-auth
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return nil }, nil)
}

func llmServeSSE(s any) {
	// ruleid: traust-go-llm-application-mcp-http-without-auth
	sse := server.NewSSEServer(s)
	_ = sse
}

func llmResearch(ctx context.Context, question string) (string, error) {
	// ruleid: traust-go-llm-application-unbounded-agent-loop
	for {
		resp, err := llmShimClient.Chat.Completions.New(ctx, question)
		if err != nil {
			return "", err
		}
		if text := resp.Choices[0].Message.Content; strings.HasPrefix(text, "DONE") {
			return text, nil
		}
	}
}

func llmBoundedResearch(ctx context.Context, question string, maxSteps int) (string, error) {
	steps := 0
	// ok: traust-go-llm-application-unbounded-agent-loop
	for {
		steps++
		if steps > maxSteps {
			return "", nil
		}
		resp, err := llmShimClient.Chat.Completions.New(ctx, question)
		if err != nil {
			return "", err
		}
		if text := resp.Choices[0].Message.Content; strings.HasPrefix(text, "DONE") {
			return text, nil
		}
	}
}

func llmDrain(ch chan string) {
	// ok: traust-go-llm-application-unbounded-agent-loop
	for {
		item, ok := <-ch
		if !ok {
			return
		}
		_ = item
	}
}
