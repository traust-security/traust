package rules

import (
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func llmServeAuthenticated(verify auth.TokenVerifier) http.Handler {
	// ok: traust-go-llm-application-mcp-http-without-auth
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return nil }, nil)
	return auth.RequireBearerToken(verify, nil)(h)
}
