package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nsmcp/internal/urlparse"
)

type decodeURLInput struct {
	URL string `json:"url" jsonschema:"a NowSecure console URL or deep link to parse"`
}

func (s *srv) decodeURL(_ context.Context, _ *mcp.CallToolRequest, in decodeURLInput) (*mcp.CallToolResult, *urlparse.Parsed, error) {
	out, err := urlparse.Parse(in.URL)
	if err != nil {
		return nil, nil, err
	}
	return nil, out, nil
}
