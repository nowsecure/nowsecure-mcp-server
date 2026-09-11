package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nsmcp/internal/nsclient"
)

// addFindingsTool retains the normal typed input and output schemas, but owns
// output serialization: go-sdk v1.6.1's typed-output validator decodes through
// float64, rounding large numeric evidence in both MCP output channels.
func addFindingsTool(s *srv, server *mcp.Server, tool *mcp.Tool, h mcp.ToolHandlerFor[getFindingsInput, *nsclient.AssessmentFindings]) {
	schema, err := jsonschema.For[nsclient.AssessmentFindings](nil)
	if err != nil {
		panic(fmt.Errorf("findings output schema: %w", err))
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
	if err != nil {
		panic(fmt.Errorf("findings output schema: %w", err))
	}
	tool.OutputSchema = schema
	typed := logCalls(s.logger, tool.Name, denilOutput(h))
	mcp.AddTool(server, tool, func(ctx context.Context, req *mcp.CallToolRequest, in getFindingsInput) (*mcp.CallToolResult, any, error) {
		result, out, err := typed(ctx, req, in)
		if err != nil {
			return result, nil, err
		}
		if out == nil {
			out = &nsclient.AssessmentFindings{}
			denilSlices(out)
		}
		encoded, err := json.Marshal(out)
		if err != nil {
			return nil, nil, fmt.Errorf("marshaling findings output: %w", err)
		}
		// Preserve the SDK's full schema validation on a disposable copy.
		// jsonschema-go v0.4.3 does not support json.Number for type checks;
		// never re-encode this float64-decoded copy into the actual response.
		var value map[string]any
		if err := json.Unmarshal(encoded, &value); err != nil {
			return nil, nil, fmt.Errorf("decoding findings output for validation: %w", err)
		}
		if err := resolved.Validate(value); err != nil {
			return nil, nil, fmt.Errorf("validating findings output: %w", err)
		}
		if result == nil {
			result = &mcp.CallToolResult{}
		}
		result.StructuredContent = json.RawMessage(encoded)
		if result.Content == nil {
			result.Content = []mcp.Content{&mcp.TextContent{Text: string(encoded)}}
		}
		// A nil untyped output keeps the SDK from reserializing our already
		// validated JSON; the registered output schema remains advertised.
		return result, nil, nil
	})
}
