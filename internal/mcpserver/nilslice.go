package mcpserver

import (
	"context"
	"reflect"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// denilOutput wraps a typed tool handler so its structured output passes
// through denilSlices before the SDK marshals it. Every tool registration
// uses this wrapper — see denilSlices for why.
func denilOutput[In, Out any](h mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		res, out, err := h(ctx, req, in)
		// &out, not out: a value-typed Out is unaddressable and reflection
		// couldn't set its fields — the guard would silently no-op.
		denilSlices(&out)
		return res, out, err
	}
}

// denilSlices walks v (normally a pointer to a tool's output struct) and
// replaces every nil slice reachable through pointers, structs, and slices of
// structs with a non-nil, empty one: a bare nil Go slice marshals to JSON
// null, and an MCP client validating structuredContent against an
// array-typed output schema rejects that null (this took down the Gemini CLI
// against a sibling MCP server).
func denilSlices(v any) {
	denilValue(reflect.ValueOf(v))
}

func denilValue(rv reflect.Value) {
	switch rv.Kind() {
	case reflect.Pointer:
		if rv.IsNil() {
			return
		}
		denilValue(rv.Elem())
	case reflect.Struct:
		for i := range rv.NumField() {
			f := rv.Field(i)
			if !f.CanSet() {
				continue
			}
			if f.Kind() == reflect.Slice && f.IsNil() {
				f.Set(reflect.MakeSlice(f.Type(), 0, 0))
				continue
			}
			denilValue(f)
		}
	case reflect.Slice:
		for i := range rv.Len() {
			denilValue(rv.Index(i))
		}
	}
}
