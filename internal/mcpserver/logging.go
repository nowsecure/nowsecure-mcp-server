package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nsmcp/internal/config"
)

// logFileEnv is the opt-in switch for tool-call logging. Unset (the default),
// logging is a no-op: nsmcp never writes log bytes to stderr (the serve
// banner's channel) or stdout (the MCP protocol channel) on its own.
const logFileEnv = "NSMCP_LOG_FILE"

// newToolLogger returns the tool-call logger for NSMCP_LOG_FILE: a JSON slog
// logger appending to that file (opened 0600), or a no-op logger when the env
// var is unset.
func newToolLogger() (*slog.Logger, error) {
	path := strings.TrimSpace(os.Getenv(logFileEnv))
	if path == "" {
		return slog.New(slog.DiscardHandler), nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // NSMCP_LOG_FILE is an operator-set config path, not attacker input
	if err != nil {
		return nil, fmt.Errorf("open %s %q: %w", logFileEnv, path, err)
	}
	return slog.New(slog.NewJSONHandler(f, nil)), nil
}

// logServerStart emits the one-time server-start record: version, transport
// mode (stdio|http), and which tool groups are enabled.
func logServerStart(logger *slog.Logger, version, mode string, cfg *config.Config) {
	var groups []string
	if cfg.EnablePlatform {
		groups = append(groups, "platform")
	}
	if cfg.EnableMARI {
		groups = append(groups, "mari")
	}
	logger.Info("server_start", "version", version, "mode", mode, "tool_groups", groups)
}

// addTool registers h on server as tool, routing every call through the two
// cross-cutting mechanisms every tool goes through in one place: the
// nil-slice guard (denilSlices) and the NSMCP_LOG_FILE call logger.
func addTool[In, Out any](s *srv, server *mcp.Server, tool *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	mcp.AddTool(server, tool, logCalls(s.logger, tool.Name, denilOutput(h)))
}

// logCalls wraps a typed tool handler to emit one JSON record per call: tool
// name, duration_ms, and any error. Arguments and results are never logged —
// they can carry customer data.
func logCalls[In, Out any](logger *slog.Logger, name string, h mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		start := time.Now()
		res, out, err := h(ctx, req, in)
		attrs := []any{"tool", name, "duration_ms", time.Since(start).Milliseconds()}
		if err != nil {
			attrs = append(attrs, "error", err.Error())
		}
		logger.Info("tool_call", attrs...)
		return res, out, err
	}
}
