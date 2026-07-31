// Package mcpserver wires the NowSecure REST client to MCP tools and serves
// them over stdio using the official modelcontextprotocol/go-sdk.
package mcpserver

import (
	"context"
	"log/slog"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nsmcp/internal/config"
	"nsmcp/internal/nsclient"
)

// srv holds shared dependencies for tool handlers.
//
// base is the upstream client. In stdio mode it is used directly; in HTTP
// resource-server mode it supplies the shared transport/base URL and each
// request derives a per-caller client from it (see http.go). resolve returns
// the client to use for the request carried by ctx. logger is the
// NSMCP_LOG_FILE tool-call logger (a no-op when that env var is unset).
type srv struct {
	base    *nsclient.Client
	resolve func(context.Context) (*nsclient.Client, error)
	logger  *slog.Logger
}

// api returns the upstream client for the current request. Tool handlers call
// this instead of touching a fixed client, so the HTTP path can swap in a
// per-caller bearer while stdio keeps its single static client.
func (s *srv) api(ctx context.Context) (*nsclient.Client, error) {
	return s.resolve(ctx)
}

// New builds an MCP server for the single product selected in cfg, served over a
// single static bearer token (the stdio path). Behavior is unchanged from a
// plain one-client server: resolve always returns that static client.
func New(cfg *config.Config, version string) (*mcp.Server, error) {
	if err := config.ValidateProductSelection(cfg.EnablePlatform, cfg.EnableMARI); err != nil {
		return nil, err
	}
	logger, err := newToolLogger()
	if err != nil {
		return nil, err
	}
	s := &srv{
		base:   nsclient.New(cfg.BaseURL, cfg.Token, nsclient.WithUserAgent("nsmcp/"+version)),
		logger: logger,
	}
	s.resolve = func(context.Context) (*nsclient.Client, error) { return s.base, nil }
	logServerStart(logger, version, "stdio", cfg)
	return s.newServer(cfg, version), nil
}

// newServer wires the tools onto a fresh mcp.Server. Shared by the stdio (New)
// and HTTP (ServeHTTP) entry points; the two differ only in how s.resolve maps
// a request to an upstream client.
func (s *srv) newServer(cfg *config.Config, version string) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "nsmcp",
		Version: version,
		Title:   productTitle(cfg),
	}, &mcp.ServerOptions{
		Instructions: instructions(cfg),
	})

	// Surface any per-request bearer (HTTP mode) to the tool handlers via ctx;
	// a no-op for stdio, where requests carry no token info.
	server.AddReceivingMiddleware(withTokenInfo)

	// Always-available local utility.
	addTool(s, server, &mcp.Tool{
		Name: "decode_nowsecure_url",
		Description: "Parse a NowSecure console URL or deep link into the ids the other tools take, under their exact parameter names: platform, package, app_ref, assessment_ref (which also carries numeric task ids from URLs), mari_assessment_ref, group_refs, and finding. " +
			"Pass mari_assessment_ref to get_mari_assessment as its assessment_ref. " +
			"Pure/local: makes no API calls. Unparseable id-like segments are reported in a warnings array rather than dropped silently.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)},
	}, s.decodeURL)

	if cfg.EnablePlatform {
		s.registerPlatformTools(server)
		registerPlatformPrompts(server)
	}
	if cfg.EnableMARI {
		s.registerMARITools(server)
		registerMARIPrompts(server)
	}
	return server
}

// ctxKeyTokenInfo keys the verified bearer token info in a request context.
type ctxKeyTokenInfo struct{}

// withTokenInfo copies the request's bearer token info (set by the HTTP
// transport after RequireBearerToken verification) into the handler context so
// that s.api can resolve a per-caller upstream client.
func withTokenInfo(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if ex := req.GetExtra(); ex != nil && ex.TokenInfo != nil {
			ctx = context.WithValue(ctx, ctxKeyTokenInfo{}, ex.TokenInfo)
		}
		return next(ctx, method, req)
	}
}

// tokenInfoFromContext returns the bearer token info stored by withTokenInfo,
// or nil in stdio mode.
func tokenInfoFromContext(ctx context.Context) *auth.TokenInfo {
	ti, _ := ctx.Value(ctxKeyTokenInfo{}).(*auth.TokenInfo)
	return ti
}

// Serve runs the MCP server over stdio until ctx is canceled or stdin closes.
func Serve(ctx context.Context, server *mcp.Server) error {
	return server.Run(ctx, &mcp.StdioTransport{})
}

// instructions is the cross-tool usage guidance sent to the client at
// initialize time, covering the workflows that span multiple tools.
func instructions(cfg *config.Config) string {
	var b strings.Builder
	if cfg.EnablePlatform {
		b.WriteString("Read-only tools for NowSecure Platform mobile app security scans.\n")
	} else {
		b.WriteString("Read-only tools for NowSecure MARI third-party app risk intelligence.\n")
	}
	b.WriteString("The list tools default their text block to a compact table; pass format:\"json\" for the full JSON there instead, and structuredContent always carries the canonical JSON.\n")
	if cfg.EnablePlatform {
		b.WriteString("Portfolio triage: start with list_apps to get app_ref values, then get_assessment_findings. " +
			"The portfolio is a rolling 12-month window: list_apps, get_apps_affected_by_finding, and get_finding's application_count cover only apps with a completed scan in the last 12 months — apps last scanned earlier are absent entirely (never assume the portfolio is the whole tenant), and get_assessment_findings fails 'not found in portfolio' for them; list_assessments is NOT windowed and still serves their older history. " +
			"Omitting assessment_ref uses the assessment the app's portfolio row points at (its latest known scan) — that can lag a scan that just finished, so check the returned status/created_at or pass an explicit ref from list_assessments. " +
			"get_assessment_findings rows omit recommendation prose by default (pull it back with check_ids or include_recommendations); its default also omits artifact-inventory rows (counts.artifacts still counts them, include_artifacts=true restores them), and min_severity=low is the scored-vulnerability triage view. " +
			"get_finding returns a finding's docs and remediation guidance and suggests near-miss keys on a partial name (so a bare \"janus\" recovers android_janus_vuln); get_apps_affected_by_finding shows fleet impact. " +
			"search_findings substring-searches the whole catalog (key, title, description prose, category) and returns finding keys — use it when you only know a topic or risk, not a key. " +
			"list_assessments shows one app's scan history and REQUIRES app_ref, package, or appstore_key — it cannot list scans portfolio-wide. " +
			"Platform scores are 0-100 where HIGHER is better.\n")
	}
	if cfg.EnableMARI {
		b.WriteString("Third-party vetting: list_mari_apps to find the app and its assessment_ref, then get_mari_assessment. Its default is a compact risk card (scores, per-category breakdown, severity counts) with no finding rows — pull rows with min_severity or limit, per-finding deep-dive prose with check_ids, and expand sections only when needed (they are heavy). " +
			"MARI risk_score is 0-100 where HIGHER is worse — the opposite polarity of Platform scores.\n")
	}
	b.WriteString("If an operator pastes a NowSecure console URL, decode_nowsecure_url turns it into ids for the other tools.")
	return b.String()
}

func productTitle(cfg *config.Config) string {
	if cfg.EnablePlatform {
		return "NowSecure Platform"
	}
	return "NowSecure MARI"
}

// readOnlyAPI marks a tool as a read-only, idempotent GET against the
// NowSecure API so clients can gate permissions accordingly.
func readOnlyAPI() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true}
}
