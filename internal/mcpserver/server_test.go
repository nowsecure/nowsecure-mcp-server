package mcpserver_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nsmcp/internal/config"
	"nsmcp/internal/mcpserver"
)

// backendURL starts an httptest backend with h and returns its URL. When h is
// nil the backend fails the test if hit — used by tests that call no API tools.
func backendURL(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	if h == nil {
		h = func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected backend request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts.URL
}

// session builds the MCP server for cfg and connects a real client over
// in-memory transports, returning the initialized client session. Driving the
// server through an actual client session (rather than the handler structs) is
// the point: several past bugs lived in the SDK schema/validation layer.
func session(t *testing.T, cfg *config.Config) *mcp.ClientSession {
	t.Helper()
	ctx := t.Context()
	server, err := mcpserver.New(cfg, "test")
	if err != nil {
		t.Fatalf("mcpserver.New: %v", err)
	}

	serverT, clientT := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// toolNames returns the sorted set of tool names the session exposes.
func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tt := range res.Tools {
		names = append(names, tt.Name)
	}
	sort.Strings(names)
	return names
}

func promptNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListPrompts(t.Context(), nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	names := make([]string, 0, len(res.Prompts))
	for _, p := range res.Prompts {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	return names
}

// structured re-marshals the tool result's structured content and decodes it
// into a generic map, so tests inspect the exact JSON shape the server emitted.
func structured(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	if res.StructuredContent == nil {
		t.Fatalf("result has no structured content (content: %s)", contentText(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode structured content: %v (%s)", err, b)
	}
	return m
}

// contentText joins the text blocks of a result (tool errors land here).
func contentText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

const (
	platformTools = 6
	mariTools     = 2
)

func TestToolRegistrationGating(t *testing.T) {
	tests := []struct {
		name     string
		platform bool
		mari     bool
		want     []string
	}{
		{
			name:     "platform only",
			platform: true,
			want: []string{
				"decode_nowsecure_url",
				"list_apps", "list_assessments", "get_assessment_findings",
				"get_finding", "search_findings", "get_apps_affected_by_finding",
			},
		},
		{
			name: "mari only",
			mari: true,
			want: []string{"decode_nowsecure_url", "list_mari_apps", "get_mari_assessment"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Token:          "test-token",
				BaseURL:        backendURL(t, nil),
				EnablePlatform: tt.platform,
				EnableMARI:     tt.mari,
			}
			got := toolNames(t, session(t, cfg))
			if !sameSet(got, tt.want) {
				t.Errorf("tool set mismatch\n got  %v\n want %v", got, tt.want)
			}
		})
	}
}

func TestProductSelectionValidation(t *testing.T) {
	for _, cfg := range []*config.Config{
		{Token: "test-token", BaseURL: backendURL(t, nil)},
		{Token: "test-token", BaseURL: backendURL(t, nil), EnablePlatform: true, EnableMARI: true},
	} {
		if _, err := mcpserver.New(cfg, "test"); err == nil {
			t.Fatalf("mcpserver.New(%+v) succeeded, want product-selection error", cfg)
		}
	}
}

func TestToolAnnotations(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  *config.Config
		want int
	}{
		{"platform", &config.Config{Token: "test-token", BaseURL: backendURL(t, nil), EnablePlatform: true}, 1 + platformTools},
		{"mari", &config.Config{Token: "test-token", BaseURL: backendURL(t, nil), EnableMARI: true}, 1 + mariTools},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res, err := session(t, tt.cfg).ListTools(t.Context(), nil)
			if err != nil {
				t.Fatalf("ListTools: %v", err)
			}
			if len(res.Tools) != tt.want {
				t.Fatalf("tool count = %d, want %d", len(res.Tools), tt.want)
			}
			for _, tool := range res.Tools {
				if tool.Annotations == nil {
					t.Errorf("%s: Annotations is nil", tool.Name)
					continue
				}
				if !tool.Annotations.ReadOnlyHint {
					t.Errorf("%s: ReadOnlyHint = false, want true", tool.Name)
				}
				if tool.Name == "decode_nowsecure_url" {
					if tool.Annotations.OpenWorldHint == nil {
						t.Errorf("%s: OpenWorldHint is nil, want false", tool.Name)
					} else if *tool.Annotations.OpenWorldHint {
						t.Errorf("%s: OpenWorldHint = true, want false", tool.Name)
					}
				}
			}
		})
	}
}

func TestServerInstructions(t *testing.T) {
	tests := []struct {
		name                   string
		cfg                    *config.Config
		want, avoid, wantTitle string
	}{
		{"platform", &config.Config{Token: "test-token", BaseURL: backendURL(t, nil), EnablePlatform: true}, "list_apps", "list_mari_apps", "NowSecure Platform"},
		{"mari", &config.Config{Token: "test-token", BaseURL: backendURL(t, nil), EnableMARI: true}, "list_mari_apps", "list_apps", "NowSecure MARI"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			init := session(t, tt.cfg).InitializeResult()
			if init == nil { //nolint:staticcheck // SA5011 false positive: t.Fatal below halts the test
				t.Fatal("InitializeResult is nil")
			}
			if strings.TrimSpace(init.Instructions) == "" { //nolint:staticcheck // SA5011 false positive: t.Fatal above halts the test
				t.Fatal("Instructions is empty")
			}
			if !strings.Contains(init.Instructions, tt.want) { //nolint:staticcheck // SA5011 false positive: t.Fatal above halts the test
				t.Errorf("Instructions does not mention %s: %q", tt.want, init.Instructions)
			}
			if strings.Contains(init.Instructions, tt.avoid) { //nolint:staticcheck // SA5011 false positive: t.Fatal above halts the test
				t.Errorf("Instructions unexpectedly mention %s: %q", tt.avoid, init.Instructions)
			}
			if init.ServerInfo == nil || init.ServerInfo.Title != tt.wantTitle { //nolint:staticcheck // SA5011 false positive: t.Fatal above halts the test
				t.Errorf("server title = %v, want %q", init.ServerInfo, tt.wantTitle)
			}
		})
	}
}

func TestPromptRegistrationGating(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want []string
	}{
		{
			"platform",
			&config.Config{Token: "test-token", BaseURL: backendURL(t, nil), EnablePlatform: true},
			[]string{"platform_investigate_finding", "platform_review_app", "platform_triage_portfolio"},
		},
		{
			"mari",
			&config.Config{Token: "test-token", BaseURL: backendURL(t, nil), EnableMARI: true},
			[]string{"mari_compare_apps", "mari_review_app", "mari_triage_catalog"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := promptNames(t, session(t, tt.cfg)); !sameSet(got, tt.want) {
				t.Errorf("prompt set mismatch\n got  %v\n want %v", got, tt.want)
			}
		})
	}
}

func TestPromptRendersArgument(t *testing.T) {
	cfg := &config.Config{Token: "test-token", BaseURL: backendURL(t, nil), EnableMARI: true}
	res, err := session(t, cfg).GetPrompt(t.Context(), &mcp.GetPromptParams{
		Name:      "mari_review_app",
		Arguments: map[string]string{"app": "Example Wallet"},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(res.Messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(res.Messages))
	}
	content, ok := res.Messages[0].Content.(*mcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want *mcp.TextContent", res.Messages[0].Content)
	}
	if !strings.Contains(content.Text, "Example Wallet") || !strings.Contains(content.Text, "MARI") {
		t.Errorf("prompt text = %q, want rendered app and product", content.Text)
	}
}

// TestGetMARIAssessment_ExpandStructuredOutput is the audit's top regression:
// requesting an expand section used to fail with a JSON-RPC protocol error
// because the server's own MARIAssessment.Expanded (once map[string]json.RawMessage)
// made the SDK infer a byte-array output schema that rejected the real object.
func TestGetMARIAssessment_ExpandStructuredOutput(t *testing.T) {
	cfg := &config.Config{
		Token:      "test-token",
		EnableMARI: true,
		BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Path; got != "/v2/risk-intelligence/assessment/ri-1" {
				t.Errorf("path = %q", got)
			}
			// appInfo is always threaded in for identity, so the upstream expand
			// carries it alongside whatever the caller requested.
			expand := r.URL.Query().Get("expand")
			set := make(map[string]bool)
			for p := range strings.SplitSeq(expand, ",") {
				set[p] = true
			}
			if !set["permissions"] || !set["appInfo"] {
				t.Errorf("expand = %q, want permissions and appInfo", expand)
			}
			_, _ = w.Write([]byte(`{
				"createdAt":"2024-01-01","riskScore":40,"riskRating":"C","riskCategory":"MEDIUM",
				"summaryInfo":{"totalFindingsAffected":1,"totalFindingsChecked":9},
				"findings":[{"checkId":"c1","title":"T","affected":true,"severity":"high","cvssScore":7.1,"categories":["Privacy"]}],
				"permissions":{"summary":{"totalPermissions":9},"android":[{"name":"CAMERA","risky":true}]}
			}`))
		}),
	}
	cs := session(t, cfg)

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "get_mari_assessment",
		Arguments: map[string]any{"assessment_ref": "ri-1", "expand": []string{"permissions"}},
	})
	if err != nil {
		t.Fatalf("CallTool returned a protocol error (regression): %v", err)
	}
	if res.IsError {
		t.Fatalf("result IsError, content: %s", contentText(res))
	}

	m := structured(t, res)
	expanded, ok := m["expanded"].(map[string]any)
	if !ok {
		t.Fatalf("expanded is %T, want JSON object: %v", m["expanded"], m["expanded"])
	}
	perms, ok := expanded["permissions"].(map[string]any)
	if !ok {
		t.Fatalf("expanded.permissions is %T, want JSON object", expanded["permissions"])
	}
	if _, ok := perms["summary"].(map[string]any); !ok {
		t.Errorf("expanded.permissions.summary missing/not an object: %v", perms)
	}
}

// TestGetMARIAssessment_ProgressiveDisclosure walks the tool's disclosure
// ladder end-to-end: risk-card default (no rows, severity counts, category
// breakdown, findings_omitted), min_severity rows (severity-sorted, no
// prose), include_descriptions (short prose on every row), and the check_ids
// deep-dive (full prose tier).
func TestGetMARIAssessment_ProgressiveDisclosure(t *testing.T) {
	cfg := &config.Config{
		Token:      "test-token",
		EnableMARI: true,
		BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{
				"createdAt":"2024-01-01","riskScore":40,"riskRating":"C","riskCategory":"MEDIUM",
				"nowSecureRiskScoresByFindingCategory":{"Storage":80.1,"Endpoint":0},
				"summaryInfo":{"totalFindingsAffected":2,"totalFindingsChecked":9},
				"findings":[
					{"checkId":"lo","title":"Low","affected":true,"severity":"low","shortDescription":"lo short"},
					{"checkId":"hi","title":"High","affected":true,"severity":"high","cvssScore":7.1,"shortDescription":"hi short","description":"hi full","businessImpact":"hi impact","analysisType":"static",
						"regulations":[{"label":"GDPR","links":[{"title":"Art. 32","url":"https://gdpr.example/32"}]}]}
				]
			}`))
		}),
	}
	cs := session(t, cfg)
	ctx := t.Context()

	call := func(args map[string]any) map[string]any {
		t.Helper()
		args["assessment_ref"] = "ri-1"
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_mari_assessment", Arguments: args})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if res.IsError {
			t.Fatalf("result IsError: %s", contentText(res))
		}
		return structured(t, res)
	}
	rows := func(m map[string]any) []map[string]any {
		t.Helper()
		raw, ok := m["findings"].([]any)
		if !ok {
			t.Fatalf("findings is %T, want array", m["findings"])
		}
		out := make([]map[string]any, len(raw))
		for i, r := range raw {
			out[i], _ = r.(map[string]any)
		}
		return out
	}

	// Default: a risk card — counts and breakdowns, no finding rows.
	m := call(map[string]any{})
	if got := rows(m); len(got) != 0 {
		t.Errorf("default findings = %v, want none", got)
	}
	if m["findings_omitted"] != float64(2) {
		t.Errorf("findings_omitted = %v, want 2", m["findings_omitted"])
	}
	summary, _ := m["summary"].(map[string]any)
	counts, _ := summary["counts"].(map[string]any)
	if counts["high"] != float64(1) || counts["low"] != float64(1) {
		t.Errorf("summary.counts = %v, want high/low = 1", counts)
	}
	scores, _ := m["nowsecure_risk_scores_by_category"].(map[string]any)
	if scores["Storage"] != float64(80.1) || len(scores) != 1 {
		t.Errorf("category scores = %v, want only Storage 80.1 (zeros dropped)", scores)
	}

	// min_severity=info returns every row, most severe first, without prose.
	m = call(map[string]any{"min_severity": "info"})
	got := rows(m)
	if len(got) != 2 || got[0]["check_id"] != "hi" || got[1]["check_id"] != "lo" {
		t.Fatalf("min_severity=info rows = %v, want [hi lo] severity-sorted", got)
	}
	if _, ok := got[0]["short_description"]; ok {
		t.Errorf("plain rows must omit prose: %v", got[0])
	}
	if m["findings_omitted"] != nil {
		t.Errorf("findings_omitted = %v, want absent when nothing was omitted", m["findings_omitted"])
	}

	// limit keeps the most severe rows.
	m = call(map[string]any{"limit": 1})
	if got := rows(m); len(got) != 1 || got[0]["check_id"] != "hi" {
		t.Errorf("limit=1 rows = %v, want [hi]", got)
	}

	// include_descriptions=true restores short prose on every row.
	m = call(map[string]any{"include_descriptions": true})
	got = rows(m)
	if len(got) != 2 || got[0]["short_description"] != "hi short" {
		t.Errorf("include_descriptions rows = %v, want short prose on every row", got)
	}
	if _, ok := got[0]["description"]; ok {
		t.Errorf("deep prose must stay check_ids-only: %v", got[0])
	}

	// check_ids is the deep-dive: the full prose tier rides along.
	m = call(map[string]any{"check_ids": []string{"hi"}})
	got = rows(m)
	if len(got) != 1 || got[0]["check_id"] != "hi" {
		t.Fatalf("check_ids rows = %v, want [hi]", got)
	}
	hi := got[0]
	if hi["short_description"] != "hi short" || hi["description"] != "hi full" || hi["business_impact"] != "hi impact" {
		t.Errorf("deep-dive prose = %v, want all tiers", hi)
	}
	regs, _ := hi["regulations"].([]any)
	if len(regs) != 1 {
		t.Fatalf("regulations = %v, want the GDPR mapping", hi["regulations"])
	}

	// Invalid min_severity surfaces as a tool error naming the allowed set.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_mari_assessment",
		Arguments: map[string]any{"assessment_ref": "ri-1", "min_severity": "urgent"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError || !strings.Contains(contentText(res), "allowed: info, warn, low, medium, high, critical") {
		t.Errorf("min_severity=urgent: IsError=%v content=%q, want enum error", res.IsError, contentText(res))
	}
}

// TestListMARIApps_PageNumberRejectsBelowOne covers the audit finding that
// page_number 0 and -1 silently returned page 1. They now surface as tool
// errors before any upstream request.
func TestListMARIApps_PageNumberRejectsBelowOne(t *testing.T) {
	cfg := &config.Config{
		Token:      "test-token",
		EnableMARI: true,
		BaseURL:    backendURL(t, nil), // validation must reject before hitting the API
	}
	cs := session(t, cfg)

	for _, pn := range []int{0, -1} {
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "list_mari_apps",
			Arguments: map[string]any{"page_number": pn},
		})
		if err != nil {
			t.Fatalf("page_number=%d: protocol error: %v", pn, err)
		}
		if !res.IsError {
			t.Fatalf("page_number=%d: want tool error, got ok", pn)
		}
		if msg := contentText(res); !strings.Contains(msg, "page_number is 1-based") {
			t.Errorf("page_number=%d: error = %q, want 1-based message", pn, msg)
		}
	}
}

// TestListMARIApps_PageNumberPassThrough confirms a valid 1-based page reaches
// upstream translated to the 0-based param.
func TestListMARIApps_PageNumberPassThrough(t *testing.T) {
	cfg := &config.Config{
		Token:      "test-token",
		EnableMARI: true,
		BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("pageNumber"); got != "1" {
				t.Errorf("pageNumber = %q, want 1 (0-based of tool page 2)", got)
			}
			_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"totalResults":0,"start":0,"end":0}}`))
		}),
	}
	cs := session(t, cfg)

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "list_mari_apps",
		Arguments: map[string]any{"page_number": 2},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("result IsError: %s", contentText(res))
	}
}

// TestListAssessments_MissingFilterIsToolError checks handler errors surface as
// tool errors (IsError), not JSON-RPC protocol errors, and that the session
// stays usable afterward.
func TestListAssessments_MissingFilterIsToolError(t *testing.T) {
	cfg := &config.Config{
		Token:          "test-token",
		EnablePlatform: true,
		BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v2/assessments" {
				t.Errorf("unexpected path %q", r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
		}),
	}
	cs := session(t, cfg)
	ctx := t.Context()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_assessments",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool returned a protocol error, want tool error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError for missing filter, got success: %s", contentText(res))
	}
	if !strings.Contains(contentText(res), "app_ref") {
		t.Errorf("error text does not mention app_ref: %q", contentText(res))
	}

	// The session must remain usable: a valid call still works.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_assessments",
		Arguments: map[string]any{"app_ref": "app-1"},
	})
	if err != nil {
		t.Fatalf("follow-up CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("follow-up call IsError: %s", contentText(res))
	}
}

// TestListAssessments_TrackPassThrough covers the full MCP path: the new tool
// argument reaches the client as a pre-pagination visibility filter and the
// returned public row is marked unavailable to the lab findings tool.
func TestListAssessments_TrackPassThrough(t *testing.T) {
	cfg := &config.Config{
		Token:          "test-token",
		EnablePlatform: true,
		BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
			filters := r.URL.Query().Get("filters")
			if !strings.Contains(filters, `"name":"visibility","value":["public"]`) {
				t.Errorf("filters = %s, want public visibility", filters)
			}
			if !strings.Contains(filters, `"name":"type","value":["baseline"]`) {
				t.Errorf("filters = %s, want baseline type", filters)
			}
			_, _ = w.Write([]byte(`{
				"rows":[{"ref":"sm-1","visibility":"public","type":"baseline","platformType":"android","packageKey":"com.x","impactTypes":{}}],
				"pageInfo":{"hasNextPage":false}
			}`))
		}),
	}
	res := callTool(t, session(t, cfg), "list_assessments", map[string]any{
		"app_ref": "app-1", "track": "store_monitor",
	})
	rows := structured(t, res)["assessments"].([]any)
	row := rows[0].(map[string]any)
	if row["track"] != "store_monitor" || row["findings_available"] != false {
		t.Errorf("row = %v, want store_monitor with findings unavailable", row)
	}
}

// TestGetAssessmentFindings_AffectedOnlyAndStatus drives the full resolve chain
// (portfolio lookup -> per-app assessment list -> findings) and checks the
// affected_only default plus the newly surfaced status field.
func TestGetAssessmentFindings_AffectedOnlyAndStatus(t *testing.T) {
	cfg := &config.Config{
		Token:          "test-token",
		EnablePlatform: true,
		BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v2/portfolio/applications":
				_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","assessmentRef":"as-1","platform":"android","package":"com.x","group":{"ref":"g1"}}],"pageInfo":{"hasNextPage":false}}`))
			case "/app/android/com.x/assessment":
				_, _ = w.Write([]byte(`[{"ref":"as-1","task":55,"task_status":"completed","created":"2024-06-01T00:00:00Z"}]`))
			case "/assessment/55/findings":
				_, _ = w.Write([]byte(`[
					{"check_id":"aff","title":"Affected","category":"Network","severity":"high","affected":true,"cvss":7.5,"recommendations":{"developer":"patch it"}},
					{"check_id":"clean","title":"Clean","category":"Crypto","severity":"medium","affected":false}
				]`))
			default:
				t.Errorf("unexpected path %q", r.URL.Path)
			}
		}),
	}
	cs := session(t, cfg)

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "get_assessment_findings",
		Arguments: map[string]any{"app_ref": "app-1"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("result IsError: %s", contentText(res))
	}
	m := structured(t, res)
	if status, _ := m["status"].(string); status != "completed" {
		t.Errorf("status = %q, want completed", status)
	}
	ids := findingIDs(t, res, "check_id")
	if len(ids) != 1 || ids[0] != "aff" {
		t.Errorf("default findings = %v, want [aff] (affected_only defaults true)", ids)
	}
}

// singleText asserts the result carries exactly one content block, a text
// block, and returns its text. The default table mode must not append a second
// JSON text block alongside the table.
func singleText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("content blocks = %d, want 1: %s", len(res.Content), contentText(res))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] is %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

// listAppsBackend answers the portfolio endpoint with two rows: one fully
// scored, one never scanned (no score/assessment_ref), plus a next cursor.
func listAppsBackend(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/portfolio/applications" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"rows":[
			{"ref":"app-1","assessmentRef":"as-1","platform":"android","package":"com.x","title":"Alpha","score":82,"rating":"good","vulnerabilityCount":3,"group":{"ref":"g1","name":"Team A"}},
			{"ref":"app-2","platform":"ios","package":"com.y","title":"Beta","vulnerabilityCount":0}
		],"pageInfo":{"hasNextPage":true,"cursor":"CUR"},"summaryInfo":{"totalResults":42}}`))
	}
}

// TestListApps_TableDefault is the format contract: the default text block is
// the table, structuredContent stays the canonical full JSON, and no second
// JSON text block is appended.
func TestListApps_TableDefault(t *testing.T) {
	cfg := &config.Config{
		Token:          "test-token",
		EnablePlatform: true,
		BaseURL:        backendURL(t, listAppsBackend(t)),
	}
	cs := session(t, cfg)

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "list_apps",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("result IsError: %s", contentText(res))
	}

	text := singleText(t, res)
	if strings.HasPrefix(strings.TrimSpace(text), "{") {
		t.Fatalf("default text block looks like JSON, want a table:\n%s", text)
	}
	lines := strings.Split(text, "\n")
	wantHeader := "app_ref\ttitle\tplatform\tpackage\tscore\trating\tvulnerability_count\tgroup\tgroup_ref\tassessment_ref"
	if lines[0] != wantHeader {
		t.Errorf("header = %q\n want %q", lines[0], wantHeader)
	}
	if want := "app-1\tAlpha\tandroid\tcom.x\t82\tgood\t3\tTeam A\tg1\tas-1"; lines[1] != want {
		t.Errorf("row 1 = %q\n want %q", lines[1], want)
	}
	// The never-scanned row leaves score, rating, group refs, assessment_ref empty.
	if want := "app-2\tBeta\tios\tcom.y\t\t\t0\t\t\t"; lines[2] != want {
		t.Errorf("row 2 = %q\n want %q", lines[2], want)
	}
	if !strings.Contains(text, "# total: 42") || !strings.Contains(text, "# has_next_page: true") || !strings.Contains(text, "# next_cursor: CUR") {
		t.Errorf("envelope comments missing:\n%s", text)
	}

	// structuredContent is the canonical full JSON regardless of the text block.
	m := structured(t, res)
	apps, ok := m["apps"].([]any)
	if !ok || len(apps) != 2 {
		t.Fatalf("structured apps = %v, want 2", m["apps"])
	}
	a0, _ := apps[0].(map[string]any)
	if a0["app_ref"] != "app-1" || a0["score"].(float64) != 82 {
		t.Errorf("structured apps[0] = %v", a0)
	}
	if total, _ := m["total"].(float64); total != 42 {
		t.Errorf("structured total = %v, want 42 (top-level, without include_summary)", m["total"])
	}
	page, _ := m["page"].(map[string]any)
	if page["has_next_page"] != true || page["next_cursor"] != "CUR" {
		t.Errorf("structured page = %v", page)
	}
}

// TestListApps_FormatJSON makes the text block mirror the structuredContent JSON.
func TestListApps_FormatJSON(t *testing.T) {
	cfg := &config.Config{
		Token:          "test-token",
		EnablePlatform: true,
		BaseURL:        backendURL(t, listAppsBackend(t)),
	}
	cs := session(t, cfg)

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "list_apps",
		Arguments: map[string]any{"format": "json"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("result IsError: %s", contentText(res))
	}

	text := singleText(t, res)
	var fromText map[string]any
	if err := json.Unmarshal([]byte(text), &fromText); err != nil {
		t.Fatalf("format=json text block is not JSON: %v\n%s", err, text)
	}
	if apps, ok := fromText["apps"].([]any); !ok || len(apps) != 2 {
		t.Errorf("format=json text apps = %v, want 2", fromText["apps"])
	}
}

// TestFormatParam_Invalid rejects an unknown format as a tool error that names
// both allowed values.
func TestFormatParam_Invalid(t *testing.T) {
	cfg := &config.Config{
		Token:          "test-token",
		EnablePlatform: true,
		BaseURL:        backendURL(t, nil), // rejected before any upstream call
	}
	cs := session(t, cfg)

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "list_apps",
		Arguments: map[string]any{"format": "yaml"},
	})
	if err != nil {
		t.Fatalf("CallTool returned a protocol error, want tool error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("want IsError for bad format, got ok: %s", contentText(res))
	}
	msg := contentText(res)
	if !strings.Contains(msg, "table") || !strings.Contains(msg, "json") {
		t.Errorf("error %q does not name both table and json", msg)
	}
}

// TestGetAssessmentFindings_ProseForcesJSON checks the constraint that prose
// requests (include_recommendations / check_ids) force the JSON text block even
// under the default table format, since recommendation markdown does not
// tabulate.
func TestGetAssessmentFindings_ProseForcesJSON(t *testing.T) {
	cfg := &config.Config{
		Token:          "test-token",
		EnablePlatform: true,
		BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v2/portfolio/applications":
				_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","assessmentRef":"as-1","platform":"android","package":"com.x","group":{"ref":"g1"}}],"pageInfo":{"hasNextPage":false}}`))
			case "/app/android/com.x/assessment":
				_, _ = w.Write([]byte(`[{"ref":"as-1","task":55,"task_status":"completed","created":"2024-06-01T00:00:00Z"}]`))
			case "/assessment/55/findings":
				_, _ = w.Write([]byte(`[{"check_id":"aff","title":"Affected","category":"Network","severity":"high","affected":true,"cvss":7.5,"recommendations":{"developer":"patch it"}}]`))
			default:
				t.Errorf("unexpected path %q", r.URL.Path)
			}
		}),
	}
	cs := session(t, cfg)

	// Default format=table, but include_recommendations forces JSON.
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "get_assessment_findings",
		Arguments: map[string]any{"app_ref": "app-1", "include_recommendations": true},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("result IsError: %s", contentText(res))
	}
	text := singleText(t, res)
	if !strings.HasPrefix(strings.TrimSpace(text), "{") {
		t.Errorf("prose request should force a JSON text block, got:\n%s", text)
	}
	if !strings.Contains(text, "patch it") {
		t.Errorf("forced-json text block missing recommendation prose:\n%s", text)
	}
}

// TestGetAssessmentFindings_TableDefault confirms the plain findings path
// (no prose) renders the compact table with the counts/envelope comments.
func TestGetAssessmentFindings_TableDefault(t *testing.T) {
	cfg := &config.Config{
		Token:          "test-token",
		EnablePlatform: true,
		BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v2/portfolio/applications":
				_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","assessmentRef":"as-1","platform":"android","package":"com.x","group":{"ref":"g1"}}],"pageInfo":{"hasNextPage":false}}`))
			case "/app/android/com.x/assessment":
				_, _ = w.Write([]byte(`[{"ref":"as-1","task":55,"task_status":"completed","created":"2024-06-01T00:00:00Z"}]`))
			case "/assessment/55/findings":
				_, _ = w.Write([]byte(`[{"check_id":"aff","title":"Affected","category":"Network","severity":"high","affected":true,"cvss":7.5}]`))
			default:
				t.Errorf("unexpected path %q", r.URL.Path)
			}
		}),
	}
	cs := session(t, cfg)

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "get_assessment_findings",
		Arguments: map[string]any{"app_ref": "app-1"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("result IsError: %s", contentText(res))
	}
	text := singleText(t, res)
	lines := strings.Split(text, "\n")
	if want := "check_id\tseverity\tcvss\tcategory\tanalysis_type\taffected\ttitle"; lines[0] != want {
		t.Errorf("header = %q\n want %q", lines[0], want)
	}
	if want := "aff\thigh\t7.5\tnetwork\t\ttrue\tAffected"; lines[1] != want {
		t.Errorf("row = %q\n want %q", lines[1], want)
	}
	if !strings.Contains(text, "# counts: c:0 h:1 m:0 l:0 w:0 i:0") {
		t.Errorf("counts comment missing/wrong:\n%s", text)
	}
	if !strings.Contains(text, "# status: completed") {
		t.Errorf("status comment missing:\n%s", text)
	}
}

// requireJSONArray asserts that structured content's field at key round-trips
// as a JSON array, never null — the regression denilSlices guards against: a
// bare nil Go slice marshals to JSON null, which breaks an MCP client
// validating structuredContent against an array-typed output schema.
func requireJSONArray(t *testing.T, m map[string]any, key string) []any {
	t.Helper()
	v, ok := m[key].([]any)
	if !ok {
		t.Fatalf("%s = %v (%T), want a JSON array, not null", key, m[key], m[key])
	}
	return v
}

// callTool is a small CallTool wrapper shared by the empty-rows regression
// tests: it fails the test on a protocol error or a tool error.
func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("CallTool %s: result IsError: %s", name, contentText(res))
	}
	return res
}

// TestEmptyRowsYieldJSONArrays drives every list-shaped tool with a backend
// that reports zero rows and asserts each tool's array-typed field marshals as
// [] rather than null (see denilSlices). get_assessment_findings and
// get_mari_assessment are the two that append into a nil slice and previously
// shipped null here; the rest are covered too so the invariant holds
// server-wide, not just where it happened to break.
func TestEmptyRowsYieldJSONArrays(t *testing.T) {
	t.Run("list_apps", func(t *testing.T) {
		cfg := &config.Config{
			Token:          "test-token",
			EnablePlatform: true,
			BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false},"summaryInfo":{"totalResults":0}}`))
			}),
		}
		res := callTool(t, session(t, cfg), "list_apps", map[string]any{})
		requireJSONArray(t, structured(t, res), "apps")
	})

	t.Run("list_assessments", func(t *testing.T) {
		cfg := &config.Config{
			Token:          "test-token",
			EnablePlatform: true,
			BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
			}),
		}
		res := callTool(t, session(t, cfg), "list_assessments", map[string]any{"app_ref": "app-1"})
		requireJSONArray(t, structured(t, res), "assessments")
	})

	t.Run("get_assessment_findings", func(t *testing.T) {
		cfg := &config.Config{
			Token:          "test-token",
			EnablePlatform: true,
			BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v2/portfolio/applications":
					_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","assessmentRef":"as-1","platform":"android","package":"com.x","group":{"ref":"g1"}}],"pageInfo":{"hasNextPage":false}}`))
				case "/app/android/com.x/assessment":
					_, _ = w.Write([]byte(`[{"ref":"as-1","task":55,"task_status":"completed","created":"2024-06-01T00:00:00Z"}]`))
				case "/assessment/55/findings":
					_, _ = w.Write([]byte(`[]`))
				default:
					t.Errorf("unexpected path %q", r.URL.Path)
				}
			}),
		}
		res := callTool(t, session(t, cfg), "get_assessment_findings", map[string]any{"app_ref": "app-1"})
		requireJSONArray(t, structured(t, res), "findings")
	})

	t.Run("search_findings", func(t *testing.T) {
		cfg := &config.Config{
			Token:          "test-token",
			EnablePlatform: true,
			BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/graphql" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				_, _ = w.Write([]byte(`{"data":{"findings":{"list":[]}}}`))
			}),
		}
		res := callTool(t, session(t, cfg), "search_findings", map[string]any{"query": "no-such-topic"})
		requireJSONArray(t, structured(t, res), "findings")
	})

	t.Run("get_apps_affected_by_finding", func(t *testing.T) {
		cfg := &config.Config{
			Token:          "test-token",
			EnablePlatform: true,
			BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v2/portfolio/findings/some_check/applications" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false},"summaryInfo":{"totalResults":0}}`))
			}),
		}
		res := callTool(t, session(t, cfg), "get_apps_affected_by_finding", map[string]any{"finding": "some_check"})
		requireJSONArray(t, structured(t, res), "apps")
	})

	t.Run("list_mari_apps", func(t *testing.T) {
		cfg := &config.Config{
			Token:      "test-token",
			EnableMARI: true,
			BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"totalResults":0,"start":0,"end":0}}`))
			}),
		}
		res := callTool(t, session(t, cfg), "list_mari_apps", map[string]any{})
		requireJSONArray(t, structured(t, res), "apps")
	})

	t.Run("get_mari_assessment", func(t *testing.T) {
		cfg := &config.Config{
			Token:      "test-token",
			EnableMARI: true,
			BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
				// No "findings" key at all: the raw decode leaves it nil, the
				// shape that used to reach the marshaler as null.
				_, _ = w.Write([]byte(`{"createdAt":"2024-01-01","riskScore":10,"riskRating":"A","riskCategory":"LOW","summaryInfo":{"totalFindingsAffected":0,"totalFindingsChecked":9}}`))
			}),
		}
		res := callTool(t, session(t, cfg), "get_mari_assessment", map[string]any{"assessment_ref": "ri-1"})
		requireJSONArray(t, structured(t, res), "findings")
	})
}

// findingIDs pulls the given key out of each element of the result's "findings"
// array in the structured content.
func findingIDs(t *testing.T, res *mcp.CallToolResult, key string) []string {
	t.Helper()
	m := structured(t, res)
	raw, ok := m["findings"].([]any)
	if !ok {
		if m["findings"] == nil {
			return nil
		}
		t.Fatalf("findings is %T, want array", m["findings"])
	}
	out := make([]string, 0, len(raw))
	for _, f := range raw {
		fm, ok := f.(map[string]any)
		if !ok {
			t.Fatalf("finding is %T, want object", f)
		}
		s, _ := fm[key].(string)
		out = append(out, s)
	}
	return out
}
