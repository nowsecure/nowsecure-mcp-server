package cli

// Tests for the in-process MCP surface of profile: `profile call` (tool
// listing, schemas, invocation) and `profile budget` (measurement, budget
// enforcement, skip handling) against a stub backend.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubBackend serves the minimal fixture set the budget suite touches:
// a one-app Platform portfolio with one completed scan and one finding, a
// GraphQL check catalog with one "ssl" match, and an empty MARI catalog.
func stubBackend(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","assessmentRef":"as-1","platform":"android","package":"com.x","title":"X","group":{"ref":"g1"}}],"pageInfo":{"hasNextPage":false},"summaryInfo":{"totalResults":1}}`))
		case "/app/android/com.x/assessment":
			_, _ = w.Write([]byte(`[{"ref":"as-1","task":55,"task_status":"completed","created":"2024-06-01T00:00:00Z"}]`))
		case "/assessment/55/findings":
			_, _ = w.Write([]byte(`[{"check_id":"c1","title":"T","category":"networking","severity":"high","affected":true,"cvss":7.0,"analysis_type":"static","recommendations":{"developer":"fix it"}}]`))
		case "/v2/assessments":
			_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
		case "/graphql":
			_, _ = w.Write([]byte(`{"data":{"findings":{"list":[{"id":"ssl_check","title":"SSL pinning","platformType":"android","deprecated":false,"issue":{"severity":"high","category":"networking"}}]}}}`))
		case "/v2/portfolio/findings/ssl_check":
			_, _ = w.Write([]byte(`{"key":"ssl_check","title":"SSL pinning"}`))
		case "/v2/portfolio/findings/ssl_check/applications":
			_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false},"summaryInfo":{"totalResults":0}}`))
		case "/v2/risk-intelligence/apps":
			_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"totalResults":0,"start":0,"end":0}}`))
		default:
			t.Errorf("unexpected backend path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestProfileCallListsToolsWithoutToken(t *testing.T) {
	clearTokenEnv(t)
	_, out, _, err := runCLI(t, "profile", "call", "--platform")
	if err != nil {
		t.Fatalf("profile call (list) should not need a token: %v", err)
	}
	for _, tool := range []string{"list_apps", "get_assessment_findings", "decode_nowsecure_url"} {
		if !strings.Contains(out, tool) {
			t.Errorf("tool listing missing %s:\n%s", tool, out)
		}
	}
}

func TestProfileCallSchema(t *testing.T) {
	clearTokenEnv(t)
	_, out, _, err := runCLI(t, "profile", "call", "get_mari_assessment", "--schema", "--mari")
	if err != nil {
		t.Fatalf("--schema should not need a token: %v", err)
	}
	for _, opt := range []string{"min_severity", "check_ids", "expand"} {
		if !strings.Contains(out, opt) {
			t.Errorf("schema missing option %s:\n%s", opt, out)
		}
	}
	if _, _, _, err := runCLI(t, "profile", "call", "no_such_tool", "--schema", "--platform"); err == nil {
		t.Error("expected an error for an unknown tool")
	}
}

func TestProfileCallInvokesTool(t *testing.T) {
	clearTokenEnv(t)
	// decode_nowsecure_url is local, but invocation still goes through the
	// full MCP session — the result is the exact CallTool payload.
	_, out, _, err := runCLI(t, "profile", "call", "--token", "test-token",
		"--platform", "decode_nowsecure_url", `{"url":"https://app.nowsecure.com/app/android/com.example.app/assessment/987654321/findings/apk_janus"}`)
	if err != nil {
		t.Fatalf("call decode_nowsecure_url: %v", err)
	}
	for _, want := range []string{`"structuredContent"`, `"com.example.app"`, `"apk_janus"`} {
		if !strings.Contains(out, want) {
			t.Errorf("call output missing %s:\n%s", want, out)
		}
	}
	// Bad JSON args error before any call.
	if _, _, _, err := runCLI(t, "profile", "call", "--token", "test-token", "--platform", "list_apps", "{oops"); err == nil {
		t.Error("expected a json-args parse error")
	}
}

func TestProfileBudgetSuite(t *testing.T) {
	clearTokenEnv(t)
	base := stubBackend(t)

	// Default budgets pass: Platform cases measure small, while ref-dependent
	// MARI cases skip because the fixture catalog is empty.
	_, out, _, err := runCLI(t, "profile", "budget", "--token", "test-token", "--base-url", base)
	if err != nil {
		t.Fatalf("budget run failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "get_assessment_findings.default") || !strings.Contains(out, "ok") {
		t.Errorf("report missing measured Platform case:\n%s", out)
	}
	if !strings.Contains(out, "get_mari_assessment.default") || !strings.Contains(out, "skip") {
		t.Errorf("report missing skipped MARI case:\n%s", out)
	}

	// A tightened per-case budget must breach and exit non-zero.
	budgets := filepath.Join(t.TempDir(), "budgets.json")
	if err := os.WriteFile(budgets, []byte(`{"list_apps.default": 10}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _, err = runCLI(t, "profile", "budget", "--token", "test-token", "--base-url", base, "--budgets", budgets)
	if err == nil || !strings.Contains(err.Error(), "over budget") {
		t.Fatalf("expected an over-budget failure, got err=%v\n%s", err, out)
	}
	if !strings.Contains(out, "over") {
		t.Errorf("report does not mark the breached case:\n%s", out)
	}

	// Unknown case names in the override file fail loudly.
	if err := os.WriteFile(budgets, []byte(`{"no_such_case": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := runCLI(t, "profile", "budget", "--token", "test-token", "--base-url", base, "--budgets", budgets); err == nil ||
		!strings.Contains(err.Error(), "unknown budget case") {
		t.Fatalf("expected an unknown-case error, got %v", err)
	}
}
