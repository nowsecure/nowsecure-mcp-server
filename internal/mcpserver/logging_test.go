package mcpserver_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nsmcp/internal/config"
)

// TestNSMCPLogFile_ToolCallAndServerStart drives one tool call with
// NSMCP_LOG_FILE set and checks the two record shapes the feature promises:
// one server_start record (version, mode, tool_groups) and one tool_call
// record per call (tool name, duration_ms, error if any) — and that neither
// record leaks call arguments or results.
func TestNSMCPLogFile_ToolCallAndServerStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nsmcp.log")
	t.Setenv("NSMCP_LOG_FILE", path)

	cfg := &config.Config{
		Token:          "test-token",
		EnablePlatform: true,
		// A search argument is the "customer data" this test proves never
		// reaches the log; hasNextPage:false keeps the client-side search a
		// single upstream call.
		BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false},"summaryInfo":{"totalResults":0}}`))
		}),
	}
	cs := session(t, cfg)
	callTool(t, cs, "list_apps", map[string]any{"search": "some-customer-app-name"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	var sawStart, sawCall bool
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %v: %s", err, line)
		}
		for _, forbidden := range []string{"args", "arguments", "input", "output", "result", "search"} {
			if _, ok := rec[forbidden]; ok {
				t.Errorf("log record leaked %q (arguments/results must never be logged): %v", forbidden, rec)
			}
		}
		if strings.Contains(line, "some-customer-app-name") {
			t.Errorf("log line contains a tool argument value: %s", line)
		}
		switch rec["msg"] {
		case "server_start":
			sawStart = true
			if rec["version"] != "test" {
				t.Errorf("server_start version = %v, want %q", rec["version"], "test")
			}
			if rec["mode"] != "stdio" {
				t.Errorf("server_start mode = %v, want %q", rec["mode"], "stdio")
			}
			groups, _ := rec["tool_groups"].([]any)
			if len(groups) != 1 || groups[0] != "platform" {
				t.Errorf("server_start tool_groups = %v, want [platform]", rec["tool_groups"])
			}
		case "tool_call":
			sawCall = true
			if rec["tool"] != "list_apps" {
				t.Errorf("tool_call tool = %v, want list_apps", rec["tool"])
			}
			if _, ok := rec["duration_ms"]; !ok {
				t.Errorf("tool_call record missing duration_ms: %v", rec)
			}
		}
	}
	if !sawStart {
		t.Errorf("no server_start record found in log:\n%s", data)
	}
	if !sawCall {
		t.Errorf("no tool_call record found in log:\n%s", data)
	}
}

// TestNSMCPLogFile_UnsetIsNoop checks that leaving NSMCP_LOG_FILE unset never
// writes a log file and never fails a tool call.
func TestNSMCPLogFile_UnsetIsNoop(t *testing.T) {
	t.Setenv("NSMCP_LOG_FILE", "")

	cfg := &config.Config{
		Token:          "test-token",
		EnablePlatform: true,
		BaseURL:        backendURL(t, listAppsBackend(t)),
	}
	cs := session(t, cfg)
	callTool(t, cs, "list_apps", map[string]any{})
}
