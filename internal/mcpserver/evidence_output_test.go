package mcpserver_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nsmcp/internal/config"
	"nsmcp/internal/mcpserver"
)

// Read raw HTTP JSON: the SDK client's own decoding of structuredContent also
// rounds large numbers, so inspecting its map would not test the server bytes.
func TestGetAssessmentFindings_EvidenceNumbersOnWire(t *testing.T) {
	server, err := mcpserver.New(&config.Config{
		Token: "test-token", EnablePlatform: true,
		BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v2/portfolio/applications":
				fmt.Fprint(w, `{"rows":[{"ref":"app-1","assessmentRef":"as-1","platform":"android","package":"com.acme","group":{"ref":"grp"}}],"pageInfo":{"hasNextPage":false}}`)
			case "/app/android/com.acme/assessment":
				fmt.Fprint(w, `[{"ref":"as-1","task":55,"task_status":"completed"}]`)
			case "/assessment/55/findings":
				fmt.Fprint(w, `[{"check_id":"code","title":"Code","severity":"high","affected":true,"context":{"fields":{"address":{"max":9007199254740993}},"certificate":{"serial":9007199254740993},"rows":[{"address":9007199254740993,"location_id":"site"}]}}]`)
			case "/graphql":
				fmt.Fprint(w, `{"data":{"auto":{"assessment":{"codeLocations":[{"id":"site","data":{"address":9007199254740993}}]}}}}`)
			default:
				t.Errorf("unexpected path %q", r.URL.Path)
			}
		}),
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true,
	})
	for _, tc := range []struct {
		name, args string
		evidence   bool
	}{
		{"evidence", `{"app_ref":"app-1","assessment_ref":"as-1","check_ids":["code"],"include_evidence":true}`, true},
		{"default table", `{"app_ref":"app-1","assessment_ref":"as-1"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_assessment_findings","arguments":`+tc.args+`}}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json, text/event-stream")
			request.Header.Set("MCP-Protocol-Version", "2025-06-18")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("HTTP status %d: %s", recorder.Code, recorder.Body.String())
			}
			var response struct {
				Error  json.RawMessage `json:"error"`
				Result struct {
					IsError bool `json:"isError"`
					Content []struct {
						Type string `json:"type"`
						Text string `json:"text"`
					} `json:"content"`
					Structured json.RawMessage `json:"structuredContent"`
				} `json:"result"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			result := response.Result
			if len(response.Error) > 0 || result.IsError || len(result.Content) != 1 || result.Content[0].Type != "text" {
				t.Fatalf("unexpected MCP result: %s", recorder.Body.String())
			}
			if !tc.evidence {
				if json.Valid([]byte(result.Content[0].Text)) || !strings.Contains(result.Content[0].Text, "check_id\t") || !strings.Contains(result.Content[0].Text, "code\t") {
					t.Fatalf("default findings output lost its compact table: %s", result.Content[0].Text)
				}
				if !json.Valid(result.Structured) || bytes.Contains(result.Structured, []byte(`"evidence"`)) {
					t.Fatalf("default structured output is invalid or includes evidence: %s", result.Structured)
				}
				return
			}
			for _, payload := range []string{result.Content[0].Text, string(result.Structured)} {
				var out map[string]any
				decoder := json.NewDecoder(strings.NewReader(payload))
				decoder.UseNumber()
				if err := decoder.Decode(&out); err != nil {
					t.Fatal(err)
				}
				evidence := out["findings"].([]any)[0].(map[string]any)["evidence"].(map[string]any)
				values := map[string]any{
					"row":         evidence["rows"].([]any)[0].(map[string]any)["address"],
					"field":       evidence["fields"].(map[string]any)["address"].(map[string]any)["max"],
					"certificate": evidence["certificate"].(map[string]any)["serial"],
					"code":        evidence["code_locations"].([]any)[0].(map[string]any)["data"].(map[string]any)["address"],
				}
				for name, value := range values {
					if value != json.Number("9007199254740993") {
						t.Errorf("%s number changed on the wire: %v", name, value)
					}
				}
			}
			if result.Content[0].Text != string(result.Structured) {
				t.Error("evidence text and structured JSON differ")
			}
		})
	}
}
