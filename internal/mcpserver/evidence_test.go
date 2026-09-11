package mcpserver_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nsmcp/internal/config"
	"nsmcp/internal/nsclient"
)

// Go-client evidence must also survive schema validation and both MCP output
// channels, including the arrays that are empty when a scan has no evidence.
func TestGetAssessmentFindings_EvidenceMCP(t *testing.T) {
	cfg := &config.Config{
		Token: "test-token", EnablePlatform: true,
		BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v2/portfolio/applications":
				fmt.Fprint(w, `{"rows":[{"ref":"app-1","assessmentRef":"as-1","platform":"android","package":"com.acme","group":{"ref":"grp"}}],"pageInfo":{"hasNextPage":false}}`)
			case "/app/android/com.acme/assessment":
				fmt.Fprint(w, `[{"ref":"as-1","task":55,"task_status":"completed"}]`)
			case "/assessment/55/findings":
				fmt.Fprint(w, `[
					{"check_id":"code","title":"Code","severity":"high","affected":true,"recommendations":{"developer":"Use the secure API.\nRebuild and rescan."},"context":{"fields":{"path":{"title":"Source file"}},"rows":[{"path":"Network.java","locations":[{"location_id":"loc-1"},{"location_id":"missing"}]}]}},
					{"check_id":"empty","title":"No evidence","severity":"low","affected":true,"context":null}
				]`)
			case "/graphql":
				fmt.Fprint(w, `{"data":{"auto":{"assessment":{"codeLocations":[{"id":"loc-1","data":{"file":"Network.java","line":42,"code":"connect();"}}]}}}}`)
			default:
				t.Errorf("unexpected path %q", r.URL.Path)
			}
		}),
	}
	cs := session(t, cfg)
	for _, id := range []string{"code", "empty"} {
		t.Run(id, func(t *testing.T) {
			res := callTool(t, cs, "get_assessment_findings", map[string]any{
				"app_ref": "app-1", "assessment_ref": "as-1",
				"check_ids": []string{id}, "include_evidence": true, "format": "table",
			})
			var textJSON map[string]any
			if err := json.Unmarshal([]byte(singleText(t, res)), &textJSON); err != nil {
				t.Fatalf("evidence did not force JSON: %v", err)
			}
			out := structured(t, res)
			if !reflect.DeepEqual(out, textJSON) {
				t.Fatal("text and structured evidence differ")
			}
			findings := requireJSONArray(t, out, "findings")
			if len(findings) != 1 {
				t.Fatalf("findings = %v, want one selected finding", findings)
			}
			finding := findings[0].(map[string]any)
			evidence, ok := finding["evidence"].(map[string]any)
			if !ok {
				t.Fatalf("evidence = %v, want object", finding["evidence"])
			}
			rows := requireJSONArray(t, evidence, "rows")
			locations := requireJSONArray(t, evidence, "code_locations")
			if id == "empty" {
				if len(rows) != 0 || len(locations) != 0 {
					t.Fatal("empty context invented evidence")
				}
				return
			}
			if len(rows) != 1 || len(locations) != 1 || locations[0].(map[string]any)["id"] != "loc-1" {
				t.Fatalf("evidence was lost or encoded incorrectly: %v", evidence)
			}
			if got := evidence["unresolved_location_ids"]; !reflect.DeepEqual(got, []any{"missing"}) {
				t.Errorf("unresolved ids = %v, want [missing]", got)
			}
			if !strings.Contains(finding["recommendation"].(string), "Rebuild and rescan.") {
				t.Error("recommendation missing")
			}
		})
	}
	// The SDK must return invalid evidence selection as a tool error, with
	// actionable guidance rather than a protocol failure or an unscoped dump.
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "get_assessment_findings", Arguments: map[string]any{"app_ref": "app-1", "include_evidence": true},
	})
	if err != nil || !res.IsError || !strings.Contains(contentText(res), "check_ids") {
		t.Fatalf("invalid selection: result=%v err=%v", res, err)
	}
}

func TestGetAssessmentFindings_EvidencePaginationMCP(t *testing.T) {
	cfg := &config.Config{
		Token: "test-token", EnablePlatform: true,
		BaseURL: backendURL(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v2/portfolio/applications":
				fmt.Fprint(w, `{"rows":[{"ref":"app-1","assessmentRef":"as-1","platform":"android","package":"com.acme","group":{"ref":"grp"}}],"pageInfo":{"hasNextPage":false}}`)
			case "/app/android/com.acme/assessment":
				fmt.Fprint(w, `[{"ref":"as-1","task":55,"task_status":"completed"}]`)
			case "/assessment/55/findings":
				rows := make([]any, 23)
				for i := range rows {
					rows[i] = map[string]any{"path": fmt.Sprintf("File%d.java", i), "location_id": fmt.Sprintf("loc-%d", i)}
				}
				_ = json.NewEncoder(w).Encode([]any{map[string]any{
					"check_id": "c", "title": "Code", "severity": "high", "affected": true,
					"context": map[string]any{"rows": rows},
				}})
			case "/graphql":
				var body struct{ Query string }
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					return
				}
				_, idsPart, ok := strings.Cut(body.Query, "codeLocations(ids: ")
				if !ok {
					t.Errorf("unexpected query: %s", body.Query)
					return
				}
				idsJSON, _, _ := strings.Cut(idsPart, ")")
				var ids []string
				if err := json.Unmarshal([]byte(idsJSON), &ids); err != nil {
					t.Error(err)
					return
				}
				locations := make([]any, len(ids))
				for i, id := range ids {
					locations[i] = map[string]any{"id": id, "data": map[string]any{"method": "connect"}}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"auto": map[string]any{
					"assessment": map[string]any{"codeLocations": locations},
				}}})
			default:
				t.Errorf("unexpected path %q", r.URL.Path)
			}
		}),
	}
	cs := session(t, cfg)
	for _, tc := range []struct{ offset, limit, rows, next int }{
		{0, 0, 20, 20}, {20, 0, 3, 0}, {23, 0, 0, 0}, {0, 1, 1, 1},
	} {
		res := callTool(t, cs, "get_assessment_findings", map[string]any{
			"app_ref": "app-1", "assessment_ref": "as-1", "check_ids": []string{"c"},
			"include_evidence": true, "evidence_offset": tc.offset, "evidence_limit": tc.limit,
		})
		var out nsclient.AssessmentFindings
		if err := json.Unmarshal([]byte(singleText(t, res)), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Findings) != 1 || out.Findings[0].Evidence == nil {
			t.Fatalf("missing finding/evidence: %+v", out)
		}
		e := out.Findings[0].Evidence
		if e.TotalRows != 23 || e.Offset != tc.offset || len(e.Rows) != tc.rows || e.NextOffset != tc.next || e.HasMore != (tc.next != 0) {
			t.Fatalf("page offset=%d limit=%d returned %+v", tc.offset, tc.limit, e)
		}
		if len(e.CodeLocations) != len(e.Rows) {
			t.Errorf("fetched code locations outside this page: rows=%d locations=%d", len(e.Rows), len(e.CodeLocations))
		}
		for i, row := range e.Rows {
			if row.(map[string]any)["path"] != fmt.Sprintf("File%d.java", tc.offset+i) {
				t.Fatalf("offset selected the wrong row: %+v", row)
			}
		}
	}
}
