package mcpserver_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nsmcp/internal/config"
)

// This audit is opt-in and consumes credentials from the process environment.
// It never reads credential files, records raw evidence, or names customer apps.
// Set NSMCP_EVIDENCE_AUDIT_PATH to save its aggregate-only JSON report.
// NSMCP_EVIDENCE_AUDIT_MAX_FINDINGS defaults to 3; values 4..100 widen sampling
// from the first 12 affected scored findings to all affected scored findings.
// The first paginated finding is also read to completion using 100-row pages.
func TestEvidenceLiveContextConsumption(t *testing.T) {
	if os.Getenv("NSMCP_EVIDENCE_LIVE_TEST") != "1" {
		t.Skip("set NSMCP_EVIDENCE_LIVE_TEST=1 to run the real-data evidence audit")
	}
	maxFindings := 3
	if value := os.Getenv("NSMCP_EVIDENCE_AUDIT_MAX_FINDINGS"); value != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || parsed < 1 || parsed > 100 {
			t.Fatal("NSMCP_EVIDENCE_AUDIT_MAX_FINDINGS must be an integer from 1 to 100")
		}
		maxFindings = parsed
	}
	candidateScope := "first 12 affected scored findings"
	if maxFindings > 3 {
		candidateScope = "entire set of affected scored findings"
	}
	token := strings.TrimSpace(os.Getenv("NOWSECURE_API_TOKEN"))
	if token == "" {
		t.Fatal("live evidence audit requires NOWSECURE_API_TOKEN in the environment")
	}
	baseURL, err := config.ResolveBaseURL("")
	if err != nil {
		t.Fatal("live evidence audit has an invalid NOWSECURE_API_URL")
	}
	cs := session(t, &config.Config{Token: token, BaseURL: baseURL, EnablePlatform: true})
	started := time.Now()
	audit := liveEvidenceAudit{
		GeneratedAt:      started.UTC().Format(time.RFC3339),
		EstimationMethod: "ceil(bytes / 4), separately for text, structured, and combined payload; heuristic, not tokenizer output. Model context consumption depends on which representations the client includes.",
		SamplingPolicy:   fmt.Sprintf("first page of 10 portfolio apps; up to 3 distinct platform/package pairs; up to %d diverse findings among each app's %s", maxFindings, candidateScope),
		Calls:            []liveEvidenceCall{},
	}
	t.Cleanup(func() {
		audit.ElapsedMS = time.Since(started).Milliseconds()
		audit.Passed = !t.Failed()
		encoded, err := json.MarshalIndent(audit, "", "  ")
		if err != nil {
			t.Error("could not encode the aggregate evidence audit")
			return
		}
		if path := os.Getenv("NSMCP_EVIDENCE_AUDIT_PATH"); path != "" {
			if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil { //nolint:gosec // The audit path is explicitly chosen by the test operator, not supplied by app evidence.
				t.Error("could not save the aggregate evidence audit to NSMCP_EVIDENCE_AUDIT_PATH")
				return
			}
		}
		t.Logf("aggregate evidence audit:\n%s", encoded)
	})

	call := func(app, checkID, mode, tool string, args map[string]any) []byte {
		t.Helper()
		callStart := time.Now()
		result, callErr := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: args})
		stat := liveEvidenceCall{App: app, CheckID: checkID, Mode: mode, Tool: tool, ElapsedMS: time.Since(callStart).Milliseconds()}
		var encoded []byte
		switch {
		case callErr != nil:
			stat.FailureClass = "protocol_error"
		case result == nil:
			stat.FailureClass = "missing_result"
		default:
			for _, content := range result.Content {
				if text, ok := content.(*mcp.TextContent); ok {
					stat.TextBytes += len(text.Text)
				}
			}
			if result.StructuredContent != nil {
				encoded, err = json.Marshal(result.StructuredContent)
				if err != nil {
					stat.FailureClass = "invalid_structured_content"
				}
				stat.StructuredBytes = len(encoded)
			} else {
				stat.FailureClass = "missing_structured_content"
			}
			if result.IsError {
				stat.FailureClass = liveEvidenceFailureClass(contentText(result))
			}
		}
		stat.TotalBytes = stat.TextBytes + stat.StructuredBytes
		stat.EstTextTokens = (stat.TextBytes + 3) / 4
		stat.EstStructuredTokens = (stat.StructuredBytes + 3) / 4
		stat.EstCombinedTokens = (stat.TotalBytes + 3) / 4
		if stat.FailureClass == "" && tool == "get_assessment_findings" {
			if err := liveEvidenceComponents(encoded, &stat); err != nil {
				stat.FailureClass = "invalid_findings_content"
			}
		}
		audit.Calls = append(audit.Calls, stat)
		audit.MCPCallCount++
		audit.TotalTextBytes += stat.TextBytes
		audit.TotalStructuredBytes += stat.StructuredBytes
		audit.TotalBytes += stat.TotalBytes
		audit.EstTextTokens = (audit.TotalTextBytes + 3) / 4
		audit.EstStructuredTokens = (audit.TotalStructuredBytes + 3) / 4
		audit.EstCombinedTokens = (audit.TotalBytes + 3) / 4
		if stat.TotalBytes > audit.MaxPayload.TotalBytes {
			audit.MaxPayload = stat
		}
		t.Logf("%s %s %s: text_bytes=%d structured_bytes=%d combined_bytes=%d est_text_tokens=%d est_structured_tokens=%d est_combined_tokens=%d rows=%d total_rows=%d offset=%d has_more=%t locations=%d unresolved=%d elapsed_ms=%d",
			app, mode, checkID, stat.TextBytes, stat.StructuredBytes, stat.TotalBytes, stat.EstTextTokens, stat.EstStructuredTokens, stat.EstCombinedTokens,
			stat.EvidenceRows, stat.EvidenceTotalRows, stat.EvidenceOffset, stat.EvidenceHasMore, stat.CodeLocations, stat.UnresolvedLocations, stat.ElapsedMS)
		if stat.FailureClass != "" {
			t.Fatalf("%s %s failed (%s); response details omitted to protect app and evidence data", app, mode, stat.FailureClass)
		}
		return encoded
	}

	discovery := call("portfolio", "", "discovery", "list_apps", map[string]any{"page_size": 10})
	var portfolio struct {
		Apps []struct {
			AppRef        string `json:"app_ref"`
			AssessmentRef string `json:"assessment_ref"`
			Platform      string `json:"platform"`
			Package       string `json:"package"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(discovery, &portfolio); err != nil {
		t.Fatal("could not decode portfolio discovery for the evidence audit")
	}
	audit.DiscoveryRows = len(portfolio.Apps)
	seen := map[string]bool{}
	for _, app := range portfolio.Apps {
		if audit.AppsSampled == 3 {
			break
		}
		identity := app.Platform + "\x00" + app.Package
		if app.AppRef == "" || app.AssessmentRef == "" || app.Platform == "" || app.Package == "" || seen[identity] {
			continue
		}
		seen[identity] = true
		audit.AppsSampled++
		label := fmt.Sprintf("app_%d", audit.AppsSampled)
		triage := call(label, "", "triage_default", "get_assessment_findings", map[string]any{
			"app_ref": app.AppRef, "assessment_ref": app.AssessmentRef,
		})
		var findings struct {
			Findings []liveEvidenceCandidate `json:"findings"`
		}
		if err := json.Unmarshal(triage, &findings); err != nil {
			t.Fatalf("could not decode %s triage findings", label)
		}
		for _, finding := range liveEvidenceSelect(findings.Findings, maxFindings) {
			audit.FindingsSampled++
			args := map[string]any{"app_ref": app.AppRef, "assessment_ref": app.AssessmentRef, "check_ids": []string{finding.CheckID}}
			call(label, finding.CheckID, "recommendation_only", "get_assessment_findings", args)
			args["include_evidence"] = true
			call(label, finding.CheckID, "with_evidence", "get_assessment_findings", args)
			stat := audit.Calls[len(audit.Calls)-1]
			if stat.EvidenceRows > 0 || stat.CodeLocations > 0 {
				audit.NonemptyEvidenceSamples++
			}
			if !audit.PaginationVerified && stat.EvidenceHasMore {
				totalRows := stat.EvidenceTotalRows
				if err := liveEvidenceValidatePage(stat, 0, totalRows, 20); err != nil {
					t.Fatalf("%s initial evidence page is invalid: %v", label, err)
				}
				rowsRead := stat.EvidenceRows
				audit.PaginationPagesRead = 1
				for stat.EvidenceHasMore {
					args["evidence_offset"] = *stat.EvidenceNextOffset
					args["evidence_limit"] = 100
					call(label, finding.CheckID, "evidence_page", "get_assessment_findings", args)
					stat = audit.Calls[len(audit.Calls)-1]
					if err := liveEvidenceValidatePage(stat, rowsRead, totalRows, 100); err != nil {
						t.Fatalf("%s subsequent evidence page is invalid: %v", label, err)
					}
					rowsRead += stat.EvidenceRows
					audit.PaginationPagesRead++
				}
				if rowsRead != totalRows {
					t.Fatalf("%s paginated evidence returned %d cumulative rows, want %d", label, rowsRead, totalRows)
				}
				audit.PaginationVerified = true
				audit.PaginationEvidenceRows = rowsRead
			}
		}
	}
	if audit.AppsSampled == 0 {
		t.Fatal("no distinct apps with a fixed assessment were available in the first 10 portfolio rows")
	}
	if audit.FindingsSampled == 0 {
		t.Fatalf("the %d sampled apps had no affected scored findings; real evidence consumption was not measured", audit.AppsSampled)
	}
	if audit.NonemptyEvidenceSamples == 0 {
		t.Fatalf("all %d sampled findings returned empty evidence; cannot validate real evidence consumption from these samples", audit.FindingsSampled)
	}
}

type liveEvidenceAudit struct {
	GeneratedAt             string             `json:"generated_at"`
	Passed                  bool               `json:"passed"`
	SamplingPolicy          string             `json:"sampling_policy"`
	EstimationMethod        string             `json:"token_estimate"`
	DiscoveryRows           int                `json:"discovery_rows"`
	AppsSampled             int                `json:"apps_sampled"`
	FindingsSampled         int                `json:"findings_sampled"`
	NonemptyEvidenceSamples int                `json:"nonempty_evidence_samples"`
	PaginationVerified      bool               `json:"pagination_verified"`
	PaginationPagesRead     int                `json:"pagination_pages_read"`
	PaginationEvidenceRows  int                `json:"pagination_evidence_rows"`
	MCPCallCount            int                `json:"mcp_call_count"`
	TotalTextBytes          int                `json:"total_text_bytes"`
	TotalStructuredBytes    int                `json:"total_structured_bytes"`
	TotalBytes              int                `json:"total_bytes"`
	EstTextTokens           int                `json:"est_text_tokens"`
	EstStructuredTokens     int                `json:"est_structured_tokens"`
	EstCombinedTokens       int                `json:"est_combined_tokens"`
	ElapsedMS               int64              `json:"elapsed_ms"`
	MaxPayload              liveEvidenceCall   `json:"max_payload"`
	Calls                   []liveEvidenceCall `json:"calls"`
}

type liveEvidenceCall struct {
	App                 string `json:"app"`
	CheckID             string `json:"check_id,omitempty"`
	Mode                string `json:"mode"`
	Tool                string `json:"tool"`
	TextBytes           int    `json:"text_bytes"`
	StructuredBytes     int    `json:"structured_bytes"`
	TotalBytes          int    `json:"total_bytes"`
	EstTextTokens       int    `json:"est_text_tokens"`
	EstStructuredTokens int    `json:"est_structured_tokens"`
	EstCombinedTokens   int    `json:"est_combined_tokens"`
	EvidenceRows        int    `json:"evidence_rows"`
	EvidenceTotalRows   int    `json:"evidence_total_rows"`
	EvidenceOffset      int    `json:"evidence_offset"`
	EvidenceHasMore     bool   `json:"evidence_has_more"`
	EvidenceNextOffset  *int   `json:"evidence_next_offset,omitempty"`
	CodeLocations       int    `json:"code_locations"`
	UnresolvedLocations int    `json:"unresolved_locations"`
	EvidenceBytes       int    `json:"evidence_bytes"`
	EvidenceRowsBytes   int    `json:"evidence_rows_bytes"`
	CodeLocationsBytes  int    `json:"code_locations_bytes"`
	CodeDataBytes       int    `json:"code_data_bytes"`
	ElapsedMS           int64  `json:"elapsed_ms"`
	FailureClass        string `json:"failure_class,omitempty"`
}

type liveEvidenceCandidate struct {
	CheckID      string `json:"check_id"`
	Affected     bool   `json:"affected"`
	Severity     string `json:"severity"`
	Category     string `json:"category"`
	AnalysisType string `json:"analysis_type"`
}

func liveEvidenceSelect(findings []liveEvidenceCandidate, maxFindings int) []liveEvidenceCandidate {
	candidates := []liveEvidenceCandidate{}
	for _, finding := range findings {
		if !finding.Affected || finding.CheckID == "" {
			continue
		}
		switch strings.ToLower(finding.Severity) {
		case "critical", "high", "medium", "low":
			candidates = append(candidates, finding)
		}
		if maxFindings <= 3 && len(candidates) == 12 {
			break
		}
	}
	selected := []liveEvidenceCandidate{}
	seenIDs, seenAnalysis, seenCategories := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for len(selected) < maxFindings {
		best, bestScore := -1, -1
		for i, finding := range candidates {
			if seenIDs[finding.CheckID] {
				continue
			}
			score := 0
			if finding.AnalysisType != "" && !seenAnalysis[finding.AnalysisType] {
				score += 2
			}
			if finding.Category != "" && !seenCategories[finding.Category] {
				score++
			}
			if score > bestScore {
				best, bestScore = i, score
			}
		}
		if best == -1 {
			break
		}
		finding := candidates[best]
		selected = append(selected, finding)
		seenIDs[finding.CheckID], seenAnalysis[finding.AnalysisType], seenCategories[finding.Category] = true, true, true
	}
	return selected
}

func liveEvidenceComponents(encoded []byte, stat *liveEvidenceCall) error {
	var report struct {
		Findings []struct {
			Evidence json.RawMessage `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(encoded, &report); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		if len(finding.Evidence) == 0 || string(finding.Evidence) == "null" {
			continue
		}
		var evidence struct {
			Rows                  json.RawMessage `json:"rows"`
			TotalRows             int             `json:"total_rows"`
			Offset                int             `json:"offset"`
			HasMore               bool            `json:"has_more"`
			NextOffset            *int            `json:"next_offset"`
			CodeLocations         json.RawMessage `json:"code_locations"`
			UnresolvedLocationIDs []string        `json:"unresolved_location_ids"`
		}
		if err := json.Unmarshal(finding.Evidence, &evidence); err != nil {
			return err
		}
		var rows []json.RawMessage
		if err := json.Unmarshal(evidence.Rows, &rows); err != nil {
			return err
		}
		var locations []struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(evidence.CodeLocations, &locations); err != nil {
			return err
		}
		stat.EvidenceBytes += len(finding.Evidence)
		stat.EvidenceRowsBytes += len(evidence.Rows)
		stat.CodeLocationsBytes += len(evidence.CodeLocations)
		stat.EvidenceRows += len(rows)
		stat.EvidenceTotalRows += evidence.TotalRows
		stat.EvidenceOffset = evidence.Offset
		stat.EvidenceHasMore = stat.EvidenceHasMore || evidence.HasMore
		stat.EvidenceNextOffset = evidence.NextOffset
		stat.CodeLocations += len(locations)
		stat.UnresolvedLocations += len(evidence.UnresolvedLocationIDs)
		for _, location := range locations {
			stat.CodeDataBytes += len(location.Data)
		}
	}
	return nil
}

func liveEvidenceValidatePage(stat liveEvidenceCall, offset, totalRows, limit int) error {
	if stat.EvidenceOffset != offset {
		return fmt.Errorf("offset=%d, want %d", stat.EvidenceOffset, offset)
	}
	if stat.EvidenceTotalRows != totalRows {
		return fmt.Errorf("total_rows changed from %d to %d", totalRows, stat.EvidenceTotalRows)
	}
	wantRows := min(limit, totalRows-offset)
	if wantRows <= 0 || stat.EvidenceRows != wantRows {
		return fmt.Errorf("returned rows=%d, want %d", stat.EvidenceRows, wantRows)
	}
	nextOffset := offset + stat.EvidenceRows
	if stat.EvidenceHasMore != (nextOffset < totalRows) {
		return fmt.Errorf("has_more=%t for %d of %d cumulative rows", stat.EvidenceHasMore, nextOffset, totalRows)
	}
	if stat.EvidenceHasMore {
		if stat.EvidenceNextOffset == nil || *stat.EvidenceNextOffset != nextOffset {
			return fmt.Errorf("next_offset must equal %d", nextOffset)
		}
	} else if stat.EvidenceNextOffset != nil {
		return fmt.Errorf("terminal page must omit next_offset")
	}
	return nil
}

func liveEvidenceFailureClass(message string) string {
	message = strings.ToLower(message)
	switch {
	case strings.Contains(message, "401"), strings.Contains(message, "expired"), strings.Contains(message, "unauthorized"):
		return "unauthorized_or_expired_token"
	case strings.Contains(message, "403"), strings.Contains(message, "forbidden"):
		return "forbidden"
	case strings.Contains(message, "429"), strings.Contains(message, "rate limit"):
		return "rate_limited"
	default:
		return "api_tool_error"
	}
}
