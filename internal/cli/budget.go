package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

// budgetCase is one measured tool call in the budget suite. Budget caps the
// result's total bytes (text content + structuredContent).
type budgetCase struct {
	Name   string         `json:"name"`
	Tool   string         `json:"tool"`
	Args   map[string]any `json:"args"`
	Budget int            `json:"budget_bytes"`
}

// budgetRow is one case's measured outcome.
type budgetRow struct {
	Case            string `json:"case"`
	Tool            string `json:"tool"`
	TextBytes       int    `json:"text_bytes"`
	StructuredBytes int    `json:"structured_bytes"`
	TotalBytes      int    `json:"total_bytes"`
	EstTokens       int    `json:"est_tokens" jsonschema:"total_bytes/4 heuristic"`
	BudgetBytes     int    `json:"budget_bytes"`
	Status          string `json:"status"` // ok | over | error | skip
	Note            string `json:"note,omitempty"`
}

// defaultBudgets are the built-in per-case byte ceilings, calibrated against
// the reference tenant on 2026-07-11 at roughly 2x the measured size (see
// .local/docs/MARI_PROGRESSIVE_DISCLOSURE_2026-07-11.md for the method).
// They guard against order-of-magnitude bloat from tool-default changes, not
// exact sizes — tenant data drifts. Override per case with --budgets.
var defaultBudgets = map[string]int{
	"list_apps.default":                        10_000,
	"list_assessments.default":                 16_000,
	"get_assessment_findings.default":          40_000,
	"get_assessment_findings.min_severity_low": 16_000,
	"get_assessment_findings.recommendations":  175_000,
	"get_finding.default":                      8_000,
	"search_findings.default":                  8_000,
	"get_apps_affected_by_finding.default":     8_000,
	"list_mari_apps.default":                   12_000,
	"get_mari_assessment.default":              3_000,
	"get_mari_assessment.all_rows":             40_000,
	"get_mari_assessment.descriptions":         110_000,
	"get_mari_assessment.expand_libraries":     10_000,
}

// newProfileBudgetCmd is the CI guard: it runs a fixed suite of tool calls —
// every tool's default plus the known-heavy option paths — through the
// in-process MCP session, measures each result's size, and fails when a case
// exceeds its byte budget. Refs (an app, a finding, a MARI assessment) are
// discovered from the tenant, so the suite needs only a token.
func newProfileBudgetCmd(opts *rootOptions) *cobra.Command {
	var (
		budgetsFile string
		asJSON      bool
		listOnly    bool
	)
	cmd := &cobra.Command{
		Use:   "budget",
		Short: "Measure tool response sizes against byte budgets (CI guard)",
		Long: `Run every MCP tool (defaults plus the known-heavy option paths) through an
in-process MCP session and measure what an agent would receive: text-block
bytes, structuredContent bytes, and their total. Each case has a byte budget;
any case over budget (or erroring) fails the command with a non-zero exit, so
CI catches changes that bloat tool output before agents pay for them.

Budgets are built in (calibrated ~2x against the reference tenant) and guard
order-of-magnitude regressions, not exact sizes — tenant data drifts. Override
any case with a --budgets JSON file of {"case_name": max_total_bytes}.
Refs the suite needs (an app, a finding key, a MARI assessment) are
discovered from the tenant at the start of the run; cases whose ref cannot be
discovered are reported as skipped, not failed.`,
		Example: `  # run the suite (CI: non-zero exit on breach)
  nsmcp profile budget

  # machine-readable report
  nsmcp profile budget --json

  # tighten one case
  echo '{"get_mari_assessment.default": 2000}' > budgets.json
  nsmcp profile budget --budgets budgets.json`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			budgets, err := mergedBudgets(budgetsFile)
			if err != nil {
				return err
			}
			if listOnly {
				return printJSON(cmd, budgetSuite(discoveredRefs{
					AppRef: "<app_ref>", FindingKey: "<finding>", MARIAssessmentRef: "<mari_assessment_ref>",
				}, budgets))
			}
			ctx := cmd.Context()
			cs, err := newToolSession(ctx, opts, false)
			if err != nil {
				return err
			}
			defer func() { _ = cs.Close() }()

			refs := discoverRefs(ctx, cs)
			rows := make([]budgetRow, 0, len(defaultBudgets))
			over := 0
			for _, c := range budgetSuite(refs, budgets) {
				row := runBudgetCase(ctx, cs, c)
				if row.Status == "over" || row.Status == "error" {
					over++
				}
				rows = append(rows, row)
			}

			if asJSON {
				if err := printJSON(cmd, rows); err != nil {
					return err
				}
			} else {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 2, 4, 2, ' ', 0)
				fmt.Fprintln(w, "CASE\tTEXT\tSTRUCTURED\tTOTAL\t~TOKENS\tBUDGET\tSTATUS")
				for _, r := range rows {
					fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%s%s\n",
						r.Case, r.TextBytes, r.StructuredBytes, r.TotalBytes, r.EstTokens, r.BudgetBytes, r.Status, noteSuffix(r.Note))
				}
				if err := w.Flush(); err != nil {
					return err
				}
			}
			if over > 0 {
				return fmt.Errorf("%d case(s) over budget or failed", over)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&budgetsFile, "budgets", "", "JSON file of per-case budget overrides: {\"case_name\": max_total_bytes}")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the report as JSON")
	cmd.Flags().BoolVar(&listOnly, "list", false, "print the suite (cases, args, budgets) without calling anything")
	return cmd
}

// discoveredRefs are the tenant-specific ids the suite's get/list-by-ref
// cases need. Empty fields skip their dependent cases.
type discoveredRefs struct {
	AppRef            string
	FindingKey        string
	MARIAssessmentRef string
}

// discoverRefs pulls one app, one finding key, and one MARI assessment ref
// from the tenant. Failures leave fields empty — the dependent cases report
// as skipped so a Platform-only or MARI-only tenant can still run the suite.
func discoverRefs(ctx context.Context, cs *mcp.ClientSession) discoveredRefs {
	var refs discoveredRefs
	if m := callStructured(ctx, cs, "list_apps", map[string]any{"page_size": 1}); m != nil {
		if apps, _ := m["apps"].([]any); len(apps) > 0 {
			row, _ := apps[0].(map[string]any)
			refs.AppRef, _ = row["app_ref"].(string)
		}
	}
	if m := callStructured(ctx, cs, "search_findings", map[string]any{"query": "ssl", "limit": 1}); m != nil {
		if rows, _ := m["findings"].([]any); len(rows) > 0 {
			row, _ := rows[0].(map[string]any)
			refs.FindingKey, _ = row["key"].(string)
		}
	}
	if m := callStructured(ctx, cs, "list_mari_apps", map[string]any{"page_size": 1}); m != nil {
		if apps, _ := m["apps"].([]any); len(apps) > 0 {
			row, _ := apps[0].(map[string]any)
			refs.MARIAssessmentRef, _ = row["assessment_ref"].(string)
		}
	}
	return refs
}

// callStructured runs a tool call for discovery and returns its structured
// content as a map, or nil on any failure.
func callStructured(ctx context.Context, cs *mcp.ClientSession, tool string, args map[string]any) map[string]any {
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil || res.IsError {
		return nil
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

// budgetSuite is the fixed measurement suite: every tool's default call plus
// the option paths that history showed can explode (recommendation prose,
// MARI descriptions, librariesAndSdks). Cases whose ref was not discovered
// carry empty args values and are skipped by runBudgetCase.
func budgetSuite(refs discoveredRefs, budgets map[string]int) []budgetCase {
	cases := []budgetCase{
		{Name: "list_apps.default", Tool: "list_apps", Args: map[string]any{}},
		{Name: "list_assessments.default", Tool: "list_assessments", Args: map[string]any{"app_ref": refs.AppRef}},
		{Name: "get_assessment_findings.default", Tool: "get_assessment_findings", Args: map[string]any{"app_ref": refs.AppRef}},
		{Name: "get_assessment_findings.min_severity_low", Tool: "get_assessment_findings", Args: map[string]any{"app_ref": refs.AppRef, "min_severity": "low"}},
		{Name: "get_assessment_findings.recommendations", Tool: "get_assessment_findings", Args: map[string]any{"app_ref": refs.AppRef, "include_recommendations": true}},
		{Name: "get_finding.default", Tool: "get_finding", Args: map[string]any{"finding": refs.FindingKey}},
		{Name: "search_findings.default", Tool: "search_findings", Args: map[string]any{"query": "ssl"}},
		{Name: "get_apps_affected_by_finding.default", Tool: "get_apps_affected_by_finding", Args: map[string]any{"finding": refs.FindingKey}},
		{Name: "list_mari_apps.default", Tool: "list_mari_apps", Args: map[string]any{}},
		{Name: "get_mari_assessment.default", Tool: "get_mari_assessment", Args: map[string]any{"assessment_ref": refs.MARIAssessmentRef}},
		{Name: "get_mari_assessment.all_rows", Tool: "get_mari_assessment", Args: map[string]any{"assessment_ref": refs.MARIAssessmentRef, "min_severity": "info"}},
		{Name: "get_mari_assessment.descriptions", Tool: "get_mari_assessment", Args: map[string]any{"assessment_ref": refs.MARIAssessmentRef, "include_descriptions": true}},
		{Name: "get_mari_assessment.expand_libraries", Tool: "get_mari_assessment", Args: map[string]any{"assessment_ref": refs.MARIAssessmentRef, "expand": []any{"librariesAndSdks"}}},
	}
	for i := range cases {
		cases[i].Budget = budgets[cases[i].Name]
	}
	return cases
}

// runBudgetCase executes one case and measures the result. A case whose args
// contain an empty discovered ref is skipped rather than failed.
func runBudgetCase(ctx context.Context, cs *mcp.ClientSession, c budgetCase) budgetRow {
	row := budgetRow{Case: c.Name, Tool: c.Tool, BudgetBytes: c.Budget}
	for k, v := range c.Args {
		if s, ok := v.(string); ok && s == "" {
			row.Status = "skip"
			row.Note = k + " not discovered on this tenant"
			return row
		}
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: c.Tool, Arguments: c.Args})
	if err != nil {
		row.Status = "error"
		row.Note = err.Error()
		return row
	}
	if res.IsError {
		row.Status = "error"
		row.Note = firstSentence(resultText(res))
		return row
	}
	for _, content := range res.Content {
		if t, ok := content.(*mcp.TextContent); ok {
			row.TextBytes += len(t.Text)
		}
	}
	if res.StructuredContent != nil {
		if b, err := json.Marshal(res.StructuredContent); err == nil {
			row.StructuredBytes = len(b)
		}
	}
	row.TotalBytes = row.TextBytes + row.StructuredBytes
	row.EstTokens = row.TotalBytes / 4
	row.Status = "ok"
	if row.TotalBytes > c.Budget {
		row.Status = "over"
	}
	return row
}

// mergedBudgets overlays a --budgets override file onto the defaults,
// rejecting unknown case names so typos fail loudly instead of guarding
// nothing.
func mergedBudgets(path string) (map[string]int, error) {
	budgets := maps.Clone(defaultBudgets)
	if path == "" {
		return budgets, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading budgets file: %w", err)
	}
	var overrides map[string]int
	if err := json.Unmarshal(b, &overrides); err != nil {
		return nil, fmt.Errorf("parsing budgets file: %w", err)
	}
	names := make([]string, 0, len(defaultBudgets))
	for k := range defaultBudgets {
		names = append(names, k)
	}
	sort.Strings(names)
	for k, v := range overrides {
		if _, ok := budgets[k]; !ok {
			return nil, fmt.Errorf("unknown budget case %q (cases: %v)", k, names)
		}
		budgets[k] = v
	}
	return budgets, nil
}

// resultText concatenates a result's text blocks (for error notes).
func resultText(res *mcp.CallToolResult) string {
	var out strings.Builder
	for _, content := range res.Content {
		if t, ok := content.(*mcp.TextContent); ok {
			out.WriteString(t.Text)
		}
	}
	return out.String()
}

func noteSuffix(note string) string {
	if note == "" {
		return ""
	}
	return " (" + note + ")"
}
