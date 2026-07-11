package mcpserver

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nsmcp/internal/nsclient"
)

// Text-content formats for the flat row-listing tools. table is the default
// (compact tab-separated grid); json mirrors the canonical structuredContent
// JSON in the text block. structuredContent carries the full JSON either way.
const (
	formatTable = "table"
	formatJSON  = "json"
)

// resolveFormat defaults an unset format to table and rejects anything but the
// two known values, naming both.
func resolveFormat(f string) (string, error) {
	switch f {
	case "", formatTable:
		return formatTable, nil
	case formatJSON:
		return formatJSON, nil
	default:
		return "", fmt.Errorf("invalid format %q (allowed: table, json)", f)
	}
}

// tableResult wraps a rendered table as a tool result whose own Content the SDK
// keeps, still populating structuredContent from the typed output (go-sdk
// v1.6.1 mcp/server.go:384 sets StructuredContent unconditionally, :389 appends
// a JSON text block only when Content is nil).
func tableResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// table accumulates a header, tab-separated data rows, and trailing "# "
// envelope comment lines.
type table struct {
	cols []string
	rows [][]string
	env  []string
}

func newTable(cols ...string) *table { return &table{cols: cols} }

// row appends one data row, sanitizing each cell so tabs/newlines cannot break
// the grid.
func (t *table) row(cells ...string) {
	r := make([]string, len(cells))
	for i, c := range cells {
		r[i] = sanitizeCell(c)
	}
	t.rows = append(t.rows, r)
}

// comment records one "# " envelope line.
func (t *table) comment(format string, args ...any) {
	t.env = append(t.env, "# "+fmt.Sprintf(format, args...))
}

func (t *table) String() string {
	var b strings.Builder
	b.WriteString(strings.Join(t.cols, "\t"))
	for _, r := range t.rows {
		b.WriteByte('\n')
		b.WriteString(strings.Join(r, "\t"))
	}
	for _, e := range t.env {
		b.WriteByte('\n')
		b.WriteString(e)
	}
	return b.String()
}

// sanitizeCell collapses any run of tab/newline/CR to a single space.
func sanitizeCell(s string) string {
	if !strings.ContainsAny(s, "\t\n\r") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prevWS := false
	for _, r := range s {
		if r == '\t' || r == '\n' || r == '\r' {
			if !prevWS {
				b.WriteByte(' ')
				prevWS = true
			}
			continue
		}
		b.WriteRune(r)
		prevWS = false
	}
	return b.String()
}

func fFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// fFloatOpt renders a float that is absent (omitempty) at its zero value.
func fFloatOpt(f float64) string {
	if f == 0 {
		return ""
	}
	return fFloat(f)
}

// pFloat renders a nullable float; a nil pointer is an absent value.
func pFloat(p *float64) string {
	if p == nil {
		return ""
	}
	return fFloat(*p)
}

// fCounts renders SeverityCounts as "c:N h:N m:N l:N w:N i:N", appending "a:N"
// only when artifacts are present and "p:N" only when pass was computed.
func fCounts(sc nsclient.SeverityCounts) string {
	parts := []string{
		"c:" + strconv.Itoa(sc.Critical),
		"h:" + strconv.Itoa(sc.High),
		"m:" + strconv.Itoa(sc.Medium),
		"l:" + strconv.Itoa(sc.Low),
		"w:" + strconv.Itoa(sc.Warn),
		"i:" + strconv.Itoa(sc.Info),
	}
	if sc.Artifacts != 0 {
		parts = append(parts, "a:"+strconv.Itoa(sc.Artifacts))
	}
	if sc.Pass != nil {
		parts = append(parts, "p:"+strconv.Itoa(*sc.Pass))
	}
	return strings.Join(parts, " ")
}

// ---- per-tool renderers ---------------------------------------------------

func appsTable(p *nsclient.AppPage) string {
	t := newTable("app_ref", "title", "platform", "package", "score", "rating",
		"vulnerability_count", "group", "group_ref", "assessment_ref")
	for _, a := range p.Apps {
		t.row(a.AppRef, a.Title, a.Platform, a.Package, pFloat(a.Score), a.Rating,
			strconv.Itoa(a.VulnerabilityCount), a.Group, a.GroupRef, a.AssessmentRef)
	}
	t.comment("total: %d", p.Total)
	t.comment("has_next_page: %t", p.Page.HasNextPage)
	if p.Page.NextCursor != "" {
		t.comment("next_cursor: %s", p.Page.NextCursor)
	}
	if p.Summary != nil {
		t.comment("summary: portfolio_score=%s portfolio_rating=%s",
			fFloat(p.Summary.PortfolioScore), p.Summary.PortfolioRating)
	}
	return t.String()
}

func assessmentsTable(p *nsclient.AssessmentPage) string {
	t := newTable("assessment_ref", "created_at", "status", "track", "findings_available",
		"score", "rating", "type", "origin", "platform", "package", "package_version",
		"build_version", "title", "app_ref", "policy", "findings")
	for _, a := range p.Assessments {
		t.row(a.Ref, a.CreatedAt, a.Status, a.Track, strconv.FormatBool(a.FindingsAvailable),
			fFloat(a.Score), a.Rating, a.Type, a.Origin, a.Platform, a.Package, a.PackageVersion,
			a.BuildVersion, a.Title, a.AppRef, a.Policy, fCounts(a.Findings))
	}
	t.comment("has_next_page: %t", p.Page.HasNextPage)
	if p.Page.NextCursor != "" {
		t.comment("next_cursor: %s", p.Page.NextCursor)
	}
	return t.String()
}

func findingsTable(p *nsclient.AssessmentFindings) string {
	t := newTable("check_id", "severity", "cvss", "category", "analysis_type", "affected", "title")
	for _, f := range p.Findings {
		t.row(f.CheckID, f.Severity, fFloatOpt(f.CVSS), f.Category, f.AnalysisType,
			strconv.FormatBool(f.Affected), f.Title)
	}
	t.comment("assessment_ref: %s", p.AssessmentRef)
	t.comment("total_returned: %d total_findings: %d", p.TotalReturned, p.TotalFindings)
	t.comment("counts: %s", fCounts(p.Counts))
	if p.Report != "" {
		t.comment("report: %s", p.Report)
	}
	if p.Status != "" {
		t.comment("status: %s", p.Status)
	}
	if p.CreatedAt != "" {
		t.comment("created_at: %s", p.CreatedAt)
	}
	return t.String()
}

func findingSearchTable(p *nsclient.FindingSearchResult) string {
	t := newTable("key", "title", "platform", "severity", "category",
		"matched_in", "deprecated", "covered_by", "snippet")
	for _, m := range p.Findings {
		dep := ""
		if m.Deprecated {
			dep = "true"
		}
		cover := make([]string, 0, len(m.CoveredBy))
		for _, c := range m.CoveredBy {
			cover = append(cover, c.ID)
		}
		t.row(m.Key, m.Title, m.Platform, m.Severity, m.Category,
			strings.Join(m.MatchedIn, ","), dep, strings.Join(cover, ","), m.Snippet)
	}
	t.comment("query: %s", p.Query)
	t.comment("total: %d total_returned: %d", p.Total, p.TotalReturned)
	if p.ExcludedDeprecated > 0 {
		t.comment("excluded_deprecated: %d (pass include_deprecated=true to see them)", p.ExcludedDeprecated)
	}
	return t.String()
}

func affectedTable(p *nsclient.AffectedAppPage) string {
	t := newTable("app_ref", "title", "platform", "package", "package_version",
		"build_version", "group", "created_at", "assessment_ref")
	for _, a := range p.Apps {
		t.row(a.AppRef, a.Title, a.Platform, a.Package, a.PackageVersion,
			a.BuildVersion, a.Group, a.CreatedAt, a.AssessmentRef)
	}
	t.comment("finding: %s", p.Finding)
	t.comment("total: %d", p.Total)
	t.comment("has_next_page: %t", p.Page.HasNextPage)
	if p.Page.NextCursor != "" {
		t.comment("next_cursor: %s", p.Page.NextCursor)
	}
	return t.String()
}

func mariAppsTable(p *nsclient.MARIAppPage) string {
	t := newTable("assessment_ref", "title", "platform", "package", "risk_score",
		"risk_rating", "risk_category", "build_version", "application_id", "created_at", "updated_at")
	for _, a := range p.Apps {
		t.row(a.AssessmentRef, a.Title, a.Platform, a.Package, fFloat(a.RiskScore),
			a.RiskRating, a.RiskCategory, a.BuildVersion, a.ApplicationID, a.CreatedAt, a.UpdatedAt)
	}
	t.comment("total: %d", p.Total)
	t.comment("has_next_page: %t", p.Page.HasNextPage)
	if p.Page.NextPageNumber != 0 {
		t.comment("next_page_number: %d", p.Page.NextPageNumber)
	}
	return t.String()
}
