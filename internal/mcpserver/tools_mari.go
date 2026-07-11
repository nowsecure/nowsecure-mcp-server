package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nsmcp/internal/nsclient"
)

func (s *srv) registerMARITools(server *mcp.Server) {
	addTool(s, server, &mcp.Tool{
		Name: "list_mari_apps",
		Description: "List third-party apps in your NowSecure MARI (Mobile App Risk Intelligence) catalog with their risk score, letter rating (A-F), and risk category (LOW/MEDIUM/HIGH). " +
			"The starting point for third-party / supply-chain app vetting. risk_score (0-100, HIGHER is worse — the opposite polarity of Platform scores) is bucketed upstream into risk_rating (A-F) and risk_category (LOW/MEDIUM/HIGH); the thresholds are upstream-defined and the axes don't align intuitively (category LOW reaches C-rated scores ~50), so filter on the axis your policy uses. " +
			"Sorted riskiest-first by default. Offset-paginated: use page_number (1-based) and page_size. Filter by platform, rating, risk_category, or search. " +
			"Correlate an app with the Platform portfolio by matching (package, platform). " +
			"Default text block is a compact table (one row per app; '# ' comment lines carry total and the page envelope); pass format:\"json\" to mirror the full JSON in the text block. structuredContent always carries the canonical JSON.",
		Annotations: readOnlyAPI(),
	}, s.listMARIApps)

	addTool(s, server, &mcp.Tool{
		Name: "get_mari_assessment",
		Description: "Get the risk profile for one third-party app by its MARI assessment ref. The default response is a compact risk card: title/package/platform identity, overall risk score/rating/category, NowSecure risk, per-category risk scores and impact breakdown, and summary.counts of affected findings by severity — " +
			"finding rows themselves are omitted (findings_omitted reports how many; upstream reports only findings the app is affected by, the summary counts both affected and checked). " +
			"risk_score is 0-100 where HIGHER is worse. Two score families: risk_* reflects any org-specific score override; nowsecure_risk_* is NowSecure's unmodified computed risk — identical unless your org overrode the score. " +
			"Pull finding rows with min_severity (info returns every row, most severe first) or limit (top-N most severe); rows carry check_id, title, categories, severity, and cvss_score or rating. " +
			"check_ids=[...] is the per-finding deep-dive: full short_description, description, business_impact, and regulations (GDPR/HIPAA/PCI/OWASP/CWE/... mappings with links). include_descriptions=true adds short_description to every returned row. " +
			"Use expand to opt into heavier sections (permissions, trackingDomains, networkConnections, librariesAndSdks, aiUsage, iosMetadata, appInfo) for a deeper due-diligence report; expanded librariesAndSdks is shaped down to its summary plus CVE-bearing components only.",
		Annotations: readOnlyAPI(),
	}, s.getMARIAssessment)
}

type listMARIInput struct {
	Platform     string   `json:"platform,omitempty" jsonschema:"filter by platform: android or ios"`
	Rating       []string `json:"rating,omitempty" jsonschema:"filter by risk rating letters: A, B, C, D, F"`
	RiskCategory []string `json:"risk_category,omitempty" jsonschema:"filter by risk category: LOW, MEDIUM, HIGH"`
	Search       string   `json:"search,omitempty" jsonschema:"filter by app title/package search text"`
	AppTitle     []string `json:"app_title,omitempty" jsonschema:"filter to specific app titles"`
	Since        string   `json:"since,omitempty" jsonschema:"only apps ADDED to the catalog on/after this date (YYYY-MM-DD or RFC3339); does not filter updated_at"`
	Until        string   `json:"until,omitempty" jsonschema:"only apps ADDED to the catalog on/before this date (YYYY-MM-DD or RFC3339); does not filter updated_at"`
	OrderBy      string   `json:"order_by,omitempty" jsonschema:"sort order: title, updated_at, risk_score, created_at (prefix with - for descending; default -risk_score, riskiest first)"`
	PageSize     int      `json:"page_size,omitempty" jsonschema:"max apps per page (upstream cap 100)"`
	PageNumber   *int     `json:"page_number,omitempty" jsonschema:"1-based page number (offset pagination; must be >= 1)"`
	Format       string   `json:"format,omitempty" jsonschema:"text-content format: table (default, compact tab-separated grid) or json (text block mirrors the full structuredContent JSON); structuredContent always carries the canonical JSON"`
}

type getMARIInput struct {
	AssessmentRef string   `json:"assessment_ref" jsonschema:"MARI assessment ref (from list_mari_apps assessment_ref)"`
	MinSeverity   string   `json:"min_severity,omitempty" jsonschema:"return finding rows at this severity or higher: info, warn, low, medium, high, critical (info returns every row; default returns none — summary.counts still covers them)"`
	Limit         int      `json:"limit,omitempty" jsonschema:"max finding rows to return, most severe kept (summary.counts still covers the full report)"`
	CheckIDs      []string `json:"check_ids,omitempty" jsonschema:"only return these findings (check_id values), each with its full prose: short_description, description, business_impact, regulations — the on-demand deep-dive"`
	IncludeDescs  bool     `json:"include_descriptions,omitempty" jsonschema:"include short_description on every returned finding row; on its own returns every row (default false; prefer check_ids for specific findings)"`
	Expand        []string `json:"expand,omitempty" jsonschema:"optional heavier sections to include: appInfo, aiUsage, iosMetadata, librariesAndSdks (shaped/compact: summary + CVE-bearing components only), networkConnections, permissions, trackingDomains"`
}

func (s *srv) listMARIApps(ctx context.Context, _ *mcp.CallToolRequest, in listMARIInput) (*mcp.CallToolResult, *nsclient.MARIAppPage, error) {
	format, err := resolveFormat(in.Format)
	if err != nil {
		return nil, nil, err
	}
	c, err := s.api(ctx)
	if err != nil {
		return nil, nil, err
	}
	// *int distinguishes an explicit page_number from unset; upstream silently
	// clamps <1 to page 1, so reject it rather than lie about the page.
	pageNumber := 0
	if in.PageNumber != nil {
		if *in.PageNumber < 1 {
			return nil, nil, fmt.Errorf("page_number is 1-based (must be >= 1)")
		}
		pageNumber = *in.PageNumber
	}
	out, err := c.ListMARIApps(ctx, nsclient.ListMARIAppsParams{
		Platform:     in.Platform,
		Rating:       in.Rating,
		RiskCategory: in.RiskCategory,
		Search:       in.Search,
		AppTitle:     in.AppTitle,
		Since:        in.Since,
		Until:        in.Until,
		OrderBy:      in.OrderBy,
		PageSize:     in.PageSize,
		PageNumber:   pageNumber,
	})
	if err != nil {
		return nil, nil, err
	}
	if format == formatJSON {
		return nil, out, nil
	}
	return tableResult(mariAppsTable(out)), out, nil
}

func (s *srv) getMARIAssessment(ctx context.Context, _ *mcp.CallToolRequest, in getMARIInput) (*mcp.CallToolResult, *nsclient.MARIAssessment, error) {
	c, err := s.api(ctx)
	if err != nil {
		return nil, nil, err
	}
	// Same progressive-disclosure contract as get_assessment_findings, one
	// notch further: the default is a risk card with no rows at all; row and
	// prose selection live in the client (nsclient.MARIAssessmentParams).
	out, err := c.GetMARIAssessment(ctx, nsclient.MARIAssessmentParams{
		AssessmentRef:       in.AssessmentRef,
		Expand:              in.Expand,
		MinSeverity:         in.MinSeverity,
		Limit:               in.Limit,
		CheckIDs:            in.CheckIDs,
		IncludeDescriptions: in.IncludeDescs,
	})
	if err != nil {
		return nil, nil, err
	}
	return nil, out, nil
}
