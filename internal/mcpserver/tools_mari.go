package mcpserver

import (
	"context"
	"fmt"
	"strings"

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
		Description: "Get the risk profile for one third-party app by its MARI assessment ref: title/package/platform identity (always populated), overall risk score/rating/category, NowSecure risk, findings summary, and a compact list of findings — " +
			"upstream reports only the findings the app is affected by (the summary counts both affected and checked). risk_score is 0-100 where HIGHER is worse. " +
			"Two score families: risk_* reflects any org-specific score override; nowsecure_risk_* is NowSecure's unmodified computed risk — identical unless your org overrode the score. " +
			"Finding rows omit short_description prose by default — pull it back with check_ids=[...] for specific findings or include_descriptions=true for every row. " +
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
	CheckIDs      []string `json:"check_ids,omitempty" jsonschema:"only return these findings (check_id values), each with its full short_description — the on-demand deep-dive"`
	IncludeDescs  bool     `json:"include_descriptions,omitempty" jsonschema:"include short_description on every finding row (default false; prefer check_ids for specific findings)"`
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
	out, err := c.GetMARIAssessment(ctx, in.AssessmentRef, in.Expand)
	if err != nil {
		return nil, nil, err
	}
	// Same progressive-disclosure contract as get_assessment_findings:
	// prose is omitted by default, scoped check_ids get it in full.
	if len(in.CheckIDs) > 0 {
		keep := make(map[string]bool, len(in.CheckIDs))
		for _, id := range in.CheckIDs {
			keep[strings.ToLower(strings.TrimSpace(id))] = true
		}
		rows := make([]nsclient.MARIFinding, 0, len(in.CheckIDs))
		for _, f := range out.Findings {
			if keep[strings.ToLower(f.CheckID)] {
				rows = append(rows, f)
			}
		}
		out.Findings = rows
	} else if !in.IncludeDescs {
		for i := range out.Findings {
			out.Findings[i].ShortDescription = ""
		}
	}
	return nil, out, nil
}
