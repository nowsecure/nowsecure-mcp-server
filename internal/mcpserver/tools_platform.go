package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nsmcp/internal/nsclient"
)

func (s *srv) registerPlatformTools(server *mcp.Server) {
	addTool(s, server, &mcp.Tool{
		Name: "list_apps",
		Description: "List mobile apps in your NowSecure portfolio with their latest security score, rating, and open vulnerability count. " +
			"The primary starting point for DevSecOps triage. Returns a compact row per app (title, platform, package, score, rating, vulnerability_count, app_ref, assessment_ref, group, group_ref — rows are the group-discovery source for group_refs params). " +
			"score is 0-100 where HIGHER is better (the opposite polarity of MARI risk scores); correlate an app with the MARI catalog by matching (package, platform). " +
			"search is the front door for the MARI↔Platform (package, platform) join, and one package can match multiple portfolio apps (one per group) — all are returned. " +
			"The portfolio covers only the last 12 months: an app is listed if and only if it has a completed scan in that window — apps whose newest scan is older, and apps never scanned, are absent entirely, so absence here does not mean the app is unknown (list_assessments is not windowed and still serves their history by app_ref or package). " +
			"Cursor-paginated: pass the returned next_cursor to fetch the next page. Use threshold_score/threshold_severity to focus on the riskiest apps. " +
			"Default text block is a compact table (one row per app; '# ' comment lines carry the total match count, the page envelope, and — with include_summary — the portfolio summary); pass format:\"json\" to mirror the full JSON in the text block. structuredContent always carries the canonical JSON.",
		Annotations: readOnlyAPI(),
	}, s.listApps)

	addTool(s, server, &mcp.Tool{
		Name: "list_assessments",
		Description: "List the scan history of an app, newest first, with score, rating, status, and finding counts by severity. " +
			"Requires app_ref, package, or appstore_key — the API rejects portfolio-wide queries, so to survey many apps call list_apps first and query per app. " +
			"Note: package/appstore_key scoping merges the history of EVERY app sharing that id across groups; use app_ref for one app's history. " +
			"Rows with track=store_monitor come from store monitoring, not lab analysis: their finding counts use a different upstream source than get_assessment_findings (which cannot serve them — check findings_available). " +
			"Further filter by platform/status/rating/type/date. Cursor-paginated: pages default to the 10 newest scans and page_size caps at 25 (larger values are clamped) — follow next_cursor for older history. " +
			"Unlike the portfolio tools (list_apps, get_apps_affected_by_finding), history is NOT limited to the last 12 months: this tool still sees apps that have aged out of the portfolio. " +
			"Default text block is a compact table (one row per assessment; the findings column packs severity counts as c/h/m/l/w/i[/p]; '# ' comment lines carry the page envelope); pass format:\"json\" to mirror the full JSON in the text block. structuredContent always carries the canonical JSON.",
		Annotations: readOnlyAPI(),
	}, s.listAssessments)

	addTool(s, server, &mcp.Tool{
		Name: "get_assessment_findings",
		Description: "Get the findings for one assessment as a compact, triage-ready list (check_id, title, category, severity, affected, cvss), sorted most-severe first. " +
			"Evidence, raw context, and recommendation prose are deliberately stripped to keep the response small — for remediation, call get_finding with a check_id, " +
			"or re-query with check_ids=[...] for full recommendations on specific findings, or include_recommendations=true for truncated ones on every row. " +
			"Takes app_ref (returned by list_apps/list_assessments); assessment_ref is optional — when omitted, the assessment the app's portfolio row points at is used (its latest known scan, which can lag a just-finished one) — " +
			"check the returned status/created_at, and pass an explicit ref from a list_assessments row with findings_available=true to pin a scan. " +
			"The app must still be in the portfolio's 12-month window (a completed scan in the last 12 months): an app_ref that has aged out fails with 'not found in portfolio' even though list_assessments still lists its history. " +
			"The response echoes the applied report profile. Defaults to affected findings only; use affected_only=false, min_severity, or limit to adjust the size. " +
			"The default omits artifact-category inventory rows (counts still show them as counts.artifacts; include_artifacts=true restores them); min_severity=low returns exactly the scored vulnerabilities behind vulnerability_count. " +
			"Default text block is a compact table (one row per finding; '# ' comment lines carry counts and the report/status/created_at envelope), forced to json when check_ids or include_recommendations pulls in recommendation prose; pass format:\"json\" to mirror the full JSON in the text block otherwise. structuredContent always carries the canonical JSON.",
		Annotations: readOnlyAPI(),
	}, s.getAssessmentFindings)

	addTool(s, server, &mcp.Tool{
		Name: "get_finding",
		Description: "Get documentation for a single finding by key or id: title, category, severity/CVSS range, description, steps to reproduce, testing method, and markdown remediation guidance. " +
			"Static reference data (no per-app evidence). Use include=[...] to fetch only specific prose sections (e.g. just remediation). " +
			"Two taxonomies: category is the lab analysis category (lowercase; matches get_assessment_findings rows), categories are capability groups (Title Case). " +
			"platform is omitted for findings that apply to both android and ios; application_count equals get_apps_affected_by_finding's total and shares its 12-month portfolio window (apps last scanned earlier are not counted). " +
			"Use after list_apps/get_assessment_findings to understand or remediate a specific finding.",
		Annotations: readOnlyAPI(),
	}, s.getFinding)

	addTool(s, server, &mcp.Tool{
		Name: "search_findings",
		Description: "Search the finding catalog by free text: case-insensitive substring match over finding key, title, description/impact prose, and category. " +
			"The front door when you know a topic or risk but not a finding's key — e.g. every finding related to \"cleartext\", \"keyboard cache\", or \"janus\". " +
			"Static reference data (portfolio-independent): rows say nothing about whether YOUR apps are affected — feed key into get_finding (docs/remediation), get_apps_affected_by_finding (fleet impact), or get_assessment_findings check_ids (that finding in a specific scan). " +
			"Returns compact rows (key, title, platform, severity, category, matched_in) with key/title matches sorted first; a match visible only in prose carries a snippet of the surrounding text. " +
			"platform omitted on a row means the finding applies to both android and ios. " +
			"Deprecated checks are excluded by default (excluded_deprecated counts matches that were hidden; include_deprecated=true restores them, each row's covered_by naming its replacements). " +
			"Default text block is a compact table (one row per match; '# ' comment lines carry the query and totals); pass format:\"json\" to mirror the full JSON in the text block. structuredContent always carries the canonical JSON.",
		Annotations: readOnlyAPI(),
	}, s.searchFindings)

	addTool(s, server, &mcp.Tool{
		Name: "get_apps_affected_by_finding",
		Description: "Fleet-wide impact: list portfolio apps whose latest assessment is affected by a given finding (key or id). " +
			"Answers 'which of my apps are exposed to X?'. Coverage is the portfolio's 12-month window: only apps with a completed scan in the last 12 months are listed or counted in total — an app last scanned earlier is absent even if that scan was affected. " +
			"Cursor-paginated; filter by platform, group, or search text. " +
			"Rows carry no score/rating (join app_ref to list_apps to prioritize); created_at is the latest assessment date (what order_by=created_at sorts by). " +
			"A platform filter is orthogonal to the finding's own platform (e.g. an android-only finding with platform=ios) and legitimately returns an empty list with total:0. " +
			"Default text block is a compact table (one row per app; '# ' comment lines carry finding/total and the page envelope); pass format:\"json\" to mirror the full JSON in the text block. structuredContent always carries the canonical JSON.",
		Annotations: readOnlyAPI(),
	}, s.getAppsAffectedByFinding)
}

// ---- inputs ---------------------------------------------------------------

type listAppsInput struct {
	ThresholdScore    *float64 `json:"threshold_score,omitempty" jsonschema:"only list apps with this NowSecure score (0-100) or lower"`
	ThresholdSeverity string   `json:"threshold_severity,omitempty" jsonschema:"only list apps with a finding at this severity or higher: critical, high, medium, or low (finding severity, not the app rating — many apps rate \"critical\" without any critical-severity finding)"`
	ApplicationRefs   []string `json:"app_refs,omitempty" jsonschema:"limit to these app_ref UUIDs (from list_apps rows)"`
	GroupRefs         []string `json:"group_refs,omitempty" jsonschema:"limit to these group UUIDs"`
	Search            string   `json:"search,omitempty" jsonschema:"case-insensitive substring match on title or package, applied by nsmcp (the upstream API has no text filter); scans up to 20 upstream pages per call — repeat with next_cursor to continue"`
	OrderBy           string   `json:"order_by,omitempty" jsonschema:"sort order: score, -score, created_at, -created_at, vulnerability_count, or -vulnerability_count; score ascending = riskiest first (score is higher-is-better, and the default); -score lists the best apps first"`
	PageSize          int      `json:"page_size,omitempty" jsonschema:"max apps to return in this page (upstream cap 50)"`
	Cursor            string   `json:"cursor,omitempty" jsonschema:"pagination cursor from a previous page's next_cursor"`
	IncludeSummary    bool     `json:"include_summary,omitempty" jsonschema:"include a portfolio-level score/rating summary"`
	Format            string   `json:"format,omitempty" jsonschema:"text-content format: table (default, compact tab-separated grid) or json (text block mirrors the full structuredContent JSON); structuredContent always carries the canonical JSON"`
}

type listAssessmentsInput struct {
	AppRef      string   `json:"app_ref,omitempty" jsonschema:"application UUID (from list_apps app_ref). Provide this OR package OR appstore_key — at least one is required"`
	Package     string   `json:"package,omitempty" jsonschema:"android package or iOS bundle id to scope to (alternative to app_ref; merges all apps sharing the id)"`
	AppstoreKey string   `json:"appstore_key,omitempty" jsonschema:"app store application key to scope to (alternative to app_ref)"`
	GroupRefs   []string `json:"group_refs,omitempty" jsonschema:"limit to these group UUIDs"`
	Platforms   []string `json:"platforms,omitempty" jsonschema:"filter by platform types: android, ios"`
	Status      []string `json:"status,omitempty" jsonschema:"filter by status: completed, failed, processing, pending, cancelled, partial, incomplete"` //nolint:misspell // "cancelled" is the upstream API's actual wire value
	Rating      []string `json:"rating,omitempty" jsonschema:"filter by rating: critical, poor, fair, good, excellent"`
	Type        []string `json:"type,omitempty" jsonschema:"filter by assessment type: advanced, baseline, guided, pen_test, workstation"`
	Since       string   `json:"since,omitempty" jsonschema:"only assessments created on/after this date (YYYY-MM-DD or RFC3339)"`
	Until       string   `json:"until,omitempty" jsonschema:"only assessments created on/before this date (YYYY-MM-DD or RFC3339)"`
	OrderBy     string   `json:"order_by,omitempty" jsonschema:"sort order: created_at, -created_at, build_version, package_version (default -created_at)"`
	PageSize    int      `json:"page_size,omitempty" jsonschema:"max assessments to return in this page (default 10, max 25 — larger values are clamped; page with cursor for older history)"`
	Cursor      string   `json:"cursor,omitempty" jsonschema:"pagination cursor from a previous page's next_cursor"`
	Format      string   `json:"format,omitempty" jsonschema:"text-content format: table (default, compact tab-separated grid) or json (text block mirrors the full structuredContent JSON); structuredContent always carries the canonical JSON"`
}

type getFindingsInput struct {
	AppRef           string   `json:"app_ref" jsonschema:"application UUID (the app_ref from list_apps or list_assessments); the app must still be in the portfolio's 12-month window — refs for apps last scanned over 12 months ago fail with 'not found in portfolio'"`
	AssessmentRef    string   `json:"assessment_ref,omitempty" jsonschema:"assessment UUID, or a numeric task id as extracted from a console URL by decode_nowsecure_url; omit to use the app's latest assessment"`
	AffectedOnly     *bool    `json:"affected_only,omitempty" jsonschema:"only return findings the app is affected by (default true)"`
	MinSeverity      string   `json:"min_severity,omitempty" jsonschema:"only return findings at this severity or higher: info, warn, low, medium, high, critical"`
	Report           string   `json:"report,omitempty" jsonschema:"report profile: lab-auto (default), intel, or niap; profiles frequently share the same finding set — the response echoes the applied profile"`
	Limit            int      `json:"limit,omitempty" jsonschema:"max findings to return (most severe kept; counts still cover the full report)"`
	CheckIDs         []string `json:"check_ids,omitempty" jsonschema:"only return these findings (check_id values), each with its FULL untruncated developer recommendation — the on-demand deep-dive"`
	IncludeRecs      bool     `json:"include_recommendations,omitempty" jsonschema:"include a truncated developer recommendation on every row (default false; prefer get_finding or check_ids for full remediation)"`
	IncludeArtifacts bool     `json:"include_artifacts,omitempty" jsonschema:"include category=artifact inventory rows (extracted files, IP addresses, ...) in the findings array; default false keeps only scored findings (counts.artifacts still reports them)"`
	Format           string   `json:"format,omitempty" jsonschema:"text-content format: table (default, compact tab-separated grid) or json (text block mirrors the full structuredContent JSON); structuredContent always carries the canonical JSON. Forced to json when check_ids or include_recommendations is set (multiline recommendation prose does not tabulate)"`
}

type getFindingInput struct {
	Finding string   `json:"finding" jsonschema:"finding key, e.g. android_janus_vuln"`
	Include []string `json:"include,omitempty" jsonschema:"prose sections to return: description, steps_to_reproduce, testing_method, remediation — omit for all; scalar metadata is always included"`
}

type searchFindingsInput struct {
	Query             string `json:"query" jsonschema:"free text to substring-match (case-insensitive) against finding key, title, description/impact prose, and category; spaces also match key underscores (so \"janus vuln\" hits android_janus_vuln)"`
	Platform          string `json:"platform,omitempty" jsonschema:"filter by platform: android or ios (findings that apply to both platforms always pass)"`
	IncludeDeprecated bool   `json:"include_deprecated,omitempty" jsonschema:"include deprecated checks (default false; excluded_deprecated reports how many matches were hidden, and each deprecated row's covered_by names its replacements)"`
	Limit             int    `json:"limit,omitempty" jsonschema:"max matches to return (default 25; total always reports the full match count)"`
	Format            string `json:"format,omitempty" jsonschema:"text-content format: table (default, compact tab-separated grid) or json (text block mirrors the full structuredContent JSON); structuredContent always carries the canonical JSON"`
}

type affectedInput struct {
	Finding   string   `json:"finding" jsonschema:"finding key, e.g. android_janus_vuln"`
	Platform  string   `json:"platform,omitempty" jsonschema:"filter by platform: android or ios"`
	Search    string   `json:"search,omitempty" jsonschema:"filter by app title/package search text"`
	GroupRefs []string `json:"group_refs,omitempty" jsonschema:"limit to these group UUIDs"`
	OrderBy   string   `json:"order_by,omitempty" jsonschema:"sort order: title, -title, package, -package, platform, -platform, created_at, -created_at (default -created_at: newest assessment first)"`
	PageSize  int      `json:"page_size,omitempty" jsonschema:"max apps to return in this page (upstream cap 50)"`
	Cursor    string   `json:"cursor,omitempty" jsonschema:"pagination cursor from a previous page's next_cursor"`
	Format    string   `json:"format,omitempty" jsonschema:"text-content format: table (default, compact tab-separated grid) or json (text block mirrors the full structuredContent JSON); structuredContent always carries the canonical JSON"`
}

// ---- handlers -------------------------------------------------------------

func (s *srv) listApps(ctx context.Context, _ *mcp.CallToolRequest, in listAppsInput) (*mcp.CallToolResult, *nsclient.AppPage, error) {
	format, err := resolveFormat(in.Format)
	if err != nil {
		return nil, nil, err
	}
	c, err := s.api(ctx)
	if err != nil {
		return nil, nil, err
	}
	out, err := c.ListApps(ctx, nsclient.ListAppsParams{
		ThresholdScore:    in.ThresholdScore,
		ThresholdSeverity: in.ThresholdSeverity,
		ApplicationRefs:   in.ApplicationRefs,
		GroupRefs:         in.GroupRefs,
		Search:            in.Search,
		OrderBy:           in.OrderBy,
		PageSize:          in.PageSize,
		Cursor:            in.Cursor,
		IncludeSummary:    in.IncludeSummary,
	})
	if err != nil {
		return nil, nil, err
	}
	if format == formatJSON {
		return nil, out, nil
	}
	return tableResult(appsTable(out)), out, nil
}

func (s *srv) listAssessments(ctx context.Context, _ *mcp.CallToolRequest, in listAssessmentsInput) (*mcp.CallToolResult, *nsclient.AssessmentPage, error) {
	format, err := resolveFormat(in.Format)
	if err != nil {
		return nil, nil, err
	}
	c, err := s.api(ctx)
	if err != nil {
		return nil, nil, err
	}
	out, err := c.ListAssessments(ctx, nsclient.ListAssessmentsParams{
		ApplicationRef: in.AppRef,
		PackageKey:     in.Package,
		AppstoreKey:    in.AppstoreKey,
		GroupRefs:      in.GroupRefs,
		PlatformTypes:  in.Platforms,
		Status:         in.Status,
		Rating:         in.Rating,
		Type:           in.Type,
		Since:          in.Since,
		Until:          in.Until,
		OrderBy:        in.OrderBy,
		PageSize:       in.PageSize,
		Cursor:         in.Cursor,
	})
	if err != nil {
		return nil, nil, err
	}
	if format == formatJSON {
		return nil, out, nil
	}
	return tableResult(assessmentsTable(out)), out, nil
}

func (s *srv) getAssessmentFindings(ctx context.Context, _ *mcp.CallToolRequest, in getFindingsInput) (*mcp.CallToolResult, *nsclient.AssessmentFindings, error) {
	format, err := resolveFormat(in.Format)
	if err != nil {
		return nil, nil, err
	}
	// Recommendation prose (check_ids / include_recommendations) is multiline
	// markdown that does not tabulate; force the JSON text block.
	if len(in.CheckIDs) > 0 || in.IncludeRecs {
		format = formatJSON
	}
	affectedOnly := true
	if in.AffectedOnly != nil {
		affectedOnly = *in.AffectedOnly
	}
	c, err := s.api(ctx)
	if err != nil {
		return nil, nil, err
	}
	out, err := c.GetAssessmentFindings(ctx, nsclient.FindingsParams{
		AppRef:           in.AppRef,
		AssessmentRef:    in.AssessmentRef,
		AffectedOnly:     affectedOnly,
		MinSeverity:      in.MinSeverity,
		Report:           in.Report,
		Limit:            in.Limit,
		CheckIDs:         in.CheckIDs,
		IncludeRecs:      in.IncludeRecs,
		IncludeArtifacts: in.IncludeArtifacts,
	})
	if err != nil {
		return nil, nil, err
	}
	if format == formatJSON {
		return nil, out, nil
	}
	return tableResult(findingsTable(out)), out, nil
}

func (s *srv) getFinding(ctx context.Context, _ *mcp.CallToolRequest, in getFindingInput) (*mcp.CallToolResult, *nsclient.FindingDoc, error) {
	c, err := s.api(ctx)
	if err != nil {
		return nil, nil, err
	}
	out, err := c.GetFinding(ctx, in.Finding)
	if err != nil {
		return nil, nil, err
	}
	if len(in.Include) > 0 {
		keep := make(map[string]bool, len(in.Include))
		for _, f := range in.Include {
			f = strings.ToLower(strings.TrimSpace(f))
			switch f {
			case "description", "steps_to_reproduce", "testing_method", "remediation":
				keep[f] = true
			default:
				return nil, nil, fmt.Errorf("invalid include value %q (allowed: description, steps_to_reproduce, testing_method, remediation)", f)
			}
		}
		// The doc is cached and shared; filter a copy.
		cp := *out
		if !keep["description"] {
			cp.Description = ""
		}
		if !keep["steps_to_reproduce"] {
			cp.StepsToReproduce = ""
		}
		if !keep["testing_method"] {
			cp.TestingMethod = ""
		}
		if !keep["remediation"] {
			cp.Remediation = ""
		}
		out = &cp
	}
	return nil, out, nil
}

func (s *srv) searchFindings(ctx context.Context, _ *mcp.CallToolRequest, in searchFindingsInput) (*mcp.CallToolResult, *nsclient.FindingSearchResult, error) {
	format, err := resolveFormat(in.Format)
	if err != nil {
		return nil, nil, err
	}
	c, err := s.api(ctx)
	if err != nil {
		return nil, nil, err
	}
	out, err := c.SearchFindings(ctx, nsclient.SearchFindingsParams{
		Query:             in.Query,
		Platform:          in.Platform,
		IncludeDeprecated: in.IncludeDeprecated,
		Limit:             in.Limit,
	})
	if err != nil {
		return nil, nil, err
	}
	if format == formatJSON {
		return nil, out, nil
	}
	return tableResult(findingSearchTable(out)), out, nil
}

func (s *srv) getAppsAffectedByFinding(ctx context.Context, _ *mcp.CallToolRequest, in affectedInput) (*mcp.CallToolResult, *nsclient.AffectedAppPage, error) {
	format, err := resolveFormat(in.Format)
	if err != nil {
		return nil, nil, err
	}
	c, err := s.api(ctx)
	if err != nil {
		return nil, nil, err
	}
	out, err := c.AppsAffectedByFinding(ctx, in.Finding, nsclient.AffectedByParams{
		Platform:   in.Platform,
		SearchText: in.Search,
		GroupRefs:  in.GroupRefs,
		OrderBy:    in.OrderBy,
		PageSize:   in.PageSize,
		Cursor:     in.Cursor,
	})
	if err != nil {
		return nil, nil, err
	}
	if format == formatJSON {
		return nil, out, nil
	}
	return tableResult(affectedTable(out)), out, nil
}
