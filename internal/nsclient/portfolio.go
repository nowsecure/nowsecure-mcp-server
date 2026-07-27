package nsclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// ---- portfolio applications ----------------------------------------------

// ListAppsParams filters and paginates GET /v2/portfolio/applications.
type ListAppsParams struct {
	ThresholdScore    *float64 // list apps with this score or lower
	ThresholdSeverity string   // critical|high|medium|low: min severity present
	ApplicationRefs   []string // limit to these app UUIDs
	GroupRefs         []string // limit to these group UUIDs
	Search            string   // client-side substring match on title/package (no upstream text filter)
	OrderBy           string   // score, created_at, vulnerability_count (+/-); snake aliases translated to camelCase
	PageSize          int
	Cursor            string
	IncludeSummary    bool
}

type rawAppRow struct {
	Ref                string   `json:"ref"`
	AssessmentRef      string   `json:"assessmentRef"`
	Platform           string   `json:"platform"`
	Package            string   `json:"package"`
	Title              string   `json:"title"`
	Score              *float64 `json:"score"`
	Rating             string   `json:"rating"`
	VulnerabilityCount int      `json:"vulnerabilityCount"`
	Group              struct {
		Ref  string `json:"ref"`
		Name string `json:"name"`
	} `json:"group"`
}

func (r rawAppRow) toApp() App {
	return App{
		AppRef:             r.Ref,
		AssessmentRef:      r.AssessmentRef,
		Title:              r.Title,
		Platform:           r.Platform,
		Package:            r.Package,
		Score:              r.Score,
		Rating:             r.Rating,
		VulnerabilityCount: r.VulnerabilityCount,
		Group:              r.Group.Name,
		GroupRef:           r.Group.Ref,
	}
}

type rawAppsResponse struct {
	Rows        []rawAppRow   `json:"rows"`
	PageInfo    rawCursorPage `json:"pageInfo"`
	SummaryInfo *struct {
		PortfolioScore                                   float64 `json:"portfolioScore"`
		PortfolioRating                                  string  `json:"portfolioRating"`
		TotalResults                                     int     `json:"totalResults"`
		TotalResultsBelowThresholdScore                  *int    `json:"totalResultsBelowThresholdScore"`
		TotalResultsWithFindingsAtLeastThresholdSeverity *int    `json:"totalResultsWithFindingsAtLeastThresholdSeverity"`
	} `json:"summaryInfo"`
}

func (raw *rawAppsResponse) summary() *PortfolioSummary {
	if raw.SummaryInfo == nil {
		return nil
	}
	return &PortfolioSummary{
		PortfolioScore:  raw.SummaryInfo.PortfolioScore,
		PortfolioRating: raw.SummaryInfo.PortfolioRating,
	}
}

type rawCursorPage struct {
	HasNextPage bool   `json:"hasNextPage"`
	Cursor      string `json:"cursor"`
}

const (
	// The applications endpoint caps pages at 50 rows. Filtered scans use the
	// largest window so a sparse threshold does not turn into one request per
	// requested result.
	listAppsScanPageSize = 50

	listAppsScanCursorKind = "nsmcp-list-apps-scan-v1"
)

// listAppsScanCursor resumes a filtered walk inside an upstream page. The
// thresholdSeverity filter is evaluated by the applications endpoint after it
// takes the sorted page window, so a filtered request can discard the
// upstream cursor. We therefore walk an unfiltered shadow page for its
// envelope and, when the requested result page fills partway through that
// window, remember how many source rows were already consumed.
//
// Limit preserves the result-page size when a caller follows next_cursor
// without repeating page_size, matching the behavior of native upstream
// cursors.
type listAppsScanCursor struct {
	Kind          string `json:"kind"`
	Cursor        string `json:"cursor,omitempty"`
	Consumed      int    `json:"consumed,omitempty"`
	Limit         int    `json:"limit"`
	MatchedBefore *int   `json:"matched_before,omitempty"`
}

func encodeListAppsScanCursor(cursor string, consumed, limit int, matchedBefore *int) string {
	b, _ := json.Marshal(listAppsScanCursor{
		Kind:          listAppsScanCursorKind,
		Cursor:        cursor,
		Consumed:      consumed,
		Limit:         limit,
		MatchedBefore: matchedBefore,
	})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeListAppsScanCursor(cursor string) (listAppsScanCursor, bool) {
	if cursor == "" {
		return listAppsScanCursor{}, false
	}
	var b []byte
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		decoded, err := enc.DecodeString(cursor)
		if err == nil {
			b = decoded
			break
		}
	}
	if b == nil {
		return listAppsScanCursor{}, false
	}
	var scan listAppsScanCursor
	if err := json.Unmarshal(b, &scan); err != nil || scan.Kind != listAppsScanCursorKind ||
		scan.Consumed < 0 || scan.Consumed > listAppsScanPageSize || scan.Limit < 1 ||
		(scan.MatchedBefore != nil && *scan.MatchedBefore < 0) {
		return listAppsScanCursor{}, false
	}
	return scan, true
}

// listAppsRaw performs one GET against the applications endpoint with an
// explicit page size and cursor, leaving the filter shaping to p. includeSummary
// requests the summaryInfo block (portfolio score/rating and the row total); the
// list path always asks for it (the total is part of the envelope), the single-
// ref lookup never does.
func (c *Client) listAppsRaw(ctx context.Context, p ListAppsParams, pageSize int, cursor string, includeSummary bool) (*rawAppsResponse, error) {
	q := url.Values{}
	f := filters{}
	if p.ThresholdScore != nil {
		f = f.add("thresholdScore", *p.ThresholdScore)
	}
	f = f.add("thresholdSeverity", p.ThresholdSeverity)
	if len(p.ApplicationRefs) > 0 {
		f = f.add("applicationRefs", p.ApplicationRefs)
	}
	if len(p.GroupRefs) > 0 {
		f = f.add("groupRefs", p.GroupRefs)
	}
	f.apply(q)
	// Send upstream's implicit default (score ascending, riskiest first)
	// explicitly so the contract holds if that default ever drifts. Ties keep
	// upstream's unspecified order: the allowlist is single-field only — a
	// compound "orderBy=score,createdAt" 400s when the comma is
	// percent-encoded (it survives a curl with a literal comma only through
	// an accidental array-parse path, which is nothing to build on).
	orderBy := p.OrderBy
	if strings.TrimSpace(orderBy) == "" {
		orderBy = "score"
	}
	setOrderBy(q, orderBy)
	setInt(q, "pageSize", pageSize)
	setStr(q, "cursor", cursor)
	if includeSummary {
		q.Set("includeSummaryInfo", "true")
	}
	var raw rawAppsResponse
	if err := c.getJSON(ctx, "list portfolio applications", "/v2/portfolio/applications", q, &raw); err != nil {
		return nil, err
	}
	return &raw, nil
}

// ListApps lists portfolio applications. Upstream scopes the portfolio to a
// rolling 12-month window: an app is present iff it has a completed assessment
// in the last 12 months — older-scanned and never-scanned apps are absent
// entirely, never score-less (verified 2026-07 against the un-windowed GraphQL
// auto.applications list: 89/394 apps in-window, zero exceptions). The other
// /v2/portfolio endpoints (affected-apps, applicationCount) share the window.
func (c *Client) ListApps(ctx context.Context, p ListAppsParams) (*AppPage, error) {
	if p.PageSize < 0 {
		return nil, fmt.Errorf("page_size must not be negative")
	}
	if err := validateUUIDRefs("app_refs", "application UUIDs (from list_apps app_ref)", p.ApplicationRefs); err != nil {
		return nil, err
	}
	if err := validateUUIDRefs("group_refs", "group UUIDs (from list_apps group_ref)", p.GroupRefs); err != nil {
		return nil, err
	}
	// Upstream answers a bad severity with an anyOf filter-schema dump; the set
	// is stable, so reject it client-side like the list_assessments enums.
	if p.ThresholdSeverity != "" {
		sev, err := validateEnum("threshold_severity", []string{p.ThresholdSeverity}, enumThresholdSeverity)
		if err != nil {
			return nil, err
		}
		p.ThresholdSeverity = sev[0]
	}
	if p.ThresholdScore != nil || p.ThresholdSeverity != "" {
		return c.scanFilteredApps(ctx, p)
	}
	if strings.TrimSpace(p.Search) != "" {
		return c.searchApps(ctx, p)
	}
	if len(p.ApplicationRefs) > 0 || len(p.GroupRefs) > 0 {
		return c.scanFilteredApps(ctx, p)
	}

	pageSize := p.PageSize
	if pageSize == 0 {
		pageSize = pageSizeFromCursor(p.Cursor)
	}
	raw, err := c.listAppsRaw(ctx, p, pageSize, p.Cursor, true)
	if err != nil {
		return nil, err
	}
	out := &AppPage{
		Apps: make([]App, 0, len(raw.Rows)),
		Page: CursorPage{HasNextPage: raw.PageInfo.HasNextPage},
	}
	if raw.SummaryInfo != nil {
		out.Total = raw.SummaryInfo.TotalResults
		if p.IncludeSummary {
			out.Summary = raw.summary()
		}
	}
	if raw.PageInfo.HasNextPage {
		out.Page.NextCursor = raw.PageInfo.Cursor
	}
	for _, r := range raw.Rows {
		out.Apps = append(out.Apps, r.toApp())
	}
	return out, nil
}

// scanFilteredApps works around the applications endpoint's filter/pagination
// order. In particular, thresholdSeverity is applied to only the sorted source
// window and pageInfo is then computed from the surviving rows. A sparse
// filtered window can consequently claim the portfolio is exhausted.
//
// The unfiltered request is the source of truth for ordered rows and its
// cursor envelope. threshold_score is evaluated directly against those rows.
// Severity is not present on an application row (and rating is not an
// equivalent), so a second request applies thresholdSeverity to the identical
// source window and supplies the matching app refs.
func (c *Client) scanFilteredApps(ctx context.Context, p ListAppsParams) (*AppPage, error) {
	pageSize := p.PageSize
	sourceCursor := p.Cursor
	consumed := 0
	matchedCount := 0
	countStartedAtPortfolioBeginning := p.Cursor == ""
	if scan, ok := decodeListAppsScanCursor(p.Cursor); ok {
		sourceCursor = scan.Cursor
		consumed = scan.Consumed
		if scan.MatchedBefore != nil {
			matchedCount = *scan.MatchedBefore
			countStartedAtPortfolioBeginning = true
		}
		if pageSize == 0 {
			pageSize = scan.Limit
		}
	} else if pageSize == 0 {
		pageSize = pageSizeFromCursor(p.Cursor)
	}
	if pageSize == 0 || pageSize > listAppsScanPageSize {
		pageSize = listAppsScanPageSize
	}

	out := &AppPage{Apps: make([]App, 0, pageSize)}
	appRefs := stringSet(p.ApplicationRefs)
	groupRefs := stringSet(p.GroupRefs)

	// Walk the whole portfolio envelope. App/group filters are cheap to apply
	// from rawAppRow and keeping them off the shadow request ensures they cannot
	// suppress the cursor in the same way as a threshold filter.
	sourceParams := p
	sourceParams.ThresholdScore = nil
	sourceParams.ThresholdSeverity = ""
	sourceParams.ApplicationRefs = nil
	sourceParams.GroupRefs = nil
	sourceParams.Search = ""
	sourceParams.Cursor = ""

	seenCursors := map[string]bool{}
	totalKnown := false
	pageFilled := false
	for {
		if seenCursors[sourceCursor] {
			return nil, fmt.Errorf("list portfolio applications: upstream cursor repeated during filtered scan")
		}
		seenCursors[sourceCursor] = true

		source, err := c.listAppsRaw(ctx, sourceParams, listAppsScanPageSize, sourceCursor, true)
		if err != nil {
			return nil, err
		}
		if source.SummaryInfo != nil {
			if p.IncludeSummary {
				out.Summary = source.summary()
			}
		}
		if consumed > len(source.Rows) {
			return nil, fmt.Errorf("list portfolio applications: filtered cursor consumed %d rows from a %d-row upstream page", consumed, len(source.Rows))
		}

		var severityRefs map[string]bool
		if p.ThresholdSeverity != "" {
			severityParams := sourceParams
			severityParams.ThresholdSeverity = p.ThresholdSeverity
			wantSeverityTotal := canUseSingleThresholdTotal(p)
			filtered, err := c.listAppsRaw(ctx, severityParams, listAppsScanPageSize, sourceCursor, wantSeverityTotal)
			if err != nil {
				return nil, err
			}
			if wantSeverityTotal && filtered.SummaryInfo != nil &&
				filtered.SummaryInfo.TotalResultsWithFindingsAtLeastThresholdSeverity != nil {
				out.Total = *filtered.SummaryInfo.TotalResultsWithFindingsAtLeastThresholdSeverity
				totalKnown = true
			}
			severityRefs = make(map[string]bool, len(filtered.Rows))
			for _, row := range filtered.Rows {
				severityRefs[row.Ref] = true
			}
		}

		for i := consumed; i < len(source.Rows); i++ {
			row := source.Rows[i]
			if !appMatchesListFilters(row, p, appRefs, groupRefs, severityRefs) {
				continue
			}
			matchedCount++
			if pageFilled {
				continue
			}
			out.Apps = append(out.Apps, row.toApp())
			if len(out.Apps) == pageSize {
				nextConsumed := i + 1
				hasMoreSource := nextConsumed < len(source.Rows) || source.PageInfo.HasNextPage
				if hasMoreSource {
					nextSourceCursor := sourceCursor
					if nextConsumed == len(source.Rows) {
						if source.PageInfo.Cursor == "" {
							return nil, fmt.Errorf("list portfolio applications: upstream page has_next_page without a cursor")
						}
						nextSourceCursor = source.PageInfo.Cursor
						nextConsumed = 0
					}
					var matchedBefore *int
					if countStartedAtPortfolioBeginning {
						n := matchedCount
						matchedBefore = &n
					}
					out.Page.HasNextPage = true
					out.Page.NextCursor = encodeListAppsScanCursor(nextSourceCursor, nextConsumed, pageSize, matchedBefore)
				}
				pageFilled = true

				// A lone severity threshold exposes its exact match total in
				// the paired response. A lone score threshold exposes the
				// corresponding exact counter through a cheap summary query.
				// Both paths can stop as soon as the requested page is full.
				if out.Page.HasNextPage && !totalKnown && canUseSingleThresholdTotal(p) && p.ThresholdScore != nil {
					summaryParams := sourceParams
					summaryParams.ThresholdScore = p.ThresholdScore
					summary, err := c.listAppsRaw(ctx, summaryParams, 1, "", true)
					if err != nil {
						return nil, err
					}
					if summary.SummaryInfo != nil && summary.SummaryInfo.TotalResultsBelowThresholdScore != nil {
						out.Total = *summary.SummaryInfo.TotalResultsBelowThresholdScore
						totalKnown = true
					}
				}
				if totalKnown {
					return out, nil
				}
			}
		}

		if !source.PageInfo.HasNextPage {
			if totalKnown {
				return out, nil
			}
			if countStartedAtPortfolioBeginning {
				out.Total = matchedCount
			} else {
				total, err := c.countFilteredApps(ctx, p)
				if err != nil {
					return nil, err
				}
				out.Total = total
			}
			return out, nil
		}
		if source.PageInfo.Cursor == "" {
			return nil, fmt.Errorf("list portfolio applications: upstream page has_next_page without a cursor")
		}
		sourceCursor = source.PageInfo.Cursor
		consumed = 0
	}
}

// canUseSingleThresholdTotal reports whether upstream's summary counter is
// exactly the same set the caller requested. The two threshold counters are
// independent, so combinations (or additional local filters) still require a
// complete scan to count the intersection.
func canUseSingleThresholdTotal(p ListAppsParams) bool {
	if strings.TrimSpace(p.Search) != "" || len(p.ApplicationRefs) > 0 || len(p.GroupRefs) > 0 {
		return false
	}
	return (p.ThresholdScore != nil) != (p.ThresholdSeverity != "")
}

// countFilteredApps computes the global match count from the beginning of the
// portfolio. New nsmcp scan cursors carry the number of matches consumed before
// their source position, so this fallback is primarily for a native/legacy
// upstream cursor that cannot provide that prefix count.
func (c *Client) countFilteredApps(ctx context.Context, p ListAppsParams) (int, error) {
	appRefs := stringSet(p.ApplicationRefs)
	groupRefs := stringSet(p.GroupRefs)
	sourceParams := p
	sourceParams.ThresholdScore = nil
	sourceParams.ThresholdSeverity = ""
	sourceParams.ApplicationRefs = nil
	sourceParams.GroupRefs = nil
	sourceParams.Search = ""
	sourceParams.Cursor = ""

	total := 0
	cursor := ""
	seenCursors := map[string]bool{}
	for {
		if seenCursors[cursor] {
			return 0, fmt.Errorf("list portfolio applications: upstream cursor repeated while counting filtered apps")
		}
		seenCursors[cursor] = true

		source, err := c.listAppsRaw(ctx, sourceParams, listAppsScanPageSize, cursor, false)
		if err != nil {
			return 0, err
		}
		var severityRefs map[string]bool
		if p.ThresholdSeverity != "" {
			severityParams := sourceParams
			severityParams.ThresholdSeverity = p.ThresholdSeverity
			filtered, err := c.listAppsRaw(ctx, severityParams, listAppsScanPageSize, cursor, false)
			if err != nil {
				return 0, err
			}
			severityRefs = make(map[string]bool, len(filtered.Rows))
			for _, row := range filtered.Rows {
				severityRefs[row.Ref] = true
			}
		}
		for _, row := range source.Rows {
			if appMatchesListFilters(row, p, appRefs, groupRefs, severityRefs) {
				total++
			}
		}
		if !source.PageInfo.HasNextPage {
			return total, nil
		}
		if source.PageInfo.Cursor == "" {
			return 0, fmt.Errorf("list portfolio applications: upstream page has_next_page without a cursor")
		}
		cursor = source.PageInfo.Cursor
	}
}

func stringSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func appMatchesListFilters(row rawAppRow, p ListAppsParams, appRefs, groupRefs, severityRefs map[string]bool) bool {
	if appRefs != nil && !appRefs[row.Ref] {
		return false
	}
	if groupRefs != nil && !groupRefs[row.Group.Ref] {
		return false
	}
	if p.ThresholdScore != nil && (row.Score == nil || *row.Score > *p.ThresholdScore) {
		return false
	}
	if severityRefs != nil && !severityRefs[row.Ref] {
		return false
	}
	if needle := strings.ToLower(strings.TrimSpace(p.Search)); needle != "" &&
		!strings.Contains(strings.ToLower(row.Title), needle) &&
		!strings.Contains(strings.ToLower(row.Package), needle) {
		return false
	}
	return true
}

// searchAppPageSize is the upstream page stride used while scanning for a
// client-side match; it is the upstream page-size cap.
const searchAppPageSize = 50

// searchApps scans upstream pages for a case-insensitive substring match on
// title or package, since the applications endpoint has no text filter. It
// collects every match (page_size does not bound matches here) and exhausts the
// portfolio so Total is the exact global match count.
func (c *Client) searchApps(ctx context.Context, p ListAppsParams) (*AppPage, error) {
	out := &AppPage{Apps: []App{}}
	appRefs := stringSet(p.ApplicationRefs)
	groupRefs := stringSet(p.GroupRefs)
	sourceParams := p
	sourceParams.ApplicationRefs = nil
	sourceParams.GroupRefs = nil
	sourceParams.Search = ""
	sourceParams.Cursor = ""

	cursor := p.Cursor
	countStartedAtPortfolioBeginning := cursor == ""
	matchedCount := 0
	seenCursors := map[string]bool{}
	for {
		if seenCursors[cursor] {
			return nil, fmt.Errorf("list portfolio applications: upstream cursor repeated during search")
		}
		seenCursors[cursor] = true

		raw, err := c.listAppsRaw(ctx, sourceParams, searchAppPageSize, cursor, true)
		if err != nil {
			return nil, err
		}
		if raw.SummaryInfo != nil {
			if p.IncludeSummary {
				out.Summary = raw.summary()
			}
		}
		for _, r := range raw.Rows {
			if appMatchesListFilters(r, p, appRefs, groupRefs, nil) {
				out.Apps = append(out.Apps, r.toApp())
				matchedCount++
			}
		}
		if !raw.PageInfo.HasNextPage {
			break
		}
		if raw.PageInfo.Cursor == "" {
			return nil, fmt.Errorf("list portfolio applications: upstream page has_next_page without a cursor")
		}
		cursor = raw.PageInfo.Cursor
	}
	if countStartedAtPortfolioBeginning {
		out.Total = matchedCount
	} else {
		total, err := c.countFilteredApps(ctx, p)
		if err != nil {
			return nil, err
		}
		out.Total = total
	}
	return out, nil
}

// validateUUIDRefs rejects any ref that is not a canonical UUID, naming the
// param and the offending value (a package name or MARI-style id pasted into a
// ref field is the common mistake).
func validateUUIDRefs(field, want string, refs []string) error {
	for _, r := range refs {
		if _, ok := uuidVersion(r); !ok {
			return fmt.Errorf("%s entries must be %s; got %q", field, want, r)
		}
	}
	return nil
}

// GetAppByRef looks up a single portfolio application by its UUID, returning
// the platform, package, group ref, and latest assessment ref needed to
// resolve findings. Results are cached briefly (the client's TTL) to keep
// chained tool calls cheap.
func (c *Client) GetAppByRef(ctx context.Context, appRef string) (*App, error) {
	if appRef == "" {
		return nil, fmt.Errorf("app_ref is required")
	}
	if v, ok := c.cache.get("app:" + appRef); ok {
		return v.(*App), nil
	}
	// A single-ref lookup: fetch raw so the caller's ref reaches upstream even
	// if it is not UUID-shaped (the not-found path below explains that case).
	raw, err := c.listAppsRaw(ctx, ListAppsParams{ApplicationRefs: []string{appRef}}, 1, "", false)
	if err != nil {
		return nil, err
	}
	if len(raw.Rows) == 0 {
		// A real MARI ref 404s here identically to a fabricated one; a v4
		// version nibble is the tell that it belongs to the MARI namespace.
		if v, ok := uuidVersion(appRef); ok && v == '4' {
			return nil, fmt.Errorf("application ref %q not found in portfolio; this is a v4 UUID — Platform app refs are v1; if it came from MARI, pass it to get_mari_assessment as assessment_ref", appRef)
		}
		return nil, fmt.Errorf("application ref %q not found in portfolio — the portfolio covers only apps with a completed scan in the last 12 months, so a ref for an app last scanned earlier lands here too; list_assessments (app_ref or package scope) still serves its history", appRef)
	}
	app := raw.Rows[0].toApp()
	c.cache.set("app:"+appRef, &app)
	return &app, nil
}

// ---- finding documentation ------------------------------------------------

type rawFindingDoc struct {
	Key              string      `json:"key"`
	Title            string      `json:"title"`
	Category         string      `json:"category"`
	Categories       []string    `json:"categories"`
	Platform         string      `json:"platform"`
	SeverityMin      string      `json:"severityMin"`
	SeverityMax      string      `json:"severityMax"`
	CVSSMin          float64     `json:"cvssMin"`
	CVSSMax          float64     `json:"cvssMax"`
	FindingType      string      `json:"findingType"`
	AnalysisType     string      `json:"analysisType"`
	ApplicationCount float64     `json:"applicationCount"`
	Description      string      `json:"description"`
	StepsToReproduce string      `json:"stepsToReproduce"`
	TestingMethod    string      `json:"testingMethod"`
	Deprecated       bool        `json:"deprecated"`
	CoveredBy        []CoveredBy `json:"coveredBy"`
}

// findingRecommendations returns remediation markdown for every finding check,
// keyed by finding id and legacy key. The GraphQL findings list is the only
// API that carries this content; it has no per-key lookup, so the full map is
// fetched once and cached.
func (c *Client) findingRecommendations(ctx context.Context) (map[string]string, error) {
	const cacheKey = "finding:recommendations"
	if v, ok := c.cache.get(cacheKey); ok {
		return v.(map[string]string), nil
	}
	var data struct {
		Findings struct {
			List []struct {
				ID    string `json:"id"`
				Issue *struct {
					Recommendation string `json:"recommendation"`
				} `json:"issue"`
			} `json:"list"`
		} `json:"findings"`
	}
	const q = `{ findings { list { id issue { recommendation } } } }`
	if err := c.graphQL(ctx, "get finding recommendations", q, &data); err != nil {
		return nil, err
	}
	m := make(map[string]string, len(data.Findings.List))
	for _, f := range data.Findings.List {
		if f.Issue == nil || f.Issue.Recommendation == "" {
			continue
		}
		m[f.ID] = f.Issue.Recommendation
	}
	c.cache.set(cacheKey, m)
	return m, nil
}

// GetFinding returns documentation/metadata for a finding by key or id.
func (c *Client) GetFinding(ctx context.Context, findingKeyOrID string) (*FindingDoc, error) {
	if v, ok := c.cache.get("finding:" + findingKeyOrID); ok {
		return v.(*FindingDoc), nil
	}
	var raw rawFindingDoc
	if err := c.getJSON(ctx, "get finding", "/v2/portfolio/findings/"+url.PathEscape(findingKeyOrID), nil, &raw); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return nil, c.findingNotFound(ctx, findingKeyOrID, err)
		}
		return nil, err
	}
	doc := &FindingDoc{
		Key:              raw.Key,
		Title:            raw.Title,
		Category:         raw.Category,
		Categories:       raw.Categories,
		Platform:         raw.Platform,
		SeverityMin:      raw.SeverityMin,
		SeverityMax:      raw.SeverityMax,
		CVSSMin:          raw.CVSSMin,
		CVSSMax:          raw.CVSSMax,
		FindingType:      raw.FindingType,
		AnalysisType:     raw.AnalysisType,
		ApplicationCount: int(raw.ApplicationCount),
		Description:      raw.Description,
		StepsToReproduce: raw.StepsToReproduce,
		TestingMethod:    raw.TestingMethod,
		Deprecated:       raw.Deprecated,
		CoveredBy:        raw.CoveredBy,
	}
	if doc.TestingMethod != "" && doc.TestingMethod == doc.StepsToReproduce {
		// Upstream frequently duplicates the two; drop the copy but flag it so
		// include=[testing_method] callers know why the field is absent.
		doc.TestingMethod = ""
		doc.TestingMethodSameAsSteps = true
	}
	// Remediation lives only in the GraphQL API; degrade to a doc without it
	// rather than failing the whole lookup.
	if recs, err := c.findingRecommendations(ctx); err == nil {
		doc.Remediation = recs[doc.Key]
	}
	c.cache.set("finding:"+findingKeyOrID, doc)
	return doc, nil
}

// catalogEntry is one row of the finding catalog, enough to suggest keys.
type catalogEntry struct {
	Key      string
	Title    string
	Platform string
}

// findingCatalog fetches the full finding catalog (GET with no key), cached:
// it is the only endpoint that lists finding keys/titles, so a 404 lookup can
// suggest near matches instead of dead-ending.
func (c *Client) findingCatalog(ctx context.Context) ([]catalogEntry, error) {
	const cacheKey = "finding:catalog"
	if v, ok := c.cache.get(cacheKey); ok {
		return v.([]catalogEntry), nil
	}
	var raw struct {
		Findings []struct {
			Key      string `json:"key"`
			Title    string `json:"title"`
			Platform string `json:"platform"`
		} `json:"findings"`
	}
	if err := c.getJSON(ctx, "list findings catalog", "/v2/portfolio/findings", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]catalogEntry, 0, len(raw.Findings))
	for _, f := range raw.Findings {
		out = append(out, catalogEntry{Key: f.Key, Title: f.Title, Platform: f.Platform})
	}
	c.cache.set(cacheKey, out)
	return out, nil
}

// findingNotFound turns a per-key 404 into a message that suggests catalog keys
// whose key or title substring-matches the query. It degrades silently to the
// original 404 (keeping its cross-namespace hint) if the catalog is unavailable.
func (c *Client) findingNotFound(ctx context.Context, query string, orig error) error {
	needle := strings.ToLower(strings.TrimSpace(query))
	if needle == "" {
		return orig
	}
	catalog, err := c.findingCatalog(ctx)
	if err != nil {
		return orig
	}
	alt := strings.ReplaceAll(needle, " ", "_")
	var matches []catalogEntry
	for _, e := range catalog {
		k, t := strings.ToLower(e.Key), strings.ToLower(e.Title)
		if strings.Contains(k, needle) || strings.Contains(t, needle) || strings.Contains(k, alt) || strings.Contains(t, alt) {
			matches = append(matches, e)
			if len(matches) == 5 {
				break
			}
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("%w; finding keys come from get_assessment_findings rows (check_id), or search_findings can find them by topic", orig)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "finding %q not found; did you mean: ", query)
	for i, m := range matches {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s (%q)", m.Key, m.Title)
	}
	b.WriteString("?")
	return errors.New(b.String())
}

// ---- finding catalog search ------------------------------------------------

// SearchFindingsParams shapes search_findings.
type SearchFindingsParams struct {
	Query             string // substring to match, case-insensitive (required)
	Platform          string // android|ios; cross-platform findings always pass
	IncludeDeprecated bool   // include deprecated checks (default false)
	Limit             int    // max matches returned (0 = searchFindingsDefaultLimit)
}

// searchFindingsDefaultLimit caps search_findings rows when no limit is given;
// total still reports the full match count so the caller knows to refine.
const searchFindingsDefaultLimit = 25

// searchCheck is one check of the searchable catalog: the scalar metadata a
// match row carries plus the prose fields the substring match runs over.
type searchCheck struct {
	Key        string
	Title      string
	Platform   string
	Severity   string
	Category   string   // lab analysis category (lowercased like get_assessment_findings)
	Categories []string // capability groups (Title Case)
	Deprecated bool
	CoveredBy  []CoveredBy
	Prose      []string // description-bucket fields, snippet-priority order
}

// searchCatalog returns the full check catalog with documentation prose,
// fetched once via GraphQL and cached. GraphQL is the only bulk source of
// descriptions — the REST catalog list omits them, and it also lists only the
// curated portfolio findings while the per-key doc endpoint (get_finding)
// serves the full check space this list covers.
func (c *Client) searchCatalog(ctx context.Context) ([]searchCheck, error) {
	const cacheKey = "finding:search-catalog"
	if v, ok := c.cache.get(cacheKey); ok {
		return v.([]searchCheck), nil
	}
	var data struct {
		Findings struct {
			List []struct {
				ID               string      `json:"id"`
				Title            string      `json:"title"`
				Description      string      `json:"description"`
				ShortDescription string      `json:"shortDescription"`
				PlatformType     string      `json:"platformType"`
				Deprecated       bool        `json:"deprecated"`
				Categories       []string    `json:"categories"`
				CoveredBy        []CoveredBy `json:"coveredBy"`
				Issue            *struct {
					Description   string `json:"description"`
					ImpactSummary string `json:"impactSummary"`
					Category      string `json:"category"`
					Severity      string `json:"severity"`
				} `json:"issue"`
			} `json:"list"`
		} `json:"findings"`
	}
	const q = `{ findings { list { id title description shortDescription platformType deprecated categories coveredBy { id title } issue { description impactSummary category severity } } } }`
	if err := c.graphQL(ctx, "search findings catalog", q, &data); err != nil {
		return nil, err
	}
	out := make([]searchCheck, 0, len(data.Findings.List))
	for _, f := range data.Findings.List {
		e := searchCheck{
			Key:        f.ID,
			Title:      f.Title,
			Platform:   f.PlatformType,
			Deprecated: f.Deprecated,
			Categories: f.Categories,
			CoveredBy:  f.CoveredBy,
			Prose:      []string{f.Description, f.ShortDescription},
		}
		if f.Issue != nil {
			e.Severity = strings.ToLower(f.Issue.Severity)
			e.Category = strings.ToLower(f.Issue.Category) // upstream mixes "Resilience" into a lowercase set
			e.Prose = append(e.Prose, f.Issue.Description, f.Issue.ImpactSummary)
		}
		out = append(out, e)
	}
	c.cache.set(cacheKey, out)
	return out, nil
}

// match reports which buckets of e contain the needle, in fixed key, title,
// description, category order. alt is the needle with spaces mapped to
// underscores so a spoken name can hit a key. snippet carries prose context
// around the first description hit, but only when neither key nor title
// matched — the one case where the row itself does not show why it is here.
func (e *searchCheck) match(needle, alt string) (matchedIn []string, snippet string) {
	key := strings.ToLower(e.Key)
	if strings.Contains(key, needle) || strings.Contains(key, alt) {
		matchedIn = append(matchedIn, "key")
	}
	if strings.Contains(strings.ToLower(e.Title), needle) {
		matchedIn = append(matchedIn, "title")
	}
	rowVisible := len(matchedIn) > 0
	for _, pr := range e.Prose {
		idx := strings.Index(strings.ToLower(pr), needle)
		if idx < 0 {
			continue
		}
		matchedIn = append(matchedIn, "description")
		if !rowVisible {
			snippet = proseSnippet(pr, idx, len(needle))
		}
		break
	}
	inCategory := strings.Contains(e.Category, needle)
	for _, g := range e.Categories {
		if inCategory {
			break
		}
		inCategory = strings.Contains(strings.ToLower(g), needle)
	}
	if inCategory {
		matchedIn = append(matchedIn, "category")
	}
	return matchedIn, snippet
}

// snippetRadius is how many bytes of context proseSnippet keeps on each side
// of a match.
const snippetRadius = 60

// proseSnippet returns a whitespace-collapsed window of s around the match at
// [idx, idx+matchLen), with "…" marking a cut edge. idx comes from an index
// into a lowercased copy of s; offsets agree for the ASCII prose this catalog
// holds, and the rune-boundary clamps keep any exotic text merely cosmetic.
func proseSnippet(s string, idx, matchLen int) string {
	start := max(idx-snippetRadius, 0)
	end := min(idx+matchLen+snippetRadius, len(s))
	for start > 0 && !utf8.RuneStart(s[start]) {
		start--
	}
	for end < len(s) && !utf8.RuneStart(s[end]) {
		end++
	}
	snip := strings.Join(strings.Fields(s[start:end]), " ")
	if start > 0 {
		snip = "…" + snip
	}
	if end < len(s) {
		snip += "…"
	}
	return snip
}

// SearchFindings substring-matches the finding catalog on key, title,
// description prose, and category, returning compact rows for key discovery.
// The match runs client-side over the cached catalog (the API has no text
// search). Deprecated checks are excluded unless asked for, with the excluded
// match count reported so a thin result stays explainable.
func (c *Client) SearchFindings(ctx context.Context, p SearchFindingsParams) (*FindingSearchResult, error) {
	needle := strings.ToLower(strings.TrimSpace(p.Query))
	if needle == "" {
		return nil, fmt.Errorf("query is required")
	}
	if p.Limit < 0 {
		return nil, fmt.Errorf("limit must not be negative")
	}
	platform := ""
	if p.Platform != "" {
		pf, err := validateEnum("platform", []string{p.Platform}, enumPlatforms)
		if err != nil {
			return nil, err
		}
		platform = pf[0]
	}
	catalog, err := c.searchCatalog(ctx)
	if err != nil {
		return nil, err
	}
	alt := strings.ReplaceAll(needle, " ", "_")
	out := &FindingSearchResult{Query: p.Query, Findings: []FindingSearchMatch{}}
	type ranked struct {
		m    FindingSearchMatch
		rank int
	}
	var matches []ranked
	for i := range catalog {
		e := &catalog[i]
		// An empty catalog platform means the finding applies to both.
		if platform != "" && e.Platform != "" && e.Platform != platform {
			continue
		}
		matchedIn, snippet := e.match(needle, alt)
		if len(matchedIn) == 0 {
			continue
		}
		if e.Deprecated && !p.IncludeDeprecated {
			out.ExcludedDeprecated++
			continue
		}
		rank := 1 // prose/category-only match
		if matchedIn[0] == "key" || matchedIn[0] == "title" {
			rank = 0
		}
		matches = append(matches, ranked{rank: rank, m: FindingSearchMatch{
			Key:        e.Key,
			Title:      e.Title,
			Platform:   e.Platform,
			Severity:   e.Severity,
			Category:   e.Category,
			Deprecated: e.Deprecated,
			CoveredBy:  e.CoveredBy,
			MatchedIn:  matchedIn,
			Snippet:    snippet,
		}})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].rank != matches[j].rank {
			return matches[i].rank < matches[j].rank
		}
		return matches[i].m.Key < matches[j].m.Key
	})
	out.Total = len(matches)
	limit := p.Limit
	if limit == 0 {
		limit = searchFindingsDefaultLimit
	}
	if len(matches) > limit {
		matches = matches[:limit]
	}
	for _, r := range matches {
		out.Findings = append(out.Findings, r.m)
	}
	out.TotalReturned = len(out.Findings)
	return out, nil
}

// ---- apps affected by a finding ------------------------------------------

// AffectedByParams filters GET /v2/portfolio/findings/{key}/applications.
type AffectedByParams struct {
	Platform   string // android|ios
	SearchText string
	GroupRefs  []string
	OrderBy    string // created_at|package|platform|title (+/- prefix); snake aliases translated
	PageSize   int
	Cursor     string
}

type rawAffectedResponse struct {
	Rows []struct {
		AssessmentRef  string  `json:"assessmentRef"`
		Ref            string  `json:"ref"`
		Title          string  `json:"title"`
		Platform       string  `json:"platform"`
		Package        string  `json:"package"`
		PackageVersion string  `json:"packageVersion"`
		BuildVersion   string  `json:"buildVersion"`
		GroupName      string  `json:"groupName"`
		CreatedAt      float64 `json:"createdAt"` // epoch milliseconds
	} `json:"rows"`
	PageInfo    rawCursorPage `json:"pageInfo"`
	SummaryInfo *struct {
		TotalResults int `json:"totalResults"`
	} `json:"summaryInfo"`
}

// AppsAffectedByFinding lists portfolio apps affected by a finding.
func (c *Client) AppsAffectedByFinding(ctx context.Context, findingKeyOrID string, p AffectedByParams) (*AffectedAppPage, error) {
	if p.PageSize < 0 {
		return nil, fmt.Errorf("page_size must not be negative")
	}
	if err := validateUUIDRefs("group_refs", "group UUIDs (from list_apps group_ref)", p.GroupRefs); err != nil {
		return nil, err
	}
	q := url.Values{}
	f := filters{}
	f = f.add("platform", p.Platform)
	f = f.add("searchText", p.SearchText)
	if len(p.GroupRefs) > 0 {
		f = f.add("groupRefs", p.GroupRefs)
	}
	f.apply(q)
	// Upstream's unordered default has no contract (neither createdAt
	// direction matches); rows surface created_at as the latest assessment
	// date, so newest-assessed first is the natural read. Verified honored
	// server-side.
	orderBy := p.OrderBy
	if strings.TrimSpace(orderBy) == "" {
		orderBy = "-created_at"
	}
	setOrderBy(q, orderBy)
	pageSize := p.PageSize
	if pageSize == 0 {
		pageSize = pageSizeFromCursor(p.Cursor)
	}
	setInt(q, "pageSize", pageSize)
	setStr(q, "cursor", p.Cursor)
	q.Set("includeSummaryInfo", "true")

	var raw rawAffectedResponse
	path := "/v2/portfolio/findings/" + url.PathEscape(findingKeyOrID) + "/applications"
	if err := c.getJSON(ctx, "get apps affected by finding", path, q, &raw); err != nil {
		return nil, err
	}
	out := &AffectedAppPage{
		Finding: findingKeyOrID,
		Apps:    make([]AffectedApp, 0, len(raw.Rows)),
		Page:    CursorPage{HasNextPage: raw.PageInfo.HasNextPage},
	}
	if raw.PageInfo.HasNextPage {
		out.Page.NextCursor = raw.PageInfo.Cursor
	}
	if raw.SummaryInfo != nil {
		out.Total = raw.SummaryInfo.TotalResults
	}
	for _, r := range raw.Rows {
		out.Apps = append(out.Apps, AffectedApp{
			AppRef:         r.Ref,
			AssessmentRef:  r.AssessmentRef,
			Title:          r.Title,
			Platform:       r.Platform,
			Package:        r.Package,
			PackageVersion: r.PackageVersion,
			BuildVersion:   r.BuildVersion,
			Group:          r.GroupName,
			CreatedAt:      epochMillisToRFC3339(r.CreatedAt),
		})
	}
	return out, nil
}

// epochMillisToRFC3339 renders an epoch-milliseconds timestamp (the form the
// affected-apps rows use, which normalizeTimestamp does not handle) as RFC3339
// UTC. A non-positive value yields "" (no timestamp).
func epochMillisToRFC3339(ms float64) string {
	if ms <= 0 {
		return ""
	}
	m := int64(ms)
	return time.Unix(m/1000, (m%1000)*int64(time.Millisecond)).UTC().Format(time.RFC3339)
}
