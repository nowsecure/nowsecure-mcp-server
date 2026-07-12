package nsclient

import (
	"context"
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
		PortfolioScore  float64 `json:"portfolioScore"`
		PortfolioRating string  `json:"portfolioRating"`
		TotalResults    int     `json:"totalResults"`
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

// ListApps lists portfolio applications.
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
	if strings.TrimSpace(p.Search) != "" {
		return c.searchApps(ctx, p)
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

// searchAppPages caps how many upstream pages a single search call walks; the
// caller resumes from next_cursor when the window closes with pages remaining.
const searchAppPages = 20

// searchAppPageSize is the upstream page stride used while scanning for a
// client-side match; it is the upstream page-size cap.
const searchAppPageSize = 50

// searchApps scans upstream pages for a case-insensitive substring match on
// title or package, since the applications endpoint has no text filter. It
// collects every match in the scan window (page_size does not bound matches
// here) and, if it stopped with pages still outstanding, hands back the last
// upstream cursor so a repeat call continues the walk.
func (c *Client) searchApps(ctx context.Context, p ListAppsParams) (*AppPage, error) {
	needle := strings.ToLower(strings.TrimSpace(p.Search))
	out := &AppPage{Apps: []App{}}
	cursor := p.Cursor
	for range searchAppPages {
		raw, err := c.listAppsRaw(ctx, p, searchAppPageSize, cursor, true)
		if err != nil {
			return nil, err
		}
		if raw.SummaryInfo != nil {
			out.Total = raw.SummaryInfo.TotalResults
			if p.IncludeSummary {
				out.Summary = raw.summary()
			}
		}
		for _, r := range raw.Rows {
			if strings.Contains(strings.ToLower(r.Title), needle) || strings.Contains(strings.ToLower(r.Package), needle) {
				out.Apps = append(out.Apps, r.toApp())
			}
		}
		if !raw.PageInfo.HasNextPage {
			cursor = ""
			break
		}
		cursor = raw.PageInfo.Cursor
	}
	if cursor != "" {
		out.Page.HasNextPage = true
		out.Page.NextCursor = cursor
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
		return nil, fmt.Errorf("application ref %q not found in portfolio", appRef)
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
