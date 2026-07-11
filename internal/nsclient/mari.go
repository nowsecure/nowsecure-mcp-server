package nsclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// ---- MARI domain types ----------------------------------------------------

// MARIApp is one third-party app in the Risk Intelligence catalog.
type MARIApp struct {
	Title              string  `json:"title"`
	Platform           string  `json:"platform"`
	Package            string  `json:"package"`
	ApplicationID      string  `json:"application_id" jsonschema:"store id (ios) / package name (android)"`
	AssessmentRef      string  `json:"assessment_ref,omitempty"`
	BuildVersion       string  `json:"build_version,omitempty"`
	RiskScore          float64 `json:"risk_score"`
	RiskRating         string  `json:"risk_rating,omitempty"`
	RiskCategory       string  `json:"risk_category,omitempty"`
	RiskRecommendation string  `json:"risk_recommendation,omitempty"`
	CreatedAt          string  `json:"created_at,omitempty" jsonschema:"when the app was added to the catalog — the date since/until filter against"`
	UpdatedAt          string  `json:"updated_at,omitempty"`
}

// OffsetPage is offset-based pagination metadata (MARI), the counterpart of
// CursorPage so every list tool nests pagination under a "page" object.
type OffsetPage struct {
	HasNextPage    bool `json:"has_next_page"`
	NextPageNumber int  `json:"next_page_number,omitempty" jsonschema:"pass as page_number to fetch the next page (absent on the last page)"`
}

// MARIAppPage is a page of MARI apps (offset pagination, 1-based pages).
type MARIAppPage struct {
	Apps  []MARIApp  `json:"apps"`
	Total int        `json:"total"`
	Page  OffsetPage `json:"page"`
}

// MARIFinding is a compacted MARI assessment finding.
type MARIFinding struct {
	CheckID          string   `json:"check_id"`
	Title            string   `json:"title"`
	ShortDescription string   `json:"short_description,omitempty"`
	Categories       []string `json:"categories,omitempty"`
	Affected         bool     `json:"affected"`
	Severity         string   `json:"severity,omitempty"`
	CVSSScore        float64  `json:"cvss_score,omitempty"`
}

// MARISummary counts findings checked vs affected.
type MARISummary struct {
	TotalFindingsAffected int `json:"total_findings_affected"`
	TotalFindingsChecked  int `json:"total_findings_checked"`
}

// MARIAssessment is a single third-party app risk profile.
// Expanded holds the opt-in sections as plain decoded JSON. It must stay
// map[string]any: the MCP SDK infers the tool's output schema from this type,
// and json.RawMessage would be inferred as a byte array, making the server
// reject its own responses whenever expand is used.
type MARIAssessment struct {
	AssessmentRef               string         `json:"assessment_ref"`
	Title                       string         `json:"title,omitempty" jsonschema:"app title (when reported by upstream)"`
	Package                     string         `json:"package,omitempty"`
	Platform                    string         `json:"platform,omitempty"`
	CreatedAt                   string         `json:"created_at,omitempty"`
	RiskScore                   float64        `json:"risk_score"`
	RiskRating                  string         `json:"risk_rating,omitempty"`
	RiskCategory                string         `json:"risk_category,omitempty"`
	RiskRecommendation          string         `json:"risk_recommendation,omitempty"`
	NowSecureRiskScore          float64        `json:"nowsecure_risk_score"`
	NowSecureRiskCategory       string         `json:"nowsecure_risk_category,omitempty"`
	NowSecureRiskRecommendation string         `json:"nowsecure_risk_recommendation,omitempty"`
	Summary                     MARISummary    `json:"summary"`
	Findings                    []MARIFinding  `json:"findings"`
	Expanded                    map[string]any `json:"expanded,omitempty" jsonschema:"requested expand sections keyed by snake_case section name"`
}

// libComponent is one third-party software component that carries known CVEs.
// Rows sharing (name, version) are merged, their file locations collected into
// Sources.
type libComponent struct {
	Name             string   `json:"name"`
	Version          string   `json:"version,omitempty"`
	CVECount         int      `json:"cve_count"`
	HighestCVSSScore float64  `json:"highest_cvss_score,omitempty"`
	Sources          []string `json:"sources,omitempty"`
}

// shapedLibrariesAndSdks compacts the librariesAndSdks expand section. The raw
// section lists every detected component (hundreds of KB) and overflows MCP
// token limits, so only CVE-bearing components are listed; clean components are
// counted in OmittedComponents and their totals remain in Summary.
type shapedLibrariesAndSdks struct {
	Description       string         `json:"description,omitempty"`
	BusinessImpact    string         `json:"business_impact,omitempty"`
	Categories        []string       `json:"categories,omitempty"`
	Summary           map[string]any `json:"summary,omitempty"`
	CVEComponents     []libComponent `json:"cve_components"`
	OmittedComponents int            `json:"omitted_components" jsonschema:"count of components with no known CVEs, omitted to fit token limits; their totals remain in summary"`
}

// MARIExpandValues are the supported expand sections (opt-in, heavier).
var MARIExpandValues = []string{
	"appInfo", "aiUsage", "iosMetadata", "librariesAndSdks",
	"networkConnections", "permissions", "trackingDomains",
}

// expandSectionKeys maps upstream camelCase section names to the snake_case
// keys used in responses.
var expandSectionKeys = map[string]string{
	"appInfo": "app_info", "aiUsage": "ai_usage", "iosMetadata": "ios_metadata",
	"librariesAndSdks": "libraries_and_sdks", "networkConnections": "network_connections",
	"permissions": "permissions", "trackingDomains": "tracking_domains",
}

// ---- MARI apps ------------------------------------------------------------

// ListMARIAppsParams filters/paginates GET /v2/risk-intelligence/apps.
type ListMARIAppsParams struct {
	Platform     string   // android|ios
	Rating       []string // A|B|C|D|F
	RiskCategory []string // LOW|MEDIUM|HIGH
	Search       string
	AppTitle     []string
	Since        string // filters when the app was added to the catalog, not updated_at
	Until        string // see Since
	OrderBy      string // title|updated_at|risk_score|created_at (+/-); snake aliases translated; default -risk_score
	PageSize     int
	PageNumber   int // 1-based; translated to the 0-based upstream param
}

type rawMARIAppsResponse struct {
	Rows []struct {
		Title         string `json:"title"`
		Platform      string `json:"platform"`
		ApplicationID string `json:"applicationId"`
		PackageName   string `json:"packageName"`
		CreatedAt     string `json:"createdAt"`
		RecentScore   struct {
			AssessmentRef      string  `json:"assessmentRef"`
			BuildVersion       string  `json:"buildVersion"`
			RiskScore          float64 `json:"riskScore"`
			RiskRating         string  `json:"riskRating"`
			UpdatedAt          string  `json:"updatedAt"`
			RiskRecommendation string  `json:"riskRecommendation"`
			RiskCategory       string  `json:"riskCategory"`
		} `json:"recentScore"`
	} `json:"rows"`
	PageInfo struct {
		TotalResults int `json:"totalResults"`
		Start        int `json:"start"`
		End          int `json:"end"`
	} `json:"pageInfo"`
}

// ListMARIApps lists the Risk Intelligence third-party app catalog.
func (c *Client) ListMARIApps(ctx context.Context, p ListMARIAppsParams) (*MARIAppPage, error) {
	// Upstream answers bad enum values with an anyOf filter-schema dump that
	// mashes every branch together; the sets are stable, so reject client-side.
	if p.Platform != "" {
		pf, err := validateEnum("platform", []string{p.Platform}, enumPlatforms)
		if err != nil {
			return nil, err
		}
		p.Platform = pf[0]
	}
	rating, err := validateEnum("rating", p.Rating, enumMARIRating)
	if err != nil {
		return nil, err
	}
	riskCategory, err := validateEnum("risk_category", p.RiskCategory, enumMARIRiskCategory)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	f := filters{}
	f = f.add("platform", p.Platform)
	f = f.add("search", p.Search)
	f = f.add("since", p.Since)
	f = f.add("until", p.Until)
	if len(rating) > 0 {
		f = f.add("rating", rating)
	}
	if len(riskCategory) > 0 {
		f = f.add("riskCategory", riskCategory)
	}
	if len(p.AppTitle) > 0 {
		f = f.add("appTitle", p.AppTitle)
	}
	f.apply(q)
	if p.OrderBy == "" {
		p.OrderBy = "-riskScore" // riskiest first: the vetting default
	}
	setOrderBy(q, p.OrderBy)
	setInt(q, "pageSize", p.PageSize)
	// The tool speaks 1-based pages; upstream is 0-based. setInt drops zeros,
	// so the translated first page must be set explicitly.
	if p.PageNumber > 0 {
		q.Set("pageNumber", strconv.Itoa(p.PageNumber-1))
	}

	var raw rawMARIAppsResponse
	if err := c.getJSON(ctx, "list MARI apps", "/v2/risk-intelligence/apps", q, &raw); err != nil {
		return nil, err
	}
	out := &MARIAppPage{
		Apps:  make([]MARIApp, 0, len(raw.Rows)),
		Total: raw.PageInfo.TotalResults,
	}
	if raw.PageInfo.End < raw.PageInfo.TotalResults {
		out.Page.HasNextPage = true
		if size := raw.PageInfo.End - raw.PageInfo.Start; size > 0 {
			out.Page.NextPageNumber = raw.PageInfo.End/size + 1
		}
	}
	for _, r := range raw.Rows {
		out.Apps = append(out.Apps, MARIApp{
			Title:              r.Title,
			Platform:           r.Platform,
			Package:            r.PackageName,
			ApplicationID:      r.ApplicationID,
			AssessmentRef:      r.RecentScore.AssessmentRef,
			BuildVersion:       r.RecentScore.BuildVersion,
			RiskScore:          r.RecentScore.RiskScore,
			RiskRating:         r.RecentScore.RiskRating,
			RiskCategory:       r.RecentScore.RiskCategory,
			RiskRecommendation: r.RecentScore.RiskRecommendation,
			CreatedAt:          r.CreatedAt,
			UpdatedAt:          r.RecentScore.UpdatedAt,
		})
	}
	return out, nil
}

// ---- MARI assessment ------------------------------------------------------

// GetMARIAssessment returns a third-party app's risk profile. expand names
// optional heavier sections (permissions, trackingDomains, ...) captured as
// decoded JSON. Upstream reports only findings the app is affected by; the
// summary still counts both affected and checked.
func (c *Client) GetMARIAssessment(ctx context.Context, assessmentRef string, expand []string) (*MARIAssessment, error) {
	if assessmentRef == "" {
		return nil, fmt.Errorf("assessment_ref is required")
	}
	norm, err := normalizeExpand(expand)
	if err != nil {
		return nil, err
	}
	// appInfo carries the app's identity (title/package/platform), which the
	// default response omits, so it is always fetched; it surfaces in Expanded
	// only when the caller asked for it.
	upstream := norm
	hasAppInfo := slices.Contains(norm, "appInfo")
	if !hasAppInfo {
		upstream = append(append([]string{}, norm...), "appInfo")
	}
	q := url.Values{}
	q.Set("expand", strings.Join(upstream, ","))

	// Decode into a raw map so expandables can be captured without modeling
	// their deep nesting, and core fields pulled from a typed view.
	var rawMap map[string]json.RawMessage
	if err := c.getJSON(ctx, "get MARI assessment", "/v2/risk-intelligence/assessment/"+url.PathEscape(assessmentRef), q, &rawMap); err != nil {
		return nil, err
	}

	var core struct {
		Title                       string  `json:"title"`
		PackageName                 string  `json:"packageName"`
		Platform                    string  `json:"platform"`
		CreatedAt                   string  `json:"createdAt"`
		RiskScore                   float64 `json:"riskScore"`
		RiskRating                  string  `json:"riskRating"`
		RiskCategory                string  `json:"riskCategory"`
		RiskRecommendation          string  `json:"riskRecommendation"`
		NowSecureRiskScore          float64 `json:"nowSecureRiskScore"`
		NowSecureRiskCategory       string  `json:"nowSecureRiskCategory"`
		NowSecureRiskRecommendation string  `json:"nowSecureRiskRecommendation"`
		SummaryInfo                 struct {
			TotalFindingsAffected int `json:"totalFindingsAffected"`
			TotalFindingsChecked  int `json:"totalFindingsChecked"`
		} `json:"summaryInfo"`
		Findings []struct {
			CheckID          string   `json:"checkId"`
			Title            string   `json:"title"`
			ShortDescription string   `json:"shortDescription"`
			Categories       []string `json:"categories"`
			Affected         bool     `json:"affected"`
			Severity         string   `json:"severity"`
			CVSSScore        float64  `json:"cvssScore"`
		} `json:"findings"`
	}
	// Re-marshal the map to decode the typed core in one shot. Decode failures
	// must surface: a silently zeroed risk profile reads as "no risk".
	b, err := json.Marshal(rawMap)
	if err != nil {
		return nil, fmt.Errorf("get MARI assessment: %w", err)
	}
	if err := json.Unmarshal(b, &core); err != nil {
		return nil, fmt.Errorf("get MARI assessment: decoding response: %w", err)
	}

	// The default response omits identity; appInfo (always fetched) carries it.
	// Read it from the raw bytes so it is unaffected by any Expanded stripping.
	var appInfo struct {
		Title       string `json:"title"`
		PackageName string `json:"packageName"`
		Platform    string `json:"platform"`
		CreatedAt   string `json:"createdAt"`
	}
	if raw, ok := rawMap["appInfo"]; ok {
		if err := json.Unmarshal(raw, &appInfo); err != nil {
			return nil, fmt.Errorf("get MARI assessment: decoding appInfo: %w", err)
		}
	}

	out := &MARIAssessment{
		AssessmentRef:               assessmentRef,
		Title:                       core.Title,
		Package:                     core.PackageName,
		Platform:                    core.Platform,
		CreatedAt:                   core.CreatedAt,
		RiskScore:                   core.RiskScore,
		RiskRating:                  core.RiskRating,
		RiskCategory:                core.RiskCategory,
		RiskRecommendation:          core.RiskRecommendation,
		NowSecureRiskScore:          core.NowSecureRiskScore,
		NowSecureRiskCategory:       core.NowSecureRiskCategory,
		NowSecureRiskRecommendation: core.NowSecureRiskRecommendation,
		Summary: MARISummary{
			TotalFindingsAffected: core.SummaryInfo.TotalFindingsAffected,
			TotalFindingsChecked:  core.SummaryInfo.TotalFindingsChecked,
		},
	}
	if appInfo.Title != "" {
		out.Title = appInfo.Title
	}
	if appInfo.PackageName != "" {
		out.Package = appInfo.PackageName
	}
	if appInfo.Platform != "" {
		out.Platform = appInfo.Platform
	}
	if out.CreatedAt == "" {
		out.CreatedAt = appInfo.CreatedAt
	}
	for _, ff := range core.Findings {
		out.Findings = append(out.Findings, MARIFinding{
			CheckID:          ff.CheckID,
			Title:            ff.Title,
			ShortDescription: ff.ShortDescription,
			Categories:       ff.Categories,
			Affected:         ff.Affected,
			Severity:         ff.Severity,
			CVSSScore:        ff.CVSSScore,
		})
	}
	if len(norm) > 0 {
		out.Expanded = make(map[string]any, len(norm))
		for _, k := range norm {
			raw, ok := rawMap[k]
			if !ok {
				continue
			}
			if k == "librariesAndSdks" {
				shaped, err := shapeLibrariesAndSdks(raw)
				if err != nil {
					return nil, fmt.Errorf("get MARI assessment: decoding expand section %q: %w", k, err)
				}
				out.Expanded[expandSectionKeys[k]] = shaped
				continue
			}
			var v any
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("get MARI assessment: decoding expand section %q: %w", k, err)
			}
			if m, ok := v.(map[string]any); ok {
				switch k {
				case "appInfo":
					delete(m, "icon") // multi-KB base64 data URI; iconUrl carries the same image
				case "permissions":
					delete(m, "highRiskPermissions") // verbatim subset of allPermissions
				case "aiUsage":
					trimAIUsage(m)
				}
			}
			out.Expanded[expandSectionKeys[k]] = v
		}
	}
	return out, nil
}

// shapeLibrariesAndSdks compacts the raw librariesAndSdks section: it keeps the
// prose/summary fields, lists only CVE-bearing components (deduped by (name,
// version) with their sources merged, riskiest first), and counts the clean
// components dropped so the totals in summary stay verifiable.
func shapeLibrariesAndSdks(raw json.RawMessage) (*shapedLibrariesAndSdks, error) {
	var in struct {
		Description    string         `json:"description"`
		BusinessImpact string         `json:"businessImpact"`
		Categories     []string       `json:"categories"`
		Summary        map[string]any `json:"summary"`
		Components     []struct {
			Name             string  `json:"name"`
			Version          string  `json:"version"`
			Source           string  `json:"source"`
			CVECount         int     `json:"cveCount"`
			HighestCVSSScore float64 `json:"highestCvssScore"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := &shapedLibrariesAndSdks{
		Description:    in.Description,
		BusinessImpact: in.BusinessImpact,
		Categories:     in.Categories,
		Summary:        in.Summary,
		CVEComponents:  []libComponent{},
	}
	idx := make(map[string]int)
	for _, comp := range in.Components {
		if comp.CVECount <= 0 {
			out.OmittedComponents++
			continue
		}
		key := comp.Name + "\x00" + comp.Version
		if i, ok := idx[key]; ok {
			if comp.Source != "" {
				out.CVEComponents[i].Sources = append(out.CVEComponents[i].Sources, comp.Source)
			}
			continue
		}
		idx[key] = len(out.CVEComponents)
		c := libComponent{
			Name:             comp.Name,
			Version:          comp.Version,
			CVECount:         comp.CVECount,
			HighestCVSSScore: comp.HighestCVSSScore,
		}
		if comp.Source != "" {
			c.Sources = []string{comp.Source}
		}
		out.CVEComponents = append(out.CVEComponents, c)
	}
	sort.SliceStable(out.CVEComponents, func(i, j int) bool {
		a, b := out.CVEComponents[i], out.CVEComponents[j]
		switch {
		case a.CVECount != b.CVECount:
			return a.CVECount > b.CVECount
		case a.HighestCVSSScore != b.HighestCVSSScore:
			return a.HighestCVSSScore > b.HighestCVSSScore
		case a.Name != b.Name:
			return a.Name < b.Name
		default:
			return a.Version < b.Version
		}
	})
	return out, nil
}

// trimAIUsage reduces each aiUsage subsection the app is not affected by (no
// evidence) to just {"affected": false}, dropping its boilerplate description.
func trimAIUsage(m map[string]any) {
	for k, v := range m {
		sub, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if affected, _ := sub["affected"].(bool); affected {
			continue
		}
		count, _ := sub["evidenceCount"].(float64)
		evidence, _ := sub["evidence"].([]any)
		if count == 0 && len(evidence) == 0 {
			m[k] = map[string]any{"affected": false}
		}
	}
}

func normalizeExpand(expand []string) ([]string, error) {
	if len(expand) == 0 {
		return nil, nil
	}
	allowed := make(map[string]struct{}, len(MARIExpandValues))
	for _, v := range MARIExpandValues {
		allowed[v] = struct{}{}
	}
	seen := make(map[string]struct{})
	var out []string
	for _, e := range expand {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, ok := allowed[e]; !ok {
			return nil, fmt.Errorf("unsupported expand value %q (allowed: %s)", e, strings.Join(MARIExpandValues, ", "))
		}
		if _, dup := seen[e]; dup {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	return out, nil
}
