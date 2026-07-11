package nsclient

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// normalizeTimestamp re-emits an upstream timestamp as RFC3339 UTC; /v2 rows
// mix RFC3339 and Postgres-style ("2026-05-20 00:06:28.066197+00") formats in
// one page. Unparseable values pass through untouched.
func normalizeTimestamp(s string) string {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999-07", "2006-01-02 15:04:05.999999-07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}

// Allowed values for enum filters, in the exact casing the wire expects. Kept
// client-side because upstream answers bad values with an empty page, a 500,
// or an anyOf filter-schema dump depending on the endpoint.
var (
	enumPlatforms         = []string{"android", "ios"}
	enumStatus            = []string{"completed", "failed", "processing", "pending", "cancelled", "partial", "incomplete"} //nolint:misspell // "cancelled" is the upstream API's actual wire value
	enumRating            = []string{"critical", "poor", "fair", "good", "excellent"}
	enumType              = []string{"advanced", "baseline", "guided", "pen_test", "workstation"}
	enumThresholdSeverity = []string{"critical", "high", "medium", "low"}
	enumMARIRating        = []string{"A", "B", "C", "D", "F"}
	enumMARIRiskCategory  = []string{"LOW", "MEDIUM", "HIGH"}
)

// validateEnum matches each value case-insensitively against allowed and
// returns the canonical spellings (the wire expects them exactly: lowercase
// statuses, uppercase MARI ratings). The error mirrors min_severity's
// allowed-values style.
func validateEnum(field string, values, allowed []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		tv := strings.TrimSpace(v)
		ok := false
		for _, a := range allowed {
			if strings.EqualFold(tv, a) {
				out = append(out, a)
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("invalid %s %q (allowed: %s)", field, v, strings.Join(allowed, ", "))
		}
	}
	return out, nil
}

// ---- assessment list (GET /v2/assessments) --------------------------------

// ListAssessmentsParams filters and paginates GET /v2/assessments.
type ListAssessmentsParams struct {
	ApplicationRef string   // limit to one app UUID
	GroupRefs      []string // limit to groups
	PlatformTypes  []string // android, ios, ...
	Status         []string // completed, failed, processing, ...
	Rating         []string // critical, poor, fair, good, excellent
	Type           []string // advanced, baseline, guided, pen_test, workstation
	PackageKey     string   // android package / ios bundle id
	AppstoreKey    string   // app store application key
	Since          string   // date or date-time lower bound
	Until          string   // date or date-time upper bound
	OrderBy        string   // created_at|build_version|package_version (+/-); snake aliases translated
	PageSize       int
	Cursor         string
}

type rawImpactTypes struct {
	Critical float64 `json:"critical"`
	High     float64 `json:"high"`
	Medium   float64 `json:"medium"`
	Low      float64 `json:"low"`
	Warn     float64 `json:"warn"`
	Info     float64 `json:"info"`
	Pass     float64 `json:"pass"`
}

func (r rawImpactTypes) counts() SeverityCounts {
	pass := int(r.Pass)
	return SeverityCounts{
		Critical: int(r.Critical), High: int(r.High), Medium: int(r.Medium),
		Low: int(r.Low), Warn: int(r.Warn), Info: int(r.Info), Pass: &pass,
	}
}

type rawAssessmentsResponse struct {
	Rows []struct {
		Ref         string `json:"ref"`
		Application struct {
			Ref  string `json:"ref"`
			Name string `json:"name"`
		} `json:"application"`
		BuildVersion   string  `json:"buildVersion"`
		CreatedAt      string  `json:"createdAt"`
		Origin         string  `json:"origin"`
		PackageKey     string  `json:"packageKey"`
		PlatformType   string  `json:"platformType"`
		Score          float64 `json:"score"`
		Status         string  `json:"status"`
		PackageVersion string  `json:"packageVersion"`
		Rating         string  `json:"rating"`
		Type           string  `json:"type"`
		AppliedPolicy  struct {
			Name string `json:"name"`
		} `json:"appliedPolicy"`
		ImpactTypes rawImpactTypes `json:"impactTypes"`
	} `json:"rows"`
	PageInfo rawCursorPage `json:"pageInfo"`
}

// ListAssessments lists assessments (scan history) for an application.
// The API requires narrowing by one of applicationRef, packageKey, or
// appstoreApplicationKey, so at least one must be provided.
func (c *Client) ListAssessments(ctx context.Context, p ListAssessmentsParams) (*AssessmentPage, error) {
	if p.ApplicationRef == "" && p.PackageKey == "" && p.AppstoreKey == "" {
		return nil, fmt.Errorf("one of app_ref, package, or appstore_key is required")
	}
	if p.PageSize < 0 {
		return nil, fmt.Errorf("page_size must not be negative")
	}
	if err := validateUUIDRefs("group_refs", "group UUIDs (from list_apps group_ref)", p.GroupRefs); err != nil {
		return nil, err
	}
	// Validate client-side: an unknown status/rating silently returns an empty
	// page and an unknown type leaks a raw upstream 500, both indistinguishable
	// from a real answer. Send the lowercased values upstream.
	platforms, err := validateEnum("platforms", p.PlatformTypes, enumPlatforms)
	if err != nil {
		return nil, err
	}
	status, err := validateEnum("status", p.Status, enumStatus)
	if err != nil {
		return nil, err
	}
	rating, err := validateEnum("rating", p.Rating, enumRating)
	if err != nil {
		return nil, err
	}
	typ, err := validateEnum("type", p.Type, enumType)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	f := filters{}
	f = f.add("applicationRef", p.ApplicationRef)
	f = f.add("packageKey", p.PackageKey)
	f = f.add("appstoreApplicationKey", p.AppstoreKey)
	f = f.add("since", p.Since)
	f = f.add("until", p.Until)
	if len(p.GroupRefs) > 0 {
		f = f.add("groupRefs", p.GroupRefs)
	}
	if len(platforms) > 0 {
		f = f.add("platformTypes", platforms)
	}
	if len(status) > 0 {
		f = f.add("status", status)
	}
	if len(rating) > 0 {
		f = f.add("rating", rating)
	}
	if len(typ) > 0 {
		f = f.add("type", typ)
	}
	f.apply(q)
	setOrderBy(q, p.OrderBy)
	pageSize := p.PageSize
	if pageSize == 0 {
		pageSize = pageSizeFromCursor(p.Cursor)
	}
	setInt(q, "pageSize", pageSize)
	setStr(q, "cursor", p.Cursor)

	var raw rawAssessmentsResponse
	if err := c.getJSON(ctx, "list assessments", "/v2/assessments", q, &raw); err != nil {
		return nil, err
	}
	out := &AssessmentPage{
		Assessments: make([]Assessment, 0, len(raw.Rows)),
		Page:        CursorPage{HasNextPage: raw.PageInfo.HasNextPage},
	}
	if raw.PageInfo.HasNextPage {
		out.Page.NextCursor = raw.PageInfo.Cursor
	}
	for _, r := range raw.Rows {
		// Store-monitor rows arrive without an application ref or applied
		// policy and have no lab analysis behind them: their findings cannot
		// be served and their pass count was never computed.
		track := "platform"
		counts := r.ImpactTypes.counts()
		if r.Application.Ref == "" && r.AppliedPolicy.Name == "" {
			track = "store_monitor"
			counts.Pass = nil
		}
		appRef := r.Application.Ref
		if appRef == "" && p.ApplicationRef != "" {
			appRef = p.ApplicationRef // rows can only belong to the app the query was scoped to
		}
		out.Assessments = append(out.Assessments, Assessment{
			Ref:               r.Ref,
			Title:             r.Application.Name,
			AppRef:            appRef,
			Track:             track,
			FindingsAvailable: track == "platform",
			Platform:          r.PlatformType,
			Package:           r.PackageKey,
			PackageVersion:    r.PackageVersion,
			BuildVersion:      r.BuildVersion,
			Score:             r.Score,
			Rating:            r.Rating,
			Status:            r.Status,
			Type:              r.Type,
			Origin:            r.Origin,
			CreatedAt:         normalizeTimestamp(r.CreatedAt),
			Policy:            r.AppliedPolicy.Name,
			Findings:          counts,
		})
	}
	return out, nil
}

// ---- per-assessment findings (compacted) ----------------------------------

// FindingsParams shapes get_assessment_findings.
type FindingsParams struct {
	AppRef           string   // application UUID from list_apps/list_assessments (required)
	AssessmentRef    string   // optional; assessment UUID or numeric task id; default = the app's latest assessment
	AffectedOnly     bool     // default true: only findings the app is affected by
	MinSeverity      string   // optional: info|warn|low|medium|high|critical
	Report           string   // optional report profile: lab-auto (default)|intel|niap
	Limit            int      // optional: cap the findings returned (most severe kept)
	CheckIDs         []string // optional: only these findings, with full untruncated recommendations
	IncludeRecs      bool     // include per-row recommendations (truncated); default false
	IncludeArtifacts bool     // include category=artifact inventory rows in the findings array; default false
}

type rawAppAssessment struct {
	Ref        string  `json:"ref"`
	Task       float64 `json:"task"`
	TaskStatus string  `json:"task_status"`
	Created    string  `json:"created"`
}

type rawFinding struct {
	CheckID         string  `json:"check_id"`
	Title           string  `json:"title"`
	Category        string  `json:"category"`
	Severity        string  `json:"severity"`
	Affected        bool    `json:"affected"`
	CVSS            float64 `json:"cvss"`
	AnalysisType    string  `json:"analysis_type"`
	Hidden          bool    `json:"hidden"`
	Recommendations struct {
		Developer string `json:"developer"`
	} `json:"recommendations"`
}

// resolveAssessment maps (platform, package, group, ref) to the assessment
// backing a findings fetch. The group ref is required because the same package
// can exist in multiple groups. ref may be an assessment UUID or a numeric
// analysis-task id (the form found in console URLs); when empty, the newest
// completed assessment is selected (falling back to the newest of any status).
// The per-app assessment list is cached; on a miss the cache is refreshed once
// so a freshly finished scan resolves without waiting out the TTL.
func (c *Client) resolveAssessment(ctx context.Context, platform, pkg, groupRef, ref string) (rawAppAssessment, error) {
	key := "appassess:" + platform + "/" + pkg + "/" + groupRef

	fetch := func(bypassCache bool) ([]rawAppAssessment, error) {
		if !bypassCache {
			if v, ok := c.cache.get(key); ok {
				return v.([]rawAppAssessment), nil
			}
		}
		path := fmt.Sprintf("/app/%s/%s/assessment", url.PathEscape(platform), url.PathEscape(pkg))
		q := url.Values{}
		setStr(q, "group", groupRef)
		var list []rawAppAssessment
		if err := c.getJSON(ctx, "resolve assessment task", path, q, &list); err != nil {
			return nil, err
		}
		// Sort newest-first before caching; cached slices are never mutated
		// afterwards (tool calls run concurrently and share the cache).
		sort.SliceStable(list, func(i, j int) bool { return list[i].Created > list[j].Created })
		c.cache.set(key, list)
		return list, nil
	}

	pick := func(list []rawAppAssessment) (rawAppAssessment, bool) {
		if ref == "" {
			for _, a := range list {
				if a.TaskStatus == "completed" {
					return a, true
				}
			}
			if len(list) > 0 {
				return list[0], true
			}
			return rawAppAssessment{}, false
		}
		for _, a := range list {
			if a.Ref == ref || strconv.FormatInt(int64(a.Task), 10) == ref {
				return a, true
			}
		}
		return rawAppAssessment{}, false
	}

	list, err := fetch(false)
	if err != nil {
		return rawAppAssessment{}, err
	}
	a, ok := pick(list)
	if !ok {
		// The cached list may predate a just-finished scan; refresh once.
		if list, err = fetch(true); err != nil {
			return rawAppAssessment{}, err
		}
		a, ok = pick(list)
	}
	if !ok {
		if ref != "" {
			return rawAppAssessment{}, fmt.Errorf("assessment %q not found among the lab-analyzed assessments of %s/%s — store-monitor refs (see list_assessments findings_available=false), other apps' refs, and unknown ids all land here; pick a row with findings_available=true or omit assessment_ref for the latest servable scan", ref, platform, pkg)
		}
		return rawAppAssessment{}, fmt.Errorf("no assessments found for %s/%s", platform, pkg)
	}
	return a, nil
}

var severityRank = map[string]int{
	"info": 0, "warn": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
}

// GetAssessmentFindings returns a compacted findings view for an assessment,
// resolving the app ref to its platform/package/group, then to the numeric
// analysis task, and finally stripping evidence from the report.
func (c *Client) GetAssessmentFindings(ctx context.Context, p FindingsParams) (*AssessmentFindings, error) {
	if p.AppRef == "" {
		return nil, fmt.Errorf("app_ref is required")
	}
	if p.Limit < 0 {
		return nil, fmt.Errorf("limit must not be negative")
	}
	minRank := -1
	if p.MinSeverity != "" {
		r, ok := severityRank[strings.ToLower(p.MinSeverity)]
		if !ok {
			return nil, fmt.Errorf("invalid min_severity %q (allowed: info, warn, low, medium, high, critical)", p.MinSeverity)
		}
		minRank = r
	}
	app, err := c.GetAppByRef(ctx, p.AppRef)
	if err != nil {
		return nil, err
	}
	// Default to the app's latest assessment when none is specified.
	targetRef := p.AssessmentRef
	if targetRef == "" {
		targetRef = app.AssessmentRef
	}
	assessment, err := c.resolveAssessment(ctx, app.Platform, app.Package, app.GroupRef, targetRef)
	if err != nil {
		return nil, err
	}
	report := p.Report
	if report == "" {
		report = "lab-auto"
	}
	switch report {
	case "lab-auto", "intel", "niap":
	default:
		return nil, fmt.Errorf("invalid report %q (allowed: lab-auto, intel, niap)", p.Report)
	}
	q := url.Values{}
	q.Set("report", report)

	var raw []rawFinding
	findKey := fmt.Sprintf("findings:%d:%s", int(assessment.Task), report)
	if v, ok := c.cache.get(findKey); ok {
		raw = v.([]rawFinding)
	} else {
		if err := c.getJSON(ctx, "get assessment findings", "/assessment/"+strconv.Itoa(int(assessment.Task))+"/findings", q, &raw); err != nil {
			return nil, err
		}
		// The loops below only read raw; cached slices are never mutated
		// afterwards (tool calls run concurrently and share the cache).
		c.cache.set(findKey, raw)
	}

	checkSet := make(map[string]struct{}, len(p.CheckIDs))
	for _, id := range p.CheckIDs {
		if id = strings.TrimSpace(id); id != "" {
			checkSet[strings.ToLower(id)] = struct{}{}
		}
	}

	out := &AssessmentFindings{
		AssessmentRef: assessment.Ref,
		Report:        report,
		Status:        assessment.TaskStatus,
		CreatedAt:     normalizeTimestamp(assessment.Created),
	}
	for _, r := range raw {
		if r.Hidden {
			continue
		}
		out.TotalFindings++
		if r.Affected {
			if strings.EqualFold(r.Category, "artifact") {
				out.Counts.Artifacts++
			} else {
				switch strings.ToLower(r.Severity) {
				case "critical":
					out.Counts.Critical++
				case "high":
					out.Counts.High++
				case "medium":
					out.Counts.Medium++
				case "low":
					out.Counts.Low++
				case "warn":
					out.Counts.Warn++
				case "info":
					out.Counts.Info++
				}
			}
		} else {
			if out.Counts.Pass == nil {
				out.Counts.Pass = new(int)
			}
			*out.Counts.Pass++
		}

		if p.AffectedOnly && !r.Affected {
			continue
		}
		if len(checkSet) > 0 {
			if _, ok := checkSet[strings.ToLower(r.CheckID)]; !ok {
				continue
			}
		} else if !p.IncludeArtifacts && strings.EqualFold(r.Category, "artifact") {
			// Artifact-category rows are inventory dumps, not scored vulns; they
			// stay in counts.artifacts but leave the findings array unless asked
			// for (an explicit check_ids match above always serves the row).
			continue
		}
		if minRank >= 0 {
			if rr, ok := severityRank[strings.ToLower(r.Severity)]; !ok || rr < minRank {
				continue
			}
		}
		// Recommendation prose dominates the payload, so it is opt-in: full
		// text when the caller scoped to specific check_ids, truncated under
		// include_recommendations, omitted otherwise (get_finding serves the
		// full remediation on demand).
		rec := ""
		if len(checkSet) > 0 {
			rec = strings.TrimSpace(r.Recommendations.Developer)
		} else if p.IncludeRecs {
			rec = truncate(strings.TrimSpace(r.Recommendations.Developer), 500)
		}
		out.Findings = append(out.Findings, AssessmentFinding{
			CheckID:        r.CheckID,
			Title:          r.Title,
			Category:       strings.ToLower(r.Category), // upstream mixes one Title Case value ("Resilience") into a lowercase set
			Severity:       r.Severity,
			Affected:       r.Affected,
			CVSS:           r.CVSS,
			AnalysisType:   r.AnalysisType,
			Recommendation: rec,
		})
	}
	// Sort most-severe first for triage.
	sort.SliceStable(out.Findings, func(i, j int) bool {
		return severityRank[strings.ToLower(out.Findings[i].Severity)] > severityRank[strings.ToLower(out.Findings[j].Severity)]
	})
	if p.Limit > 0 && len(out.Findings) > p.Limit {
		out.Findings = out.Findings[:p.Limit]
	}
	out.TotalReturned = len(out.Findings)
	return out, nil
}
