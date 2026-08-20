package nsclient

// These are the compact, purpose-built shapes the client returns. They are the
// MCP-facing contract: small, flat, and free of evidence dumps. Raw API decode
// structs live alongside each endpoint's method and are mapped into these.

// CursorPage is cursor-based pagination metadata (portfolio, assessments).
type CursorPage struct {
	HasNextPage bool   `json:"has_next_page"`
	NextCursor  string `json:"next_cursor,omitempty"`
}

// App is a portfolio application (one per app, latest assessment referenced).
// Score is a pointer so an app that has never been assessed is distinguishable
// from one that scored an actual 0 (score and assessment_ref are omitted).
type App struct {
	AppRef             string   `json:"app_ref"`
	AssessmentRef      string   `json:"assessment_ref,omitempty"`
	Title              string   `json:"title"`
	Platform           string   `json:"platform"`
	Package            string   `json:"package"`
	Score              *float64 `json:"score,omitempty"`
	Rating             string   `json:"rating,omitempty"`
	VulnerabilityCount int      `json:"vulnerability_count"`
	Group              string   `json:"group,omitempty"`
	GroupRef           string   `json:"group_ref,omitempty"`
}

// PortfolioSummary is the optional score/rating aggregate opted into with
// include_summary; the row total lives on AppPage.Total, always populated.
type PortfolioSummary struct {
	PortfolioScore  float64 `json:"portfolio_score"`
	PortfolioRating string  `json:"portfolio_rating,omitempty"`
}

// AppPage is a page of portfolio applications. Total is the full match count
// (no omitempty): it ships even at zero so the caller always sees the size.
type AppPage struct {
	Apps    []App             `json:"apps"`
	Total   int               `json:"total"`
	Page    CursorPage        `json:"page"`
	Summary *PortfolioSummary `json:"summary,omitempty"`
}

// SeverityCounts summarizes findings by severity for an assessment. Pass is a
// pointer so rows where pass was never computed (store-monitor scans) omit it
// instead of reporting a fake 0. Artifacts counts affected rows in the
// "artifact" category (extracted files, screenshots), which upstream labels
// severity info; only the per-assessment findings report can distinguish them.
type SeverityCounts struct {
	Critical  int  `json:"critical"`
	High      int  `json:"high"`
	Medium    int  `json:"medium"`
	Low       int  `json:"low"`
	Warn      int  `json:"warn"`
	Info      int  `json:"info"`
	Artifacts int  `json:"artifacts,omitempty"`
	Pass      *int `json:"pass,omitempty"`
}

// Assessment is one assessment (scan) in the portfolio history. Track is
// "platform" for NowSecure Platform assessments, "store_monitor" for store
// monitoring, or "external" for pen-test/workstation assessments.
// FindingsAvailable says whether get_assessment_findings can serve this ref;
// only platform rows can.
type Assessment struct {
	Ref               string `json:"assessment_ref"`
	Title             string `json:"title,omitempty"`
	AppRef            string `json:"app_ref,omitempty"`
	Track             string `json:"track"`
	FindingsAvailable bool   `json:"findings_available"`

	Platform       string         `json:"platform"`
	Package        string         `json:"package"`
	PackageVersion string         `json:"package_version,omitempty"`
	BuildVersion   string         `json:"build_version,omitempty"`
	Score          float64        `json:"score"`
	Rating         string         `json:"rating,omitempty"`
	Status         string         `json:"status"`
	Type           string         `json:"type,omitempty"`
	Origin         string         `json:"origin,omitempty"`
	CreatedAt      string         `json:"created_at,omitempty"`
	Policy         string         `json:"policy,omitempty"`
	Findings       SeverityCounts `json:"findings"`
}

// AssessmentPage is a page of assessments.
type AssessmentPage struct {
	Assessments []Assessment `json:"assessments"`
	Page        CursorPage   `json:"page"`
}

// AssessmentFinding is a single finding, compacted (no evidence/context).
type AssessmentFinding struct {
	CheckID        string  `json:"check_id"`
	Title          string  `json:"title"`
	Category       string  `json:"category,omitempty"`
	Severity       string  `json:"severity"`
	Affected       bool    `json:"affected"`
	CVSS           float64 `json:"cvss,omitempty"`
	AnalysisType   string  `json:"analysis_type,omitempty"`
	Recommendation string  `json:"recommendation,omitempty"`
}

// AssessmentFindings is the compacted findings view of one assessment.
// Status/CreatedAt tell the caller whether the scan is completed and how fresh
// it is — the default-latest path can fall back to a processing or failed scan.
// TotalFindings counts every non-hidden finding in the report; TotalReturned
// is what survived the affected_only/min_severity/limit filters.
type AssessmentFindings struct {
	AssessmentRef string              `json:"assessment_ref"`
	Report        string              `json:"report,omitempty" jsonschema:"the report profile these findings came from"`
	Status        string              `json:"status,omitempty"`
	CreatedAt     string              `json:"created_at,omitempty"`
	Counts        SeverityCounts      `json:"counts"`
	TotalReturned int                 `json:"total_returned"`
	TotalFindings int                 `json:"total_findings"`
	Findings      []AssessmentFinding `json:"findings"`
}

// CoveredBy names a replacement finding for a deprecated one.
type CoveredBy struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// FindingDoc is finding documentation/metadata (no per-app evidence).
type FindingDoc struct {
	Key                      string      `json:"key"`
	Title                    string      `json:"title"`
	Category                 string      `json:"category,omitempty"`
	Categories               []string    `json:"categories,omitempty"`
	Platform                 string      `json:"platform,omitempty"`
	SeverityMin              string      `json:"severity_min,omitempty"`
	SeverityMax              string      `json:"severity_max,omitempty"`
	CVSSMin                  float64     `json:"cvss_min,omitempty"`
	CVSSMax                  float64     `json:"cvss_max,omitempty"`
	FindingType              string      `json:"finding_type,omitempty"`
	AnalysisType             string      `json:"analysis_type,omitempty"`
	ApplicationCount         int         `json:"application_count" jsonschema:"portfolio apps whose latest assessment is affected"`
	Description              string      `json:"description,omitempty"`
	StepsToReproduce         string      `json:"steps_to_reproduce,omitempty"`
	TestingMethod            string      `json:"testing_method,omitempty" jsonschema:"omitted when identical to steps_to_reproduce"`
	TestingMethodSameAsSteps bool        `json:"testing_method_same_as_steps,omitempty" jsonschema:"true when upstream's testing_method duplicated steps_to_reproduce and was omitted"`
	Remediation              string      `json:"remediation,omitempty" jsonschema:"markdown remediation guidance"`
	Deprecated               bool        `json:"deprecated,omitempty"`
	CoveredBy                []CoveredBy `json:"covered_by,omitempty"`
}

// FindingSearchMatch is one finding-catalog row matched by search_findings.
// MatchedIn names the matched buckets in fixed order (key, title, description,
// category); Snippet carries prose context only when the match is not visible
// in the row's own key or title. Platform is omitted for findings that apply
// to both android and ios.
type FindingSearchMatch struct {
	Key        string      `json:"key"`
	Title      string      `json:"title"`
	Platform   string      `json:"platform,omitempty"`
	Severity   string      `json:"severity,omitempty" jsonschema:"typical severity of the finding when an app is affected"`
	Category   string      `json:"category,omitempty" jsonschema:"lab analysis category (matches get_assessment_findings rows)"`
	Deprecated bool        `json:"deprecated,omitempty"`
	CoveredBy  []CoveredBy `json:"covered_by,omitempty" jsonschema:"replacement findings for a deprecated one"`
	MatchedIn  []string    `json:"matched_in"`
	Snippet    string      `json:"snippet,omitempty" jsonschema:"prose context around the match when it is only visible in description text"`
}

// FindingSearchResult is a catalog text-search result. Total counts every
// match (no omitempty — zero is the answer); ExcludedDeprecated counts matches
// hidden by the default deprecated filter so a thin result stays explainable.
type FindingSearchResult struct {
	Query              string               `json:"query"`
	Total              int                  `json:"total"`
	TotalReturned      int                  `json:"total_returned"`
	ExcludedDeprecated int                  `json:"excluded_deprecated,omitempty" jsonschema:"matches hidden because the finding is deprecated; include_deprecated=true restores them"`
	Findings           []FindingSearchMatch `json:"findings"`
}

// AffectedApp is one app whose latest assessment is affected by a finding.
// CreatedAt is that latest assessment's date (what order_by=createdAt sorts on).
type AffectedApp struct {
	AppRef         string `json:"app_ref"`
	AssessmentRef  string `json:"assessment_ref,omitempty"`
	Title          string `json:"title"`
	Platform       string `json:"platform"`
	Package        string `json:"package"`
	PackageVersion string `json:"package_version,omitempty"`
	BuildVersion   string `json:"build_version,omitempty"`
	Group          string `json:"group,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
}

// AffectedAppPage is a page of affected apps. Total keeps its zero value (no
// omitempty): a platform filter orthogonal to the finding's platform returns
// an empty page, and total:0 is the signal the caller needs to see.
type AffectedAppPage struct {
	Finding string        `json:"finding"`
	Apps    []AffectedApp `json:"apps"`
	Page    CursorPage    `json:"page"`
	Total   int           `json:"total"`
}
