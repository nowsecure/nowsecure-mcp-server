package nsclient

// MARI-domain tests: ListMARIApps (1-based pagination, enum validation and
// canonical casing, created_at decode, page envelope) and GetMARIAssessment
// (expand capture/validation, identity threading, librariesAndSdks shaping,
// aiUsage trim, risk-card default, row selection, deep-dive prose tiers,
// decode errors).

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

// expandContains reports whether the comma-joined expand query holds want.
func expandContains(query, want string) bool {
	return slices.Contains(strings.Split(query, ","), want)
}

func TestListMARIApps_OffsetPaginationAndMapping(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/risk-intelligence/apps" {
			t.Fatalf("path %q", r.URL.Path)
		}
		// The tool's 1-based page 2 must reach the 0-based upstream as page 1.
		if r.URL.Query().Get("pageNumber") != "1" || r.URL.Query().Get("pageSize") != "10" {
			t.Errorf("pagination params = %q/%q", r.URL.Query().Get("pageNumber"), r.URL.Query().Get("pageSize"))
		}
		_, _ = w.Write([]byte(`{
			"rows":[{"title":"Bank","platform":"ios","applicationId":"123","packageName":"com.bank","recentScore":{"assessmentRef":"ri-1","riskScore":31.2,"riskRating":"D","riskCategory":"HIGH","riskRecommendation":"review"}}],
			"pageInfo":{"totalResults":57,"start":10,"end":20}
		}`))
	})
	got, err := c.ListMARIApps(t.Context(), ListMARIAppsParams{PageNumber: 2, PageSize: 10, RiskCategory: []string{"HIGH"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 57 || len(got.Apps) != 1 || got.Apps[0].RiskRating != "D" || got.Apps[0].AssessmentRef != "ri-1" {
		t.Fatalf("unexpected: %+v", got)
	}
	if !got.Page.HasNextPage || got.Page.NextPageNumber != 3 {
		t.Fatalf("page envelope = hasNext %v next %d, want true/3", got.Page.HasNextPage, got.Page.NextPageNumber)
	}
}

func TestListMARIApps_DecodesCreatedAt(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"rows":[{"title":"Bank","platform":"ios","applicationId":"123","packageName":"com.bank","createdAt":"2024-10-07T15:21:31.332+00:00","recentScore":{"assessmentRef":"ri-1","riskScore":31.2,"updatedAt":"2025-01-01T00:00:00Z"}}],
			"pageInfo":{"totalResults":1,"start":0,"end":1}
		}`))
	})
	got, err := c.ListMARIApps(t.Context(), ListMARIAppsParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Apps) != 1 {
		t.Fatalf("apps = %d, want 1", len(got.Apps))
	}
	if got.Apps[0].CreatedAt != "2024-10-07T15:21:31.332+00:00" {
		t.Errorf("created_at = %q, want catalog-added date", got.Apps[0].CreatedAt)
	}
	if got.Apps[0].UpdatedAt != "2025-01-01T00:00:00Z" {
		t.Errorf("updated_at = %q, want recentScore date", got.Apps[0].UpdatedAt)
	}
}

func TestListMARIApps_EnumsValidatedClientSide(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("request must not reach upstream")
	})
	for _, tc := range []struct {
		params ListMARIAppsParams
		want   string
	}{
		{ListMARIAppsParams{Rating: []string{"G"}}, `invalid rating "G" (allowed: A, B, C, D, F)`},
		{ListMARIAppsParams{Platform: "windows"}, `invalid platform "windows" (allowed: android, ios)`},
		{ListMARIAppsParams{RiskCategory: []string{"SEVERE"}}, `invalid risk_category "SEVERE" (allowed: LOW, MEDIUM, HIGH)`},
	} {
		_, err := c.ListMARIApps(t.Context(), tc.params)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("params %+v: got %v, want %q", tc.params, err, tc.want)
		}
	}
}

func TestListMARIApps_EnumsCanonicalized(t *testing.T) {
	var gotFilters string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotFilters = r.URL.Query().Get("filters")
		_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"totalResults":0,"start":0,"end":0}}`))
	})
	_, err := c.ListMARIApps(t.Context(), ListMARIAppsParams{Platform: "ANDROID", Rating: []string{"a"}, RiskCategory: []string{"low"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"android"`, `["A"]`, `["LOW"]`} {
		if !strings.Contains(gotFilters, want) {
			t.Errorf("filters %q missing canonical %s", gotFilters, want)
		}
	}
}

func TestGetMARIAssessment_ExpandCaptured(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// appInfo is always fetched for identity, alongside the caller's request.
		exp := r.URL.Query().Get("expand")
		if !expandContains(exp, "permissions") || !expandContains(exp, "appInfo") {
			t.Errorf("expand = %q, want permissions+appInfo", exp)
		}
		_, _ = w.Write([]byte(`{
			"createdAt":"2024-01-01","riskScore":40,"riskRating":"C","riskCategory":"MEDIUM",
			"summaryInfo":{"totalFindingsAffected":2,"totalFindingsChecked":50},
			"findings":[{"checkId":"c1","title":"T","affected":true,"severity":"high","cvssScore":7.1,"categories":["Privacy"]}],
			"permissions":{"summary":{"totalPermissions":9}}
		}`))
	})
	got, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", Expand: []string{"permissions"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary.TotalFindingsChecked != 50 || len(got.Findings) != 0 || got.FindingsOmitted != 1 {
		t.Fatalf("core mapping wrong: %+v", got)
	}
	if _, ok := got.Expanded["permissions"]; !ok {
		t.Errorf("expected permissions captured in Expanded, got %v", got.Expanded)
	}
}

func TestGetMARIAssessment_BadExpand(t *testing.T) {
	c := New("http://unused", "tok")
	if _, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", Expand: []string{"nope"}}); err == nil {
		t.Error("expected error for unsupported expand value")
	}
}

// riskCardBody is a four-finding fixture (mixed severities, deliberately not
// severity-ordered, full prose on every row) shared by the risk-card, row
// selection, and deep-dive tests.
const riskCardBody = `{
	"createdAt":"2024-01-01","riskScore":40,"riskRating":"C",
	"nowSecureRiskScoresByFindingCategory":{"Storage":80.1,"Privacy":63.2,"Endpoint":0},
	"categoryImpactBreakdown":{"Storage":33.91,"Endpoint":0},
	"summaryInfo":{"totalFindingsAffected":3,"totalFindingsChecked":9},
	"findings":[
		{"checkId":"med","title":"M","affected":true,"severity":"medium","cvssScore":5.7,"shortDescription":"med short","description":"med full","businessImpact":"med impact","analysisType":"static",
			"regulations":[{"label":"CWE","links":[{"title":"346","url":"https://cwe.example/346"}]}]},
		{"checkId":"info","title":"I","affected":true,"severity":"info","shortDescription":"info short","description":"info full","analysisType":"dynamic"},
		{"checkId":"crit","title":"C","affected":true,"severity":"critical","rating":9,"shortDescription":"crit short","description":"crit full","businessImpact":"crit impact","analysisType":"dynamic"},
		{"checkId":"clean","title":"OK","affected":false,"severity":"low","shortDescription":"clean short"}
	]
}`

func TestGetMARIAssessment_DefaultRiskCard(t *testing.T) {
	// The default response is a compact risk card: severity counts and the
	// category breakdowns stand in for the finding rows, which are omitted
	// and accounted for in findings_omitted.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(riskCardBody))
	})
	got, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 0 || got.FindingsOmitted != 4 {
		t.Errorf("findings = %d rows, omitted %d, want 0/4", len(got.Findings), got.FindingsOmitted)
	}
	if got.Summary.TotalFindingsChecked != 9 || got.Summary.TotalFindingsAffected != 3 {
		t.Errorf("summary = %+v, want totals preserved", got.Summary)
	}
	counts := got.Summary.Counts
	if counts.Critical != 1 || counts.Medium != 1 || counts.Info != 1 || counts.High != 0 {
		t.Errorf("counts = %+v, want critical/medium/info = 1", counts)
	}
	// The unaffected row lands in pass, not a severity bucket.
	if counts.Low != 0 || counts.Pass == nil || *counts.Pass != 1 {
		t.Errorf("counts = %+v, want low 0 and pass 1", counts)
	}
	// Category maps are kept, zero-score categories dropped.
	if got.NowSecureRiskScoresByCategory["Storage"] != 80.1 || got.NowSecureRiskScoresByCategory["Privacy"] != 63.2 {
		t.Errorf("risk scores by category = %v, want Storage 80.1 / Privacy 63.2", got.NowSecureRiskScoresByCategory)
	}
	if _, ok := got.NowSecureRiskScoresByCategory["Endpoint"]; ok {
		t.Errorf("zero-score category must be dropped: %v", got.NowSecureRiskScoresByCategory)
	}
	if got.CategoryImpactBreakdown["Storage"] != 33.91 || len(got.CategoryImpactBreakdown) != 1 {
		t.Errorf("impact breakdown = %v, want only Storage 33.91", got.CategoryImpactBreakdown)
	}
}

func TestGetMARIAssessment_RowSelection(t *testing.T) {
	// min_severity / limit / include_descriptions opt into rows, always
	// sorted most-severe first; counts and findings_omitted keep covering
	// the full report.
	handler := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(riskCardBody))
	}

	c := newTestClient(t, handler)
	got, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", MinSeverity: "medium"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 2 || got.Findings[0].CheckID != "crit" || got.Findings[1].CheckID != "med" {
		t.Fatalf("min_severity=medium rows = %+v, want [crit med]", got.Findings)
	}
	if got.FindingsOmitted != 2 {
		t.Errorf("findings_omitted = %d, want 2", got.FindingsOmitted)
	}
	if got.Summary.Counts.Info != 1 {
		t.Errorf("counts must cover filtered-out rows: %+v", got.Summary.Counts)
	}
	// Plain rows carry scalars but no prose tier.
	crit := got.Findings[0]
	if crit.Rating != 9 || crit.AnalysisType != "dynamic" || got.Findings[1].CVSSScore != 5.7 {
		t.Errorf("row scalars wrong: %+v", got.Findings)
	}
	if crit.ShortDescription != "" || crit.Description != "" || crit.BusinessImpact != "" || crit.Regulations != nil {
		t.Errorf("prose must be omitted on plain rows: %+v", crit)
	}

	c = newTestClient(t, handler)
	got, err = c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || got.Findings[0].CheckID != "crit" || got.FindingsOmitted != 3 {
		t.Errorf("limit=1 = %+v (omitted %d), want just crit / 3", got.Findings, got.FindingsOmitted)
	}

	// include_descriptions alone returns every row, with short_description.
	c = newTestClient(t, handler)
	got, err = c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", IncludeDescriptions: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 4 || got.FindingsOmitted != 0 {
		t.Fatalf("include_descriptions rows = %d (omitted %d), want 4/0", len(got.Findings), got.FindingsOmitted)
	}
	if got.Findings[0].CheckID != "crit" || got.Findings[0].ShortDescription != "crit short" {
		t.Errorf("first row = %+v, want crit with short prose", got.Findings[0])
	}
	if got.Findings[0].Description != "" {
		t.Errorf("deep prose must stay check_ids-only: %+v", got.Findings[0])
	}
}

func TestGetMARIAssessment_CheckIDsDeepDive(t *testing.T) {
	// check_ids scopes the rows and returns the full prose tier: short and
	// full descriptions, business impact, and regulation mappings.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(riskCardBody))
	})
	got, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", CheckIDs: []string{" MED ", "crit"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 2 || got.Findings[0].CheckID != "crit" || got.Findings[1].CheckID != "med" {
		t.Fatalf("check_ids rows = %+v, want [crit med] (trimmed, case-insensitive, severity-sorted)", got.Findings)
	}
	med := got.Findings[1]
	if med.ShortDescription != "med short" || med.Description != "med full" || med.BusinessImpact != "med impact" {
		t.Errorf("deep-dive prose = %+v, want all tiers populated", med)
	}
	if len(med.Regulations) != 1 || med.Regulations[0].Label != "CWE" || med.Regulations[0].Links[0].URL != "https://cwe.example/346" {
		t.Errorf("regulations = %+v, want the CWE mapping", med.Regulations)
	}
	if got.FindingsOmitted != 2 {
		t.Errorf("findings_omitted = %d, want 2", got.FindingsOmitted)
	}
}

func TestGetMARIAssessment_UnknownSeverity(t *testing.T) {
	// A severity outside the known set must not vanish: it counts as info and
	// min_severity=info (the "every row" tier) still returns it, while higher
	// thresholds exclude it.
	handler := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"riskScore":40,"summaryInfo":{"totalFindingsAffected":2,"totalFindingsChecked":2},
			"findings":[
				{"checkId":"hi","title":"H","affected":true,"severity":"high"},
				{"checkId":"odd","title":"O","affected":true,"severity":"brand-new-label"}
			]
		}`))
	}
	c := newTestClient(t, handler)
	got, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", MinSeverity: "info"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 2 || got.Summary.Counts.Info != 1 || got.Summary.Counts.High != 1 {
		t.Errorf("min_severity=info rows = %+v counts = %+v, want both rows, unknown counted as info", got.Findings, got.Summary.Counts)
	}
	c = newTestClient(t, handler)
	got, err = c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", MinSeverity: "low"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || got.Findings[0].CheckID != "hi" {
		t.Errorf("min_severity=low rows = %+v, want unknown severity excluded", got.Findings)
	}
}

func TestGetMARIAssessment_BlankCheckIDsStayRiskCard(t *testing.T) {
	// check_ids of only blank strings reads as unset: the caller scoped to
	// nothing, so the response stays a risk card instead of dumping all rows.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(riskCardBody))
	})
	got, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", CheckIDs: []string{" ", ""}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 0 || got.FindingsOmitted != 4 {
		t.Errorf("blank check_ids = %d rows (omitted %d), want the risk card (0/4)", len(got.Findings), got.FindingsOmitted)
	}
}

func TestGetMARIAssessment_RowParamValidation(t *testing.T) {
	c := New("http://unused", "tok")
	if _, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", MinSeverity: "urgent"}); err == nil ||
		!strings.Contains(err.Error(), `invalid min_severity "urgent" (allowed: info, warn, low, medium, high, critical)`) {
		t.Errorf("min_severity error = %v, want the enum list", err)
	}
	if _, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", Limit: -1}); err == nil ||
		!strings.Contains(err.Error(), "limit must not be negative") {
		t.Errorf("limit error = %v, want negative-limit rejection", err)
	}
}

func TestGetMARIAssessment_CoreDecodeError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// riskScore is a number in the model; a string must surface, not be
		// swallowed into a zeroed (== "no risk") profile.
		_, _ = w.Write([]byte(`{"riskScore":"not-a-number"}`))
	})
	_, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1"})
	if err == nil || !strings.Contains(err.Error(), "decoding response") {
		t.Fatalf("error = %v, want 'decoding response'", err)
	}
}

func TestGetMARIAssessment_ExpandedIsDecodedMap(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		exp := r.URL.Query().Get("expand")
		if !expandContains(exp, "permissions") || !expandContains(exp, "appInfo") {
			t.Errorf("expand = %q, want permissions+appInfo", exp)
		}
		_, _ = w.Write([]byte(`{
			"riskScore":10,
			"summaryInfo":{"totalFindingsAffected":0,"totalFindingsChecked":1},
			"findings":[],
			"permissions":{"summary":{"totalPermissions":9}}
		}`))
	})
	got, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", Expand: []string{"permissions"}})
	if err != nil {
		t.Fatal(err)
	}
	perms, ok := got.Expanded["permissions"].(map[string]any)
	if !ok {
		t.Fatalf("Expanded[permissions] = %T, want map[string]any", got.Expanded["permissions"])
	}
	summary, ok := perms["summary"].(map[string]any)
	if !ok {
		t.Fatalf("permissions.summary = %T, want map[string]any", perms["summary"])
	}
	if summary["totalPermissions"] != float64(9) {
		t.Errorf("totalPermissions = %v, want 9", summary["totalPermissions"])
	}
}

func TestGetMARIAssessment_IdentityFromAppInfo(t *testing.T) {
	// Upstream reports identity only inside appInfo; the default response omits
	// title/packageName/platform. The client threads them onto the top level.
	body := `{
		"createdAt":"2024-05-01T00:00:00Z","riskScore":40,"riskRating":"C","riskCategory":"MEDIUM",
		"summaryInfo":{"totalFindingsAffected":0,"totalFindingsChecked":1},"findings":[],
		"appInfo":{"title":"WhatsApp","packageName":"com.whatsapp","platform":"android","iconUrl":"https://x/i.png","icon":"BIGBASE64","createdAt":null}
	}`

	// Caller did not request appInfo: identity threaded, app_info absent from Expanded.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !expandContains(r.URL.Query().Get("expand"), "appInfo") {
			t.Errorf("expand = %q, want appInfo always included", r.URL.Query().Get("expand"))
		}
		_, _ = w.Write([]byte(body))
	})
	got, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "WhatsApp" || got.Package != "com.whatsapp" || got.Platform != "android" {
		t.Errorf("identity = %q/%q/%q, want WhatsApp/com.whatsapp/android", got.Title, got.Package, got.Platform)
	}
	if _, ok := got.Expanded["app_info"]; ok {
		t.Errorf("app_info must not appear in Expanded when not requested: %v", got.Expanded)
	}

	// Caller requested appInfo: identity still threaded, app_info in Expanded with icon stripped.
	c = newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	got, err = c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", Expand: []string{"appInfo"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "WhatsApp" {
		t.Errorf("title = %q, want WhatsApp", got.Title)
	}
	ai, ok := got.Expanded["app_info"].(map[string]any)
	if !ok {
		t.Fatalf("Expanded[app_info] = %T, want map[string]any", got.Expanded["app_info"])
	}
	if _, ok := ai["icon"]; ok {
		t.Errorf("icon must be stripped from app_info: %v", ai)
	}
	if ai["iconUrl"] != "https://x/i.png" {
		t.Errorf("iconUrl = %v, want kept", ai["iconUrl"])
	}
}

func TestGetMARIAssessment_LibrariesAndSdksShaped(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"riskScore":50,"summaryInfo":{"totalFindingsAffected":0,"totalFindingsChecked":1},"findings":[],
			"librariesAndSdks":{
				"description":"desc","businessImpact":"impact","categories":["Code Quality"],
				"summary":{"totalComponents":5,"componentsWithCves":4},
				"components":[
					{"name":"libpng","version":"1.6.34","source":"/a/libmainstone.so","cveCount":4,"highestCvssScore":8.1},
					{"name":"OpenSSL","version":"1.0.2k","source":"/a/libwcdb.so","cveCount":36,"highestCvssScore":9.8},
					{"name":"FFmpeg","version":"1.0.2","source":"/a/libffavc.so","cveCount":158,"highestCvssScore":10},
					{"name":"libpng","version":"1.6.34","source":"/a/libopencv.so","cveCount":4,"highestCvssScore":8.1},
					{"name":"_COROUTINE","version":null,"source":"/base.apk/classes.dex","cveCount":0,"highestCvssScore":null}
				]
			}
		}`))
	})
	got, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", Expand: []string{"librariesAndSdks"}})
	if err != nil {
		t.Fatal(err)
	}
	shaped, ok := got.Expanded["libraries_and_sdks"].(*shapedLibrariesAndSdks)
	if !ok {
		t.Fatalf("libraries_and_sdks = %T, want *shapedLibrariesAndSdks", got.Expanded["libraries_and_sdks"])
	}
	if shaped.Description != "desc" || shaped.BusinessImpact != "impact" {
		t.Errorf("prose fields dropped: %+v", shaped)
	}
	if shaped.OmittedComponents != 1 {
		t.Errorf("omitted_components = %d, want 1 (clean components dropped)", shaped.OmittedComponents)
	}
	if len(shaped.CVEComponents) != 3 {
		t.Fatalf("cve_components = %d, want 3 (libpng deduped): %+v", len(shaped.CVEComponents), shaped.CVEComponents)
	}
	// Riskiest first by CVE count.
	if shaped.CVEComponents[0].Name != "FFmpeg" || shaped.CVEComponents[0].CVECount != 158 {
		t.Errorf("first = %+v, want FFmpeg/158", shaped.CVEComponents[0])
	}
	if shaped.CVEComponents[1].Name != "OpenSSL" {
		t.Errorf("second = %+v, want OpenSSL", shaped.CVEComponents[1])
	}
	// libpng deduped into one entry carrying both source paths.
	png := shaped.CVEComponents[2]
	if png.Name != "libpng" || png.Version != "1.6.34" || len(png.Sources) != 2 {
		t.Errorf("libpng entry = %+v, want one entry with two sources", png)
	}
}

func TestGetMARIAssessment_AIUsageTrimmed(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"riskScore":10,"summaryInfo":{"totalFindingsAffected":0,"totalFindingsChecked":1},"findings":[],
			"aiUsage":{
				"onDevice":{"affected":false,"shortDescription":"boilerplate","evidenceCount":0,"evidence":[],"categories":["Privacy"]},
				"cloudBased":{"affected":true,"shortDescription":"keep me","evidenceCount":2,"evidence":[{"x":1}],"categories":["Privacy"]}
			}
		}`))
	})
	got, err := c.GetMARIAssessment(t.Context(), MARIAssessmentParams{AssessmentRef: "ri-1", Expand: []string{"aiUsage"}})
	if err != nil {
		t.Fatal(err)
	}
	ai, ok := got.Expanded["ai_usage"].(map[string]any)
	if !ok {
		t.Fatalf("ai_usage = %T, want map[string]any", got.Expanded["ai_usage"])
	}
	onDevice, _ := ai["onDevice"].(map[string]any)
	if len(onDevice) != 1 || onDevice["affected"] != false {
		t.Errorf("onDevice = %v, want reduced to {affected:false}", onDevice)
	}
	cloud, _ := ai["cloudBased"].(map[string]any)
	if cloud["shortDescription"] != "keep me" {
		t.Errorf("cloudBased (affected) = %v, want untouched", cloud)
	}
}
