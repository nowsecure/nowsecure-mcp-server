package nsclient

// MARI-domain tests: ListMARIApps (1-based pagination, enum validation and
// canonical casing, created_at decode, page envelope) and GetMARIAssessment
// (expand capture/validation, identity threading, librariesAndSdks shaping,
// aiUsage trim, findings pass-through, decode errors).

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
	got, err := c.GetMARIAssessment(t.Context(), "ri-1", []string{"permissions"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary.TotalFindingsChecked != 50 || len(got.Findings) != 1 {
		t.Fatalf("core mapping wrong: %+v", got)
	}
	if _, ok := got.Expanded["permissions"]; !ok {
		t.Errorf("expected permissions captured in Expanded, got %v", got.Expanded)
	}
}

func TestGetMARIAssessment_BadExpand(t *testing.T) {
	c := New("http://unused", "tok")
	if _, err := c.GetMARIAssessment(t.Context(), "ri-1", []string{"nope"}); err == nil {
		t.Error("expected error for unsupported expand value")
	}
}

func TestGetMARIAssessment_FindingsPassThrough(t *testing.T) {
	// Upstream reports only affected findings; the client applies no filter of
	// its own, so every reported finding survives and summary totals are kept.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"createdAt":"2024-01-01","riskScore":40,"riskRating":"C",
			"summaryInfo":{"totalFindingsAffected":1,"totalFindingsChecked":2},
			"findings":[
				{"checkId":"a","title":"A","affected":true,"severity":"high"}
			]
		}`))
	})
	got, err := c.GetMARIAssessment(t.Context(), "ri-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || got.Findings[0].CheckID != "a" {
		t.Errorf("findings = %+v, want [a]", got.Findings)
	}
	if got.Summary.TotalFindingsChecked != 2 || got.Summary.TotalFindingsAffected != 1 {
		t.Errorf("summary = %+v, want totals preserved", got.Summary)
	}
}

func TestGetMARIAssessment_CoreDecodeError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// riskScore is a number in the model; a string must surface, not be
		// swallowed into a zeroed (== "no risk") profile.
		_, _ = w.Write([]byte(`{"riskScore":"not-a-number"}`))
	})
	_, err := c.GetMARIAssessment(t.Context(), "ri-1", nil)
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
	got, err := c.GetMARIAssessment(t.Context(), "ri-1", []string{"permissions"})
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
	got, err := c.GetMARIAssessment(t.Context(), "ri-1", nil)
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
	got, err = c.GetMARIAssessment(t.Context(), "ri-1", []string{"appInfo"})
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
	got, err := c.GetMARIAssessment(t.Context(), "ri-1", []string{"librariesAndSdks"})
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
	got, err := c.GetMARIAssessment(t.Context(), "ri-1", []string{"aiUsage"})
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
