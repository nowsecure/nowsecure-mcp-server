package nsclient

import (
	"net/http"
	"strings"
	"testing"
)

// searchCatalogClient serves a small GraphQL check catalog and counts hits so
// tests can assert the catalog is fetched once and cached.
func searchCatalogClient(t *testing.T) (client *Client, hitCount *int) {
	t.Helper()
	hits := new(int)
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			t.Fatalf("path = %q, want /graphql", r.URL.Path)
		}
		*hits++
		_, _ = w.Write([]byte(`{"data":{"findings":{"list":[
			{"id":"android_janus_vuln","title":"APK Vulnerable to the Janus Exploit","description":"The APK is signed with the v1 scheme only.","shortDescription":"","platformType":"android","deprecated":false,"categories":["Code Quality"],"coveredBy":[],
			 "issue":{"description":"The v1 signature scheme allows injecting a DEX prefix without breaking the signature.","impactSummary":"Attackers can ship modified clones.","category":"code","severity":"high"}},
			{"id":"android_janus_warn","title":"APK May Be Vulnerable to Janus","description":"","shortDescription":"","platformType":"android","deprecated":true,"categories":[],
			 "coveredBy":[{"id":"android_janus_vuln","title":"APK Vulnerable to the Janus Exploit"}],
			 "issue":{"description":"","impactSummary":"","category":"code","severity":"medium"}},
			{"id":"ios_ats_disabled","title":"App Transport Security Disabled","description":"","shortDescription":"","platformType":"ios","deprecated":false,"categories":["Network Security"],"coveredBy":[],
			 "issue":{"description":"Leading filler prose to push the interesting words past the snippet radius so both edges get cut: NSAllowsArbitraryLoads permits cleartext HTTP connections to any host, and that exposes session tokens plus user data to interception by an on-path attacker along the network path.","impactSummary":"","category":"network","severity":"medium"}},
			{"id":"keyboard_cache_check","title":"Keyboard Cache Enabled for Sensitive Fields","description":"Text entered into sensitive fields may be stored by the keyboard.","shortDescription":"","platformType":null,"deprecated":false,"categories":[],"coveredBy":[],
			 "issue":{"description":"","impactSummary":"","category":"storage","severity":"low"}},
			{"id":"apk_obfuscation_probe","title":"Obfuscation Missing","description":"","shortDescription":"","platformType":"android","deprecated":false,"categories":[],"coveredBy":[],
			 "issue":{"description":"","impactSummary":"","category":"Resilience","severity":"info"}}
		]}}}`))
	})
	return c, hits
}

func TestSearchFindings_KeyAndTitleMatch(t *testing.T) {
	c, _ := searchCatalogClient(t)
	got, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: "Janus"})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if got.Total != 1 || len(got.Findings) != 1 {
		t.Fatalf("total = %d, rows = %d, want 1 non-deprecated match", got.Total, len(got.Findings))
	}
	m := got.Findings[0]
	if m.Key != "android_janus_vuln" {
		t.Errorf("key = %q", m.Key)
	}
	if want := []string{"key", "title"}; strings.Join(m.MatchedIn, ",") != strings.Join(want, ",") {
		t.Errorf("matched_in = %v, want %v", m.MatchedIn, want)
	}
	if m.Snippet != "" {
		t.Errorf("snippet = %q, want empty when the match is visible in key/title", m.Snippet)
	}
	if m.Severity != "high" || m.Category != "code" || m.Platform != "android" {
		t.Errorf("row metadata = %q/%q/%q", m.Severity, m.Category, m.Platform)
	}
	if got.ExcludedDeprecated != 1 {
		t.Errorf("excluded_deprecated = %d, want 1 (android_janus_warn)", got.ExcludedDeprecated)
	}
}

func TestSearchFindings_IncludeDeprecatedRestoresCoveredBy(t *testing.T) {
	c, _ := searchCatalogClient(t)
	got, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: "janus", IncludeDeprecated: true})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if got.Total != 2 || got.ExcludedDeprecated != 0 {
		t.Fatalf("total = %d, excluded_deprecated = %d, want 2 and 0", got.Total, got.ExcludedDeprecated)
	}
	var warn *FindingSearchMatch
	for i := range got.Findings {
		if got.Findings[i].Key == "android_janus_warn" {
			warn = &got.Findings[i]
		}
	}
	if warn == nil { //nolint:staticcheck // SA5011 false positive: t.Fatal below halts the test
		t.Fatal("android_janus_warn missing from include_deprecated results")
	}
	if !warn.Deprecated { //nolint:staticcheck // SA5011 false positive: t.Fatal above halts the test
		t.Error("deprecated = false on the deprecated row")
	}
	if len(warn.CoveredBy) != 1 || warn.CoveredBy[0].ID != "android_janus_vuln" { //nolint:staticcheck // SA5011 false positive: t.Fatal above halts the test
		t.Errorf("covered_by = %+v", warn.CoveredBy)
	}
}

func TestSearchFindings_DescriptionOnlyMatchGetsSnippet(t *testing.T) {
	c, _ := searchCatalogClient(t)
	got, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: "cleartext"})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Key != "ios_ats_disabled" {
		t.Fatalf("findings = %+v, want just ios_ats_disabled", got.Findings)
	}
	m := got.Findings[0]
	if want := "description"; len(m.MatchedIn) != 1 || m.MatchedIn[0] != want {
		t.Errorf("matched_in = %v, want [%s]", m.MatchedIn, want)
	}
	if !strings.Contains(m.Snippet, "cleartext") {
		t.Errorf("snippet %q does not contain the needle", m.Snippet)
	}
	if !strings.HasPrefix(m.Snippet, "…") || !strings.HasSuffix(m.Snippet, "…") {
		t.Errorf("snippet %q should be cut (…) on both edges", m.Snippet)
	}
}

func TestSearchFindings_SpacesMatchKeyUnderscores(t *testing.T) {
	c, _ := searchCatalogClient(t)
	got, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: "janus vuln"})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Key != "android_janus_vuln" {
		t.Fatalf("findings = %+v, want android_janus_vuln via underscore mapping", got.Findings)
	}
	if m := got.Findings[0]; len(m.MatchedIn) != 1 || m.MatchedIn[0] != "key" {
		t.Errorf("matched_in = %v, want [key]", m.MatchedIn)
	}
}

func TestSearchFindings_CategoryMatch(t *testing.T) {
	c, _ := searchCatalogClient(t)

	// Lab category, case-insensitively (upstream mixes "Resilience" in).
	got, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: "resilience"})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Key != "apk_obfuscation_probe" {
		t.Fatalf("findings = %+v, want apk_obfuscation_probe", got.Findings)
	}
	if m := got.Findings[0]; len(m.MatchedIn) != 1 || m.MatchedIn[0] != "category" {
		t.Errorf("matched_in = %v, want [category]", m.MatchedIn)
	}
	if got.Findings[0].Category != "resilience" {
		t.Errorf("category = %q, want lowercased", got.Findings[0].Category)
	}

	// Capability-group list ("Code Quality") is part of the category bucket.
	got, err = c.SearchFindings(t.Context(), SearchFindingsParams{Query: "code quality"})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Key != "android_janus_vuln" {
		t.Fatalf("findings = %+v, want android_janus_vuln via categories", got.Findings)
	}
}

func TestSearchFindings_PlatformFilterKeepsCrossPlatform(t *testing.T) {
	c, _ := searchCatalogClient(t)
	// "sensitive" hits keyboard_cache_check (cross-platform, title) and nothing ios.
	got, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: "sensitive", Platform: "IOS"})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Key != "keyboard_cache_check" {
		t.Fatalf("findings = %+v, want the cross-platform row to pass an ios filter", got.Findings)
	}
	if got.Findings[0].Platform != "" {
		t.Errorf("platform = %q, want empty (applies to both)", got.Findings[0].Platform)
	}
	// The same query with an android filter also keeps the cross-platform row.
	got, err = c.SearchFindings(t.Context(), SearchFindingsParams{Query: "janus", Platform: "ios"})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if got.Total != 0 || got.ExcludedDeprecated != 0 {
		t.Errorf("total = %d, excluded_deprecated = %d, want 0 and 0 (android rows filtered before matching counts)", got.Total, got.ExcludedDeprecated)
	}
}

func TestSearchFindings_OrderingAndLimit(t *testing.T) {
	c, _ := searchCatalogClient(t)
	// "apk" hits android_janus_vuln (title) and apk_obfuscation_probe (key):
	// same rank, so alphabetical by key.
	got, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: "apk"})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if got.Total != 2 {
		t.Fatalf("total = %d, want 2", got.Total)
	}
	if got.Findings[0].Key != "android_janus_vuln" || got.Findings[1].Key != "apk_obfuscation_probe" {
		t.Errorf("order = %v", []string{got.Findings[0].Key, got.Findings[1].Key})
	}

	got, err = c.SearchFindings(t.Context(), SearchFindingsParams{Query: "apk", Limit: 1})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if got.TotalReturned != 1 || len(got.Findings) != 1 {
		t.Errorf("total_returned = %d, rows = %d, want 1", got.TotalReturned, len(got.Findings))
	}
	if got.Total != 2 {
		t.Errorf("total = %d, want the pre-limit match count", got.Total)
	}
}

func TestSearchFindings_ProseMatchesCarrySnippets(t *testing.T) {
	c, _ := searchCatalogClient(t)
	// "attack" appears only in prose: android_janus_vuln's impact summary
	// ("Attackers ...") and ios_ats_disabled's description ("... attacker ...").
	got, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: "attack"})
	if err != nil {
		t.Fatalf("SearchFindings: %v", err)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("findings = %+v, want 2 prose matches", got.Findings)
	}
	if got.Findings[0].Key != "android_janus_vuln" || got.Findings[1].Key != "ios_ats_disabled" {
		t.Errorf("order = %v, want alphabetical within the prose rank", []string{got.Findings[0].Key, got.Findings[1].Key})
	}
	if got.Findings[0].Snippet == "" || got.Findings[1].Snippet == "" {
		t.Error("prose-only matches should carry snippets")
	}
}

func TestSearchFindings_Validation(t *testing.T) {
	c, hits := searchCatalogClient(t)
	if _, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: "  "}); err == nil || !strings.Contains(err.Error(), "query is required") {
		t.Errorf("blank query error = %v", err)
	}
	if _, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: "x", Limit: -1}); err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Errorf("negative limit error = %v", err)
	}
	if _, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: "x", Platform: "windows"}); err == nil || !strings.Contains(err.Error(), "invalid platform") {
		t.Errorf("bad platform error = %v", err)
	}
	if *hits != 0 {
		t.Errorf("graphql hits = %d, want 0 (validation precedes the fetch)", *hits)
	}
}

func TestSearchFindings_CatalogCached(t *testing.T) {
	c, hits := searchCatalogClient(t)
	for _, q := range []string{"janus", "cleartext", "keyboard"} {
		if _, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: q}); err != nil {
			t.Fatalf("SearchFindings(%q): %v", q, err)
		}
	}
	if *hits != 1 {
		t.Errorf("graphql hits = %d, want 1 (catalog cached)", *hits)
	}
}

func TestSearchFindings_GraphQLErrorPropagates(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errors":[{"message":"boom"}]}`))
	})
	_, err := c.SearchFindings(t.Context(), SearchFindingsParams{Query: "janus"})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("error = %v, want the graphql message surfaced", err)
	}
}
