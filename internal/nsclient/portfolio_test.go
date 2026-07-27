package nsclient

// Portfolio-domain tests: ListApps (filters, score pointer, cursor stride,
// threshold_severity validation, search), GetAppByRef, GetFinding (cache,
// escaping, testing_method dedup, 404 catalog suggestions), and
// AppsAffectedByFinding (summary mapping, epoch conversion, total:0).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestListApps_FiltersAndMapping(t *testing.T) {
	var requests atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/v2/portfolio/applications" {
			t.Fatalf("path = %q", got)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token" {
			t.Errorf("auth header = %q", auth)
		}
		if ps := r.URL.Query().Get("pageSize"); ps != "50" {
			t.Errorf("pageSize = %q, want 50-row scan window", ps)
		}
		if r.URL.Query().Get("orderBy") != "-score" {
			t.Errorf("orderBy = %q", r.URL.Query().Get("orderBy"))
		}

		var f []map[string]any
		if encoded := r.URL.Query().Get("filters"); encoded != "" {
			if err := json.Unmarshal([]byte(encoded), &f); err != nil {
				t.Fatalf("filters not JSON: %v (%q)", err, encoded)
			}
		}
		switch requests.Add(1) {
		case 1:
			// The source walk must keep threshold filters off the request so
			// its cursor reflects the full sorted envelope.
			if len(f) != 0 {
				t.Errorf("source filters = %v, want none", f)
			}
		case 2:
			// Severity cannot be inferred from score/rating, so it is queried
			// over the same source window. Score is evaluated from the row.
			if len(f) != 1 || f[0]["name"] != "thresholdSeverity" || f[0]["value"] != "high" {
				t.Errorf("severity filters = %v, want thresholdSeverity=high only", f)
			}
		default:
			t.Fatalf("unexpected request %d", requests.Load())
		}
		_, _ = w.Write([]byte(`{
			"rows":[{"ref":"app-1","assessmentRef":"as-1","platform":"android","package":"com.x","title":"X","score":42.5,"rating":"poor","vulnerabilityCount":3,"group":{"ref":"g1","name":"Team A"}}],
			"pageInfo":{"hasNextPage":false}
		}`))
	})
	score := 80.0
	got, err := c.ListApps(t.Context(), ListAppsParams{ThresholdScore: &score, ThresholdSeverity: "high", OrderBy: "-score"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Apps) != 1 || got.Apps[0].AppRef != "app-1" || got.Apps[0].Group != "Team A" {
		t.Fatalf("unexpected apps: %+v", got.Apps)
	}
	if got.Page.HasNextPage || got.Page.NextCursor != "" {
		t.Errorf("pagination = %+v", got.Page)
	}
	if requests.Load() != 2 {
		t.Errorf("requests = %d, want source + severity", requests.Load())
	}
}

func TestListApps_ScorePointer(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rows":[
			{"ref":"app-a","platform":"ios","package":"com.a","title":"Unassessed"},
			{"ref":"app-b","platform":"ios","package":"com.b","title":"Assessed","score":42.5}
		],"pageInfo":{"hasNextPage":false}}`))
	})
	got, err := c.ListApps(t.Context(), ListAppsParams{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Apps[0].Score != nil {
		t.Errorf("unassessed app Score = %v, want nil", *got.Apps[0].Score)
	}
	if got.Apps[1].Score == nil || *got.Apps[1].Score != 42.5 {
		t.Errorf("scored app Score = %v, want 42.5", got.Apps[1].Score)
	}
	// A nil score is omitted from JSON; a real score is present.
	var m0 map[string]any
	b0, _ := json.Marshal(got.Apps[0])
	if err := json.Unmarshal(b0, &m0); err != nil {
		t.Fatal(err)
	}
	if _, ok := m0["score"]; ok {
		t.Errorf("unassessed app JSON should omit score: %s", b0)
	}
	b1, _ := json.Marshal(got.Apps[1])
	if !strings.Contains(string(b1), `"score":42.5`) {
		t.Errorf("scored app JSON should include score: %s", b1)
	}
}

// TestListApps_IncludeSummaryEnvelope covers the include_summary path: the
// portfolio-wide score/rating envelope is attached only when the caller opts
// in, while total always reflects summaryInfo.totalResults.
func TestListApps_IncludeSummaryEnvelope(t *testing.T) {
	const body = `{"rows":[{"ref":"app-1","platform":"ios","package":"com.x","title":"X"}],
		"pageInfo":{"hasNextPage":false},
		"summaryInfo":{"portfolioScore":73.5,"portfolioRating":"fair","totalResults":9}}`
	// Opted in: the summary aggregate is present.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	got, err := c.ListApps(t.Context(), ListAppsParams{IncludeSummary: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 9 {
		t.Errorf("total = %d, want 9", got.Total)
	}
	if got.Summary == nil || got.Summary.PortfolioScore != 73.5 || got.Summary.PortfolioRating != "fair" {
		t.Fatalf("summary = %+v, want score 73.5 / rating fair", got.Summary)
	}
	// Default: total still set from summaryInfo, but the summary aggregate is withheld.
	c = newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	got, err = c.ListApps(t.Context(), ListAppsParams{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 9 {
		t.Errorf("total = %d, want 9 even without include_summary", got.Total)
	}
	if got.Summary != nil {
		t.Errorf("summary = %+v, want nil without include_summary", got.Summary)
	}
}

func TestListApps_CursorPageSizeReused(t *testing.T) {
	cursor := base64.StdEncoding.EncodeToString([]byte(`{"limit":50,"offset":50}`))
	var gotPageSize string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPageSize = r.URL.Query().Get("pageSize")
		_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
	})
	if _, err := c.ListApps(t.Context(), ListAppsParams{Cursor: cursor}); err != nil {
		t.Fatal(err)
	}
	if gotPageSize != "50" {
		t.Errorf("pageSize sent = %q, want 50 (recovered from the cursor)", gotPageSize)
	}
	// An explicit page_size still wins over the cursor's claimed limit.
	if _, err := c.ListApps(t.Context(), ListAppsParams{Cursor: cursor, PageSize: 10}); err != nil {
		t.Fatal(err)
	}
	if gotPageSize != "10" {
		t.Errorf("pageSize sent = %q, want 10 (explicit page_size wins)", gotPageSize)
	}
}

// TestListApps_DefaultOrderRiskiestFirst guards the listing contract: score
// ascending (riskiest first) is upstream's implicit default, sent explicitly
// so the order survives an upstream default change. Ties keep upstream's
// unspecified order — the orderBy allowlist is single-field, so a compound
// sort is not available (a percent-encoded comma is rejected with a 400).
func TestListApps_DefaultOrderRiskiestFirst(t *testing.T) {
	var gotOrderBy string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotOrderBy = r.URL.Query().Get("orderBy")
		_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
	})
	ctx := t.Context()
	if _, err := c.ListApps(ctx, ListAppsParams{}); err != nil {
		t.Fatal(err)
	}
	if gotOrderBy != "score" {
		t.Errorf("default orderBy sent = %q, want score (riskiest first)", gotOrderBy)
	}
	if _, err := c.ListApps(ctx, ListAppsParams{OrderBy: "-vulnerability_count"}); err != nil {
		t.Fatal(err)
	}
	if gotOrderBy != "-vulnerabilityCount" {
		t.Errorf("explicit orderBy sent = %q, want -vulnerabilityCount (caller's choice preserved)", gotOrderBy)
	}
}

// TestAppsAffectedByFinding_DefaultOrderNewestFirst guards the affected-apps
// default: upstream's unordered default has no contract, so -createdAt is
// sent whenever the caller gives no order.
func TestAppsAffectedByFinding_DefaultOrderNewestFirst(t *testing.T) {
	var gotOrderBy string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotOrderBy = r.URL.Query().Get("orderBy")
		_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
	})
	ctx := t.Context()
	if _, err := c.AppsAffectedByFinding(ctx, "uses_http", AffectedByParams{}); err != nil {
		t.Fatal(err)
	}
	if gotOrderBy != "-createdAt" {
		t.Errorf("default orderBy sent = %q, want -createdAt", gotOrderBy)
	}
	if _, err := c.AppsAffectedByFinding(ctx, "uses_http", AffectedByParams{OrderBy: "title"}); err != nil {
		t.Fatal(err)
	}
	if gotOrderBy != "title" {
		t.Errorf("explicit orderBy sent = %q, want title (caller's choice preserved)", gotOrderBy)
	}
}

func TestListApps_ThresholdSeverityValidatedClientSide(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("request must not reach upstream")
	})
	_, err := c.ListApps(t.Context(), ListAppsParams{ThresholdSeverity: "sev1"})
	if err == nil || !strings.Contains(err.Error(), `invalid threshold_severity "sev1" (allowed: critical, high, medium, low)`) {
		t.Errorf("got %v, want client-side allowed-values error", err)
	}
}

func TestListApps_ThresholdFilterScansUpstreamEnvelope(t *testing.T) {
	var requests atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if ps := r.URL.Query().Get("pageSize"); ps != "50" {
			t.Errorf("scan pageSize = %q, want 50", ps)
		}
		severity := strings.Contains(r.URL.Query().Get("filters"), `"thresholdSeverity"`)
		switch r.URL.Query().Get("cursor") {
		case "":
			if severity {
				_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false,"cursor":null},
					"summaryInfo":{"totalResults":11,"totalResultsWithFindingsAtLeastThresholdSeverity":3}}`))
			} else {
				_, _ = w.Write([]byte(`{"rows":[
					{"ref":"best-1","title":"Best One","score":99},
					{"ref":"best-2","title":"Best Two","score":98}
				],"pageInfo":{"hasNextPage":true,"cursor":"C2"},"summaryInfo":{"totalResults":11}}`))
			}
		case "C2":
			if severity {
				_, _ = w.Write([]byte(`{"rows":[
					{"ref":"uber","title":"Uber Driver","score":48}
				],"pageInfo":{"hasNextPage":false,"cursor":null}}`))
			} else {
				_, _ = w.Write([]byte(`{"rows":[
					{"ref":"uber","title":"Uber Driver","score":48},
					{"ref":"other-1","title":"Other One","score":47}
				],"pageInfo":{"hasNextPage":true,"cursor":"C4"},"summaryInfo":{"totalResults":11}}`))
			}
		case "C4":
			if severity {
				_, _ = w.Write([]byte(`{"rows":[
					{"ref":"nyseg","title":"NYSEG","score":44.6}
				],"pageInfo":{"hasNextPage":false,"cursor":null}}`))
			} else {
				_, _ = w.Write([]byte(`{"rows":[
					{"ref":"nyseg","title":"NYSEG","score":44.6},
					{"ref":"other-2","title":"Other Two","score":44.5}
				],"pageInfo":{"hasNextPage":true,"cursor":"C6"},"summaryInfo":{"totalResults":11}}`))
			}
		case "C6":
			if severity {
				_, _ = w.Write([]byte(`{"rows":[
					{"ref":"bh","title":"B&H Photo","score":44}
				],"pageInfo":{"hasNextPage":false,"cursor":null}}`))
			} else {
				_, _ = w.Write([]byte(`{"rows":[
					{"ref":"bh","title":"B&H Photo","score":44}
				],"pageInfo":{"hasNextPage":false,"cursor":null},"summaryInfo":{"totalResults":11}}`))
			}
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	})

	first, err := c.ListApps(t.Context(), ListAppsParams{
		ThresholdSeverity: "high",
		OrderBy:           "-score",
		PageSize:          2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Apps) != 2 {
		t.Fatalf("first page apps = %+v, want two matches", first.Apps)
	}
	if got := []string{first.Apps[0].Title, first.Apps[1].Title}; fmt.Sprint(got) != "[Uber Driver NYSEG]" {
		t.Fatalf("first page titles = %v, want Uber Driver and NYSEG", got)
	}
	if first.Total != 3 {
		t.Errorf("first total = %d, want exact severity match count 3", first.Total)
	}
	if !first.Page.HasNextPage || first.Page.NextCursor == "" {
		t.Fatalf("first page envelope = %+v, want resumable upstream envelope", first.Page)
	}
	if first.Page.NextCursor == "C4" || first.Page.NextCursor == "C6" {
		t.Errorf("next_cursor = %q, want an nsmcp cursor preserving the partial source window", first.Page.NextCursor)
	}

	second, err := c.ListApps(t.Context(), ListAppsParams{
		ThresholdSeverity: "high",
		OrderBy:           "-score",
		Cursor:            first.Page.NextCursor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Apps) != 1 || second.Apps[0].Title != "B&H Photo" {
		t.Fatalf("second page apps = %+v, want B&H Photo only", second.Apps)
	}
	if second.Page.HasNextPage {
		t.Errorf("second page envelope = %+v, want exhausted", second.Page)
	}
	if second.Total != 3 {
		t.Errorf("second total = %d, want global severity match count 3", second.Total)
	}
	if requests.Load() != 10 {
		t.Errorf("upstream requests = %d, want five source/severity window pairs across both calls", requests.Load())
	}
}

func TestListApps_ThresholdScoreScansAndFiltersRowsLocally(t *testing.T) {
	var requests atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if filters := r.URL.Query().Get("filters"); filters != "" {
			if !strings.Contains(filters, `"thresholdScore"`) || r.URL.Query().Get("cursor") != "" ||
				r.URL.Query().Get("pageSize") != "1" {
				t.Errorf("summary request = %q, want one-row global threshold_score summary", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false},
				"summaryInfo":{"totalResults":6,"totalResultsBelowThresholdScore":2}}`))
			return
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			_, _ = w.Write([]byte(`{"rows":[
				{"ref":"best-1","title":"Best One","score":90},
				{"ref":"best-2","title":"Best Two","score":80}
			],"pageInfo":{"hasNextPage":true,"cursor":"C2"},"summaryInfo":{"totalResults":4}}`))
		case "C2":
			_, _ = w.Write([]byte(`{"rows":[
				{"ref":"risk-1","title":"Risk One","score":60},
				{"ref":"risk-2","title":"Risk Two","score":55}
			],"pageInfo":{"hasNextPage":true,"cursor":"C4"},"summaryInfo":{"totalResults":6}}`))
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	})

	score := 60.0
	got, err := c.ListApps(t.Context(), ListAppsParams{
		ThresholdScore: &score,
		OrderBy:        "-score",
		PageSize:       2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Apps) != 2 || got.Apps[0].Title != "Risk One" || got.Apps[1].Title != "Risk Two" {
		t.Fatalf("apps = %+v, want both score <= 60 rows in source order", got.Apps)
	}
	if !got.Page.HasNextPage || got.Page.NextCursor == "" {
		t.Errorf("page = %+v, want remaining upstream envelope", got.Page)
	}
	if got.Total != 2 {
		t.Errorf("total = %d, want exact score match count 2", got.Total)
	}
	if requests.Load() != 3 {
		t.Errorf("requests = %d, want two source windows plus one exact score summary", requests.Load())
	}
}

func TestListApps_CombinedFiltersCountFullIntersection(t *testing.T) {
	var requests atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		severity := strings.Contains(r.URL.Query().Get("filters"), `"thresholdSeverity"`)
		if severity && strings.Contains(r.URL.Query().Get("filters"), `"thresholdScore"`) {
			t.Errorf("severity request must not apply threshold_score before the local intersection")
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			if severity {
				_, _ = w.Write([]byte(`{"rows":[
					{"ref":"a","title":"Match A","score":50},
					{"ref":"b","title":"Match B","score":70}
				],"pageInfo":{"hasNextPage":false}}`))
			} else {
				_, _ = w.Write([]byte(`{"rows":[
					{"ref":"a","title":"Match A","score":50},
					{"ref":"b","title":"Match B","score":70}
				],"pageInfo":{"hasNextPage":true,"cursor":"C2"},"summaryInfo":{"totalResults":4}}`))
			}
		case "C2":
			if severity {
				_, _ = w.Write([]byte(`{"rows":[
					{"ref":"d","title":"Match D","score":45}
				],"pageInfo":{"hasNextPage":false}}`))
			} else {
				_, _ = w.Write([]byte(`{"rows":[
					{"ref":"c","title":"Other","score":40},
					{"ref":"d","title":"Match D","score":45}
				],"pageInfo":{"hasNextPage":false},"summaryInfo":{"totalResults":4}}`))
			}
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	})

	score := 60.0
	first, err := c.ListApps(t.Context(), ListAppsParams{
		ThresholdScore:    &score,
		ThresholdSeverity: "high",
		Search:            "match",
		PageSize:          1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Apps) != 1 || first.Apps[0].AppRef != "a" {
		t.Fatalf("first apps = %+v, want a only", first.Apps)
	}
	if first.Total != 2 || !first.Page.HasNextPage {
		t.Fatalf("first result = %+v, want total 2 and a next page", first)
	}

	second, err := c.ListApps(t.Context(), ListAppsParams{
		ThresholdScore:    &score,
		ThresholdSeverity: "high",
		Search:            "match",
		Cursor:            first.Page.NextCursor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Apps) != 1 || second.Apps[0].AppRef != "d" {
		t.Fatalf("second apps = %+v, want d only", second.Apps)
	}
	if second.Total != 2 || second.Page.HasNextPage {
		t.Fatalf("second result = %+v, want global total 2 and exhausted page", second)
	}
	if requests.Load() != 8 {
		t.Errorf("requests = %d, want two full source/severity scans", requests.Load())
	}
}

func TestListApps_AppRefFilterHasExactTotal(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if filters := r.URL.Query().Get("filters"); filters != "" {
			t.Errorf("source filters = %q, want app_refs evaluated over the complete envelope", filters)
		}
		fmt.Fprintf(w, `{"rows":[
			{"ref":%q,"title":"Wanted"},
			{"ref":%q,"title":"Other"}
		],"pageInfo":{"hasNextPage":false},"summaryInfo":{"totalResults":2}}`, testUUIDv1, testUUIDv4)
	})
	got, err := c.ListApps(t.Context(), ListAppsParams{ApplicationRefs: []string{testUUIDv1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Apps) != 1 || got.Apps[0].AppRef != testUUIDv1 || got.Total != 1 {
		t.Fatalf("result = %+v, want one returned app and total 1", got)
	}
}

func TestListApps_SearchScansAllPages(t *testing.T) {
	var pages atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		pages.Add(1)
		if ps := r.URL.Query().Get("pageSize"); ps != "50" {
			t.Errorf("search pageSize = %q, want 50", ps)
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			_, _ = w.Write([]byte(`{"rows":[
				{"ref":"a1","title":"Camera Scanner","package":"com.foo.cam"},
				{"ref":"a2","title":"Bank","package":"com.bank"}
			],"pageInfo":{"hasNextPage":true,"cursor":"C2"}}`))
		case "C2":
			_, _ = w.Write([]byte(`{"rows":[
				{"ref":"a3","title":"Other","package":"com.intsig.camscanner"}
			],"pageInfo":{"hasNextPage":false}}`))
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	})
	// page_size does not bound the number of matches while searching.
	got, err := c.ListApps(t.Context(), ListAppsParams{Search: "cam", PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Apps) != 2 {
		t.Fatalf("matches = %+v, want a1 and a3 (2)", got.Apps)
	}
	if got.Page.HasNextPage {
		t.Errorf("has_next_page = true, want false (scan exhausted the pages)")
	}
	if got.Total != 2 {
		t.Errorf("total = %d, want exact search match count 2", got.Total)
	}
	if n := pages.Load(); n != 2 {
		t.Errorf("upstream pages walked = %d, want 2", n)
	}
}

func TestListApps_SearchExhaustsBeyondLegacyWindow(t *testing.T) {
	const pagesToExhaust = 21
	var pages atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		n := pages.Add(1)
		hasNext := n < pagesToExhaust
		fmt.Fprintf(w, `{"rows":[],"pageInfo":{"hasNextPage":%t,"cursor":"cur-%d"}}`, hasNext, n)
	})
	got, err := c.ListApps(t.Context(), ListAppsParams{Search: "zzz"})
	if err != nil {
		t.Fatal(err)
	}
	if n := pages.Load(); n != pagesToExhaust {
		t.Errorf("upstream pages walked = %d, want %d (complete scan)", n, pagesToExhaust)
	}
	if got.Page.HasNextPage || got.Total != 0 {
		t.Errorf("result = %+v, want exhausted page and exact total 0", got)
	}
}

func TestGetAppByRef_V4RefHint(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
	})
	_, err := c.GetAppByRef(t.Context(), testUUIDv4)
	if err == nil || !strings.Contains(err.Error(), "v4 UUID") || !strings.Contains(err.Error(), "get_mari_assessment") {
		t.Errorf("err = %v, want the v4 cross-namespace hint", err)
	}
	_, err = c.GetAppByRef(t.Context(), testUUIDv1)
	if err == nil || strings.Contains(err.Error(), "v4 UUID") {
		t.Errorf("err = %v, want a plain not-found for a v1 ref", err)
	}
}

func TestGetFinding_CacheAndEscaping(t *testing.T) {
	var hits atomic.Int32
	var graphHits atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			graphHits.Add(1)
			_, _ = w.Write([]byte(`{"data":{"findings":{"list":[{"id":"weird/key","issue":{"recommendation":"patch it"}}]}}}`))
			return
		}
		hits.Add(1)
		if got := r.URL.EscapedPath(); got != "/v2/portfolio/findings/weird%2Fkey" {
			t.Errorf("escaped path = %q, want .../weird%%2Fkey", got)
		}
		_, _ = w.Write([]byte(`{"key":"weird/key","title":"W"}`))
	})
	for range 2 {
		got, err := c.GetFinding(t.Context(), "weird/key")
		if err != nil {
			t.Fatal(err)
		}
		if got.Key != "weird/key" {
			t.Errorf("Key = %q, want weird/key", got.Key)
		}
		if got.Remediation != "patch it" {
			t.Errorf("Remediation = %q, want the GraphQL recommendation", got.Remediation)
		}
	}
	if n := graphHits.Load(); n != 1 {
		t.Errorf("graphql hits = %d, want 1 (recommendation map cached)", n)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("backend hits = %d, want 1 (second call served from TTL cache)", n)
	}
}

func TestGetFinding_TestingMethodDedupFlag(t *testing.T) {
	dup := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			_, _ = w.Write([]byte(`{"data":{"findings":{"list":[]}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"key":"k","title":"T","stepsToReproduce":"do X","testingMethod":"do X"}`))
	})
	got, err := dup.GetFinding(t.Context(), "k")
	if err != nil {
		t.Fatal(err)
	}
	if got.TestingMethod != "" {
		t.Errorf("TestingMethod = %q, want empty (deduped)", got.TestingMethod)
	}
	if !got.TestingMethodSameAsSteps {
		t.Error("TestingMethodSameAsSteps = false, want true when the two matched")
	}

	none := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			_, _ = w.Write([]byte(`{"data":{"findings":{"list":[]}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"key":"k2","title":"T2"}`))
	})
	got2, err := none.GetFinding(t.Context(), "k2")
	if err != nil {
		t.Fatal(err)
	}
	if got2.TestingMethodSameAsSteps {
		t.Error("TestingMethodSameAsSteps = true for a finding with no testing method")
	}
}

// findingCatalogServer answers the finding catalog endpoint with three known
// keys and 404s every other path, so the get_finding 404-suggestion logic has
// a catalog to match against.
func findingCatalogServer(t *testing.T) *Client {
	t.Helper()
	return newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() == "/v2/portfolio/findings" {
			_, _ = w.Write([]byte(`{"findings":[
				{"key":"android_janus_vuln","title":"APK Vulnerable to the Janus Exploit","platform":"android"},
				{"key":"android_janus_warn","title":"APK May Be Vulnerable to Janus","platform":"android"},
				{"key":"ios_ats_disabled","title":"App Transport Security Disabled","platform":"ios"}
			]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	})
}

func TestGetFinding_404SuggestsCatalogMatches(t *testing.T) {
	c := findingCatalogServer(t)
	_, err := c.GetFinding(t.Context(), "janus")
	if err == nil {
		t.Fatal("expected a not-found error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "did you mean") || !strings.Contains(msg, "android_janus_vuln") || !strings.Contains(msg, "android_janus_warn") {
		t.Errorf("message %q missing catalog suggestions", msg)
	}
	if !strings.Contains(msg, `("APK Vulnerable to the Janus Exploit")`) {
		t.Errorf("message %q missing the matched title", msg)
	}
	if strings.Contains(msg, "ios_ats_disabled") {
		t.Errorf("message %q suggested an unrelated finding", msg)
	}
}

func TestGetFinding_404SuggestSpacesToUnderscores(t *testing.T) {
	c := findingCatalogServer(t)
	_, err := c.GetFinding(t.Context(), "android janus")
	if err == nil {
		t.Fatal("expected a not-found error")
	}
	if msg := err.Error(); !strings.Contains(msg, "android_janus_vuln") {
		t.Errorf("message %q should match keys after mapping spaces to underscores", msg)
	}
}

func TestGetFinding_404NoMatchAppendsKeyOriginHint(t *testing.T) {
	c := findingCatalogServer(t)
	_, err := c.GetFinding(t.Context(), "zzznope")
	if err == nil {
		t.Fatal("expected a not-found error")
	}
	msg := err.Error()
	if strings.Contains(msg, "did you mean") {
		t.Errorf("message %q should carry no suggestions", msg)
	}
	if !strings.Contains(msg, "finding keys come from get_assessment_findings rows (check_id)") {
		t.Errorf("message %q missing the key-origin hint", msg)
	}
	if !strings.Contains(msg, "not found") {
		t.Errorf("message %q should still read as a 404", msg)
	}
}

func TestGetFinding_404CatalogUnavailableDegrades(t *testing.T) {
	// Every request 404s (catalog included); the plain 404 with its
	// cross-namespace hint must survive.
	err := errFromUpstream(t, http.StatusNotFound, `{"message":"Not Found"}`, func(c *Client) error {
		_, e := c.GetFinding(t.Context(), testUUIDv4)
		return e
	})
	msg := err.Error()
	if strings.Contains(msg, "did you mean") {
		t.Errorf("message %q should not suggest when the catalog is unavailable", msg)
	}
	if !strings.Contains(msg, "this looks like a MARI ref") {
		t.Errorf("message %q lost the cross-namespace hint on catalog failure", msg)
	}
}

func TestAppsAffectedByFinding_SummaryFiltersMapping(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("includeSummaryInfo") != "true" {
			t.Errorf("includeSummaryInfo = %q, want true", r.URL.Query().Get("includeSummaryInfo"))
		}
		var f []map[string]any
		if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &f); err != nil {
			t.Fatalf("filters not JSON: %v (%q)", err, r.URL.Query().Get("filters"))
		}
		var hasGroup bool
		for _, e := range f {
			if e["name"] == "groupRefs" {
				hasGroup = true
			}
		}
		if !hasGroup {
			t.Errorf("filters missing groupRefs: %v", f)
		}
		_, _ = w.Write([]byte(`{
			"rows":[{"ref":"app-1","assessmentRef":"as-1","title":"X","platform":"ios","package":"com.x","packageVersion":"1.2","buildVersion":"9","groupName":"Team A"}],
			"pageInfo":{"hasNextPage":false},
			"summaryInfo":{"totalResults":123}
		}`))
	})
	got, err := c.AppsAffectedByFinding(t.Context(), "finding-1", AffectedByParams{GroupRefs: []string{testUUIDv1, testUUIDv4}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 123 {
		t.Errorf("Total = %d, want 123 (from summaryInfo.totalResults)", got.Total)
	}
	if len(got.Apps) != 1 || got.Apps[0].AppRef != "app-1" || got.Apps[0].Group != "Team A" || got.Apps[0].PackageVersion != "1.2" {
		t.Fatalf("apps = %+v", got.Apps)
	}
}

func TestAppsAffectedByFinding_NoSummaryTotalZero(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("includeSummaryInfo") != "true" {
			t.Errorf("includeSummaryInfo = %q, want true", r.URL.Query().Get("includeSummaryInfo"))
		}
		_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
	})
	got, err := c.AppsAffectedByFinding(t.Context(), "finding-1", AffectedByParams{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 0 {
		t.Errorf("Total = %d, want 0 when summaryInfo is absent", got.Total)
	}
}

func TestAppsAffectedByFinding_EpochMillisAndTotalZero(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"rows":[{"ref":"app-1","title":"X","platform":"android","package":"com.x","createdAt":1779378957642}],
			"pageInfo":{"hasNextPage":false},
			"summaryInfo":{"totalResults":1}
		}`))
	})
	got, err := c.AppsAffectedByFinding(t.Context(), "f", AffectedByParams{})
	if err != nil {
		t.Fatal(err)
	}
	want := time.UnixMilli(1779378957642).UTC().Format(time.RFC3339)
	if got.Apps[0].CreatedAt != want {
		t.Errorf("CreatedAt = %q, want %q (epoch millis -> RFC3339)", got.Apps[0].CreatedAt, want)
	}
}

func TestAffectedAppPage_TotalZeroShips(t *testing.T) {
	b, err := json.Marshal(AffectedAppPage{Finding: "f", Apps: []AffectedApp{}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"total":0`) {
		t.Errorf("marshaled page %s dropped total:0", b)
	}
}
