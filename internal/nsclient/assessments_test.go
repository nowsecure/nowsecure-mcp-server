package nsclient

// Assessments-domain tests: ListAssessments (filter requirement, mapping/JSON
// envelope, enum validation and lowercasing) and GetAssessmentFindings
// (assessment resolution, min_severity/limit/artifact filters, findings cache,
// category lowercasing).

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestListAssessments_RequiresFilter(t *testing.T) {
	c := New("http://unused", "tok")
	if _, err := c.ListAssessments(t.Context(), ListAssessmentsParams{PlatformTypes: []string{"ios"}}); err == nil {
		t.Error("expected error when no app/package/appstore filter is given")
	}
}

func TestListAssessments_MappingAndJSON(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/assessments" {
			t.Fatalf("path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"rows":[{
				"ref":"as-1","platformType":"android","packageKey":"com.x",
				"appliedPolicy":{"name":"Strict"},
				"impactTypes":{"critical":2,"high":1,"medium":3,"low":4,"warn":5,"info":6,"pass":7}
			}],
			"pageInfo":{"hasNextPage":false,"cursor":"CURSOR-X"}
		}`))
	})
	got, err := c.ListAssessments(t.Context(), ListAssessmentsParams{ApplicationRef: "app-1"})
	if err != nil {
		t.Fatal(err)
	}
	a := got.Assessments[0]
	if a.Policy != "Strict" {
		t.Errorf("Policy = %q, want Strict (from appliedPolicy.name)", a.Policy)
	}
	if a.Findings.Critical != 2 || a.Findings.Warn != 5 || a.Findings.Pass == nil || *a.Findings.Pass != 7 {
		t.Errorf("Findings = %+v, want impactTypes mapped through", a.Findings)
	}
	// hasNextPage=false => NextCursor empty even though a cursor is present.
	if got.Page.HasNextPage || got.Page.NextCursor != "" {
		t.Errorf("page = %+v, want no next page and empty cursor", got.Page)
	}
	// JSON contract: the key is assessment_ref, not the legacy ref.
	b, _ := json.Marshal(a)
	if !strings.Contains(string(b), `"assessment_ref":"as-1"`) {
		t.Errorf("Assessment JSON missing assessment_ref: %s", b)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["ref"]; ok {
		t.Errorf("Assessment JSON should not carry a legacy 'ref' key: %s", b)
	}
}

func TestListAssessments_EnumValidation(t *testing.T) {
	c := New("http://unused", "tok") // validation must fail before any HTTP
	cases := []struct {
		name string
		p    ListAssessmentsParams
		want string
	}{
		{"status", ListAssessmentsParams{ApplicationRef: "app-1", Status: []string{"complete"}}, `invalid status "complete"`},
		{"rating", ListAssessmentsParams{ApplicationRef: "app-1", Rating: []string{"crit"}}, `invalid rating "crit"`},
		{"type", ListAssessmentsParams{ApplicationRef: "app-1", Type: []string{"baselin"}}, `invalid type "baselin"`},
		{"platforms", ListAssessmentsParams{ApplicationRef: "app-1", PlatformTypes: []string{"windows"}}, `invalid platforms "windows"`},
		{"track", ListAssessmentsParams{ApplicationRef: "app-1", Track: "intel"}, `invalid track "intel"`},
	}
	for _, tc := range cases {
		_, err := c.ListAssessments(t.Context(), tc.p)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestListAssessments_TrackFiltersUpstream guards the key source-selection
// contract: track is translated to Platform's visibility/type filters before
// the merged assessment history is sorted and paginated.
func TestListAssessments_TrackFiltersUpstream(t *testing.T) {
	cases := []struct {
		name           string
		track          string
		types          []string
		wantVisibility string
		wantTypes      []string
	}{
		{"default platform", "", nil, "private", []string{"advanced", "baseline", "guided"}},
		{"explicit platform intersects types", "PLATFORM", []string{"baseline", "pen_test"}, "private", []string{"baseline"}},
		{"store monitor", "store_monitor", nil, "public", []string{"baseline"}},
		{"external", "external", nil, "private", []string{"pen_test", "workstation"}},
		{"all", "all", nil, "", nil},
		{"all preserves type", "all", []string{"guided"}, "", []string{"guided"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				var filters []struct {
					Name  string `json:"name"`
					Value any    `json:"value"`
				}
				if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil {
					t.Fatalf("filters: %v", err)
				}
				values := make(map[string]any, len(filters))
				for _, filter := range filters {
					values[filter.Name] = filter.Value
				}
				if got, _ := values["visibility"].([]any); tc.wantVisibility == "" {
					if _, ok := values["visibility"]; ok {
						t.Errorf("visibility filter = %v, want absent", values["visibility"])
					}
				} else if len(got) != 1 || got[0] != tc.wantVisibility {
					t.Errorf("visibility filter = %v, want [%s]", got, tc.wantVisibility)
				}
				gotTypes, _ := values["type"].([]any)
				if len(gotTypes) != len(tc.wantTypes) {
					t.Errorf("type filter = %v, want %v", gotTypes, tc.wantTypes)
				} else {
					for i, want := range tc.wantTypes {
						if gotTypes[i] != want {
							t.Errorf("type filter = %v, want %v", gotTypes, tc.wantTypes)
							break
						}
					}
				}
				_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
			})
			if _, err := c.ListAssessments(t.Context(), ListAssessmentsParams{
				ApplicationRef: "app-1", Track: tc.track, Type: tc.types,
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestListAssessments_IncompatibleTrackAndTypeIsEmpty(t *testing.T) {
	c := New("http://unused", "tok") // disjoint filters must not reach HTTP
	got, err := c.ListAssessments(t.Context(), ListAssessmentsParams{
		ApplicationRef: "app-1", Track: "platform", Type: []string{"pen_test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Assessments) != 0 || got.Page.HasNextPage {
		t.Errorf("page = %+v, want an empty terminal page", got)
	}
}

func TestListAssessments_SourceClassification(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"rows":[
				{"ref":"lab","visibility":"private","type":"baseline","application":{"ref":"app-1"},"impactTypes":{"pass":3}},
				{"ref":"monitor","visibility":"public","type":"baseline","application":{"ref":"should-not-win"},"appliedPolicy":{"name":"also-ignored"},"impactTypes":{"pass":9}},
				{"ref":"external","visibility":"private","type":"pen_test","application":{"ref":"app-1"},"impactTypes":{"pass":1}}
			],
			"pageInfo":{"hasNextPage":false}
		}`))
	})
	got, err := c.ListAssessments(t.Context(), ListAssessmentsParams{ApplicationRef: "app-1", Track: "all"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Assessments) != 3 {
		t.Fatalf("assessments = %+v, want 3 rows", got.Assessments)
	}
	wantTracks := []string{"platform", "store_monitor", "external"}
	wantFindings := []bool{true, false, false}
	for i, assessment := range got.Assessments {
		if assessment.Track != wantTracks[i] || assessment.FindingsAvailable != wantFindings[i] {
			t.Errorf("row %d = track %q findings_available=%t, want %q/%t",
				i, assessment.Track, assessment.FindingsAvailable, wantTracks[i], wantFindings[i])
		}
	}
	if got.Assessments[1].Findings.Pass != nil {
		t.Errorf("store-monitor pass = %v, want omitted", got.Assessments[1].Findings.Pass)
	}
}

func TestListAssessments_EnumLowercasedUpstream(t *testing.T) {
	var sent string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		sent = r.URL.Query().Get("filters")
		_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
	})
	if _, err := c.ListAssessments(t.Context(), ListAssessmentsParams{
		ApplicationRef: "app-1", Status: []string{"COMPLETED"}, Rating: []string{"Critical"},
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sent, "completed") || strings.Contains(sent, "COMPLETED") {
		t.Errorf("filters = %q, want lowercased status", sent)
	}
	if !strings.Contains(sent, "critical") || strings.Contains(sent, "Critical") {
		t.Errorf("filters = %q, want lowercased rating", sent)
	}
}

// TestListAssessments_PageSizeDefaultAndClamp guards the small-page contract:
// the default page size is always sent explicitly (never left to upstream,
// whose default could drift), an oversized page_size is clamped, and a
// cursor's recovered stride is reused but subject to the same clamp.
func TestListAssessments_PageSizeDefaultAndClamp(t *testing.T) {
	var gotPageSize string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPageSize = r.URL.Query().Get("pageSize")
		_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
	})
	ctx := t.Context()
	cases := []struct {
		name string
		p    ListAssessmentsParams
		want string
	}{
		{"default", ListAssessmentsParams{ApplicationRef: "app-1"}, "10"},
		{"explicit within cap", ListAssessmentsParams{ApplicationRef: "app-1", PageSize: 25}, "25"},
		{"explicit over cap clamped", ListAssessmentsParams{ApplicationRef: "app-1", PageSize: 100}, "25"},
		{"cursor stride reused", ListAssessmentsParams{
			ApplicationRef: "app-1",
			Cursor:         base64.StdEncoding.EncodeToString([]byte(`{"limit":5,"offset":5}`)),
		}, "5"},
		{"cursor stride clamped", ListAssessmentsParams{
			ApplicationRef: "app-1",
			Cursor:         base64.StdEncoding.EncodeToString([]byte(`{"limit":50,"offset":50}`)),
		}, "25"},
	}
	for _, tc := range cases {
		if _, err := c.ListAssessments(ctx, tc.p); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if gotPageSize != tc.want {
			t.Errorf("%s: pageSize sent = %q, want %q", tc.name, gotPageSize, tc.want)
		}
	}
}

// TestListAssessments_DefaultOrderNewestFirst guards the newest-first promise:
// upstream's default sort is buildVersion compared as a string ("7" > "39" >
// "14"), so an order must always be sent when the caller gives none.
func TestListAssessments_DefaultOrderNewestFirst(t *testing.T) {
	var gotOrderBy string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotOrderBy = r.URL.Query().Get("orderBy")
		_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
	})
	ctx := t.Context()
	if _, err := c.ListAssessments(ctx, ListAssessmentsParams{ApplicationRef: "app-1"}); err != nil {
		t.Fatal(err)
	}
	if gotOrderBy != "-createdAt" {
		t.Errorf("default orderBy sent = %q, want -createdAt", gotOrderBy)
	}
	if _, err := c.ListAssessments(ctx, ListAssessmentsParams{ApplicationRef: "app-1", OrderBy: "build_version"}); err != nil {
		t.Fatal(err)
	}
	if gotOrderBy != "buildVersion" {
		t.Errorf("explicit orderBy sent = %q, want buildVersion (caller's choice preserved)", gotOrderBy)
	}
}

// TestListAssessments_DedupRows guards against the upstream quirk where one
// page serves the same assessment twice, one copy missing the application
// name: a single row survives, with the title backfilled from the richer copy.
func TestListAssessments_DedupRows(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"rows":[
				{"ref":"as-dup","application":{"ref":"app-1"},"platformType":"ios","packageKey":"com.x","appliedPolicy":{"name":"P"},"impactTypes":{}},
				{"ref":"as-dup","application":{"ref":"app-1","name":"Acme"},"platformType":"ios","packageKey":"com.x","appliedPolicy":{"name":"P"},"impactTypes":{}},
				{"ref":"as-2","application":{"ref":"app-1","name":"Acme"},"platformType":"ios","packageKey":"com.x","appliedPolicy":{"name":"P"},"impactTypes":{}}
			],
			"pageInfo":{"hasNextPage":false}
		}`))
	})
	got, err := c.ListAssessments(t.Context(), ListAssessmentsParams{ApplicationRef: "app-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Assessments) != 2 {
		t.Fatalf("rows = %d, want 2 (duplicate ref collapsed): %+v", len(got.Assessments), got.Assessments)
	}
	if got.Assessments[0].Ref != "as-dup" || got.Assessments[0].Title != "Acme" {
		t.Errorf("row 0 = ref %q title %q, want as-dup with title backfilled from the duplicate", got.Assessments[0].Ref, got.Assessments[0].Title)
	}
	if got.Assessments[1].Ref != "as-2" {
		t.Errorf("row 1 ref = %q, want as-2", got.Assessments[1].Ref)
	}
}

func TestGetAssessmentFindings_ResolveAndCompact(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			// lookup-by-app_ref returns the app's platform/package/group/latest.
			_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","assessmentRef":"as-new","platform":"ios","package":"com.acme","group":{"ref":"grp-9","name":"Team"}}],"pageInfo":{"hasNextPage":false}}`))
		case "/app/ios/com.acme/assessment":
			if r.URL.Query().Get("group") != "grp-9" {
				t.Errorf("group query = %q, want grp-9", r.URL.Query().Get("group"))
			}
			_, _ = w.Write([]byte(`[
				{"ref":"as-old","task":100,"task_status":"completed","created":"2024-01-01T00:00:00Z"},
				{"ref":"as-new","task":200,"task_status":"completed","created":"2024-06-01T00:00:00Z"}
			]`))
		case "/assessment/200/findings":
			if r.URL.Query().Get("report") != "lab-auto" {
				t.Errorf("report = %q", r.URL.Query().Get("report"))
			}
			_, _ = w.Write([]byte(`[
				{"check_id":"low1","title":"Low","severity":"low","affected":true,"cvss":2.1},
				{"check_id":"crit1","title":"Crit","severity":"critical","affected":true,"cvss":9.8,"recommendations":{"developer":"fix it"}},
				{"check_id":"pass1","title":"Pass","severity":"medium","affected":false},
				{"check_id":"hid","title":"Hidden","severity":"high","affected":true,"hidden":true}
			]`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	})

	got, err := c.GetAssessmentFindings(t.Context(), FindingsParams{
		AppRef: "app-1", AssessmentRef: "as-new", AffectedOnly: true, IncludeRecs: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// affected_only drops the pass; hidden is always dropped.
	if got.TotalReturned != 2 {
		t.Fatalf("TotalReturned = %d, want 2 (%+v)", got.TotalReturned, got.Findings)
	}
	// most-severe first
	if got.Findings[0].CheckID != "crit1" {
		t.Errorf("expected critical first, got %q", got.Findings[0].CheckID)
	}
	if got.Findings[0].Recommendation != "fix it" {
		t.Errorf("recommendation = %q", got.Findings[0].Recommendation)
	}
	// counts include affected + pass; hidden excluded
	if got.Counts.Critical != 1 || got.Counts.Low != 1 || got.Counts.Pass == nil || *got.Counts.Pass != 1 {
		t.Errorf("counts = %+v", got.Counts)
	}
	// total_findings counts every non-hidden finding (4 raw - 1 hidden = 3).
	if got.TotalFindings != 3 {
		t.Errorf("TotalFindings = %d, want 3 (hidden excluded)", got.TotalFindings)
	}
	// status/created surface from the resolved (completed) assessment.
	if got.Status != "completed" {
		t.Errorf("Status = %q, want completed", got.Status)
	}
	if got.CreatedAt != "2024-06-01T00:00:00Z" {
		t.Errorf("CreatedAt = %q, want the resolved assessment's created", got.CreatedAt)
	}

	// Default (no include flag): recommendation prose is omitted.
	lean, err := c.GetAssessmentFindings(t.Context(), FindingsParams{
		AppRef: "app-1", AssessmentRef: "as-new", AffectedOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if lean.Findings[0].Recommendation != "" {
		t.Errorf("default Recommendation = %q, want omitted", lean.Findings[0].Recommendation)
	}

	// check_ids scopes the rows and restores the FULL recommendation.
	deep, err := c.GetAssessmentFindings(t.Context(), FindingsParams{
		AppRef: "app-1", AssessmentRef: "as-new", AffectedOnly: true, CheckIDs: []string{"crit1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(deep.Findings) != 1 || deep.Findings[0].CheckID != "crit1" || deep.Findings[0].Recommendation != "fix it" {
		t.Errorf("check_ids result = %+v, want just crit1 with its full recommendation", deep.Findings)
	}
	if deep.TotalFindings != 3 {
		t.Errorf("check_ids TotalFindings = %d, want 3 (counts still cover the report)", deep.TotalFindings)
	}
}

func TestGetAssessmentFindings_LatestWhenNoRef(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			// app's latest assessment is "b".
			_, _ = w.Write([]byte(`{"rows":[{"ref":"app-x","assessmentRef":"b","platform":"android","package":"com.x","group":{"ref":"g1"}}],"pageInfo":{"hasNextPage":false}}`))
		case "/app/android/com.x/assessment":
			_, _ = w.Write([]byte(`[
				{"ref":"a","task":1,"task_status":"completed","created":"2024-01-01T00:00:00Z"},
				{"ref":"b","task":2,"task_status":"completed","created":"2024-09-09T00:00:00Z"}
			]`))
		case "/assessment/2/findings":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	})
	got, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-x"})
	if err != nil {
		t.Fatal(err)
	}
	if got.AssessmentRef != "b" {
		t.Errorf("expected latest ref b, got %q", got.AssessmentRef)
	}
}

func TestGetAssessmentFindings_NumericTaskRef(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","platform":"ios","package":"com.acme","group":{"ref":"grp-9"}}],"pageInfo":{"hasNextPage":false}}`))
		case "/app/ios/com.acme/assessment":
			_, _ = w.Write([]byte(`[{"ref":"as-x","task":200,"task_status":"completed","created":"2024-06-01T00:00:00Z"}]`))
		case "/assessment/200/findings":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	})
	// A numeric ref matches the assessment's task id and resolves to its UUID.
	got, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1", AssessmentRef: "200"})
	if err != nil {
		t.Fatal(err)
	}
	if got.AssessmentRef != "as-x" {
		t.Errorf("AssessmentRef = %q, want as-x", got.AssessmentRef)
	}
}

func TestGetAssessmentFindings_RefreshOnMiss(t *testing.T) {
	var appHits, assessHits atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			appHits.Add(1)
			_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","platform":"ios","package":"com.acme","group":{"ref":"grp-9"}}],"pageInfo":{"hasNextPage":false}}`))
		case "/app/ios/com.acme/assessment":
			if assessHits.Add(1) == 1 {
				// First list omits as-2.
				_, _ = w.Write([]byte(`[{"ref":"as-1","task":1,"task_status":"completed","created":"2024-01-01T00:00:00Z"}]`))
			} else {
				// Refreshed list: as-2 has since appeared.
				_, _ = w.Write([]byte(`[{"ref":"as-1","task":1,"task_status":"completed","created":"2024-01-01T00:00:00Z"},{"ref":"as-2","task":2,"task_status":"completed","created":"2024-02-01T00:00:00Z"}]`))
			}
		case "/assessment/1/findings", "/assessment/2/findings":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	})
	// Call 1 resolves as-1 from the first list and caches it (1 list hit).
	if _, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1", AssessmentRef: "as-1"}); err != nil {
		t.Fatalf("call 1: %v", err)
	}
	// Call 2 wants as-2, absent from the cached list -> forces one refresh.
	got, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1", AssessmentRef: "as-2"})
	if err != nil {
		t.Fatalf("call 2: %v", err)
	}
	if got.AssessmentRef != "as-2" {
		t.Errorf("AssessmentRef = %q, want as-2", got.AssessmentRef)
	}
	if n := assessHits.Load(); n != 2 {
		t.Errorf("assessment-list hits = %d, want 2 (initial + one refresh)", n)
	}
	if n := appHits.Load(); n != 1 {
		t.Errorf("app lookups = %d, want 1 (cached)", n)
	}
}

func TestGetAssessmentFindings_RefNeverFound(t *testing.T) {
	var assessHits atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","platform":"ios","package":"com.acme","group":{"ref":"grp-9"}}],"pageInfo":{"hasNextPage":false}}`))
		case "/app/ios/com.acme/assessment":
			assessHits.Add(1)
			_, _ = w.Write([]byte(`[{"ref":"as-1","task":1,"task_status":"completed","created":"2024-01-01T00:00:00Z"}]`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	})
	_, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1", AssessmentRef: "ghost"})
	if err == nil {
		t.Fatal("expected error for an unknown ref")
	}
	if !strings.Contains(err.Error(), "not found among the NowSecure Platform assessments") || !strings.Contains(err.Error(), "findings_available") {
		t.Errorf("error = %q, want not-found + findings_available hint", err)
	}
	if n := assessHits.Load(); n != 2 {
		t.Errorf("assessment-list hits = %d, want 2 (initial + one refresh)", n)
	}
}

func TestGetAssessmentFindings_NoAssessments(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			// No assessmentRef on the app -> default (latest) resolution path.
			_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","platform":"ios","package":"com.acme","group":{"ref":"grp-9"}}],"pageInfo":{"hasNextPage":false}}`))
		case "/app/ios/com.acme/assessment":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	})
	_, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1"})
	if err == nil || !strings.Contains(err.Error(), "no assessments found") {
		t.Fatalf("error = %v, want 'no assessments found'", err)
	}
}

func TestGetAssessmentFindings_NonCompletedFallback(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","platform":"ios","package":"com.acme","group":{"ref":"grp-9"}}],"pageInfo":{"hasNextPage":false}}`))
		case "/app/ios/com.acme/assessment":
			// No completed assessment; newest (by created) should win.
			_, _ = w.Write([]byte(`[
				{"ref":"as-old","task":10,"task_status":"processing","created":"2024-01-01T00:00:00Z"},
				{"ref":"as-new","task":11,"task_status":"processing","created":"2024-09-09T00:00:00Z"}
			]`))
		case "/assessment/11/findings":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	})
	got, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.AssessmentRef != "as-new" {
		t.Errorf("AssessmentRef = %q, want as-new (newest)", got.AssessmentRef)
	}
	if got.Status != "processing" {
		t.Errorf("Status = %q, want processing (surfaced from fallback)", got.Status)
	}
	if got.CreatedAt != "2024-09-09T00:00:00Z" {
		t.Errorf("CreatedAt = %q, want the newest assessment's created", got.CreatedAt)
	}
}

func TestGetAssessmentFindings_ConcurrentNoRace(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","platform":"ios","package":"com.acme","group":{"ref":"grp-9"}}],"pageInfo":{"hasNextPage":false}}`))
		case "/app/ios/com.acme/assessment":
			_, _ = w.Write([]byte(`[
				{"ref":"as-1","task":1,"task_status":"completed","created":"2024-01-01T00:00:00Z"},
				{"ref":"as-2","task":2,"task_status":"completed","created":"2024-02-01T00:00:00Z"},
				{"ref":"as-3","task":3,"task_status":"completed","created":"2024-03-01T00:00:00Z"}
			]`))
		case "/assessment/1/findings", "/assessment/2/findings", "/assessment/3/findings":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	})
	// Prime the per-app cache so both goroutines read the same cached slice
	// (the pre-fix bug sorted that shared slice in place under -race).
	if _, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1", AssessmentRef: "as-1"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if _, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1", AssessmentRef: "as-2"}); err != nil {
				t.Errorf("concurrent call: %v", err)
			}
		})
	}
	wg.Wait()
}

func TestGetAssessmentFindings_InvalidMinSeverity(t *testing.T) {
	var hits atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		t.Errorf("unexpected HTTP request to %q", r.URL.Path)
	})
	_, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1", MinSeverity: "sev"})
	if err == nil || !strings.Contains(err.Error(), "info, warn, low, medium, high, critical") {
		t.Fatalf("error = %v, want allowed-values list", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("made %d HTTP requests, want 0 (validated before any call)", n)
	}
}

func TestGetAssessmentFindings_MinSeverityFilter(t *testing.T) {
	newC := func() *Client {
		return newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v2/portfolio/applications":
				_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","platform":"ios","package":"com.acme","group":{"ref":"grp-9"}}],"pageInfo":{"hasNextPage":false}}`))
			case "/app/ios/com.acme/assessment":
				_, _ = w.Write([]byte(`[{"ref":"as-1","task":1,"task_status":"completed","created":"2024-01-01T00:00:00Z"}]`))
			case "/assessment/1/findings":
				_, _ = w.Write([]byte(`[
					{"check_id":"i","title":"i","severity":"info","affected":true},
					{"check_id":"w","title":"w","severity":"warn","affected":true},
					{"check_id":"l","title":"l","severity":"low","affected":true}
				]`))
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		})
	}
	sevSet := func(f *AssessmentFindings) map[string]bool {
		m := map[string]bool{}
		for _, x := range f.Findings {
			m[x.Severity] = true
		}
		return m
	}
	// min=warn keeps warn (and above) but drops info: warn ranks above info.
	got, err := newC().GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1", MinSeverity: "warn"})
	if err != nil {
		t.Fatal(err)
	}
	if s := sevSet(got); s["info"] || !s["warn"] || !s["low"] {
		t.Errorf("min=warn severities = %v, want {warn,low} without info", s)
	}
	// min=low drops warn too: warn ranks below low.
	got2, err := newC().GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1", MinSeverity: "low"})
	if err != nil {
		t.Fatal(err)
	}
	if s := sevSet(got2); s["info"] || s["warn"] || !s["low"] {
		t.Errorf("min=low severities = %v, want {low} only", s)
	}
}

func TestGetAssessmentFindings_Limit(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","platform":"ios","package":"com.acme","group":{"ref":"grp-9"}}],"pageInfo":{"hasNextPage":false}}`))
		case "/app/ios/com.acme/assessment":
			_, _ = w.Write([]byte(`[{"ref":"as-1","task":1,"task_status":"completed","created":"2024-01-01T00:00:00Z"}]`))
		case "/assessment/1/findings":
			_, _ = w.Write([]byte(`[
				{"check_id":"crit","title":"c","severity":"critical","affected":true},
				{"check_id":"high","title":"h","severity":"high","affected":true},
				{"check_id":"low","title":"l","severity":"low","affected":true}
			]`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	})
	got, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Limit keeps only the single most-severe finding...
	if len(got.Findings) != 1 || got.Findings[0].CheckID != "crit" {
		t.Fatalf("Findings = %+v, want 1 (critical)", got.Findings)
	}
	if got.TotalReturned != 1 {
		t.Errorf("TotalReturned = %d, want 1", got.TotalReturned)
	}
	// ...but counts and total_findings still reflect everything.
	if got.TotalFindings != 3 {
		t.Errorf("TotalFindings = %d, want 3 (limit is display-only)", got.TotalFindings)
	}
	if got.Counts.Critical != 1 || got.Counts.High != 1 || got.Counts.Low != 1 {
		t.Errorf("Counts = %+v, want critical/high/low each 1", got.Counts)
	}
}

func TestGetAssessmentFindings_FindingsCached(t *testing.T) {
	var findingsHits atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","platform":"ios","package":"com.acme","group":{"ref":"grp-9"}}],"pageInfo":{"hasNextPage":false}}`))
		case "/app/ios/com.acme/assessment":
			_, _ = w.Write([]byte(`[{"ref":"as-1","task":7,"task_status":"completed","created":"2024-01-01T00:00:00Z"}]`))
		case "/assessment/7/findings":
			findingsHits.Add(1)
			_, _ = w.Write([]byte(`[{"check_id":"c","title":"C","severity":"high","affected":true}]`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	})
	for i := range 2 {
		if _, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1", AssessmentRef: "as-1"}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if n := findingsHits.Load(); n != 1 {
		t.Errorf("findings fetches = %d, want 1 (second call served from cache)", n)
	}
}

func TestGetAssessmentFindings_ArtifactExclusion(t *testing.T) {
	newC := func() *Client {
		return newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v2/portfolio/applications":
				_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","platform":"ios","package":"com.acme","group":{"ref":"grp-9"}}],"pageInfo":{"hasNextPage":false}}`))
			case "/app/ios/com.acme/assessment":
				_, _ = w.Write([]byte(`[{"ref":"as-1","task":1,"task_status":"completed","created":"2024-01-01T00:00:00Z"}]`))
			case "/assessment/1/findings":
				_, _ = w.Write([]byte(`[
					{"check_id":"vuln","title":"V","category":"Network","severity":"high","affected":true},
					{"check_id":"art","title":"A","category":"artifact","severity":"info","affected":true}
				]`))
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		})
	}
	ids := func(f *AssessmentFindings) []string {
		out := make([]string, 0, len(f.Findings))
		for _, x := range f.Findings {
			out = append(out, x.CheckID)
		}
		return out
	}
	ctx := t.Context()

	got, err := newC().GetAssessmentFindings(ctx, FindingsParams{AppRef: "app-1"})
	if err != nil {
		t.Fatal(err)
	}
	if g := ids(got); len(g) != 1 || g[0] != "vuln" {
		t.Errorf("default findings = %v, want [vuln] (artifact excluded)", g)
	}
	if got.Counts.Artifacts != 1 {
		t.Errorf("counts.artifacts = %d, want 1 (still counted)", got.Counts.Artifacts)
	}

	inc, err := newC().GetAssessmentFindings(ctx, FindingsParams{AppRef: "app-1", IncludeArtifacts: true})
	if err != nil {
		t.Fatal(err)
	}
	if g := ids(inc); len(g) != 2 {
		t.Errorf("include_artifacts findings = %v, want both rows", g)
	}

	chk, err := newC().GetAssessmentFindings(ctx, FindingsParams{AppRef: "app-1", CheckIDs: []string{"art"}})
	if err != nil {
		t.Fatal(err)
	}
	if g := ids(chk); len(g) != 1 || g[0] != "art" {
		t.Errorf("check_ids=[art] findings = %v, want [art] served despite the default artifact exclusion", g)
	}
}

// TestGetAssessmentFindings_CategoryLowercased guards the upstream quirk where
// one finding category ("Resilience") ships in Title Case amid an otherwise
// lowercase set. The client lowercases every category so callers match on a
// single canonical spelling; a green suite once shipped without this check.
func TestGetAssessmentFindings_CategoryLowercased(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			_, _ = w.Write([]byte(`{"rows":[{"ref":"app-1","platform":"ios","package":"com.acme","group":{"ref":"grp-9"}}],"pageInfo":{"hasNextPage":false}}`))
		case "/app/ios/com.acme/assessment":
			_, _ = w.Write([]byte(`[{"ref":"as-1","task":1,"task_status":"completed","created":"2024-01-01T00:00:00Z"}]`))
		case "/assessment/1/findings":
			_, _ = w.Write([]byte(`[{"check_id":"c","title":"C","category":"Resilience","severity":"high","affected":true}]`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	})
	got, err := c.GetAssessmentFindings(t.Context(), FindingsParams{AppRef: "app-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings = %+v, want 1", got.Findings)
	}
	if got.Findings[0].Category != "resilience" {
		t.Errorf("category = %q, want \"resilience\" (Title Case lowercased)", got.Findings[0].Category)
	}
}
