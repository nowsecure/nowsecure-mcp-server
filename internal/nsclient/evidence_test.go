package nsclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Exercise triage -> scoped evidence -> cached evidence on the same client.
// Legacy finding keys intentionally differ from GraphQL check IDs: code
// locations must resolve by assessment and location IDs, not finding keys.
func TestGetAssessmentFindings_Evidence(t *testing.T) {
	var findingHits, locationHits atomic.Int32
	recommendation := strings.TrimSpace(strings.Repeat("Fix the affected configuration. ", 30))
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/portfolio/applications":
			fmt.Fprint(w, `{"rows":[{"ref":"app-1","assessmentRef":"as-latest","platform":"android","package":"com.acme","group":{"ref":"grp"}}],"pageInfo":{"hasNextPage":false}}`)
		case "/app/android/com.acme/assessment":
			if r.URL.Query().Get("group") != "grp" {
				t.Errorf("assessment lookup lost the app's group")
			}
			fmt.Fprint(w, `[{"ref":"as-target","task":55,"task_status":"completed","created":"2026-01-01T00:00:00Z"},{"ref":"as-latest","task":56,"task_status":"completed","created":"2026-02-01T00:00:00Z"}]`)
		case "/assessment/55/findings":
			findingHits.Add(1)
			if r.URL.Query().Get("report") != "lab-auto" {
				t.Errorf("report = %q", r.URL.Query().Get("report"))
			}
			encodedRec, _ := json.Marshal(recommendation)
			fmt.Fprintf(w, `[
				{"check_id":"legacy_key","title":"Affected code","severity":"high","affected":true,"recommendations":{"developer":%s},"context":{"title":"Code evidence","view":"table","fields":{"path":{"title":"File"}},"rows":[{"path":"src/Network.java","locations":[{"location_id":"loc-1"}],"observation":{"setting":false,"extra":[null,1,"value"]}}]}},
				{"check_id":"low","title":"Low","severity":"low","affected":true,"context":{"rows":[{"location_id":"excluded-low"}]}},
				{"check_id":"hidden","severity":"critical","affected":true,"hidden":true,"context":{"rows":[{"location_id":"excluded-hidden"}]}},
				{"check_id":"pass","severity":"critical","affected":false,"context":{"rows":[{"location_id":"excluded-pass"}]}},
				{"check_id":"artifact","category":"artifact","severity":"info","affected":true,"context":{"rows":[{"path":"AndroidManifest.xml"}]}}
			]`, encodedRec)
		case "/graphql":
			locationHits.Add(1)
			var body struct{ Query string }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if !strings.Contains(body.Query, `assessment(ref: "as-target")`) ||
				!strings.Contains(body.Query, `codeLocations(ids: ["loc-1"])`) || strings.Contains(body.Query, "legacy_key") {
				t.Errorf("evidence query lost scan/location scoping: %s", body.Query)
			}
			fmt.Fprint(w, `{"data":{"auto":{"assessment":{"codeLocations":[{"id":"loc-1","data":{"entries":[{"file":"src/Network.java","class":"com.acme.Network","method":"connect","line":42,"code":"connection.connect();"}]}}]}}}}`)
		default:
			t.Errorf("unexpected request: %s", r.URL)
			http.NotFound(w, r)
		}
	})
	p := FindingsParams{AppRef: "app-1", AssessmentRef: "55", AffectedOnly: true}
	for _, ids := range [][]string{nil, {"legacy_key"}} {
		p.CheckIDs = ids
		out, err := c.GetAssessmentFindings(t.Context(), p)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range out.Findings {
			if f.Evidence != nil {
				t.Fatal("evidence returned without include_evidence")
			}
		}
	}
	if locationHits.Load() != 0 {
		t.Fatal("triage fetched code locations")
	}
	p.IncludeEvidence = true
	p.CheckIDs = []string{" LEGACY_KEY ", "low", "hidden", "pass"}
	p.Limit = 1
	out, err := c.GetAssessmentFindings(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	if out.AssessmentRef != "as-target" || out.TotalReturned != 1 || out.TotalFindings != 4 || out.Counts.Artifacts != 1 {
		t.Fatalf("evidence changed the scan or counts: %+v", out)
	}
	f := out.Findings[0]
	if f.CheckID != "legacy_key" || f.Recommendation != recommendation || f.Evidence == nil {
		t.Fatalf("scoped evidence missing full recommendation: %+v", f)
	}
	e := f.Evidence
	if e.Title != "Code evidence" || len(e.Rows) != 1 || len(e.CodeLocations) != 1 {
		t.Fatalf("missing evidence: %+v", e)
	}
	if e.Rows[0].(map[string]any)["path"] != "src/Network.java" || e.CodeLocations[0].ID != "loc-1" {
		t.Fatalf("lost evidence/code location identity: %+v", e)
	}
	// Concurrent calls reuse cached raw data without modifying one another.
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			again, err := c.GetAssessmentFindings(t.Context(), p)
			if err != nil {
				t.Error(err)
				return
			}
			if !reflect.DeepEqual(out, again) {
				t.Error("cached evidence changed")
			}
		})
	}
	wg.Wait()
	if findingHits.Load() != 1 || locationHits.Load() != 1 {
		t.Errorf("cache missed: findings=%d locations=%d", findingHits.Load(), locationHits.Load())
	}
	// Explicit artifact selections expose their evidence despite the default
	// inventory exclusion, without requiring a code-location lookup.
	p.CheckIDs = []string{"artifact"}
	artifact, err := c.GetAssessmentFindings(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Findings) != 1 || artifact.Findings[0].Evidence.Rows[0].(map[string]any)["path"] != "AndroidManifest.xml" {
		t.Fatalf("artifact evidence missing: %+v", artifact.Findings)
	}
	if locationHits.Load() != 1 {
		t.Fatal("artifact without location refs fetched code locations")
	}
}

func TestGetAssessmentFindings_EvidenceRequiresSelection(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("invalid evidence request reached HTTP: %s", r.URL)
	})
	for _, ids := range [][]string{nil, {}, {"", " \t "}} {
		_, err := c.GetAssessmentFindings(t.Context(), FindingsParams{
			AppRef: "app-1", IncludeEvidence: true, CheckIDs: ids,
		})
		if err == nil || !strings.Contains(err.Error(), "check_ids") {
			t.Errorf("error = %v, want check_ids guidance", err)
		}
	}
}

func TestGetAssessmentFindings_EvidencePaginationInputs(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("invalid evidence pagination reached HTTP: %s", r.URL)
	})
	for _, tc := range []struct {
		name string
		p    FindingsParams
		want string
	}{
		{"negative offset", FindingsParams{IncludeEvidence: true, CheckIDs: []string{"c"}, EvidenceOffset: -1}, "negative"},
		{"negative limit", FindingsParams{IncludeEvidence: true, CheckIDs: []string{"c"}, EvidenceLimit: -1}, "negative"},
		{"offset without evidence", FindingsParams{CheckIDs: []string{"c"}, EvidenceOffset: 1}, "include_evidence"},
		{"limit without evidence", FindingsParams{CheckIDs: []string{"c"}, EvidenceLimit: 5}, "include_evidence"},
		{"ambiguous offset", FindingsParams{IncludeEvidence: true, CheckIDs: []string{"a", "b"}, EvidenceOffset: 20}, "exactly one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.p.AppRef = "app-1"
			_, err := c.GetAssessmentFindings(t.Context(), tc.p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
