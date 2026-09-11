package nsclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFindingEvidence_PaginationPreservesRowsAndFetchesOnlyPageLocations(t *testing.T) {
	rows := make([]any, 5)
	for i := range rows {
		rows[i] = map[string]any{"index": i, "location_id": fmt.Sprintf("site-%d", i), "observation": strings.Repeat("complete evidence ", 1000)}
	}
	raw, _ := json.Marshal(map[string]any{"title": "Evidence", "fields": map[string]any{"index": map[string]any{"type": "number"}}, "rows": rows})
	var requestIDs [][]string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, after, ok := strings.Cut(body.Query, "codeLocations(ids: ")
		idsJSON, _, closed := strings.Cut(after, ")")
		var ids []string
		if !ok || !closed || json.Unmarshal([]byte(idsJSON), &ids) != nil {
			t.Error("could not decode page location IDs from the query")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requestIDs = append(requestIDs, ids)
		locations := make([]map[string]any, len(ids))
		for i, id := range ids {
			locations[i] = map[string]any{"id": id, "data": map[string]any{"method": id}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"auto": map[string]any{"assessment": map[string]any{"codeLocations": locations}}}})
	})
	var reconstructed []any
	for offset := 0; ; {
		got, err := c.findingEvidence(t.Context(), testUUIDv1, raw, offset, 2)
		if err != nil {
			t.Fatal(err)
		}
		wantRows := min(2, len(rows)-offset)
		wantMore := offset+wantRows < len(rows)
		if got.TotalRows != len(rows) || got.Offset != offset || len(got.Rows) != wantRows || got.HasMore != wantMore {
			t.Fatalf("unexpected page metadata at offset %d: total=%d offset=%d returned=%d has_more=%v", offset, got.TotalRows, got.Offset, len(got.Rows), got.HasMore)
		}
		if got.Title != "Evidence" || got.Fields == nil || len(got.CodeLocations) != wantRows {
			t.Fatal("a page lost its field definitions, title, or code locations")
		}
		reconstructed = append(reconstructed, got.Rows...)
		if !got.HasMore {
			if got.NextOffset != 0 {
				t.Fatal("terminal page must not advertise a next offset")
			}
			break
		}
		if got.NextOffset != offset+wantRows {
			t.Fatalf("next offset = %d, want %d", got.NextOffset, offset+wantRows)
		}
		offset = got.NextOffset
	}
	wantIDs := [][]string{{"site-0", "site-1"}, {"site-2", "site-3"}, {"site-4"}}
	if !reflect.DeepEqual(requestIDs, wantIDs) {
		t.Fatalf("fetched locations outside the requested pages: %v", requestIDs)
	}
	wantJSON, _ := json.Marshal(rows)
	gotJSON, _ := json.Marshal(reconstructed)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatal("following next_offset failed to reconstruct the original full rows exactly")
	}
	terminal, err := c.findingEvidence(t.Context(), testUUIDv1, raw, len(rows), 2)
	if err != nil || terminal.Rows == nil || len(terminal.Rows) != 0 || terminal.CodeLocations == nil || terminal.HasMore || len(requestIDs) != 3 {
		t.Fatalf("terminal empty page must not fetch locations: evidence=%+v, err=%v", terminal, err)
	}
}

func TestFindingEvidence_PageLimitsAndValidation(t *testing.T) {
	rows := make([]any, 105)
	for i := range rows {
		rows[i] = map[string]any{"index": i}
	}
	raw, _ := json.Marshal(map[string]any{"rows": rows})
	c := New("http://unused", "test-token")
	for _, tc := range []struct {
		name                 string
		offset, limit, count int
		hasMore              bool
	}{
		{"default", 0, 0, 20, true},
		{"explicit", 0, 7, 7, true},
		{"clamped", 0, 101, 100, true},
		{"final full page", 5, 100, 100, false},
		{"final partial page", 104, 10, 1, false},
		{"empty terminal", 105, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.findingEvidence(t.Context(), testUUIDv1, raw, tc.offset, tc.limit)
			if err != nil {
				t.Fatal(err)
			}
			if got.TotalRows != 105 || got.Offset != tc.offset || len(got.Rows) != tc.count || got.HasMore != tc.hasMore || got.Rows == nil || got.CodeLocations == nil {
				t.Fatalf("unexpected page: %+v", got)
			}
			if tc.hasMore && got.NextOffset != tc.offset+tc.count || !tc.hasMore && got.NextOffset != 0 {
				t.Fatalf("next offset = %d", got.NextOffset)
			}
		})
	}
	for _, tc := range []struct {
		name          string
		raw           json.RawMessage
		offset, limit int
		want          string
	}{
		{"negative offset", raw, -1, 0, "evidence_offset must be non-negative"},
		{"negative limit", raw, 0, -1, "evidence_limit must be non-negative"},
		{"past final row", raw, 106, 0, "exceeds total evidence rows 105"},
		{"null context overshoot", json.RawMessage("null"), 1, 0, "exceeds total evidence rows 0"},
		{"missing context overshoot", nil, 1, 0, "exceeds total evidence rows 0"},
		{"null rows overshoot", json.RawMessage(`{"rows":null}`), 1, 0, "exceeds total evidence rows 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.findingEvidence(t.Context(), testUUIDv1, tc.raw, tc.offset, tc.limit)
			if got != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %+v, error %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestFindingEvidence_NoLocationRequests(t *testing.T) {
	for _, raw := range []string{"", "null", `{}`, `{"rows":null}`, `{"rows":[]}`, `{"rows":[{"path":"AndroidManifest.xml"}]}`} {
		t.Run(raw, func(t *testing.T) {
			var requests atomic.Int32
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusBadRequest)
			})
			got, err := c.findingEvidence(t.Context(), testUUIDv1, json.RawMessage(raw), 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got.Rows == nil || got.CodeLocations == nil {
				t.Fatalf("evidence arrays must be explicit: %+v", got)
			}
			if requests.Load() != 0 {
				t.Fatalf("evidence without location references made %d requests", requests.Load())
			}
		})
	}
}

func TestFindingEvidence_ResolvesEscapedReferencesAndReportsMissingData(t *testing.T) {
	const escapedID = "quoted\"location\nnext"
	ids := []string{"missing", "no-data", "null-data", escapedID}
	wantIDs, _ := json.Marshal(ids)
	var requests atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/graphql" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !strings.Contains(body.Query, "codeLocations(ids: "+string(wantIDs)+")") ||
			!strings.Contains(body.Query, `assessment(ref: "`+testUUIDv1+`")`) {
			t.Errorf("query must escape and deduplicate location references: %s", body.Query)
		}
		response := map[string]any{"data": map[string]any{"auto": map[string]any{"assessment": map[string]any{
			"codeLocations": []any{
				map[string]any{"id": escapedID, "data": map[string]any{"file": "src/Main.java", "start": 42}},
				map[string]any{"id": "null-data", "data": nil},
				map[string]any{"id": "no-data"},
			},
		}}}}
		_ = json.NewEncoder(w).Encode(response)
	})
	raw, _ := json.Marshal(map[string]any{"rows": []any{
		map[string]any{"location_id": escapedID},
		map[string]any{"locations": []any{
			map[string]any{"location_id": escapedID},
			map[string]any{"location_id": "missing"},
			map[string]any{"location_id": "no-data"},
		}},
		map[string]any{"nested": map[string]any{"location_id": "null-data"}},
	}})
	got, err := c.findingEvidence(t.Context(), testUUIDv1, raw, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.UnresolvedLocationIDs, []string{"missing", "no-data", "null-data"}) {
		t.Fatalf("unresolved references = %v", got.UnresolvedLocationIDs)
	}
	if len(got.Rows) != 3 || len(got.CodeLocations) != 3 || requests.Load() != 1 {
		t.Fatalf("evidence=%+v, requests=%d", got, requests.Load())
	}
	if got.Rows[0].(map[string]any)["location_id"] != escapedID {
		t.Fatal("resolving locations changed the original row reference")
	}
}

func TestFindingEvidence_CachePreservesNumbersAndReturnsFreshData(t *testing.T) {
	const large = "9007199254740993"
	const raw = `{"title":"Call site","view":"table","description":"Observed invocation","pdfView":"table","fields":{"address":{"max":9007199254740993}},"certificate":{"serial":9007199254740993},"rows":[{"location_id":"site","address":9007199254740993}]}`
	var requests atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"data":{"auto":{"assessment":{"codeLocations":[{"id":"site","data":{"address":9007199254740993,"entries":[{"method":"original"}]}}]}}}}`))
	})
	first, err := c.findingEvidence(t.Context(), testUUIDv1, json.RawMessage(raw), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	cacheKey := "finding_code_locations:" + testUUIDv1 + `:["site"]`
	expires := c.cache.m[cacheKey].exp
	first.Rows[0].(map[string]any)["address"] = "changed"
	first.Fields.(map[string]any)["address"] = nil
	first.CodeLocations[0].Data.(map[string]any)["entries"].([]any)[0].(map[string]any)["method"] = "changed"

	second, err := c.findingEvidence(t.Context(), testUUIDv1, json.RawMessage(raw), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || !c.cache.m[cacheKey].exp.Equal(expires) {
		t.Fatal("cache reuse should avoid both another request and extending the evidence expiry")
	}
	data := second.CodeLocations[0].Data.(map[string]any)
	values := []any{
		second.Rows[0].(map[string]any)["address"],
		second.Fields.(map[string]any)["address"].(map[string]any)["max"],
		second.Certificate.(map[string]any)["serial"],
		data["address"],
	}
	for _, value := range values {
		if number, ok := value.(json.Number); !ok || number.String() != large {
			t.Fatalf("evidence number lost precision or changed type: %#v", value)
		}
	}
	if data["entries"].([]any)[0].(map[string]any)["method"] != "original" {
		t.Fatal("a caller mutated the cached code-location data")
	}
	if second.Title != "Call site" || second.View != "table" || second.Description != "Observed invocation" || second.PDFView != "table" {
		t.Fatalf("REST context metadata was lost: %+v", second)
	}
	encoded, err := json.Marshal(second)
	if err != nil || strings.Count(string(encoded), large) != 4 {
		t.Fatalf("large evidence numbers must survive output JSON: %s, %v", encoded, err)
	}
	if _, err := c.findingEvidence(t.Context(), testUUIDv4, json.RawMessage(raw), 0, 0); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatal("location cache reused evidence from a different assessment")
	}
}

func TestFindingEvidence_UpstreamErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"graphql error", `{"data":{"auto":{"assessment":null}},"errors":[{"message":"access denied"}]}`, "access denied"},
		{"missing assessment", `{"data":{"auto":{"assessment":null}}}`, "verify the assessment reference and access"},
		{"missing auto", `{"data":{"auto":null}}`, "verify the assessment reference and access"},
		{"malformed locations", `{"data":{"auto":{"assessment":{"codeLocations":{}}}}}`, "decoding code locations"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = w.Write([]byte(tc.body))
			})
			for range 2 {
				got, err := c.findingEvidence(t.Context(), testUUIDv1, json.RawMessage(`{"rows":[{"location_id":"site"}]}`), 0, 0)
				if got != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %+v, error %v; want %q", got, err, tc.want)
				}
			}
			if requests.Load() != 2 {
				t.Fatal("failed evidence responses must not be cached")
			}
		})
	}
}

func TestFindingEvidence_AbsentLocationListsRemainUnresolved(t *testing.T) {
	for _, body := range []string{
		`{"data":{"auto":{"assessment":{}}}}`,
		`{"data":{"auto":{"assessment":{"codeLocations":null}}}}`,
		`{"data":{"auto":{"assessment":{"codeLocations":[]}}}}`,
	} {
		t.Run(body, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			})
			got, err := c.findingEvidence(t.Context(), testUUIDv1, json.RawMessage(`{"rows":[{"location_id":"site"}]}`), 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got.CodeLocations == nil || !reflect.DeepEqual(got.UnresolvedLocationIDs, []string{"site"}) {
				t.Fatalf("missing location data needs an explicit unresolved reference: %+v", got)
			}
		})
	}
}
