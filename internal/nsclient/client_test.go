package nsclient

// Cross-cutting client machinery: HTTP retry/decode, the snippet truncator,
// the token-keyed cache registry, cursor page-size decoding, orderBy alias
// translation, shared UUID/negativity validation guards, and uuidVersion.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// TestSetOrderBy_SnakeAliasTranslated confirms the tools' snake_case order_by
// tokens reach upstream as the camelCase it expects, sign preserved.
func TestSetOrderBy_SnakeAliasTranslated(t *testing.T) {
	var gotOrderBy string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotOrderBy = r.URL.Query().Get("orderBy")
		_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
	})
	if _, err := c.ListApps(context.Background(), ListAppsParams{OrderBy: "-vulnerability_count"}); err != nil {
		t.Fatal(err)
	}
	if gotOrderBy != "-vulnerabilityCount" {
		t.Errorf("orderBy = %q, want -vulnerabilityCount (snake alias translated)", gotOrderBy)
	}
}

func TestGetJSON_Retry(t *testing.T) {
	const okBody = `{"rows":[],"pageInfo":{"totalResults":0}}`
	cases := []struct {
		name       string
		statuses   []int
		retryAfter string
		wantReqs   int32
		wantErr    bool
		errSubstr  string
	}{
		{name: "429 then 200 honors Retry-After", statuses: []int{429, 200}, retryAfter: "1", wantReqs: 2},
		{name: "502 then 200", statuses: []int{502, 200}, wantReqs: 2},
		{name: "persistent 429", statuses: []int{429, 429, 429, 429}, wantReqs: 3, wantErr: true, errSubstr: "rate limited"},
		{name: "400 no retry", statuses: []int{400, 200}, wantReqs: 1, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reqs atomic.Int32
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				n := int(reqs.Add(1))
				status := tc.statuses[len(tc.statuses)-1]
				if n-1 < len(tc.statuses) {
					status = tc.statuses[n-1]
				}
				if status == http.StatusTooManyRequests && tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(status)
				if status >= 200 && status < 300 {
					_, _ = w.Write([]byte(okBody))
				} else {
					_, _ = w.Write([]byte(`{"error":"x"}`))
				}
			})
			_, err := c.ListMARIApps(context.Background(), ListMARIAppsParams{})
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.errSubstr != "" && (err == nil || !strings.Contains(err.Error(), tc.errSubstr)) {
				t.Errorf("error = %v, want substring %q", err, tc.errSubstr)
			}
			if got := reqs.Load(); got != tc.wantReqs {
				t.Errorf("requests = %d, want %d", got, tc.wantReqs)
			}
		})
	}
}

func TestGetJSON_DecodeErrorIncludesSnippet(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>oops</html>`))
	})
	_, err := c.ListMARIApps(context.Background(), ListMARIAppsParams{})
	if err == nil {
		t.Fatal("expected a decode error")
	}
	if !strings.Contains(err.Error(), "decoding response") || !strings.Contains(err.Error(), "<html>") {
		t.Errorf("error = %q, want 'decoding response' + body snippet", err)
	}
}

func TestTruncate_RuneBoundary(t *testing.T) {
	// 200 three-byte runes = 600 bytes; a 500-byte cut lands mid-rune (500%3!=0).
	s := strings.Repeat("€", 200)
	got := truncate(s, 500)
	if !utf8.ValidString(got) {
		t.Errorf("truncate produced invalid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncate result does not end with ellipsis: %q", got)
	}
	if got == s {
		t.Error("expected truncation, got the original string back")
	}
	// A string within the limit is returned verbatim, no ellipsis.
	if truncate("hi", 500) != "hi" {
		t.Error("short string should be returned unchanged")
	}
}

func TestWithToken_CacheRegistry(t *testing.T) {
	base := New("http://unused", "base")
	a1 := base.WithToken("tok-a")
	a2 := base.WithToken("tok-a")
	b1 := base.WithToken("tok-b")
	if a1.cache == nil {
		t.Fatal("WithToken produced a nil cache")
	}
	if a1.cache != a2.cache {
		t.Error("same token must reuse the same cache pointer")
	}
	if a1.cache == b1.cache {
		t.Error("different tokens must not share a cache")
	}
}

func TestCacheRegistry_Bounded(t *testing.T) {
	r := newCacheRegistry(time.Hour)
	for i := 0; i <= maxCacheRegistry; i++ {
		r.cacheFor(fmt.Sprintf("tok-%d", i))
	}
	if len(r.m) > maxCacheRegistry {
		t.Errorf("registry size = %d, want <= %d (oldest evicted)", len(r.m), maxCacheRegistry)
	}
}

func TestPageSizeFromCursor(t *testing.T) {
	payload := []byte(`{"limit":50,"offset":50}`)
	cases := []struct {
		name   string
		cursor string
		want   int
	}{
		{"std", base64.StdEncoding.EncodeToString(payload), 50},
		{"raw-std", base64.RawStdEncoding.EncodeToString(payload), 50},
		{"url", base64.URLEncoding.EncodeToString(payload), 50},
		{"raw-url", base64.RawURLEncoding.EncodeToString(payload), 50},
		{"empty", "", 0},
		{"not-base64", "!!!nope!!!", 0},
		{"no-limit", base64.StdEncoding.EncodeToString([]byte(`{"offset":10}`)), 0},
		{"zero-limit", base64.StdEncoding.EncodeToString([]byte(`{"limit":0}`)), 0},
	}
	for _, tc := range cases {
		if got := pageSizeFromCursor(tc.cursor); got != tc.want {
			t.Errorf("%s: pageSizeFromCursor = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestValidation_UUIDAndNegatives exercises the shared client-side guards
// (UUID-shaped refs, non-negative page_size/limit) across every endpoint that
// enforces them; all cases must fail before any HTTP call.
func TestValidation_UUIDAndNegatives(t *testing.T) {
	c := New("http://unused", "tok")
	ctx := context.Background()
	cases := []struct {
		name string
		call func() error
		want string
	}{
		{"application_refs non-uuid", func() error {
			_, e := c.ListApps(ctx, ListAppsParams{ApplicationRefs: []string{"com.intsig.camscanner"}})
			return e
		}, `app_refs entries must be application UUIDs (from list_apps app_ref); got "com.intsig.camscanner"`},
		{"list_apps group_refs non-uuid", func() error {
			_, e := c.ListApps(ctx, ListAppsParams{GroupRefs: []string{"nope"}})
			return e
		}, "group_refs entries must be group UUIDs"},
		{"list_apps negative page_size", func() error {
			_, e := c.ListApps(ctx, ListAppsParams{PageSize: -1})
			return e
		}, "page_size must not be negative"},
		{"list_assessments group_refs non-uuid", func() error {
			_, e := c.ListAssessments(ctx, ListAssessmentsParams{ApplicationRef: "app-1", GroupRefs: []string{"nope"}})
			return e
		}, "group_refs entries must be group UUIDs"},
		{"list_assessments negative page_size", func() error {
			_, e := c.ListAssessments(ctx, ListAssessmentsParams{ApplicationRef: "app-1", PageSize: -2})
			return e
		}, "page_size must not be negative"},
		{"affected group_refs non-uuid", func() error {
			_, e := c.AppsAffectedByFinding(ctx, "f", AffectedByParams{GroupRefs: []string{"nope"}})
			return e
		}, "group_refs entries must be group UUIDs"},
		{"affected negative page_size", func() error {
			_, e := c.AppsAffectedByFinding(ctx, "f", AffectedByParams{PageSize: -5})
			return e
		}, "page_size must not be negative"},
		{"findings negative limit", func() error {
			_, e := c.GetAssessmentFindings(ctx, FindingsParams{AppRef: "app-1", Limit: -3})
			return e
		}, "limit must not be negative"},
	}
	for _, tc := range cases {
		err := tc.call()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want substring %q", tc.name, err, tc.want)
		}
	}
}

func TestUUIDVersion(t *testing.T) {
	cases := []struct {
		in     string
		want   byte
		wantOK bool
	}{
		{testUUIDv1, '1', true},
		{testUUIDv4, '4', true},
		{strings.ToUpper(testUUIDv4), '4', true},
		{"not-a-uuid", 0, false},
		{"2f1a3b44-5c6d-11ee-8c99-0242ac12000", 0, false},   // 35 chars
		{"2f1a3b44-5c6d-11ee-8c99-0242ac1200022", 0, false}, // 37 chars
		{"2f1a3b44x5c6d-11ee-8c99-0242ac120002", 0, false},  // bad separator
		{"2f1a3b44-5c6d-11ee-8c99-0242ac12000g", 0, false},  // non-hex
	}
	for _, tc := range cases {
		got, ok := uuidVersion(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("uuidVersion(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}
