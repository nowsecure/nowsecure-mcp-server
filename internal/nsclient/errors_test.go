package nsclient

// Error-surface tests: APIError message wording, status-specific hints, 400
// schema-ValidationError translation to tool vocabulary, upstream error-body
// interception (group-leak, invalid-cursor), snippet bounds, and the
// cross-namespace UUID-version hints.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// asAPIError reports whether err is an *APIError, storing it in target.
func asAPIError(err error, target **APIError) bool {
	e, ok := err.(*APIError)
	if ok {
		*target = e
	}
	return ok
}

func TestAPIError_HelpfulMessage(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"no license"}`))
	})
	_, err := c.ListMARIApps(context.Background(), ListMARIAppsParams{})
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !asAPIError(err, &apiErr) || apiErr.StatusCode != 403 {
		t.Fatalf("expected 403 APIError, got %v", err)
	}
}

func TestAPIError_Error(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusUnauthorized, "unauthorized"},
		{http.StatusForbidden, "forbidden"},
		{http.StatusNotFound, "not found"},
		{http.StatusTooManyRequests, "rate limited"},
	}
	for _, tc := range cases {
		e := &APIError{Op: "op", StatusCode: tc.status, Snippet: "BODYSNIP"}
		msg := e.Error()
		if !strings.Contains(msg, tc.want) {
			t.Errorf("status %d: message %q missing %q", tc.status, msg, tc.want)
		}
		if !strings.Contains(msg, "BODYSNIP") {
			t.Errorf("status %d: message %q missing appended body snippet", tc.status, msg)
		}
	}
}

// ---- 401: application-scope denial vs bad token ---------------------------

func TestAPIError_401AppScopeDenialDoesNotBlameToken(t *testing.T) {
	err := errFromUpstream(t, http.StatusUnauthorized,
		`{"message":"Unauthorized access to application"}`,
		func(c *Client) error {
			_, e := c.ListAssessments(context.Background(), ListAssessmentsParams{AppstoreKey: "1234"})
			return e
		})
	msg := err.Error()
	if !strings.Contains(msg, "use list_apps to discover valid refs") {
		t.Errorf("message %q missing app-scope hint", msg)
	}
	if strings.Contains(msg, "check the API token") {
		t.Errorf("message %q blames the token for an app-scope denial", msg)
	}
}

func TestAPIError_401PlainStillBlamesToken(t *testing.T) {
	err := errFromUpstream(t, http.StatusUnauthorized, `{"message":"Unauthorized"}`, listAppsErr)
	if msg := err.Error(); !strings.Contains(msg, "check the API token") {
		t.Errorf("message %q missing token hint for a plain 401", msg)
	}
}

// ---- 400: snippet bounds and pageSize hint ---------------------------------

func TestAPIError_SnippetKeepsLongValidationBodies(t *testing.T) {
	// A ~1KB body (old cap: 300 bytes) must survive intact, no ellipsis.
	long := `{"message":"Invalid filter value","allowed":"` + strings.Repeat("x", 950) + `"}`
	err := errFromUpstream(t, http.StatusBadRequest, long, listAppsErr)
	msg := err.Error()
	if !strings.Contains(msg, long) {
		t.Errorf("1KB error body was truncated: %q", msg)
	}
	if strings.Contains(msg, "…") {
		t.Errorf("unexpected ellipsis in %q", msg)
	}
}

func TestAPIError_SnippetStillBounded(t *testing.T) {
	err := errFromUpstream(t, http.StatusBadRequest, strings.Repeat("z", 5000), listAppsErr)
	msg := err.Error()
	if len(msg) > 2000 {
		t.Errorf("message length = %d, snippet cap not applied", len(msg))
	}
	if !strings.Contains(msg, "…") {
		t.Errorf("truncated message %q missing ellipsis", msg)
	}
}

func TestAPIError_400PageSizeHint(t *testing.T) {
	err := errFromUpstream(t, http.StatusBadRequest,
		`{"message":"child \"pageSize\" fails because [\"pageSize\" must be less than or equal to 50]"}`,
		listAppsErr)
	if msg := err.Error(); !strings.Contains(msg, "reduce page_size") {
		t.Errorf("message %q missing page_size hint", msg)
	}
}

func TestAPIError_400WithoutPageSizeNoHint(t *testing.T) {
	err := errFromUpstream(t, http.StatusBadRequest, `{"message":"bad filter"}`, listAppsErr)
	if msg := err.Error(); strings.Contains(msg, "reduce page_size") {
		t.Errorf("message %q has a page_size hint for an unrelated 400", msg)
	}
}

// ---- 500 "Invalid cursor" rewritten as caller guidance ---------------------

func TestInvalidCursor500BecomesClientError(t *testing.T) {
	err := errFromUpstream(t, http.StatusInternalServerError,
		`{"message":"Invalid cursor"}`,
		func(c *Client) error {
			_, e := c.ListApps(context.Background(), ListAppsParams{Cursor: "stale"})
			return e
		})
	msg := err.Error()
	if !strings.Contains(msg, "invalid or stale cursor — re-issue the query without cursor") {
		t.Errorf("message %q missing cursor guidance", msg)
	}
	if strings.Contains(msg, "500") {
		t.Errorf("message %q still reads as a server failure", msg)
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Errorf("cursor error should not be an APIError, got %v", apiErr)
	}
}

func TestPlain500StaysAPIError(t *testing.T) {
	err := errFromUpstream(t, http.StatusInternalServerError, `{"error":"boom"}`, listAppsErr)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 APIError, got %v", err)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("message %q missing body snippet", err.Error())
	}
}

// ---- unknown-group enumeration replaced ------------------------------------

func TestUnknownGroupEnumerationReplaced(t *testing.T) {
	err := errFromUpstream(t, http.StatusBadRequest,
		`{"message":"Unknown group. Allowed options are: `+testUUIDv1+`, `+testUUIDv4+`"}`,
		func(c *Client) error {
			// A UUID-shaped but unknown group reaches upstream (a non-UUID would
			// be caught client-side); the enumeration must still be replaced.
			_, e := c.ListApps(context.Background(), ListAppsParams{GroupRefs: []string{testUUIDv1}})
			return e
		})
	msg := err.Error()
	if !strings.Contains(msg, "unknown group_ref; discover groups via list_apps rows") {
		t.Errorf("message %q missing group discovery hint", msg)
	}
	if strings.Contains(msg, testUUIDv1) || strings.Contains(msg, testUUIDv4) {
		t.Errorf("message %q still leaks tenant group UUIDs", msg)
	}
}

// ---- 404 cross-namespace UUID hints ----------------------------------------

func TestAPIError_404MARIPathWithV1UUIDHintsPlatform(t *testing.T) {
	err := errFromUpstream(t, http.StatusNotFound, `{"message":"Not Found"}`,
		func(c *Client) error {
			_, e := c.GetMARIAssessment(context.Background(), testUUIDv1, nil)
			return e
		})
	if msg := err.Error(); !strings.Contains(msg, "this looks like a Platform ref") {
		t.Errorf("message %q missing Platform-ref hint", msg)
	}
}

func TestAPIError_404PlatformPathWithV4UUIDHintsMARI(t *testing.T) {
	err := errFromUpstream(t, http.StatusNotFound, `{"message":"Not Found"}`,
		func(c *Client) error {
			_, e := c.GetFinding(context.Background(), testUUIDv4)
			return e
		})
	if msg := err.Error(); !strings.Contains(msg, "this looks like a MARI ref") {
		t.Errorf("message %q missing MARI-ref hint", msg)
	}
}

func TestAPIError_404MatchingNamespaceNoHint(t *testing.T) {
	err := errFromUpstream(t, http.StatusNotFound, `{"message":"Not Found"}`,
		func(c *Client) error {
			_, e := c.GetMARIAssessment(context.Background(), testUUIDv4, nil)
			return e
		})
	msg := err.Error()
	if strings.Contains(msg, "looks like") {
		t.Errorf("message %q has a cross-namespace hint for a matching ref", msg)
	}
	if !strings.Contains(msg, "not found — check the ref/id") {
		t.Errorf("message %q missing the base 404 hint", msg)
	}
}

func TestAPIError_404NonUUIDPathNoHint(t *testing.T) {
	err := errFromUpstream(t, http.StatusNotFound, `{"message":"Not Found"}`,
		func(c *Client) error {
			_, e := c.GetFinding(context.Background(), "apk_janus")
			return e
		})
	if msg := err.Error(); strings.Contains(msg, "looks like") {
		t.Errorf("message %q has a cross-namespace hint without a UUID in the path", msg)
	}
}

// ---- 400 schema-ValidationError translated to tool vocabulary --------------

func TestAPIError_400ValidationTranslatedToToolVocab(t *testing.T) {
	// The exact wire shape of a real upstream ValidationError: errors[] holds
	// prose strings that embed the instance path mid-sentence, and the anyOf
	// sibling branches (constant, uuid-array) arrive alongside the enum line.
	body := `{"message":"Invalid request","error":true,"errors":[
		"The value at /filters/0/name must be equal to constant.",
		"The value at /filters/0/value must be a number but it was a string.",
		"The value at /filters/0/value must be one of: \"critical\", \"high\", \"medium\", or \"low\".",
		"The value at /filters/0/value/0 must be a valid uuid string but it was not.",
		"The value at /filters/0 must match a schema in anyOf."
	],"type":"ValidationError"}`
	err := errFromUpstream(t, http.StatusBadRequest, body, listAppsErr)
	msg := err.Error()
	if !strings.Contains(msg, `invalid filter value: must be one of: "critical", "high", "medium", or "low"`) {
		t.Errorf("message %q missing the translated filter line", msg)
	}
	if strings.Contains(msg, "anyOf") || strings.Contains(msg, "constant") || strings.Contains(msg, "/filters/0") {
		t.Errorf("message %q kept validation noise", msg)
	}
	if strings.Contains(msg, "uuid") {
		t.Errorf("message %q kept the uuid anyOf-branch noise next to the enum line", msg)
	}
	if n := strings.Count(msg, "must be one of"); n != 1 {
		t.Errorf("message %q has %d copies of the line, want 1 (deduped)", msg, n)
	}
}

func TestAPIError_400ValidationRewritesParamNames(t *testing.T) {
	body := `{"type":"ValidationError","errors":[
		{"instancePath":"/pageSize","message":"must be equal to or less than 50"},
		{"instancePath":"/orderBy","message":"must be one of \"score\", \"-score\""},
		{"instancePath":"/filters/2","message":"must be a valid uuid"}
	]}`
	err := errFromUpstream(t, http.StatusBadRequest, body, func(c *Client) error {
		_, e := c.AppsAffectedByFinding(context.Background(), "finding-1", AffectedByParams{})
		return e
	})
	msg := err.Error()
	for _, want := range []string{"page_size must be equal to or less than 50", "order_by must be one of", "invalid filter value: must be a valid uuid"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
	// The page_size hint must still fire even though pageSize was rewritten.
	if !strings.Contains(msg, "reduce page_size") {
		t.Errorf("message %q lost the page_size hint after translation", msg)
	}
}

func TestAPIError_400ValidationStringErrors(t *testing.T) {
	// The errors array may also arrive as plain "<path> <message>" strings.
	body := `{"errors":["/filters/0 must be one of \"a\", \"b\"","/filters/0 must match a schema in anyOf"]}`
	err := errFromUpstream(t, http.StatusBadRequest, body, listAppsErr)
	if msg := err.Error(); !strings.Contains(msg, `invalid filter value: must be one of "a", "b"`) {
		t.Errorf("message %q missing the translated string-form line", msg)
	}
}

func TestAPIError_400ValidationNoInformativeLineKeepsSnippet(t *testing.T) {
	body := `{"type":"ValidationError","errors":[{"instancePath":"/filters/0","message":"must match a schema in anyOf"}]}`
	err := errFromUpstream(t, http.StatusBadRequest, body, listAppsErr)
	if msg := err.Error(); !strings.Contains(msg, "anyOf") {
		t.Errorf("message %q should fall back to the raw snippet when nothing informative matched", msg)
	}
}

// TestAPIError_400ValidationGenericParamAndBarePath covers the two
// rewriteValidationLine branches the param-name cases miss: a generic
// instancePath (neither filters/pageSize/orderBy) keeps its name minus the
// slash, and a bare message with no path passes through verbatim.
func TestAPIError_400ValidationGenericParamAndBarePath(t *testing.T) {
	body := `{"type":"ValidationError","errors":[
		{"instancePath":"/since","message":"must be greater than 0"},
		"must be greater than 5"
	]}`
	err := errFromUpstream(t, http.StatusBadRequest, body, listAppsErr)
	msg := err.Error()
	if !strings.Contains(msg, "since must be greater than 0") {
		t.Errorf("message %q missing the generic-path line (default branch)", msg)
	}
	if !strings.Contains(msg, "must be greater than 5") {
		t.Errorf("message %q missing the bare-message line (empty-path branch)", msg)
	}
}
