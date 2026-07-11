package urlparse

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Parsed
	}{
		{
			name: "full android findings url with numeric task",
			in:   "https://app.nowsecure.com/app/android/com.example.app/assessment/987654321/findings/apk_janus",
			want: Parsed{Platform: "android", Package: "com.example.app", AssessmentRef: "987654321", Finding: "apk_janus", Host: "app.nowsecure.com"},
		},
		{
			name: "ios assessment uuid",
			in:   "https://app.nowsecure.com/app/ios/com.acme.wallet/assessment/6323aa10-0000-1111-2222-abcdef012345",
			want: Parsed{Platform: "ios", Package: "com.acme.wallet", AssessmentRef: "6323aa10-0000-1111-2222-abcdef012345", Host: "app.nowsecure.com"},
		},
		{
			name: "fragment deep link",
			in:   "https://app.nowsecure.com/#/app/android/com.foo/assessment/42",
			want: Parsed{Platform: "android", Package: "com.foo", AssessmentRef: "42", Host: "app.nowsecure.com"},
		},
		{
			name: "bare path",
			in:   "/app/ios/com.bar",
			want: Parsed{Platform: "ios", Package: "com.bar"},
		},
		{
			// REGRESSION: a fragment deep link carrying its own query used to
			// glue "?assessment=..." onto the package segment; the package must
			// come back clean and the assessment ref pulled from the frag query.
			name: "fragment query does not corrupt package",
			in:   "https://app.nowsecure.com/#/app/android/com.foo?assessment=6323aa10-0000-1111-2222-abcdef012345",
			want: Parsed{Platform: "android", Package: "com.foo", AssessmentRef: "6323aa10-0000-1111-2222-abcdef012345", Host: "app.nowsecure.com"},
		},
		{
			name: "fragment query carries finding",
			in:   "https://x.com/#/app/ios/com.bar?finding=apk_janus",
			want: Parsed{Platform: "ios", Package: "com.bar", Finding: "apk_janus", Host: "x.com"},
		},
		{
			name: "real query fallbacks",
			in:   "https://app.nowsecure.com/somepage?assessment=6323aa10-0000-1111-2222-abcdef012345&finding=apk_janus",
			want: Parsed{AssessmentRef: "6323aa10-0000-1111-2222-abcdef012345", Finding: "apk_janus", Host: "app.nowsecure.com"},
		},
		{
			name: "path assessment wins over query",
			in:   "https://app.nowsecure.com/app/android/com.x/assessment/aaaaaaaa-0000-1111-2222-abcdef012345?assessment=bbbbbbbb-0000-1111-2222-abcdef012345",
			want: Parsed{Platform: "android", Package: "com.x", AssessmentRef: "aaaaaaaa-0000-1111-2222-abcdef012345", Host: "app.nowsecure.com"},
		},
		{
			name: "numeric task in fragment",
			in:   "#/app/android/com.x/assessment/987654321",
			want: Parsed{Platform: "android", Package: "com.x", AssessmentRef: "987654321"},
		},
		{
			// REGRESSION: this shape used to lose the app UUID entirely.
			name: "app uuid with assessment uuid",
			in:   "https://app.nowsecure.com/app/cca82000-0000-1111-2222-abcdef012345/assessment/cd792000-0000-1111-2222-abcdef012345",
			want: Parsed{ApplicationRef: "cca82000-0000-1111-2222-abcdef012345", AssessmentRef: "cd792000-0000-1111-2222-abcdef012345", Host: "app.nowsecure.com"},
		},
		{
			// REGRESSION: this shape used to error "no NowSecure identifiers".
			name: "app uuid only",
			in:   "https://app.nowsecure.com/app/cca82000-0000-1111-2222-abcdef012345",
			want: Parsed{ApplicationRef: "cca82000-0000-1111-2222-abcdef012345", Host: "app.nowsecure.com"},
		},
		{
			name: "app query fallback",
			in:   "https://app.nowsecure.com/somepage?app=cca82000-0000-1111-2222-abcdef012345",
			want: Parsed{ApplicationRef: "cca82000-0000-1111-2222-abcdef012345", Host: "app.nowsecure.com"},
		},
		{
			name: "group url yields one-element array",
			in:   "https://app.nowsecure.com/group/38a6ce00-0000-1111-2222-abcdef012345/apps",
			want: Parsed{GroupRefs: []string{"38a6ce00-0000-1111-2222-abcdef012345"}, Host: "app.nowsecure.com"},
		},
		{
			name: "multiple group refs collected",
			in:   "https://app.nowsecure.com/group/38a6ce00-0000-1111-2222-abcdef012345/group/771b2200-0000-1111-2222-abcdef012345",
			want: Parsed{GroupRefs: []string{"38a6ce00-0000-1111-2222-abcdef012345", "771b2200-0000-1111-2222-abcdef012345"}, Host: "app.nowsecure.com"},
		},
		{
			name: "mari details url",
			in:   "https://mari.nowsecure.com/app-search/details/85afe000-0000-4111-2222-abcdef012345",
			want: Parsed{MARIAssessmentRef: "85afe000-0000-4111-2222-abcdef012345", Host: "mari.nowsecure.com"},
		},
		{
			// REGRESSION: MARI details on the app.* host used to error; the
			// mari/app-search path tokens must flag it regardless of host.
			name: "mari details via path token on app host",
			in:   "https://app.nowsecure.com/mari/app-search/details/2ee17546-89d0-4c54-8177-e0e8e7e84680",
			want: Parsed{MARIAssessmentRef: "2ee17546-89d0-4c54-8177-e0e8e7e84680", Host: "app.nowsecure.com"},
		},
		{
			name: "risk-intelligence path token flags details",
			in:   "https://app.nowsecure.com/risk-intelligence/details/2ee17546-89d0-4c54-8177-e0e8e7e84680",
			want: Parsed{MARIAssessmentRef: "2ee17546-89d0-4c54-8177-e0e8e7e84680", Host: "app.nowsecure.com"},
		},
		{
			name: "finding anchor fragment",
			in:   "https://app.nowsecure.com/app/android/com.x/assessment/42#finding-uses_http",
			want: Parsed{Platform: "android", Package: "com.x", AssessmentRef: "42", Finding: "uses_http", Host: "app.nowsecure.com"},
		},
		{
			// A malformed assessment segment is reported, not silently dropped —
			// the default-latest fallback would otherwise fetch the wrong scan.
			name: "malformed assessment id warns",
			in:   "https://app.nowsecure.com/app/android/com.x/assessment/not-a-ref",
			want: Parsed{Platform: "android", Package: "com.x", Host: "app.nowsecure.com", Warnings: []string{`unrecognized assessment id "not-a-ref" ignored`}},
		},
		{
			// An id-like segment after "app" that is neither a platform nor a
			// UUID (a truncated UUID here) is reported, not dropped.
			name: "malformed app id warns",
			in:   "https://app.nowsecure.com/app/cca820d2-3826-11f1/assessment/6323aa10-0000-1111-2222-abcdef012345",
			want: Parsed{AssessmentRef: "6323aa10-0000-1111-2222-abcdef012345", Host: "app.nowsecure.com", Warnings: []string{`unrecognized app id "cca820d2-3826-11f1" ignored (expected a UUID or <platform>/<package>)`}},
		},
		{
			name: "malformed group id warns",
			in:   "https://app.nowsecure.com/groups/team-42/app/android/com.x",
			want: Parsed{Platform: "android", Package: "com.x", Host: "app.nowsecure.com", Warnings: []string{`unrecognized group id "team-42" ignored (expected a UUID)`}},
		},
		{
			// Plain navigation words after "app" must not trip the id warning.
			name: "nav word after app is silent",
			in:   "https://app.nowsecure.com/apps/dashboard/app/ios/com.x",
			want: Parsed{Platform: "ios", Package: "com.x", Host: "app.nowsecure.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.in, err)
			}
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("Parse(%q)\n got  %+v\n want %+v", tt.in, *got, tt.want)
			}
		})
	}
}

// TestParseNoTaskKey guards that the dropped Task field leaves no "task" key in
// the JSON output; the numeric task id must surface only under assessment_ref.
func TestParseNoTaskKey(t *testing.T) {
	got, err := Parse("https://app.nowsecure.com/app/android/com.x/assessment/987654321")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"task"`) {
		t.Errorf("output carries a task key: %s", b)
	}
	if !strings.Contains(string(b), `"assessment_ref":"987654321"`) {
		t.Errorf("numeric task id missing from assessment_ref: %s", b)
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "https://example.com/unrelated/path"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) expected error, got nil", in)
		}
	}
}

func TestParseErrorMessages(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantSub []string
	}{
		{"invalid url", "http://exa mple.com/%zz", []string{"invalid URL"}},
		{"no identifiers", "https://app.nowsecure.com/settings/profile", []string{"no NowSecure identifiers"}},
		{
			// REGRESSION: a truncated app UUID errored with no mention of the
			// dropped segment; the warning must ride along in the error.
			name:    "dropped app id surfaces in error",
			in:      "https://app.nowsecure.com/app/cca820d2-3826-11f1",
			wantSub: []string{"no NowSecure identifiers", "warnings:", `cca820d2-3826-11f1`},
		},
		{
			name:    "dropped mari id surfaces in error",
			in:      "https://mari.nowsecure.com/app-search/details/85afe000-bad",
			wantSub: []string{"warnings:", "MARI assessment id", "85afe000-bad"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.in)
			if err == nil {
				t.Fatalf("Parse(%q) expected error, got nil", tt.in)
			}
			for _, sub := range tt.wantSub {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("Parse(%q) error = %q, want substring %q", tt.in, err.Error(), sub)
				}
			}
		})
	}
}
