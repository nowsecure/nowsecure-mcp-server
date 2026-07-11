// Package urlparse extracts NowSecure identifiers from console/deep-link URLs.
//
// It is pure and local (no network), turning a pasted console URL such as
//
//	https://app.nowsecure.com/app/android/com.example/assessment/987654321/findings/apk_janus
//
// into the platform, package, assessment ref, and finding id an operator can
// feed to the other tools.
package urlparse

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	uuidRE    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	numericRE = regexp.MustCompile(`^[0-9]+$`)
	platforms = map[string]bool{"android": true, "ios": true}
	// mariPathTokens flag a MARI URL by path (not just the mari.* host) so a
	// details/<uuid> segment following one of them is recognized on any host.
	mariPathTokens = map[string]bool{"mari": true, "app-search": true, "risk-intelligence": true}
)

// supportedShapes lists the URL forms Parse understands, quoted back in the
// no-identifiers error.
const supportedShapes = "app/<platform>/<package>, app/<app-uuid>[/assessment/<uuid-or-task>], " +
	"assessment/<uuid-or-task>, findings/<key> or #finding-<key>, group/<uuid>, " +
	"…/app-search/details/<mari-uuid> (MARI), and ?assessment=/?app=/?finding= query params"

// Parsed holds the identifiers extracted from a NowSecure URL. JSON keys match
// the parameter names of the tools that consume them (app_ref, assessment_ref,
// group_refs, ...) so the output can be passed through directly.
type Parsed struct {
	Platform          string   `json:"platform,omitempty"`
	Package           string   `json:"package,omitempty"`
	ApplicationRef    string   `json:"app_ref,omitempty"`
	AssessmentRef     string   `json:"assessment_ref,omitempty"`
	MARIAssessmentRef string   `json:"mari_assessment_ref,omitempty"`
	GroupRefs         []string `json:"group_refs,omitempty"`
	Finding           string   `json:"finding,omitempty"`
	Host              string   `json:"host,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
}

// Parse extracts identifiers from a NowSecure console URL or path.
func Parse(raw string) (*Parsed, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty URL")
	}
	// Accept bare paths as well as absolute URLs.
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	p := &Parsed{Host: u.Host}

	// Collect path segments plus any fragment path (deep links use "#/app/...").
	// A fragment can carry its own query ("#/app/...?assessment=<uuid>"), which
	// url.Parse leaves glued to the fragment — split it off so it neither
	// corrupts the last segment nor loses its ids.
	frag := u.Fragment
	fragQuery := url.Values{}
	if i := strings.IndexByte(frag, '?'); i >= 0 {
		if q, err := url.ParseQuery(frag[i+1:]); err == nil {
			fragQuery = q
		}
		frag = frag[:i]
	}
	segs := splitSegs(u.Path)
	if frag != "" {
		segs = append(segs, splitSegs(frag)...)
	}

	mariCtx := strings.HasPrefix(strings.ToLower(u.Host), "mari.")
	for i := 0; i < len(segs); i++ {
		if mariPathTokens[strings.ToLower(segs[i])] {
			mariCtx = true
		}
		switch segs[i] {
		case "app", "apps":
			// app/<platform>/<package> or app/<application-uuid>
			if i+1 < len(segs) {
				switch {
				case platforms[strings.ToLower(segs[i+1])]:
					p.Platform = strings.ToLower(segs[i+1])
					if i+2 < len(segs) {
						p.Package = segs[i+2]
					}
				case uuidRE.MatchString(segs[i+1]):
					p.ApplicationRef = segs[i+1]
				case looksLikeID(segs[i+1]):
					p.Warnings = append(p.Warnings, fmt.Sprintf("unrecognized app id %q ignored (expected a UUID or <platform>/<package>)", segs[i+1]))
				}
			}
		case "assessment", "assessments":
			if i+1 < len(segs) {
				id := segs[i+1]
				switch {
				case uuidRE.MatchString(id):
					p.AssessmentRef = id
				case numericRE.MatchString(id):
					// A numeric task id is accepted wherever an assessment ref is.
					p.AssessmentRef = id
				default:
					p.Warnings = append(p.Warnings, fmt.Sprintf("unrecognized assessment id %q ignored", id))
				}
			}
		case "group", "groups":
			if i+1 < len(segs) {
				switch {
				case uuidRE.MatchString(segs[i+1]):
					p.GroupRefs = append(p.GroupRefs, segs[i+1])
				case looksLikeID(segs[i+1]):
					p.Warnings = append(p.Warnings, fmt.Sprintf("unrecognized group id %q ignored (expected a UUID)", segs[i+1]))
				}
			}
		case "details":
			// MARI console: <mari|app-search|risk-intelligence>/details/<uuid>,
			// e.g. mari.nowsecure.com/app-search/details/<uuid>.
			if mariCtx && i+1 < len(segs) {
				switch {
				case uuidRE.MatchString(segs[i+1]):
					p.MARIAssessmentRef = segs[i+1]
				case looksLikeID(segs[i+1]):
					p.Warnings = append(p.Warnings, fmt.Sprintf("unrecognized MARI assessment id %q ignored (expected a UUID)", segs[i+1]))
				}
			}
		case "finding", "findings":
			if i+1 < len(segs) {
				p.Finding = segs[i+1]
			}
		default:
			// Console anchors link findings as "#finding-<key>".
			if k, ok := strings.CutPrefix(segs[i], "finding-"); ok && k != "" {
				p.Finding = k
			}
		}
	}

	// Query params sometimes carry the ids too (e.g. ?assessment=<uuid>),
	// either in the real query or in the fragment's query.
	q := u.Query()
	getParam := func(key string) string {
		if v := q.Get(key); v != "" {
			return v
		}
		return fragQuery.Get(key)
	}
	if p.AssessmentRef == "" {
		if v := getParam("assessment"); uuidRE.MatchString(v) {
			p.AssessmentRef = v
		}
	}
	if p.ApplicationRef == "" {
		if v := getParam("app"); uuidRE.MatchString(v) {
			p.ApplicationRef = v
		}
	}
	if p.Finding == "" {
		if v := getParam("finding"); v != "" {
			p.Finding = v
		}
	}

	if p.Platform == "" && p.Package == "" && p.ApplicationRef == "" && p.AssessmentRef == "" &&
		p.MARIAssessmentRef == "" && len(p.GroupRefs) == 0 && p.Finding == "" {
		if len(p.Warnings) > 0 {
			return nil, fmt.Errorf("no NowSecure identifiers found in URL (warnings: %s); supported shapes: %s",
				strings.Join(p.Warnings, "; "), supportedShapes)
		}
		return nil, fmt.Errorf("no NowSecure identifiers found in URL; supported shapes: %s", supportedShapes)
	}
	return p, nil
}

// looksLikeID reports whether a segment plausibly is an id worth warning about
// when unrecognized: it carries a digit or dash and is not a known platform or
// navigation word (so plain nav segments like "dashboard" stay silent).
func looksLikeID(s string) bool {
	l := strings.ToLower(s)
	if platforms[l] || mariPathTokens[l] {
		return false
	}
	return strings.ContainsAny(s, "0123456789-")
}

func splitSegs(s string) []string {
	parts := strings.Split(s, "/")
	out := make([]string, 0, len(parts))
	for _, x := range parts {
		if x = strings.TrimSpace(x); x != "" {
			if dec, err := url.PathUnescape(x); err == nil {
				x = dec
			}
			out = append(out, x)
		}
	}
	return out
}
