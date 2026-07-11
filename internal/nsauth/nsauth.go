// Package nsauth is the interactive OAuth login library for the nsmcp CLI.
//
// It runs the OAuth 2.0 device authorization flow (RFC 8628) against the
// NowSecure Auth0 tenant, then trades the resulting short-lived access token
// for a long-lived static Platform API token via POST /user/token/. The static
// token — not the OAuth access token — is what the CLI stores and uses, which
// sidesteps refresh entirely.
//
// Scope constraints: this is a pure library. It has no dependency on cobra and
// never touches the server, client, or global config. The caller owns the CLI
// surface and decides where the returned credentials are stored (see Store).
package nsauth

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Well-known defaults. These are production values; the ClientID has no default
// because a dedicated Auth0 native client must be provisioned per deployment.
const (
	defaultIssuer         = "https://id.nowsecure.com"
	defaultAudience       = "https://app.nowsecure.com"
	defaultBaseURL        = "https://api.nowsecure.com"
	defaultExpirationDays = 365
)

// requireSecureIssuer rejects issuer URLs that would carry the device-code
// exchange — and with it a live Platform-audience access token — over
// cleartext. Same rule as the config package's base-URL validation: https
// only, with plain http allowed for loopback (local test issuers). The issuer
// is env-controlled (NOWSECURE_OAUTH_ISSUER), so this is a boundary check.
func requireSecureIssuer(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid issuer %q: %v", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid issuer %q: missing host", raw)
	}
	if u.User != nil {
		return fmt.Errorf("invalid issuer %q: must not contain credentials", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("issuer %q uses plain http: the OAuth access token would be sent in cleartext (http is allowed only for localhost)", raw)
		}
	default:
		return fmt.Errorf("invalid issuer %q: scheme must be https", raw)
	}
	return nil
}

// HostKey derives the storage key (the API host) from a base URL, so a login
// saved by the CLI and a later Logout resolve to the same Store entry.
func HostKey(baseURL string) string {
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		return u.Host
	}
	return strings.TrimRight(baseURL, "/")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// truncate cuts s to at most n bytes on a rune boundary, appending an ellipsis
// when anything was dropped. Used to keep error snippets bounded.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
