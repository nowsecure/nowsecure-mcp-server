// Package config resolves runtime configuration from flags and environment.
//
// Keep it deliberately small: an API token, a base URL, and which product
// surface to expose. Token *acquisition* (the `nsmcp login` OAuth flow, keychain
// storage) lives in internal/nsauth; this package only consumes a stored token
// through the StoredToken hook so it stays free of that dependency.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// DefaultBaseURL is the NowSecure Platform API for production tenants.
// Tokens are minted at https://app.nowsecure.com/account/tokens.
const DefaultBaseURL = "https://api.nowsecure.com"

// tokenEnvVars are checked in order; the first non-empty value wins.
// NOWSECURE_API_TOKEN is canonical; the rest are accepted for compatibility
// with existing setups (including the older nsmcp's NSMCP_API_KEY).
var tokenEnvVars = []string{
	"NOWSECURE_API_TOKEN",
	"NOWSECURE_API_KEY",
	"NS_API_TOKEN",
	"NSMCP_API_TOKEN",
	"NSMCP_API_KEY",
}

// Config holds resolved settings for the server and CLI.
type Config struct {
	Token          string
	BaseURL        string
	EnablePlatform bool // expose DevSecOps / Platform tools
	EnableMARI     bool // expose Risk Intelligence (MARI) tools
}

// Inputs are the raw values Resolve merges: flag values (which may be empty),
// mode requirements, and an optional stored-token lookup.
type Inputs struct {
	Token    string // --token flag; beats env and StoredToken
	BaseURL  string // --base-url flag; beats NOWSECURE_API_URL and the default
	Platform bool
	MARI     bool

	// TokenOptional skips the token requirement. The HTTP resource-server mode
	// sets it: there every request carries its own verified bearer, so a static
	// token is never used.
	TokenOptional bool

	// StoredToken, when non-nil, is consulted after the flag and env vars, with
	// the resolved base URL. main wires it to the `nsmcp login` credential
	// store; tests and paths that must not touch the keychain leave it nil.
	StoredToken func(baseURL string) string
}

// Resolve merges flag values with environment fallbacks (flag wins) and
// validates the result.
func Resolve(in Inputs) (*Config, error) {
	if err := ValidateProductSelection(in.Platform, in.MARI); err != nil {
		return nil, err
	}
	baseURL, err := ResolveBaseURL(in.BaseURL)
	if err != nil {
		return nil, err
	}
	c := &Config{
		Token:          firstNonEmpty(in.Token, envToken()),
		BaseURL:        baseURL,
		EnablePlatform: in.Platform,
		EnableMARI:     in.MARI,
	}
	if c.Token == "" && in.StoredToken != nil {
		c.Token = strings.TrimSpace(in.StoredToken(c.BaseURL))
	}

	if c.Token == "" && !in.TokenOptional {
		return nil, fmt.Errorf("no API token found: run `nsmcp login`, set NOWSECURE_API_TOKEN, or pass --token. " +
			"Tokens can also be minted at https://app.nowsecure.com/account/tokens")
	}
	return c, nil
}

// ValidateProductSelection enforces the one-server/one-product invariant.
// Keeping it exported lets server constructors reject invalid Config values
// assembled directly rather than through Resolve.
func ValidateProductSelection(platform, mari bool) error {
	switch {
	case platform && mari:
		return fmt.Errorf("product selection is ambiguous: choose exactly one product")
	case !platform && !mari:
		return fmt.Errorf("choose exactly one product: pass --product platform or --product mari")
	default:
		return nil
	}
}

// ResolveBaseURL resolves the API base URL from the flag value, the
// NOWSECURE_API_URL env var, or the default (in that order), trims any
// trailing slash, and validates it. Exported for commands (login) that need
// the base URL before — or without — a full Resolve.
func ResolveBaseURL(flagBaseURL string) (string, error) {
	u := firstNonEmpty(flagBaseURL, os.Getenv("NOWSECURE_API_URL"), DefaultBaseURL)
	u = strings.TrimRight(u, "/")
	if err := validateBaseURL(u); err != nil {
		return "", err
	}
	return u, nil
}

// validateBaseURL rejects base URLs that would silently leak the bearer token:
// non-https schemes (http is allowed only for loopback hosts, for local
// testing) and URLs carrying userinfo. Every request sends the token in the
// Authorization header, so this must fail fast rather than surface later as
// confusing per-request errors.
func validateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid base URL %q: %v", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid base URL %q: missing host", raw)
	}
	if u.User != nil {
		return fmt.Errorf("invalid base URL %q: must not contain credentials", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("base URL %q uses plain http: the API token would be sent in cleartext (http is allowed only for localhost)", raw)
		}
	default:
		return fmt.Errorf("invalid base URL %q: scheme must be https", raw)
	}
	return nil
}

func envToken() string {
	for _, k := range tokenEnvVars {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
