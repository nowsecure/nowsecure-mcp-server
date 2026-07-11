package config

import (
	"strings"
	"testing"
)

// clearTokenEnv blanks every token source (and the base-URL override) so a real
// token or URL from the developer's environment cannot leak into a test.
// t.Setenv restores the originals when the test (or subtest) finishes.
func clearTokenEnv(t *testing.T) {
	t.Helper()
	for _, k := range tokenEnvVars {
		t.Setenv(k, "")
	}
	t.Setenv("NOWSECURE_API_URL", "")
}

func TestResolve_FlagTokenBeatsEnv(t *testing.T) {
	clearTokenEnv(t)
	t.Setenv("NOWSECURE_API_TOKEN", "env-token")
	c, err := Resolve(Inputs{Token: "flag-token", Platform: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "flag-token" {
		t.Errorf("Token = %q, want flag-token (flag beats env)", c.Token)
	}
}

func TestResolve_EnvTokenFallbackOrder(t *testing.T) {
	// The canonical var wins over a compatibility alias.
	clearTokenEnv(t)
	t.Setenv("NOWSECURE_API_TOKEN", "canonical")
	t.Setenv("NOWSECURE_API_KEY", "legacy")
	c, err := Resolve(Inputs{Platform: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "canonical" {
		t.Errorf("Token = %q, want canonical (NOWSECURE_API_TOKEN wins)", c.Token)
	}

	// With the canonical var empty, the next alias in the chain wins.
	clearTokenEnv(t)
	t.Setenv("NOWSECURE_API_KEY", "legacy")
	t.Setenv("NS_API_TOKEN", "third")
	c, err = Resolve(Inputs{Platform: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "legacy" {
		t.Errorf("Token = %q, want legacy (NOWSECURE_API_KEY precedes NS_API_TOKEN)", c.Token)
	}
}

func TestResolve_WhitespaceEnvSkipped(t *testing.T) {
	clearTokenEnv(t)
	t.Setenv("NOWSECURE_API_TOKEN", "   ")
	t.Setenv("NOWSECURE_API_KEY", "real")
	c, err := Resolve(Inputs{Platform: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "real" {
		t.Errorf("Token = %q, want real (whitespace-only canonical is skipped)", c.Token)
	}
}

func TestResolve_MissingToken(t *testing.T) {
	// Must clear every source first, or a real token would leak in here.
	clearTokenEnv(t)
	_, err := Resolve(Inputs{Platform: true})
	if err == nil || !strings.Contains(err.Error(), "NOWSECURE_API_TOKEN") {
		t.Fatalf("error = %v, want a mention of NOWSECURE_API_TOKEN", err)
	}
}

func TestResolve_BaseURL(t *testing.T) {
	// Default when neither flag nor env provides one.
	clearTokenEnv(t)
	c, err := Resolve(Inputs{Token: "tok", Platform: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != DefaultBaseURL {
		t.Errorf("BaseURL = %q, want default %q", c.BaseURL, DefaultBaseURL)
	}

	// Flag beats the NOWSECURE_API_URL env var.
	clearTokenEnv(t)
	t.Setenv("NOWSECURE_API_URL", "https://env.example.com")
	c, err = Resolve(Inputs{Token: "tok", BaseURL: "https://flag.example.com", Platform: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != "https://flag.example.com" {
		t.Errorf("BaseURL = %q, want the flag value", c.BaseURL)
	}

	// Env is used when no flag is given.
	clearTokenEnv(t)
	t.Setenv("NOWSECURE_API_URL", "https://env.example.com")
	c, err = Resolve(Inputs{Token: "tok", Platform: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != "https://env.example.com" {
		t.Errorf("BaseURL = %q, want the env value", c.BaseURL)
	}

	// A trailing slash is trimmed.
	clearTokenEnv(t)
	c, err = Resolve(Inputs{Token: "tok", BaseURL: "https://api.example.com/", Platform: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != "https://api.example.com" {
		t.Errorf("BaseURL = %q, want the trailing slash trimmed", c.BaseURL)
	}
}

func TestResolve_ValidateBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
		substr  string
	}{
		{name: "https ok", url: "https://api.example.com", wantErr: false},
		{name: "http public rejected", url: "http://api.example.com", wantErr: true, substr: "cleartext"},
		{name: "http localhost ok", url: "http://localhost:8080", wantErr: false},
		{name: "http loopback ip ok", url: "http://127.0.0.1:9999", wantErr: false},
		{name: "credentials rejected", url: "https://user:pass@api.example.com", wantErr: true, substr: "credentials"},
		{name: "garbage rejected", url: "not a url", wantErr: true},
		{name: "scheme-less rejected", url: "api.example.com", wantErr: true},
		{name: "ftp rejected", url: "ftp://x", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearTokenEnv(t)
			// Valid token + one tool group so the only thing under test is the URL.
			_, err := Resolve(Inputs{Token: "tok", BaseURL: tc.url, Platform: true})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q", tc.url)
				}
				if tc.substr != "" && !strings.Contains(err.Error(), tc.substr) {
					t.Errorf("error = %q, want substring %q", err, tc.substr)
				}
			} else if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.url, err)
			}
		})
	}
}

func TestResolve_NoToolGroups(t *testing.T) {
	clearTokenEnv(t)
	_, err := Resolve(Inputs{Token: "tok", BaseURL: "https://api.example.com"})
	if err == nil || !strings.Contains(err.Error(), "tool groups") {
		t.Fatalf("error = %v, want a mention of tool groups", err)
	}
}

func TestResolve_StoredTokenFallback(t *testing.T) {
	// The store is consulted only when flag and env are empty, and receives the
	// resolved base URL.
	clearTokenEnv(t)
	var gotBaseURL string
	stored := func(baseURL string) string { gotBaseURL = baseURL; return "stored-token" }
	c, err := Resolve(Inputs{Platform: true, StoredToken: stored})
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "stored-token" {
		t.Errorf("Token = %q, want stored-token", c.Token)
	}
	if gotBaseURL != DefaultBaseURL {
		t.Errorf("StoredToken got base URL %q, want %q", gotBaseURL, DefaultBaseURL)
	}

	// Env beats the store.
	clearTokenEnv(t)
	t.Setenv("NOWSECURE_API_TOKEN", "env-token")
	c, err = Resolve(Inputs{Platform: true, StoredToken: func(string) string { return "stored-token" }})
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "env-token" {
		t.Errorf("Token = %q, want env-token (env beats store)", c.Token)
	}
}

func TestResolve_TokenOptional(t *testing.T) {
	// HTTP mode: no token from any source is fine, but base-URL and tool-group
	// validation still apply.
	clearTokenEnv(t)
	c, err := Resolve(Inputs{Platform: true, TokenOptional: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "" {
		t.Errorf("Token = %q, want empty", c.Token)
	}
	if _, err := Resolve(Inputs{TokenOptional: true}); err == nil {
		t.Error("want a tool-groups error even when the token is optional")
	}
}
