package mcpserver

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"nsmcp/internal/config"
)

const (
	testPlatformAudience = "https://app.nowsecure.com"
	testResourceAudience = "https://mcp.nowsecure.example"
	testPublicURL        = "https://mcp.example.test"
	testExchangedToken   = "EXCHANGED-TOKEN"
)

// fakeIssuer is a minimal Auth0-shaped authorization server: OIDC discovery,
// a JWKS, and a token endpoint that records the RFC 8693 exchange request.
type fakeIssuer struct {
	server *httptest.Server
	issuer string
	key    *rsa.PrivateKey
	kid    string

	tokenHits atomic.Int32
	mu        sync.Mutex
	lastForm  url.Values
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	fi := &fakeIssuer{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                fi.issuer,
			"authorization_endpoint":                fi.issuer + "/authorize",
			"token_endpoint":                        fi.issuer + "/oauth/token",
			"jwks_uri":                              fi.issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &fi.key.PublicKey,
			KeyID:     fi.kid,
			Algorithm: "RS256",
			Use:       "sig",
		}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fi.mu.Lock()
		fi.lastForm = r.PostForm
		fi.mu.Unlock()
		fi.tokenHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      testExchangedToken,
			"issued_token_type": accessTokenType,
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	})

	fi.server = httptest.NewServer(mux)
	fi.issuer = fi.server.URL
	t.Cleanup(fi.server.Close)
	return fi
}

// mint signs an RS256 JWT for this issuer with the given audience and expiry.
func (fi *fakeIssuer) mint(t *testing.T, audience string, exp time.Time, scope string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: fi.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", fi.kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss":   fi.issuer,
		"sub":   "auth0|user-123",
		"aud":   audience,
		"exp":   exp.Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"scope": scope,
	})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	tok, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return tok
}

func (fi *fakeIssuer) exchangeForm() url.Values {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	return fi.lastForm
}

func passthroughOpts(fi *fakeIssuer) HTTPOptions {
	return HTTPOptions{
		Addr:             ":0",
		PublicURL:        testPublicURL,
		Issuer:           fi.issuer,
		Audience:         testPlatformAudience,
		PlatformAudience: testPlatformAudience,
	}
}

func oboOpts(fi *fakeIssuer) HTTPOptions {
	return HTTPOptions{
		Addr:             ":0",
		PublicURL:        testPublicURL,
		Issuer:           fi.issuer,
		Audience:         testResourceAudience,
		PlatformAudience: testPlatformAudience,
		OBOClientID:      "obo-client",
		OBOClientSecret:  "obo-secret",
	}
}

// serveHandler builds the resource-server handler for opts/cfg and puts it
// behind an httptest server, returning that server's URL.
func serveHandler(t *testing.T, opts HTTPOptions, cfg *config.Config) *httptest.Server {
	t.Helper()
	h, err := newHTTPHandler(t.Context(), cfg, "test", opts)
	if err != nil {
		t.Fatalf("newHTTPHandler: %v", err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

// bearerRT injects a bearer token onto every outbound request.
type bearerRT struct {
	token string
	base  http.RoundTripper
}

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// connectMCP dials the MCP server over Streamable HTTP with the given bearer.
func connectMCP(t *testing.T, endpoint, token string) *mcp.ClientSession {
	t.Helper()
	transport := &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		HTTPClient:           &http.Client{Transport: bearerRT{token: token, base: http.DefaultTransport}},
		DisableStandaloneSSE: true,
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	cs, err := client.Connect(t.Context(), transport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// unauthedGet issues a GET carrying token (empty for none) and returns status
// and the WWW-Authenticate header.
func unauthedGet(t *testing.T, endpoint, token string) (status int, wwwAuthenticate string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
}

func TestHTTP_NoTokenChallenges(t *testing.T) {
	fi := newFakeIssuer(t)
	cfg := &config.Config{Token: "unused", BaseURL: "https://api.invalid", EnablePlatform: true}
	ts := serveHandler(t, passthroughOpts(fi), cfg)

	code, wa := unauthedGet(t, ts.URL, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	if !strings.Contains(wa, "resource_metadata=") {
		t.Errorf("WWW-Authenticate = %q, want a resource_metadata parameter", wa)
	}
	if !strings.Contains(wa, testPublicURL+"/.well-known/oauth-protected-resource") {
		t.Errorf("WWW-Authenticate = %q, want the protected-resource metadata URL", wa)
	}
}

func TestHTTP_ValidTokenInitialize(t *testing.T) {
	fi := newFakeIssuer(t)
	cfg := &config.Config{Token: "unused", BaseURL: "https://api.invalid", EnablePlatform: true, EnableMARI: true}
	opts := passthroughOpts(fi)
	ts := serveHandler(t, opts, cfg)

	tok := fi.mint(t, opts.Audience, time.Now().Add(time.Hour), "openid")
	cs := connectMCP(t, ts.URL, tok)

	init := cs.InitializeResult()
	if init == nil || init.ServerInfo == nil {
		t.Fatal("InitializeResult/ServerInfo is nil")
	}
	if init.ServerInfo.Name != "nsmcp" {
		t.Errorf("server name = %q, want nsmcp", init.ServerInfo.Name)
	}
	// A full list round-trip confirms the authed session is usable.
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(res.Tools) == 0 {
		t.Error("ListTools returned no tools")
	}
}

func TestHTTP_WrongAudienceRejected(t *testing.T) {
	fi := newFakeIssuer(t)
	cfg := &config.Config{Token: "unused", BaseURL: "https://api.invalid", EnablePlatform: true}
	opts := passthroughOpts(fi)
	ts := serveHandler(t, opts, cfg)

	tok := fi.mint(t, "https://some-other-api.example", time.Now().Add(time.Hour), "openid")
	code, _ := unauthedGet(t, ts.URL, tok)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for wrong audience", code)
	}
}

func TestHTTP_ExpiredTokenRejected(t *testing.T) {
	fi := newFakeIssuer(t)
	cfg := &config.Config{Token: "unused", BaseURL: "https://api.invalid", EnablePlatform: true}
	opts := passthroughOpts(fi)
	ts := serveHandler(t, opts, cfg)

	tok := fi.mint(t, opts.Audience, time.Now().Add(-time.Hour), "openid")
	code, _ := unauthedGet(t, ts.URL, tok)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for expired token", code)
	}
}

func TestHTTP_ProtectedResourceMetadata(t *testing.T) {
	fi := newFakeIssuer(t)
	cfg := &config.Config{Token: "unused", BaseURL: "https://api.invalid", EnablePlatform: true}
	opts := passthroughOpts(fi)
	ts := serveHandler(t, opts, cfg)

	resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200", resp.StatusCode)
	}
	var prm oauthex.ProtectedResourceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&prm); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if prm.Resource != testPublicURL {
		t.Errorf("resource = %q, want %q", prm.Resource, testPublicURL)
	}
	if len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != fi.issuer {
		t.Errorf("authorization_servers = %v, want [%q]", prm.AuthorizationServers, fi.issuer)
	}
}

func TestHTTP_OnBehalfOfExchangeAndCache(t *testing.T) {
	fi := newFakeIssuer(t)

	var platformAuth atomic.Value
	var platformHits atomic.Int32
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		platformHits.Add(1)
		platformAuth.Store(r.Header.Get("Authorization"))
		if r.URL.Path != "/v2/portfolio/applications" {
			t.Errorf("unexpected platform path %q", r.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
	}))
	defer platform.Close()

	opts := oboOpts(fi)
	cfg := &config.Config{Token: "unused", BaseURL: platform.URL, EnablePlatform: true}
	ts := serveHandler(t, opts, cfg)

	tok := fi.mint(t, opts.Audience, time.Now().Add(time.Hour), "openid")
	cs := connectMCP(t, ts.URL, tok)

	call := func() {
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "list_apps",
			Arguments: map[string]any{},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if res.IsError {
			t.Fatalf("tool error: %s", resultText(res))
		}
	}
	call()
	call()

	if got, _ := platformAuth.Load().(string); got != "Bearer "+testExchangedToken {
		t.Errorf("platform Authorization = %q, want Bearer %s", got, testExchangedToken)
	}
	if n := fi.tokenHits.Load(); n != 1 {
		t.Errorf("token-endpoint hits = %d, want 1 (second call served from cache)", n)
	}
	if n := platformHits.Load(); n != 2 {
		t.Errorf("platform hits = %d, want 2 (both tool calls reach upstream)", n)
	}

	form := fi.exchangeForm()
	if got := form.Get("grant_type"); got != oauthex.GrantTypeTokenExchange {
		t.Errorf("grant_type = %q, want %q", got, oauthex.GrantTypeTokenExchange)
	}
	if got := form.Get("subject_token"); got != tok {
		t.Errorf("subject_token = %q, want the inbound token", got)
	}
	if got := form.Get("audience"); got != testPlatformAudience {
		t.Errorf("audience = %q, want %q", got, testPlatformAudience)
	}
	if got := form.Get("client_id"); got != "obo-client" {
		t.Errorf("client_id = %q, want obo-client", got)
	}
	if got := form.Get("client_secret"); got != "obo-secret" {
		t.Errorf("client_secret = %q, want obo-secret", got)
	}
}

func TestHTTP_PassThroughUsesInboundToken(t *testing.T) {
	fi := newFakeIssuer(t)

	var platformAuth atomic.Value
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		platformAuth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"rows":[],"pageInfo":{"hasNextPage":false}}`))
	}))
	defer platform.Close()

	opts := passthroughOpts(fi)
	cfg := &config.Config{Token: "unused", BaseURL: platform.URL, EnablePlatform: true}
	ts := serveHandler(t, opts, cfg)

	tok := fi.mint(t, opts.Audience, time.Now().Add(time.Hour), "openid")
	cs := connectMCP(t, ts.URL, tok)

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "list_apps",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %s", resultText(res))
	}
	if got, _ := platformAuth.Load().(string); got != "Bearer "+tok {
		t.Errorf("platform Authorization = %q, want the inbound bearer (pass-through)", got)
	}
	if n := fi.tokenHits.Load(); n != 0 {
		t.Errorf("token-endpoint hits = %d, want 0 (pass-through performs no exchange)", n)
	}
}

func TestHTTP_MissingOBOCredentials(t *testing.T) {
	fi := newFakeIssuer(t)
	opts := oboOpts(fi)
	opts.OBOClientSecret = ""
	cfg := &config.Config{Token: "unused", BaseURL: "https://api.invalid", EnablePlatform: true}

	if _, err := newHTTPHandler(t.Context(), cfg, "test", opts); err == nil {
		t.Fatal("expected an error when OBO credentials are incomplete")
	}
}

func TestTokenExchanger_SweepsDeadCacheEntries(t *testing.T) {
	fi := newFakeIssuer(t)
	x, err := newTokenExchanger(oboOpts(fi))
	if err != nil {
		t.Fatal(err)
	}
	x.tokenEndpoint = fi.issuer + "/oauth/token"

	// Seed entries that can never be served again: expired, and zero-exp.
	x.cache["expired"] = cachedToken{token: "old", exp: time.Now().Add(-time.Minute)}
	x.cache["zero-exp"] = cachedToken{token: "old"}

	got, err := x.upstreamToken(t.Context(), "inbound-token", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("upstreamToken: %v", err)
	}
	if got != testExchangedToken {
		t.Fatalf("upstreamToken = %q, want %q", got, testExchangedToken)
	}

	x.mu.Lock()
	defer x.mu.Unlock()
	if _, ok := x.cache["expired"]; ok {
		t.Error("expired entry survived the write-path sweep")
	}
	if _, ok := x.cache["zero-exp"]; ok {
		t.Error("zero-exp entry survived the write-path sweep")
	}
	if len(x.cache) != 1 {
		t.Errorf("cache size = %d, want 1 (just the fresh exchange)", len(x.cache))
	}
}
