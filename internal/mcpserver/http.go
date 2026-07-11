package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"nsmcp/internal/config"
	"nsmcp/internal/nsclient"
)

// HTTPOptions configures the remote OAuth 2.1 resource-server mode. The server
// validates inbound Auth0-issued JWT bearers, exposes the tools over Streamable
// HTTP, and resolves an upstream NowSecure token per request.
type HTTPOptions struct {
	// Addr is the TCP listen address, e.g. ":8080".
	Addr string
	// PublicURL is the externally reachable base URL of this server and its
	// RFC 8707 resource identifier (advertised in protected-resource metadata
	// and the WWW-Authenticate challenge). Any trailing slash is trimmed.
	PublicURL string
	// Issuer is the OAuth authorization server issuer, e.g.
	// "https://id.nowsecure.com/". It must match the issuer in the provider's
	// discovery document and in token `iss` claims verbatim, trailing slash
	// included (Auth0 uses one), or discovery and verification will reject it.
	Issuer string
	// Audience is the expected access-token audience for THIS server (the
	// resource-server identifier registered with the authorization server).
	Audience string
	// PlatformAudience is the audience the NowSecure Platform API accepts. When
	// it equals Audience the inbound bearer is passed upstream unchanged;
	// otherwise the inbound token is exchanged for a platform-audience token
	// (RFC 8693 on-behalf-of).
	PlatformAudience string
	// OBOClientID and OBOClientSecret authenticate this server as an OAuth
	// client for the on-behalf-of exchange. Required unless Audience ==
	// PlatformAudience (pass-through mode).
	OBOClientID     string
	OBOClientSecret string
}

// ServeHTTP runs the resource-server mode until ctx is cancelled. It performs
// OIDC discovery against the issuer, then serves the Streamable HTTP MCP
// endpoint (bearer-protected) plus the RFC 9728 protected-resource metadata
// endpoint, shutting down gracefully when ctx is done.
//
// TLS is out of scope: termination is expected upstream (load balancer or
// ingress). This server speaks plain HTTP on opts.Addr and must not be exposed
// to the internet directly.
func ServeHTTP(ctx context.Context, cfg *config.Config, version string, opts HTTPOptions) error {
	handler, err := newHTTPHandler(ctx, cfg, version, opts)
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              opts.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// newHTTPHandler builds the mux (protected MCP endpoint + protected-resource
// metadata) for the resource-server mode. Split from ServeHTTP so the wiring
// can be exercised in tests without binding a socket.
func newHTTPHandler(ctx context.Context, cfg *config.Config, version string, opts HTTPOptions) (http.Handler, error) {
	if opts.Addr == "" || opts.PublicURL == "" || opts.Issuer == "" || opts.Audience == "" || opts.PlatformAudience == "" {
		return nil, fmt.Errorf("http mode requires Addr, PublicURL, Issuer, Audience, and PlatformAudience")
	}
	publicURL := strings.TrimRight(opts.PublicURL, "/")

	exch, err := newTokenExchanger(opts)
	if err != nil {
		return nil, err
	}

	// OIDC discovery drives both bearer verification (JWKS) and, in OBO mode,
	// the token endpoint used for the exchange.
	provider, err := oidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		return nil, fmt.Errorf("http: OIDC discovery for issuer %q: %w", opts.Issuer, err)
	}
	if !exch.passthrough {
		exch.tokenEndpoint = provider.Endpoint().TokenURL
	}
	verifier := bearerVerifier(provider, opts.Audience)

	// Per-request upstream client: verify -> (pass through | exchange) -> bearer.
	base := nsclient.New(cfg.BaseURL, cfg.Token, nsclient.WithUserAgent("nsmcp/"+version))
	s := &srv{base: base}
	s.resolve = func(ctx context.Context) (*nsclient.Client, error) {
		ti := tokenInfoFromContext(ctx)
		if ti == nil {
			return nil, fmt.Errorf("no authenticated caller in request context")
		}
		raw, _ := ti.Extra[rawTokenExtraKey].(string)
		if raw == "" {
			return nil, fmt.Errorf("no bearer token available for the upstream call")
		}
		upstream, err := exch.upstreamToken(ctx, raw, ti.Expiration)
		if err != nil {
			return nil, err
		}
		return s.base.WithToken(upstream), nil
	}
	server := s.newServer(cfg, version)

	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	protected := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: publicURL + "/.well-known/oauth-protected-resource",
	})(streamable)

	prm := auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               publicURL,
		AuthorizationServers:   []string{opts.Issuer},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "NowSecure Platform & MARI",
	})

	mux := http.NewServeMux()
	mux.Handle("/.well-known/oauth-protected-resource", prm)
	mux.Handle("/", protected)
	return mux, nil
}

// rawTokenExtraKey is the TokenInfo.Extra key under which the verifier stashes
// the raw inbound bearer, needed downstream for pass-through / OBO exchange.
const rawTokenExtraKey = "raw_token"

// bearerVerifier adapts a go-oidc RS256+aud+exp+iss check into the go-sdk
// TokenVerifier. It records the raw token for upstream use. RequireBearerToken
// rejects a zero Expiration, so tokens without an exp claim (which go-oidc also
// rejects) never reach a handler.
func bearerVerifier(provider *oidc.Provider, audience string) auth.TokenVerifier {
	v := provider.Verifier(&oidc.Config{ClientID: audience})
	return func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		idt, err := v.Verify(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
		}
		var claims struct {
			Scope string `json:"scope"`
		}
		_ = idt.Claims(&claims)
		return &auth.TokenInfo{
			Scopes:     strings.Fields(claims.Scope),
			Expiration: idt.Expiry,
			UserID:     idt.Subject,
			Extra:      map[string]any{rawTokenExtraKey: token},
		}, nil
	}
}

// accessTokenType is the RFC 8693 URN for OAuth 2.0 access tokens, used as both
// the subject and requested token type in the on-behalf-of exchange.
const accessTokenType = "urn:ietf:params:oauth:token-type:access_token"

// oboSkew is subtracted from an exchanged token's cached lifetime so it is
// refreshed before it (or the inbound token backing it) actually expires.
const oboSkew = 30 * time.Second

// tokenExchanger turns an inbound bearer into the token used against the
// NowSecure Platform API. In pass-through mode it returns the inbound token
// unchanged; otherwise it performs an RFC 8693 on-behalf-of exchange and caches
// the result keyed by the inbound token's hash.
type tokenExchanger struct {
	passthrough      bool
	tokenEndpoint    string
	platformAudience string
	creds            *oauthex.ClientCredentials
	httpClient       *http.Client

	mu    sync.Mutex
	cache map[string]cachedToken
}

type cachedToken struct {
	token string
	exp   time.Time // already skew-adjusted; zero means "do not cache-hit"
}

// newTokenExchanger validates the credential requirements: pass-through mode
// (Audience == PlatformAudience) needs no client creds; OBO mode requires both.
func newTokenExchanger(opts HTTPOptions) (*tokenExchanger, error) {
	if opts.Audience == opts.PlatformAudience {
		return &tokenExchanger{passthrough: true}, nil
	}
	if opts.OBOClientID == "" || opts.OBOClientSecret == "" {
		return nil, fmt.Errorf("http: on-behalf-of exchange requires OBOClientID and OBOClientSecret "+
			"(audience %q differs from platform audience %q)", opts.Audience, opts.PlatformAudience)
	}
	return &tokenExchanger{
		platformAudience: opts.PlatformAudience,
		creds: &oauthex.ClientCredentials{
			ClientID:         opts.OBOClientID,
			ClientSecretAuth: &oauthex.ClientSecretAuth{ClientSecret: opts.OBOClientSecret},
		},
		httpClient: http.DefaultClient,
		cache:      make(map[string]cachedToken),
	}, nil
}

func (x *tokenExchanger) upstreamToken(ctx context.Context, inbound string, inboundExp time.Time) (string, error) {
	if x.passthrough {
		return inbound, nil
	}

	sum := sha256.Sum256([]byte(inbound))
	key := hex.EncodeToString(sum[:])

	x.mu.Lock()
	if e, ok := x.cache[key]; ok && !e.exp.IsZero() && time.Now().Before(e.exp) {
		tok := e.token
		x.mu.Unlock()
		return tok, nil
	}
	x.mu.Unlock()

	tok, err := oauthex.ExchangeToken(ctx, x.tokenEndpoint, &oauthex.TokenExchangeRequest{
		RequestedTokenType: accessTokenType,
		Audience:           x.platformAudience,
		Resource:           x.platformAudience,
		SubjectToken:       inbound,
		SubjectTokenType:   accessTokenType,
	}, x.creds, x.httpClient)
	if err != nil {
		return "", fmt.Errorf("on-behalf-of token exchange: %w", err)
	}

	exp := earliest(inboundExp, tok.Expiry)
	if !exp.IsZero() {
		exp = exp.Add(-oboSkew)
	}
	x.mu.Lock()
	// Sweep dead entries on each write (mirrors nsclient's ttlCache): rotated
	// inbound tokens hash to new keys, so without this the map of a long-lived
	// server grows without bound. Zero-exp entries can never cache-hit either.
	now := time.Now()
	for k, e := range x.cache {
		if e.exp.IsZero() || now.After(e.exp) {
			delete(x.cache, k)
		}
	}
	x.cache[key] = cachedToken{token: tok.AccessToken, exp: exp}
	x.mu.Unlock()
	return tok.AccessToken, nil
}

// earliest returns the earlier of two times, ignoring zero values (a zero time
// means "no known expiry").
func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case a.Before(b):
		return a
	default:
		return b
	}
}
