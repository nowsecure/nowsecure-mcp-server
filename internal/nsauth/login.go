package nsauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Options configures Login. Only ClientID is mandatory; the rest fall back to
// the production defaults in withDefaults.
type Options struct {
	Issuer         string             // Auth0 issuer (default https://id.nowsecure.com)
	ClientID       string             // Auth0 native client id (required)
	Audience       string             // API audience (default https://app.nowsecure.com)
	BaseURL        string             // Platform API base (default https://api.nowsecure.com)
	TokenName      string             // name for the minted token (default nsmcp/<hostname>)
	ExpirationDays int                // minted token lifetime, 1-365 (default 365)
	Out            io.Writer          // user-facing progress (default os.Stderr)
	OpenBrowser    func(string) error // browser opener (nil = platform default; failure is non-fatal)
	HTTPClient     *http.Client       // nil = default; tests inject a client pointed at a fake server
}

// Credentials is the minted static Platform API token plus enough metadata to
// display and later revoke it. ExpiresAt is decoded from the token's exp claim
// and is zero when absent.
type Credentials struct {
	Token     string    `json:"token"`
	TokenRef  string    `json:"tokenRef"`
	Name      string    `json:"name"`
	MintedAt  time.Time `json:"mintedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Login runs the device-code flow and mints a static Platform API token. It
// prints progress (verification URL + user code) to Options.Out and attempts to
// open a browser, then blocks polling the token endpoint until the user
// authorizes or the device code expires. It does not persist anything; the
// caller stores the returned Credentials via a Store.
func Login(ctx context.Context, opts Options) (*Credentials, error) {
	o := opts.withDefaults()
	if o.ClientID == "" {
		return nil, errors.New("nsauth: ClientID is required")
	}
	if err := requireSecureIssuer(o.Issuer); err != nil {
		return nil, fmt.Errorf("nsauth: %w", err)
	}
	if o.ExpirationDays < 1 || o.ExpirationDays > 365 {
		return nil, fmt.Errorf("nsauth: ExpirationDays must be between 1 and 365, got %d", o.ExpirationDays)
	}

	httpClient := o.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 90 * time.Second}
	}
	// oauth2's device-flow helpers pick up the HTTP client from the context.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	cfg := &oauth2.Config{
		ClientID: o.ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:       o.Issuer + "/authorize",
			TokenURL:      o.Issuer + "/oauth/token",
			DeviceAuthURL: o.Issuer + "/oauth/device/code",
		},
		Scopes: []string{"openid", "profile", "email"},
	}

	// The audience is load-bearing: the Platform API only accepts tokens minted
	// for https://app.nowsecure.com. Auth0 takes it as a query param.
	da, err := cfg.DeviceAuth(ctx, oauth2.SetAuthURLParam("audience", o.Audience))
	if err != nil {
		return nil, fmt.Errorf("nsauth: requesting device code: %w", err)
	}

	verifyURL := firstNonEmpty(da.VerificationURIComplete, da.VerificationURI)
	fmt.Fprintf(o.Out, "\nTo authorize nsmcp, open this URL in your browser:\n\n    %s\n\n", verifyURL)
	fmt.Fprintf(o.Out, "and confirm the code: %s\n\n", da.UserCode)
	if verifyURL != "" {
		if err := o.OpenBrowser(verifyURL); err != nil {
			fmt.Fprintf(o.Out, "(couldn't open a browser automatically: %v — open the URL above manually)\n\n", err)
		}
	}
	fmt.Fprintln(o.Out, "Waiting for authorization…")

	tok, err := cfg.DeviceAccessToken(ctx, da)
	if err != nil {
		return nil, fmt.Errorf("nsauth: waiting for authorization: %w", err)
	}

	creds, err := mintToken(ctx, httpClient, o.BaseURL, tok.AccessToken, o.TokenName, o.ExpirationDays)
	if err != nil {
		return nil, err
	}
	if creds.ExpiresAt.IsZero() {
		fmt.Fprintf(o.Out, "Success — minted Platform API token %q.\n", creds.Name)
	} else {
		fmt.Fprintf(o.Out, "Success — minted Platform API token %q (expires %s).\n", creds.Name, creds.ExpiresAt.Format("2006-01-02"))
	}
	return creds, nil
}

func (o Options) withDefaults() Options {
	o.Issuer = firstNonEmpty(o.Issuer, defaultIssuer)
	o.Issuer = strings.TrimRight(o.Issuer, "/")
	o.Audience = firstNonEmpty(o.Audience, defaultAudience)
	o.BaseURL = strings.TrimRight(firstNonEmpty(o.BaseURL, defaultBaseURL), "/")
	if o.ExpirationDays == 0 {
		o.ExpirationDays = defaultExpirationDays
	}
	o.TokenName = firstNonEmpty(o.TokenName, defaultTokenName())
	if o.Out == nil {
		o.Out = os.Stderr
	}
	if o.OpenBrowser == nil {
		o.OpenBrowser = openBrowser
	}
	return o
}

func defaultTokenName() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		host = "cli"
	}
	return "nsmcp/" + host
}

// mintToken exchanges an Auth0 access token for a long-lived static Platform
// token via POST {baseURL}/user/token/.
func mintToken(ctx context.Context, client *http.Client, baseURL, accessToken, name string, expirationDays int) (*Credentials, error) {
	reqBody, err := json.Marshal(map[string]any{"name": name, "expirationDays": expirationDays})
	if err != nil {
		return nil, err
	}
	u := strings.TrimRight(baseURL, "/") + "/user/token/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nsauth: minting token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("nsauth: reading mint response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("nsauth: minting token: HTTP %d: %s", resp.StatusCode, truncate(strings.TrimSpace(string(body)), 300))
	}
	return parseMintResponse(body, name)
}

// parseMintResponse tolerantly extracts the token string and a reference from
// the mint response. Field names vary; it accepts "token" for the JWT string
// and "ref" or "id" for the handle, falling back to the token's own jti when
// neither is present.
func parseMintResponse(body []byte, fallbackName string) (*Credentials, error) {
	var mr struct {
		Token string `json:"token"`
		Ref   string `json:"ref"`
		ID    string `json:"id"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &mr); err != nil {
		return nil, fmt.Errorf("nsauth: decoding mint response: %w (body: %s)", err, truncate(strings.TrimSpace(string(body)), 300))
	}
	if mr.Token == "" {
		return nil, fmt.Errorf("nsauth: mint response contained no token string (body: %s)", truncate(strings.TrimSpace(string(body)), 300))
	}
	creds := &Credentials{
		Token:    mr.Token,
		TokenRef: firstNonEmpty(mr.Ref, mr.ID),
		Name:     firstNonEmpty(mr.Name, fallbackName),
		MintedAt: time.Now().UTC(),
	}
	// The minted token is itself a JWT: prefer its embedded metadata.
	if claims, err := DecodeClaims(mr.Token); err == nil {
		creds.ExpiresAt = claims.ExpiresAt
		if creds.TokenRef == "" {
			creds.TokenRef = claims.JTI
		}
		if !claims.IssuedAt.IsZero() {
			creds.MintedAt = claims.IssuedAt
		}
	}
	return creds, nil
}

// openBrowser is the platform-default opener. Failure is non-fatal: the caller
// has already printed the URL.
func openBrowser(url string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{url}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		name, args = "xdg-open", []string{url}
	}
	return exec.Command(name, args...).Start()
}
