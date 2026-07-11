package nsauth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// deviceServer fakes the three endpoints Login touches: Auth0 device_code,
// Auth0 token, and the Platform mint. It records what it saw for assertions.
type deviceServer struct {
	mintToken string

	deviceAudience string  // audience param forwarded to /oauth/device/code
	mintAuth       string  // Authorization header on the mint call
	mintName       string  // "name" from the mint body
	mintExpiryDays float64 // "expirationDays" from the mint body
}

func (d *deviceServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device/code":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse device form: %v", err)
			}
			d.deviceAudience = r.PostFormValue("audience")
			if r.PostFormValue("client_id") == "" {
				t.Error("device request missing client_id")
			}
			writeJSON(w, map[string]any{
				"device_code":               "dev-code-1",
				"user_code":                 "WXYZ-1234",
				"verification_uri":          "https://id.nowsecure.com/activate",
				"verification_uri_complete": "https://id.nowsecure.com/activate?user_code=WXYZ-1234",
				"expires_in":                300,
				"interval":                  1,
			})
		case "/oauth/token":
			writeJSON(w, map[string]any{ //nolint:gosec // test fixture token value, not a real credential
				"access_token": "auth0-access-token",
				"token_type":   "Bearer",
				"expires_in":   86400,
			})
		case "/user/token/":
			d.mintAuth = r.Header.Get("Authorization")
			var body struct {
				Name           string  `json:"name"`
				ExpirationDays float64 `json:"expirationDays"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode mint body: %v", err)
			}
			d.mintName = body.Name
			d.mintExpiryDays = body.ExpirationDays
			writeJSON(w, map[string]any{"token": d.mintToken, "ref": "token-ref-1"})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestLogin_EndToEnd(t *testing.T) {
	exp := time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second).UTC()
	minted := makeJWT(t, map[string]any{"jti": "jti-1", "name": "nsmcp/host", "exp": exp.Unix()})

	ds := &deviceServer{mintToken: minted}
	ts := httptest.NewServer(ds.handler(t))
	defer ts.Close()

	var openedURL string
	var out bytes.Buffer
	creds, err := Login(t.Context(), Options{ //nolint:gosec // test fixture client id/token name, not a real credential
		Issuer:         ts.URL,
		ClientID:       "native-client-id",
		Audience:       "https://app.nowsecure.com",
		BaseURL:        ts.URL,
		TokenName:      "nsmcp/host",
		ExpirationDays: 30,
		Out:            &out,
		OpenBrowser:    func(u string) error { openedURL = u; return nil },
		HTTPClient:     ts.Client(),
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if creds.Token != minted {
		t.Errorf("token = %q, want minted JWT", creds.Token)
	}
	if creds.TokenRef != "token-ref-1" {
		t.Errorf("TokenRef = %q, want token-ref-1", creds.TokenRef)
	}
	if !creds.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v, want %v", creds.ExpiresAt, exp)
	}
	if ds.deviceAudience != "https://app.nowsecure.com" {
		t.Errorf("audience forwarded = %q", ds.deviceAudience)
	}
	if ds.mintAuth != "Bearer auth0-access-token" {
		t.Errorf("mint Authorization = %q", ds.mintAuth)
	}
	if ds.mintName != "nsmcp/host" || ds.mintExpiryDays != 30 {
		t.Errorf("mint body name=%q days=%v", ds.mintName, ds.mintExpiryDays)
	}
	if !strings.Contains(openedURL, "WXYZ-1234") {
		t.Errorf("browser opened %q, want the complete verification URL", openedURL)
	}
	if !strings.Contains(out.String(), "WXYZ-1234") {
		t.Errorf("progress output missing user code: %q", out.String())
	}
}

func TestLogin_RequiresClientID(t *testing.T) {
	_, err := Login(t.Context(), Options{Out: io.Discard, OpenBrowser: noopBrowser})
	if err == nil || !strings.Contains(err.Error(), "ClientID") {
		t.Fatalf("err = %v, want ClientID required", err)
	}
}

func TestLogin_RejectsBadExpiration(t *testing.T) {
	_, err := Login(t.Context(), Options{ClientID: "x", ExpirationDays: 999, Out: io.Discard, OpenBrowser: noopBrowser})
	if err == nil || !strings.Contains(err.Error(), "ExpirationDays") {
		t.Fatalf("err = %v, want ExpirationDays validation", err)
	}
}

func noopBrowser(string) error { return nil }

func TestParseMintResponse(t *testing.T) {
	jwtWithJTI := makeJWT(t, map[string]any{"jti": "jti-from-token", "exp": time.Now().Add(time.Hour).Unix()})

	tests := []struct {
		name     string
		body     string
		wantRef  string
		wantErr  bool
		wantName string
	}{
		{name: "ref field", body: `{"token":"tok","ref":"r1"}`, wantRef: "r1", wantName: "fallback"},
		{name: "id field", body: `{"token":"tok","id":"i1"}`, wantRef: "i1", wantName: "fallback"},
		{name: "name from response", body: `{"token":"tok","ref":"r1","name":"custom"}`, wantRef: "r1", wantName: "custom"},
		{name: "jti fallback", body: `{"token":"` + jwtWithJTI + `"}`, wantRef: "jti-from-token", wantName: "fallback"},
		{name: "no token string", body: `{"ref":"r1"}`, wantErr: true},
		{name: "malformed json", body: `{not json`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parseMintResponse([]byte(tc.body), "fallback")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got creds %+v", c)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMintResponse: %v", err)
			}
			if c.TokenRef != tc.wantRef {
				t.Errorf("TokenRef = %q, want %q", c.TokenRef, tc.wantRef)
			}
			if c.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", c.Name, tc.wantName)
			}
		})
	}
}

func TestLogin_RejectsInsecureIssuer(t *testing.T) {
	for _, issuer := range []string{
		"http://id.evil.example",
		"ftp://id.nowsecure.com",
		"https://user:pass@id.nowsecure.com",
	} {
		_, err := Login(t.Context(), Options{ClientID: "c", Issuer: issuer})
		if err == nil {
			t.Errorf("Login with issuer %q: want an error, got nil", issuer)
		}
	}
}
