package nsauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrInvalidToken reports that the Platform API rejected a token as
// unauthorized or forbidden.
var ErrInvalidToken = errors.New("nsauth: token rejected by the Platform API")

// Claims is the subset of a Platform/Auth0 JWT payload useful for a whoami
// display. It is decoded WITHOUT signature verification — treat it as
// informational only, never as an authorization decision.
type Claims struct {
	Issuer    string
	Subject   string
	Name      string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// DecodeClaims base64url-decodes the payload segment of a JWT and extracts the
// standard claims. It does not verify the signature.
func DecodeClaims(token string) (*Claims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 || parts[1] == "" {
		return nil, errors.New("nsauth: not a JWT: expected header.payload.signature")
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("nsauth: decoding JWT payload: %w", err)
	}
	var raw struct {
		Iss  string `json:"iss"`
		Sub  string `json:"sub"`
		Name string `json:"name"`
		JTI  string `json:"jti"`
		Iat  int64  `json:"iat"`
		Exp  int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("nsauth: decoding JWT claims: %w", err)
	}
	c := &Claims{Issuer: raw.Iss, Subject: raw.Sub, Name: raw.Name, JTI: raw.JTI}
	if raw.Iat > 0 {
		c.IssuedAt = time.Unix(raw.Iat, 0).UTC()
	}
	if raw.Exp > 0 {
		c.ExpiresAt = time.Unix(raw.Exp, 0).UTC()
	}
	return c, nil
}

// decodeSegment tolerates both padded and unpadded base64url, since not every
// issuer omits padding.
func decodeSegment(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// Verify checks a token against the Platform API by calling GET
// {baseURL}/user/token/. A 2xx means the token works; 401/403 returns
// ErrInvalidToken; anything else is surfaced as a transport error.
func Verify(ctx context.Context, baseURL, token string, client *http.Client) error {
	if client == nil {
		client = http.DefaultClient
	}
	u := strings.TrimRight(baseURL, "/") + "/user/token/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("nsauth: verifying token: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrInvalidToken
	default:
		return fmt.Errorf("nsauth: verifying token: unexpected HTTP %d", resp.StatusCode)
	}
}
