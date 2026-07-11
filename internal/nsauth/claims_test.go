package nsauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// makeJWT builds an unsigned JWT with the given payload claims. The signature
// segment is a placeholder; nsauth never verifies it.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return hdr + "." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

func TestDecodeClaims(t *testing.T) {
	iat := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	exp := iat.Add(365 * 24 * time.Hour)
	token := makeJWT(t, map[string]any{
		"iss":  "lab-api.nowsecure.com",
		"sub":  "user-42",
		"name": "nsmcp/laptop",
		"jti":  "jti-abc",
		"iat":  iat.Unix(),
		"exp":  exp.Unix(),
	})

	c, err := DecodeClaims(token)
	if err != nil {
		t.Fatalf("DecodeClaims: %v", err)
	}
	if c.Issuer != "lab-api.nowsecure.com" || c.Subject != "user-42" || c.Name != "nsmcp/laptop" || c.JTI != "jti-abc" {
		t.Errorf("claims = %+v", c)
	}
	if !c.IssuedAt.Equal(iat) {
		t.Errorf("IssuedAt = %v, want %v", c.IssuedAt, iat)
	}
	if !c.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v, want %v", c.ExpiresAt, exp)
	}
}

func TestDecodeClaims_NotAJWT(t *testing.T) {
	if _, err := DecodeClaims("not-a-jwt"); err == nil {
		t.Fatal("expected error for non-JWT input")
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   error
	}{
		{"ok", http.StatusOK, nil},
		{"unauthorized", http.StatusUnauthorized, ErrInvalidToken},
		{"forbidden", http.StatusForbidden, ErrInvalidToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/user/token/" {
					t.Errorf("path = %q", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer tok-1" {
					t.Errorf("auth = %q", got)
				}
				w.WriteHeader(tc.status)
			}))
			defer ts.Close()

			err := Verify(context.Background(), ts.URL, "tok-1", ts.Client())
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerify_UnexpectedStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	err := Verify(context.Background(), ts.URL, "tok-1", ts.Client())
	if err == nil || errors.Is(err, ErrInvalidToken) {
		t.Fatalf("want transport error, got %v", err)
	}
}
