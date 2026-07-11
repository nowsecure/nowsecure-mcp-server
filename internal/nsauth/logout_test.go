package nsauth

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestLogout_RevokesAndDeletes(t *testing.T) {
	keyring.MockInit()

	var deletedPath, deletedAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		deletedPath = r.URL.Path
		deletedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	store := DefaultStore()
	host := HostKey(ts.URL)
	if err := store.Save(host, &Credentials{Token: "stored-tok", TokenRef: "ref-9"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var out bytes.Buffer
	if err := Logout(t.Context(), ts.URL, store, &out); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if deletedPath != "/user/token/ref-9" {
		t.Errorf("revoke path = %q", deletedPath)
	}
	if deletedAuth != "Bearer stored-tok" {
		t.Errorf("revoke auth = %q", deletedAuth)
	}
	if _, err := store.Load(host); !errors.Is(err, ErrNotFound) {
		t.Errorf("creds still present after logout: %v", err)
	}
}

func TestLogout_NotLoggedIn(t *testing.T) {
	keyring.MockInit()
	var out bytes.Buffer
	if err := Logout(t.Context(), "https://api.nowsecure.com", DefaultStore(), &out); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !strings.Contains(out.String(), "Not logged in") {
		t.Errorf("output = %q, want a no-op message", out.String())
	}
}

func TestLogout_RevokeFailureStillDeletesLocally(t *testing.T) {
	keyring.MockInit()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	store := DefaultStore()
	host := HostKey(ts.URL)
	if err := store.Save(host, &Credentials{Token: "t", TokenRef: "ref-x"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var out bytes.Buffer
	if err := Logout(t.Context(), ts.URL, store, &out); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !strings.Contains(out.String(), "Warning") {
		t.Errorf("expected a warning about failed revoke: %q", out.String())
	}
	if _, err := store.Load(host); !errors.Is(err, ErrNotFound) {
		t.Errorf("creds not deleted locally after revoke failure: %v", err)
	}
}
