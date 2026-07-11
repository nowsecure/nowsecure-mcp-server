package nsauth

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

func sampleCreds() *Credentials {
	return &Credentials{
		Token:     "jwt-token",
		TokenRef:  "ref-1",
		Name:      "nsmcp/host",
		MintedAt:  time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2027, 7, 9, 0, 0, 0, 0, time.UTC),
	}
}

func TestDefaultStore_KeyringRoundtrip(t *testing.T) {
	keyring.MockInit()

	s := DefaultStore()
	const host = "api.nowsecure.com"

	if _, err := s.Load(host); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load before Save = %v, want ErrNotFound", err)
	}
	if err := s.Save(host, sampleCreds()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Load(host)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Token != "jwt-token" || got.TokenRef != "ref-1" || !got.ExpiresAt.Equal(sampleCreds().ExpiresAt) {
		t.Errorf("loaded creds = %+v", got)
	}
	if err := s.Delete(host); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Load(host); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load after Delete = %v, want ErrNotFound", err)
	}
}

func TestDefaultStore_FileFallback(t *testing.T) {
	// Force the keyring to be "unavailable" so every op falls back to the file.
	keyring.MockInitWithError(errors.New("no keyring here"))
	t.Cleanup(keyring.MockInit)

	path := filepath.Join(t.TempDir(), "nsmcp", "credentials.json")
	s := &defaultStore{service: keyringService, file: &fileStore{path: path}}
	const host = "lab-api.nowsecure.com"

	if err := s.Save(host, sampleCreds()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat credentials file: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("credentials file mode = %o, want 600", perm)
		}
	}

	got, err := s.Load(host)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Token != "jwt-token" {
		t.Errorf("loaded token = %q", got.Token)
	}
	if err := s.Delete(host); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Load(host); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load after Delete = %v, want ErrNotFound", err)
	}
}

func TestFileStore_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	f := &fileStore{path: filepath.Join(dir, "nsmcp", "credentials.json")}

	if _, err := f.load("h1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("load empty = %v, want ErrNotFound", err)
	}
	if err := f.delete("h1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing = %v, want ErrNotFound", err)
	}

	if err := f.save("h1", sampleCreds()); err != nil {
		t.Fatalf("save h1: %v", err)
	}
	if err := f.save("h2", &Credentials{Token: "second"}); err != nil {
		t.Fatalf("save h2: %v", err)
	}

	// Dir must be 0700, file 0600.
	if runtime.GOOS != "windows" {
		di, err := os.Stat(filepath.Dir(f.path))
		if err != nil {
			t.Fatalf("stat dir: %v", err)
		}
		if perm := di.Mode().Perm(); perm != 0o700 {
			t.Errorf("dir mode = %o, want 700", perm)
		}
		fi, _ := os.Stat(f.path)
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("file mode = %o, want 600", perm)
		}
	}

	// Both hosts coexist; deleting one leaves the other.
	if err := f.delete("h1"); err != nil {
		t.Fatalf("delete h1: %v", err)
	}
	if _, err := f.load("h1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("h1 still present after delete")
	}
	got, err := f.load("h2")
	if err != nil || got.Token != "second" {
		t.Fatalf("h2 load = %+v, %v", got, err)
	}
}
