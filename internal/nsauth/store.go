package nsauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

// ErrNotFound is returned by Store.Load and Store.Delete when there are no
// stored credentials for the host.
var ErrNotFound = errors.New("nsauth: credentials not found")

// keyringService is the service name under which credentials are filed in the
// OS keychain (host is the per-entry user/account).
const keyringService = "nsmcp"

// Store persists credentials keyed by host (see HostKey).
type Store interface {
	Save(host string, c *Credentials) error
	Load(host string) (*Credentials, error)
	Delete(host string) error
}

// DefaultStore returns the standard store: the OS keychain when reachable,
// otherwise a 0600 JSON file under os.UserConfigDir()/nsmcp. The fallback
// engages per-operation, so a keychain that becomes available is used again.
func DefaultStore() Store {
	var path string
	if dir, err := os.UserConfigDir(); err == nil {
		path = filepath.Join(dir, "nsmcp", "credentials.json")
	}
	return &defaultStore{service: keyringService, file: &fileStore{path: path}}
}

type defaultStore struct {
	service string
	file    *fileStore
}

func (s *defaultStore) Save(host string, c *Credentials) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := keyring.Set(s.service, host, string(b)); err != nil {
		// Keyring unavailable (headless, no Secret Service) or value too big.
		return s.file.save(host, c)
	}
	return nil
}

func (s *defaultStore) Load(host string) (*Credentials, error) {
	v, err := keyring.Get(s.service, host)
	if err == nil {
		return decodeCredentials([]byte(v))
	}
	// Whether the keychain lacks the entry or is unreachable, a prior Save may
	// have landed in the file fallback — check it before giving up. (Save falls
	// back per-operation, so the two stores can diverge across sessions.)
	c, ferr := s.file.load(host)
	if ferr == nil {
		return c, nil
	}
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotFound
	}
	return nil, ferr
}

func (s *defaultStore) Delete(host string) error {
	// Delete from both places: fallback churn can leave the credential in
	// either. Success means it is gone from at least one that had it.
	kerr := keyring.Delete(s.service, host)
	ferr := s.file.delete(host)
	if kerr == nil || ferr == nil {
		return nil
	}
	if errors.Is(kerr, keyring.ErrNotFound) && errors.Is(ferr, ErrNotFound) {
		return ErrNotFound
	}
	if !errors.Is(ferr, ErrNotFound) {
		return ferr
	}
	return kerr
}

func decodeCredentials(b []byte) (*Credentials, error) {
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("nsauth: decoding stored credentials: %w", err)
	}
	return &c, nil
}

// fileStore is the keychain fallback: a single JSON object mapping host to
// credentials, written 0600 in a 0700 directory.
type fileStore struct {
	path string
}

func (f *fileStore) save(host string, c *Credentials) error {
	m, err := f.readAll()
	if err != nil {
		return err
	}
	m[host] = c
	return f.writeAll(m)
}

func (f *fileStore) load(host string) (*Credentials, error) {
	m, err := f.readAll()
	if err != nil {
		return nil, err
	}
	c, ok := m[host]
	if !ok {
		return nil, ErrNotFound
	}
	return c, nil
}

func (f *fileStore) delete(host string) error {
	m, err := f.readAll()
	if err != nil {
		return err
	}
	if _, ok := m[host]; !ok {
		return ErrNotFound
	}
	delete(m, host)
	return f.writeAll(m)
}

func (f *fileStore) readAll() (map[string]*Credentials, error) {
	if f.path == "" {
		return nil, errors.New("nsauth: no config directory available for credential fallback")
	}
	b, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]*Credentials{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]*Credentials{}
	if len(bytes.TrimSpace(b)) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("nsauth: parsing %s: %w", f.path, err)
	}
	return m, nil
}

// writeAll persists the map atomically: a 0600 temp file renamed into place, so
// a crash mid-write can't leave a truncated or world-readable credentials file.
func (f *fileStore) writeAll(m map[string]*Credentials) error {
	if f.path == "" {
		return errors.New("nsauth: no config directory available for credential fallback")
	}
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".credentials-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, f.path)
}
