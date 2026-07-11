package nsauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Logout revokes and forgets the stored credentials for baseURL's host. It
// revokes the token remotely on a best-effort basis (a warning is printed if
// that fails), then deletes it locally regardless. Absent credentials are a
// no-op.
func Logout(ctx context.Context, baseURL string, store Store, out io.Writer) error {
	if out == nil {
		out = os.Stderr
	}
	host := HostKey(baseURL)

	creds, err := store.Load(host)
	if errors.Is(err, ErrNotFound) {
		fmt.Fprintf(out, "Not logged in to %s; nothing to do.\n", host)
		return nil
	}
	if err != nil {
		return err
	}

	if creds.TokenRef != "" {
		if err := revokeToken(ctx, baseURL, creds.TokenRef, creds.Token); err != nil {
			fmt.Fprintf(out, "Warning: could not revoke token %s remotely (%v); removing it locally anyway.\n", creds.TokenRef, err)
		}
	}
	if err := store.Delete(host); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	fmt.Fprintf(out, "Logged out of %s.\n", host)
	return nil
}

// revokeToken calls DELETE {baseURL}/user/token/{ref}. It uses the default HTTP
// client since revocation is a one-shot best-effort call against a real host.
func revokeToken(ctx context.Context, baseURL, ref, token string) error {
	u := strings.TrimRight(baseURL, "/") + "/user/token/" + url.PathEscape(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(strings.TrimSpace(string(body)), 200))
	}
	return nil
}
