package nsclient

// Shared test helpers and fixtures for the nsclient package tests.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// UUID fixtures used across the validation and cross-namespace-hint tests.
// testUUIDv1 is a Platform-style ref (version nibble 1); testUUIDv4 is a
// MARI-style ref (version nibble 4).
const (
	testUUIDv1 = "2f1a3b44-5c6d-11ee-8c99-0242ac120002" // Platform-style ref
	testUUIDv4 = "9b2f8c1e-3d4a-4f5b-8c6d-7e8f9a0b1c2d" // MARI-style ref
)

// newTestClient returns a Client wired to an httptest server running h. The
// server is torn down when the test finishes.
func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return New(ts.URL, "test-token", WithHTTPClient(ts.Client()))
}

// errFromUpstream runs call against a server that answers every request with
// status/body and returns the resulting (non-nil) error.
func errFromUpstream(t *testing.T, status int, body string, call func(c *Client) error) error {
	t.Helper()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	err := call(c)
	if err == nil {
		t.Fatal("expected error")
	}
	return err
}

// listAppsErr is the simplest call that reaches the shared error surface: a
// bare ListApps whose only interesting output is its error.
func listAppsErr(c *Client) error {
	_, err := c.ListApps(context.Background(), ListAppsParams{})
	return err
}
