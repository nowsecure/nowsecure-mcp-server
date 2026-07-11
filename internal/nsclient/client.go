// Package nsclient is a small HTTP client for the NowSecure Platform REST API.
//
// It covers only the read-only, low-context endpoints this MCP server exposes:
// portfolio applications, assessments, findings, and MARI (risk-intelligence).
// Auth is a static bearer token; every response is decoded into a purpose-built
// struct rather than passed through raw.
package nsclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Client talks to one NowSecure Platform tenant.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
	ua      string

	cache    *ttlCache      // in-process memo for heavy/idempotent reads
	registry *cacheRegistry // per-token caches handed out by WithToken
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the underlying *http.Client (useful in tests).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option { return func(c *Client) { c.ua = ua } }

// New returns a Client for baseURL authenticating with token.
func New(baseURL, token string, opts ...Option) *Client {
	// DefaultTransport caps idle conns per host at 2, so >2 parallel tool
	// calls open (and discard) fresh TLS; widen the pool for concurrent reads.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 16
	tr.MaxIdleConns = 64
	const ttl = 10 * time.Minute
	c := &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		token:    token,
		http:     &http.Client{Timeout: 60 * time.Second, Transport: tr},
		ua:       "nsmcp",
		cache:    newTTLCache(ttl),
		registry: newCacheRegistry(ttl),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// WithToken returns a shallow copy of c that authenticates with a different
// bearer, reusing the same HTTP client, base URL, and user agent. Used by the
// HTTP resource-server mode to derive a per-caller client from a shared base.
// The response cache is token-scoped, not shared: WithToken hands back the
// same cache for a token it has seen (so repeated per-request derivation stays
// warm) but never lets one caller's cached data surface under another bearer.
func (c *Client) WithToken(token string) *Client {
	cp := *c
	cp.token = token
	if c.registry != nil {
		cp.cache = c.registry.cacheFor(token)
	}
	return &cp
}

// APIError is returned for non-2xx responses. It keeps a bounded body snippet
// so the model gets an actionable message without a giant dump.
type APIError struct {
	Op         string
	StatusCode int
	Path       string // request path (no query), used for namespace-aware hints
	Snippet    string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("%s: HTTP %d", e.Op, e.StatusCode)
	if h := e.hint(); h != "" {
		msg += " (" + h + ")"
	}
	if e.Snippet != "" {
		msg += ": " + e.Snippet
	}
	return msg
}

// hint translates a status (plus body/path context) into agent guidance.
func (e *APIError) hint() string {
	switch e.StatusCode {
	case http.StatusBadRequest:
		// Upstream page-size caps surface as validation errors naming the
		// wire param (raw camelCase, or page_size once translated); point at
		// the tool param instead.
		if strings.Contains(e.Snippet, "pageSize") || strings.Contains(e.Snippet, "page_size") {
			return "reduce page_size"
		}
	case http.StatusUnauthorized:
		// Upstream also answers 401 (not 403/404) for an app the token cannot
		// see; blaming the token would send agents chasing an auth failure.
		if strings.Contains(strings.ToLower(e.Snippet), "application") {
			return "the requested app/key may not exist or the token lacks access to it — use list_apps to discover valid refs"
		}
		return "unauthorized — check the API token"
	case http.StatusForbidden:
		return "forbidden — the token may lack the required scope or license, e.g. Risk Intelligence for MARI"
	case http.StatusNotFound:
		h := "not found — check the ref/id"
		if x := crossNamespaceHint(e.Path); x != "" {
			h += "; " + x
		}
		return h
	case http.StatusTooManyRequests:
		return "rate limited — wait before retrying"
	}
	return ""
}

// crossNamespaceHint spots a ref pasted into the wrong API family: Platform
// refs are UUIDv1, MARI refs UUIDv4. Empty when the path holds no UUID or the
// version matches its namespace.
func crossNamespaceHint(path string) string {
	mari := strings.Contains(path, "/risk-intelligence/")
	for seg := range strings.SplitSeq(path, "/") {
		v, ok := uuidVersion(seg)
		if !ok {
			continue
		}
		if mari && v == '1' {
			return "this looks like a Platform ref — use the matching Platform tool"
		}
		if !mari && v == '4' {
			return "this looks like a MARI ref — use the matching MARI tool"
		}
	}
	return ""
}

// uuidVersion returns the RFC 4122 version nibble ('1'…'5') of s when s is a
// canonical 8-4-4-4-12 UUID.
func uuidVersion(s string) (byte, bool) {
	if len(s) != 36 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return 0, false
			}
		default:
			if !isHex(c) {
				return 0, false
			}
		}
	}
	return s[14], true // first hex digit of the third group
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// maxBodyBytes caps how much of a response body is read (defense against a
// misbehaving endpoint, not a pagination substitute).
const maxBodyBytes = 64 << 20

// maxRetries is how many times a request is re-attempted after a retryable
// status (429 or transient 5xx). GETs are idempotent, so retrying is safe.
const maxRetries = 2

// getJSON performs a GET and decodes the JSON body into out, retrying briefly
// on 429/502/503/504.
func (c *Client) getJSON(ctx context.Context, op, path string, query url.Values, out any) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.ua)

		resp, err := c.http.Do(req)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		_ = resp.Body.Close()
		if err != nil {
			return fmt.Errorf("%s: reading response: %w", op, err)
		}
		if len(body) > maxBodyBytes {
			return fmt.Errorf("%s: response exceeded the %d MiB limit", op, maxBodyBytes>>20)
		}

		if retryable(resp.StatusCode) && attempt < maxRetries {
			if err := sleepBeforeRetry(ctx, resp.Header.Get("Retry-After"), attempt); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lower := strings.ToLower(string(body))
			// Upstream reports a bad or expired cursor as a 500; surface it as
			// caller guidance instead of a server failure.
			if resp.StatusCode == http.StatusInternalServerError && strings.Contains(lower, "invalid cursor") {
				return fmt.Errorf("%s: invalid or stale cursor — re-issue the query without cursor", op)
			}
			snip := snippet(body)
			switch {
			// The upstream unknown-group error enumerates every tenant group
			// UUID (leaky, and it truncates); replace with a discovery hint.
			case strings.Contains(lower, "unknown group"):
				snip = "unknown group_ref; discover groups via list_apps rows"
			// A schema ValidationError dumps ~17 wire-field lines that never
			// name the tool param; keep only the ones stating an allowed value.
			case resp.StatusCode == http.StatusBadRequest:
				if t := translateValidation(body); t != "" {
					snip = t
				}
			}
			return &APIError{Op: op, StatusCode: resp.StatusCode, Path: path, Snippet: snip}
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("%s: decoding response: %w (body starts: %s)", op, err, snippet(body))
		}
		return nil
	}
}

// graphQL performs a POST /graphql query and decodes the data envelope into
// out. Queries here are read-only, so the GET retry policy applies unchanged.
func (c *Client) graphQL(ctx context.Context, op, query string, out any) error {
	payload, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/graphql", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", c.ua)

		resp, err := c.http.Do(req)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		_ = resp.Body.Close()
		if err != nil {
			return fmt.Errorf("%s: reading response: %w", op, err)
		}
		if len(body) > maxBodyBytes {
			return fmt.Errorf("%s: response exceeded the %d MiB limit", op, maxBodyBytes>>20)
		}
		if retryable(resp.StatusCode) && attempt < maxRetries {
			if err := sleepBeforeRetry(ctx, resp.Header.Get("Retry-After"), attempt); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return &APIError{Op: op, StatusCode: resp.StatusCode, Path: "/graphql", Snippet: snippet(body)}
		}
		var envelope struct {
			Data   json.RawMessage `json:"data"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("%s: decoding response: %w (body starts: %s)", op, err, snippet(body))
		}
		if len(envelope.Errors) > 0 {
			return fmt.Errorf("%s: graphql: %s", op, envelope.Errors[0].Message)
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return fmt.Errorf("%s: decoding data: %w", op, err)
		}
		return nil
	}
}

func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// sleepBeforeRetry waits out a short backoff (or the server's Retry-After,
// capped at 10s) while staying responsive to ctx cancellation.
func sleepBeforeRetry(ctx context.Context, retryAfter string, attempt int) error {
	delay := 500 * time.Millisecond << attempt
	if s, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && s > 0 {
		delay = time.Duration(s) * time.Second
	}
	if delay > 10*time.Second {
		delay = 10 * time.Second
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// filter is one entry in a NowSecure `filters` query array: {"name","value"}.
type filter struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

// filters is a builder for the repeated `filters=[{name,value}]` query param.
type filters []filter

func (f filters) add(name string, value any) filters {
	if value == nil {
		return f
	}
	if s, ok := value.(string); ok && s == "" {
		return f
	}
	return append(f, filter{Name: name, Value: value})
}

// apply encodes the filters as JSON into query["filters"] when non-empty.
func (f filters) apply(q url.Values) {
	if len(f) == 0 {
		return
	}
	b, _ := json.Marshal(f)
	q.Set("filters", string(b))
}

func setInt(q url.Values, key string, v int) {
	if v > 0 {
		q.Set(key, strconv.Itoa(v))
	}
}

func setStr(q url.Values, key, v string) {
	if strings.TrimSpace(v) != "" {
		q.Set(key, v)
	}
}

// setOrderBy sets orderBy, accepting the snake_case field names the tools speak
// (created_at, vulnerability_count, risk_score, ...) and translating them to the
// camelCase upstream expects; a leading '-' (descending) is preserved and an
// already-camelCase token passes through untouched.
func setOrderBy(q url.Values, v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	desc := strings.HasPrefix(v, "-")
	tok := snakeToLowerCamel(strings.TrimPrefix(v, "-"))
	if desc {
		tok = "-" + tok
	}
	q.Set("orderBy", tok)
}

// snakeToLowerCamel converts snake_case to lowerCamelCase, leaving a token with
// no underscore (a single word or already camelCase) unchanged.
func snakeToLowerCamel(s string) string {
	if !strings.Contains(s, "_") {
		return s
	}
	var b strings.Builder
	for p := range strings.SplitSeq(s, "_") {
		if p == "" {
			continue
		}
		if b.Len() == 0 {
			b.WriteString(p)
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		b.WriteString(p[1:])
	}
	return b.String()
}

// snippet bounds an error body for inclusion in messages. 1500 bytes keeps
// upstream validation errors (filter DSL dumps, UUID lists) intact instead of
// truncating them mid-array.
func snippet(b []byte) string {
	return truncate(strings.TrimSpace(string(b)), 1500)
}

// truncate cuts s to at most n bytes on a rune boundary, appending an ellipsis
// when anything was dropped.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// validationKeepPhrases are the substrings that mark a schema-validation line
// as informative (an allowed value or a bound), as opposed to the anyOf /
// "must be equal to constant" branch noise around it.
var validationKeepPhrases = []string{
	"must be one of",
	"must be a valid uuid",
	"must be equal to or less than",
	"must be greater than",
}

// translateValidation rewrites an upstream JSON-schema ValidationError body
// into a snippet that names the tool parameter instead of the wire field: it
// keeps only the informative lines, dedupes them, and maps the wire path to
// tool vocabulary. Returns "" when the body is not a recognizable
// ValidationError or carries no informative line.
func translateValidation(body []byte) string {
	var env struct {
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Errors) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(env.Errors))
	var lines []string
	for _, raw := range env.Errors {
		path, msg := validationParts(raw)
		msg = strings.TrimSpace(msg)
		if !containsAny(msg, validationKeepPhrases) {
			continue
		}
		line := rewriteValidationLine(path, msg)
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		lines = append(lines, line)
	}
	// An enum filter and a uuid-array filter are sibling anyOf branches; when an
	// enum filter line matched, a uuid filter line describes a branch the caller
	// never sent. Non-filter uuid lines are real errors and stay.
	if len(lines) > 1 && containsAny(strings.Join(lines, ";"), []string{"invalid filter value: must be one of"}) {
		kept := lines[:0]
		for _, l := range lines {
			if strings.HasPrefix(l, "invalid filter value: ") && strings.Contains(l, "must be a valid uuid") {
				continue
			}
			kept = append(kept, l)
		}
		lines = kept
	}
	return strings.Join(lines, "; ")
}

// validationParts extracts (path, message) from one errors[] entry, accepting
// a plain "<path> <message>" string, the v2 endpoints' prose form
// "The value at <path> <message>", or an object with an instance path and
// message field.
func validationParts(raw json.RawMessage) (path, msg string) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if strings.HasPrefix(s, "/") {
			if i := strings.IndexByte(s, ' '); i > 0 {
				return s[:i], s[i+1:]
			}
			return s, ""
		}
		if rest, ok := strings.CutPrefix(s, "The value at /"); ok {
			if i := strings.IndexByte(rest, ' '); i > 0 {
				return "/" + rest[:i], rest[i+1:]
			}
		}
		return "", s
	}
	var o struct {
		Path         string `json:"path"`
		InstancePath string `json:"instancePath"`
		DataPath     string `json:"dataPath"`
		Message      string `json:"message"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return firstNonEmpty(o.InstancePath, o.DataPath, o.Path), o.Message
	}
	return "", ""
}

// rewriteValidationLine maps a wire path onto tool vocabulary: filter entries
// become a generic "invalid filter value" (their /filters/N index is noise),
// pageSize/orderBy take their tool-param names, everything else loses the
// leading slash.
func rewriteValidationLine(path, msg string) string {
	switch {
	case strings.HasPrefix(path, "/filters/"):
		return "invalid filter value: " + msg
	case strings.HasPrefix(path, "/pageSize"):
		return "page_size " + msg
	case strings.HasPrefix(path, "/orderBy"):
		return "order_by " + msg
	case path == "":
		return msg
	default:
		return strings.TrimPrefix(path, "/") + " " + msg
	}
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// pageSizeFromCursor recovers the page size a cursor was minted with. Upstream
// reads the page size from the pageSize param, not the cursor, so following a
// cursor without repeating pageSize silently drops back to the default page;
// decoding the cursor's own {"limit":N} keeps a walk at its original stride.
// Returns 0 (meaning "leave unset") unless the cursor yields a positive limit.
func pageSizeFromCursor(cursor string) int {
	if cursor == "" {
		return 0
	}
	var raw []byte
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(cursor); err == nil {
			raw = b
			break
		}
	}
	if raw == nil {
		return 0
	}
	var v struct {
		Limit int `json:"limit"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.Limit < 1 {
		return 0
	}
	return v.Limit
}

// ---- tiny in-process TTL cache -------------------------------------------

type ttlCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]cacheEntry
}

type cacheEntry struct {
	val any
	exp time.Time
}

func newTTLCache(ttl time.Duration) *ttlCache {
	return &ttlCache{ttl: ttl, m: make(map[string]cacheEntry)}
}

func (c *ttlCache) get(key string) (any, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Now().After(e.exp) {
		return nil, false
	}
	return e.val, true
}

func (c *ttlCache) set(key string, val any) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Sweep expired entries so a long-lived server doesn't grow without bound.
	now := time.Now()
	for k, e := range c.m {
		if now.After(e.exp) {
			delete(c.m, k)
		}
	}
	c.m[key] = cacheEntry{val: val, exp: now.Add(c.ttl)}
}

// ---- per-token cache registry --------------------------------------------

// maxCacheRegistry bounds how many distinct-token caches a busy multi-tenant
// server retains; past it the least-recently-used entry is evicted.
const maxCacheRegistry = 64

// cacheRegistry hands out a ttlCache per bearer so HTTP/OAuth mode, which
// derives a client per request via WithToken, stays warm across requests
// without ever sharing a cache between callers.
type cacheRegistry struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]*registeredCache
}

type registeredCache struct {
	cache *ttlCache
	used  time.Time
}

func newCacheRegistry(ttl time.Duration) *cacheRegistry {
	return &cacheRegistry{ttl: ttl, m: make(map[string]*registeredCache)}
}

// cacheFor returns the cache for token, creating one on first use. Tokens are
// hashed so raw bearers are never map keys; a returning token gets its own
// cache back, a new one gets a fresh cache, and the two never coincide.
func (r *cacheRegistry) cacheFor(token string) *ttlCache {
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])

	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	// Drop caches untouched for longer than the TTL: their entries have all
	// expired, so a returning token would get a cold cache regardless.
	for k, e := range r.m {
		if now.Sub(e.used) > r.ttl {
			delete(r.m, k)
		}
	}
	if e, ok := r.m[key]; ok {
		e.used = now
		return e.cache
	}
	if len(r.m) >= maxCacheRegistry {
		var oldestKey string
		var oldest time.Time
		for k, e := range r.m {
			if oldestKey == "" || e.used.Before(oldest) {
				oldestKey, oldest = k, e.used
			}
		}
		delete(r.m, oldestKey)
	}
	nc := newTTLCache(r.ttl)
	r.m[key] = &registeredCache{cache: nc, used: now}
	return nc
}
