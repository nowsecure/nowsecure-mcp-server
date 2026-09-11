package nsclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

const (
	defaultEvidenceLimit = 20
	maxEvidenceLimit     = 100
)

// findingEvidence keeps the REST evidence observations and resolves the code
// location references for the requested page that REST leaves unexpanded.
func (c *Client) findingEvidence(ctx context.Context, assessmentRef string, rawContext json.RawMessage, offset, limit int) (*FindingEvidence, error) {
	if offset < 0 {
		return nil, fmt.Errorf("evidence_offset must be non-negative")
	}
	if limit < 0 {
		return nil, fmt.Errorf("evidence_limit must be non-negative")
	}
	if limit == 0 {
		limit = defaultEvidenceLimit
	} else if limit > maxEvidenceLimit {
		limit = maxEvidenceLimit
	}
	evidence := &FindingEvidence{
		Rows:          []any{},
		CodeLocations: []FindingCodeLocation{},
		Offset:        offset,
	}

	// The REST endpoint spells pdfView in camel case. Its arbitrary fields and
	// row values must retain JSON numbers exactly, including large addresses.
	var wire struct {
		Title       string `json:"title"`
		View        string `json:"view"`
		Description string `json:"description"`
		Rows        []any  `json:"rows"`
		Fields      any    `json:"fields"`
		PDFView     any    `json:"pdfView"`
		Certificate any    `json:"certificate"`
	}
	if len(bytes.TrimSpace(rawContext)) != 0 && !bytes.Equal(bytes.TrimSpace(rawContext), []byte("null")) {
		decoder := json.NewDecoder(bytes.NewReader(rawContext))
		decoder.UseNumber()
		if err := decoder.Decode(&wire); err != nil {
			return nil, fmt.Errorf("get finding evidence: decoding context: %w", err)
		}
	}
	evidence.Title = wire.Title
	evidence.View = wire.View
	evidence.Description = wire.Description
	evidence.Fields = wire.Fields
	evidence.PDFView = wire.PDFView
	evidence.Certificate = wire.Certificate
	evidence.TotalRows = len(wire.Rows)
	if offset > evidence.TotalRows {
		return nil, fmt.Errorf("evidence_offset %d exceeds total evidence rows %d; use an offset from 0 to %d", offset, evidence.TotalRows, evidence.TotalRows)
	}
	end := evidence.TotalRows
	if limit < evidence.TotalRows-offset {
		end = offset + limit
	}
	if offset < end {
		evidence.Rows = wire.Rows[offset:end]
	}
	evidence.HasMore = end < evidence.TotalRows
	if evidence.HasMore {
		evidence.NextOffset = end
	}

	ids := findingLocationIDs(evidence.Rows)
	if len(ids) == 0 {
		return evidence, nil
	}
	locations, err := c.findingCodeLocations(ctx, assessmentRef, ids)
	if err != nil {
		return nil, err
	}
	evidence.CodeLocations = locations
	resolved := make(map[string]bool, len(locations))
	for _, location := range locations {
		if location.Data != nil {
			resolved[location.ID] = true
		}
	}
	for _, id := range ids {
		if !resolved[id] {
			evidence.UnresolvedLocationIDs = append(evidence.UnresolvedLocationIDs, id)
		}
	}
	return evidence, nil
}

// Location references occur both directly on old evidence rows and inside
// locations arrays. Walking the observations also supports nested rows.
func findingLocationIDs(rows []any) []string {
	seen := make(map[string]bool)
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			if id, ok := value["location_id"].(string); ok && id != "" {
				seen[id] = true
			}
			for _, child := range value {
				visit(child)
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	visit(rows)
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (c *Client) findingCodeLocations(ctx context.Context, assessmentRef string, ids []string) ([]FindingCodeLocation, error) {
	// JSON string/array literals are valid GraphQL literals, avoiding string
	// interpolation of unescaped assessment refs or upstream location IDs.
	refJSON, err := json.Marshal(assessmentRef)
	if err != nil {
		return nil, fmt.Errorf("get finding evidence: encoding assessment reference: %w", err)
	}
	idsJSON, err := json.Marshal(ids)
	if err != nil {
		return nil, fmt.Errorf("get finding evidence: encoding location ids: %w", err)
	}
	cacheKey := "finding_code_locations:" + assessmentRef + ":" + string(idsJSON)
	var raw json.RawMessage
	fetched := false
	if cached, ok := c.cache.get(cacheKey); ok {
		raw = cached.(json.RawMessage)
	} else {
		query := fmt.Sprintf(`query {
  auto {
    assessment(ref: %s) {
      codeLocations(ids: %s) { id data }
    }
  }
}`, refJSON, idsJSON)
		var response struct {
			Auto *struct {
				Assessment *struct {
					CodeLocations json.RawMessage `json:"codeLocations"`
				} `json:"assessment"`
			} `json:"auto"`
		}
		if err := c.graphQL(ctx, "get finding evidence code locations", query, &response); err != nil {
			return nil, err
		}
		if response.Auto == nil || response.Auto.Assessment == nil {
			return nil, fmt.Errorf("get finding evidence: assessment %q was not returned; verify the assessment reference and access", assessmentRef)
		}
		raw = response.Auto.Assessment.CodeLocations
		fetched = true
	}

	// Decode a fresh copy on every call so callers cannot mutate the cache and
	// large numeric addresses/offsets do not pass through float64.
	locations := []FindingCodeLocation{}
	if len(bytes.TrimSpace(raw)) != 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&locations); err != nil {
			return nil, fmt.Errorf("get finding evidence: decoding code locations: %w", err)
		}
	}
	if fetched {
		c.cache.set(cacheKey, raw)
	}
	return locations, nil
}
