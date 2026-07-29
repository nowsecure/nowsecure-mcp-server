package mcpserver_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"nsmcp/internal/config"
)

// update regenerates testdata/tools.golden.json from the server's current
// tool registrations, the standard Go golden-file idiom:
//
//	go test ./internal/mcpserver/... -run TestToolSchemasGolden -update
var update = flag.Bool("update", false, "update the tool schema golden file")

// toolSchemasGoldenPath is relative to this package's directory (go test
// runs with the package dir as its working directory).
const toolSchemasGoldenPath = "testdata/tools.golden.json"

// toolSnapshot is the model-facing slice of an mcp.Tool this test pins: the
// fields a client actually sees and validates calls against. Name is
// exported first for readability of the golden file; the rest follow the
// order requested for the audit (description, inputSchema, outputSchema,
// annotations).
type toolSnapshot struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	InputSchema  any    `json:"inputSchema"`
	OutputSchema any    `json:"outputSchema,omitempty"`
	Annotations  any    `json:"annotations,omitempty"`
}

// TestToolSchemasGolden builds each of the two valid production server modes,
// unions their tools (the shared URL decoder is de-duplicated), and compares
// every registered tool's {name,
// description, inputSchema, outputSchema, annotations} byte-for-byte against
// testdata/tools.golden.json.
//
// This file is the model-facing contract: a diff means a tool's name,
// description, or schema changed in a way every downstream MCP client will
// see. Read the diff carefully before trusting it — a wording tweak is
// probably fine, a dropped required field or renamed property is a breaking
// change — then regenerate with:
//
//	go test ./internal/mcpserver/... -run TestToolSchemasGolden -update
func TestToolSchemasGolden(t *testing.T) {
	byName := make(map[string]toolSnapshot)
	for _, cfg := range []*config.Config{
		{Token: "test-token", BaseURL: backendURL(t, nil), EnablePlatform: true},
		{Token: "test-token", BaseURL: backendURL(t, nil), EnableMARI: true},
	} {
		res, err := session(t, cfg).ListTools(t.Context(), nil)
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		for _, tool := range res.Tools {
			byName[tool.Name] = toolSnapshot{
				Name:         tool.Name,
				Description:  tool.Description,
				InputSchema:  tool.InputSchema,
				OutputSchema: tool.OutputSchema,
				Annotations:  tool.Annotations,
			}
		}
	}
	snaps := make([]toolSnapshot, 0, len(byName))
	for _, snap := range byName {
		snaps = append(snaps, snap)
	}
	// ListTools order reflects registration order, not a documented contract;
	// sort by name so the golden file doesn't churn if registration order
	// ever changes.
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].Name < snaps[j].Name })

	// encoding/json always sorts map keys (the decoded schema objects), so
	// this indent-only marshal is already deterministic byte-for-byte.
	got, err := json.MarshalIndent(snaps, "", "  ")
	if err != nil {
		t.Fatalf("marshal tool snapshot: %v", err)
	}
	got = append(got, '\n')

	if *update {
		if err := os.WriteFile(toolSchemasGoldenPath, got, 0o600); err != nil {
			t.Fatalf("write golden file: %v", err)
		}
		return
	}

	want, err := os.ReadFile(toolSchemasGoldenPath)
	if err != nil {
		t.Fatalf("read golden file %s: %v (run with -update to create it)", toolSchemasGoldenPath, err)
	}
	if bytes.Equal(got, want) {
		return
	}
	t.Errorf("tool schema snapshot changed from %s — this is the model-facing contract every MCP "+
		"client sees, so review the diff below carefully before accepting it, then rerun with "+
		"`go test ./internal/mcpserver/... -run TestToolSchemasGolden -update`:\n%s",
		toolSchemasGoldenPath, firstDiff(string(want), string(got)))
}

// firstDiff returns a small line-based window around the first line where
// want and got diverge, prefixed "-"/"+" like a diff hunk. It is a debugging
// aid for the golden-file failure message, not a general-purpose diff (no
// snapshot/diff library is a dependency of this project).
func firstDiff(want, got string) string {
	wl := strings.Split(want, "\n")
	gl := strings.Split(got, "\n")
	i := 0
	for i < len(wl) && i < len(gl) && wl[i] == gl[i] {
		i++
	}
	const radius = 3
	var b strings.Builder
	fmt.Fprintf(&b, "first difference at line %d\n", i+1)
	for _, l := range window(wl, i, radius) {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	for _, l := range window(gl, i, radius) {
		fmt.Fprintf(&b, "+ %s\n", l)
	}
	return b.String()
}

// window returns up to radius+1 lines of s starting at i (clamped to s's
// bounds), for firstDiff's context display.
func window(s []string, i, radius int) []string {
	if i >= len(s) {
		return nil
	}
	end := min(i+radius+1, len(s))
	return s[i:end]
}
