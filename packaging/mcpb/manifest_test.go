package mcpb

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestManifestProductConfiguration(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	var manifest struct {
		Server struct {
			MCPConfig struct {
				Args []string `json:"args"`
			} `json:"mcp_config"`
		} `json:"server"`
		UserConfig map[string]json.RawMessage `json:"user_config"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}

	productJSON, ok := manifest.UserConfig["product"]
	if !ok {
		t.Fatal("manifest user_config is missing product")
	}
	var product struct {
		Type        string   `json:"type"`
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Required    bool     `json:"required"`
		Default     string   `json:"default"`
		Multiple    *bool    `json:"multiple,omitempty"`
		Sensitive   *bool    `json:"sensitive,omitempty"`
		Min         *float64 `json:"min,omitempty"`
		Max         *float64 `json:"max,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(productJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&product); err != nil {
		t.Fatalf("parse product user_config using supported MCPB fields: %v", err)
	}

	if product.Type != "string" {
		t.Errorf("product type = %q, want string", product.Type)
	}
	if !product.Required {
		t.Error("product must be required")
	}
	if product.Default != "platform" {
		t.Errorf("product default = %q, want platform", product.Default)
	}
	for _, phrase := range []string{`"platform"`, `"mari"`, "No other values are accepted"} {
		if !strings.Contains(product.Description, phrase) {
			t.Errorf("product description must contain %q", phrase)
		}
	}

	wantArgs := []string{"serve", "--product", "${user_config.product}"}
	if !slices.Equal(manifest.Server.MCPConfig.Args, wantArgs) {
		t.Errorf("server args = %q, want %q", manifest.Server.MCPConfig.Args, wantArgs)
	}
}
