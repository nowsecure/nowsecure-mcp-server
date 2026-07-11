package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"nsmcp/internal/config"
	"nsmcp/internal/mcpserver"
)

// newToolSession builds the MCP server exactly as serve does (both tool
// groups enabled) and connects an in-memory client to it. Commands built on
// it exercise the full path agents see — handlers, output shaping, schema
// validation, dual emission — unlike the raw REST probes, which drive
// nsclient directly. tokenOptional permits token-less sessions for
// operations that never reach the API (tool listing, schemas).
func newToolSession(ctx context.Context, opts *rootOptions, tokenOptional bool) (*mcp.ClientSession, error) {
	cfg, err := config.Resolve(config.Inputs{
		Token: opts.token, BaseURL: opts.baseURL,
		Platform: true, MARI: true,
		TokenOptional: tokenOptional,
		StoredToken:   storedTokenFn,
	})
	if err != nil {
		return nil, err
	}
	server, err := mcpserver.New(cfg, opts.version)
	if err != nil {
		return nil, err
	}
	serverT, clientT := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverT, nil); err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "nsmcp-cli", Version: opts.version}, nil)
	return client.Connect(ctx, clientT, nil)
}

// newProfileCallCmd is the schema-driven tool invoker: any registered MCP
// tool, called in-process with JSON arguments, printing the exact CallTool
// result an agent would receive. New tools and options appear here
// automatically — there is nothing to keep in sync by hand.
func newProfileCallCmd(opts *rootOptions) *cobra.Command {
	var showSchema bool
	cmd := &cobra.Command{
		Use:   "call [tool] [json-args]",
		Short: "Call an MCP tool in-process (the exact result agents see)",
		Long: `Call any registered MCP tool through an in-memory MCP session — the same
handlers, output shaping, and dual emission agents get, unlike the raw REST
probe subcommands.

With no arguments, lists the registered tools. Arguments are passed as one
JSON object. Use --schema to print a tool's input schema instead of calling
it (tool listing and --schema need no API token).`,
		Example: `  # what tools exist?
  nsmcp profile call

  # how do I call one?
  nsmcp profile call get_mari_assessment --schema

  # call it exactly as an agent would
  nsmcp profile call get_mari_assessment '{"assessment_ref":"<ref>","min_severity":"high"}'`,
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cs, err := newToolSession(ctx, opts, len(args) == 0 || showSchema)
			if err != nil {
				return err
			}
			defer func() { _ = cs.Close() }()

			if len(args) == 0 {
				res, err := cs.ListTools(ctx, nil)
				if err != nil {
					return err
				}
				for _, t := range res.Tools {
					fmt.Fprintf(cmd.OutOrStdout(), "%-30s %s\n", t.Name, firstSentence(t.Description))
				}
				fmt.Fprintln(cmd.OutOrStdout(), "\nUse 'profile call <tool> --schema' for a tool's options.")
				return nil
			}

			name := args[0]
			if showSchema {
				res, err := cs.ListTools(ctx, nil)
				if err != nil {
					return err
				}
				for _, t := range res.Tools {
					if t.Name == name {
						return printJSON(cmd, t.InputSchema)
					}
				}
				return fmt.Errorf("unknown tool %q (run 'profile call' to list tools)", name)
			}

			toolArgs := map[string]any{}
			if len(args) > 1 {
				if err := json.Unmarshal([]byte(args[1]), &toolArgs); err != nil {
					return fmt.Errorf("parsing json-args: %w", err)
				}
			}
			res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: toolArgs})
			if err != nil {
				return err
			}
			if err := printJSON(cmd, res); err != nil {
				return err
			}
			if res.IsError {
				return fmt.Errorf("tool %s returned an error", name)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&showSchema, "schema", false, "print the tool's input schema instead of calling it")
	return cmd
}

// firstSentence trims a tool description to its first sentence for listings.
func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i+1]
	}
	return s
}
