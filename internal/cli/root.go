// Package cli builds the nsmcp cobra command tree. The entrypoint
// (cmd/nsmcp) stamps the version and executes NewRootCmd; tests execute it
// in-process with injected args (SetArgs) and captured output (SetOut/SetErr).
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// rootOptions holds the persistent, global flag values plus the version
// stamped into the binary. The flags are bound once on the root command;
// because Cobra shares persistent flags by reference with every subcommand,
// flags given after a subcommand (e.g. "serve --token X") update these same
// fields.
type rootOptions struct {
	version  string
	token    string
	baseURL  string
	platform bool
	mari     bool
}

// NewRootCmd builds the full command tree. main() executes it, and tests can
// execute it in-process with injected args (SetArgs) and captured output
// (SetOut/SetErr).
func NewRootCmd(version string) *cobra.Command {
	opts := &rootOptions{version: version}

	root := &cobra.Command{
		Use:   "nsmcp",
		Short: "MCP server for the NowSecure Platform & MARI",
		Long: `nsmcp is a Model Context Protocol (MCP) server for the NowSecure Platform
(DevSecOps mobile app security) and MARI (Mobile App Risk Intelligence).

Running nsmcp with no subcommand starts the MCP server over stdio (identical to
"nsmcp serve"). The profile subcommands call the REST API directly and are handy
for verifying endpoint shapes against a live tenant.

Environment:
  NOWSECURE_API_TOKEN        API token (fallbacks: NOWSECURE_API_KEY, NS_API_TOKEN,
                             NSMCP_API_TOKEN, NSMCP_API_KEY)
  NOWSECURE_API_URL          API base URL override (default https://api.nowsecure.com)
  NOWSECURE_OAUTH_CLIENT_ID  OAuth client id for "nsmcp login"

Authenticate with "nsmcp login", or mint a token at
https://app.nowsecure.com/account#token.`,
		Version: version,
		// No subcommand => run the stdio server (preserves the old default).
		// The --http flags live on the serve subcommand only.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd, opts, &serveOptions{})
		},
		// Leave SilenceUsage false on the root: unknown commands and flag-parse
		// errors are resolved against the root, so this is what makes them print
		// usage (the spec requires it). Runtime errors from serve are silenced on
		// the serve command itself.
	}
	// "nsmcp --version" prints the same string as the version subcommand.
	root.SetVersionTemplate("nsmcp {{.Version}}\n")
	// Cobra's generated completions cover subcommands and flags for free:
	// `nsmcp completion zsh|bash|fish|powershell`.

	pf := root.PersistentFlags()
	pf.StringVar(&opts.token, "token", "", "NowSecure API token (default: $NOWSECURE_API_TOKEN)")
	pf.StringVar(&opts.baseURL, "base-url", "", "API base URL (default: https://api.nowsecure.com)")
	pf.BoolVar(&opts.platform, "platform", true, "expose DevSecOps/Platform tools")
	pf.BoolVar(&opts.mari, "mari", true, "expose MARI/Risk-Intelligence tools")

	root.AddCommand(newServeCmd(opts), newProfileCmd(opts), newVersionCmd(version),
		newLoginCmd(opts), newLogoutCmd(opts), newWhoamiCmd(opts))
	return root
}

func newVersionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the nsmcp version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "nsmcp", version)
			return nil
		},
	}
}
