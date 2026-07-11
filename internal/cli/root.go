// Package cli builds the nsmcp cobra command tree. The entrypoint
// (cmd/nsmcp) stamps the version and executes NewRootCmd; tests execute it
// in-process with injected args (SetArgs) and captured output (SetOut/SetErr).
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// BuildInfo carries the values stamped into the binary at link time by the
// release build (goreleaser's -X main.version/commit/date). Commit and Date
// are empty in plain "go build" / Makefile builds, and the display string
// omits them then.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// String renders "0.1.0" for dev builds and
// "0.1.0 (commit abc1234..., built 2026-07-11T14:49:04Z)" for stamped ones.
// The bare Version stays the first token so `nsmcp version | awk '{print $2}'`
// always yields clean semver.
func (b BuildInfo) String() string {
	if b.Commit == "" {
		return b.Version
	}
	return fmt.Sprintf("%s (commit %s, built %s)", b.Version, b.Commit, b.Date)
}

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
func NewRootCmd(build BuildInfo) *cobra.Command {
	// opts.version stays the bare semver: it flows into the MCP server
	// identity, the serve banner, and User-Agent strings, where the
	// parenthetical build metadata would be noise (or break parsers).
	opts := &rootOptions{version: build.Version}

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
  NSMCP_LOG_FILE             opt-in tool-call log path (JSON lines, append-mode 0600);
                             unset (default) means no logging

Authenticate with "nsmcp login", or mint a token at
https://app.nowsecure.com/account#token.`,
		Version: build.String(),
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

	root.AddCommand(newServeCmd(opts), newProfileCmd(opts), newVersionCmd(build),
		newLoginCmd(opts), newLogoutCmd(opts), newWhoamiCmd(opts))
	return root
}

func newVersionCmd(build BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the nsmcp version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "nsmcp", build.String())
			return nil
		},
	}
}
