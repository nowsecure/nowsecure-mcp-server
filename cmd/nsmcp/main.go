// Command nsmcp is a Model Context Protocol server for the NowSecure Platform
// and MARI (Mobile App Risk Intelligence).
//
// Usage:
//
//	nsmcp [flags]                  # run the MCP server over stdio (default)
//	nsmcp [flags] serve            # same as above
//	nsmcp [flags] serve --http :8080 --public-url ... --oauth-audience ...
//	                               # remote OAuth 2.1 resource-server mode
//	nsmcp [flags] login            # OAuth device-flow login (mints + stores a token)
//	nsmcp [flags] logout           # revoke and forget the stored token
//	nsmcp [flags] whoami           # show the identity/token in use
//	nsmcp [flags] profile <cmd>    # hit the REST API directly (for verification)
//	nsmcp version
//
// Flags:
//
//	--token     NowSecure API token (else $NOWSECURE_API_TOKEN and fallbacks,
//	            else the credential stored by `nsmcp login`)
//	--base-url  API base URL (default https://api.nowsecure.com)
//	--platform  expose DevSecOps/Platform tools (default true)
//	--mari      expose MARI/Risk-Intelligence tools (default true)
//
// The command tree itself lives in internal/cli; this package only stamps the
// version and executes it.
package main

import (
	"os"

	"nsmcp/internal/cli"
)

// These are vars, not consts, so releases can override them at link time.
// GoReleaser stamps all three (-X main.version/commit/date); the Makefile
// stamps only VERSION, leaving commit/date empty for dev builds.
var (
	version = "0.1.0"
	commit  = ""
	date    = ""
)

func main() {
	build := cli.BuildInfo{Version: version, Commit: commit, Date: date}
	if err := cli.NewRootCmd(build).Execute(); err != nil {
		// Cobra has already printed the error (and usage where appropriate).
		os.Exit(1)
	}
}
