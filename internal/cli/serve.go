package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"nsmcp/internal/config"
	"nsmcp/internal/mcpserver"
)

// serveOptions holds the serve-only flags for the remote HTTP resource-server
// mode. Zero value = stdio (the default and the root command's only mode).
type serveOptions struct {
	httpAddr         string
	publicURL        string
	oauthIssuer      string
	oauthAudience    string
	platformAudience string
}

func newServeCmd(opts *rootOptions) *cobra.Command {
	so := &serveOptions{}
	cmd := &cobra.Command{
		Use:          "serve",
		Aliases:      []string{"mcp"},
		Short:        "Run the MCP server (stdio by default, HTTP with --http)",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd, opts, so)
		},
	}
	f := cmd.Flags()
	f.StringVar(&so.httpAddr, "http", "", "listen address (e.g. :8080) for the remote OAuth 2.1 resource-server mode; empty = stdio")
	f.StringVar(&so.publicURL, "public-url", "", "externally reachable base URL of this server (required with --http)")
	f.StringVar(&so.oauthIssuer, "oauth-issuer", "https://id.nowsecure.com/", "OAuth authorization server issuer")
	f.StringVar(&so.oauthAudience, "oauth-audience", "", "audience of inbound access tokens (required with --http)")
	f.StringVar(&so.platformAudience, "platform-audience", "https://app.nowsecure.com", "audience the Platform API accepts")
	return cmd
}

// runServe resolves config, builds the server, and serves over stdio until the
// context is canceled (SIGINT/SIGTERM) or stdin closes. The startup line goes
// to STDERR because stdout is the MCP stdio transport. With --http it defers
// to the remote resource-server mode instead.
func runServe(cmd *cobra.Command, opts *rootOptions, so *serveOptions) error {
	if so.httpAddr != "" {
		return runServeHTTP(cmd, opts, so)
	}
	cfg, err := config.Resolve(config.Inputs{
		Token: opts.token, BaseURL: opts.baseURL,
		Platform: opts.platform, MARI: opts.mari,
		StoredToken: storedTokenFn,
	})
	if err != nil {
		return err
	}
	server := mcpserver.New(cfg, opts.version)

	groups := ""
	if cfg.EnablePlatform {
		groups += "platform "
	}
	if cfg.EnableMARI {
		groups += "mari"
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "nsmcp %s serving on stdio (base_url=%s, tools=%s)\n", opts.version, cfg.BaseURL, groups)

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := mcpserver.Serve(ctx, server); err != nil {
		// A canceled context is a clean shutdown on SIGINT/SIGTERM, not a
		// failure — exit 0.
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	return nil
}

// runServeHTTP runs the remote OAuth 2.1 resource-server mode. No static token
// is resolved: every request carries its own verified bearer, which is either
// passed upstream or exchanged (see internal/mcpserver/http.go). OBO client
// credentials come from the environment only — secrets don't belong in argv.
func runServeHTTP(cmd *cobra.Command, opts *rootOptions, so *serveOptions) error {
	if so.publicURL == "" {
		return errors.New("--public-url is required with --http")
	}
	if so.oauthAudience == "" {
		return errors.New("--oauth-audience is required with --http")
	}
	cfg, err := config.Resolve(config.Inputs{
		BaseURL:  opts.baseURL,
		Platform: opts.platform, MARI: opts.mari,
		TokenOptional: true,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "nsmcp %s serving MCP over http on %s (public_url=%s, issuer=%s, audience=%s)\n",
		opts.version, so.httpAddr, so.publicURL, so.oauthIssuer, so.oauthAudience)

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = mcpserver.ServeHTTP(ctx, cfg, opts.version, mcpserver.HTTPOptions{
		Addr:             so.httpAddr,
		PublicURL:        so.publicURL,
		Issuer:           so.oauthIssuer,
		Audience:         so.oauthAudience,
		PlatformAudience: so.platformAudience,
		OBOClientID:      os.Getenv("NSMCP_OBO_CLIENT_ID"),
		OBOClientSecret:  os.Getenv("NSMCP_OBO_CLIENT_SECRET"),
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
