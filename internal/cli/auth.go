package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"nsmcp/internal/config"
	"nsmcp/internal/nsauth"
)

// storedTokenFn adapts the `nsmcp login` credential store to config.Resolve's
// fallback hook. Any failure (no keychain, never logged in) means "no stored
// token"; the resolver produces the actionable error. It is a var so tests can
// stub it out — otherwise a developer's real keychain credential would leak
// into the CLI tests and change their outcome.
var storedTokenFn = func(baseURL string) string {
	creds, err := nsauth.DefaultStore().Load(nsauth.HostKey(baseURL))
	if err != nil {
		return ""
	}
	return creds.Token
}

func newLoginCmd(opts *rootOptions) *cobra.Command {
	var (
		clientID  string
		tokenName string
		days      int
		noBrowser bool
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in with your NowSecure account (OAuth device flow)",
		Long: `Log in with your NowSecure account via the OAuth device flow.

login opens a browser to authorize this machine, then mints a named Platform
API token and stores it in the OS keychain (file fallback: the nsmcp dir under
your user config dir, 0600). serve and profile pick it up automatically when
neither --token nor the token env vars are set. Undo with "nsmcp logout".`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			baseURL, err := config.ResolveBaseURL(opts.baseURL)
			if err != nil {
				return err
			}
			if clientID == "" {
				clientID = os.Getenv("NOWSECURE_OAUTH_CLIENT_ID")
			}
			if clientID == "" {
				return errors.New("login needs the NS MCP CLI OAuth client id: pass --client-id or set NOWSECURE_OAUTH_CLIENT_ID")
			}

			lo := nsauth.Options{
				// Issuer/Audience default to production inside nsauth; the env
				// overrides exist for other tenants (e.g. id.<env>.nowsecure.io).
				Issuer:         os.Getenv("NOWSECURE_OAUTH_ISSUER"),
				Audience:       os.Getenv("NOWSECURE_OAUTH_AUDIENCE"),
				ClientID:       clientID,
				BaseURL:        baseURL,
				TokenName:      tokenName,
				ExpirationDays: days,
				Out:            cmd.ErrOrStderr(),
			}
			if noBrowser {
				lo.OpenBrowser = func(string) error { return nil }
			}
			creds, err := nsauth.Login(cmd.Context(), lo)
			if err != nil {
				return err
			}

			host := nsauth.HostKey(baseURL)
			if err := nsauth.DefaultStore().Save(host, creds); err != nil {
				return fmt.Errorf("token minted but could not be stored: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Logged in to %s.\n", host)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&clientID, "client-id", "", "OAuth client id (default: $NOWSECURE_OAUTH_CLIENT_ID)")
	f.StringVar(&tokenName, "token-name", "", `name for the minted API token (default "nsmcp/<hostname>")`)
	f.IntVar(&days, "expiration-days", 90, "lifetime of the minted API token in days (1-365)")
	f.BoolVar(&noBrowser, "no-browser", false, "print the verification URL instead of opening a browser")
	return cmd
}

func newLogoutCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:          "logout",
		Short:        "Revoke the stored API token and forget it",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			baseURL, err := config.ResolveBaseURL(opts.baseURL)
			if err != nil {
				return err
			}
			return nsauth.Logout(cmd.Context(), baseURL, nsauth.DefaultStore(), cmd.ErrOrStderr())
		},
	}
}

func newWhoamiCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:          "whoami",
		Short:        "Show which identity and token nsmcp is using",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Same resolution the server uses: flag > env > login store.
			cfg, err := config.Resolve(config.Inputs{
				Token: opts.token, BaseURL: opts.baseURL,
				// whoami resolves credentials but exposes no MCP surface.
				Platform:    true,
				StoredToken: storedTokenFn,
			})
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "api:     %s\n", cfg.BaseURL)
			claims, err := nsauth.DecodeClaims(cfg.Token)
			if err != nil {
				fmt.Fprintf(w, "token:   (opaque: %v)\n", err)
			} else {
				if claims.Name != "" {
					fmt.Fprintf(w, "token:   %s\n", claims.Name)
				}
				if claims.Subject != "" {
					fmt.Fprintf(w, "subject: %s\n", claims.Subject)
				}
				if claims.Issuer != "" {
					fmt.Fprintf(w, "issuer:  %s\n", claims.Issuer)
				}
				if !claims.ExpiresAt.IsZero() {
					fmt.Fprintf(w, "expires: %s\n", claims.ExpiresAt.Format("2006-01-02"))
				}
			}

			if err := nsauth.Verify(cmd.Context(), cfg.BaseURL, cfg.Token, nil); err != nil {
				if errors.Is(err, nsauth.ErrInvalidToken) {
					return fmt.Errorf("the API at %s rejected the token — run `nsmcp login` or mint a new one", cfg.BaseURL)
				}
				fmt.Fprintf(w, "status:  could not verify against the API (%v)\n", err)
				return nil
			}
			fmt.Fprintln(w, "status:  token accepted by the API")
			return nil
		},
	}
}
