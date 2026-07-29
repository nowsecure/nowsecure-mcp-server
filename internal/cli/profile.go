package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"nsmcp/internal/config"
	"nsmcp/internal/nsclient"
	"nsmcp/internal/urlparse"
)

// newProfileCmd builds the "profile" command tree. It lets an operator verify
// endpoint shapes live with a real token; output is pretty JSON to stdout.
// The raw profile probes drive the REST client directly and do not expose an
// MCP product surface, so they ignore --platform/--mari.
func newProfileCmd(opts *rootOptions) *cobra.Command {
	profile := &cobra.Command{
		Use:   "profile",
		Short: "Verify tools and endpoints against a live tenant",
		Long: `Verification surface for a live tenant, in three layers:

  call    invoke any MCP tool in-process — the exact result agents see
  budget  measure every tool's response size against byte budgets (CI guard)
  others  raw REST probes that drive the API client directly (endpoint shapes)

Output is pretty JSON to stdout.`,
		// A parent command with subcommands is, by cobra's default, non-runnable
		// and treats "profile bogus" as a help request (no error). Giving it a
		// RunE makes bare "profile" print help but "profile <unknown>" error.
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
		},
	}

	profile.AddCommand(
		newProfileCallCmd(opts),
		newProfileBudgetCmd(opts),
		&cobra.Command{
			Use:   "apps",
			Short: "List portfolio apps",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				c, err := newProfileClient(opts)
				if err != nil {
					return err
				}
				res, err := c.ListApps(cmd.Context(), nsclient.ListAppsParams{PageSize: 20})
				if err != nil {
					return err
				}
				return printJSON(cmd, res)
			},
		},
		&cobra.Command{
			Use:   "assessments <package>",
			Short: "List a package's assessment (scan) history",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := newProfileClient(opts)
				if err != nil {
					return err
				}
				res, err := c.ListAssessments(cmd.Context(), nsclient.ListAssessmentsParams{PackageKey: args[0], PageSize: 20})
				if err != nil {
					return err
				}
				return printJSON(cmd, res)
			},
		},
		&cobra.Command{
			Use:   "findings <app_ref> [assessment_ref]",
			Short: "Get an assessment's findings (affected-only)",
			Args:  cobra.RangeArgs(1, 2),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := newProfileClient(opts)
				if err != nil {
					return err
				}
				ref := ""
				if len(args) > 1 {
					ref = args[1]
				}
				res, err := c.GetAssessmentFindings(cmd.Context(), nsclient.FindingsParams{AppRef: args[0], AssessmentRef: ref, AffectedOnly: true})
				if err != nil {
					return err
				}
				return printJSON(cmd, res)
			},
		},
		&cobra.Command{
			Use:   "finding <key>",
			Short: "Get a finding's remediation document",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := newProfileClient(opts)
				if err != nil {
					return err
				}
				res, err := c.GetFinding(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return printJSON(cmd, res)
			},
		},
		&cobra.Command{
			Use:   "affected <key>",
			Short: "List apps affected by a finding",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := newProfileClient(opts)
				if err != nil {
					return err
				}
				res, err := c.AppsAffectedByFinding(cmd.Context(), args[0], nsclient.AffectedByParams{PageSize: 20})
				if err != nil {
					return err
				}
				return printJSON(cmd, res)
			},
		},
		&cobra.Command{
			Use:   "mari",
			Short: "List MARI (risk intelligence) apps",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				c, err := newProfileClient(opts)
				if err != nil {
					return err
				}
				res, err := c.ListMARIApps(cmd.Context(), nsclient.ListMARIAppsParams{PageSize: 20, PageNumber: 1})
				if err != nil {
					return err
				}
				return printJSON(cmd, res)
			},
		},
		newProfileMARIAssessmentCmd(opts),
		&cobra.Command{
			Use:   "url <url>",
			Short: "Decode a NowSecure console URL into ids",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				res, err := urlparse.Parse(args[0])
				if err != nil {
					return err
				}
				return printJSON(cmd, res)
			},
		},
	)
	return profile
}

// newProfileMARIAssessmentCmd mirrors the get_mari_assessment MCP tool: the
// default is the same compact risk card, and the tool's row/prose options are
// exposed as flags so every disclosure tier can be exercised from the CLI.
func newProfileMARIAssessmentCmd(opts *rootOptions) *cobra.Command {
	var (
		minSeverity  string
		limit        int
		checkIDs     string
		includeDescs bool
	)
	cmd := &cobra.Command{
		Use:   "mari-assessment <ref> [expand,...]",
		Short: "Get a MARI assessment (risk card by default, like the MCP tool)",
		Long: `Mirrors the get_mari_assessment MCP tool. The default response is the compact
risk card: identity, both risk score families, per-category score/impact
breakdowns, and severity counts — finding rows are omitted (findings_omitted
reports how many).

Pull finding rows with --min-severity or --limit (most severe first), the
full per-finding prose (description, business impact, regulations) with
--check-ids, or short descriptions on every row with --include-descriptions.

The optional second argument opts into heavier sections, comma-separated:
` + strings.Join(nsclient.MARIExpandValues, ", ") + `.`,
		Example: `  # compact risk card
  nsmcp profile mari-assessment <ref>

  # the most severe findings only
  nsmcp profile mari-assessment <ref> --min-severity high --limit 10

  # full prose deep-dive for specific findings
  nsmcp profile mari-assessment <ref> --check-ids remote_code_execution,uses_http

  # expand heavier sections
  nsmcp profile mari-assessment <ref> permissions,trackingDomains`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newProfileClient(opts)
			if err != nil {
				return err
			}
			var expand []string
			if len(args) > 1 {
				expand = splitCSV(args[1])
			}
			res, err := c.GetMARIAssessment(cmd.Context(), nsclient.MARIAssessmentParams{
				AssessmentRef:       args[0],
				Expand:              expand,
				MinSeverity:         minSeverity,
				Limit:               limit,
				CheckIDs:            splitCSV(checkIDs),
				IncludeDescriptions: includeDescs,
			})
			if err != nil {
				return err
			}
			return printJSON(cmd, res)
		},
	}
	cmd.Flags().StringVar(&minSeverity, "min-severity", "", "finding rows at this severity or higher (info returns every row)")
	cmd.Flags().IntVar(&limit, "limit", 0, "max finding rows to return (most severe kept)")
	cmd.Flags().StringVar(&checkIDs, "check-ids", "", "comma-separated check_ids: the full-prose deep-dive")
	cmd.Flags().BoolVar(&includeDescs, "include-descriptions", false, "include short_description on every returned row")
	return cmd
}

// newProfileClient resolves credentials and returns a REST client. Platform is
// selected only to satisfy Config's one-product invariant; raw profile probes
// do not register or gate MCP features.
func newProfileClient(opts *rootOptions) (*nsclient.Client, error) {
	cfg, err := config.Resolve(config.Inputs{
		Token: opts.token, BaseURL: opts.baseURL,
		Platform:    true,
		StoredToken: storedTokenFn,
	})
	if err != nil {
		return nil, err
	}
	return nsclient.New(cfg.BaseURL, cfg.Token, nsclient.WithUserAgent("nsmcp-profile/"+opts.version)), nil
}

func printJSON(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// splitCSV splits a comma-separated list, trimming whitespace and dropping
// empty fields (so "a, ,b," -> ["a","b"]).
func splitCSV(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
