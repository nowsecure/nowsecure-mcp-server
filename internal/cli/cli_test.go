package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// testVersion is the version stamp used by every in-process test invocation.
// It deliberately differs from the default in cmd/nsmcp so a test failure
// can't be masked by the real value leaking in.
const testVersion = "0.0.0-test"

// runCLI builds a fresh command tree, runs it in-process with the given args,
// and returns the root command (so bound flags can be inspected) plus captured
// stdout/stderr and the execution error. It never touches the real network:
// every test below is arranged so the command fails or returns before any API
// call or before the blocking stdio serve loop.
func runCLI(t *testing.T, args ...string) (root *cobra.Command, stdout, stderr string, err error) {
	t.Helper()
	root = NewRootCmd(BuildInfo{Version: testVersion})
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err = root.Execute()
	return root, out.String(), errBuf.String(), err
}

// clearTokenEnv blanks every environment variable config.Resolve consults AND
// stubs out the `nsmcp login` credential store, so tests are hermetic
// regardless of the developer's shell (.envrc etc.) or keychain — a real
// stored credential would otherwise satisfy the token check and change (or
// block) the serve-path tests.
func clearTokenEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"NOWSECURE_API_TOKEN",
		"NOWSECURE_API_KEY",
		"NS_API_TOKEN",
		"NSMCP_API_TOKEN",
		"NSMCP_API_KEY",
		"NOWSECURE_API_URL",
	} {
		t.Setenv(k, "")
	}
	prev := storedTokenFn
	storedTokenFn = func(string) string { return "" }
	t.Cleanup(func() { storedTokenFn = prev })
}

// TestServeFlagsAfterSubcommand is the regression test for the original bug:
// stdlib flag stopped parsing at the "serve" positional, so "serve --token X"
// silently dropped --token. With cobra the persistent flag is honored after the
// subcommand. We prove it two ways without ever entering the blocking serve
// loop: (1) the config-resolution error changes once --token is supplied, and
// (2) the bound flag value is readable after Execute.
func TestServeFlagsAfterSubcommand(t *testing.T) {
	clearTokenEnv(t)

	// No --token, token env cleared: resolution fails on the missing token.
	_, _, _, err := runCLI(t, "serve", "--platform")
	if err == nil {
		t.Fatal("expected an error when no token is available")
	}
	if !strings.Contains(err.Error(), "no API token found") {
		t.Fatalf("expected missing-token error, got: %v", err)
	}

	// With --token after the subcommand, the token check passes. Selecting both
	// products then gives a different, deterministic error before the serve loop,
	// proving --token reached the command.
	root, _, _, err := runCLI(t, "serve", "--token", "dummy", "--platform", "--mari")
	if err == nil {
		t.Fatal("expected an error when both products are selected")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected product-selection error (proving --token was parsed), got: %v", err)
	}
	if got := root.PersistentFlags().Lookup("token").Value.String(); got != "dummy" {
		t.Fatalf("--token after subcommand not bound: got %q, want %q", got, "dummy")
	}
}

// TestNoArgsDispatchesToServe verifies that running nsmcp with no subcommand
// takes the serve path. With no product selected it fails fast in
// config.Resolve (the serve path's error) rather than blocking on stdin.
func TestNoArgsDispatchesToServe(t *testing.T) {
	clearTokenEnv(t)

	_, _, _, err := runCLI(t)
	if err == nil {
		t.Fatal("expected serve path to fail fast with no product")
	}
	if !strings.Contains(err.Error(), "choose exactly one product") {
		t.Fatalf("expected the serve config error, got: %v", err)
	}
}

func TestServeRequiresExactlyOneProduct(t *testing.T) {
	clearTokenEnv(t)

	_, _, _, err := runCLI(t, "serve", "--token", "dummy")
	if err == nil || !strings.Contains(err.Error(), "choose exactly one product") {
		t.Fatalf("no product error = %v, want choose-exactly-one guidance", err)
	}

	_, _, _, err = runCLI(t, "serve", "--token", "dummy", "--platform", "--mari")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("both products error = %v, want mutual-exclusion guidance", err)
	}
}

func TestHelpExitsCleanly(t *testing.T) {
	_, stdout, _, err := runCLI(t, "--help")
	if err != nil {
		t.Fatalf("--help should exit cleanly, got error: %v", err)
	}
	if !strings.Contains(stdout, "nsmcp") {
		t.Fatalf("--help output missing program name; got: %q", stdout)
	}
	// The env-var documentation from the old usage text must survive.
	if !strings.Contains(stdout, "NOWSECURE_API_TOKEN") {
		t.Fatalf("--help output missing environment docs; got: %q", stdout)
	}

	if _, _, _, err := runCLI(t, "profile", "--help"); err != nil {
		t.Fatalf("profile --help should exit cleanly, got error: %v", err)
	}
	if _, _, _, err := runCLI(t, "-h"); err != nil {
		t.Fatalf("-h should exit cleanly, got error: %v", err)
	}
}

func TestVersion(t *testing.T) {
	// version subcommand.
	_, stdout, _, err := runCLI(t, "version")
	if err != nil {
		t.Fatalf("version command errored: %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "nsmcp "+testVersion {
		t.Fatalf("version output = %q, want %q", got, "nsmcp "+testVersion)
	}

	// --version flag should print the same string.
	_, stdout, _, err = runCLI(t, "--version")
	if err != nil {
		t.Fatalf("--version errored: %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "nsmcp "+testVersion {
		t.Fatalf("--version output = %q, want %q", got, "nsmcp "+testVersion)
	}

	// A release build stamps commit/date; they render parenthetically after
	// the bare version, which must stay the second token (parseable semver).
	stamped := BuildInfo{Version: testVersion, Commit: "abc1234", Date: "2026-07-11T00:00:00Z"}
	root := NewRootCmd(stamped)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("stamped version command errored: %v", err)
	}
	want := "nsmcp " + testVersion + " (commit abc1234, built 2026-07-11T00:00:00Z)"
	if got := strings.TrimSpace(out.String()); got != want {
		t.Fatalf("stamped version output = %q, want %q", got, want)
	}
}

func TestUnknownCommand(t *testing.T) {
	_, _, stderr, err := runCLI(t, "bogus")
	if err == nil {
		t.Fatal("expected an error for an unknown command")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("expected unknown-command error, got: %v", err)
	}
	// The spec requires an error plus usage guidance on stderr. Cobra's
	// unknown-top-level-command path prints "Error: ..." and a
	// "Run 'nsmcp --help' for usage." pointer.
	if !strings.Contains(strings.ToLower(stderr), "usage") {
		t.Fatalf("expected usage guidance on stderr for unknown command; got: %q", stderr)
	}
}

// TestProfileRouting checks that profile subcommands are wired and enforce their
// argument counts before doing any work (so no network call happens).
func TestProfileRouting(t *testing.T) {
	// Missing required <package> argument: cobra rejects it up front.
	_, _, _, err := runCLI(t, "profile", "assessments")
	if err == nil {
		t.Fatal("expected an arg-count error for 'profile assessments' with no package")
	}

	// Unknown profile subcommand errors.
	_, _, _, err = runCLI(t, "profile", "nope")
	if err == nil {
		t.Fatal("expected an error for an unknown profile subcommand")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("expected unknown-command error, got: %v", err)
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV(" a, ,b ,,c,")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("splitCSV length = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitCSV[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if splitCSV("") != nil {
		t.Fatalf("splitCSV(\"\") = %v, want nil", splitCSV(""))
	}
}
