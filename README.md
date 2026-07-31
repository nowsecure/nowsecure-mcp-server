# NowSecure MCP (beta)

A small **Model Context Protocol (MCP) server** for two NowSecure products —
**[NowSecure Platform](https://www.nowsecure.com/products/nowsecure-platform/)**
(DevSecOps triage of your own mobile app portfolio) and
**[NowSecure MARI](https://www.nowsecure.com/products/nowsecure-risk-intelligence/)**
(Mobile App Risk Intelligence — vetting vendor/third-party apps). It gives an
AI assistant a focused set of read-only tools for each — see
[Supported products and tools](#supported-products-and-tools).

## Install

### Claude Desktop: MCPB bundle (fastest)

1. Download the `.mcpb` asset from the
   [latest release](https://github.com/nowsecure/nowsecure-mcp-server/releases/latest).
2. Open it in Claude Desktop and follow the guided setup.

That's it—the bundle includes nsmcp and configures it for you. There is no
separate binary to install and no JSON to edit. It supports macOS (Apple
silicon and Intel) and Windows x64.

## One-click Platform install

Pick your client below — each button uses the client's native install link to
prefill the nsmcp config, so you don't need to edit any JSON by hand.

<table align="center">
  <tr>
    <td align="center" width="200">
      <a href="https://cursor.com/en/install-mcp?name=nsmcp-platform&config=eyJjb21tYW5kIjoibnNtY3AiLCJhcmdzIjpbInNlcnZlIiwiLS1wcm9kdWN0IiwicGxhdGZvcm0iXSwiZW52Ijp7Ik5PV1NFQ1VSRV9BUElfVE9LRU4iOiJZT1VSX1RPS0VOIn19">
        <img src="https://img.shields.io/badge/Cursor-000000?style=for-the-badge&logo=cursor&logoColor=white" alt="Add to Cursor"><br>
        <b>Add to Cursor</b>
      </a>
      <br><sub>Triage app findings without leaving your editor.</sub>
    </td>
    <td align="center" width="200">
      <a href="https://vscode.dev/redirect/mcp/install?name=nsmcp-platform&config=%7B%22command%22%3A%22nsmcp%22%2C%22args%22%3A%5B%22serve%22%2C%22--product%22%2C%22platform%22%5D%2C%22env%22%3A%7B%22NOWSECURE_API_TOKEN%22%3A%22YOUR_TOKEN%22%7D%7D">
        <img src="https://img.shields.io/badge/VS_Code-0098FF?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZmZmZiI+PHBhdGggZD0iTTE3LjUgMiA5LjIgOS42IDQuNiA2LjEgMyA2Ljl2MTAuMmwxLjYuOCA0LjYtMy41IDguMyA3LjZMMjEgMjFWM3pNNi40IDEybDIuOS0yLjJ2NC40em0xMS4xIDQuOS01LjQtNC45IDUuNC00Ljl6Ii8+PC9zdmc+&logoColor=white" alt="Add to VS Code"><br>
        <b>Add to VS Code</b>
      </a>
      <br><sub>Query your portfolio via GitHub Copilot.</sub>
    </td>
  </tr>
</table>

Both buttons prefill a config with `"command": "nsmcp"`, so **`nsmcp` must
already be on your `PATH`** for it to launch (edit the `command` field to an
absolute path otherwise). After installing, replace `YOUR_TOKEN` with a real
token from <https://app.nowsecure.com/account/tokens>. The buttons configure
Platform; for MARI, change the product value from `platform` to `mari` and
name the entry `nsmcp-mari`.

## Per-client setup

<details>
<summary><strong>Claude Code (CLI)</strong></summary>

```bash
claude mcp add --env NOWSECURE_API_TOKEN=$NOWSECURE_API_TOKEN --transport stdio nsmcp-platform -- nsmcp serve --product platform
```

`--scope` controls where the entry is stored (defaults to `local`,
i.e. `~/.claude.json` keyed to this project directory):

```bash
claude mcp add --scope user  --env NOWSECURE_API_TOKEN=$NOWSECURE_API_TOKEN --transport stdio nsmcp-platform -- nsmcp serve --product platform   # global, all projects
claude mcp add --scope project --env NOWSECURE_API_TOKEN=$NOWSECURE_API_TOKEN --transport stdio nsmcp-platform -- nsmcp serve --product platform # .mcp.json, team-shared
```

Manage with `claude mcp list` / `claude mcp get nsmcp-platform` /
`claude mcp remove nsmcp-platform`, or `/mcp` inside a session.

</details>

<details>
<summary><strong>Claude Desktop</strong></summary>

Download the `.mcpb` release asset and open it in Claude Desktop for a guided
install. The single bundle supports macOS (`arm64` and `amd64`) and Windows
`amd64`; the installer asks for `platform` or `mari` and stores your API token
as a sensitive setting.

For a manual installation, use Settings → Developer → Edit Config to open
`claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "nsmcp-platform": {
      "command": "/absolute/path/to/nsmcp",
      "args": ["serve", "--product", "platform"],
      "env": { "NOWSECURE_API_TOKEN": "YOUR_TOKEN" }
    }
  }
}
```

Restart Claude Desktop after editing.

</details>

<details>
<summary><strong>Cursor</strong></summary>

Use the [one-click button](#one-click-platform-install) above, or edit
`~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project) by hand:

```json
{
  "mcpServers": {
    "nsmcp-platform": {
      "command": "nsmcp",
      "args": ["serve", "--product", "platform"],
      "env": { "NOWSECURE_API_TOKEN": "YOUR_TOKEN" }
    }
  }
}
```

</details>

<details>
<summary><strong>VS Code (GitHub Copilot)</strong></summary>

CLI:

```bash
code --add-mcp "{\"name\":\"nsmcp-platform\",\"command\":\"nsmcp\",\"args\":[\"serve\",\"--product\",\"platform\"],\"env\":{\"NOWSECURE_API_TOKEN\":\"YOUR_TOKEN\"}}"
```

Or `.vscode/mcp.json`, using VS Code's `inputs` prompt so the token isn't
checked into the file:

```json
{
  "servers": {
    "nsmcp-platform": {
      "command": "nsmcp",
      "args": ["serve", "--product", "platform"],
      "env": { "NOWSECURE_API_TOKEN": "${input:nsmcp_token}" }
    }
  },
  "inputs": [
    { "type": "promptString", "id": "nsmcp_token", "description": "NowSecure API Token", "password": true }
  ]
}
```

</details>

<details>
<summary><strong>Windsurf</strong></summary>

Command Palette → "Windsurf: Configure MCP Servers", or edit directly:

- macOS/Linux: `~/.codeium/windsurf/mcp_config.json`
- Windows: `%USERPROFILE%\.codeium\windsurf\mcp_config.json`

```json
{
  "mcpServers": {
    "nsmcp-platform": {
      "command": "nsmcp",
      "args": ["serve", "--product", "platform"],
      "env": { "NOWSECURE_API_TOKEN": "YOUR_TOKEN" }
    }
  }
}
```

Windsurf config is global only (no per-project file).

</details>

<details>
<summary><strong>Gemini CLI</strong></summary>

```bash
gemini mcp add -e NOWSECURE_API_TOKEN=$NOWSECURE_API_TOKEN nsmcp-platform nsmcp serve --product platform
```

Or `~/.gemini/settings.json` (user) / `.gemini/settings.json` (project):

```json
{
  "mcpServers": {
    "nsmcp-platform": {
      "command": "nsmcp",
      "args": ["serve", "--product", "platform"],
      "env": { "NOWSECURE_API_TOKEN": "YOUR_TOKEN" }
    }
  }
}
```

</details>

<details>
<summary><strong>Codex CLI</strong></summary>

```bash
codex mcp add nsmcp-platform --env NOWSECURE_API_TOKEN=$NOWSECURE_API_TOKEN -- nsmcp serve --product platform
```

Or `~/.codex/config.toml` (note snake_case `mcp_servers`, unlike other clients):

```toml
[mcp_servers.nsmcp-platform]
command = "nsmcp"
args = ["serve", "--product", "platform"]
env = { NOWSECURE_API_TOKEN = "YOUR_TOKEN" }
```

</details>

<details>
<summary><strong>ChatGPT (Desktop)</strong></summary>

**Desktop app (Codex features) — local stdio, like other clients.** The
ChatGPT desktop app shares MCP configuration with Codex
(`~/.codex/config.toml`), so the Codex CLI setup above also enables nsmcp
here. Or add it in-app: Settings → **MCP servers** → **Add server** →
**STDIO**, command `nsmcp serve --product platform`. This powers the app's Codex/agent
features, not regular chat conversations. See
[docs](https://developers.openai.com/api/docs/guides/tools-connectors-mcp) for
details.

</details>

<details>
<summary><strong>Zed</strong></summary>

`settings.json` (`~/.config/zed/settings.json`, or Command Palette → "zed: open settings")
uses `context_servers`, not `mcpServers`:

```json
{
  "context_servers": {
    "nsmcp-platform": {
      "command": "nsmcp",
      "args": ["serve", "--product", "platform"],
      "env": { "NOWSECURE_API_TOKEN": "YOUR_TOKEN" }
    }
  }
}
```

</details>


## Supported products and tools

Each server process exposes exactly one product. Choose it explicitly with
`--product platform` or `--product mari`; the flag is required. To use both
products in one MCP client, configure two nsmcp server entries with different
names and product values.

### NowSecure Platform (`--product platform`)

Triage your own mobile app portfolio: scores, findings, fleet-wide impact, and
remediation guidance.

The portfolio covers a rolling 12-month window: apps without a completed scan
in the last 12 months are absent from `list_apps` and
`get_apps_affected_by_finding` entirely. `list_assessments` is not windowed
and still serves their older scan history.

| Tool | Description |
| --- | --- |
| `list_apps` | List portfolio apps with their latest security score, rating, and open vulnerability count. The starting point for DevSecOps triage. |
| `list_assessments` | Scan history of one app, newest first, with score, rating, status, and finding counts by severity. |
| `get_assessment_findings` | Findings for one assessment as a compact, triage-ready list, sorted most-severe first. |
| `get_finding` | Documentation for a single finding: description, steps to reproduce, testing method, and remediation guidance. |
| `search_findings` | Free-text search over the finding catalog (key, title, description, category) — returns finding keys when you only know a topic or risk. |
| `get_apps_affected_by_finding` | Fleet-wide impact: which portfolio apps' latest assessments are affected by a given finding. |

### NowSecure MARI (`--product mari`)

Vet vendor and third-party apps you didn't build, by risk score, letter
rating, and findings.

| Tool | Description |
| --- | --- |
| `list_mari_apps` | List third-party apps in your MARI catalog with risk score, letter rating (A–F), and risk category (LOW/MEDIUM/HIGH). |
| `get_mari_assessment` | Risk profile for one third-party app: score, rating, findings summary, and opt-in deep-dive sections (permissions, tracking domains, libraries/SDKs, AI usage, …). |

## Suggested prompts

Clients that support MCP prompts can show these workflow starters directly in
their prompt picker. Each product mode advertises only its own prompts.

### Platform prompts

| Prompt | Purpose |
| --- | --- |
| `platform_triage_portfolio` | Prioritize the riskiest first-party apps and their remediation work. |
| `platform_review_app` | Review the latest scan and affected findings for an app title, package, ref, or URL. |
| `platform_investigate_finding` | Find fleet-wide impact and remediation guidance for a finding key, topic, or URL. |

### MARI prompts

| Prompt | Purpose |
| --- | --- |
| `mari_triage_catalog` | Prioritize third-party apps that need vendor-risk review. |
| `mari_review_app` | Review one third-party app's MARI risk profile. |
| `mari_compare_apps` | Compare two or more third-party apps and recommend the safer choice. |

## Security

Connecting an AI assistant to your NowSecure data creates powerful workflows
but also structural risks. Any MCP client or server you enable (IDE plugins,
desktop apps, other MCP servers running alongside nsmcp) can cause an AI agent
to act on your behalf with your credentials.

Large language models are vulnerable to
[prompt injection](https://owasp.org/www-community/attacks/PromptInjection)
and related attacks (indirect prompt injection,
[tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)).
Anything the model reads can carry instructions that steer the agent to
exfiltrate data or take unintended actions you never asked for — and some of
what nsmcp returns originates in third-party apps (titles, metadata, finding
details), so treat it as untrusted content, not just results. nsmcp's tools
are currently all read-only, which limits what an agent can change through
this server — but review the tools your client actually lists rather than
relying on this document: the tool set will evolve, and other NowSecure MCP
servers may expose read-write tools. The vulnerability data nsmcp returns is
sensitive regardless, and a compromised agent could leak it through *other*
tools it has access to (file writes, web requests, messaging).

To reduce risk:

- Only use trusted MCP clients, and review which other MCP servers and tools
  are enabled alongside nsmcp.
- Apply least privilege: use short-lived, scoped tokens and revoke ones you
  no longer use at <https://app.nowsecure.com/account/tokens>.
- Run only the product you need (`--product platform` or `--product mari`).
- Require human confirmation for high-impact actions an agent takes in the
  same session it reads nsmcp data.

## Quick start

1. Download a binary for your platform from the
   [releases page](https://github.com/nowsecure/nowsecure-mcp-server/releases),
   or build from source (see [Build & run](#build--run)):

   ```bash
   git clone git@github.com:nowsecure/nowsecure-mcp-server.git && cd nowsecure-mcp-server
   make build   # -> ./nsmcp
   ```

   Put `./nsmcp` on your `PATH`, or use an absolute path in client configs below.

   > **macOS:** release binaries are unsigned; if Gatekeeper blocks a
   > downloaded binary, clear the quarantine flag:
   > `xattr -d com.apple.quarantine ./nsmcp`

2. Get credentials:

   - **Static token (works today):** mint one at
     <https://app.nowsecure.com/account/tokens> and set `NOWSECURE_API_TOKEN`.
   - **`nsmcp login` (coming soon):** OAuth device-code login — not usable
     until the dedicated Auth0 CLI client is provisioned; see
     [Log in with your NowSecure account](#log-in-with-your-nowsecure-account).

3. Choose a product: use `--product platform` for your own mobile app portfolio
   or `--product mari` for third-party app risk intelligence. Then configure
   your client from the list below.

## Configuration

| Env var | Purpose |
| --- | --- |
| `NOWSECURE_API_TOKEN` | API token (**required** unless you've run `nsmcp login`). Fallbacks: `NOWSECURE_API_KEY`, `NS_API_TOKEN`, `NSMCP_API_TOKEN`, `NSMCP_API_KEY`. |
| `NOWSECURE_API_URL` | Base URL override (default `https://api.nowsecure.com`). Must be `https`; plain `http` is allowed only for localhost. |
| `NOWSECURE_OAUTH_CLIENT_ID` | OAuth client ID used by `nsmcp login`. No default yet — see below. |
| `NOWSECURE_OAUTH_ISSUER` | OAuth issuer override for `nsmcp login` (default `https://id.nowsecure.com`). Only needed for non-production tenants, paired with `NOWSECURE_API_URL`. |
| `NOWSECURE_OAUTH_AUDIENCE` | OAuth audience override for `nsmcp login` (default `https://app.nowsecure.com`). Env-specific on non-production tenants. |
| `NSMCP_LOG_FILE` | Opt-in tool-call log path. When set, nsmcp opens it append-mode (`0600`) and writes one JSON line per tool call (tool name, `duration_ms`, error if any) plus one line at server start (version, transport, selected product) — never call arguments or results. Unset (the default): no logging, nothing written to stderr or stdout. |

Mint a static token at <https://app.nowsecure.com/account/tokens>.

Flags (accepted before or after the subcommand): `--token`, `--base-url`, and
the required `--product` value (`platform` or `mari`).

## Log in with your NowSecure account (coming soon)

```bash
nsmcp login    # device-code OAuth flow
nsmcp whoami
nsmcp logout
```

`nsmcp login` opens a browser to a device-code confirmation page, then mints a
scoped NowSecure platform API token named `nsmcp/<hostname>` and stores it in
your OS keychain (falls back to a local file if no keychain is available).
`nsmcp serve --product platform` (or `--product mari`) picks that token up
automatically — no `NOWSECURE_API_TOKEN` needed. `nsmcp logout` revokes the
stored token.

Login flags: `--expiration-days` (token lifetime, default 90, max 365),
`--token-name` (default `nsmcp/<hostname>`), `--client-id` (else
`$NOWSECURE_OAUTH_CLIENT_ID`), `--no-browser` (print the verification URL
instead of opening a browser).

**Caveat:** this requires a dedicated Auth0 OAuth client for CLI login, which
does not exist yet (it is being provisioned). Until it lands, `nsmcp login`
cannot succeed for any client ID; once it does, set
`NOWSECURE_OAUTH_CLIENT_ID` (a default will ship in a later release). The
static token flow above works today with no extra setup.

`nsmcp serve --product platform --http <addr>` (or `--product mari`) runs a
remote, OAuth-protected resource server instead of stdio (the MCP-spec OAuth 2.1 flow:
clients discover the
authorization server via `/.well-known/oauth-protected-resource` and drive the
browser login themselves). It's a separate deployment mode, not needed for the
local-client setups above.

## Build & run

```bash
make build           # -> ./nsmcp
./nsmcp serve --product platform  # Platform MCP server over stdio
./nsmcp serve --product mari      # MARI MCP server over stdio
./nsmcp login             # OAuth device-code login (see above)
./nsmcp whoami
./nsmcp logout
./nsmcp version
./nsmcp profile apps     # call the REST API directly (endpoint verification)
./nsmcp completion zsh   # bash|zsh|fish|powershell
```

### Build MCPB packages

Build the single installable bundle from a macOS development machine:

```bash
make mcpb VERSION=0.1.3
# -> dist/nsmcp.mcpb
```

The bundle prompts for the product (`platform` or `mari`) when installed.
It contains a universal macOS binary (`arm64` + `amd64`) and a Windows `amd64`
binary, selected by the manifest's platform override. `mcpb-checksums.txt` is
written alongside the bundle, and the bundle is attached to each GitHub
release automatically.

`go install` isn't available yet — this module has no hosted module path, so
download a prebuilt binary from the
[releases page](https://github.com/nowsecure/nowsecure-mcp-server/releases) or
build from a clone (`git clone` + `make build`) as shown in
[Quick start](#quick-start). Homebrew is future work.

## Development

```bash
make test    # go test ./...
make vet     # go vet ./...
make fmt     # gofmt -w .
```

## License

Copyright © 2026 NowSecure, Inc. All rights reserved.

This is proprietary software. Authorized NowSecure customers may download,
build, and run unmodified copies solely for internal use with NowSecure
services they are authorized to access, subject to their applicable agreement
with NowSecure. See the [NowSecure Customer Use License](LICENSE.md).
