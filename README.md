# nsmcp (beta)

A small **Model Context Protocol (MCP) server** for two NowSecure products —
**[NowSecure Platform](https://www.nowsecure.com/products/nowsecure-platform/)**
(DevSecOps triage of your own mobile app portfolio) and
**[NowSecure MARI](https://www.nowsecure.com/products/nowsecure-risk-intelligence/)**
(Mobile App Risk Intelligence — vetting vendor/third-party apps). It gives an
AI assistant a focused set of read-only tools for each — see
[Supported products and tools](#supported-products-and-tools).

nsmcp runs **locally on stdio**. Each client below launches the `nsmcp` binary
itself.

## Supported products and tools

Tools are grouped by product. Each group is toggled by a serve flag — both
are enabled by default, and at least one must be enabled.

| Product | Tools | Flag |
| --- | --- | :---: |
| **NowSecure Platform** | `list_apps` · `list_assessments` · `get_assessment_findings` · `get_finding` · `search_findings` · `get_apps_affected_by_finding` | `--platform` |
| **NowSecure MARI** | `list_mari_apps` · `get_mari_assessment` | `--mari` |

### NowSecure Platform

Triage your own mobile app portfolio: scores, findings, fleet-wide impact, and
remediation guidance.

| Tool | Description |
| --- | --- |
| `list_apps` | List portfolio apps with their latest security score, rating, and open vulnerability count. The starting point for DevSecOps triage. |
| `list_assessments` | Scan history of one app, newest first, with score, rating, status, and finding counts by severity. |
| `get_assessment_findings` | Findings for one assessment as a compact, triage-ready list, sorted most-severe first. |
| `get_finding` | Documentation for a single finding: description, steps to reproduce, testing method, and remediation guidance. |
| `search_findings` | Free-text search over the finding catalog (key, title, description, category) — returns finding keys when you only know a topic or risk. |
| `get_apps_affected_by_finding` | Fleet-wide impact: which portfolio apps' latest assessments are affected by a given finding. |

### NowSecure MARI

Vet vendor and third-party apps you didn't build, by risk score, letter
rating, and findings.

| Tool | Description |
| --- | --- |
| `list_mari_apps` | List third-party apps in your MARI catalog with risk score, letter rating (A–F), and risk category (LOW/MEDIUM/HIGH). |
| `get_mari_assessment` | Risk profile for one third-party app: score, rating, findings summary, and opt-in deep-dive sections (permissions, tracking domains, libraries/SDKs, AI usage, …). |

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
  no longer use at <https://app.nowsecure.com/account#token>.
- Disable the tool group you don't need (`--platform=false` / `--mari=false`).
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
     <https://app.nowsecure.com/account#token> and set `NOWSECURE_API_TOKEN`.
   - **`nsmcp login` (coming soon):** OAuth device-code login — not usable
     until the dedicated Auth0 CLI client is provisioned; see
     [Log in with your NowSecure account](#log-in-with-your-nowsecure-account).

3. Configure your client — pick it from the list below.

## One-click install

Pick your client below — each button uses the client's native install link to
prefill the nsmcp config, so you don't need to edit any JSON by hand.

<table align="center">
  <tr>
    <td align="center" width="200">
      <a href="https://cursor.com/en/install-mcp?name=nsmcp&config=eyJjb21tYW5kIjoibnNtY3AiLCJhcmdzIjpbInNlcnZlIl0sImVudiI6eyJOT1dTRUNVUkVfQVBJX1RPS0VOIjoiWU9VUl9UT0tFTiJ9fQ%3D%3D">
        <img src="https://img.shields.io/badge/Cursor-000000?style=for-the-badge&logo=cursor&logoColor=white" alt="Add to Cursor"><br>
        <b>Add to Cursor</b>
      </a>
      <br><sub>Triage app findings without leaving your editor.</sub>
    </td>
    <td align="center" width="200">
      <a href="https://vscode.dev/redirect/mcp/install?name=nsmcp&config=%7B%22command%22%3A%22nsmcp%22%2C%22args%22%3A%5B%22serve%22%5D%2C%22env%22%3A%7B%22NOWSECURE_API_TOKEN%22%3A%22YOUR_TOKEN%22%7D%7D">
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
token from <https://app.nowsecure.com/account#token>.

## Per-client setup

<details>
<summary><strong>Claude Code (CLI)</strong></summary>

```bash
claude mcp add --env NOWSECURE_API_TOKEN=$NOWSECURE_API_TOKEN --transport stdio nsmcp -- nsmcp serve
```

`--scope` controls where the entry is stored (defaults to `local`,
i.e. `~/.claude.json` keyed to this project directory):

```bash
claude mcp add --scope user  --env NOWSECURE_API_TOKEN=$NOWSECURE_API_TOKEN --transport stdio nsmcp -- nsmcp serve   # global, all projects
claude mcp add --scope project --env NOWSECURE_API_TOKEN=$NOWSECURE_API_TOKEN --transport stdio nsmcp -- nsmcp serve # .mcp.json, team-shared
```

Manage with `claude mcp list` / `claude mcp get nsmcp` / `claude mcp remove nsmcp`,
or `/mcp` inside a session.

</details>

<details>
<summary><strong>Claude Desktop</strong></summary>

Settings → Developer → Edit Config opens `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "nsmcp": {
      "command": "/absolute/path/to/nsmcp",
      "args": ["serve"],
      "env": { "NOWSECURE_API_TOKEN": "YOUR_TOKEN" }
    }
  }
}
```

Restart Claude Desktop after editing.

</details>

<details>
<summary><strong>Cursor</strong></summary>

Use the [one-click button](#one-click-install) above, or edit
`~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project) by hand:

```json
{
  "mcpServers": {
    "nsmcp": {
      "command": "nsmcp",
      "args": ["serve"],
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
code --add-mcp "{\"name\":\"nsmcp\",\"command\":\"nsmcp\",\"args\":[\"serve\"],\"env\":{\"NOWSECURE_API_TOKEN\":\"YOUR_TOKEN\"}}"
```

Or `.vscode/mcp.json`, using VS Code's `inputs` prompt so the token isn't
checked into the file:

```json
{
  "servers": {
    "nsmcp": {
      "command": "nsmcp",
      "args": ["serve"],
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
    "nsmcp": {
      "command": "nsmcp",
      "args": ["serve"],
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
gemini mcp add -e NOWSECURE_API_TOKEN=$NOWSECURE_API_TOKEN nsmcp nsmcp serve
```

Or `~/.gemini/settings.json` (user) / `.gemini/settings.json` (project):

```json
{
  "mcpServers": {
    "nsmcp": {
      "command": "nsmcp",
      "args": ["serve"],
      "env": { "NOWSECURE_API_TOKEN": "YOUR_TOKEN" }
    }
  }
}
```

</details>

<details>
<summary><strong>Codex CLI</strong></summary>

```bash
codex mcp add nsmcp --env NOWSECURE_API_TOKEN=$NOWSECURE_API_TOKEN -- nsmcp serve
```

Or `~/.codex/config.toml` (note snake_case `mcp_servers`, unlike other clients):

```toml
[mcp_servers.nsmcp]
command = "nsmcp"
args = ["serve"]
env = { NOWSECURE_API_TOKEN = "YOUR_TOKEN" }
```

</details>

<details>
<summary><strong>Zed</strong></summary>

`settings.json` (`~/.config/zed/settings.json`, or Command Palette → "zed: open settings")
uses `context_servers`, not `mcpServers`:

```json
{
  "context_servers": {
    "nsmcp": {
      "command": "nsmcp",
      "args": ["serve"],
      "env": { "NOWSECURE_API_TOKEN": "YOUR_TOKEN" }
    }
  }
}
```

</details>

## Configuration

| Env var | Purpose |
| --- | --- |
| `NOWSECURE_API_TOKEN` | API token (**required** unless you've run `nsmcp login`). Fallbacks: `NOWSECURE_API_KEY`, `NS_API_TOKEN`, `NSMCP_API_TOKEN`, `NSMCP_API_KEY`. |
| `NOWSECURE_API_URL` | Base URL override (default `https://api.nowsecure.com`). Must be `https`; plain `http` is allowed only for localhost. |
| `NOWSECURE_OAUTH_CLIENT_ID` | OAuth client ID used by `nsmcp login`. No default yet — see below. |
| `NOWSECURE_OAUTH_ISSUER` | OAuth issuer override for `nsmcp login` (default `https://id.nowsecure.com`). Only needed for non-production tenants, paired with `NOWSECURE_API_URL`. |
| `NOWSECURE_OAUTH_AUDIENCE` | OAuth audience override for `nsmcp login` (default `https://app.nowsecure.com`). Env-specific on non-production tenants. |

Mint a static token at <https://app.nowsecure.com/account#token>.

Flags (accepted before or after the subcommand): `--token`, `--base-url`,
`--platform` (default true), `--mari` (default true).

## Log in with your NowSecure account (coming soon)

```bash
nsmcp login    # device-code OAuth flow
nsmcp whoami
nsmcp logout
```

`nsmcp login` opens a browser to a device-code confirmation page, then mints a
scoped NowSecure platform API token named `nsmcp/<hostname>` and stores it in
your OS keychain (falls back to a local file if no keychain is available).
`nsmcp serve` picks that token up automatically — no `NOWSECURE_API_TOKEN`
needed. `nsmcp logout` revokes the stored token.

Login flags: `--expiration-days` (token lifetime, default 90, max 365),
`--token-name` (default `nsmcp/<hostname>`), `--client-id` (else
`$NOWSECURE_OAUTH_CLIENT_ID`), `--no-browser` (print the verification URL
instead of opening a browser).

**Caveat:** this requires a dedicated Auth0 OAuth client for CLI login, which
does not exist yet (it is being provisioned). Until it lands, `nsmcp login`
cannot succeed for any client ID; once it does, set
`NOWSECURE_OAUTH_CLIENT_ID` (a default will ship in a later release). The
static token flow above works today with no extra setup.

`nsmcp serve --http <addr>` runs a remote, OAuth-protected resource server
instead of stdio (the MCP-spec OAuth 2.1 flow: clients discover the
authorization server via `/.well-known/oauth-protected-resource` and drive the
browser login themselves). It's a separate deployment mode, not needed for the
local-client setups above.

## Build & run

```bash
make build           # -> ./nsmcp
./nsmcp serve        # MCP server over stdio (default subcommand)
./nsmcp login        # OAuth device-code login (see above)
./nsmcp whoami
./nsmcp logout
./nsmcp version
./nsmcp profile apps     # call the REST API directly (endpoint verification)
./nsmcp completion zsh   # bash|zsh|fish|powershell
```

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
