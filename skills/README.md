# NowSecure skills

Portable workflows for assistants connected to `nsmcp`. Install the server
separately using the [client setup guide](../README.md#per-client-setup), select
`--product platform`, and confirm that `list_apps` works in the same session.
Skills contain instructions, not credentials or a server. Installing the MCPB
does not install these skills automatically.

Available: [nowsecure-backend-technologies](nowsecure-backend-technologies/SKILL.md)
uses `api_hsts` evidence to inventory observed backend technologies and identify
apps contacting PHP services for possible CVE exposure review.

Releases containing this workflow publish `nowsecure-backend-technologies.zip`
and `skill-checksums.txt` as separate assets on the
[release page](https://github.com/nowsecure/nowsecure-mcp-server/releases).
Use the server and skill from the same release. Download the skill ZIP directly
for Claude, or extract its folder for other clients. The ZIP includes the
PHP2Shell reference. The release tag identifies its version.

Example request after installation:

> Use nowsecure-backend-technologies to find which apps in my NowSecure Platform
> portfolio contact PHP services and could be impacted by PHP2Shell. Include
> endpoint evidence, scan dates, and coverage gaps.

## Claude Desktop

Download the release skill ZIP, or from this repository's `skills` directory,
create a ZIP containing the skill folder (not the entire repository):

```sh
zip -r /tmp/nowsecure-backend-technologies.zip nowsecure-backend-technologies
```

In Claude, open **Customize → Skills → + → Create skill → Upload a skill**,
upload the ZIP, and enable it. Enable code execution if required by the client.
The NowSecure MCPB/connection must also be enabled in the conversation. If
upload is unavailable, check your organization's skill permissions.

Source: [Use skills in Claude](https://support.claude.com/en/articles/12512180-use-skills-in-claude).

## GitHub Copilot in VS Code

Copy `nowsecure-backend-technologies/` into your project's `.github/skills/`:

```text
your-project/.github/skills/nowsecure-backend-technologies/SKILL.md
```

Keep the entire skill folder when copying. Ensure `chat.useAgentSkills` is
enabled and the NowSecure Platform MCP tools are available in Copilot agent
mode. Start a new chat and use the example request above. This location is
for GitHub Copilot, not Microsoft 365 Copilot.

Source: [Use Agent Skills in VS Code](https://code.visualstudio.com/docs/agent-customization/agent-skills).

## ChatGPT / Work mode

Use a skills plugin for persistent installation. A bare `SKILL.md` attachment
is conversation context, not an installed skill. Local plugin availability
depends on the ChatGPT surface and workspace policy.

Create a local plugin folder with this layout:

```text
nowsecure-workflows/
  plugin.json
  skills/nowsecure-backend-technologies/SKILL.md
```

Copy this repository's skill folder into that `skills/` directory. Use this
minimal `plugin.json`:

```json
{
  "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
  "name": "nowsecure-workflows",
  "version": "0.1.0",
  "description": "NowSecure Platform evidence investigation workflows"
}
```

In Work mode, ask `@plugin-creator` to add this local plugin folder to a personal
marketplace. Refresh/restart the desktop app, open the Plugins Directory, select
the local source, and install the plugin. Start a new chat with the skill and
NowSecure Platform tools available. This plugin assumes an existing connection;
it does not configure one. A local stdio server is not automatically accessible
to a web-only ChatGPT session.

If local plugins are unavailable, attach `SKILL.md` and explicitly ask the
assistant to follow it for that conversation, provided the session has Platform
tools. Persistent web distribution requires the supported plugin publication
path; this repository does not yet supply a published plugin.

Sources: [Package a plugin](https://developers.openai.com/plugins/build/plugins),
[plugin submission](https://developers.openai.com/plugins/deploy/submission).

## Verify and update

Contributors can build the same artifacts as CI with Python 3.15. CI selects
the latest available 3.15 patch release; PyYAML is pinned in the requirements
file for repeatable dependency installation:

```sh
python3 -m venv /tmp/nsmcp-skills-venv
/tmp/nsmcp-skills-venv/bin/python -m pip install -r scripts/requirements-skills.txt
make test-skills skills PYTHON=/tmp/nsmcp-skills-venv/bin/python
```

Run these commands from the repository root. Output goes to `dist/skills/`.
CI validates frontmatter and local reference paths, tests ZIP packaging, and
uploads the ZIP and checksum as a workflow artifact. Tagged releases build
them into `.skills-dist/`, outside GoReleaser's cleaned `dist/` directory.
The packager currently permits Markdown assets only; extend its validation
deliberately if a later skill needs scripts or other resources.

Ask the assistant which skill it loaded and which Platform tools it can access.
Then try the example request with one app before a portfolio-wide inventory.
Check that results cite actual scan evidence and distinguish potential CVE
exposure from confirmed vulnerability. No PHP match must not be reported as
proof of safety.

These instructions were checked against vendor documentation on 2026-10-27;
client UI and workspace capabilities can differ. Installation flows have not
been exercised in each client. To update a copied/uploaded skill, replace it
with the current folder or ZIP and start a new chat. Server upgrades alone do
not update separately installed skills.
