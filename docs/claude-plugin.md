# Claude plugin

The repository root is also a Claude plugin, declared in
[`.claude-plugin/plugin.json`](../.claude-plugin/plugin.json). It references the
published MCPB bundle pinned in the manifest, which includes the server binaries for macOS
(Apple silicon and Intel) and Windows x64. Linux users should use the manual
[MCP setup](../README.md#per-client-setup). Use a Claude client that supports MCPB URLs in plugin
manifests; this is a local server, not a hosted web connector.

When configuring the bundle, select `platform` for your own mobile apps or
`mari` for third-party app risk intelligence and provide your NowSecure API
token in the sensitive credential field. An authorized NowSecure account
with access to the selected product is required. No separate `nsmcp`
installation is needed. Avoid also enabling a manual MCP entry for the same
product, which would expose duplicate tools.

For the Claude plugin submission form, use:

- **Repository:** `https://github.com/nowsecure/nowsecure-mcp-server`
- **Plugin path:** leave empty (repository root)
- **Branch or tag:** the branch containing this manifest while reviewing;
  leave empty to track the default branch after the PR is merged.

Click **Validate** again after the manifest is available on the selected
branch. This addresses the missing `plugin.json` check; the directory's
remaining checks and review still apply.

Maintainers can check a clean checkout with
`claude plugin validate . --profile directory --strict`.
To test locally, use a clean checkout and launch `claude --plugin-dir .`,
then inspect `/mcp` and try a read-only query for the configured product.
A clean checkout avoids loading a developer's ignored, project-local
`.mcp.json` alongside the plugin's server.

## Release updates

After GoReleaser publishes a stable release, the release workflow opens a PR
updating the plugin version and pinned MCPB URL together. Merge that PR to
roll the plugin forward. Prereleases and reruns of older releases do not
change the plugin. The workflow verifies that the expected bundle is a
published release asset before proposing the update.

The repository must allow **GitHub Actions to create and approve pull
requests** under Settings → Actions → General → Workflow permissions.
The workflow only creates a PR; it does not approve or merge it. PRs created
with `GITHUB_TOKEN` do not automatically trigger the normal PR workflows;
validate the manifest before merging (or use a GitHub App token if automatic
PR checks are required).

The URL stays pinned for reproducible installs and the version changes so
Claude can recognize an update. The plugin runs the released binary, not
unreleased Go source on the selected branch. To generate an update locally:

```bash
python3 packaging/claude/update_manifest.py v0.1.9
```

Use the tag of an already published stable release. The script updates both
fields; the release workflow checks asset availability.

The listing icon in `.claude-plugin/icon.png` is the
[official NowSecure website icon](https://www.nowsecure.com/wp-content/uploads/2018/12/cropped-Image-from-iOS.png).

