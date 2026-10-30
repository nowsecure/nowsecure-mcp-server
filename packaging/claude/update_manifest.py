"""Update the Claude plugin to a stable release tag (no network requests)."""

import json
from pathlib import Path
import re
import sys


def update_manifest(path, tag):
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ValueError("expected a stable release tag such as v0.1.9")
    version = tag[1:]
    manifest = json.loads(path.read_text())
    manifest["version"] = version
    manifest["mcpServers"] = (
        "https://github.com/nowsecure/nowsecure-mcp-server/releases/download/"
        f"{tag}/nsmcp_{version}.mcpb"
    )
    path.write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: update_manifest.py vMAJOR.MINOR.PATCH")
    try:
        update_manifest(
            Path(__file__).resolve().parents[2] / ".claude-plugin/plugin.json",
            sys.argv[1],
        )
    except ValueError as error:
        sys.exit(str(error))
