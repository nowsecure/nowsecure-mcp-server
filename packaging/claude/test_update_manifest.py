import json
from pathlib import Path
import tempfile
import unittest

from update_manifest import update_manifest


class UpdateManifestTest(unittest.TestCase):
    def test_updates_release_and_preserves_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plugin.json"
            original = {"name": "nowsecure", "author": {"name": "NowSecure"}}
            path.write_text(json.dumps(original))
            update_manifest(path, "v1.2.3")
            updated = json.loads(path.read_text())
            self.assertEqual(updated["version"], "1.2.3")
            self.assertEqual(updated["mcpServers"],
                             "https://github.com/nowsecure/nowsecure-mcp-server/"
                             "releases/download/v1.2.3/nsmcp_1.2.3.mcpb")
            for key, value in original.items():
                self.assertEqual(updated[key], value)
            first = path.read_bytes()
            update_manifest(path, "v1.2.3")
            self.assertEqual(path.read_bytes(), first)

    def test_invalid_or_prerelease_tag_does_not_modify_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plugin.json"
            path.write_text('{"name":"nowsecure"}\n')
            original = path.read_bytes()
            for tag in ("1.2.3", "v1.2.3-rc.1", "v1.2.3+build", "v01.2.3", "v1.2", "../main"):
                with self.subTest(tag=tag), self.assertRaises(ValueError):
                    update_manifest(path, tag)
                self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
