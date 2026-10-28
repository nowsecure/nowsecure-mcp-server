import hashlib
from pathlib import Path
import tempfile
import unittest
import zipfile

from package_skills import package, skill_files


class SkillPackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "skills"
        self.folder = self.root / "example"
        self.folder.mkdir(parents=True)
        self.entry = self.folder / "SKILL.md"
        self.entry.write_text("---\nname: example\ndescription: An example workflow.\n---\nRead [guide](guide.md).\n")
        (self.folder / "guide.md").write_text("Example reference.\n")

    def test_archive_contents_checksum_and_rebuild(self):
        output = Path(self.temp.name) / "out"
        package(self.root, output)
        archive = output / "example.zip"
        original = archive.read_bytes()
        with zipfile.ZipFile(archive) as built:
            self.assertEqual(set(built.namelist()), {"example/SKILL.md", "example/guide.md"})
            self.assertEqual(built.read("example/SKILL.md"), self.entry.read_bytes())
        self.assertEqual((output / "skill-checksums.txt").read_text(), f"{hashlib.sha256(original).hexdigest()}  example.zip\n")
        package(self.root, output)
        self.assertEqual(archive.read_bytes(), original)
        self.entry.write_text(self.entry.read_text().replace("Read [guide](guide.md).", "Updated."))
        (self.folder / "guide.md").unlink()
        package(self.root, output)
        with zipfile.ZipFile(archive) as built:
            self.assertEqual(built.namelist(), ["example/SKILL.md"])

    def test_rejects_invalid_metadata_and_missing_reference(self):
        original = self.entry.read_text()
        for bad in [original.replace("name: example", "name: wrong"), original.replace("description: An example workflow.", "description: []"), original.replace("guide.md", "missing.md")]:
            with self.subTest(content=bad):
                self.entry.write_text(bad)
                with self.assertRaises(ValueError):
                    skill_files(self.folder)

    def test_rejects_symlinks_and_hidden_files(self):
        link = self.folder / "link.md"
        link.symlink_to(self.entry)
        with self.assertRaises(ValueError):
            skill_files(self.folder)
        link.unlink()
        (self.folder / ".env").write_text("not for distribution")
        with self.assertRaises(ValueError):
            skill_files(self.folder)

    def test_rejects_stale_release_artifacts(self):
        output = Path(self.temp.name) / "out"
        output.mkdir()
        (output / "removed-skill.zip").write_bytes(b"stale")
        with self.assertRaises(ValueError):
            package(self.root, output)


if __name__ == "__main__":
    unittest.main()
