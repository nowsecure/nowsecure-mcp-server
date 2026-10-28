"""Validate repository skills and build reproducible, uploadable ZIPs."""

import argparse
import hashlib
from pathlib import Path
import re
import zipfile

import yaml


def skill_files(folder):
    if folder.is_symlink():
        raise ValueError(f"Symlink skill directory: {folder}")
    files = sorted(folder.rglob("*"))
    for path in files:
        if path.is_symlink():
            raise ValueError(f"Symlink in skill: {path}")
        if any(part.startswith(".") for part in path.relative_to(folder).parts):
            raise ValueError(f"Hidden file/directory in skill: {path}")
        if path.is_file() and path.suffix != ".md":
            raise ValueError(f"Unexpected skill asset (review before allowing): {path}")
    files = [path for path in files if path.is_file()]
    entry = folder / "SKILL.md"
    content = entry.read_text(encoding="utf-8")
    match = re.match(r"\A---\n(.*?)\n---\n", content, re.DOTALL)
    if not match:
        raise ValueError(f"Missing YAML frontmatter: {entry}")
    metadata = yaml.safe_load(match[1])
    if not isinstance(metadata, dict):
        raise ValueError(f"Frontmatter must be a mapping: {entry}")
    name = metadata.get("name", "")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 64 or name != folder.name:
        raise ValueError(f"Invalid skill name/directory: {entry}")
    description = metadata.get("description")
    if not isinstance(description, str) or not description.strip() or len(description) > 1024:
        raise ValueError(f"Invalid skill description: {entry}")
    for path in files:
        text = path.read_text(encoding="utf-8")
        for target in re.findall(r"\]\(([^)]+)\)", text):
            if re.match(r"https?://|mailto:|#", target):
                continue
            target = target.split("#", 1)[0]
            resolved = (path.parent / target).resolve()
            if not resolved.is_relative_to(folder.resolve()) or not resolved.is_file():
                raise ValueError(f"Missing or external local reference in {path}: {target}")
    return files


def package(root, output):
    folders = sorted(path for path in root.iterdir() if path.is_dir())
    if not folders:
        raise ValueError("No skills found")
    # Validate every skill before writing any release artifacts.
    validated = [(folder, skill_files(folder)) for folder in folders]
    output.mkdir(parents=True, exist_ok=True)
    expected = {f"{folder.name}.zip" for folder in folders}
    unexpected = {path.name for path in output.glob("*.zip")} - expected
    if unexpected:
        raise ValueError(f"Stale ZIPs in output; use a clean output directory: {sorted(unexpected)}")
    checksums = []
    for folder, files in validated:
        archive = output / f"{folder.name}.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as dest:
            for path in files:
                info = zipfile.ZipInfo(path.relative_to(root).as_posix(), (1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                dest.writestr(info, path.read_bytes())
        with zipfile.ZipFile(archive) as built:
            if built.testzip() is not None:
                raise ValueError(f"Corrupt ZIP: {archive}")
        checksums.append(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
        print(f"Validated and packaged {archive}")
    (output / "skill-checksums.txt").write_text("".join(checksums), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("skills"))
    parser.add_argument("--output", type=Path, default=Path("dist/skills"))
    args = parser.parse_args()
    package(args.source, args.output)
