from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).parents[1]))

from internal.component_lock import load_component_lock
from scripts.build_preview import build_preview
from scripts.build_release import build_release
from scripts.verify_components import verify_lock


def _regular_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or _reparse_or_link(path) or not path.is_dir():
        raise ValueError(f"{label} must be a regular absolute directory")
    return path


def _reparse_or_link(path: Path) -> bool:
    try:
        current = path
        while True:
            information = current.stat(follow_symlinks=False)
            if current.is_symlink() or getattr(information, "st_file_attributes", 0) & 0x400:
                return True
            if current == current.parent:
                return False
            current = current.parent
    except OSError:
        return True


def _git(source: Path, *arguments: str) -> str:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    result = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={source}",
            "-C",
            str(source),
            *arguments,
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return result.stdout.strip()


def _source_commit(source: Path) -> str:
    if _git(source, "status", "--porcelain"):
        raise ValueError("source checkout must be clean")
    commit = _git(source, "rev-parse", "--verify", "HEAD")
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise ValueError("source checkout has an invalid HEAD")
    return commit


def _extract_generated_archive(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as package:
        for member in package.infolist():
            if member.is_dir() or Path(member.filename).is_absolute() or ".." in Path(member.filename).parts:
                raise ValueError("source archive contains an invalid member")
        package.extractall(destination)


def _publish_create_only(candidate: Path, output: Path, expected_sha256: str) -> None:
    if os.name != "nt":
        raise ValueError("release publication requires Windows")
    before = candidate.stat(follow_symlinks=False)
    if _reparse_or_link(candidate) or not candidate.is_file() or before.st_nlink != 1:
        raise ValueError("release candidate must be a regular unlinked file")
    os.rename(candidate, output)
    after = output.stat(follow_symlinks=False)
    if (
        _reparse_or_link(output)
        or not output.is_file()
        or before.st_size != after.st_size
        or hashlib.sha256(output.read_bytes()).hexdigest() != expected_sha256
    ):
        raise ValueError("release output identity changed during publication")


def build_public_release(source: Path, component_root: Path, output: Path) -> dict:
    source = _regular_directory(Path(source), "source")
    component_root = _regular_directory(Path(component_root), "component root")
    output = Path(output)
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    _regular_directory(output.parent, "output parent")
    if output.exists() or output.is_symlink():
        raise ValueError("output must not exist")

    source_commit = _source_commit(source)
    lock_path = source / "manifests" / "components.lock.json"
    verify_lock(lock_path, component_root)
    locked = load_component_lock(lock_path)
    components = {
        name: (
            identity["version"],
            component_root / name / identity["version"] / identity["asset"],
        )
        for name, identity in locked.items()
    }

    with tempfile.TemporaryDirectory() as temporary_name:
        temporary = Path(temporary_name)
        source_archive = temporary / "source.zip"
        staged_source = temporary / "source"
        staged_source.mkdir()
        build_release(source, source_archive, source / "manifests" / "public-tree.json")
        _extract_generated_archive(source_archive, staged_source)
        with tempfile.TemporaryDirectory(
            dir=output.parent, prefix=f".{output.name}."
        ) as output_temporary_name:
            candidate = Path(output_temporary_name) / output.name
            build_preview(
                staged_source,
                components["ao2"][1],
                locked["ao2"]["version"],
                candidate,
                components,
                component_root,
            )
            data = candidate.read_bytes()
            _publish_create_only(candidate, output, hashlib.sha256(data).hexdigest())

    return {
        "source_commit": source_commit,
        "output": output.name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--component-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args(argv)
    record = build_public_release(
        arguments.source, arguments.component_root, arguments.output
    )
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
