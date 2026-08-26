from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path

from internal.component_lock import load_component_lock

_MUTABLE_FILES = {"pool.json", ".pool.lock", *(f"offices/O{n}/office-state.json" for n in range(1, 6))}
_MUTABLE_PREFIXES = ("runtime/", "operator-secrets/", "updates/", *(f"offices/O{n}/{part}/" for n in range(1, 6) for part in ("history", "work")))
_REQUIRED_BOOTSTRAP_MEMBERS = {
    "README.md",
    "README-FIRST.md",
    "docs/QUICKSTART.md",
    "docs/AI_OPERATOR_RUNBOOK.md",
    "docs/OPERATOR_GUIDE.md",
    "packaging/Install-AOOfficePool.ps1",
    "packaging/Verify-AOOfficePool.ps1",
    "packaging/Uninstall-AOOfficePool.ps1",
    "schemas/developer-preview-release.schema.json",
    "schemas/developer-preview-candidate.schema.json",
    "skills/thought-experiment/SKILL.md",
    "skills/engineering-research/SKILL.md",
    "skills/scope-to-deliverable-workflow/SKILL.md",
}
_CONTROL_CONTRACT = "manifests/developer-preview-release.json"
# Compatibility hook for older tests; accepted identities come only from _LOCK_PATH.
_S01_LOCKS = None
_LOCK_PATH = Path(__file__).parents[1] / "manifests" / "components.lock.json"


def _mutable(path: str) -> bool:
    return path in _MUTABLE_FILES or path.startswith(_MUTABLE_PREFIXES)


def _write(z: zipfile.ZipFile, path: str, data: bytes) -> None:
    info = zipfile.ZipInfo(path, (1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    z.writestr(info, data)


def _directory(z: zipfile.ZipFile, path: str) -> None:
    info = zipfile.ZipInfo(path + "/", (1980, 1, 1, 0, 0, 0))
    info.external_attr = 0o40755 << 16
    z.writestr(info, b"")


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


def _validate_s01_components(ao2: Path, runtime_version: str, components: dict[str, tuple[str, Path]], component_root: Path) -> dict[str, bytes]:
    component_root = Path(component_root)
    if not component_root.is_absolute() or _reparse_or_link(component_root) or not component_root.is_dir():
        raise ValueError("component root must be a regular absolute directory")
    locked = load_component_lock(_LOCK_PATH)
    if runtime_version != locked["ao2"]["version"] or set(components) != set(locked):
        raise ValueError("component map must contain exactly the S01 components")
    if len({name.casefold() for name in components}) != len(components):
        raise ValueError("component map has case-insensitive duplicate names")
    if len({str(Path(binary)).casefold() for _, binary in components.values()}) != len(components):
        raise ValueError("component inputs have case-insensitive duplicate paths")
    paths = []
    for name, (version, binary) in components.items():
        expected = locked[name]
        expected_version = expected["version"]
        expected_name = expected["asset"]
        expected_hash = expected["sha256"]
        if version != expected_version or Path(binary).name != expected_name:
            raise ValueError("component identity is not bound in S01")
        binary = Path(binary)
        try:
            binary.relative_to(component_root)
        except ValueError as error:
            raise ValueError("component input must be within component root") from error
        if _reparse_or_link(binary) or not binary.is_file():
            raise ValueError("component input must be a verified S01 file")
        data = binary.read_bytes()
        if _reparse_or_link(binary) or hashlib.sha256(data).hexdigest() != expected_hash:
            raise ValueError("component input hash does not match S01")
        paths.append((str(binary).casefold(), data))
    if len({path for path, _ in paths}) != len(paths) or Path(ao2) != Path(components["ao2"][1]):
        raise ValueError("component inputs have duplicate or unbound paths")
    return dict(zip(components, (data for _, data in paths)))


def _validate_bootstrap_source(source: Path) -> None:
    if _reparse_or_link(source) or not source.is_dir():
        raise ValueError("source is missing bootstrap contract")
    for relative in _REQUIRED_BOOTSTRAP_MEMBERS:
        path = source / relative
        if _reparse_or_link(path) or not path.is_file():
            raise ValueError("source is missing bootstrap contract")


def _admit_source(source: Path) -> tuple[list[str], list[tuple[str, bytes]]]:
    directories: list[str] = []
    files: list[tuple[str, bytes]] = []
    folded: set[str] = set()
    for directory, names, filenames in os.walk(source, followlinks=False):
        base = Path(directory)
        for name in sorted(names):
            path = base / name
            relative = path.relative_to(source).as_posix()
            if _reparse_or_link(path):
                raise ValueError("source entries must be regular unlinked files and directories")
            key = relative.casefold()
            if key in folded:
                raise ValueError("source entries must have unique case-insensitive paths")
            folded.add(key)
            directories.append(relative)
        for name in sorted(filenames):
            path = base / name
            relative = path.relative_to(source).as_posix()
            if relative == _CONTROL_CONTRACT:
                continue
            if _mutable(relative):
                raise ValueError("mutable source state is not admitted")
            information = path.stat(follow_symlinks=False)
            if _reparse_or_link(path) or not path.is_file() or information.st_nlink != 1:
                raise ValueError("source entries must be regular unlinked files and directories")
            key = relative.casefold()
            if key in folded:
                raise ValueError("source entries must have unique case-insensitive paths")
            folded.add(key)
            data = path.read_bytes()
            after = path.stat(follow_symlinks=False)
            if after.st_nlink != 1 or (information.st_dev, information.st_ino, information.st_size) != (after.st_dev, after.st_ino, after.st_size):
                raise ValueError("source entry changed during admission")
            files.append((relative, data))
    return directories, files


def _initialize_preview_directories(root: Path) -> None:
    directories = {
        "operator-secrets",
        "runtime/governance/consumed",
        "runtime/governance/issued",
        "runtime/governance/revoked",
        "runtime/pointers",
        "runtime/receipts",
        "runtime/recovery",
        "runtime/transactions",
    }
    directories.update(
        f"offices/O{office}/{part}"
        for office in range(1, 6)
        for part in ("history", "runtime/versions", "work")
    )
    for relative in sorted(directories):
        (root / relative).mkdir(parents=True, exist_ok=True)


def build_preview(source: Path, ao2: Path, runtime_version: str, output: Path, components: dict[str, tuple[str, Path]] | None = None, component_root: Path | None = None) -> Path:
    source, ao2, output = Path(source), Path(ao2), Path(output)
    if components is None:
        raise ValueError("component map is required")
    if component_root is None:
        raise ValueError("component root is required")
    verified = _validate_s01_components(ao2, runtime_version, components, component_root)
    _validate_bootstrap_source(source)
    source_directories, source_files = _admit_source(source)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "preview"
        root.mkdir()
        for relative in source_directories:
            (root / relative).mkdir(parents=True, exist_ok=True)
        for relative, data in source_files:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        _initialize_preview_directories(root)
        for office in range(1, 6):
            destination = root / f"offices/O{office}/runtime/versions/{runtime_version}/ao2.exe"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(verified["ao2"])
        for name, (version, binary) in sorted((components or {}).items()):
            binary = Path(binary)
            destination = root / "components" / name / version / binary.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(verified[name])
        files = []
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            relative = path.relative_to(root).as_posix()
            if not _mutable(relative):
                data = path.read_bytes()
                files.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
        immutable_paths = {row["path"] for row in files}
        if not _REQUIRED_BOOTSTRAP_MEMBERS <= immutable_paths or _CONTROL_CONTRACT in immutable_paths:
            raise ValueError("source is missing bootstrap contract")
        manifest = {"schema_version": 1, "label": "developer-preview", "architecture": "windows-x86_64", "runtime_version": runtime_version, "files": files}
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as package:
            for path in sorted(p for p in root.rglob("*") if p.is_dir()):
                _directory(package, path.relative_to(root).as_posix())
            for path in sorted(p for p in root.rglob("*") if p.is_file()):
                _write(package, path.relative_to(root).as_posix(), path.read_bytes())
            _write(package, "developer-preview-manifest.json", (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return output
