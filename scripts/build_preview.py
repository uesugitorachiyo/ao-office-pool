from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

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
    "skills/thought-experiment/SKILL.md",
    "skills/engineering-research/SKILL.md",
    "skills/scope-to-deliverable-workflow/SKILL.md",
}
_CONTROL_CONTRACT = "manifests/developer-preview-release.json"
_S01_LOCKS = {
    "ao2": {"name": "ao2", "version": "v0.5.12", "repository": "https://github.com/uesugitorachiyo/ao2.git", "commit": "68cf6914ae51cb4b638a7441ac05c1b4e86ec6d6", "asset": "ao2.exe", "license": "Apache-2.0", "sha256": "f2fb203040c0f67fe159e3f84cf84e5e8dcd3e882ff79f6abaa306e909d29dd1"},
    "ao-mission": {"name": "ao-mission", "version": "v0.1.6", "repository": "https://github.com/uesugitorachiyo/ao-mission.git", "commit": "f631893906e3bed6f257ac30bc3d0ad2739fe9df", "asset": "ao-mission.exe", "license": "Apache-2.0", "sha256": "46639c6389721dbc691d5e20f3d7478451bd160a7618352bff87917d2307d87b"},
    "ao-command": {"name": "ao-command", "version": "v0.1.3", "repository": "https://github.com/uesugitorachiyo/ao-command.git", "commit": "ffef6d76306e892c3e7a7f39734433d5a832006a", "asset": "ao-command.exe", "license": "Apache-2.0", "sha256": "3023530b6035e86e4167069840da4dcd61f2eeba261fca75a670415a12d71d55"},
    "ao-atlas": {"name": "ao-atlas", "version": "v0.2.1", "repository": "https://github.com/uesugitorachiyo/ao-atlas.git", "commit": "3603a2bb8af5adafcd9ff17b807ab89f32283d18", "asset": "ao-atlas.exe", "license": "Apache-2.0", "sha256": "d6d0bf089c8b04359fdd84bc9b825752eb2e4f5655ee6005c8f77a976295e521"},
    "ao-forge": {"name": "ao-forge", "version": "v0.1.5", "repository": "https://github.com/uesugitorachiyo/ao-forge.git", "commit": "d1723769949269dcd0589916d83769dcb7275f98", "asset": "forge.exe", "license": "Apache-2.0", "sha256": "17545288d7c3ad62e0d091e282b363cd5e9c61af533cd3bb6dbaeb90f97aaed7"},
    "ao-covenant": {"name": "ao-covenant", "version": "v0.1.1", "repository": "https://github.com/uesugitorachiyo/ao-covenant.git", "commit": "2fd72a0426a747868826581612fa1dc9727b53b9", "asset": "ao-covenant_v0.1.1_windows_amd64.exe", "license": "Apache-2.0", "sha256": "fd6e3a0033608d3f47dccb60f48191e4c4b2dc4fdce893c87d8ea96199610c5d"},
    "ao2-control-plane": {"name": "ao2-control-plane", "version": "v0.1.19", "repository": "https://github.com/uesugitorachiyo/ao2-control-plane.git", "commit": "5de3541e9007e12d95b125e7f911c02932e21479", "asset": "ao2-cp-server.exe", "license": "Apache-2.0", "sha256": "75c74af686ae6fb28d0566b66b908090567f848ecff1b6c1da4940691d416135"},
    "ao-blueprint": {"name": "ao-blueprint", "version": "git-ec6a80b60b54", "repository": "https://github.com/uesugitorachiyo/ao-blueprint.git", "commit": "ec6a80b60b54c0c0ac1822f873c1abf337fe5eb5", "asset": "ao-blueprint.exe", "license": "Apache-2.0", "sha256": "8f4dd9766e77948e7688b0c80dc8e49ea1cd5fe7ab57be900c651ea2a2f4b4be"},
}
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
    if runtime_version != "v0.5.12" or set(components) != set(_S01_LOCKS):
        raise ValueError("component map must contain exactly the S01 components")
    if len({name.casefold() for name in components}) != len(components):
        raise ValueError("component map has case-insensitive duplicate names")
    if len({str(Path(binary)).casefold() for _, binary in components.values()}) != len(components):
        raise ValueError("component inputs have case-insensitive duplicate paths")
    lock = json.loads(_LOCK_PATH.read_text(encoding="utf-8"))
    entries = lock.get("components") if isinstance(lock, dict) else None
    if not isinstance(entries, list):
        raise ValueError("components lock is malformed")
    locked = {entry.get("name"): entry for entry in entries if isinstance(entry, dict) and isinstance(entry.get("name"), str)}
    if len(locked) != len(entries) or set(locked) != set(_S01_LOCKS):
        raise ValueError("components lock must contain exactly the S01 components")
    paths = []
    for name, (version, binary) in components.items():
        expected = _S01_LOCKS[name]
        expected_version = expected["version"]
        expected_name = expected["asset"]
        expected_hash = expected["sha256"]
        if version != expected_version or Path(binary).name != expected_name:
            raise ValueError("component identity is not bound in S01")
        entry = locked[name]
        if entry != _S01_LOCKS[name]:
            raise ValueError("components lock identity does not match S01")
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
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "preview"
        control_parent = source / Path(_CONTROL_CONTRACT).parent
        shutil.copytree(
            source,
            root,
            ignore=lambda directory, names: (
                [Path(_CONTROL_CONTRACT).name]
                if Path(directory) == control_parent
                and Path(_CONTROL_CONTRACT).name in names
                else []
            ),
        )
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
