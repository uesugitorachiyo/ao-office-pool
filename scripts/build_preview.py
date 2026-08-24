from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from internal.pool import Pool


_MUTABLE_FILES = {"pool.json", ".pool.lock", *(f"offices/O{n}/office-state.json" for n in range(1, 6))}
_MUTABLE_PREFIXES = ("runtime/", "operator-secrets/", "updates/", *(f"offices/O{n}/{part}/" for n in range(1, 6) for part in ("history", "work")))


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


def build_preview(source: Path, ao2: Path, runtime_version: str, output: Path, components: dict[str, tuple[str, Path]] | None = None) -> Path:
    source, ao2, output = Path(source), Path(ao2), Path(output)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "preview"
        shutil.copytree(source, root)
        Pool(root, runtime_version=runtime_version).initialize()
        for office in range(1, 6):
            destination = root / f"offices/O{office}/runtime/versions/{runtime_version}/ao2.exe"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ao2, destination)
        for name, (version, binary) in sorted((components or {}).items()):
            binary = Path(binary)
            destination = root / "components" / name / version / binary.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(binary, destination)
        files = []
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            relative = path.relative_to(root).as_posix()
            if not _mutable(relative):
                data = path.read_bytes()
                files.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
        manifest = {"schema_version": 1, "label": "developer-preview", "architecture": "windows-x86_64", "runtime_version": runtime_version, "files": files}
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as package:
            for path in sorted(p for p in root.rglob("*") if p.is_dir()):
                _directory(package, path.relative_to(root).as_posix())
            for path in sorted(p for p in root.rglob("*") if p.is_file()):
                _write(package, path.relative_to(root).as_posix(), path.read_bytes())
            _write(package, "developer-preview-manifest.json", (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return output
