import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit


_LOCK_FIELDS = {"schema_version", "components"}
_COMPONENT_FIELDS = {"name", "version", "repository", "commit", "asset", "license", "sha256"}
_EXPECTED_COMPONENTS = {
    "ao2", "ao-mission", "ao-command", "ao-atlas", "ao-forge", "ao-covenant",
    "ao2-control-plane", "ao-blueprint",
}
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


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


def _load(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as lock_file:
            data = json.load(lock_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid component lock: {path}") from error
    if not isinstance(data, dict) or set(data) != _LOCK_FIELDS or data["schema_version"] != 1:
        raise ValueError("invalid component lock fields")
    if not isinstance(data["components"], list) or not data["components"]:
        raise ValueError("components must be a nonempty list")
    return data


def _asset_path(component: dict[str, str], component_root: Path) -> Path:
    name, version, asset = (component[key] for key in ("name", "version", "asset"))
    if any(not isinstance(value, str) or not value for value in (name, version, asset)):
        raise ValueError("component path fields must be nonempty strings")
    if any("/" in value or "\\" in value or value in {".", ".."} for value in (name, version)):
        raise ValueError("component name and version must be path segments")
    if "/" in asset or "\\" in asset or Path(asset).name != asset or asset in {".", ".."}:
        raise ValueError("asset must be a file name")
    if _reparse_or_link(component_root) or not component_root.is_dir():
        raise ValueError("component root contains a reparse point or link")
    root = component_root.resolve()
    candidate = root / name / version / asset
    if _reparse_or_link(candidate):
        raise ValueError("component input contains a reparse point or link")
    path = candidate.resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError("asset escapes component root") from error
    return path


def _digest(path: Path) -> str:
    if _reparse_or_link(path):
        raise ValueError("component input contains a reparse point or link")
    digest = hashlib.sha256()
    with path.open("rb") as asset:
        for chunk in iter(lambda: asset.read(1024 * 1024), b""):
            digest.update(chunk)
    if _reparse_or_link(path):
        raise ValueError("component input contains a reparse point or link")
    return digest.hexdigest()


def verify_lock(path: Path, component_root: Path) -> dict[str, str]:
    components = _load(path)["components"]
    verified = {}
    for component in components:
        if not isinstance(component, dict) or set(component) != _COMPONENT_FIELDS:
            raise ValueError("invalid component fields")
        if any(not isinstance(value, str) or not value.strip() for value in component.values()):
            raise ValueError("component fields must be nonblank strings")
        if component["name"] in verified:
            raise ValueError("duplicate component name")
        if not _COMMIT.fullmatch(component["commit"]) or not _SHA256.fullmatch(component["sha256"]):
            raise ValueError("invalid component digest")
        repository = urlsplit(component["repository"])
        if repository.scheme != "https" or not repository.hostname or repository.username or repository.password:
            raise ValueError("repository must be an anonymous HTTPS URL")
        if not isinstance(component["license"], str) or not component["license"]:
            raise ValueError("license must be a nonempty string")
        asset = _asset_path(component, component_root)
        if not asset.is_file() or _digest(asset) != component["sha256"]:
            raise ValueError("asset digest does not match lock")
        verified[component["name"]] = component["sha256"]
    if set(verified) != _EXPECTED_COMPONENTS:
        raise ValueError("components must contain the exact expected name set")
    return verified
