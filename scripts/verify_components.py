import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit


_LOCK_FIELDS = {"schema_version", "components"}
_COMPONENT_FIELDS = {"name", "version", "repository", "commit", "asset", "license", "sha256"}
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


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
    if Path(asset).name != asset or asset in {".", ".."}:
        raise ValueError("asset must be a file name")
    root = component_root.resolve()
    path = (root / name / version / asset).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError("asset escapes component root") from error
    return path


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as asset:
        for chunk in iter(lambda: asset.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_lock(path: Path, component_root: Path) -> dict[str, str]:
    components = _load(path)["components"]
    verified = {}
    for component in components:
        if not isinstance(component, dict) or set(component) != _COMPONENT_FIELDS:
            raise ValueError("invalid component fields")
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
    return verified
