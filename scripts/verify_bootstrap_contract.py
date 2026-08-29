from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote


REPOSITORY = "uesugitorachiyo/ao-office-pool"
ASSET_NAMES = (
    "candidate-manifest.json",
    "ao-office-pool-developer-preview.zip",
    "ao-office-pool-developer-preview.zip.sha256",
    "member-inventory.json",
    "provenance.json",
    "RELEASE-NOTES.md",
    "SBOM.json",
    "SHA256SUMS",
)
ROOT_FIELDS = {
    "schema_version",
    "repository",
    "visibility",
    "tag",
    "product_source_commit",
    "architecture",
    "asset_names",
    "candidate_manifest",
}
IDENTITY_FIELDS = {"name", "size", "sha256"}
MANIFEST_FIELDS = {
    "schema_version",
    "candidate_id",
    "label",
    "architecture",
    "source",
    "component_lock_sha256",
    "archive",
    "components",
    "metadata",
    "installer",
    "immutable",
    "authority",
}
HEX_40 = re.compile(r"[0-9a-f]{40}")
HEX_64 = re.compile(r"[0-9a-f]{64}")
TAG = re.compile(r"developer-preview-v[0-9]{2}")
ABSOLUTE_PATH = re.compile(r"[A-Za-z]:\\|/[U]sers/|/[V]olumes/|/[h]ome/")
MARKDOWN_LINK = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")
BOOTSTRAP_DOCUMENTS = (
    "README.md",
    "README-FIRST.md",
    "docs/QUICKSTART.md",
    "docs/AI_OPERATOR_RUNBOOK.md",
    "docs/OPERATOR_GUIDE.md",
)
BOOTSTRAP_MEMBERS = (
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
)
COMPONENT_FIELDS = {"name", "version", "repository", "commit", "asset", "license", "sha256"}
INSTALLER = {
    "acquire": "packaging/Get-AOOfficePoolRelease.ps1",
    "ai_runbook": "docs/AI_OPERATOR_RUNBOOK.md",
    "install": "packaging/Install-AOOfficePool.ps1",
    "read_first": "README-FIRST.md",
    "uninstall": "packaging/Uninstall-AOOfficePool.ps1",
    "verify": "packaging/Verify-AOOfficePool.ps1",
}
COMPONENT_LOCK = Path(__file__).parents[1] / "manifests" / "components.lock.json"


def _regular_json(path: Path) -> tuple[dict, bytes]:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat(follow_symlinks=False).st_nlink != 1:
        raise ValueError("contract must be a regular file")
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("contract is not canonical JSON") from error
    if not isinstance(value, dict):
        raise ValueError("contract must be an object")
    return value, raw


def _identity(value: object, expected_name: str) -> dict:
    if not isinstance(value, dict) or set(value) != IDENTITY_FIELDS:
        raise ValueError("invalid candidate manifest identity")
    name, size, digest = value.get("name"), value.get("size"), value.get("sha256")
    if (
        name != expected_name
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size < 1
        or not isinstance(digest, str)
        or HEX_64.fullmatch(digest) is None
    ):
        raise ValueError("invalid candidate manifest identity")
    return {"name": name, "size": size, "sha256": digest}


def verify_release_manifest(path: Path) -> dict:
    value, _ = _regular_json(path)
    names = value.get("asset_names")
    if (
        set(value) != ROOT_FIELDS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("repository") != REPOSITORY
        or value.get("visibility") != "private"
        or value.get("architecture") != "windows-x86_64"
        or not isinstance(value.get("tag"), str)
        or TAG.fullmatch(value["tag"]) is None
        or not isinstance(value.get("product_source_commit"), str)
        or HEX_40.fullmatch(value["product_source_commit"]) is None
        or not isinstance(names, list)
        or tuple(names) != ASSET_NAMES
        or len({name.casefold() for name in names if isinstance(name, str)})
        != len(ASSET_NAMES)
    ):
        raise ValueError("invalid private release contract")
    normalized = dict(value)
    normalized["asset_names"] = list(ASSET_NAMES)
    normalized["candidate_manifest"] = _identity(
        value.get("candidate_manifest"), "candidate-manifest.json"
    )
    return normalized


def verify_candidate_manifest(path: Path, release: dict) -> dict:
    value, raw = _regular_json(path)
    identity = release["candidate_manifest"]
    if (
        len(raw) != identity["size"]
        or hashlib.sha256(raw).hexdigest() != identity["sha256"]
        or set(value) != MANIFEST_FIELDS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("architecture") != release["architecture"]
        or value.get("immutable") is not True
    ):
        raise ValueError("candidate manifest identity mismatch")
    source = value.get("source")
    metadata = value.get("metadata")
    if (
        not isinstance(source, dict)
        or set(source) != {"commit", "clean"}
        or source.get("commit") != release["product_source_commit"]
        or source.get("clean") is not True
        or not isinstance(metadata, list)
    ):
        raise ValueError("candidate manifest contract mismatch")
    rows = []
    for row in metadata:
        if not isinstance(row, dict) or set(row) != IDENTITY_FIELDS:
            raise ValueError("candidate metadata row is invalid")
        rows.append(_identity(row, row.get("name")))
    names = [identity["name"], *(row["name"] for row in rows)]
    if tuple(names) != tuple(release["asset_names"]):
        raise ValueError("candidate asset set is invalid")
    archive = _identity(value.get("archive"), ASSET_NAMES[1])
    if archive != rows[0]:
        raise ValueError("candidate archive identity is not metadata-bound")
    try:
        lock_raw = COMPONENT_LOCK.read_bytes()
        lock = json.loads(lock_raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("component lock is unavailable") from error
    locked_components = lock.get("components") if isinstance(lock, dict) else None
    components = value.get("components")
    if (
        not isinstance(locked_components, list)
        or len(locked_components) != 8
        or any(not isinstance(row, dict) or set(row) != COMPONENT_FIELDS for row in locked_components)
        or components != locked_components
        or value.get("component_lock_sha256") != hashlib.sha256(lock_raw).hexdigest()
    ):
        raise ValueError("candidate components are not lock-bound")
    expected_id = f"windows-ai-bootstrap-{release['tag'].removeprefix('developer-preview-')}-{release['product_source_commit'][:7]}"
    if value.get("candidate_id") != expected_id or value.get("label") != "developer-preview":
        raise ValueError("candidate identity is invalid")
    if value.get("installer") != INSTALLER:
        raise ValueError("candidate installer contract is invalid")
    authority = value.get("authority")
    if (
        not isinstance(authority, dict)
        or set(authority) != {"publication_authorized", "release_visibility", "tag_target"}
        or authority.get("publication_authorized") is not False
        or authority.get("release_visibility") != "private"
        or authority.get("tag_target") != release["product_source_commit"]
    ):
        raise ValueError("candidate authority contract is invalid")
    return value


def verify_asset_directory(root: Path, contract: Path) -> list[dict]:
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("asset directory must be a regular directory")
    entries = list(root.iterdir())
    if (
        len(entries) != len(ASSET_NAMES)
        or {entry.name for entry in entries} != set(ASSET_NAMES)
        or any(entry.is_symlink() or not entry.is_file() or entry.stat(follow_symlinks=False).st_nlink != 1 for entry in entries)
    ):
        raise ValueError("asset directory does not contain the closed set")
    release = verify_release_manifest(contract)
    candidate = verify_candidate_manifest(root / ASSET_NAMES[0], release)
    identities = [release["candidate_manifest"], *candidate["metadata"]]
    verified = []
    for identity in identities:
        path = root / identity["name"]
        raw = path.read_bytes()
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat(follow_symlinks=False).st_nlink != 1
            or len(raw) != identity["size"]
            or hashlib.sha256(raw).hexdigest() != identity["sha256"]
        ):
            raise ValueError(f"asset identity mismatch: {identity['name']}")
        verified.append(dict(identity))
    return verified


def verify_bootstrap_tree(root: Path) -> dict:
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("bootstrap root must be a regular directory")
    resolved_root = root.resolve()
    for relative in BOOTSTRAP_MEMBERS:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("bootstrap tree is incomplete")
    verify_release_manifest(root / "manifests/developer-preview-release.json")
    for relative in BOOTSTRAP_DOCUMENTS:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        if ABSOLUTE_PATH.search(text):
            raise ValueError("bootstrap documentation contains an absolute path")
        for raw_target in MARKDOWN_LINK.findall(text):
            target = raw_target.strip().strip("<>").split("#", 1)[0]
            if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
                continue
            resolved = (path.parent / unquote(target)).resolve()
            try:
                resolved.relative_to(resolved_root)
            except ValueError as error:
                raise ValueError("bootstrap documentation link escapes the tree") from error
            if not resolved.exists():
                raise ValueError("bootstrap documentation link is broken")
    return {
        "schema_version": 1,
        "bootstrap_members": len(BOOTSTRAP_MEMBERS),
        "documents": len(BOOTSTRAP_DOCUMENTS),
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    path = Path(arguments[0]) if arguments else Path(__file__).parents[1] / "manifests" / "developer-preview-release.json"
    result = verify_bootstrap_tree(path) if path.is_dir() else verify_release_manifest(path)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
