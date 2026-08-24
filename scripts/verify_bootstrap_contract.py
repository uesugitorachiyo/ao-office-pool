from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


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


def _regular_json(path: Path) -> tuple[dict, bytes]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
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
    return value


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    path = Path(arguments[0]) if arguments else Path(__file__).parents[1] / "manifests" / "developer-preview-release.json"
    print(json.dumps(verify_release_manifest(path), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
