from __future__ import annotations

import hashlib
import importlib
import json
import re
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).parents[1]))

from internal.pool import Pool, PoolError
from internal.qualification import Qualification, QualificationError
from internal.readback import protected_record, public_record
from internal.runtime_update import RuntimeUpdate, RuntimeUpdateError
from internal.transactions import read_json
from scripts.verify_requirements import verify_requirements


_BLOCKERS = tuple(f"B{number:02d}" for number in range(1, 20))
_MAX_INSTRUCTION_LINES = 200
_MAX_INSTRUCTION_MARKDOWN_TOKENS = 2000
_MAX_INSTRUCTION_LINE_LENGTH = 100
_LEAF_AUTHORITY = "Authority: inherit-root"
_DESCENDANT_POLICY = "Descendants: narrow-only"
_FORBIDDEN_LEAF_POLICY = (
    "authority: override-root",
    "descendants: may-weaken",
    "ignore root agents",
    "supersede root agents",
)
_SPECIFICATION = Path("docs/superpowers/specs/2026-08-10-ao-office-pool-design.md")
_SURFACE_ROLES = (
    "manifest_builder",
    "builder_tests",
    "contract_verifier",
    "runtime_finalizer",
    "qualification_lifecycle",
)
_MARKDOWN_TOKEN = re.compile(r"(?P<word>\w+)|[^\w\s]")


def _specification(root: Path, *, fallback: bool = False) -> str:
    path = root / _SPECIFICATION
    if fallback and (path.is_symlink() or not path.is_file()):
        path = Path(__file__).parents[1] / _SPECIFICATION
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing approved design")
    return path.read_text(encoding="utf-8")


def _contract_lines(specification: str, name: str) -> tuple[str, ...]:
    marker = f"```{name}\n"
    if specification.count(marker) != 1:
        raise ValueError(f"invalid approved {name}")
    body = specification.split(marker, 1)[1].split("```", 1)[0]
    lines = tuple(line for line in body.splitlines() if line.strip())
    if not lines or len(lines) != len(set(lines)):
        raise ValueError(f"invalid approved {name}")
    return lines


def _markdown_tokens(text: str) -> int:
    count = 0
    for match in _MARKDOWN_TOKEN.finditer(text):
        piece = match.group(0)
        if match.lastgroup == "word":
            count += max(1, (len(piece.encode("utf-8")) + 3) // 4)
        else:
            count += 1
    return count


def _instruction_metrics(path: Path) -> dict[str, int]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"invalid instruction file: {path}")
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    metrics = {
        "lines": len(lines),
        "markdown_tokens": _markdown_tokens(text),
        "max_line": max((len(line) for line in lines), default=0),
    }
    if (
        metrics["lines"] > _MAX_INSTRUCTION_LINES
        or metrics["markdown_tokens"] > _MAX_INSTRUCTION_MARKDOWN_TOKENS
        or metrics["max_line"] > _MAX_INSTRUCTION_LINE_LENGTH
    ):
        raise ValueError(f"unreadable instruction file: {path}")
    return metrics


def verify_instruction_contract(root: Path) -> dict[str, dict[str, int]]:
    if not isinstance(root, Path) or root.is_symlink() or not root.is_dir():
        raise ValueError("invalid repository root")
    root_instruction = root / "AGENTS.md"
    paths = [
        path
        for path in root.rglob("AGENTS.md")
        if ".git" not in path.relative_to(root).parts
        and ".worktrees" not in path.relative_to(root).parts
    ]
    if root_instruction not in paths:
        raise ValueError("missing root AGENTS.md")

    root_contract = _contract_lines(
        _specification(root, fallback=True),
        "root-agent-contract",
    )
    metrics = {}
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix()
        metrics[relative] = _instruction_metrics(path)
        lines = set(path.read_text(encoding="utf-8").splitlines())
        if path == root_instruction:
            if any(required not in lines for required in root_contract):
                raise ValueError("invalid root authority order")
            continue
        text = path.read_text(encoding="utf-8").casefold()
        if (
            _LEAF_AUTHORITY not in lines
            or _DESCENDANT_POLICY not in lines
            or any(policy in text for policy in _FORBIDDEN_LEAF_POLICY)
        ):
            raise ValueError(f"conflicting descendant authority: {relative}")
    return metrics


def _resolve_surface(dotted_name: str):
    try:
        module_name, attribute_name = dotted_name.rsplit(".", 1)
        value = getattr(importlib.import_module(module_name), attribute_name)
        if not callable(value):
            raise ValueError("not callable")
        return value
    except (AttributeError, ImportError, TypeError, ValueError) as error:
        raise ValueError(
            f"release surface is not callable: {dotted_name}"
        ) from error


def _resolve_test(test_id: str):
    try:
        module_name, class_name, method_name = test_id.rsplit(".", 2)
        test_class = getattr(importlib.import_module(module_name), class_name)
        method = getattr(test_class, method_name)
        if not isinstance(test_class, type) or not callable(method):
            raise ValueError("not callable")
        return method
    except (AttributeError, ImportError, TypeError, ValueError) as error:
        raise ValueError(
            f"requirement test is not callable: {test_id}"
        ) from error


def _release_surfaces(specification: str) -> dict[str, str]:
    section_marker = "The executable release contract names these surfaces:\n"
    if specification.count(section_marker) != 1:
        raise ValueError("invalid executable release contract")
    section = specification.split(section_marker, 1)[1].split("\n## ", 1)[0]
    normalized = re.sub(r"\n  ", " ", section)
    matches = re.findall(
        r"^- `([a-z_]+)`: `([A-Za-z0-9_.]+)`(?:\s|$)",
        normalized,
        flags=re.MULTILINE,
    )
    surfaces = dict(matches)
    if tuple(surfaces) != _SURFACE_ROLES or len(matches) != len(surfaces):
        raise ValueError("invalid executable release surfaces")
    return surfaces


def verify_release_contract(root: Path) -> dict:
    verify_instruction_contract(root)
    requirements = verify_requirements(root / "manifests" / "requirements.json")
    blocker_ids = tuple(
        identifier for identifier in requirements if identifier.startswith("B")
    )
    if blocker_ids != _BLOCKERS:
        raise ValueError("requirements must contain exactly B01 through B19 in order")

    test_ids = tuple(
        requirements[identifier].test_id for identifier in blocker_ids
    )
    callable_tests = {test_id: bool(_resolve_test(test_id)) for test_id in test_ids}

    specification = _specification(root)
    surfaces = _release_surfaces(specification)
    for dotted_name in surfaces.values():
        _resolve_surface(dotted_name)

    return {
        "blockers": blocker_ids,
        "test_ids": test_ids,
        "callable_tests": callable_tests,
        "surfaces": surfaces,
    }


def verify_lifecycle_contract(repository_root: Path, pool_root: Path) -> dict:
    try:
        contract = verify_release_contract(repository_root)
        surfaces = contract["surfaces"]
        if (
            _resolve_surface(surfaces["contract_verifier"])
            is not verify_release_contract
        ):
            raise ValueError("contract verifier surface mismatch")

        finalizer_type = _resolve_surface(surfaces["runtime_finalizer"])
        lifecycle_type = _resolve_surface(surfaces["qualification_lifecycle"])
        if finalizer_type is not RuntimeUpdate or lifecycle_type is not Qualification:
            raise ValueError("lifecycle surface mismatch")
        metadata_path = pool_root / "pool.json"

        metadata = read_json(metadata_path)
        runtime_version = metadata["runtime_version"]
        pool = Pool(pool_root, runtime_version=runtime_version)
        status = pool.public_status()
        qualification = Qualification(pool_root)._existing()
        if qualification is None:
            raise ValueError("missing durable qualification")

        finalizer = RuntimeUpdate(pool_root)
        manifest, _, components_raw = finalizer._staged(runtime_version)
        public = public_record(pool_root, status, qualification)
        protected = protected_record(pool_root, status, qualification)
        identities = {
            "runtime_version": runtime_version,
            "runtime_sha256": manifest["sha256"],
            "components_sha256": hashlib.sha256(components_raw).hexdigest(),
            "semantic_fingerprint": qualification["semantic_fingerprint"],
            "qualification_state": qualification["qualification_state"],
            "record_digest": qualification["record_digest"],
        }
        if (
            metadata.get("schema_version") != 1
            or metadata.get("office_count") != 5
            or manifest["version"] != runtime_version
            or qualification["runtime_version"] != runtime_version
            or qualification["runtime_sha256"] != identities["runtime_sha256"]
            or qualification["components_sha256"]
            != identities["components_sha256"]
            or qualification.get("runtime_state") != "activated"
            or public["runtime_version"] != runtime_version
            or public["qualification_state"]
            != identities["qualification_state"]
            or protected["runtime"]
            != {
                "version": runtime_version,
                "sha256": identities["runtime_sha256"],
                "state": "activated",
            }
            or protected["qualification"]
            != {
                "state": identities["qualification_state"],
                "semantic_fingerprint": identities["semantic_fingerprint"],
                "record_digest": identities["record_digest"],
            }
            or public["offices"] != protected["offices"]
        ):
            raise ValueError("lifecycle identity mismatch")
        return {
            "surfaces": {
                role: surfaces[role]
                for role in (
                    "contract_verifier",
                    "runtime_finalizer",
                    "qualification_lifecycle",
                )
            },
            "identities": identities,
        }
    except ValueError:
        raise
    except (
        AttributeError,
        ImportError,
        KeyError,
        OSError,
        PoolError,
        QualificationError,
        RuntimeUpdateError,
        TypeError,
        json.JSONDecodeError,
    ) as error:
        raise ValueError("invalid lifecycle contract") from error


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    root = Path(arguments[0]) if arguments else Path(__file__).parents[1]
    print(json.dumps(verify_release_contract(root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
