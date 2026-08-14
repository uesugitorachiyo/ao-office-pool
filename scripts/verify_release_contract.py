from __future__ import annotations

import importlib
import json
import re
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).parents[1]))

from scripts.verify_requirements import verify_requirements


_BLOCKERS = tuple(f"B{number:02d}" for number in range(1, 20))
_MAX_INSTRUCTION_LINES = 200
_MAX_INSTRUCTION_WORDS = 2000
_MAX_INSTRUCTION_LINE_LENGTH = 100
_ROOT_AUTHORITY = "Authority: platform-and-user > root-AGENTS > descendant-AGENTS"
_LEAF_AUTHORITY = "Authority: inherit-root"
_DESCENDANT_POLICY = "Descendants: narrow-only"
_FORBIDDEN_LEAF_POLICY = (
    "authority: override-root",
    "descendants: may-weaken",
    "ignore root agents",
    "supersede root agents",
)
_SPECIFICATION = Path("docs/superpowers/specs/2026-08-10-ao-office-pool-design.md")
_SURFACES = {
    "manifest_builder": "scripts.build_release.build_release",
    "builder_tests": "tests.test_release_tree.BuildReleaseTests",
    "contract_verifier": "scripts.verify_release_contract.verify_release_contract",
    "runtime_finalizer": "internal.runtime_update.RuntimeUpdate",
    "qualification_lifecycle": "internal.qualification.Qualification",
}


def _instruction_metrics(path: Path) -> dict[str, int]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"invalid instruction file: {path}")
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    metrics = {
        "lines": len(lines),
        "words": len(re.findall(r"\S+", text)),
        "max_line": max((len(line) for line in lines), default=0),
    }
    if (
        metrics["lines"] > _MAX_INSTRUCTION_LINES
        or metrics["words"] > _MAX_INSTRUCTION_WORDS
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

    metrics = {}
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix()
        metrics[relative] = _instruction_metrics(path)
        lines = set(path.read_text(encoding="utf-8").splitlines())
        if path == root_instruction:
            if _ROOT_AUTHORITY not in lines or _DESCENDANT_POLICY not in lines:
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
    module_name, attribute_name = dotted_name.rsplit(".", 1)
    value = getattr(importlib.import_module(module_name), attribute_name)
    if not callable(value):
        raise ValueError(f"release surface is not callable: {dotted_name}")
    return value


def _resolve_test(test_id: str):
    module_name, class_name, method_name = test_id.rsplit(".", 2)
    test_class = getattr(importlib.import_module(module_name), class_name)
    method = getattr(test_class, method_name)
    if not isinstance(test_class, type) or not callable(method):
        raise ValueError(f"requirement test is not callable: {test_id}")
    return method


def verify_release_contract(root: Path) -> dict:
    verify_instruction_contract(root)
    requirements = verify_requirements(root / "manifests" / "requirements.json")
    blocker_ids = tuple(identifier for identifier in requirements if identifier.startswith("B"))
    if blocker_ids != _BLOCKERS:
        raise ValueError("requirements must contain exactly B01 through B19 in order")

    test_ids = tuple(requirements[identifier].test_id for identifier in blocker_ids)
    callable_tests = {test_id: bool(_resolve_test(test_id)) for test_id in test_ids}

    specification = (root / _SPECIFICATION).read_text(encoding="utf-8")
    for dotted_name in _SURFACES.values():
        if f"`{dotted_name}`" not in specification:
            raise ValueError(f"specification omits release surface: {dotted_name}")
        _resolve_surface(dotted_name)

    return {
        "blockers": blocker_ids,
        "test_ids": test_ids,
        "callable_tests": callable_tests,
        "surfaces": dict(_SURFACES),
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    root = Path(arguments[0]) if arguments else Path(__file__).parents[1]
    print(json.dumps(verify_release_contract(root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
