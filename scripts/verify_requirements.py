import json
from dataclasses import dataclass
from pathlib import Path


_DOCUMENT_FIELDS = {"schema_version", "requirements"}
_REQUIREMENT_FIELDS = {"id", "description", "test_id", "release_phase"}
_EXPECTED_IDS = {*(f"V11-{number:02d}" for number in range(1, 13)), *(f"B{number:02d}" for number in range(1, 20))}
_PHASES = {f"month-{number}" for number in range(1, 7)}


@dataclass(frozen=True)
class Requirement:
    id: str
    description: str
    test_id: str
    release_phase: str


def verify_requirements(path: Path) -> dict[str, Requirement]:
    try:
        with path.open(encoding="utf-8") as requirements_file:
            data = json.load(requirements_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid requirements manifest: {path}") from error
    if not isinstance(data, dict) or set(data) != _DOCUMENT_FIELDS or data["schema_version"] != 1:
        raise ValueError("invalid requirements manifest fields")
    rows = data["requirements"]
    if not isinstance(rows, list):
        raise ValueError("requirements must be a list")

    requirements = {}
    test_ids = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != _REQUIREMENT_FIELDS:
            raise ValueError("invalid requirement fields")
        if any(not isinstance(row[field], str) or not row[field].strip() for field in _REQUIREMENT_FIELDS):
            raise ValueError("requirement fields must be nonempty strings")
        if row["id"] in requirements or row["test_id"] in test_ids:
            raise ValueError("requirement and test ids must be unique")
        if row["release_phase"] not in _PHASES:
            raise ValueError("invalid release phase")
        requirements[row["id"]] = Requirement(**row)
        test_ids.add(row["test_id"])
    if set(requirements) != _EXPECTED_IDS:
        raise ValueError("requirements must contain the exact inherited id set")
    return requirements
