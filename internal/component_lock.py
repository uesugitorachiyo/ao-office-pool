import json
import re
from pathlib import Path


NAMES = frozenset(
    {
        "ao2",
        "ao-mission",
        "ao-command",
        "ao-atlas",
        "ao-forge",
        "ao-covenant",
        "ao2-control-plane",
        "ao-blueprint",
    }
)
FIELDS = frozenset(
    {"name", "version", "repository", "commit", "asset", "license", "sha256"}
)
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")


def load_component_lock(path: Path) -> dict[str, dict]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = (
        value.get("components")
        if isinstance(value, dict)
        and set(value) == {"schema_version", "components"}
        and value.get("schema_version") == 1
        else None
    )
    if not isinstance(rows, list):
        raise ValueError("component lock is malformed")
    result = {}
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != FIELDS
            or any(not isinstance(row[name], str) or not row[name] for name in FIELDS)
            or row["name"] in result
            or row["name"] not in NAMES
            or not row["repository"].startswith(
                "https://github.com/uesugitorachiyo/"
            )
            or not HEX40.fullmatch(row["commit"])
            or not HEX64.fullmatch(row["sha256"])
            or Path(row["asset"]).name != row["asset"]
            or row["asset"] in {".", ".."}
        ):
            raise ValueError("component lock is malformed")
        result[row["name"]] = row
    if set(result) != NAMES:
        raise ValueError("component lock is not the coherent Windows stack")
    return result
