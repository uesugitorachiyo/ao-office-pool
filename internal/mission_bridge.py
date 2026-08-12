import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from internal.transactions import atomic_write_bytes, atomic_write_json
from internal.pool import Pool, PoolError


MISSION_EXECUTABLE = Path(__file__).parents[1] / ".local/bin/ao-mission"
COMPONENT_LOCK = Path(__file__).parents[1] / "manifests/components.lock.json"
MAX_OUTPUT = 64 * 1024
_AUTHORITY_FLAGS = (
    "executes_work",
    "approves_policy",
    "calls_providers",
    "publishes",
    "deploys",
    "mutates_repositories",
)


class MissionBridgeError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class MissionReadback:
    mission_id: str
    objective_digest: str
    status: str
    current_route: str
    record: Path
    resumed: bool
    executes_work: bool = False
    approves_policy: bool = False
    calls_providers: bool = False
    publishes: bool = False
    deploys: bool = False
    mutates_repositories: bool = False


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _authority(receipt: Path, objective: str) -> tuple[dict, bytes, Path]:
    if not isinstance(receipt, Path) or not isinstance(objective, str) or not objective:
        raise MissionBridgeError("invalid-request")
    try:
        pool = Pool(receipt.parents[2])
        pool.resume(receipt)
        raw = receipt.read_bytes()
        authority = json.loads(raw)
        project = Path(authority["project_path"])
    except (OSError, IndexError, KeyError, PoolError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise MissionBridgeError("unauthorized") from error
    if authority.get("task_digest") != _digest(objective.encode("utf-8")):
        raise MissionBridgeError("task-mismatch")
    return authority, raw, project


def _verify_executable() -> None:
    try:
        lock = json.loads(COMPONENT_LOCK.read_text(encoding="utf-8"))
        component = next(
            item for item in lock["components"] if item.get("name") == "ao-mission"
        )
        if component["asset"] != MISSION_EXECUTABLE.name:
            raise ValueError("wrong asset")
        expected = component["sha256"]
        actual = _digest(MISSION_EXECUTABLE.read_bytes())
        if actual != expected or not MISSION_EXECUTABLE.is_file():
            raise ValueError("digest mismatch")
    except (OSError, KeyError, StopIteration, TypeError, ValueError, json.JSONDecodeError) as error:
        raise MissionBridgeError("mission-identity-mismatch") from error


def _run(arguments: list[str]) -> dict:
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            result = subprocess.run(
                [str(MISSION_EXECUTABLE), *arguments],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=30,
                check=False,
            )
            if stdout.tell() > MAX_OUTPUT or stderr.tell() > MAX_OUTPUT:
                raise MissionBridgeError("mission-output-too-large")
            stdout.seek(0)
            output = stdout.read(MAX_OUTPUT + 1)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MissionBridgeError("mission-launch-failed") from error
    if result.returncode:
        raise MissionBridgeError("mission-launch-failed")
    try:
        value = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MissionBridgeError("invalid-mission-readback") from error
    if not isinstance(value, dict):
        raise MissionBridgeError("invalid-mission-readback")
    if any(value.get(field) is not None and value.get(field) is not False for field in _AUTHORITY_FLAGS):
        raise MissionBridgeError("mission-authority-escalation")
    required = {"mission_id", "objective_digest", "status", "current_route"}
    if not required <= value.keys() or any(not isinstance(value[field], str) for field in required):
        raise MissionBridgeError("invalid-mission-readback")
    return value


def _record_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def start_or_resume(receipt: Path, objective: str) -> MissionReadback:
    authority, authority_raw, project = _authority(receipt, objective)
    _verify_executable()
    mission_root = project / ".ao/mission"
    record_root = mission_root / "office-pool"
    record = record_root / f"{authority['task_digest']}.json"
    seal = record.with_suffix(".sha256")
    resumed = record.exists() or seal.exists()
    if resumed:
        try:
            raw = record.read_bytes()
            wrapper = json.loads(raw)
            if seal.read_text(encoding="ascii") != _digest(raw) + "\n":
                raise ValueError("bad seal")
            expected = {
                "schema_version": 1,
                "mission_id": wrapper["mission_id"],
                "objective_digest": "sha256:" + authority["task_digest"],
                "authority_digest": _digest(authority_raw),
                "office_id": authority["office_id"],
                "generation": authority["generation"],
                "project_path": authority["project_path"],
            }
            if wrapper != expected:
                raise ValueError("record mismatch")
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise MissionBridgeError("mission-record-mismatch") from error
        readback = _run(
            [
                "--home",
                str(mission_root),
                "mission",
                "inspect",
                "--mission",
                wrapper["mission_id"],
                "--json",
            ]
        )
    else:
        readback = _run(["--home", str(mission_root), "start", objective])
        wrapper = {
            "schema_version": 1,
            "mission_id": readback["mission_id"],
            "objective_digest": "sha256:" + authority["task_digest"],
            "authority_digest": _digest(authority_raw),
            "office_id": authority["office_id"],
            "generation": authority["generation"],
            "project_path": authority["project_path"],
        }
        if readback["objective_digest"] != wrapper["objective_digest"]:
            raise MissionBridgeError("mission-record-mismatch")
        atomic_write_json(record, wrapper)
        atomic_write_bytes(seal, (_digest(record.read_bytes()) + "\n").encode("ascii"))
    if readback["objective_digest"] != "sha256:" + authority["task_digest"]:
        raise MissionBridgeError("mission-record-mismatch")
    return MissionReadback(
        mission_id=readback["mission_id"],
        objective_digest=readback["objective_digest"],
        status=readback["status"],
        current_route=readback["current_route"],
        record=record,
        resumed=resumed,
    )
