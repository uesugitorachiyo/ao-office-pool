import ast
import hashlib
import hmac
import json
import os
import stat
from pathlib import Path

from internal.mission_bridge import _validate_schema
from internal.pool import AUTHORITY_FIELDS, OFFICE_IDS, Pool, PoolError
from internal.transactions import atomic_write_json, read_json
from scripts.verify_requirements import verify_requirements


_ROOT = Path(__file__).parents[1]
_RUNTIME_SCHEMA = _ROOT / "schemas/runtime-package.schema.json"
_MISSION_SCHEMA = _ROOT / "schemas/mission-record.schema.json"
_GOVERNANCE_SCHEMA = _ROOT / "schemas/governance-envelope.schema.json"
_EXECUTION_SCHEMA = _ROOT / "schemas/execution-record.schema.json"
_QUALIFICATION_SCHEMA = _ROOT / "schemas/qualification-record.schema.json"
_AUTHORITATIVE_REQUIREMENTS = _ROOT / "manifests/requirements.json"
_INPUTS = (
    "runtime-package.json",
    "components.lock.json",
    "claim-receipt.json",
    "mission-record.json",
    "governance-envelope.json",
    "execution-record.json",
    "requirements.json",
    "critical-matrix.json",
)
_STATES = ("candidate", "pilot-qualified", "release-qualified")
_MAX_INPUT = 64 * 1024 * 1024


class QualificationError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest_value(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _strict_object(raw: bytes) -> dict:
    def unique(pairs):
        value = {}
        for name, member in pairs:
            if name in value:
                raise ValueError("duplicate JSON field")
            value[name] = member
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def _read_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _MAX_INPUT:
            raise ValueError("unsafe evidence member")
        chunks = []
        remaining = _MAX_INPUT + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        stable = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) > _MAX_INPUT or any(getattr(before, name) != getattr(after, name) for name in stable):
            raise ValueError("evidence member changed")
        return raw
    finally:
        os.close(descriptor)


def _test_exists(test_id: str) -> bool:
    parts = test_id.split(".")
    if len(parts) != 4 or parts[0] != "tests" or not all(part.isidentifier() for part in parts):
        return False
    path = _ROOT / "tests" / f"{parts[1]}.py"
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeError):
        return False
    return any(
        isinstance(node, ast.ClassDef)
        and node.name == parts[2]
        and any(isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and member.name == parts[3] for member in node.body)
        for node in tree.body
    )


class Qualification:
    def __init__(self, root: Path):
        if not isinstance(root, Path):
            raise TypeError("root must be a pathlib.Path")
        self.root = root.resolve(strict=False)

    @property
    def _record_path(self) -> Path:
        return self.root / "updates" / "qualification.json"

    def _pool(self) -> Pool:
        try:
            metadata = read_json(self.root / "pool.json")
            return Pool(self.root, runtime_version=metadata["runtime_version"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise QualificationError("qualification-not-initialized") from error

    def _evidence(self, evidence_set: Path) -> tuple[dict[str, dict], dict[str, bytes], str]:
        try:
            if not isinstance(evidence_set, Path) or evidence_set.is_symlink():
                raise ValueError("unsafe evidence root")
            root = evidence_set.resolve(strict=True)
            expected = {*_INPUTS, "semantic-inputs.json"}
            members = {path.name for path in root.iterdir()}
            if not root.is_dir() or members != expected:
                raise QualificationError("qualification-evidence-set-mismatch")
            raw = {name: _read_regular(root / name) for name in expected}
            values = {name: _strict_object(member) for name, member in raw.items()}
            semantic = values["semantic-inputs.json"]
            if set(semantic) != {"schema_version", "inputs"} or semantic["schema_version"] != 1 or not isinstance(semantic["inputs"], list):
                raise ValueError("invalid semantic manifest")
            supplied = {}
            for item in semantic["inputs"]:
                if (
                    not isinstance(item, dict)
                    or set(item) != {"name", "sha256"}
                    or item["name"] in supplied
                    or item["name"] not in _INPUTS
                    or not isinstance(item["sha256"], str)
                    or len(item["sha256"]) != 64
                ):
                    raise ValueError("invalid semantic input")
                supplied[item["name"]] = item["sha256"]
            actual = {name: hashlib.sha256(raw[name]).hexdigest() for name in _INPUTS}
            if supplied != actual:
                raise QualificationError("qualification-fingerprint-mismatch")
            fingerprint = _digest_value([{"name": name, "sha256": actual[name]} for name in sorted(actual)])
            return values, raw, fingerprint
        except QualificationError:
            raise
        except (OSError, KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
            raise QualificationError("qualification-evidence-set-mismatch") from error

    @staticmethod
    def _component(runtime: dict, components: dict) -> None:
        if (
            set(components) != {"schema_version", "components"}
            or components["schema_version"] != 1
            or not isinstance(components["components"], list)
            or any(not isinstance(row, dict) for row in components["components"])
        ):
            raise QualificationError("qualification-identity-mismatch")
        matches = [row for row in components["components"] if isinstance(row, dict) and row.get("name") == "ao2"]
        if len(matches) != 1:
            raise QualificationError("qualification-identity-mismatch")
        component = matches[0]
        try:
            expected = {name: component[name] for name in ("name", "version", "commit", "asset", "sha256")}
        except KeyError as error:
            raise QualificationError("qualification-identity-mismatch") from error
        if runtime != {"schema_version": 1, **expected}:
            raise QualificationError("qualification-identity-mismatch")

    def _installed_component(self, components: dict) -> None:
        try:
            installed = _strict_object(
                _read_regular(self.root / "manifests" / "components.lock.json")
            )
            if (
                set(installed) != {"schema_version", "components"}
                or installed["schema_version"] != 1
                or not isinstance(installed["components"], list)
                or any(not isinstance(row, dict) for row in installed["components"])
            ):
                raise ValueError("invalid installed component lock")
            evidence = [row for row in components["components"] if row.get("name") == "ao2"]
            anchored = [row for row in installed["components"] if row.get("name") == "ao2"]
            if len(evidence) != 1 or anchored != evidence:
                raise ValueError("installed AO2 identity mismatch")
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise QualificationError("qualification-identity-mismatch") from error

    @staticmethod
    def _matrix(requirements_path: Path, matrix: dict) -> list[dict]:
        try:
            evidence_requirements = verify_requirements(requirements_path)
            blocker_ids = [f"B{number:02d}" for number in range(1, 20)]
            expected = [
                {"requirement_id": identifier, "test_id": evidence_requirements[identifier].test_id}
                for identifier in blocker_ids
            ]
            if any(not _test_exists(row["test_id"]) for row in expected):
                raise QualificationError("qualification-test-binding-mismatch")
            if matrix != {"schema_version": 1, "assertions": expected}:
                raise QualificationError("qualification-critical-matrix-mismatch")
            authoritative = verify_requirements(_AUTHORITATIVE_REQUIREMENTS)
            if any(evidence_requirements[identifier] != authoritative[identifier] for identifier in blocker_ids):
                raise QualificationError("qualification-critical-matrix-mismatch")
            return expected
        except QualificationError:
            raise
        except (KeyError, TypeError, ValueError) as error:
            raise QualificationError("qualification-critical-matrix-mismatch") from error

    @staticmethod
    def _identity(values: dict[str, dict], raw: dict[str, bytes], pool: Pool) -> None:
        runtime = values["runtime-package.json"]
        authority = values["claim-receipt.json"]
        mission = values["mission-record.json"]
        governance = values["governance-envelope.json"]
        execution = values["execution-record.json"]
        requirements = values["requirements.json"]
        try:
            _validate_schema(runtime, _RUNTIME_SCHEMA)
            _validate_schema(mission, _MISSION_SCHEMA)
            _validate_schema(governance, _GOVERNANCE_SCHEMA)
            _validate_schema(execution, _EXECUTION_SCHEMA)
            if set(authority) != AUTHORITY_FIELDS or authority["schema_version"] != 1:
                raise ValueError("invalid authority")
            authority_digest = hashlib.sha256(raw["claim-receipt.json"]).hexdigest()
            pool._validate_project_record(authority)
            project = {
                "project_path": authority["project_path"],
                "project_volume": authority["project_volume"],
                "project_file_id": authority["project_file_id"],
            }
            mission_expected = {
                "authority_digest": authority_digest,
                "chat_digest": authority["holder_digest"],
                "task_digest": authority["task_digest"],
                "office_id": authority["office_id"],
                "generation": authority["generation"],
                "project_path": authority["project_path"],
                "objective_digest": "sha256:" + authority["task_digest"],
            }
            if any(mission.get(name) != member for name, member in mission_expected.items()):
                raise ValueError("mission identity mismatch")
            governance_expected = {
                "authority_digest": authority_digest,
                "office_id": authority["office_id"],
                "generation": authority["generation"],
                "runtime_version": runtime["version"],
                **project,
                "task_digest": authority["task_digest"],
            }
            if any(governance.get(name) != member for name, member in governance_expected.items()):
                raise ValueError("governance authority mismatch")
            if governance["mission"] != {
                "mission_id": mission["mission_id"],
                "objective_digest": mission["objective_digest"],
                "status": mission["mission_status"],
                "current_route": mission["current_route"],
            }:
                raise ValueError("governance mission mismatch")
            payload = {name: member for name, member in governance.items() if name != "payload_digest"}
            if not hmac.compare_digest(governance["payload_digest"], _digest_value(payload)):
                raise ValueError("governance digest mismatch")
            blocker_rows = [row for row in requirements["requirements"] if row["id"].startswith("B")]
            bindings = {row["id"]: row["test_id"] for row in blocker_rows}
            requirement_evidence = {
                "requirements_sha256": hashlib.sha256(raw["requirements.json"]).hexdigest(),
                "test_bindings_sha256": _digest_value(bindings),
                "requirement_ids": [f"B{number:02d}" for number in range(1, 20)],
            }
            if governance["requirements_evidence_digest"] != _digest_value(requirement_evidence):
                raise ValueError("requirements evidence mismatch")
            request = {
                "authority_digest": governance["authority_digest"],
                "mission_id": governance["mission"]["mission_id"],
                "route_digest": governance["route"]["decision_digest"],
                "target": governance["target"],
                "workflow_digest": governance["workflow_digest"],
                "run_id": governance["run_id"],
                "producer_artifacts": governance["producer_artifacts"],
                "requirements_evidence_digest": governance["requirements_evidence_digest"],
                "ao2": governance["ao2"],
            }
            if governance["request_digest"] != _digest_value(request):
                raise ValueError("governance request mismatch")
            execution_payload = {name: member for name, member in execution.items() if name != "record_digest"}
            if execution["record_digest"] != _digest_value(execution_payload):
                raise ValueError("execution digest mismatch")
            execution_expected = {
                "request_digest": governance["request_digest"],
                "mission_id": mission["mission_id"],
                "objective_digest": mission["objective_digest"],
                "route_digest": governance["route"]["decision_digest"],
                "authority_digest": authority_digest,
                "office_id": authority["office_id"],
                "generation": authority["generation"],
                "project_path": authority["project_path"],
                "target_path": authority["project_path"],
                "workflow_sha256": governance["workflow_digest"],
                "run_id": governance["run_id"],
                "blueprint_digest": governance["producer_artifacts"]["ao-blueprint"]["artifact_sha256"],
                "atlas_digest": governance["producer_artifacts"]["ao-atlas"]["artifact_sha256"],
                "forge_digest": governance["producer_artifacts"]["ao-forge"]["artifact_sha256"],
                "covenant_digest": governance["producer_artifacts"]["ao-covenant"]["artifact_sha256"],
                "ao2_sha256": runtime["sha256"],
            }
            if any(execution.get(name) != member for name, member in execution_expected.items()):
                raise ValueError("execution identity mismatch")
            if governance["ao2"] != {
                "name": "ao2", "commit": runtime["commit"], "asset": runtime["asset"], "sha256": runtime["sha256"]
            }:
                raise ValueError("runtime governance mismatch")
            metadata = pool._ensure_initialized()
            if metadata["runtime_version"] != runtime["version"]:
                raise ValueError("inactive runtime")
            executable = "ao2.exe" if os.name == "nt" else "ao2"
            for office_id in OFFICE_IDS:
                candidate = pool.root / "offices" / office_id / "runtime" / "versions" / runtime["version"] / executable
                if hashlib.sha256(_read_regular(candidate)).hexdigest() != runtime["sha256"]:
                    raise ValueError("runtime copy mismatch")
        except QualificationError:
            raise
        except (OSError, KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError, PoolError) as error:
            raise QualificationError("qualification-identity-mismatch") from error

    def _existing(self) -> dict | None:
        if not self._record_path.exists():
            return None
        try:
            value = read_json(self._record_path)
            _validate_schema(value, _QUALIFICATION_SCHEMA)
            digest = value["record_digest"]
            if digest != _digest_value({name: member for name, member in value.items() if name != "record_digest"}):
                raise ValueError("qualification digest mismatch")
            return value
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise QualificationError("qualification-record-invalid") from error

    def promote(self, evidence_set: Path, state: str) -> Path:
        if state not in _STATES:
            raise QualificationError("qualification-state-invalid")
        values, raw, fingerprint = self._evidence(evidence_set)
        self._component(values["runtime-package.json"], values["components.lock.json"])
        self._installed_component(values["components.lock.json"])
        matrix = self._matrix(evidence_set / "requirements.json", values["critical-matrix.json"])
        pool = self._pool()
        try:
            with pool._locked():
                pool._ensure_initialized()
                self._identity(values, raw, pool)
                existing = self._existing()
                if existing is not None:
                    current = existing["qualification_state"]
                    if existing["semantic_fingerprint"] != fingerprint:
                        raise QualificationError("qualification-evidence-changed")
                    if state == current:
                        return self._record_path
                    if _STATES.index(state) != _STATES.index(current) + 1:
                        raise QualificationError("qualification-transition-invalid")
                elif state != "candidate":
                    raise QualificationError("qualification-transition-invalid")
                runtime = values["runtime-package.json"]
                authority = values["claim-receipt.json"]
                record = {
                    "schema_version": 1,
                    "runtime_version": runtime["version"],
                    "runtime_sha256": runtime["sha256"],
                    "runtime_state": "activated",
                    "qualification_state": state,
                    "components_sha256": hashlib.sha256(raw["components.lock.json"]).hexdigest(),
                    "project_identity_sha256": _digest_value({name: authority[name] for name in ("project_path", "project_volume", "project_file_id")}),
                    "authority_sha256": hashlib.sha256(raw["claim-receipt.json"]).hexdigest(),
                    "mission_id": values["mission-record.json"]["mission_id"],
                    "mission_sha256": hashlib.sha256(raw["mission-record.json"]).hexdigest(),
                    "witness_id": values["governance-envelope.json"]["witness_id"],
                    "governance_sha256": hashlib.sha256(raw["governance-envelope.json"]).hexdigest(),
                    "execution_id": values["execution-record.json"]["execution_id"],
                    "execution_sha256": hashlib.sha256(raw["execution-record.json"]).hexdigest(),
                    "requirements_sha256": hashlib.sha256(raw["requirements.json"]).hexdigest(),
                    "critical_matrix_sha256": hashlib.sha256(raw["critical-matrix.json"]).hexdigest(),
                    "semantic_fingerprint": fingerprint,
                    "assertion_count": len(matrix),
                    "record_digest": "0" * 64,
                }
                record["record_digest"] = _digest_value({name: member for name, member in record.items() if name != "record_digest"})
                _validate_schema(record, _QUALIFICATION_SCHEMA)
                try:
                    atomic_write_json(self._record_path, record)
                except OSError as error:
                    raise QualificationError("qualification-promotion-failed") from error
                if self._existing() != record:
                    raise QualificationError("qualification-promotion-failed")
                return self._record_path
        except QualificationError:
            raise
        except PoolError as error:
            raise QualificationError("qualification-recovery-required") from error
