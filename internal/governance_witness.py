from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from internal.mission_bridge import (
    MissionBridgeError,
    MissionReadback,
    _PrivateDirectory,
    _canonical_bytes,
    _load_record,
    _open_verified_file,
    _private_directory,
    _private_exists,
    _private_file,
    _read_private_bytes,
    _receipt_project_root,
    _run_output,
    _validate_schema,
)
from internal.planning_routes import PlanningRouteError, RouteDecision, select_route
from internal.pool import AuthorityLease, Pool, PoolError


COMPONENT_LOCK = Path(__file__).parents[1] / "manifests/components.lock.json"
BIN_DIR = Path(__file__).parents[1] / ".local/bin"
ENVELOPE_SCHEMA = Path(__file__).parents[1] / "schemas/governance-envelope.schema.json"
_PRIVATE_PARTS = (".ao", "governance", "office-pool")
_PRODUCERS = {
    "ao-blueprint": ("pack", "inspect", "--pack", "{artifact}", "--json"),
    "ao-atlas": ("workgraph", "validate", "--workgraph", "{artifact}"),
    "ao-forge": ("goal", "validate", "--goal-run", "{artifact}", "--json"),
    "ao-covenant": ("verify", "--evidence", "{artifact}", "--json"),
}
_PINNED = {
    "ao-blueprint": ("a581a22af7d06483287a1b7590709e4c4d3739b8", "ao-blueprint"),
    "ao-atlas": ("e19acf2619588b6257b37ebd0fcf7219645284f3", "ao-atlas"),
    "ao-forge": ("4bf267bc7cbd9d6289728ebcaefa939135ddfb00", "forge"),
    "ao-covenant": ("7d2af0d3446757f096ebf3ce51e0918716daf7ff", "covenant"),
    "ao2": ("c00f78a3e1d0036205d1ac7b4c94ba2ce6dab7f0", "ao2"),
}
_ROOTS = {
    "ao-blueprint": (".ao", "evidence", "ao-blueprint"),
    "ao-atlas": (".ao", "evidence", "ao-atlas"),
    "ao-forge": (".ao", "evidence", "ao-forge"),
    "ao-covenant": (".ao", "evidence", "ao-covenant"),
    "requirements": (".ao", "evidence", "requirements"),
}
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^run-[0-9a-f]{16}$")
_WITNESS = re.compile(r"^witness-[0-9a-f]{32}$")
_MAX_ARTIFACT = 64 * 1024 * 1024
_MAX_ENVELOPE = 64 * 1024


class GovernanceError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class GovernanceArtifacts:
    blueprint_pack: Path
    atlas_workgraph: Path | None
    forge_goal_run: Path
    covenant_evidence: Path
    workflow: Path
    target: Path
    run_id: str
    evidence_set: Path


@dataclass(frozen=True)
class GovernedExecution:
    mission: MissionReadback
    route: RouteDecision
    target: _PrivateDirectory
    workflow_digest: str
    run_id: str
    producer_artifacts: dict
    requirements_evidence_digest: str
    ao2: dict
    request_digest: str


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _time(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _parse_time(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (TypeError, ValueError) as error:
        raise GovernanceError("governance-envelope-mismatch") from error


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_value(value: object) -> str:
    return _digest_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _pool(receipt: Path) -> Pool:
    try:
        root = receipt.parents[2]
        metadata = json.loads((root / "pool.json").read_text(encoding="utf-8"))
        return Pool(root, runtime_version=metadata["runtime_version"])
    except (OSError, IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise GovernanceError("governance-unauthorized") from error


def _locked_components() -> dict[str, dict]:
    try:
        value = json.loads(COMPONENT_LOCK.read_text(encoding="utf-8"))
        if value.get("schema_version") != 1 or not isinstance(
            value.get("components"), list
        ):
            raise ValueError("wrong component lock")
        result = {}
        for name, (commit, asset) in _PINNED.items():
            matches = [
                item
                for item in value["components"]
                if isinstance(item, dict) and item.get("name") == name
            ]
            if len(matches) != 1:
                raise ValueError("component count")
            item = matches[0]
            if (
                item.get("commit") != commit
                or item.get("version") != "git-" + commit[:12]
                or item.get("asset") != asset
                or not _DIGEST.fullmatch(item.get("sha256", ""))
            ):
                raise ValueError("component identity")
            result[name] = item
        return result
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise GovernanceError("governance-producer-identity-mismatch") from error


def _relative(project: _PrivateDirectory, path: Path, root: tuple[str, ...] | None) -> tuple[str, ...]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise GovernanceError("governance-artifact-unsafe")
    try:
        parts = path.relative_to(project.project_path).parts
    except ValueError as error:
        raise GovernanceError("governance-artifact-unsafe") from error
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise GovernanceError("governance-artifact-unsafe")
    if root is not None and parts[: len(root)] != root:
        raise GovernanceError("governance-artifact-unsafe")
    return parts


def _read_file(
    project: _PrivateDirectory,
    path: Path,
    root: tuple[str, ...] | None,
    *,
    code: str = "governance-artifact-unsafe",
) -> bytes:
    parts = _relative(project, path, root)
    candidate = None
    try:
        candidate = _private_file(project, tuple(parts[:-1]), parts[-1])
        if not _private_exists(candidate):
            raise ValueError("missing artifact")
        value = _read_private_bytes(candidate)
        if len(value) > _MAX_ARTIFACT:
            raise ValueError("artifact too large")
        return value
    except (OSError, TypeError, ValueError, MissionBridgeError) as error:
        raise GovernanceError(code) from error
    finally:
        if candidate is not None:
            candidate.close()


def _directory_digest(
    project: _PrivateDirectory, path: Path, root: tuple[str, ...]
) -> str:
    parts = _relative(project, path, root)
    retained = None
    try:
        retained = _private_directory(project, *parts)
        files = []
        for directory, names, filenames in os.walk(path, followlinks=False):
            current = Path(directory)
            for name in names:
                _private_directory(project, *current.joinpath(name).relative_to(project.project_path).parts).close()
            for name in filenames:
                candidate = current / name
                relative = candidate.relative_to(path).as_posix()
                files.append((relative, _read_file(project, candidate, root)))
        if not files:
            raise ValueError("empty artifact directory")
        digest = hashlib.sha256()
        total = 0
        for relative, data in sorted(files):
            total += len(data)
            if total > _MAX_ARTIFACT:
                raise ValueError("artifact directory too large")
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(data)
            digest.update(b"\0")
        return digest.hexdigest()
    except (OSError, TypeError, ValueError, MissionBridgeError) as error:
        raise GovernanceError("governance-artifact-unsafe") from error
    finally:
        if retained is not None:
            retained.close()


def _json_artifact(
    project: _PrivateDirectory, path: Path, root: tuple[str, ...]
) -> tuple[dict, str]:
    raw = _read_file(project, path, root)
    try:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value, _digest_bytes(raw)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise GovernanceError("governance-artifact-invalid") from error


def _readback(name: str, raw: bytes) -> dict:
    try:
        if name == "ao-atlas":
            value = {}
            for line in raw.decode("utf-8").splitlines():
                key, separator, member = line.partition("=")
                if not separator or key not in {"ready", "blocked", "completed"}:
                    raise ValueError("invalid Atlas readback")
                value[key] = int(member)
            if set(value) != {"ready", "blocked", "completed"}:
                raise ValueError("incomplete Atlas readback")
            return value
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("object required")
        if name == "ao-blueprint" and (
            value.get("schema") != "ao.blueprint.pack-inspection.v0.1"
            or value.get("status") != "ready"
            or type(value.get("artifact_count")) is not int
            or not isinstance(value.get("artifacts"), list)
            or not isinstance(value.get("project_id"), str)
        ):
            raise ValueError("invalid Blueprint readback")
        if name == "ao-forge" and (
            value.get("schema_version") != "ao.forge.goal-run.v0.1"
            or value.get("status") != "passed"
            or value.get("errors") != []
            or not isinstance(value.get("goal_id"), str)
        ):
            raise ValueError("invalid Forge readback")
        if name == "ao-covenant" and (
            value.get("schema_version") != "covenant.verify-result.v1"
            or value.get("verified") is not True
            or value.get("failure_count") != 0
            or value.get("failures") != []
        ):
            raise ValueError("invalid Covenant readback")
        return value
    except (UnicodeError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise GovernanceError("governance-producer-readback") from error


def _run_producer(
    name: str,
    component: dict,
    artifact: Path,
    project: _PrivateDirectory,
) -> dict:
    arguments = [
        str(artifact) if member == "{artifact}" else member
        for member in _PRODUCERS[name]
    ]
    try:
        with _open_verified_file(
            BIN_DIR / component["asset"], component["sha256"]
        ) as executable:
            raw = _run_output(
                arguments, project, executable, timeout_seconds=10
            )
    except MissionBridgeError as error:
        code = (
            "governance-producer-identity-mismatch"
            if error.code == "mission-identity-mismatch"
            else "governance-producer-failed"
        )
        raise GovernanceError(code) from error
    return _readback(name, raw)


def _mission_route(
    lease: AuthorityLease, project: _PrivateDirectory, task_text: str | None
) -> tuple[MissionReadback, RouteDecision]:
    try:
        record, record_path = _load_record(
            lease.authority, lease.authority_bytes, project, task_text
        )
        mission = MissionReadback(
            record["mission_id"],
            record["objective_digest"],
            record["mission_status"],
            record["current_route"],
            record_path.path,
            True,
        )
        return mission, select_route(mission)
    except (KeyError, TypeError, ValueError, MissionBridgeError, PlanningRouteError) as error:
        raise GovernanceError("governance-mission-mismatch") from error


def _target(
    project: _PrivateDirectory, path: Path, authority: dict
) -> dict:
    if not isinstance(path, Path):
        raise GovernanceError("governance-target-mismatch")
    try:
        if os.path.samefile(path, project.project_path) is not True:
            raise ValueError("target is not connected project")
        project.require_current_paths()
    except (OSError, TypeError, ValueError, MissionBridgeError) as error:
        raise GovernanceError("governance-target-mismatch") from error
    return {
        "canonical_path": authority["project_path"],
        "volume": authority["project_volume"],
        "file_id": authority["project_file_id"],
    }


def _validate_relationships(
    mission: MissionReadback,
    route: RouteDecision,
    authority: dict,
    artifacts: GovernanceArtifacts,
    native: dict[str, dict],
    readbacks: dict[str, dict],
    workflow_digest: str,
    ao2: dict,
    task_text: str,
) -> dict:
    blueprint = native["ao-blueprint"]
    if (
        blueprint.get("schema") != "ao.blueprint.build-authorization.v0.1"
        or blueprint.get("status") != "ready"
        or blueprint.get("approved_by_user") is not True
        or blueprint.get("blocking_assumptions") not in (None, [])
        or blueprint.get("project_id") != readbacks["ao-blueprint"].get("project_id")
    ):
        raise GovernanceError("governance-relationship-mismatch")
    allowed = {
        "ao-atlas": {"ao-atlas", "ao-atlas-then-foundry"},
        "ao-forge": {"ao-forge", "ao-foundry"},
    }
    if route.route in allowed and blueprint.get("next_allowed_action") not in allowed[
        route.route
    ]:
        raise GovernanceError("governance-relationship-mismatch")
    atlas = native.get("ao-atlas")
    if atlas is not None and any(
        (
            atlas.get("contract_version") != "ao.atlas.workgraph.v0.1",
            "mission_id" in atlas
            and atlas.get("mission_id") != mission.mission_id,
            "objective_digest" in atlas
            and atlas.get("objective_digest") != mission.objective_digest,
            atlas.get("target_instance")
            not in (authority["project_path"], Path(authority["project_path"]).name),
        )
    ):
        raise GovernanceError("governance-relationship-mismatch")
    forge = native["ao-forge"]
    if (
        forge.get("schema_version") != "ao.forge.goal-run.v0.1"
        or forge.get("goal_id") != readbacks["ao-forge"].get("goal_id")
        or forge.get("repo") != authority["project_path"]
        or forge.get("objective") != task_text
    ):
        raise GovernanceError("governance-relationship-mismatch")
    covenant = native["ao-covenant"]
    required = {
        "decision": "authorized",
        "scope": authority["project_path"],
        "revoked": False,
        "mission_id": mission.mission_id,
        "objective_digest": mission.objective_digest,
        "target_path": authority["project_path"],
        "workflow_sha256": workflow_digest,
        "run_id": artifacts.run_id,
        "ao2_sha256": ao2["sha256"],
    }
    if any(covenant.get(name) != value for name, value in required.items()):
        raise GovernanceError("governance-relationship-mismatch")
    if readbacks["ao-covenant"].get("run_id") != artifacts.run_id:
        raise GovernanceError("governance-relationship-mismatch")
    expires_at = _parse_time(covenant.get("expires_at"))
    if expires_at <= _now():
        raise GovernanceError("governance-relationship-mismatch")
    return {
        "decision": "authorized",
        "scope": authority["project_path"],
        "expires_at": _time(expires_at),
        "revoked": False,
    }


def _requirements(project: _PrivateDirectory, path: Path) -> tuple[dict, str]:
    value, _ = _json_artifact(project, path, _ROOTS["requirements"])
    if (
        set(value)
        != {"requirements_sha256", "test_bindings_sha256", "requirement_ids"}
        or not _DIGEST.fullmatch(value.get("requirements_sha256", ""))
        or not _DIGEST.fullmatch(value.get("test_bindings_sha256", ""))
        or value.get("requirement_ids")
        != [f"B{number:02d}" for number in range(1, 20)]
    ):
        raise GovernanceError("governance-requirements-mismatch")
    return value, _digest_value(value)


def _create_private(path, data: bytes) -> None:
    descriptor = path.directory.directory_descriptor
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    opened = None
    created = False
    try:
        opened = (
            os.open(path.name, flags, 0o600, dir_fd=descriptor)
            if descriptor is not None
            else os.open(path.path, flags, 0o600)
        )
        created = True
        view = memoryview(data)
        while view:
            count = os.write(opened, view)
            if count <= 0:
                raise OSError("create-only write made no progress")
            view = view[count:]
        os.fsync(opened)
        os.close(opened)
        opened = None
        if descriptor is not None:
            os.fsync(descriptor)
    except BaseException:
        if opened is not None:
            try:
                os.close(opened)
            except OSError:
                pass
            opened = None
        if created:
            try:
                _unlink_private(path)
            except (FileNotFoundError, OSError):
                pass
        raise
    finally:
        if opened is not None:
            os.close(opened)


def _unlink_private(path) -> None:
    descriptor = path.directory.directory_descriptor
    if descriptor is None:
        path.path.unlink()
    else:
        os.unlink(path.name, dir_fd=descriptor)
        os.fsync(descriptor)


def _stage_workflow(project: _PrivateDirectory, path: Path) -> str:
    raw = _read_file(
        project, path, None, code="governance-workflow-mismatch"
    )
    digest = _digest_bytes(raw)
    staged = _private_file(project, (*_PRIVATE_PARTS, "workflows"), digest)
    try:
        try:
            _create_private(staged, raw)
        except FileExistsError:
            if _read_private_bytes(staged) != raw:
                raise GovernanceError("governance-workflow-mismatch")
        if _read_private_bytes(staged) != raw:
            raise GovernanceError("governance-workflow-mismatch")
        return digest
    except (OSError, ValueError, MissionBridgeError) as error:
        if isinstance(error, GovernanceError):
            raise
        raise GovernanceError("governance-workflow-mismatch") from error
    finally:
        staged.close()


def _producer_record(component: dict, command: tuple[str, ...], digest: str) -> dict:
    return {
        "commit": component["commit"],
        "asset": component["asset"],
        "binary_sha256": component["sha256"],
        "command_contract": " ".join((component["asset"], *command)),
        "artifact_sha256": digest,
    }


def _seal(
    pool: Pool, project: _PrivateDirectory, envelope: dict
) -> Path:
    envelope["payload_digest"] = _digest_value(
        {name: value for name, value in envelope.items() if name != "payload_digest"}
    )
    try:
        _validate_schema(envelope, ENVELOPE_SCHEMA)
    except ValueError as error:
        raise GovernanceError("governance-envelope-mismatch") from error
    for _ in range(128):
        identifier = "witness-" + uuid.uuid4().hex
        envelope["witness_id"] = identifier
        envelope["payload_digest"] = _digest_value(
            {name: value for name, value in envelope.items() if name != "payload_digest"}
        )
        raw = _canonical_bytes(envelope)
        tag = hmac.new(
            pool._read_witness_key(), raw, hashlib.sha256
        ).hexdigest().encode("ascii") + b"\n"
        record = _private_file(project, _PRIVATE_PARTS, identifier + ".json")
        seal = _private_file(project, _PRIVATE_PARTS, identifier + ".hmac")
        created_seal = False
        try:
            try:
                _create_private(seal, tag)
                created_seal = True
                _create_private(record, raw)
            except FileExistsError:
                if created_seal:
                    _unlink_private(seal)
                continue
            except BaseException:
                if created_seal:
                    _unlink_private(seal)
                raise
            return record.path
        finally:
            seal.close()
            record.close()
    raise GovernanceError("governance-envelope-collision")


def issue_witness(
    receipt: Path,
    objective: str,
    artifacts: GovernanceArtifacts,
    *,
    lifetime_seconds: int = 60,
) -> Path:
    if (
        not isinstance(receipt, Path)
        or not isinstance(objective, str)
        or not objective
        or type(artifacts) is not GovernanceArtifacts
        or type(lifetime_seconds) is not int
        or not 1 <= lifetime_seconds <= 300
        or not _RUN_ID.fullmatch(artifacts.run_id)
    ):
        raise GovernanceError("governance-invalid-request")
    pool = _pool(receipt)
    try:
        with pool.authority_lease(receipt) as lease:
            if lease.authority.get("task_digest") != _digest_bytes(
                objective.encode("utf-8")
            ):
                raise GovernanceError("governance-task-mismatch")
            project = _receipt_project_root(lease.authority)
            try:
                mission, route = _mission_route(lease, project, objective)
                if route.atlas_required and artifacts.atlas_workgraph is None:
                    raise GovernanceError("governance-atlas-required")
                if not route.atlas_required and artifacts.atlas_workgraph is not None:
                    raise GovernanceError("governance-atlas-unexpected")
                components = _locked_components()
                workflow_digest = _stage_workflow(project, artifacts.workflow)
                target = _target(project, artifacts.target, lease.authority)
                native = {}
                artifact_digests = {}
                blueprint_auth = artifacts.blueprint_pack / "build-authorization.json"
                native["ao-blueprint"], _ = _json_artifact(
                    project, blueprint_auth, _ROOTS["ao-blueprint"]
                )
                artifact_digests["ao-blueprint"] = _directory_digest(
                    project, artifacts.blueprint_pack, _ROOTS["ao-blueprint"]
                )
                paths = {
                    "ao-blueprint": artifacts.blueprint_pack,
                    "ao-atlas": artifacts.atlas_workgraph,
                    "ao-forge": artifacts.forge_goal_run,
                    "ao-covenant": artifacts.covenant_evidence,
                }
                for name in ("ao-atlas", "ao-forge", "ao-covenant"):
                    path = paths[name]
                    if path is None:
                        continue
                    native[name], artifact_digests[name] = _json_artifact(
                        project, path, _ROOTS[name]
                    )
                readbacks = {}
                for name, command in _PRODUCERS.items():
                    path = paths[name]
                    if path is None:
                        continue
                    readbacks[name] = _run_producer(
                        name, components[name], path, project
                    )
                    if name == "ao-blueprint":
                        confirmed = _directory_digest(
                            project, path, _ROOTS[name]
                        )
                    else:
                        _, confirmed = _json_artifact(
                            project, path, _ROOTS[name]
                        )
                    if confirmed != artifact_digests[name]:
                        raise GovernanceError("governance-artifact-changed")
                requirements, requirements_digest = _requirements(
                    project, artifacts.evidence_set
                )
                del requirements
                ao2_component = components["ao2"]
                ao2 = {
                    "name": "ao2",
                    "commit": ao2_component["commit"],
                    "asset": ao2_component["asset"],
                    "sha256": ao2_component["sha256"],
                }
                covenant = _validate_relationships(
                    mission,
                    route,
                    lease.authority,
                    artifacts,
                    native,
                    readbacks,
                    workflow_digest,
                    ao2,
                    objective,
                )
                for name, path in paths.items():
                    if path is None:
                        continue
                    if name == "ao-blueprint":
                        confirmed = _directory_digest(project, path, _ROOTS[name])
                    else:
                        _, confirmed = _json_artifact(project, path, _ROOTS[name])
                    if not hmac.compare_digest(confirmed, artifact_digests[name]):
                        raise GovernanceError("governance-artifact-changed")
                _, confirmed_requirements = _requirements(
                    project, artifacts.evidence_set
                )
                if not hmac.compare_digest(
                    confirmed_requirements, requirements_digest
                ):
                    raise GovernanceError("governance-artifact-changed")
                producer_artifacts = {
                    name: (
                        _producer_record(
                            components[name], _PRODUCERS[name], artifact_digests[name]
                        )
                        if paths[name] is not None
                        else None
                    )
                    for name in _PRODUCERS
                }
                created = _now().replace(microsecond=0)
                route_digest = route.as_record()["decision_digest"]
                request = {
                    "authority_digest": _digest_bytes(lease.authority_bytes),
                    "mission_id": mission.mission_id,
                    "route_digest": route_digest,
                    "target": target,
                    "workflow_digest": workflow_digest,
                    "run_id": artifacts.run_id,
                    "producer_artifacts": producer_artifacts,
                    "requirements_evidence_digest": requirements_digest,
                    "ao2": ao2,
                }
                envelope = {
                    "schema_version": 1,
                    "witness_id": "witness-" + "0" * 32,
                    "state": "ready",
                    "authority_digest": request["authority_digest"],
                    "office_id": lease.authority["office_id"],
                    "generation": lease.authority["generation"],
                    "runtime_version": pool.runtime_version,
                    "project_path": lease.authority["project_path"],
                    "project_volume": lease.authority["project_volume"],
                    "project_file_id": lease.authority["project_file_id"],
                    "mission": {
                        "mission_id": mission.mission_id,
                        "objective_digest": mission.objective_digest,
                        "status": mission.status,
                        "current_route": mission.current_route,
                    },
                    "route": {
                        "decision_digest": route_digest,
                        "route": route.route,
                        "atlas_required": route.atlas_required,
                        "execution_candidate": route.execution_candidate,
                    },
                    "task_digest": lease.authority["task_digest"],
                    "request_digest": _digest_value(request),
                    "target": target,
                    "workflow_digest": workflow_digest,
                    "run_id": artifacts.run_id,
                    "producer_artifacts": producer_artifacts,
                    "covenant": covenant,
                    "requirements_evidence_digest": requirements_digest,
                    "ao2": ao2,
                    "created_at": _time(created),
                    "expires_at": _time(created + timedelta(seconds=lifetime_seconds)),
                    "payload_digest": "0" * 64,
                }
                return _seal(pool, project, envelope)
            finally:
                project.close()
    except PoolError as error:
        raise GovernanceError("governance-unauthorized") from error


def _marker(project: _PrivateDirectory, identifier: str, suffix: str):
    return _private_file(project, _PRIVATE_PARTS, identifier + suffix)


def _load_envelope(
    lease: AuthorityLease,
    envelope_path: Path,
) -> tuple[dict, _PrivateDirectory]:
    if type(lease) is not AuthorityLease or not isinstance(envelope_path, Path):
        raise GovernanceError("governance-invalid-request")
    project = _receipt_project_root(lease.authority)
    record = seal = None
    try:
        name = envelope_path.name
        if (
            envelope_path.parent != project.path.joinpath(*_PRIVATE_PARTS)
            or envelope_path.suffix != ".json"
            or not _WITNESS.fullmatch(envelope_path.stem)
        ):
            raise GovernanceError("governance-envelope-mismatch")
        record = _private_file(project, _PRIVATE_PARTS, name)
        seal = _private_file(project, _PRIVATE_PARTS, envelope_path.stem + ".hmac")
        raw = _read_private_bytes(record)
        supplied = _read_private_bytes(seal)
        if len(raw) > _MAX_ENVELOPE:
            raise ValueError("envelope too large")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("envelope object required")
        _validate_schema(value, ENVELOPE_SCHEMA)
        if value["witness_id"] != envelope_path.stem:
            raise ValueError("witness relocation")
        payload = dict(value)
        digest = payload.pop("payload_digest")
        if not hmac.compare_digest(digest, _digest_value(payload)):
            raise ValueError("payload digest")
        pool = _pool(lease.authority_path)
        expected = hmac.new(
            pool._read_witness_key(), raw, hashlib.sha256
        ).hexdigest().encode("ascii") + b"\n"
        if not hmac.compare_digest(supplied, expected):
            raise ValueError("authentication")
        authority_expected = {
            "authority_digest": _digest_bytes(lease.authority_bytes),
            "office_id": lease.authority["office_id"],
            "generation": lease.authority["generation"],
            "project_path": lease.authority["project_path"],
            "project_volume": lease.authority["project_volume"],
            "project_file_id": lease.authority["project_file_id"],
            "task_digest": lease.authority["task_digest"],
        }
        if any(value.get(name) != expected for name, expected in authority_expected.items()):
            raise ValueError("authority mismatch")
        pool = _pool(lease.authority_path)
        if value["runtime_version"] != pool.runtime_version:
            raise ValueError("runtime mismatch")
        mission, route = _mission_route(lease, project, None)
        route_record = {
            "decision_digest": route.as_record()["decision_digest"],
            "route": route.route,
            "atlas_required": route.atlas_required,
            "execution_candidate": route.execution_candidate,
        }
        mission_record = {
            "mission_id": mission.mission_id,
            "objective_digest": mission.objective_digest,
            "status": mission.status,
            "current_route": mission.current_route,
        }
        if value["mission"] != mission_record or value["route"] != route_record:
            raise ValueError("route mismatch")
        if value["route"]["atlas_required"] != (
            value["producer_artifacts"]["ao-atlas"] is not None
        ):
            raise ValueError("Atlas mismatch")
        expected_components = _locked_components()
        for name, member in value["producer_artifacts"].items():
            if member is None:
                continue
            component = expected_components[name]
            if any(
                (
                    member["commit"] != component["commit"],
                    member["asset"] != component["asset"],
                    member["binary_sha256"] != component["sha256"],
                    member["command_contract"]
                    != " ".join((component["asset"], *_PRODUCERS[name])),
                )
            ):
                raise ValueError("producer identity mismatch")
        ao2_component = expected_components["ao2"]
        if value["ao2"] != {
            "name": "ao2",
            "commit": ao2_component["commit"],
            "asset": ao2_component["asset"],
            "sha256": ao2_component["sha256"],
        }:
            raise ValueError("AO2 identity mismatch")
        if value["target"] != {
            "canonical_path": lease.authority["project_path"],
            "volume": lease.authority["project_volume"],
            "file_id": lease.authority["project_file_id"],
        }:
            raise ValueError("target identity mismatch")
        workflow = _private_file(
            project,
            (*_PRIVATE_PARTS, "workflows"),
            value["workflow_digest"],
        )
        try:
            if not hmac.compare_digest(
                _digest_bytes(_read_private_bytes(workflow)),
                value["workflow_digest"],
            ):
                raise ValueError("workflow mismatch")
        finally:
            workflow.close()
        request = {
            "authority_digest": value["authority_digest"],
            "mission_id": value["mission"]["mission_id"],
            "route_digest": value["route"]["decision_digest"],
            "target": value["target"],
            "workflow_digest": value["workflow_digest"],
            "run_id": value["run_id"],
            "producer_artifacts": value["producer_artifacts"],
            "requirements_evidence_digest": value[
                "requirements_evidence_digest"
            ],
            "ao2": value["ao2"],
        }
        if not hmac.compare_digest(value["request_digest"], _digest_value(request)):
            raise ValueError("request digest mismatch")
        if value["covenant"] != {
            "decision": "authorized",
            "scope": lease.authority["project_path"],
            "expires_at": value["covenant"]["expires_at"],
            "revoked": False,
        }:
            raise ValueError("covenant mismatch")
        created = _parse_time(value["created_at"])
        expires = _parse_time(value["expires_at"])
        if expires <= created or expires - created > timedelta(seconds=300):
            raise ValueError("envelope lifetime")
        if created > _now():
            raise ValueError("future envelope")
        value["_mission"] = mission
        value["_route"] = route
        return value, project
    except GovernanceError:
        project.close()
        raise
    except (OSError, KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError, MissionBridgeError) as error:
        project.close()
        raise GovernanceError("governance-envelope-mismatch") from error
    finally:
        if record is not None:
            record.close()
        if seal is not None:
            seal.close()


def revoke_witness(receipt: Path, envelope: Path) -> None:
    pool = _pool(receipt)
    try:
        with pool.authority_lease(receipt) as lease:
            value, project = _load_envelope(lease, envelope)
            marker = _marker(project, value["witness_id"], ".revoked")
            try:
                data = _canonical_bytes(
                    {
                        "schema_version": 1,
                        "witness_id": value["witness_id"],
                        "authority_digest": value["authority_digest"],
                    }
                )
                try:
                    _create_private(marker, data)
                except FileExistsError:
                    if _read_private_bytes(marker) != data:
                        raise GovernanceError("governance-envelope-mismatch")
            finally:
                marker.close()
                project.close()
    except PoolError as error:
        raise GovernanceError("governance-unauthorized") from error


def _consume_witness(
    lease: AuthorityLease, envelope_path: Path
) -> GovernedExecution:
    value, project = _load_envelope(lease, envelope_path)
    revoked = _marker(project, value["witness_id"], ".revoked")
    consumed = _marker(project, value["witness_id"], ".consumed")
    try:
        if _private_exists(revoked):
            raise GovernanceError("governance-envelope-revoked")
        if _private_exists(consumed):
            raise GovernanceError("governance-envelope-consumed")
        now = _now()
        if (
            _parse_time(value["covenant"]["expires_at"]) <= now
            or _parse_time(value["expires_at"]) <= now
        ):
            raise GovernanceError("governance-envelope-expired")
        marker = _canonical_bytes(
            {
                "schema_version": 1,
                "witness_id": value["witness_id"],
                "authority_digest": value["authority_digest"],
            }
        )
        try:
            _create_private(consumed, marker)
        except FileExistsError as error:
            raise GovernanceError("governance-envelope-consumed") from error
        return GovernedExecution(
            value.pop("_mission"),
            value.pop("_route"),
            project,
            value["workflow_digest"],
            value["run_id"],
            value["producer_artifacts"],
            value["requirements_evidence_digest"],
            value["ao2"],
            value["request_digest"],
        )
    except BaseException:
        project.close()
        raise
    finally:
        revoked.close()
        consumed.close()
