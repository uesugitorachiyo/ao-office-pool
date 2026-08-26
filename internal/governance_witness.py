from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import sys
import uuid
from collections.abc import Callable
from contextlib import ExitStack, nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType

from internal.component_lock import load_component_lock

from internal.mission_bridge import (
    MissionBridgeError,
    MissionReadback,
    _PrivateDirectory,
    _canonical_bytes,
    _hash_descriptor,
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
COMPONENT_ROOT = Path(__file__).parents[1] / "components"
FORGE_RUNTIME_ROOT = Path(__file__).parents[1] / "packaging/runtime/ao-forge"
FORGE_SCHEMA_SHA256 = "1a1c48a29c6b35713b08d733191e88887795fb8482054801900ae4b37e5bda3c"
ENVELOPE_SCHEMA = Path(__file__).parents[1] / "schemas/governance-envelope.schema.json"
REQUIREMENTS_MANIFEST = Path(__file__).parents[1] / "manifests/requirements.json"
_PRIVATE_PARTS = (".ao", "governance", "office-pool")
_PRODUCERS = {
    "ao-blueprint": ("authorize", "--pack", "{artifact}", "--out", "{output}"),
    "ao-atlas": ("workgraph", "validate", "--workgraph", "{artifact}"),
    "ao-forge": ("goal", "validate", "--goal-run", "{artifact}", "--json"),
    "ao-covenant": ("verify", "--ledger", "{ledger}", "--evidence", "{artifact}", "--json"),
}
_GOVERNED_COMPONENTS = frozenset(
    {"ao-blueprint", "ao-atlas", "ao-forge", "ao-covenant", "ao2"}
)
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
_FORGE_SCHEMA_PARTS = ("docs", "contracts", "goal-run-v0.1.schema.json")
_FORGE_PRIVATE_RUNTIME_PARTS = (*_PRIVATE_PARTS, "producer-runtime", "ao-forge")


class GovernanceError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class GovernanceArtifacts:
    blueprint_pack: Path
    atlas_workgraph: Path | None
    forge_goal_run: Path
    covenant_ledger: Path
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
    producer_artifacts: MappingProxyType
    requirements_evidence_digest: str
    ao2: MappingProxyType
    witness_id: str
    authority_digest: str
    request_digest: str


@dataclass
class _RetainedFile:
    private: object
    descriptor: int
    parent_change: int
    change: int
    digest: str | None = None

    @property
    def path(self) -> Path:
        if os.name != "nt":
            for root in (Path("/proc/self/fd"), Path("/dev/fd")):
                if root.is_dir():
                    return root / str(self.descriptor)
        return self.private.path

    def read(self, limit: int) -> bytes:
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        chunks = []
        size = 0
        while True:
            chunk = os.read(self.descriptor, min(64 * 1024, limit + 1 - size))
            if not chunk:
                return b"".join(chunks)
            size += len(chunk)
            if size > limit:
                raise ValueError("retained file too large")
            chunks.append(chunk)

    def recheck(self) -> None:
        opened = os.fstat(self.descriptor)
        current = os.stat(
            self.private.name,
            dir_fd=self.private.directory.directory_descriptor,
            follow_symlinks=False,
        ) if self.private.directory.directory_descriptor is not None else self.private.path.stat(follow_symlinks=False)
        parent = self.private.directory.directory_descriptor
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or opened.st_ctime_ns != self.change
            or (parent is not None and os.fstat(parent).st_ctime_ns != self.parent_change)
        ):
            raise GovernanceError("governance-artifact-changed")
        if self.digest is not None and not hmac.compare_digest(
            _digest_bytes(self.read(_MAX_ARTIFACT)), self.digest
        ):
            raise GovernanceError("governance-artifact-changed")

    def refresh_parent_identity(self) -> None:
        if self.private.directory.directory_descriptor is not None:
            self.parent_change = os.fstat(
                self.private.directory.directory_descriptor
            ).st_ctime_ns

    def refresh_identity(self, digest: str | None = None) -> None:
        self.change = os.fstat(self.descriptor).st_ctime_ns
        self.refresh_parent_identity()
        self.digest = digest

    def accept_producer_write(self) -> None:
        opened = os.fstat(self.descriptor)
        current = os.stat(
            self.private.name,
            dir_fd=self.private.directory.directory_descriptor,
            follow_symlinks=False,
        ) if self.private.directory.directory_descriptor is not None else self.private.path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or (
                self.private.directory.directory_descriptor is not None
                and os.fstat(self.private.directory.directory_descriptor).st_ctime_ns
                != self.parent_change
            )
        ):
            raise GovernanceError("governance-artifact-changed")
        self.refresh_identity()

    def close(self) -> None:
        os.close(self.descriptor)
        self.private.close()


@dataclass
class _RetainedDirectory:
    directory: _PrivateDirectory
    digest: str
    change: int | None
    children: tuple[_RetainedFile, ...]
    child_directories: tuple[_PrivateDirectory, ...]
    directory_changes: tuple[int, ...]

    @property
    def path(self) -> Path:
        return Path(self.directory.launch_path)

    @property
    def descriptors(self) -> tuple[int, ...]:
        return tuple(
            descriptor
            for descriptor in (
                self.directory.directory_descriptor,
                *(directory.directory_descriptor for directory in self.child_directories),
                *(child.descriptor for child in self.children),
            )
            if descriptor is not None
        )

    def recheck(self, project: _PrivateDirectory) -> None:
        self.directory.require_current_paths()
        if self.change is not None and os.fstat(self.directory.directory_descriptor).st_ctime_ns != self.change:
            raise GovernanceError("governance-artifact-changed")
        if not hmac.compare_digest(
            _directory_digest(project, self.directory.path, _PRIVATE_PARTS), self.digest
        ):
            raise GovernanceError("governance-artifact-changed")
        for child in self.children:
            child.recheck()
        for directory, change in zip(self.child_directories, self.directory_changes):
            directory.require_current_paths()
            if (
                directory.directory_descriptor is not None
                and os.fstat(directory.directory_descriptor).st_ctime_ns != change
            ):
                raise GovernanceError("governance-artifact-changed")

    def close(self) -> None:
        for child in self.children:
            child.close()
        for directory in self.child_directories:
            directory.close()
        self.directory.close()


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


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({name: _freeze(member) for name, member in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(member) for member in value)
    return value


def _pool(receipt: Path) -> Pool:
    try:
        root = receipt.parents[2]
        metadata = json.loads((root / "pool.json").read_text(encoding="utf-8"))
        return Pool(root, runtime_version=metadata["runtime_version"])
    except (OSError, IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise GovernanceError("governance-unauthorized") from error


def _locked_components() -> dict[str, dict]:
    try:
        locked = load_component_lock(COMPONENT_LOCK)
        return {name: locked[name] for name in _GOVERNED_COMPONENTS}
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
    limit: int = _MAX_ARTIFACT,
) -> bytes:
    parts = _relative(project, path, root)
    candidate = None
    try:
        candidate = _private_file(project, tuple(parts[:-1]), parts[-1])
        if not _private_exists(candidate):
            raise ValueError("missing artifact")
        return _read_private_bytes(candidate, limit)
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
                files.append((relative, candidate))
        if not files:
            raise ValueError("empty artifact directory")
        digest = hashlib.sha256()
        total = 0
        for relative, candidate in sorted(files):
            data = _read_file(
                project, candidate, root, limit=_MAX_ARTIFACT - total
            )
            total += len(data)
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


def _json_retained(retained: _RetainedFile) -> tuple[dict, str]:
    try:
        retained.recheck()
        raw = retained.read(_MAX_ARTIFACT)
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value, _digest_bytes(raw)
    except GovernanceError:
        raise
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise GovernanceError("governance-artifact-invalid") from error


def _readback(name: str, raw: bytes) -> dict:
    try:
        if name == "ao-atlas":
            if raw != b"status=valid\n":
                raise ValueError("invalid Atlas readback")
            return {"status": "valid"}
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("object required")
        if name == "ao-blueprint" and (
            value.get("schema") != "ao.blueprint.build-authorization.v0.1"
            or value.get("status") != "ready"
            or value.get("approved_by_user") is not True
            or value.get("blocking_assumptions") not in (None, [])
            or not isinstance(value.get("project_id"), str)
            or not isinstance(value.get("next_allowed_action"), str)
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
            or type(value.get("event_count")) is not int
            or value.get("event_count", 0) < 1
            or type(value.get("artifact_count")) is not int
            or value.get("artifact_count", -1) < 0
            or type(value.get("input_snapshot_count")) is not int
            or value.get("input_snapshot_count", -1) < 0
            or value.get("failure_count") != 0
            or value.get("failures") != []
            or not isinstance(value.get("policy_explanations"), list)
            or not _DIGEST.fullmatch(value.get("ledger_digest", ""))
            or not _DIGEST.fullmatch(value.get("last_event_hash", ""))
        ):
            raise ValueError("invalid Covenant readback")
        return value
    except (UnicodeError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise GovernanceError("governance-producer-readback") from error


def _forge_runtime(
    stack: ExitStack, project: _PrivateDirectory
) -> tuple[_PrivateDirectory, Callable[[], None]]:
    try:
        schema_path = FORGE_RUNTIME_ROOT.joinpath(*_FORGE_SCHEMA_PARTS)
        schema = stack.enter_context(
            _open_verified_file(schema_path, FORGE_SCHEMA_SHA256)
        )
        source_runtime = stack.enter_context(
            _private_directory(FORGE_RUNTIME_ROOT, *_FORGE_SCHEMA_PARTS[:-1])
        )
        descriptor = schema.descriptors[0]
        initial = os.fstat(descriptor)
        source_directory_changes = tuple(
            os.fstat(directory).st_ctime_ns
            for directory in source_runtime.descriptors
        )
        launch_runtime = source_runtime
        retained_schema = None
        private_schema_directory = None
        private_runtime = None
        private_schema_directory_changes = ()
        private_directory_changes = ()
        if os.name != "nt":
            os.lseek(descriptor, 0, os.SEEK_SET)
            raw = os.read(descriptor, _MAX_ARTIFACT + 1)
            if len(raw) > _MAX_ARTIFACT or os.read(descriptor, 1):
                raise ValueError("Forge runtime schema too large")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if not hmac.compare_digest(_digest_bytes(raw), FORGE_SCHEMA_SHA256):
                raise ValueError("Forge runtime schema changed")
            private_schema = _private_file(
                project,
                (*_FORGE_PRIVATE_RUNTIME_PARTS, *_FORGE_SCHEMA_PARTS[:-1]),
                _FORGE_SCHEMA_PARTS[-1],
            )
            try:
                try:
                    _create_private(private_schema, raw)
                except FileExistsError:
                    if _read_private_bytes(private_schema, _MAX_ARTIFACT) != raw:
                        raise ValueError("Forge private runtime schema mismatch")
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                private_descriptor = os.open(
                    private_schema.name,
                    flags,
                    dir_fd=private_schema.directory.directory_descriptor,
                )
                retained_schema = _RetainedFile(
                    private_schema,
                    private_descriptor,
                    os.fstat(private_schema.directory.directory_descriptor).st_ctime_ns,
                    os.fstat(private_descriptor).st_ctime_ns,
                    FORGE_SCHEMA_SHA256,
                )
            except BaseException:
                private_schema.close()
                raise
            stack.callback(retained_schema.close)
            private_schema_directory = private_schema.directory
            private_schema_directory_changes = tuple(
                os.fstat(directory).st_ctime_ns
                for directory in private_schema_directory.descriptors
            )
            private_runtime = stack.enter_context(
                _private_directory(project, *_FORGE_PRIVATE_RUNTIME_PARTS)
            )
            private_directory_changes = tuple(
                os.fstat(directory).st_ctime_ns
                for directory in private_runtime.descriptors
            )
            launch_runtime = _PrivateDirectory(
                private_runtime.path,
                private_runtime.path,
                descriptors=(private_runtime.directory_descriptor,),
                borrowed_root=True,
            )
    except (IndexError, OSError, TypeError, ValueError, MissionBridgeError) as error:
        raise MissionBridgeError("mission-identity-mismatch") from error

    def verify() -> None:
        try:
            project.require_current_paths()
            source_runtime.require_current_paths()
            opened = os.fstat(descriptor)
            current = schema_path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                or opened.st_ctime_ns != initial.st_ctime_ns
                or any(
                    os.fstat(directory).st_ctime_ns != change
                    for directory, change in zip(
                        source_runtime.descriptors, source_directory_changes
                    )
                )
                or not hmac.compare_digest(
                    _hash_descriptor(descriptor), FORGE_SCHEMA_SHA256
                )
            ):
                raise ValueError("Forge runtime schema changed")
            if private_runtime is not None:
                private_runtime.require_current_paths()
                if any(
                    os.fstat(directory).st_ctime_ns != change
                    for directory, change in zip(
                        private_runtime.descriptors, private_directory_changes
                    )
                ):
                    raise ValueError("Forge private runtime changed")
                private_schema_directory.require_current_paths()
                if any(
                    os.fstat(directory).st_ctime_ns != change
                    for directory, change in zip(
                        private_schema_directory.descriptors,
                        private_schema_directory_changes,
                    )
                ):
                    raise ValueError("Forge private runtime schema directory changed")
                retained_schema.recheck()
        except (
            OSError,
            TypeError,
            ValueError,
            GovernanceError,
            MissionBridgeError,
        ) as error:
            raise MissionBridgeError("mission-identity-mismatch") from error

    verify()
    return launch_runtime, verify


def _producer_path_verifier(*values) -> Callable[[], None]:
    directories = []
    for value in values:
        if isinstance(value, _RetainedDirectory):
            candidates = (value.directory, *value.child_directories)
        else:
            private = getattr(value, "private", None)
            directory = getattr(private, "directory", None)
            candidates = (directory,) if directory is not None else ()
        for directory in candidates:
            if all(directory is not retained for retained in directories):
                directories.append(directory)
    try:
        for directory in directories:
            directory.require_current_paths()
        changes = tuple(
            tuple(os.fstat(descriptor).st_ctime_ns for descriptor in directory.descriptors)
            for directory in directories
        )
    except (OSError, MissionBridgeError) as error:
        raise GovernanceError("governance-artifact-changed") from error

    def verify() -> None:
        try:
            for directory, expected in zip(directories, changes):
                directory.require_current_paths()
                if tuple(
                    os.fstat(descriptor).st_ctime_ns
                    for descriptor in directory.descriptors
                ) != expected:
                    raise ValueError("producer path ancestor changed")
        except (OSError, ValueError, MissionBridgeError) as error:
            raise GovernanceError("governance-artifact-changed") from error

    return verify


def _run_producer(
    name: str,
    component: dict,
    artifact,
    project: _PrivateDirectory,
    ledger: Path | None = None,
    output = None,
) -> dict:
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    if os.environ.get("TMPDIR"):
        environment["TMPDIR"] = os.environ["TMPDIR"]
    retained_descriptors = tuple(
        dict.fromkeys(
            descriptor
            for descriptor in (
                getattr(artifact, "descriptor", None),
                *(getattr(artifact, "descriptors", ())),
                getattr(ledger, "descriptor", None),
                getattr(output, "descriptor", None),
            )
            if descriptor is not None
        )
    )
    previous_inheritable = {}
    try:
        if sys.platform == "darwin":
            for descriptor in retained_descriptors:
                previous_inheritable[descriptor] = os.get_inheritable(descriptor)
                os.set_inheritable(descriptor, True)
        with ExitStack() as stack:
            installed = (
                COMPONENT_ROOT
                / name
                / component["version"]
                / component["asset"]
            )
            executable_path = installed if installed.is_file() else BIN_DIR / component["asset"]
            executable = stack.enter_context(
                _open_verified_file(
                    executable_path, component["sha256"]
                )
            )
            launch_project = project
            retained_verifier = None
            if name == "ao-forge":
                launch_project, retained_verifier = _forge_runtime(stack, project)
            def producer_path(value) -> str:
                private = getattr(value, "private", None)
                path = (
                    private.path
                    if private is not None
                    else getattr(value, "directory", value).path
                )
                if os.name == "nt":
                    return str(path)
                return os.path.relpath(path, launch_project.project_path)

            arguments = [
                producer_path(artifact)
                if member == "{artifact}"
                else producer_path(ledger)
                if member == "{ledger}"
                else producer_path(output)
                if member == "{output}"
                else member
                for member in _PRODUCERS[name]
            ]
            path_verifier = _producer_path_verifier(artifact, ledger, output)
            path_verifier()
            try:
                raw = _run_output(
                    arguments,
                    launch_project,
                    executable,
                    timeout_seconds=10,
                    environment=environment,
                    retained_descriptors=retained_descriptors,
                    retained_verifier=retained_verifier,
                )
            finally:
                path_verifier()
            if retained_verifier is not None:
                retained_verifier()
    except MissionBridgeError as error:
        code = (
            "governance-producer-identity-mismatch"
            if error.code == "mission-identity-mismatch"
            else "governance-producer-failed"
        )
        raise GovernanceError(code) from error
    finally:
        for descriptor, inheritable in previous_inheritable.items():
            os.set_inheritable(descriptor, inheritable)
    if name == "ao-blueprint":
        try:
            output.accept_producer_write()
            authorization = output.read(_MAX_ENVELOPE)
        except (OSError, ValueError, MissionBridgeError) as error:
            raise GovernanceError("governance-producer-readback") from error
        return _readback(name, authorization)
    return _readback(name, raw)


def _strict_json_object(raw: bytes) -> dict:
    def unique_object(pairs):
        value = {}
        for name, member in pairs:
            if name in value:
                raise ValueError("duplicate JSON field")
            value[name] = member
        return value

    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError("ledger event is not an object")
    return value


def _validate_covenant_ledger(
    ledger: _RetainedFile,
    covenant: dict,
    verification: dict,
    run_id: str,
) -> tuple[dict, ...]:
    try:
        raw = ledger.read(_MAX_ARTIFACT)
        if not raw or not raw.endswith(b"\n"):
            raise ValueError("ledger must end with a newline")
        lines = raw[:-1].split(b"\n")
        if not lines or any(not line for line in lines):
            raise ValueError("ledger contains an empty event line")
        events = tuple(_strict_json_object(line) for line in lines)
        for sequence, event in enumerate(events, 1):
            if (
                event.get("schema_version") != "covenant.event.v1"
                or type(event.get("sequence")) is not int
                or event.get("sequence") != sequence
                or event.get("event_id") != f"event-{sequence:06d}"
                or event.get("run_id") != run_id
                or event.get("status") != "success"
                or not _DIGEST.fullmatch(event.get("event_hash", ""))
            ):
                raise ValueError("invalid authorized ledger event")
        if (
            events[0].get("type") != "run_started"
            or [
                index
                for index, event in enumerate(events)
                if event.get("type") == "run_started"
            ]
            != [0]
            or [
                index
                for index, event in enumerate(events)
                if event.get("type") == "run_finished"
            ]
            != [len(events) - 1]
            or verification.get("event_count") != len(events)
            or verification.get("last_event_hash") != events[-1].get("event_hash")
        ):
            raise ValueError("ledger is not a successful completed run")

        decisions = covenant.get("policy_decisions")
        if not isinstance(decisions, list):
            raise ValueError("invalid policy decisions")
        decisions_by_id = {}
        for decision in decisions:
            decision_id = decision.get("decision_id") if isinstance(decision, dict) else None
            if not isinstance(decision_id, str) or decision_id in decisions_by_id:
                raise ValueError("duplicate policy decision")
            decisions_by_id[decision_id] = decision
        events_by_id = {}
        for event in events:
            if event.get("type") != "policy_decided":
                continue
            decision_id = event.get("decision_id")
            if not isinstance(decision_id, str) or decision_id in events_by_id:
                raise ValueError("duplicate policy event")
            events_by_id[decision_id] = event
        if set(events_by_id) != set(decisions_by_id):
            raise ValueError("policy event set mismatch")
        for decision_id, decision in decisions_by_id.items():
            event = events_by_id[decision_id]
            if any(
                event.get(field) != decision.get(field)
                for field in ("task_id", "decision", "effect_type", "resource")
            ) or (
                not isinstance(event.get("message"), str)
                or not isinstance(decision.get("reason"), str)
                or event["message"] != decision["reason"]
            ) or (
                "approval_ticket_id" in event,
                event.get("approval_ticket_id"),
            ) != (
                "approval_ticket_id" in decision,
                decision.get("approval_ticket_id"),
            ):
                raise ValueError("policy event does not match evidence decision")
        return events
    except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise GovernanceError("governance-relationship-mismatch") from error


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
    ledger_digest: str,
    expires_at: datetime,
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
    artifact_manifest = covenant.get("artifact_manifest")
    input_snapshots = covenant.get("input_snapshots")
    decisions = covenant.get("policy_decisions")
    closure = covenant.get("closure_matrix")
    rows = closure.get("rows") if isinstance(closure, dict) else None
    verification = readbacks["ao-covenant"]
    if any(
        (
            covenant.get("schema_version") != "covenant.evidence-pack.v1",
            covenant.get("run_id") != artifacts.run_id,
            covenant.get("run_status") != "success",
            covenant.get("failures") != [],
            covenant.get("ledger_digest") != ledger_digest,
            not isinstance(covenant.get("contract_digest"), str)
            or not _DIGEST.fullmatch(covenant["contract_digest"]),
            not isinstance(artifact_manifest, list),
            not isinstance(input_snapshots, list),
            not isinstance(decisions, list) or not decisions,
            isinstance(decisions, list)
            and any(
                not isinstance(decision, dict)
                or decision.get("decision") != "allow"
                for decision in decisions
            ),
            not isinstance(closure, dict),
            isinstance(closure, dict)
            and (
                closure.get("schema_version") != "covenant.closure-matrix.v1"
                or closure.get("run_id") != artifacts.run_id
                or closure.get("contract_digest") != covenant.get("contract_digest")
                or closure.get("status") != "accepted"
            ),
            not isinstance(rows, list) or not rows,
            isinstance(rows, list)
            and (
                not any(isinstance(row, dict) and row.get("required") is True for row in rows)
                or any(
                    not isinstance(row, dict)
                    or (row.get("required") is True and row.get("status") != "closed")
                    for row in rows
                )
            ),
            verification.get("run_id") != artifacts.run_id,
            verification.get("ledger_digest") != ledger_digest,
            verification.get("artifact_count")
            != (len(artifact_manifest) if isinstance(artifact_manifest, list) else -1),
            verification.get("input_snapshot_count")
            != (len(input_snapshots) if isinstance(input_snapshots, list) else -1),
            len(verification.get("policy_explanations", ())) != len(decisions or ()),
            any(
                not isinstance(explanation, dict)
                or explanation.get("decision") != "allow"
                for explanation in verification.get("policy_explanations", ())
            ),
        )
    ):
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
        or not isinstance(value.get("requirement_ids"), list)
        or len(value["requirement_ids"]) != len(set(value["requirement_ids"]))
        or set(value["requirement_ids"])
        != {f"B{number:02d}" for number in range(1, 20)}
    ):
        raise GovernanceError("governance-requirements-mismatch")
    try:
        raw_manifest = REQUIREMENTS_MANIFEST.read_bytes()
        if len(raw_manifest) > _MAX_ARTIFACT:
            raise ValueError("requirements manifest too large")
        manifest = json.loads(raw_manifest)
        bindings = {
            row["id"]: row["test_id"]
            for row in manifest["requirements"]
            if row["id"].startswith("B")
        }
        if (
            set(bindings) != {f"B{number:02d}" for number in range(1, 20)}
            or not hmac.compare_digest(
                value["requirements_sha256"], _digest_bytes(raw_manifest)
            )
            or not hmac.compare_digest(
                value["test_bindings_sha256"], _digest_value(bindings)
            )
        ):
            raise ValueError("requirements binding mismatch")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise GovernanceError("governance-requirements-mismatch") from error
    return value, _digest_value(value)


def _create_private(path, data: bytes) -> None:
    descriptor = path.directory.directory_descriptor
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
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


def _stage_file(
    project: _PrivateDirectory, path: Path, root: tuple[str, ...], label: str
) -> tuple[_RetainedFile, str]:
    raw = _read_file(project, path, root)
    digest = _digest_bytes(raw)
    staged = _private_file(
        project, (*_PRIVATE_PARTS, "producer-input"), f"{label}-{digest}"
    )
    try:
        try:
            _create_private(staged, raw)
        except FileExistsError:
            if _read_private_bytes(staged, _MAX_ARTIFACT) != raw:
                raise GovernanceError("governance-artifact-changed")
        if _read_private_bytes(staged, _MAX_ARTIFACT) != raw:
            raise GovernanceError("governance-artifact-changed")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = (
            os.open(staged.name, flags, dir_fd=staged.directory.directory_descriptor)
            if staged.directory.directory_descriptor is not None
            else os.open(staged.path, flags)
        )
        parent_change = (
            os.fstat(staged.directory.directory_descriptor).st_ctime_ns
            if staged.directory.directory_descriptor is not None else 0
        )
        return _RetainedFile(
            staged, descriptor, parent_change, os.fstat(descriptor).st_ctime_ns, digest
        ), digest
    except BaseException:
        staged.close()
        raise


def _stage_directory(
    project: _PrivateDirectory, path: Path, root: tuple[str, ...]
) -> tuple[_RetainedDirectory, str]:
    digest = _directory_digest(project, path, root)
    destination_parts = (*_PRIVATE_PARTS, "producer-input", f"blueprint-{digest}")
    destination = _private_directory(project, *destination_parts)
    children = []
    child_directories = []
    try:
        for directory, names, filenames in os.walk(path, followlinks=False):
            current = Path(directory)
            relative_directory = current.relative_to(path).parts
            for name in names:
                child_directories.append(_private_directory(
                    project, *destination_parts, *relative_directory, name
                ))
            for name in filenames:
                source = current / name
                raw = _read_file(project, source, root)
                retained = _private_file(
                    project,
                    (*destination_parts, *relative_directory),
                    name,
                )
                try:
                    _create_private(retained, raw)
                except FileExistsError:
                    if _read_private_bytes(retained, _MAX_ARTIFACT) != raw:
                        retained.close()
                        raise GovernanceError("governance-artifact-changed")
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = (
                    os.open(retained.name, flags, dir_fd=retained.directory.directory_descriptor)
                    if retained.directory.directory_descriptor is not None
                    else os.open(retained.path, flags)
                )
                children.append(
                    _RetainedFile(
                        retained,
                        descriptor,
                        os.fstat(retained.directory.directory_descriptor).st_ctime_ns
                        if retained.directory.directory_descriptor is not None else 0,
                        os.fstat(descriptor).st_ctime_ns,
                        _digest_bytes(raw),
                    )
                )
                if os.name != "nt":
                    os.fchmod(descriptor, 0o400)
                    children[-1].refresh_identity(children[-1].digest)
        if not hmac.compare_digest(
            _directory_digest(project, destination.path, _PRIVATE_PARTS), digest
        ):
            raise GovernanceError("governance-artifact-changed")
        if os.name != "nt":
            for directory in (*child_directories, destination):
                os.fchmod(directory.directory_descriptor, 0o500)
        for child in children:
            child.refresh_parent_identity()
        change = (
            os.fstat(destination.directory_descriptor).st_ctime_ns
            if destination.directory_descriptor is not None else None
        )
        directory_changes = tuple(
            os.fstat(directory.directory_descriptor).st_ctime_ns
            if directory.directory_descriptor is not None else 0
            for directory in child_directories
        )
        return _RetainedDirectory(
            destination,
            digest,
            change,
            tuple(children),
            tuple(child_directories),
            directory_changes,
        ), digest
    except BaseException:
        for child in children:
            child.close()
        for directory in child_directories:
            directory.close()
        destination.close()
        raise


def _retained_output(pool: Pool, lease: AuthorityLease) -> _RetainedFile:
    output = _private_file(
        pool._office(lease.authority["office_id"]),
        ("work",),
        f"blueprint-{uuid.uuid4().hex}.json",
    )
    try:
        _create_private(output, b"")
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = (
            os.open(output.name, flags, dir_fd=output.directory.directory_descriptor)
            if output.directory.directory_descriptor is not None
            else os.open(output.path, flags)
        )
        parent_change = (
            os.fstat(output.directory.directory_descriptor).st_ctime_ns
            if output.directory.directory_descriptor is not None else 0
        )
        return _RetainedFile(
            output, descriptor, parent_change, os.fstat(descriptor).st_ctime_ns
        )
    except BaseException:
        output.close()
        raise


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
            if _read_private_bytes(staged, _MAX_ARTIFACT) != raw:
                raise GovernanceError("governance-workflow-mismatch")
        if _read_private_bytes(staged, _MAX_ARTIFACT) != raw:
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


def issue_witness(
    receipt: Path,
    objective: str,
    artifacts: GovernanceArtifacts,
    *,
    lifetime_seconds: int = 60,
    _lease: AuthorityLease | None = None,
    _authenticate=None,
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
    if _lease is None:
        try:
            return pool.issue_governance_witness(
                receipt, objective, artifacts, lifetime_seconds=lifetime_seconds
            )
        except PoolError as error:
            raise GovernanceError("governance-unauthorized") from error
    if type(_lease) is not AuthorityLease or not callable(_authenticate):
        raise GovernanceError("governance-invalid-request")
    try:
        with nullcontext(_lease) as lease:
            if lease.authority.get("task_digest") != _digest_bytes(
                objective.encode("utf-8")
            ):
                raise GovernanceError("governance-task-mismatch")
            project = _receipt_project_root(lease.authority)
            try:
                mission, route = _mission_route(lease, project, objective)
                if route.execution_candidate is not True:
                    raise GovernanceError("governance-route-not-executable")
                if route.atlas_required and artifacts.atlas_workgraph is None:
                    raise GovernanceError("governance-atlas-required")
                if not route.atlas_required and artifacts.atlas_workgraph is not None:
                    raise GovernanceError("governance-atlas-unexpected")
                components = _locked_components()
                workflow_digest = _stage_workflow(project, artifacts.workflow)
                target = _target(project, artifacts.target, lease.authority)
                native = {}
                artifact_digests = {}
                staged_blueprint, blueprint_pack_digest = _stage_directory(
                    project, artifacts.blueprint_pack, _ROOTS["ao-blueprint"]
                )
                source_paths = {
                    "ao-blueprint": artifacts.blueprint_pack,
                    "ao-atlas": artifacts.atlas_workgraph,
                    "ao-forge": artifacts.forge_goal_run,
                    "ao-covenant": artifacts.covenant_evidence,
                }
                staged_paths = {"ao-blueprint": staged_blueprint}
                for name in ("ao-atlas", "ao-forge", "ao-covenant"):
                    path = source_paths[name]
                    if path is None:
                        staged_paths[name] = None
                        continue
                    staged_paths[name], artifact_digests[name] = _stage_file(
                        project, path, _ROOTS[name], name
                    )
                    native[name], _ = _json_retained(staged_paths[name])
                staged_ledger, ledger_digest = _stage_file(
                    project,
                    artifacts.covenant_ledger,
                    _ROOTS["ao-covenant"],
                    "ao-covenant-ledger",
                )
                for retained in staged_paths.values():
                    if isinstance(retained, _RetainedFile):
                        retained.refresh_parent_identity()
                staged_ledger.refresh_parent_identity()
                authorization = _retained_output(pool, lease)
                readbacks = {}
                readbacks["ao-blueprint"] = _run_producer(
                    "ao-blueprint",
                    components["ao-blueprint"],
                    staged_blueprint,
                    project,
                    None,
                    authorization,
                )
                authorization.recheck()
                authorization_raw = authorization.read(_MAX_ENVELOPE)
                authorization.refresh_identity(_digest_bytes(authorization_raw))
                artifact_digests["ao-blueprint"] = _digest_bytes(
                    authorization_raw
                )
                native["ao-blueprint"] = readbacks["ao-blueprint"]
                for name in ("ao-atlas", "ao-forge", "ao-covenant"):
                    path = staged_paths[name]
                    if path is None:
                        continue
                    readbacks[name] = _run_producer(
                        name,
                        components[name],
                        path,
                        project,
                        staged_ledger if name == "ao-covenant" else None,
                    )
                    _, confirmed = _json_retained(path)
                    if not hmac.compare_digest(confirmed, artifact_digests[name]):
                        raise GovernanceError("governance-artifact-changed")
                _validate_covenant_ledger(
                    staged_ledger,
                    native["ao-covenant"],
                    readbacks["ao-covenant"],
                    artifacts.run_id,
                )
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
                created = _now().replace(microsecond=0)
                expires = created + timedelta(seconds=lifetime_seconds)
                covenant = _validate_relationships(
                    mission,
                    route,
                    lease.authority,
                    artifacts,
                    native,
                    readbacks,
                    ledger_digest,
                    expires,
                    objective,
                )
                staged_blueprint.recheck(project)
                for retained in staged_paths.values():
                    if isinstance(retained, _RetainedFile):
                        retained.recheck()
                staged_ledger.recheck()
                authorization.recheck()
                for name, path in source_paths.items():
                    if path is None:
                        continue
                    if name == "ao-blueprint":
                        confirmed = _directory_digest(project, path, _ROOTS[name])
                        expected = blueprint_pack_digest
                    else:
                        _, confirmed = _json_artifact(project, path, _ROOTS[name])
                        expected = artifact_digests[name]
                    if not hmac.compare_digest(confirmed, expected):
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
                        if staged_paths[name] is not None
                        else None
                    )
                    for name in _PRODUCERS
                }
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
                    "expires_at": _time(expires),
                    "payload_digest": "0" * 64,
                }
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
                    record = _private_file(project, _PRIVATE_PARTS, identifier + ".json")
                    seal = _private_file(project, _PRIVATE_PARTS, identifier + ".hmac")
                    created_record = False
                    try:
                        try:
                            _create_private(record, raw)
                            created_record = True
                            commitment = {
                                "schema_version": 1,
                                "witness_id": identifier,
                                "authority_digest": envelope["authority_digest"],
                                "artifact_sha256": _digest_bytes(raw),
                            }

                            def validated():
                                return commitment

                            tag = _authenticate(validated)
                            if tag is None:
                                _unlink_private(record)
                                created_record = False
                                continue
                            _create_private(seal, tag)
                        except FileExistsError:
                            if created_record:
                                _unlink_private(record)
                            continue
                        except BaseException:
                            if created_record:
                                _unlink_private(record)
                            raise
                        return record.path
                    finally:
                        seal.close()
                        record.close()
                raise GovernanceError("governance-envelope-collision")
            finally:
                authorization = locals().get("authorization")
                if authorization is not None:
                    try:
                        authorization.recheck()
                        if os.name == "nt":
                            private = authorization.private
                            authorization.close()
                            authorization = None
                            _unlink_private(private)
                        else:
                            _unlink_private(authorization.private)
                    except (OSError, MissionBridgeError) as error:
                        raise GovernanceError("governance-artifact-changed") from error
                    finally:
                        if authorization is not None:
                            authorization.close()
                for retained_name in ("staged_ledger", "staged_blueprint"):
                    retained = locals().get(retained_name)
                    if retained is not None:
                        retained.close()
                for retained in locals().get("staged_paths", {}).values():
                    if isinstance(retained, _RetainedFile):
                        retained.close()
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
    pool = _pool(lease.authority_path)
    try:
        lease.require_active()
    except PoolError as error:
        raise GovernanceError("governance-unauthorized") from error
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
        raw = _read_private_bytes(record, _MAX_ENVELOPE)
        supplied = _read_private_bytes(seal, 65)
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
        if not pool.consume_governance_witness(
            lease, value["witness_id"], _digest_bytes(raw), supplied
        ):
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
        if route.execution_candidate is not True:
            raise ValueError("route is not executable")
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
                _digest_bytes(_read_private_bytes(workflow, _MAX_ARTIFACT)),
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
                    if not pool._create_governance_marker(
                        lease,
                        "revoked",
                        value["witness_id"],
                        value["authority_digest"],
                    ) and not pool._governance_marker_exists(
                        lease,
                        "revoked",
                        value["witness_id"],
                        value["authority_digest"],
                    ):
                        raise GovernanceError("governance-envelope-mismatch")
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
    pool = _pool(lease.authority_path)
    revoked = _marker(project, value["witness_id"], ".revoked")
    consumed = _marker(project, value["witness_id"], ".consumed")
    try:
        if pool._governance_marker_exists(
            lease, "revoked", value["witness_id"], value["authority_digest"]
        ) or _private_exists(revoked):
            raise GovernanceError("governance-envelope-revoked")
        if pool._governance_marker_exists(
            lease, "consumed", value["witness_id"], value["authority_digest"]
        ) or _private_exists(consumed):
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
        consumed_by_pool = pool._consume_governance_execution(
            lease,
            value["witness_id"],
            value["authority_digest"],
        )
        if not consumed_by_pool:
            raise GovernanceError("governance-envelope-consumed")
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
            _freeze(value["producer_artifacts"]),
            value["requirements_evidence_digest"],
            _freeze(value["ao2"]),
            value["witness_id"],
            value["authority_digest"],
            value["request_digest"],
        )
    except BaseException:
        project.close()
        raise
    finally:
        revoked.close()
        consumed.close()
