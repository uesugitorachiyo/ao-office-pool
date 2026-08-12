import ctypes
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from internal.mission_bridge import (
    MissionBridgeError,
    MissionReadback,
    _load_authenticated_record,
    _private_directory,
    _private_file,
    _receipt_project_root,
    _write_private_bytes,
)
from internal.planning_routes import PlanningRouteError, RouteDecision, select_route


MAX_OUTPUT = 64 * 1024
COMPONENT_LOCK = Path(__file__).parents[1] / "manifests" / "components.lock.json"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z]+-[0-9a-f]{16}$")


class ExecutionError(RuntimeError):
    def __init__(self, code: str, record: Path | None = None):
        self.code = code
        self.record = record
        super().__init__(code)


@dataclass(frozen=True)
class BlueprintAuthorization:
    schema_version: int
    authorization_id: str
    mission_id: str
    objective_digest: str
    project_path: str
    decision: str
    authorization_digest: str


@dataclass(frozen=True)
class AtlasWorkgraph:
    schema_version: int
    workgraph_id: str
    mission_id: str
    objective_digest: str
    blueprint_digest: str
    project_path: str
    status: str
    workgraph_digest: str


@dataclass(frozen=True)
class ForgePacket:
    schema_version: int
    packet_id: str
    mission_id: str
    objective_digest: str
    blueprint_digest: str
    atlas_digest: str | None
    project_path: str
    target_path: str
    workflow_path: str
    workflow_sha256: str
    run_id: str
    packet_digest: str


@dataclass(frozen=True)
class CovenantDecision:
    schema_version: int
    decision_id: str
    forge_digest: str
    objective_digest: str
    project_path: str
    target_path: str
    ao2_sha256: str
    decision: str
    decision_digest: str


@dataclass(frozen=True)
class ExecutionRequest:
    task_text: str
    mission: MissionReadback
    route: RouteDecision
    authority_path: Path
    blueprint: BlueprintAuthorization
    atlas: AtlasWorkgraph | None
    forge: ForgePacket
    covenant: CovenantDecision
    ao2_path: Path
    ao2_sha256: str
    timeout_seconds: int = 30


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    record: Path
    request_digest: str
    diagnostics: dict


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _matches(pattern: re.Pattern, value) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _validated_evidence(value, expected_type: type, digest_field: str, *, code: str) -> dict:
    try:
        if type(value) is not expected_type:
            raise TypeError("wrong evidence type")
        record = asdict(value)
        supplied = record.pop(digest_field)
        valid = (
            record.pop("schema_version", None) == 1
            and _matches(_DIGEST, supplied)
            and hmac.compare_digest(
                supplied, _digest({"schema_version": 1, **record})
            )
        )
    except (KeyError, TypeError, ValueError):
        valid = False
    if not valid:
        raise ExecutionError(code)
    return {"schema_version": 1, **record, digest_field: supplied}


def _authenticated_mission(
    authority_path: Path, task_text: str
) -> tuple[MissionReadback, dict]:
    try:
        record, authority, _, project_path = _load_authenticated_record(
            authority_path, task_text
        )
    except MissionBridgeError as error:
        code = (
            "unauthorized"
            if error.code in {"invalid-request", "task-mismatch", "unauthorized"}
            else "mission-record-mismatch"
        )
        raise ExecutionError(code) from error
    return (
        MissionReadback(
            mission_id=record["mission_id"],
            objective_digest=record["objective_digest"],
            status=record["mission_status"],
            current_route=record["current_route"],
            record=project_path,
            resumed=True,
        ),
        authority,
    )


def _validate_mission(request: ExecutionRequest, authority: dict) -> None:
    mission = request.mission
    if (
        mission.objective_digest != "sha256:" + authority["task_digest"]
        or hashlib.sha256(request.task_text.encode()).hexdigest()
        != authority["task_digest"]
        or request.route.mission_id != mission.mission_id
        or request.route.objective_digest != mission.objective_digest
        or request.route.source_route != mission.current_route
    ):
        raise ExecutionError("mission-mismatch")
    try:
        if request.route != select_route(mission):
            raise ExecutionError("route-mismatch")
    except PlanningRouteError as error:
        raise ExecutionError("route-mismatch") from error


def _same_project(path: Path, authority: dict) -> bool:
    expected = Path(authority["project_path"])
    try:
        if os.name == "nt":
            from internal.windows_identity import open_identity, require_within

            actual = open_identity(path)
            root = open_identity(expected)
            require_within(actual, root)
            return actual == root
        actual = path.resolve(strict=True)
        root = expected.resolve(strict=True)
        return not path.is_symlink() and actual == root and actual.stat().st_ino == root.stat().st_ino
    except (OSError, ValueError):
        return False


def _validate_workflow(path: Path, project: Path) -> None:
    try:
        if path.name.startswith("-"):
            raise ValueError("option-shaped path")
        if os.name == "nt":
            from internal.windows_identity import open_identity, require_within

            identity = open_identity(path)
            require_within(identity, open_identity(project))
            if identity.is_directory or identity.link_count != 1:
                raise ValueError("unsafe workflow")
        else:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(project.resolve(strict=True)):
                raise ValueError("escaped workflow")
            current = project
            for part in resolved.relative_to(project.resolve(strict=True)).parts:
                current /= part
                if current.is_symlink():
                    raise ValueError("linked workflow")
            information = resolved.stat()
            if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
                raise ValueError("unsafe workflow")
    except (OSError, ValueError) as error:
        raise ExecutionError("unsafe-argument") from error


def _hash_descriptor(descriptor: int) -> str:
    result = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 64 * 1024):
        result.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return result.hexdigest()


def _locked_ao2_digest(executable: Path) -> str:
    try:
        value = json.loads(COMPONENT_LOCK.read_text(encoding="utf-8"))
        matches = [item for item in value["components"] if item.get("name") == "ao2"]
        if (
            value.get("schema_version") != 1
            or len(matches) != 1
            or matches[0].get("asset") != "ao2"
            or executable.name != ("ao2.exe" if os.name == "nt" else "ao2")
            or not _matches(_DIGEST, matches[0].get("sha256"))
        ):
            raise ValueError("wrong locked identity")
        return matches[0]["sha256"]
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ExecutionError("ao2-identity-mismatch") from error


@contextmanager
def _verified_executable(path: Path, expected_digest: str):
    descriptors = []
    temporary = None
    handle = None
    try:
        if not _matches(_DIGEST, expected_digest):
            raise ValueError("invalid digest")
        if os.name == "nt":
            import msvcrt
            from internal.windows_identity import (
                _BY_HANDLE_FILE_INFORMATION,
                _FILE_ATTRIBUTE_DIRECTORY,
                _FILE_ATTRIBUTE_REPARSE_POINT,
                _FILE_SHARE_READ,
                _INVALID_HANDLE_VALUE,
                _final_path,
                _kernel32,
                _native_path,
            )
            from internal.windows_paths import canonical_windows_path

            library = _kernel32()
            canonical = canonical_windows_path(str(path))
            handle = library.CreateFileW(
                _native_path(canonical), 0x80000000, _FILE_SHARE_READ, None, 3, 0x00200000, None
            )
            if handle == _INVALID_HANDLE_VALUE:
                raise ctypes.WinError(ctypes.get_last_error())
            information = _BY_HANDLE_FILE_INFORMATION()
            if not library.GetFileInformationByHandle(handle, ctypes.byref(information)):
                raise ctypes.WinError(ctypes.get_last_error())
            if (
                information.file_attributes & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
                or information.number_of_links != 1
                or _final_path(library, handle) != canonical
            ):
                raise ValueError("unsafe executable")
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            handle = None
            descriptors.append(descriptor)
            launch_path = path
        else:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            source = os.open(path, flags)
            descriptors.append(source)
            information = os.fstat(source)
            if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
                raise ValueError("unsafe executable")
            temporary = tempfile.TemporaryDirectory(prefix="ao2-verified-")
            launch_path = Path(temporary.name) / "ao2"
            target = os.open(launch_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o500)
            try:
                while chunk := os.read(source, 64 * 1024):
                    view = memoryview(chunk)
                    while view:
                        written = os.write(target, view)
                        view = view[written:]
                os.fsync(target)
            finally:
                os.close(target)
            os.lseek(source, 0, os.SEEK_SET)
            copied = os.open(launch_path, flags)
            descriptors.append(copied)
            copied_information = os.fstat(copied)
            if (
                not stat.S_ISREG(copied_information.st_mode)
                or copied_information.st_nlink != 1
                or _hash_descriptor(source) != _hash_descriptor(copied)
            ):
                raise ValueError("verified copy mismatch")
        if not hmac.compare_digest(_hash_descriptor(descriptors[0]), expected_digest):
            raise ValueError("digest mismatch")
        yield str(launch_path), tuple(descriptors)
    except (OSError, TypeError, ValueError) as error:
        raise ExecutionError("ao2-identity-mismatch") from error
    finally:
        if handle is not None:
            from internal.windows_identity import _kernel32

            _kernel32().CloseHandle(handle)
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None:
            temporary.cleanup()


def _read_process(process: subprocess.Popen, timeout: int) -> tuple[bytes, bytes]:
    buffers = [bytearray(), bytearray()]
    too_large = threading.Event()
    lock = threading.Lock()

    def drain(index, stream):
        while chunk := getattr(stream, "read1", stream.read)(8192):
            with lock:
                if sum(map(len, buffers)) + len(chunk) > MAX_OUTPUT:
                    too_large.set()
                    process.kill()
                    return
                buffers[index].extend(chunk)

    readers = [threading.Thread(target=drain, args=item, daemon=True) for item in enumerate((process.stdout, process.stderr))]
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        raise ExecutionError("execution-timeout") from error
    finally:
        for reader in readers:
            reader.join(timeout=5)
        process.stdout.close()
        process.stderr.close()
    if too_large.is_set():
        raise ExecutionError("execution-output-too-large")
    if process.returncode:
        raise ExecutionError("execution-failed")
    return bytes(buffers[0]), bytes(buffers[1])


def _diagnostics(stdout: bytes, run_id: str) -> dict:
    try:
        value = json.loads(stdout)
        if set(value) != {"status", "run_id"}:
            raise ValueError("unknown JSON diagnostics")
        status = value["status"]
    except json.JSONDecodeError:
        try:
            pairs = [line.split("=", 1) for line in stdout.decode("utf-8").splitlines()]
            if any(len(pair) != 2 for pair in pairs):
                raise ValueError("malformed native diagnostics")
            value = dict(pairs)
        except (UnicodeError, ValueError) as error:
            raise ExecutionError("invalid-execution-readback") from error
        if len(pairs) != len(value) or set(value) != {
            "run_id",
            "status",
            "run_record",
            "evidence_dir",
            "replay_state",
            "evidence_pack",
            "report",
        }:
            raise ExecutionError("invalid-execution-readback")
        status = {
            "Accepted": "accepted",
            "Rejected": "rejected",
            "Failed": "failed",
        }.get(value["status"])
    if value.get("run_id") != run_id or status not in {"accepted", "rejected", "failed"}:
        raise ExecutionError("invalid-execution-readback")
    return {"status": status, "run_id": run_id}


def _request_digest(request: ExecutionRequest, authority: dict) -> str:
    return _digest(
        {
            "mission_id": request.mission.mission_id,
            "objective_digest": request.mission.objective_digest,
            "route_digest": request.route.as_record()["decision_digest"],
            "authority_id": authority["authority_id"],
            "office_id": authority["office_id"],
            "generation": authority["generation"],
            "blueprint_digest": request.blueprint.authorization_digest,
            "atlas_digest": request.atlas.workgraph_digest if request.atlas else None,
            "forge_digest": request.forge.packet_digest,
            "covenant_digest": request.covenant.decision_digest,
            "ao2_sha256": request.ao2_sha256,
        }
    )


def _write_record(project, authority: dict, request: ExecutionRequest, request_digest: str, *, phase: str, diagnostics: dict, failure_code: str | None, exit_code: int | None) -> Path:
    value = {
        "schema_version": 1,
        "execution_id": "execution-" + uuid.uuid4().hex[:16],
        "phase": phase,
        "request_digest": request_digest,
        "mission_id": request.mission.mission_id,
        "objective_digest": request.mission.objective_digest,
        "route_digest": request.route.as_record()["decision_digest"],
        "authority_digest": hashlib.sha256(
            request.authority_path.read_bytes()
        ).hexdigest(),
        "office_id": authority["office_id"],
        "generation": authority["generation"],
        "project_path": authority["project_path"],
        "target_path": request.forge.target_path,
        "workflow_path": request.forge.workflow_path,
        "workflow_sha256": request.forge.workflow_sha256,
        "run_id": request.forge.run_id,
        "blueprint_digest": request.blueprint.authorization_digest,
        "atlas_digest": request.atlas.workgraph_digest if request.atlas else None,
        "forge_digest": request.forge.packet_digest,
        "covenant_digest": request.covenant.decision_digest,
        "ao2_sha256": request.ao2_sha256,
        "diagnostics": diagnostics,
        "exit_code": exit_code,
        "failure_code": failure_code,
    }
    value["record_digest"] = _digest(value)
    record = _private_file(
        project,
        (".ao", "evidence", "office-pool"),
        value["execution_id"] + ".json",
    )
    try:
        _write_private_bytes(record, _canonical(value) + b"\n")
        return record.path
    finally:
        record.close()


def execute(request: ExecutionRequest) -> ExecutionResult:
    if (
        type(request) is not ExecutionRequest
        or type(request.task_text) is not str
        or not request.task_text
        or not isinstance(request.authority_path, Path)
        or not isinstance(request.ao2_path, Path)
        or type(request.timeout_seconds) is not int
        or not 1 <= request.timeout_seconds <= 30
    ):
        raise ExecutionError("invalid-request")
    try:
        pool_root = request.authority_path.parents[2]
        pool_metadata = json.loads((pool_root / "pool.json").read_text(encoding="utf-8"))
        mission, authority = _authenticated_mission(
            request.authority_path, request.task_text
        )
    except (OSError, IndexError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ExecutionError("unauthorized") from error
    request = replace(request, mission=mission)
    _validate_mission(request, authority)
    blueprint = _validated_evidence(
        request.blueprint,
        BlueprintAuthorization,
        "authorization_digest",
        code="blueprint-mismatch",
    )
    if (
        not _matches(_IDENTIFIER, blueprint["authorization_id"])
        or blueprint["decision"] != "authorized"
        or blueprint["mission_id"] != request.mission.mission_id
        or blueprint["objective_digest"] != request.mission.objective_digest
        or blueprint["project_path"] != authority["project_path"]
    ):
        raise ExecutionError("blueprint-mismatch")
    atlas = None
    if request.route.atlas_required:
        if request.atlas is None:
            raise ExecutionError("atlas-required")
        atlas = _validated_evidence(
            request.atlas,
            AtlasWorkgraph,
            "workgraph_digest",
            code="atlas-mismatch",
        )
        if (
            not _matches(_IDENTIFIER, atlas["workgraph_id"])
            or atlas["status"] != "validated"
            or atlas["mission_id"] != request.mission.mission_id
            or atlas["objective_digest"] != request.mission.objective_digest
            or atlas["blueprint_digest"] != request.blueprint.authorization_digest
            or atlas["project_path"] != authority["project_path"]
        ):
            raise ExecutionError("atlas-mismatch")
    elif request.atlas is not None:
        raise ExecutionError("atlas-unexpected")
    if request.route.route not in {"ao-forge", "ao-atlas"}:
        raise ExecutionError("route-not-executable")
    forge = _validated_evidence(
        request.forge, ForgePacket, "packet_digest", code="forge-mismatch"
    )
    expected_atlas = request.atlas.workgraph_digest if request.atlas else None
    if (
        not _matches(_IDENTIFIER, forge["packet_id"])
        or forge["mission_id"] != request.mission.mission_id
        or forge["objective_digest"] != request.mission.objective_digest
        or forge["blueprint_digest"] != request.blueprint.authorization_digest
        or forge["atlas_digest"] != expected_atlas
        or forge["project_path"] != authority["project_path"]
        or not _matches(_IDENTIFIER, forge["run_id"])
        or not isinstance(forge["target_path"], str)
        or not isinstance(forge["workflow_path"], str)
        or not _matches(_DIGEST, forge["workflow_sha256"])
    ):
        raise ExecutionError("forge-mismatch")
    covenant = asdict(request.covenant)
    if (
        covenant.get("forge_digest") != request.forge.packet_digest
        or covenant.get("objective_digest") != request.mission.objective_digest
        or covenant.get("project_path") != authority["project_path"]
        or covenant.get("target_path") != request.forge.target_path
        or covenant.get("ao2_sha256") != request.ao2_sha256
        or covenant.get("decision") != "authorized"
    ):
        raise ExecutionError("covenant-mismatch")
    covenant = _validated_evidence(
        request.covenant,
        CovenantDecision,
        "decision_digest",
        code="covenant-mismatch",
    )
    project_path = Path(authority["project_path"])
    target = Path(forge["target_path"])
    workflow = Path(forge["workflow_path"])
    if forge["project_path"] != forge["target_path"] or not _same_project(target, authority):
        raise ExecutionError("target-mismatch")
    _validate_workflow(workflow, project_path)
    try:
        actual_workflow_digest = hashlib.sha256(workflow.read_bytes()).hexdigest()
    except OSError as error:
        raise ExecutionError("forge-mismatch") from error
    if not hmac.compare_digest(actual_workflow_digest, forge["workflow_sha256"]):
        raise ExecutionError("forge-mismatch")
    try:
        expected_executable = (
            request.authority_path.parents[2]
            / "offices"
            / authority["office_id"]
            / "runtime"
            / "versions"
            / pool_metadata["runtime_version"]
            / ("ao2.exe" if os.name == "nt" else "ao2")
        )
        if request.ao2_path.resolve(strict=True) != expected_executable.resolve(strict=True):
            raise ValueError("wrong office runtime")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ExecutionError("ao2-identity-mismatch") from error
    request_digest = _request_digest(request, authority)
    locked_digest = _locked_ao2_digest(request.ao2_path)
    if not hmac.compare_digest(locked_digest, request.ao2_sha256):
        raise ExecutionError("ao2-identity-mismatch")
    project = _receipt_project_root(authority)
    try:
        with _verified_executable(request.ao2_path, locked_digest) as (launch_path, descriptors):
            project.require_current_paths()
            try:
                process = subprocess.Popen(
                    [
                        launch_path,
                        "run",
                        str(workflow),
                        "--target",
                        str(target),
                        "--run-id",
                        forge["run_id"],
                    ],
                    cwd=project.project_launch_path,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    pass_fds=descriptors if os.name != "nt" else (),
                )
            except OSError as error:
                raise ExecutionError("execution-launch-failed") from error
            try:
                stdout, stderr = _read_process(process, request.timeout_seconds)
                diagnostics = _diagnostics(stdout, forge["run_id"])
            except ExecutionError as error:
                record = _write_record(project, authority, request, request_digest, phase="failed", diagnostics={}, failure_code=error.code, exit_code=process.returncode)
                raise ExecutionError(error.code, record) from error
        record = _write_record(project, authority, request, request_digest, phase="completed", diagnostics=diagnostics, failure_code=None, exit_code=0)
        return ExecutionResult(diagnostics["status"], record, request_digest, diagnostics)
    finally:
        project.close()
