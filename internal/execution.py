import hashlib
import hmac
import json
import os
import stat
import sys
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from internal.governance_witness import (
    GovernanceError,
    GovernedExecution,
    _consume_witness,
    _create_private,
    _unlink_private,
)
from internal.mission_bridge import (
    MissionBridgeError,
    _hash_descriptor,
    _open_retained_file,
    _open_verified_file,
    _private_file,
    _run_output,
    _write_private_bytes,
)
from internal.pool import Pool, PoolError


MAX_WORKFLOW = 64 * 1024 * 1024


class ExecutionError(RuntimeError):
    def __init__(self, code: str, record: Path | None = None):
        self.code = code
        self.record = record
        super().__init__(code)


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


def _execution_environment() -> dict[str, str]:
    if os.name == "nt":
        environment = {}
        for name in ("SystemRoot", "WINDIR", "TEMP", "TMP"):
            if os.environ.get(name):
                environment[name] = os.environ[name]
        return environment
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    if os.environ.get("TMPDIR"):
        environment["TMPDIR"] = os.environ["TMPDIR"]
    return environment


def _pool(receipt: Path) -> Pool:
    try:
        root = receipt.parents[2]
        metadata = json.loads((root / "pool.json").read_text(encoding="utf-8"))
        return Pool(root, runtime_version=metadata["runtime_version"])
    except (OSError, IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ExecutionError("unauthorized") from error


def _descriptor_bytes(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    size = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, MAX_WORKFLOW + 1 - size))
        if not chunk:
            os.lseek(descriptor, 0, os.SEEK_SET)
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_WORKFLOW:
            raise ExecutionError("workflow-identity-mismatch")


def _workflow_identity(descriptor: int, digest: str) -> tuple[int, int, int, int, int]:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
    ):
        raise ExecutionError("workflow-identity-mismatch")
    if hasattr(os, "pread"):
        calculated = hashlib.sha256()
        offset = 0
        while chunk := os.pread(descriptor, 64 * 1024, offset):
            calculated.update(chunk)
            offset += len(chunk)
        calculated = calculated.hexdigest()
    else:
        calculated = _hash_descriptor(descriptor)
    after = os.fstat(descriptor)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        any(getattr(before, field) != getattr(after, field) for field in stable_fields)
        or not stat.S_ISREG(after.st_mode)
        or after.st_nlink != 1
        or not hmac.compare_digest(calculated, digest)
    ):
        raise ExecutionError("workflow-identity-mismatch")
    return (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _sealed_workflow_descriptor(raw: bytes, digest: str) -> int | None:
    if not sys.platform.startswith("linux"):
        return None
    if not (
        hasattr(os, "memfd_create")
        and hasattr(os, "MFD_ALLOW_SEALING")
        and Path("/proc/self/fd").is_dir()
    ):
        raise ExecutionError("workflow-identity-mismatch")
    try:
        import fcntl
    except ImportError as error:
        raise ExecutionError("workflow-identity-mismatch") from error

    seal_names = (
        "F_ADD_SEALS",
        "F_GET_SEALS",
        "F_SEAL_WRITE",
        "F_SEAL_GROW",
        "F_SEAL_SHRINK",
        "F_SEAL_SEAL",
    )
    if not all(hasattr(fcntl, name) for name in seal_names):
        raise ExecutionError("workflow-identity-mismatch")
    required = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    descriptor = None
    readonly = None
    try:
        descriptor = os.memfd_create(
            "ao2-workflow", getattr(os, "MFD_CLOEXEC", 0) | os.MFD_ALLOW_SEALING
        )
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("workflow snapshot write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, required)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & required != required:
            raise OSError("workflow snapshot sealing failed")
        if not hmac.compare_digest(_hash_descriptor(descriptor), digest):
            raise ExecutionError("workflow-identity-mismatch")
        readonly = os.open(f"/proc/self/fd/{descriptor}", os.O_RDONLY)
        source = os.fstat(descriptor)
        retained = os.fstat(readonly)
        if (
            not stat.S_ISREG(retained.st_mode)
            or (source.st_dev, source.st_ino) != (retained.st_dev, retained.st_ino)
            or not hmac.compare_digest(_hash_descriptor(readonly), digest)
        ):
            raise ExecutionError("workflow-identity-mismatch")
        retained_descriptor = readonly
        readonly = None
        return retained_descriptor
    except ExecutionError:
        raise
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise ExecutionError("workflow-identity-mismatch") from error
    except BaseException:
        raise
    finally:
        if readonly is not None:
            try:
                os.close(readonly)
            except BaseException:
                pass
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException:
                pass


@contextmanager
def _retained_workflow(governed: GovernedExecution):
    source = _private_file(
        governed.target,
        (".ao", "governance", "office-pool", "workflows"),
        governed.workflow_digest,
    )
    staged = _private_file(
        governed.target,
        (".ao", "governance", "office-pool", "staging"),
        f"{governed.workflow_digest}-{uuid.uuid4().hex}",
    )
    staged_created = False
    try:
        with _open_retained_file(source) as source_descriptor:
            raw = _descriptor_bytes(source_descriptor)
            if not hmac.compare_digest(
                _hash_descriptor(source_descriptor), governed.workflow_digest
            ):
                raise ExecutionError("workflow-identity-mismatch")
            _create_private(staged, raw)
            staged_created = True
            with _open_retained_file(staged) as created_descriptor:
                if os.name != "nt":
                    os.fchmod(created_descriptor, 0o400)
                    os.fsync(created_descriptor)
            with _open_retained_file(staged) as snapshot_descriptor:
                snapshot_identity = _workflow_identity(
                    snapshot_descriptor, governed.workflow_digest
                )
                if os.name != "nt" and stat.S_IMODE(
                    os.fstat(snapshot_descriptor).st_mode
                ) != 0o400:
                    raise ExecutionError("workflow-identity-mismatch")
                sealed_descriptor = _sealed_workflow_descriptor(
                    raw, governed.workflow_digest
                )
                launch_descriptor = sealed_descriptor or snapshot_descriptor

                def verify_retained() -> None:
                    try:
                        if sealed_descriptor is not None:
                            if not hmac.compare_digest(
                                _hash_descriptor(sealed_descriptor),
                                governed.workflow_digest,
                            ):
                                raise MissionBridgeError(
                                    "workflow-identity-mismatch"
                                )
                            return
                        if _workflow_identity(
                            snapshot_descriptor, governed.workflow_digest
                        ) != snapshot_identity:
                            raise MissionBridgeError("workflow-identity-mismatch")
                    except ExecutionError as error:
                        raise MissionBridgeError(
                            "workflow-identity-mismatch"
                        ) from error

                try:
                    if os.name == "nt":
                        launch_path = str(staged.path)
                    elif sys.platform == "darwin":
                        launch_path = f"/dev/fd/{launch_descriptor}"
                    else:
                        if not Path("/proc/self/fd").is_dir():
                            raise ExecutionError("execution-launch-failed")
                        launch_path = f"/proc/self/fd/{launch_descriptor}"
                    yield launch_path, (launch_descriptor,), verify_retained
                finally:
                    if sealed_descriptor is not None:
                        os.close(sealed_descriptor)
    except ExecutionError:
        raise
    except (MissionBridgeError, OSError, TypeError, ValueError) as error:
        raise ExecutionError("workflow-identity-mismatch") from error
    finally:
        failure = sys.exception()
        cleanup_error = None
        if staged_created:
            try:
                _unlink_private(staged)
            except FileNotFoundError:
                pass
            except BaseException as error:
                if failure is None:
                    cleanup_error = error
        for private in (staged, source):
            try:
                private.close()
            except BaseException as error:
                if failure is None and cleanup_error is None:
                    cleanup_error = error
        if failure is None and cleanup_error is not None:
            if isinstance(cleanup_error, Exception):
                raise ExecutionError("workflow-identity-mismatch") from cleanup_error
            raise cleanup_error


def _ao2_path(receipt: Path, authority: dict, governed: GovernedExecution) -> Path:
    try:
        root = receipt.parents[2]
        runtime_version = json.loads(
            (root / "pool.json").read_text(encoding="utf-8")
        )["runtime_version"]
        if governed.ao2 != {
            "name": "ao2",
            "commit": governed.ao2["commit"],
            "asset": "ao2",
            "sha256": governed.ao2["sha256"],
        }:
            raise ValueError("invalid AO2 identity")
        return (
            root
            / "offices"
            / authority["office_id"]
            / "runtime"
            / "versions"
            / runtime_version
            / ("ao2.exe" if os.name == "nt" else "ao2")
        )
    except (OSError, IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ExecutionError("ao2-identity-mismatch") from error


@contextmanager
def _retained_windows_project(project):
    if os.name != "nt":
        yield
        return
    from internal.mission_bridge import _open_windows_directory
    from internal.windows_identity import _kernel32

    handle = _open_windows_directory(project.project_path, share_write=False)
    try:
        yield
    finally:
        _kernel32().CloseHandle(handle)


def _diagnostics(stdout: bytes, run_id: str) -> dict:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        try:
            pairs = [
                line.split("=", 1)
                for line in stdout.decode("utf-8").splitlines()
            ]
            if any(len(pair) != 2 for pair in pairs):
                raise ValueError("malformed native diagnostics")
            value = dict(pairs)
            if (
                len(pairs) != len(value)
                or set(value)
                != {
                    "run_id",
                    "status",
                    "run_record",
                    "evidence_dir",
                    "replay_state",
                    "evidence_pack",
                    "report",
                }
                or any(type(member) is not str for member in value.values())
            ):
                raise ValueError("invalid native diagnostics")
            status = {
                "Accepted": "accepted",
                "Rejected": "rejected",
                "Failed": "failed",
            }.get(value["status"])
        except (AttributeError, TypeError, UnicodeError, ValueError) as error:
            raise ExecutionError("invalid-execution-readback") from error
    except (AttributeError, TypeError, UnicodeError, ValueError) as error:
        raise ExecutionError("invalid-execution-readback") from error
    else:
        if (
            type(value) is not dict
            or set(value) != {"status", "run_id"}
            or type(value.get("status")) is not str
            or type(value.get("run_id")) is not str
        ):
            raise ExecutionError("invalid-execution-readback")
        status = value["status"]
    if value.get("run_id") != run_id or status not in {
        "accepted",
        "rejected",
        "failed",
    }:
        raise ExecutionError("invalid-execution-readback")
    return {"status": status, "run_id": run_id}


def _artifact_digest(governed: GovernedExecution, name: str) -> str | None:
    artifact = governed.producer_artifacts[name]
    return artifact["artifact_sha256"] if artifact is not None else None


def _write_record(
    project,
    authority: dict,
    authority_bytes: bytes,
    governed: GovernedExecution,
    *,
    phase: str,
    diagnostics: dict,
    failure_code: str | None,
    exit_code: int | None,
) -> Path:
    workflow_path = project.joinpath(
        ".ao",
        "governance",
        "office-pool",
        "workflows",
        governed.workflow_digest,
    )
    value = {
        "schema_version": 1,
        "execution_id": "execution-" + uuid.uuid4().hex[:16],
        "phase": phase,
        "request_digest": governed.request_digest,
        "mission_id": governed.mission.mission_id,
        "objective_digest": governed.mission.objective_digest,
        "route_digest": governed.route.as_record()["decision_digest"],
        "authority_digest": hashlib.sha256(authority_bytes).hexdigest(),
        "office_id": authority["office_id"],
        "generation": authority["generation"],
        "project_path": str(project.project_path),
        "target_path": str(project.project_path),
        "workflow_path": str(workflow_path),
        "workflow_sha256": governed.workflow_digest,
        "run_id": governed.run_id,
        "blueprint_digest": _artifact_digest(governed, "ao-blueprint"),
        "atlas_digest": _artifact_digest(governed, "ao-atlas"),
        "forge_digest": _artifact_digest(governed, "ao-forge"),
        "covenant_digest": _artifact_digest(governed, "ao-covenant"),
        "ao2_sha256": governed.ao2["sha256"],
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


def _process_error_code(error: MissionBridgeError) -> str:
    if error.code == "workflow-identity-mismatch":
        return error.code
    return {
        "timeout": "execution-timeout",
        "output-too-large": "execution-output-too-large",
        "failed": "execution-failed",
    }.get(error.reason, "execution-launch-failed")


def _execute_governed(receipt, lease, governed, timeout_seconds) -> ExecutionResult:
    executable_path = _ao2_path(receipt, lease.authority, governed)
    try:
        executable_manager = _open_verified_file(
            executable_path, governed.ao2["sha256"]
        )
        with (
            executable_manager as executable,
            _retained_workflow(governed) as workflow,
            _retained_windows_project(governed.target),
        ):
            arguments = [
                "run",
                workflow[0],
                "--target",
                ".",
                "--run-id",
                governed.run_id,
            ]
            try:
                stdout = _run_output(
                    arguments,
                    governed.target,
                    executable,
                    timeout_seconds=timeout_seconds,
                    environment=_execution_environment(),
                    retained_descriptors=workflow[1],
                    retained_verifier=workflow[2],
                )
                diagnostics = _diagnostics(stdout, governed.run_id)
            except (ExecutionError, MissionBridgeError) as error:
                code = (
                    error.code
                    if isinstance(error, ExecutionError)
                    else _process_error_code(error)
                )
                record = _write_record(
                    governed.target,
                    lease.authority,
                    lease.authority_bytes,
                    governed,
                    phase="failed",
                    diagnostics={},
                    failure_code=code,
                    exit_code=None,
                )
                raise ExecutionError(code, record) from error
    except ExecutionError:
        raise
    except MissionBridgeError as error:
        raise ExecutionError("ao2-identity-mismatch") from error
    record = _write_record(
        governed.target,
        lease.authority,
        lease.authority_bytes,
        governed,
        phase="completed",
        diagnostics=diagnostics,
        failure_code=None,
        exit_code=0,
    )
    return ExecutionResult(
        diagnostics["status"],
        record,
        governed.request_digest,
        diagnostics,
    )


def execute(
    receipt: Path,
    envelope: Path,
    *,
    timeout_seconds: int = 30,
) -> ExecutionResult:
    if (
        not isinstance(receipt, Path)
        or not isinstance(envelope, Path)
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 30
    ):
        raise ExecutionError("invalid-request")
    try:
        pool = _pool(receipt)
        with pool.authority_lease(receipt) as lease:
            governed = _consume_witness(lease, envelope)
            try:
                return _execute_governed(
                    receipt, lease, governed, timeout_seconds
                )
            finally:
                governed.target.close()
    except ExecutionError:
        raise
    except GovernanceError as error:
        raise ExecutionError(error.code) from error
    except PoolError as error:
        raise ExecutionError("unauthorized") from error
