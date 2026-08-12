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
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from internal.pool import Pool, PoolError
from internal.transactions import atomic_write_bytes


MISSION_EXECUTABLE = Path(__file__).parents[1] / ".local/bin/ao-mission"
COMPONENT_LOCK = Path(__file__).parents[1] / "manifests/components.lock.json"
MISSION_SCHEMA = Path(__file__).parents[1] / "schemas/mission-record.schema.json"
MAX_OUTPUT = 64 * 1024
_AUTHORITY_FLAGS = (
    "executes_work",
    "approves_policy",
    "calls_providers",
    "publishes",
    "deploys",
    "mutates_repositories",
)
_MISSION_ID = re.compile(r"^mission-[0-9a-f]{16}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OBJECTIVE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


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


@dataclass
class _VerifiedExecutable:
    path: Path
    descriptors: tuple[int, ...]
    temporary: tempfile.TemporaryDirectory | None = None


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _validate_schema(value: object, schema_path: Path) -> dict:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("schema unavailable") from error

    def validate(item: object, rule: dict) -> None:
        kind = rule.get("type")
        if kind == "object":
            if not isinstance(item, dict):
                raise ValueError("object required")
            properties = rule.get("properties", {})
            required = rule.get("required", [])
            if not isinstance(properties, dict) or not isinstance(required, list):
                raise ValueError("invalid schema")
            if any(name not in item for name in required):
                raise ValueError("required property missing")
            if rule.get("additionalProperties") is False and set(item) - set(properties):
                raise ValueError("additional property")
            for name, member in item.items():
                if name in properties:
                    validate(member, properties[name])
        elif kind == "string":
            if not isinstance(item, str):
                raise ValueError("string required")
            if len(item) < rule.get("minLength", 0) or len(item) > rule.get(
                "maxLength", len(item)
            ):
                raise ValueError("string length")
            pattern = rule.get("pattern")
            if pattern is not None and re.search(pattern, item) is None:
                raise ValueError("string pattern")
        elif kind == "integer":
            if type(item) is not int:
                raise ValueError("integer required")
            if "minimum" in rule and item < rule["minimum"]:
                raise ValueError("integer minimum")
        elif kind is not None:
            raise ValueError("unsupported schema type")
        if "const" in rule:
            expected = rule["const"]
            if item != expected or isinstance(item, bool) != isinstance(expected, bool):
                raise ValueError("const mismatch")
        if "enum" in rule and item not in rule["enum"]:
            raise ValueError("enum mismatch")

    validate(value, schema)
    return value


def _authority(receipt: Path, objective: str) -> tuple[dict, bytes, Path]:
    if not isinstance(receipt, Path) or not isinstance(objective, str) or not objective:
        raise MissionBridgeError("invalid-request")
    try:
        pool = Pool(receipt.parents[2])
        pool.resume(receipt)
        raw = receipt.read_bytes()
        authority = json.loads(raw)
        project = Path(authority["project_path"])
    except (
        OSError,
        IndexError,
        KeyError,
        PoolError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise MissionBridgeError("unauthorized") from error
    if authority.get("task_digest") != _digest(objective.encode("utf-8")):
        raise MissionBridgeError("task-mismatch")
    return authority, raw, project


def _project_identity(project: Path):
    if os.name == "nt":
        from internal.windows_identity import open_identity, require_within

        identity = open_identity(project)
        require_within(identity, identity)
        if not identity.is_directory or identity.traversed_reparse_point:
            raise ValueError("unsafe project")
        return identity
    resolved = project.resolve(strict=True)
    information = project.lstat()
    if project.is_symlink() or not stat.S_ISDIR(information.st_mode):
        raise ValueError("unsafe project")
    return resolved, information.st_dev, information.st_ino


def _validate_private_path(path: Path, project: Path, *, directory: bool) -> None:
    root = _project_identity(project)
    if os.name == "nt":
        from internal.windows_identity import open_identity, require_within

        identity = open_identity(path)
        require_within(identity, root)
        if identity.is_directory != directory or identity.traversed_reparse_point:
            raise ValueError("unsafe private path")
        if not directory and identity.link_count != 1:
            raise ValueError("unsafe private file")
        return
    information = path.lstat()
    if stat.S_ISLNK(information.st_mode):
        raise ValueError("linked private path")
    if directory != stat.S_ISDIR(information.st_mode):
        if directory or not stat.S_ISREG(information.st_mode):
            raise ValueError("wrong private path kind")
    if not directory and information.st_nlink != 1:
        raise ValueError("linked private file")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root[0]):
        raise ValueError("private path escaped project")


def _private_directory(project: Path, *parts: str) -> Path:
    try:
        _project_identity(project)
        current = project
        for part in parts:
            if not isinstance(part, str) or not part or part in {".", ".."} or "/" in part or "\\" in part:
                raise ValueError("unsafe private segment")
            current = current / part
            try:
                current.mkdir()
            except FileExistsError:
                pass
            _validate_private_path(current, project, directory=True)
        return current
    except (OSError, TypeError, ValueError) as error:
        raise MissionBridgeError("mission-storage-unsafe") from error


def _private_file(project: Path, directories: tuple[str, ...], name: str) -> Path:
    if not isinstance(name, str) or not name or "/" in name or "\\" in name:
        raise MissionBridgeError("mission-storage-unsafe")
    parent = _private_directory(project, *directories)
    path = parent / name
    if path.exists() or path.is_symlink():
        try:
            _validate_private_path(path, project, directory=False)
        except (OSError, TypeError, ValueError) as error:
            raise MissionBridgeError("mission-storage-unsafe") from error
    return path


def _write_authenticated(path: Path, value: dict, key: bytes, schema: Path) -> None:
    _validate_schema(value, schema)
    raw = _canonical_bytes(value)
    tag = hmac.new(key, raw, hashlib.sha256).hexdigest().encode("ascii") + b"\n"
    atomic_write_bytes(path, raw)
    atomic_write_bytes(path.with_suffix(".hmac"), tag)
    _validate_private_path(path, Path(value["project_path"]), directory=False)
    _validate_private_path(path.with_suffix(".hmac"), Path(value["project_path"]), directory=False)


def _read_authenticated(path: Path, key: bytes, schema: Path, project: Path) -> dict:
    seal = path.with_suffix(".hmac")
    try:
        _validate_private_path(path, project, directory=False)
        _validate_private_path(seal, project, directory=False)
        raw = path.read_bytes()
        supplied = seal.read_text(encoding="ascii")
        expected = hmac.new(key, raw, hashlib.sha256).hexdigest() + "\n"
        if not hmac.compare_digest(supplied, expected):
            raise ValueError("authentication mismatch")
        value = json.loads(raw)
        return _validate_schema(value, schema)
    except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise MissionBridgeError("mission-record-mismatch") from error


def _hash_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _locked_component() -> dict:
    try:
        lock = json.loads(COMPONENT_LOCK.read_text(encoding="utf-8"))
        component = next(
            item for item in lock["components"] if item.get("name") == "ao-mission"
        )
        if component["asset"] != MISSION_EXECUTABLE.name or not _DIGEST.fullmatch(
            component["sha256"]
        ):
            raise ValueError("wrong locked identity")
        return component
    except (OSError, KeyError, StopIteration, TypeError, ValueError, json.JSONDecodeError) as error:
        raise MissionBridgeError("mission-identity-mismatch") from error


@contextmanager
def _open_verified_executable():
    component = _locked_component()
    descriptors = []
    temporary = None
    try:
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
            handle = library.CreateFileW(
                _native_path(canonical_windows_path(str(MISSION_EXECUTABLE))),
                0x80000000,
                _FILE_SHARE_READ,
                None,
                3,
                0x00200000,
                None,
            )
            if handle == _INVALID_HANDLE_VALUE:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                information = _BY_HANDLE_FILE_INFORMATION()
                if not library.GetFileInformationByHandle(handle, ctypes.byref(information)):
                    raise ctypes.WinError(ctypes.get_last_error())
                if (
                    information.file_attributes
                    & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
                    or information.number_of_links != 1
                    or _final_path(library, handle)
                    != canonical_windows_path(str(MISSION_EXECUTABLE))
                ):
                    raise ValueError("unsafe executable")
                descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
                handle = None
                descriptors.append(descriptor)
            finally:
                if handle is not None:
                    library.CloseHandle(handle)
            launch_path = MISSION_EXECUTABLE
        else:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            source = os.open(MISSION_EXECUTABLE, flags)
            descriptors.append(source)
            information = os.fstat(source)
            if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
                raise ValueError("unsafe executable")
            temporary = tempfile.TemporaryDirectory(prefix="ao-mission-verified-")
            os.chmod(temporary.name, 0o700)
            launch_path = Path(temporary.name) / MISSION_EXECUTABLE.name
            target = os.open(launch_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o500)
            try:
                while True:
                    chunk = os.read(source, 64 * 1024)
                    if not chunk:
                        break
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
            copied_info = os.fstat(copied)
            if not stat.S_ISREG(copied_info.st_mode) or copied_info.st_nlink != 1:
                raise ValueError("unsafe verified copy")
            if _hash_descriptor(source) != _hash_descriptor(copied):
                raise ValueError("verified copy mismatch")
        if _hash_descriptor(descriptors[0]) != component["sha256"]:
            raise ValueError("digest mismatch")
        yield _VerifiedExecutable(Path(launch_path), tuple(descriptors), temporary)
    except (OSError, TypeError, ValueError) as error:
        raise MissionBridgeError("mission-identity-mismatch") from error
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None:
            temporary.cleanup()


def _run(
    arguments: list[str], project: Path, executable: _VerifiedExecutable
) -> dict:
    try:
        process = subprocess.Popen(
            [str(executable.path), *arguments],
            cwd=project,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise MissionBridgeError("mission-launch-failed") from error
    buffers = [bytearray(), bytearray()]
    lock = threading.Lock()
    too_large = threading.Event()

    def drain(index: int, stream) -> None:
        while True:
            chunk = stream.read1(8192)
            if not chunk:
                return
            with lock:
                aggregate = len(buffers[0]) + len(buffers[1]) + len(chunk)
                if len(buffers[index]) + len(chunk) > MAX_OUTPUT or aggregate > MAX_OUTPUT:
                    too_large.set()
                    process.kill()
                    return
                buffers[index].extend(chunk)

    readers = [
        threading.Thread(target=drain, args=(0, process.stdout), daemon=True),
        threading.Thread(target=drain, args=(1, process.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        raise MissionBridgeError("mission-launch-failed") from error
    finally:
        for reader in readers:
            reader.join(timeout=5)
        process.stdout.close()
        process.stderr.close()
    if too_large.is_set():
        raise MissionBridgeError("mission-output-too-large")
    if process.returncode:
        raise MissionBridgeError("mission-launch-failed")
    try:
        value = json.loads(bytes(buffers[0]))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MissionBridgeError("invalid-mission-readback") from error
    if not isinstance(value, dict):
        raise MissionBridgeError("invalid-mission-readback")
    if any(
        value.get(field) is not None and value.get(field) is not False
        for field in _AUTHORITY_FLAGS
    ):
        raise MissionBridgeError("mission-authority-escalation")
    required = {"mission_id", "objective_digest", "status", "current_route"}
    if (
        not required <= value.keys()
        or not _MISSION_ID.fullmatch(value.get("mission_id", ""))
        or not _OBJECTIVE_DIGEST.fullmatch(value.get("objective_digest", ""))
        or not isinstance(value.get("status"), str)
        or not 1 <= len(value["status"]) <= 64
        or not isinstance(value.get("current_route"), str)
        or not 1 <= len(value["current_route"]) <= 256
    ):
        raise MissionBridgeError("invalid-mission-readback")
    return value


def _record_paths(
    authority: dict, authority_raw: bytes, project: Path, objective: str
) -> tuple[Path, Path]:
    identity = _canonical_bytes(
        {
            "authority_id": authority["authority_id"],
            "chat_digest": authority["holder_digest"],
            "task_digest": authority["task_digest"],
            "objective_digest": _digest(objective.encode("utf-8")),
        }
    )
    name = hmac.new(authority_raw, b"mission-record\0" + identity, hashlib.sha256).hexdigest()
    record = _private_file(project, (".ao", "mission", "office-pool"), name + ".json")
    return record, record.with_suffix(".hmac")


def _expected_record(authority: dict, authority_raw: bytes, readback: dict) -> dict:
    return {
        "schema_version": 1,
        "mission_id": readback["mission_id"],
        "objective_digest": "sha256:" + authority["task_digest"],
        "authority_digest": _digest(authority_raw),
        "chat_digest": authority["holder_digest"],
        "task_digest": authority["task_digest"],
        "office_id": authority["office_id"],
        "generation": authority["generation"],
        "project_path": authority["project_path"],
        "mission_status": readback["status"],
    }


def _load_record(
    authority: dict, authority_raw: bytes, project: Path, objective: str
) -> tuple[dict, Path]:
    record, seal = _record_paths(authority, authority_raw, project, objective)
    if not record.exists() or not seal.exists():
        raise MissionBridgeError("mission-record-mismatch")
    wrapper = _read_authenticated(record, authority_raw, MISSION_SCHEMA, project)
    expected = {
        "objective_digest": "sha256:" + authority["task_digest"],
        "authority_digest": _digest(authority_raw),
        "chat_digest": authority["holder_digest"],
        "task_digest": authority["task_digest"],
        "office_id": authority["office_id"],
        "generation": authority["generation"],
        "project_path": authority["project_path"],
    }
    if any(wrapper.get(field) != value for field, value in expected.items()):
        raise MissionBridgeError("mission-record-mismatch")
    return wrapper, record


def _load_authenticated_record(receipt: Path, objective: str) -> tuple[dict, dict, bytes, Path]:
    authority, authority_raw, project = _authority(receipt, objective)
    wrapper, _ = _load_record(authority, authority_raw, project, objective)
    return wrapper, authority, authority_raw, project


def start_or_resume(receipt: Path, objective: str) -> MissionReadback:
    authority, authority_raw, project = _authority(receipt, objective)
    with _open_verified_executable() as executable:
        record, seal = _record_paths(authority, authority_raw, project, objective)
        resumed = record.exists() or seal.exists()
        if resumed:
            if not record.exists() or not seal.exists():
                raise MissionBridgeError("mission-record-mismatch")
            wrapper, _ = _load_record(authority, authority_raw, project, objective)
            readback = _run(
                [
                    "--home",
                    str(project / ".ao/mission"),
                    "mission",
                    "inspect",
                    "--mission",
                    wrapper["mission_id"],
                    "--json",
                ],
                project,
                executable,
            )
            if readback["mission_id"] != wrapper["mission_id"]:
                raise MissionBridgeError("mission-record-mismatch")
        else:
            readback = _run(
                ["--home", str(project / ".ao/mission"), "start", objective],
                project,
                executable,
            )
        wrapper = _expected_record(authority, authority_raw, readback)
        if readback["objective_digest"] != wrapper["objective_digest"]:
            raise MissionBridgeError("mission-record-mismatch")
        try:
            _write_authenticated(record, wrapper, authority_raw, MISSION_SCHEMA)
        except (OSError, TypeError, ValueError) as error:
            raise MissionBridgeError("mission-record-mismatch") from error
    return MissionReadback(
        mission_id=readback["mission_id"],
        objective_digest=readback["objective_digest"],
        status=readback["status"],
        current_route=readback["current_route"],
        record=record,
        resumed=resumed,
    )
