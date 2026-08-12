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
import uuid
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

    @property
    def launch_path(self) -> str:
        if os.name != "nt" and Path("/proc/self/fd").is_dir():
            return f"/proc/self/fd/{self.descriptors[-1]}"
        return str(self.path)


@dataclass
class _PrivateDirectory:
    path: Path
    project_path: Path
    descriptors: tuple[int, ...] = ()
    handles: tuple[object, ...] = ()

    @property
    def directory_descriptor(self) -> int | None:
        return self.descriptors[-1] if self.descriptors else None

    @property
    def launch_path(self) -> str:
        if self.directory_descriptor is not None and Path("/proc/self/fd").is_dir():
            return f"/proc/self/fd/{self.directory_descriptor}"
        return str(self.path)

    @property
    def project_launch_path(self) -> str:
        if self.descriptors and Path("/proc/self/fd").is_dir():
            return f"/proc/self/fd/{self.descriptors[0]}"
        return str(self.project_path)

    def require_current_paths(self) -> None:
        if self.descriptors:
            current = self.project_path
            parts = (None, *self.path.relative_to(self.project_path).parts)
            for descriptor, part in zip(self.descriptors, parts):
                if part is not None:
                    current = current / part
                information = os.stat(current, follow_symlinks=False)
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISDIR(information.st_mode)
                    or information.st_dev != opened.st_dev
                    or information.st_ino != opened.st_ino
                ):
                    raise MissionBridgeError("mission-storage-unsafe")
        else:
            for path in (self.project_path, self.path):
                _validate_private_path(path, self.project_path, directory=True)

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        if self.handles:
            from internal.windows_identity import _kernel32

            library = _kernel32()
            for handle in reversed(self.handles):
                library.CloseHandle(handle)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


@dataclass
class _PrivateFile:
    path: Path
    directory: _PrivateDirectory
    name: str

    def close(self) -> None:
        self.directory.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


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


def _open_windows_directory(path: Path):
    from internal.windows_identity import (
        _BY_HANDLE_FILE_INFORMATION,
        _FILE_ATTRIBUTE_DIRECTORY,
        _FILE_ATTRIBUTE_REPARSE_POINT,
        _FILE_SHARE_READ,
        _FILE_SHARE_WRITE,
        _INVALID_HANDLE_VALUE,
        _final_path,
        _kernel32,
        _native_path,
    )
    from internal.windows_paths import canonical_windows_path

    library = _kernel32()
    canonical = canonical_windows_path(str(path))
    handle = library.CreateFileW(
        _native_path(canonical),
        0x80000000,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    information = _BY_HANDLE_FILE_INFORMATION()
    if not library.GetFileInformationByHandle(handle, ctypes.byref(information)):
        library.CloseHandle(handle)
        raise ctypes.WinError(ctypes.get_last_error())
    if (
        not information.file_attributes & _FILE_ATTRIBUTE_DIRECTORY
        or information.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT
        or _final_path(library, handle) != canonical
    ):
        library.CloseHandle(handle)
        raise ValueError("unsafe private directory")
    return handle


def _private_directory(project: Path, *parts: str) -> _PrivateDirectory:
    descriptors = []
    handles = []
    try:
        _project_identity(project)
        for part in parts:
            if (
                not isinstance(part, str)
                or not part
                or part in {".", ".."}
                or "/" in part
                or "\\" in part
            ):
                raise ValueError("unsafe private segment")
        current = project
        if os.name == "nt":
            handles.append(_open_windows_directory(current))
            for part in parts:
                current = current / part
                try:
                    current.mkdir()
                except FileExistsError:
                    pass
                handles.append(_open_windows_directory(current))
            return _PrivateDirectory(current, project, handles=tuple(handles))

        flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(project, flags)
        descriptors.append(descriptor)
        information = os.fstat(descriptor)
        if not stat.S_ISDIR(information.st_mode):
            raise ValueError("unsafe project")
        for part in parts:
            try:
                os.mkdir(part, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, flags, dir_fd=descriptor)
            descriptors.append(child)
            information = os.fstat(child)
            if not stat.S_ISDIR(information.st_mode):
                raise ValueError("unsafe private directory")
            descriptor = child
            current = current / part
        return _PrivateDirectory(current, project, descriptors=tuple(descriptors))
    except (OSError, TypeError, ValueError) as error:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        if handles:
            from internal.windows_identity import _kernel32

            library = _kernel32()
            for handle in reversed(handles):
                library.CloseHandle(handle)
        raise MissionBridgeError("mission-storage-unsafe") from error


def _private_file(
    project: Path, directories: tuple[str, ...], name: str
) -> _PrivateFile:
    if not isinstance(name, str) or not name or "/" in name or "\\" in name:
        raise MissionBridgeError("mission-storage-unsafe")
    parent = _private_directory(project, *directories)
    path = parent.path / name
    return _PrivateFile(path, parent, name)


def _private_exists(path: _PrivateFile) -> bool:
    try:
        if path.directory.directory_descriptor is not None:
            information = os.stat(
                path.name,
                dir_fd=path.directory.directory_descriptor,
                follow_symlinks=False,
            )
            if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
                raise ValueError("unsafe private file")
            return True
        if not path.path.exists() and not path.path.is_symlink():
            return False
        _validate_private_path(path.path, path.directory.project_path, directory=False)
        return True
    except FileNotFoundError:
        return False
    except (OSError, TypeError, ValueError) as error:
        raise MissionBridgeError("mission-storage-unsafe") from error


def _private_sibling(path: _PrivateFile, suffix: str) -> _PrivateFile:
    name = Path(path.name).with_suffix(suffix).name
    return _PrivateFile(path.path.with_suffix(suffix), path.directory, name)


def _write_private_bytes(path: _PrivateFile, data: bytes) -> None:
    descriptor = path.directory.directory_descriptor
    if descriptor is None:
        atomic_write_bytes(path.path, data)
        _validate_private_path(
            path.path, path.directory.project_path, directory=False
        )
        return
    temporary = f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    opened = None
    try:
        opened = os.open(temporary, flags, 0o600, dir_fd=descriptor)
        view = memoryview(data)
        while view:
            written = os.write(opened, view)
            view = view[written:]
        os.fsync(opened)
        os.close(opened)
        opened = None
        os.replace(
            temporary,
            path.name,
            src_dir_fd=descriptor,
            dst_dir_fd=descriptor,
        )
        os.fsync(descriptor)
    finally:
        if opened is not None:
            os.close(opened)
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass


def _read_private_bytes(path: _PrivateFile) -> bytes:
    descriptor = path.directory.directory_descriptor
    if descriptor is None:
        if os.name != "nt":
            raise ValueError("private directory descriptor required")
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
        canonical = canonical_windows_path(str(path.path))
        handle = library.CreateFileW(
            _native_path(canonical),
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
                or _final_path(library, handle) != canonical
            ):
                raise ValueError("unsafe private file")
            opened = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            handle = None
            try:
                chunks = []
                while True:
                    chunk = os.read(opened, 64 * 1024)
                    if not chunk:
                        return b"".join(chunks)
                    chunks.append(chunk)
            finally:
                os.close(opened)
        finally:
            if handle is not None:
                library.CloseHandle(handle)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    opened = os.open(path.name, flags, dir_fd=descriptor)
    try:
        information = os.fstat(opened)
        if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
            raise ValueError("unsafe private file")
        chunks = []
        while True:
            chunk = os.read(opened, 64 * 1024)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(opened)


def _write_authenticated(
    path: _PrivateFile, value: dict, key: bytes, schema: Path
) -> None:
    _validate_schema(value, schema)
    raw = _canonical_bytes(value)
    tag = hmac.new(key, raw, hashlib.sha256).hexdigest().encode("ascii") + b"\n"
    _write_private_bytes(path, raw)
    _write_private_bytes(_private_sibling(path, ".hmac"), tag)


def _read_authenticated(
    path: _PrivateFile, key: bytes, schema: Path, project: Path
) -> dict:
    seal = _private_sibling(path, ".hmac")
    try:
        raw = _read_private_bytes(path)
        supplied = _read_private_bytes(seal).decode("ascii")
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
    arguments: list[str],
    project: Path | _PrivateDirectory,
    executable: _VerifiedExecutable,
) -> dict:
    launch_path = executable.launch_path
    if isinstance(project, _PrivateDirectory):
        project.require_current_paths()
        cwd = project.project_launch_path
        private_descriptors = project.descriptors
    else:
        cwd = project
        private_descriptors = ()
    options = {}
    if os.name != "nt":
        if not launch_path.startswith("/proc/self/fd/"):
            source = os.fstat(executable.descriptors[-1])
            current = executable.path.stat()
            if source.st_dev != current.st_dev or source.st_ino != current.st_ino:
                raise MissionBridgeError("mission-launch-failed")
        options["pass_fds"] = tuple(
            dict.fromkeys((*executable.descriptors, *private_descriptors))
        )
    try:
        process = subprocess.Popen(
            [launch_path, *arguments],
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **options,
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
) -> tuple[_PrivateFile, _PrivateFile]:
    identity = _canonical_bytes(
        {
            "authority_id": authority["authority_id"],
            "chat_digest": authority["holder_digest"],
            "task_digest": authority["task_digest"],
            "objective_digest": _digest(objective.encode("utf-8")),
        }
    )
    name = hmac.new(
        authority_raw, b"mission-record\0" + identity, hashlib.sha256
    ).hexdigest()
    record = _private_file(project, (".ao", "mission", "office-pool"), name + ".json")
    return record, _private_sibling(record, ".hmac")


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
    authority: dict,
    authority_raw: bytes,
    project: Path,
    objective: str,
    record: _PrivateFile | None = None,
) -> tuple[dict, _PrivateFile]:
    owned = record is None
    if record is None:
        record, seal = _record_paths(authority, authority_raw, project, objective)
    else:
        seal = _private_sibling(record, ".hmac")
    try:
        if not _private_exists(record) or not _private_exists(seal):
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
    finally:
        if owned:
            record.close()


def _load_authenticated_record(receipt: Path, objective: str) -> tuple[dict, dict, bytes, Path]:
    authority, authority_raw, project = _authority(receipt, objective)
    wrapper, _ = _load_record(authority, authority_raw, project, objective)
    return wrapper, authority, authority_raw, project


def start_or_resume(receipt: Path, objective: str) -> MissionReadback:
    authority, authority_raw, project = _authority(receipt, objective)
    with _open_verified_executable() as executable, _private_directory(
        project, ".ao", "mission"
    ) as mission_home, _record_paths(
        authority, authority_raw, project, objective
    )[0] as record:
        seal = _private_sibling(record, ".hmac")
        record_exists = _private_exists(record)
        seal_exists = _private_exists(seal)
        resumed = record_exists or seal_exists
        if resumed:
            if not record_exists or not seal_exists:
                raise MissionBridgeError("mission-record-mismatch")
            wrapper, _ = _load_record(
                authority, authority_raw, project, objective, record
            )
            readback = _run(
                [
                    "--home",
                    mission_home.launch_path,
                    "mission",
                    "inspect",
                    "--mission",
                    wrapper["mission_id"],
                    "--json",
                ],
                mission_home,
                executable,
            )
            if readback["mission_id"] != wrapper["mission_id"]:
                raise MissionBridgeError("mission-record-mismatch")
        else:
            readback = _run(
                ["--home", mission_home.launch_path, "start", objective],
                mission_home,
                executable,
            )
        wrapper = _expected_record(authority, authority_raw, readback)
        if readback["objective_digest"] != wrapper["objective_digest"]:
            raise MissionBridgeError("mission-record-mismatch")
        try:
            _write_authenticated(record, wrapper, authority_raw, MISSION_SCHEMA)
        except (OSError, TypeError, ValueError) as error:
            raise MissionBridgeError("mission-record-mismatch") from error
        record_path = record.path
    return MissionReadback(
        mission_id=readback["mission_id"],
        objective_digest=readback["objective_digest"],
        status=readback["status"],
        current_route=readback["current_route"],
        record=record_path,
        resumed=resumed,
    )
