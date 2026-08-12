import errno
import json
import os
import stat
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


class LockError(RuntimeError):
    pass


def _open_lock(path: Path, root: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if os.name == "nt":
            import ctypes
            import msvcrt

            from internal.windows_identity import (
                _BY_HANDLE_FILE_INFORMATION,
                _FILE_ATTRIBUTE_DIRECTORY,
                _FILE_ATTRIBUTE_REPARSE_POINT,
                _FILE_SHARE_DELETE,
                _FILE_SHARE_READ,
                _FILE_SHARE_WRITE,
                _INVALID_HANDLE_VALUE,
                _final_path,
                _kernel32,
                _native_path,
                open_identity,
                require_within,
            )
            from internal.windows_paths import canonical_windows_path

            root_identity = open_identity(root)
            require_within(root_identity, root_identity)
            library = _kernel32()
            handle = library.CreateFileW(
                _native_path(canonical_windows_path(str(path))),
                0x80000000 | 0x40000000,
                _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
                None,
                4,
                0x00200000,
                None,
            )
            if handle == _INVALID_HANDLE_VALUE:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                information = _BY_HANDLE_FILE_INFORMATION()
                if not library.GetFileInformationByHandle(handle, ctypes.byref(information)):
                    raise ctypes.WinError(ctypes.get_last_error())
                require_within(root_identity, root_identity)
                if (
                    information.file_attributes
                    & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
                    or information.number_of_links != 1
                    or _final_path(library, handle).parent != root_identity.final_path
                ):
                    raise ValueError("invalid opened pool lock")
                descriptor = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
                handle = None
            finally:
                if handle is not None:
                    library.CloseHandle(handle)
        else:
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags, 0o600)
            information = os.fstat(descriptor)
            if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
                os.close(descriptor)
                raise ValueError("invalid opened pool lock")
        return os.fdopen(descriptor, "r+b")
    except (OSError, TypeError, ValueError) as error:
        raise LockError("invalid pool lock") from error


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_json(path: Path, value: dict) -> None:
    atomic_write_bytes(
        path,
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
    )


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


@contextmanager
def pool_lock(path: Path, root: Path):
    with _open_lock(path, root) as stream:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
            os.fsync(stream.fileno())
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError as error:
                    if error.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                        raise
                    time.sleep(0.05)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
