import ctypes
import os
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from internal.windows_paths import canonical_windows_path


_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_SHARE_READ = 1
_FILE_SHARE_WRITE = 2
_FILE_SHARE_DELETE = 4
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ID_INFO_CLASS = 18
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _FILETIME(ctypes.Structure):
    _fields_ = (("low", ctypes.c_uint32), ("high", ctypes.c_uint32))


class _FILE_ID_128(ctypes.Structure):
    _fields_ = (("identifier", ctypes.c_ubyte * 16),)


class _FILE_ID_INFO(ctypes.Structure):
    _fields_ = (("volume_serial_number", ctypes.c_uint64), ("file_id", _FILE_ID_128))


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("file_attributes", ctypes.c_uint32),
        ("creation_time", _FILETIME),
        ("last_access_time", _FILETIME),
        ("last_write_time", _FILETIME),
        ("volume_serial_number", ctypes.c_uint32),
        ("file_size_high", ctypes.c_uint32),
        ("file_size_low", ctypes.c_uint32),
        ("number_of_links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    )


@dataclass(frozen=True, eq=False)
class FileIdentity:
    path: Path
    final_path: PureWindowsPath
    volume_serial_number: int
    file_id: bytes
    ancestor_ids: tuple[tuple[int, bytes], ...]
    link_count: int
    is_directory: bool
    traversed_reparse_point: bool

    @property
    def key(self) -> tuple[int, bytes]:
        return self.volume_serial_number, self.file_id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FileIdentity):
            return NotImplemented
        return self.key == other.key

    def __hash__(self) -> int:
        return hash(self.key)


@dataclass(eq=False)
class RetainedIdentity:
    identity: FileIdentity
    _library: object
    _handle: object | None

    def __enter__(self):
        if self._handle is None:
            raise ValueError("retained file identity is closed")
        return self

    def __exit__(self, _kind, _value, _traceback) -> bool:
        self.close()
        return False

    def close(self) -> None:
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        if not self._library.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def _require_windows() -> None:
    if os.name != "nt":
        raise OSError("Windows file identity is unavailable on this platform")


def _kernel32():
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.CreateFileW.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    library.CreateFileW.restype = ctypes.c_void_p
    library.GetFileInformationByHandleEx.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    )
    library.GetFileInformationByHandleEx.restype = ctypes.c_int
    library.GetFileInformationByHandle.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    )
    library.GetFileInformationByHandle.restype = ctypes.c_int
    library.GetFinalPathNameByHandleW.argtypes = (
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    )
    library.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
    library.CloseHandle.argtypes = (ctypes.c_void_p,)
    library.CloseHandle.restype = ctypes.c_int
    return library


def _native_path(path: PureWindowsPath) -> str:
    value = str(path)
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _open_handle(
    path: PureWindowsPath,
    *,
    open_reparse_point: bool = False,
    share_mode: int | None = None,
):
    library = _kernel32()
    flags = _FILE_FLAG_BACKUP_SEMANTICS
    if open_reparse_point:
        flags |= _FILE_FLAG_OPEN_REPARSE_POINT
    if share_mode is None:
        share_mode = _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE
    handle = library.CreateFileW(
        _native_path(path),
        0,
        share_mode,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    return library, handle


def _final_path(library, handle) -> PureWindowsPath:
    size = library.GetFinalPathNameByHandleW(handle, None, 0, 0)
    if not size:
        raise ctypes.WinError(ctypes.get_last_error())
    while True:
        buffer = ctypes.create_unicode_buffer(size + 1)
        length = library.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not length:
            raise ctypes.WinError(ctypes.get_last_error())
        if length < len(buffer):
            return canonical_windows_path(buffer.value)
        size = length


def _handle_snapshot(library, handle):
    identity = _FILE_ID_INFO()
    if not library.GetFileInformationByHandleEx(
        handle, _FILE_ID_INFO_CLASS, ctypes.byref(identity), ctypes.sizeof(identity)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    information = _BY_HANDLE_FILE_INFORMATION()
    if not library.GetFileInformationByHandle(handle, ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())
    return (
        (identity.volume_serial_number, bytes(identity.file_id.identifier)),
        _final_path(library, handle),
        information.file_attributes,
        information.number_of_links,
    )


def _snapshot(path: PureWindowsPath, *, open_reparse_point: bool = False):
    library, handle = _open_handle(path, open_reparse_point=open_reparse_point)
    try:
        return _handle_snapshot(library, handle)
    finally:
        library.CloseHandle(handle)


def _prefixes(path: PureWindowsPath) -> tuple[PureWindowsPath, ...]:
    parts = path.parts
    current = PureWindowsPath(parts[0])
    prefixes = [current]
    for part in parts[1:]:
        current /= part
        prefixes.append(current)
    return tuple(prefixes)


def _identity_from_handle(
    path: Path,
    canonical: PureWindowsPath,
    library,
    handle,
) -> FileIdentity:
    reparse = any(
        _snapshot(prefix, open_reparse_point=True)[2] & _FILE_ATTRIBUTE_REPARSE_POINT
        for prefix in _prefixes(canonical)
    )
    key, final_path, attributes, link_count = _handle_snapshot(library, handle)
    ancestors = tuple(_snapshot(prefix)[0] for prefix in _prefixes(final_path))
    return FileIdentity(
        path=path,
        final_path=final_path,
        volume_serial_number=key[0],
        file_id=key[1],
        ancestor_ids=ancestors,
        link_count=link_count,
        is_directory=bool(attributes & _FILE_ATTRIBUTE_DIRECTORY),
        traversed_reparse_point=bool(reparse),
    )


def open_identity(path: Path) -> FileIdentity:
    _require_windows()
    if not isinstance(path, Path):
        raise TypeError("path must be a pathlib.Path")
    canonical = canonical_windows_path(str(path))
    library, handle = _open_handle(canonical)
    try:
        return _identity_from_handle(path, canonical, library, handle)
    finally:
        library.CloseHandle(handle)


def open_retained_identity(path: Path) -> RetainedIdentity:
    """Open a native identity handle that denies write and delete sharing."""
    _require_windows()
    if not isinstance(path, Path):
        raise TypeError("path must be a pathlib.Path")
    canonical = canonical_windows_path(str(path))
    library, handle = _open_handle(canonical, share_mode=_FILE_SHARE_READ)
    try:
        identity = _identity_from_handle(path, canonical, library, handle)
        return RetainedIdentity(identity, library, handle)
    except BaseException:
        library.CloseHandle(handle)
        raise


def _require_open(retained: RetainedIdentity) -> FileIdentity:
    if not isinstance(retained, RetainedIdentity) or retained._handle is None:
        raise TypeError("an open RetainedIdentity is required")
    key, final_path, attributes, link_count = _handle_snapshot(
        retained._library,
        retained._handle,
    )
    identity = retained.identity
    if (
        key != identity.key
        or final_path != identity.final_path
        or bool(attributes & _FILE_ATTRIBUTE_DIRECTORY) != identity.is_directory
        or link_count != identity.link_count
    ):
        raise ValueError("retained file identity changed")
    return identity


def require_retained_within(
    child: RetainedIdentity,
    root: RetainedIdentity,
) -> None:
    _require_windows()
    current_child = _require_open(child)
    current_root = _require_open(root)
    if not current_root.is_directory:
        raise ValueError("containment root is not a directory")
    if current_child.traversed_reparse_point or current_root.traversed_reparse_point:
        raise ValueError("reparse-point paths are not accepted")
    if not current_child.is_directory and current_child.link_count != 1:
        raise ValueError("hard-linked files are not accepted")
    if current_root.key not in current_child.ancestor_ids:
        raise ValueError("child is not physically within root")


def require_path_identity(retained: RetainedIdentity) -> None:
    _require_windows()
    identity = _require_open(retained)
    current = open_identity(identity.path)
    if (
        current.key != identity.key
        or current.final_path != identity.final_path
        or current.ancestor_ids != identity.ancestor_ids
        or current.link_count != identity.link_count
        or current.is_directory != identity.is_directory
        or current.traversed_reparse_point != identity.traversed_reparse_point
    ):
        raise ValueError("path no longer names the retained file identity")


@contextmanager
def _retain_open_identities(root: Path, members: tuple[Path, ...]):
    _require_windows()
    if not isinstance(root, Path) or not isinstance(members, tuple) or any(
        not isinstance(member, Path) for member in members
    ):
        raise TypeError("root and members must be pathlib.Path values")
    with ExitStack() as stack:
        retained_root = stack.enter_context(open_retained_identity(root))
        retained_members = tuple(
            stack.enter_context(open_retained_identity(member))
            for member in members
        )
        require_retained_within(retained_root, retained_root)
        for retained_member in retained_members:
            require_retained_within(retained_member, retained_root)
        yield retained_root, retained_members
        require_path_identity(retained_root)
        for retained_member in retained_members:
            require_path_identity(retained_member)


def _require_same_retained(
    original: RetainedIdentity,
    final: RetainedIdentity,
) -> None:
    original_identity = _require_open(original)
    final_identity = _require_open(final)
    if (
        original_identity.key != final_identity.key
        or original_identity.final_path != final_identity.final_path
        or original_identity.ancestor_ids != final_identity.ancestor_ids
        or original_identity.link_count != final_identity.link_count
        or original_identity.is_directory != final_identity.is_directory
        or original_identity.traversed_reparse_point
        != final_identity.traversed_reparse_point
    ):
        raise ValueError("resolved path changed retained file identity")


@contextmanager
def retain_identities(root: Path, members: tuple[Path, ...]):
    """Retain original and final physical identities across one exact read."""
    with _retain_open_identities(root, members) as (
        original_root,
        original_members,
    ):
        final_root_path = root.resolve(strict=True)
        final_member_paths = tuple(member.resolve(strict=True) for member in members)
        with _retain_open_identities(final_root_path, final_member_paths) as (
            final_root,
            final_members,
        ):
            _require_same_retained(original_root, final_root)
            for original_member, final_member in zip(
                original_members,
                final_members,
                strict=True,
            ):
                _require_same_retained(original_member, final_member)
            yield final_root_path, final_member_paths


def require_within(child: FileIdentity, root: FileIdentity) -> None:
    _require_windows()
    if not isinstance(child, FileIdentity) or not isinstance(root, FileIdentity):
        raise TypeError("child and root must be FileIdentity values")
    current_child = open_identity(child.path)
    current_root = open_identity(root.path)
    if current_child != child or current_root != root:
        raise ValueError("file identity changed after it was opened")
    if not current_root.is_directory:
        raise ValueError("containment root is not a directory")
    if current_child.traversed_reparse_point or current_root.traversed_reparse_point:
        raise ValueError("reparse-point paths are not accepted")
    if not current_child.is_directory and current_child.link_count != 1:
        raise ValueError("hard-linked files are not accepted")
    if current_root.key not in current_child.ancestor_ids:
        raise ValueError("child is not physically within root")
