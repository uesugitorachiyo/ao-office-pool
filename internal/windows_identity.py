import ctypes
import os
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


def _open_handle(path: PureWindowsPath, *, open_reparse_point: bool = False):
    library = _kernel32()
    flags = _FILE_FLAG_BACKUP_SEMANTICS
    if open_reparse_point:
        flags |= _FILE_FLAG_OPEN_REPARSE_POINT
    handle = library.CreateFileW(
        _native_path(path),
        0,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
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


def _snapshot(path: PureWindowsPath, *, open_reparse_point: bool = False):
    library, handle = _open_handle(path, open_reparse_point=open_reparse_point)
    try:
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


def open_identity(path: Path) -> FileIdentity:
    _require_windows()
    if not isinstance(path, Path):
        raise TypeError("path must be a pathlib.Path")
    canonical = canonical_windows_path(str(path))
    reparse = any(
        _snapshot(prefix, open_reparse_point=True)[2] & _FILE_ATTRIBUTE_REPARSE_POINT
        for prefix in _prefixes(canonical)
    )
    key, final_path, attributes, link_count = _snapshot(canonical)
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
