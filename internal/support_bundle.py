import json
import os
import stat
from pathlib import Path

from internal.readback import _active_snapshot, _offices, public_record
from internal.windows_paths import validate_segment


_CODES = {
    "qualification-failed",
    "recovery-required",
    "runtime-update-failed",
}
_QUALIFICATION_STATES = {"candidate", "pilot-qualified", "release-qualified"}


class SupportBundleError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def support_record(
    root: Path, status: dict, qualification: dict, diagnostics: list[dict]
) -> dict:
    if not isinstance(diagnostics, list):
        raise ValueError("diagnostics must be a list")
    public = public_record(root, status, qualification)
    counts = {code: 0 for code in _CODES}
    for item in diagnostics:
        if isinstance(item, dict):
            code = item.get("code")
            if isinstance(code, str) and code in counts:
                counts[code] += 1
    return {
        "schema_version": 1,
        "runtime_version": public["runtime_version"],
        "qualification_state": public["qualification_state"],
        "offices": public["offices"],
        "diagnostics": [
            {"code": code, "count": counts[code]}
            for code in sorted(counts)
            if counts[code]
        ],
    }


def _require_active_support(root: Path, record: dict) -> None:
    selected, offices = _active_snapshot(root)
    if (
        record["runtime_version"] != selected["runtime_version"]
        or record["qualification_state"] != selected["qualification_state"]
        or record["offices"] != offices
    ):
        raise SupportBundleError("support-record-stale")


def _file_identity(information) -> tuple[int, int]:
    if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
        raise OSError("unsafe support destination")
    return information.st_dev, information.st_ino


def _path_identity(path: Path) -> tuple[int, int] | None:
    try:
        return _file_identity(path.stat(follow_symlinks=False))
    except (FileNotFoundError, OSError):
        return None


def write_support_bundle(root: Path, destination: Path, record: dict) -> Path:
    if not isinstance(root, Path):
        raise TypeError("root must be pathlib.Path")
    if not isinstance(destination, Path):
        raise TypeError("destination must be a pathlib.Path")
    expected_fields = {
        "schema_version", "runtime_version", "qualification_state", "offices", "diagnostics"
    }
    try:
        diagnostics = record["diagnostics"]
        if (
            not isinstance(record, dict)
            or set(record) != expected_fields
            or record["schema_version"] != 1
            or validate_segment(record["runtime_version"])
            != record["runtime_version"]
            or len(record["runtime_version"]) > 128
            or record["qualification_state"] not in _QUALIFICATION_STATES
            or _offices({"schema_version": 1, "offices": record["offices"]})
            != record["offices"]
            or not isinstance(diagnostics, list)
            or any(
                not isinstance(item, dict)
                or set(item) != {"code", "count"}
                or item["code"] not in _CODES
                or type(item["count"]) is not int
                or item["count"] <= 0
                for item in diagnostics
            )
            or [item["code"] for item in diagnostics]
            != sorted({item["code"] for item in diagnostics})
        ):
            raise ValueError("invalid support record")
    except (AttributeError, KeyError, TypeError, ValueError):
        raise SupportBundleError("support-record-invalid")
    try:
        _require_active_support(root, record)
    except ValueError as error:
        raise SupportBundleError("support-record-stale") from error
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = None
    created_identity = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(destination, flags, 0o600)
        created_identity = _file_identity(os.fstat(descriptor))
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError("support write made no progress")
            view = view[count:]
        os.fsync(descriptor)
        if (
            _file_identity(os.fstat(descriptor)) != created_identity
            or _path_identity(destination) != created_identity
        ):
            raise OSError("support destination identity changed")
        os.close(descriptor)
        descriptor = None
        if os.name != "nt":
            parent = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        return destination
    except FileExistsError as error:
        raise SupportBundleError("support-bundle-exists") from error
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        if created_identity is not None and _path_identity(destination) == created_identity:
            destination.unlink(missing_ok=True)
        raise SupportBundleError("support-bundle-failed") from error
