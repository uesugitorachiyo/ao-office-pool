import re
from pathlib import PureWindowsPath


_INVALID_CHARACTERS = frozenset('<>:"/\\|?*')
_RESERVED_NAMES = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        "conin$",
        "conout$",
        "com¹",
        "com²",
        "com³",
        "lpt¹",
        "lpt²",
        "lpt³",
    }
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
)
_SHORT_NAME = re.compile(r"^[^ .~]{1,6}~[0-9]+(?:\.[^.]*)?$", re.IGNORECASE)
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def validate_segment(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("Windows path segment must be a string")
    if not value or value in {".", ".."}:
        raise ValueError("Windows path segment is empty or relative")
    if value[-1] in {" ", "."}:
        raise ValueError("Windows path segment has a trailing space or period")
    if any(character in _INVALID_CHARACTERS or ord(character) < 32 for character in value):
        raise ValueError("Windows path segment contains an invalid character")
    if value.split(".", 1)[0].casefold() in _RESERVED_NAMES:
        raise ValueError("Windows path segment is a reserved device name")
    if _SHORT_NAME.fullmatch(value):
        raise ValueError("Windows short-name aliases are not accepted")
    if len(value.encode("utf-16-le")) // 2 > 255:
        raise ValueError("Windows path segment exceeds 255 UTF-16 code units")
    return value


def canonical_windows_path(value: str) -> PureWindowsPath:
    if not isinstance(value, str):
        raise TypeError("Windows path must be a string")
    if not value:
        raise ValueError("Windows path is empty")

    normalized = value.replace("/", "\\")
    folded = normalized.casefold()
    if folded.startswith("\\\\.\\"):
        raise ValueError("Windows device paths are not accepted")
    if folded.startswith("\\\\?\\unc\\"):
        normalized = "\\\\" + normalized[8:]
    elif folded.startswith("\\\\?\\"):
        normalized = normalized[4:]
        if not re.match(r"^[a-zA-Z]:\\", normalized):
            raise ValueError("Only extended drive and UNC paths are accepted")

    if normalized.startswith("\\\\"):
        components = normalized[2:].split("\\")
        if len(components) < 2 or any(not component for component in components):
            raise ValueError("UNC paths require a server and share without empty segments")
        for component in components:
            validate_segment(component)
        conventional = "\\\\" + "\\".join(components)
    elif re.match(r"^[a-zA-Z]:\\", normalized):
        components = normalized[3:].split("\\") if len(normalized) > 3 else []
        if any(not component for component in components):
            raise ValueError("Windows paths cannot contain empty segments")
        for component in components:
            validate_segment(component)
        conventional = normalized
    else:
        raise ValueError("Windows path must be drive-absolute or UNC-absolute")

    return PureWindowsPath(conventional.translate(_ASCII_LOWER))
