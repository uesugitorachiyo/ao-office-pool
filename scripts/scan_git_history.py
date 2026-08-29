from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable, Iterable, TypeVar


REPOSITORY_ROOT = Path(__file__).parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.scan_public_tree import PATS, ROOTS, scan_content


OID = re.compile(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
WINDOWS_ABSOLUTE = re.compile(r"(?i)^[a-z]:[\\/]")
MAX_OBJECTS = 10_000
MAX_REFS = 10_000
MAX_NAME_OCCURRENCES = 250_000
MAX_NAME_BYTES = 32_768
MAX_BLOB_SIZE = 64 * 1024 * 1024
MAX_AGGREGATE_SIZE = 1024 * 1024 * 1024
MAX_METADATA_OUTPUT = 64 * 1024 * 1024
MAX_METADATA_OBJECT_SIZE = 16 * 1024 * 1024
MAX_HEADER_BYTES = 256
GIT_TIMEOUT_SECONDS = 30.0
GIT_AGGREGATE_TIMEOUT_SECONDS = 180.0
HASH_BOUND_HISTORY_FILES = {
    "packaging/runtime/ao-forge/docs/contracts/goal-run-v0.1.schema.json": (
        b"517414890362c42a1f68465469093410f2389368",
        "68a0fb154124fb4c219cc68eeffcc432e2c5c445765e9dbe24b19718fb98d74c",
    )
}
T = TypeVar("T")


class GitScanError(Exception):
    def __init__(self, stage: str):
        super().__init__(stage)
        self.stage = stage


@dataclass(frozen=True)
class HistoryFinding:
    object_id: str
    path: str | None
    rule: str
    detail: str


@dataclass(frozen=True)
class BlobObject:
    object_id: bytes
    size: int


@dataclass(frozen=True)
class MetadataObject:
    object_id: bytes
    kind: bytes
    size: int


def _git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    return environment


def _git(repository: Path, *arguments: str) -> list[str]:
    safe_directory = repository.resolve().as_posix()
    return [
        "git",
        "--no-replace-objects",
        "-c",
        "core.quotepath=false",
        "-c",
        f"safe.directory={safe_directory}",
        "-C",
        str(repository),
        *arguments,
    ]


def _run_git(
    repository: Path,
    stage: str,
    arguments: tuple[str, ...],
    consumer: Callable[[BinaryIO], T],
    *,
    requests: Iterable[bytes] | None = None,
    max_output: int = MAX_METADATA_OUTPUT,
    deadline: float | None = None,
    allow_empty_exit_one: bool = False,
) -> T:
    input_stream: BinaryIO | None = None
    output_stream: BinaryIO | None = None
    process: subprocess.Popen[bytes] | None = None
    reader: threading.Thread | None = None
    output_pipe: BinaryIO | None = None
    output_limit = threading.Event()
    reader_failure: list[Exception] = []
    active_error = False
    try:
        if deadline is not None and deadline <= time.monotonic():
            raise GitScanError("git-timeout")
        if requests is not None:
            input_stream = tempfile.TemporaryFile(mode="w+b")
            for request in requests:
                input_stream.write(request + b"\n")
            input_stream.seek(0)
        output_stream = tempfile.TemporaryFile(mode="w+b")
        process = subprocess.Popen(
            _git(repository, *arguments),
            stdin=input_stream if input_stream is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
        )
        if process.stdout is None:
            raise GitScanError(stage)
        output_pipe = process.stdout

        def drain_output() -> None:
            written = 0
            try:
                while True:
                    chunk = output_pipe.read(64 * 1024)
                    if not chunk:
                        return
                    if written + len(chunk) > max_output:
                        output_limit.set()
                        try:
                            process.kill()
                        except Exception:
                            pass
                        return
                    output_stream.write(chunk)
                    written += len(chunk)
            except Exception as error:
                reader_failure.append(error)
                try:
                    process.kill()
                except Exception:
                    pass

        reader = threading.Thread(target=drain_output, daemon=True)
        reader.start()
        timeout = GIT_TIMEOUT_SECONDS
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GitScanError("git-timeout")
            timeout = min(timeout, remaining)
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise GitScanError("git-timeout") from error
        reader.join(timeout=5)
        if reader.is_alive() or reader_failure:
            raise GitScanError(stage)
        if output_limit.is_set():
            raise GitScanError("limit-protocol-size")
        output_stream.seek(0, os.SEEK_END)
        output_size = output_stream.tell()
        if return_code != 0 and not (
            allow_empty_exit_one and return_code == 1 and output_size == 0
        ):
            raise GitScanError(stage)
        output_stream.seek(0)
        result = consumer(output_stream)
        if output_stream.read(1) != b"":
            raise GitScanError(stage)
        return result
    except GitScanError:
        active_error = True
        raise
    except Exception as error:
        active_error = True
        raise GitScanError(stage) from error
    finally:
        cleanup_error: Exception | None = None
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            except Exception as error:
                cleanup_error = error
        if reader is not None:
            try:
                reader.join(timeout=5)
                if reader.is_alive():
                    cleanup_error = cleanup_error or RuntimeError("reader-active")
            except Exception as error:
                cleanup_error = cleanup_error or error
        for stream in (input_stream, output_pipe, output_stream):
            if stream is not None:
                try:
                    stream.close()
                except Exception as error:
                    cleanup_error = cleanup_error or error
        if cleanup_error is not None and not active_error:
            raise GitScanError(stage) from cleanup_error


def _safe_relative_name(raw: bytes) -> str | None:
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if (
        not value
        or value.startswith(("/", "\\"))
        or WINDOWS_ABSOLUTE.match(value)
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    low = path.name.casefold()
    if (
        any(part.casefold() in ROOTS for part in path.parts)
        or low.startswith("._")
        or low.endswith((".pyc", ".pyo"))
        or low == ".env"
        or (low.startswith(".env.") and low != ".env.example")
        or any(fnmatch.fnmatch(low, pattern) for pattern in PATS)
        or scan_content("historical-name.txt", value.encode("utf-8"))
    ):
        return None
    return value


def _hash_bound_history_name(raw: bytes, object_id: bytes) -> str | None:
    for relative, (expected_object, _) in HASH_BOUND_HISTORY_FILES.items():
        if raw == relative.encode("utf-8") and object_id == expected_object:
            return relative
    return None


def _is_hash_bound_history_blob(
    relative: str, object_id: bytes, data: bytes
) -> bool:
    binding = HASH_BOUND_HISTORY_FILES.get(relative)
    return bool(
        binding
        and object_id == binding[0]
        and hashlib.sha256(data).hexdigest() == binding[1]
    )


def _read_line(stream: BinaryIO, stage: str) -> bytes:
    line = stream.readline(MAX_HEADER_BYTES + 1)
    if not line or len(line) > MAX_HEADER_BYTES or not line.endswith(b"\n"):
        raise GitScanError(stage)
    return line[:-1]


def _enumerate_objects(
    repository: Path, refs: tuple[tuple[bytes, bytes], ...], deadline: float
) -> list[bytes]:
    targets = sorted({object_id for _, object_id in refs})
    if not targets:
        return []

    def consume(stream: BinaryIO) -> list[bytes]:
        objects: set[bytes] = set()
        for raw_line in stream:
            object_id = raw_line.rstrip(b"\r\n")
            if not OID.fullmatch(object_id):
                raise GitScanError("git-rev-list")
            if object_id not in objects:
                if len(objects) >= MAX_OBJECTS:
                    raise GitScanError("limit-object-count")
                objects.add(object_id)
        return sorted(objects)

    return _run_git(
        repository,
        "git-rev-list",
        ("rev-list", "--objects", "--no-object-names", "--stdin"),
        consume,
        requests=targets,
        deadline=deadline,
    )


def _parse_batch_header(
    stream: BinaryIO, requested: bytes, stage: str
) -> tuple[bytes, int]:
    fields = _read_line(stream, stage).split(b" ")
    if (
        len(fields) != 3
        or fields[0] != requested
        or not OID.fullmatch(fields[0])
        or not fields[2].isdigit()
        or len(fields[2]) > 20
    ):
        raise GitScanError(stage)
    return fields[1], int(fields[2])


def _classify_objects(
    repository: Path, objects: list[bytes], deadline: float
) -> tuple[list[BlobObject], list[MetadataObject]]:
    def consume(stream: BinaryIO) -> tuple[list[BlobObject], list[MetadataObject]]:
        blobs: list[BlobObject] = []
        metadata: list[MetadataObject] = []
        aggregate_size = 0
        metadata_size = 0
        for requested in objects:
            kind, size = _parse_batch_header(stream, requested, "git-batch-check")
            if kind == b"blob":
                if size > MAX_BLOB_SIZE:
                    raise GitScanError("limit-blob-size")
                aggregate_size += size
                if aggregate_size > MAX_AGGREGATE_SIZE:
                    raise GitScanError("limit-aggregate-size")
                blobs.append(BlobObject(requested, size))
            elif kind in {b"commit", b"tree", b"tag"}:
                if size > MAX_METADATA_OBJECT_SIZE:
                    raise GitScanError("limit-metadata-size")
                metadata_size += size
                if metadata_size > MAX_METADATA_OUTPUT:
                    raise GitScanError("limit-metadata-size")
                metadata.append(MetadataObject(requested, kind, size))
            else:
                raise GitScanError("git-batch-check")
        return blobs, metadata

    return _run_git(
        repository,
        "git-batch-check",
        ("cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"),
        consume,
        requests=objects,
        max_output=max(MAX_HEADER_BYTES * len(objects), MAX_HEADER_BYTES),
        deadline=deadline,
    )


def _nul_records(stream: BinaryIO, stage: str):
    pending = bytearray()
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        pending.extend(chunk)
        while True:
            boundary = pending.find(0)
            if boundary < 0:
                break
            if boundary > MAX_NAME_BYTES:
                raise GitScanError(stage)
            yield bytes(pending[:boundary])
            del pending[: boundary + 1]
        if len(pending) > MAX_NAME_BYTES:
            raise GitScanError(stage)
    if pending:
        raise GitScanError(stage)


def _read_metadata(
    repository: Path, metadata: list[MetadataObject], deadline: float
) -> dict[bytes, tuple[bytes, bytes]]:
    def consume(stream: BinaryIO) -> dict[bytes, tuple[bytes, bytes]]:
        values: dict[bytes, tuple[bytes, bytes]] = {}
        for item in metadata:
            kind, size = _parse_batch_header(stream, item.object_id, "git-metadata-read")
            if kind != item.kind or size != item.size:
                raise GitScanError("git-metadata-read")
            data = _read_exact(stream, size)
            if stream.read(1) != b"\n":
                raise GitScanError("git-metadata-read")
            values[item.object_id] = (kind, data)
        return values

    return _run_git(
        repository,
        "git-metadata-read",
        ("cat-file", "--batch"),
        consume,
        requests=(item.object_id for item in metadata),
        max_output=MAX_METADATA_OUTPUT + MAX_HEADER_BYTES * max(len(metadata), 1),
        deadline=deadline,
    )


def _enumerate_ref_targets(
    repository: Path, deadline: float
) -> tuple[tuple[bytes, bytes], ...]:
    def consume(stream: BinaryIO) -> tuple[tuple[bytes, bytes], ...]:
        refs: dict[bytes, bytes] = {}
        for raw_line in stream:
            record = raw_line.rstrip(b"\r\n")
            object_id, separator, name = record.partition(b" ")
            if (
                not separator
                or not name
                or len(name) > MAX_NAME_BYTES
                or not OID.fullmatch(object_id)
                or (name != b"HEAD" and not name.startswith(b"refs/"))
                or name in refs
            ):
                raise GitScanError("git-show-ref")
            if len(refs) >= MAX_REFS:
                raise GitScanError("limit-ref-count")
            refs[name] = object_id
        return tuple(sorted(refs.items()))

    return _run_git(
        repository,
        "git-show-ref",
        ("show-ref", "--head"),
        consume,
        deadline=deadline,
        allow_empty_exit_one=True,
    )


def _authority_line(data: bytes, prefix: bytes, stage: str) -> bytes:
    line = data.split(b"\n", 1)[0]
    value = line[len(prefix) :] if line.startswith(prefix) else b""
    if not OID.fullmatch(value):
        raise GitScanError(stage)
    return value


def _root_trees(
    values: dict[bytes, tuple[bytes, bytes]],
    ref_targets: tuple[tuple[bytes, bytes], ...],
) -> set[bytes]:
    roots = {
        _authority_line(data, b"tree ", "git-metadata-read")
        for kind, data in values.values()
        if kind == b"commit"
    }
    for _, target in ref_targets:
        visited: set[bytes] = set()
        while target in values and values[target][0] == b"tag":
            if target in visited:
                raise GitScanError("git-metadata-read")
            visited.add(target)
            target = _authority_line(
                values[target][1], b"object ", "git-metadata-read"
            )
        if target in values and values[target][0] == b"tree":
            roots.add(target)
    for root in roots:
        if root not in values or values[root][0] != b"tree":
            raise GitScanError("git-metadata-read")
    return roots


def _tree_entries(
    data: bytes, object_bytes: int
) -> Iterable[tuple[bytes, bytes, bytes]]:
    position = 0
    while position < len(data):
        space = data.find(b" ", position)
        nul = data.find(b"\0", space + 1) if space >= 0 else -1
        end = nul + 1 + object_bytes
        if space <= position or nul <= space + 1 or end > len(data):
            raise GitScanError("git-tree-read")
        mode = data[position:space]
        name = data[space + 1 : nul]
        if mode not in {
            b"040000",
            b"40000",
            b"100644",
            b"100755",
            b"120000",
            b"160000",
        } or b"/" in name:
            raise GitScanError("git-tree-read")
        yield mode, name, data[nul + 1 : end].hex().encode("ascii")
        position = end


def _historical_names(
    values: dict[bytes, tuple[bytes, bytes]],
    roots: set[bytes],
    blobs: list[BlobObject],
) -> tuple[dict[bytes, str], list[HistoryFinding]]:
    blob_ids = {blob.object_id for blob in blobs}
    safe_names: dict[bytes, str] = {}
    private_occurrences: set[tuple[bytes, bytes]] = set()
    findings: list[HistoryFinding] = []
    occurrence_count = 0

    if not values and not blob_ids and not roots:
        return safe_names, findings
    object_id_lengths = {len(object_id) for object_id in values} | {
        len(object_id) for object_id in blob_ids
    }
    if len(object_id_lengths) != 1 or next(iter(object_id_lengths), 0) not in {40, 64}:
        raise GitScanError("git-tree-read")
    object_bytes = next(iter(object_id_lengths)) // 2
    pending = [(root, b"") for root in sorted(roots)]
    visited: set[tuple[bytes, bytes]] = set()
    while pending:
        tree_id, prefix = pending.pop()
        state = (tree_id, prefix)
        if state in visited:
            continue
        visited.add(state)
        value = values.get(tree_id)
        if value is None or value[0] != b"tree":
            raise GitScanError("git-tree-read")
        for mode, component, object_id in _tree_entries(value[1], object_bytes):
            raw_name = prefix + component
            if len(raw_name) > MAX_NAME_BYTES:
                raise GitScanError("limit-name-size")
            if mode in {b"40000", b"040000"}:
                pending.append((object_id, raw_name + b"/"))
                continue
            if mode == b"160000":
                continue
            if object_id not in blob_ids:
                raise GitScanError("git-tree-read")
            occurrence_count += 1
            if occurrence_count > MAX_NAME_OCCURRENCES:
                raise GitScanError("limit-name-occurrences")
            name = _hash_bound_history_name(raw_name, object_id)
            if name is None:
                name = _safe_relative_name(raw_name)
            if name is None:
                key = (object_id, hashlib.sha256(raw_name).digest())
                if key not in private_occurrences:
                    private_occurrences.add(key)
                    findings.append(
                        HistoryFinding(
                            object_id.decode("ascii"), None, "path", "private"
                        )
                    )
            else:
                previous = safe_names.get(object_id)
                if previous is None or name < previous:
                    safe_names[object_id] = name
    return safe_names, findings


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.read(min(size - len(chunks), 1024 * 1024))
        if not chunk:
            raise GitScanError("git-batch-read")
        chunks.extend(chunk)
    return bytes(chunks)


def _scan_blobs(
    repository: Path,
    blobs: list[BlobObject],
    names: dict[bytes, str],
    deadline: float,
) -> list[HistoryFinding]:
    def consume(stream: BinaryIO) -> list[HistoryFinding]:
        findings: list[HistoryFinding] = []
        for blob in blobs:
            kind, size = _parse_batch_header(
                stream, blob.object_id, "git-batch-read"
            )
            if kind != b"blob" or size != blob.size:
                raise GitScanError("git-batch-read")
            data = _read_exact(stream, size)
            if stream.read(1) != b"\n":
                raise GitScanError("git-batch-read")
            name = names.get(blob.object_id)
            relative = name if name is not None else "historical-blob"
            content_findings = (
                []
                if _is_hash_bound_history_blob(relative, blob.object_id, data)
                else scan_content(relative, data, scan_binary=True)
            )
            for finding in content_findings:
                findings.append(
                    HistoryFinding(
                        blob.object_id.decode("ascii"),
                        name,
                        finding.rule,
                        finding.detail,
                    )
                )
        return findings

    return _run_git(
        repository,
        "git-batch-read",
        ("cat-file", "--batch"),
        consume,
        requests=(blob.object_id for blob in blobs),
        max_output=MAX_AGGREGATE_SIZE + MAX_HEADER_BYTES * max(len(blobs), 1),
        deadline=deadline,
    )


def scan_history(repository: Path) -> list[HistoryFinding]:
    repository = Path(repository)
    deadline = time.monotonic() + GIT_AGGREGATE_TIMEOUT_SECONDS
    refs = _enumerate_ref_targets(repository, deadline)
    objects = _enumerate_objects(repository, refs, deadline)
    blobs, metadata = _classify_objects(repository, objects, deadline)
    classified = {blob.object_id for blob in blobs} | {
        item.object_id for item in metadata
    }
    if any(object_id not in classified for _, object_id in refs):
        raise GitScanError("git-ref-target")
    values = _read_metadata(repository, metadata, deadline)
    roots = _root_trees(values, refs)
    names, path_findings = _historical_names(values, roots, blobs)
    if time.monotonic() >= deadline:
        raise GitScanError("git-timeout")
    content_findings = _scan_blobs(repository, blobs, names, deadline)
    if _enumerate_ref_targets(repository, deadline) != refs:
        raise GitScanError("git-ref-drift")
    return sorted(
        [*path_findings, *content_findings],
        key=lambda finding: (
            finding.object_id,
            finding.path or "",
            finding.rule,
            finding.detail,
        ),
    )


def main() -> int:
    try:
        findings = scan_history(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("."))
    except GitScanError as error:
        print(
            json.dumps(
                {"error": "scan-failed", "kind": error.stage},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        print("history scan-error=1", file=sys.stderr)
        return 2
    for finding in findings:
        row = {
            "detail": finding.detail,
            "object": finding.object_id,
            "rule": finding.rule,
        }
        if finding.path is not None:
            row["path"] = finding.path
        print(json.dumps(row, sort_keys=True, separators=(",", ":")))
    print(f"history findings={len(findings)}", file=sys.stderr)
    return int(bool(findings))


if __name__ == "__main__":
    raise SystemExit(main())
