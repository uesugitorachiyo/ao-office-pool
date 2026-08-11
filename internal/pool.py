import base64
import hashlib
import json
import os
import secrets
import shutil
import uuid
from pathlib import Path

from internal.transactions import atomic_write_bytes, atomic_write_json, pool_lock, read_json
from internal.windows_identity import open_identity, require_within
from internal.windows_paths import canonical_windows_path, validate_segment


OFFICE_IDS = tuple(f"O{number}" for number in range(1, 6))
MODES = frozenset({"conversation", "pinned"})
AUTHORITY_FIELDS = frozenset(
    {
        "schema_version",
        "authority_id",
        "office_id",
        "generation",
        "holder_digest",
        "task_digest",
        "project_path",
        "project_volume",
        "project_file_id",
        "mode",
    }
)
FREE_STATE_FIELDS = frozenset({"schema_version", "office_id", "generation", "status"})
OCCUPIED_STATE_FIELDS = (
    AUTHORITY_FIELDS - {"authority_id"}
) | {"status", "authority_name", "authority_digest"}


class PoolError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class InjectedCrash(RuntimeError):
    pass


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _encoded(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decoded(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


class Pool:
    def __init__(
        self,
        root: Path,
        *,
        runtime_version: str = "unactivated",
        crash_after: str | None = None,
    ):
        if not isinstance(root, Path):
            raise TypeError("root must be a pathlib.Path")
        self.root = root.resolve(strict=False)
        self.runtime_version = validate_segment(runtime_version)
        self.crash_after = crash_after

    @property
    def _lock_path(self) -> Path:
        return self.root / ".pool.lock"

    @property
    def _runtime(self) -> Path:
        return self.root / "runtime"

    @property
    def _authorities(self) -> Path:
        return self._runtime / "receipts"

    @property
    def _pointers(self) -> Path:
        return self._runtime / "pointers"

    @property
    def _journals(self) -> Path:
        return self._runtime / "transactions"

    def _checkpoint(self, name: str) -> None:
        if self.crash_after == name:
            raise InjectedCrash(name)

    def _office(self, office_id: str) -> Path:
        if office_id not in OFFICE_IDS:
            raise PoolError("invalid-office")
        return self.root / "offices" / office_id

    def _state_path(self, office_id: str) -> Path:
        return self._office(office_id) / "office-state.json"

    def _marker_path(self, office_id: str) -> Path:
        return self._runtime / "recovery" / f"{office_id}.json"

    def _pointer_path(self, holder_digest: str) -> Path:
        return self._pointers / f"{holder_digest}.json"

    def _authority_path(self, authority_id: str) -> Path:
        return self._authorities / f"{authority_id}.receipt.json"

    def _journal_path(self, operation_id: str) -> Path:
        return self._journals / f"{operation_id}.json"

    def initialize(self, count: int = 5) -> None:
        if type(count) is not int or count != 5:
            raise PoolError("invalid-count")
        validate_segment(self.runtime_version)
        self._preflight_existing_root()
        with pool_lock(self._lock_path):
            pool_path = self.root / "pool.json"
            if pool_path.exists():
                self._ensure_initialized()
                return
            self._runtime.mkdir(parents=True, exist_ok=True)
            self._authorities.mkdir(exist_ok=True)
            self._pointers.mkdir(exist_ok=True)
            self._journals.mkdir(exist_ok=True)
            (self._runtime / "recovery").mkdir(exist_ok=True)
            operator = self.root / "operator-secrets"
            operator.mkdir(exist_ok=True)
            authority_digests = {}
            for office_id in OFFICE_IDS:
                office = self._office(office_id)
                (office / "work").mkdir(parents=True, exist_ok=True)
                (office / "history").mkdir(exist_ok=True)
                state_path = self._state_path(office_id)
                if state_path.exists():
                    state = self._read_state_file(state_path)
                    if state != self._free_state(office_id, 0):
                        raise PoolError("recovery-required")
                else:
                    atomic_write_json(state_path, self._free_state(office_id, 0))
                self._checkpoint(f"initialize:office:{office_id}")
                key_file = operator / f"recovery-key-{office_id}"
                if not key_file.exists():
                    atomic_write_bytes(key_file, (secrets.token_urlsafe(32) + "\n").encode("utf-8"))
                authority_digests[office_id] = _bytes_digest(key_file.read_bytes())
            atomic_write_json(
                self._runtime / "recovery-authority.json",
                {"schema_version": 1, "digests": authority_digests},
            )
            atomic_write_json(
                pool_path,
                {
                    "schema_version": 1,
                    "office_count": 5,
                    "offices": list(OFFICE_IDS),
                    "runtime_version": self.runtime_version,
                },
            )
            self._verify_runtime_containment()

    def _preflight_existing_root(self) -> None:
        if os.name != "nt" or not self.root.exists():
            return
        root_identity = open_identity(self.root)
        require_within(root_identity, root_identity)
        for path in (self._runtime, self.root / "offices"):
            if path.exists():
                require_within(open_identity(path), root_identity)

    def _verify_runtime_containment(self) -> None:
        if os.name != "nt":
            return
        root_identity = open_identity(self.root)
        for path in (self._runtime, self.root / "offices"):
            require_within(open_identity(path), root_identity)

    def _ensure_initialized(self) -> dict:
        try:
            value = read_json(self.root / "pool.json")
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise PoolError("not-initialized") from error
        expected = {
            "schema_version": 1,
            "office_count": 5,
            "offices": list(OFFICE_IDS),
            "runtime_version": self.runtime_version,
        }
        if value != expected:
            raise PoolError("recovery-required")
        return value

    @staticmethod
    def _free_state(office_id: str, generation: int) -> dict:
        return {
            "schema_version": 1,
            "office_id": office_id,
            "generation": generation,
            "status": "free",
        }

    @staticmethod
    def _read_state_file(path: Path) -> dict:
        value = read_json(path)
        if not FREE_STATE_FIELDS <= set(value):
            raise ValueError("invalid office state")
        if value["schema_version"] != 1 or value["status"] not in {
            "free",
            "occupied",
            "recovery-required",
        }:
            raise ValueError("invalid office state")
        if type(value["generation"]) is not int or value["generation"] < 0:
            raise ValueError("invalid office generation")
        fields = set(value)
        if value["status"] == "free" and fields != FREE_STATE_FIELDS:
            raise ValueError("invalid free office state")
        if value["status"] == "occupied" and fields != OCCUPIED_STATE_FIELDS:
            raise ValueError("invalid occupied office state")
        if value["status"] == "recovery-required" and fields not in (
            FREE_STATE_FIELDS | {"reason"},
            OCCUPIED_STATE_FIELDS | {"reason"},
        ):
            raise ValueError("invalid recovery office state")
        return value

    def _corrupt_state(self, office_id: str) -> dict:
        generation = 0
        try:
            value = read_json(self._state_path(office_id))
            if type(value.get("generation")) is int and value["generation"] >= 0:
                generation = value["generation"]
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        return self._free_state(office_id, generation) | {
            "status": "recovery-required",
            "corrupt_state": True,
        }

    def _read_state(self, office_id: str) -> dict:
        marker = self._marker_path(office_id)
        if marker.exists():
            try:
                value = read_json(marker)
                state = self._read_state_file(self._state_path(office_id))
                state["generation"] = value["generation"]
                state["status"] = "recovery-required"
                return state
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                return self._corrupt_state(office_id)
        try:
            state = self._read_state_file(self._state_path(office_id))
        except (OSError, ValueError, json.JSONDecodeError):
            return self._corrupt_state(office_id)
        if state.get("office_id") != office_id:
            return self._free_state(office_id, state.get("generation", 0)) | {
                "status": "recovery-required"
            }
        return state

    def _unknown_paths(self, office_id: str) -> list[Path]:
        office = self._office(office_id)
        paths = list((office / "work").iterdir())
        paths.extend(
            path
            for path in office.iterdir()
            if path.name not in {"office-state.json", "work", "history"}
        )
        return sorted(paths, key=lambda path: path.name)

    def _mark_recovery(self, office_id: str, state: dict, reason: str) -> None:
        value = dict(state)
        value["status"] = "recovery-required"
        value["reason"] = reason
        atomic_write_json(self._state_path(office_id), value)

    def _quarantine_journal(self, journal: dict, reason: str) -> None:
        office_id = journal["office_id"]
        state = self._read_state(office_id)
        atomic_write_json(
            self._marker_path(office_id),
            {
                "schema_version": 1,
                "office_id": office_id,
                "generation": state["generation"],
                "reason": reason,
            },
        )
        self._journal_path(journal["operation_id"]).unlink(missing_ok=True)
        raise PoolError("recovery-required")

    def _project_record(self, project_root: Path) -> dict:
        if not isinstance(project_root, Path):
            raise PoolError("invalid-project")
        try:
            if os.name == "nt":
                canonical = canonical_windows_path(str(project_root))
                identity = open_identity(project_root)
                require_within(identity, identity)
                if not identity.is_directory:
                    raise ValueError("project root is not a directory")
                return {
                    "project_path": str(canonical),
                    "project_volume": identity.volume_serial_number,
                    "project_file_id": identity.file_id.hex(),
                }
            resolved = project_root.resolve(strict=True)
            if not resolved.is_dir():
                raise ValueError("project root is not a directory")
            information = resolved.stat()
            return {
                "project_path": str(resolved),
                "project_volume": information.st_dev,
                "project_file_id": str(information.st_ino),
            }
        except (OSError, TypeError, ValueError) as error:
            raise PoolError("invalid-project") from error

    def _validate_project_record(self, value: dict) -> None:
        current = self._project_record(Path(value["project_path"]))
        if any(current[field] != value[field] for field in current):
            raise PoolError("unauthorized")

    @staticmethod
    def _validate_text(value: str, code: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise PoolError(code)
        return value

    def claim(self, owner_id, task_id, project_root, mode):
        holder = _digest(self._validate_text(owner_id, "invalid-holder"))
        task = _digest(self._validate_text(task_id, "invalid-task"))
        if mode not in MODES:
            raise PoolError("invalid-mode")
        project = self._project_record(project_root)
        self._ensure_initialized()
        with pool_lock(self._lock_path):
            self._ensure_initialized()
            self._reconcile()
            states = {office_id: self._read_state(office_id) for office_id in OFFICE_IDS}
            if any(
                state.get("holder_digest") == holder and state["status"] != "free"
                for state in states.values()
            ):
                raise PoolError("already-claimed")
            free = []
            for office_id, state in states.items():
                if state["status"] == "free" and self._unknown_paths(office_id):
                    self._mark_recovery(office_id, state, "unknown-residue")
                elif state["status"] == "free":
                    free.append(office_id)
            if not free:
                if any(state["status"] == "recovery-required" for state in states.values()):
                    raise PoolError("recovery-required")
                raise PoolError("pool-full")
            office_id = free[0]
            before = states[office_id]
            generation = before["generation"] + 1
            authority_id = secrets.token_hex(32)
            authority = {
                "schema_version": 1,
                "authority_id": authority_id,
                "office_id": office_id,
                "generation": generation,
                "holder_digest": holder,
                "task_digest": task,
                **project,
                "mode": mode,
            }
            authority_bytes = (
                json.dumps(authority, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            authority_file = self._authority_path(authority_id)
            pointer_file = self._pointer_path(holder)
            pointer = {
                "schema_version": 1,
                "holder_digest": holder,
                "office_id": office_id,
                "generation": generation,
                "authority_name": authority_file.name,
            }
            occupied = dict(authority)
            occupied.pop("authority_id")
            occupied["status"] = "occupied"
            occupied["authority_name"] = authority_file.name
            occupied["authority_digest"] = _bytes_digest(authority_bytes)
            operation_id = uuid.uuid4().hex
            journal_file = self._journal_path(operation_id)
            journal = {
                "schema_version": 1,
                "operation_id": operation_id,
                "kind": "claim",
                "phase": "prepared",
                "office_id": office_id,
                "before_state": before,
                "after_state": occupied,
                "authority_name": authority_file.name,
                "authority_bytes": _encoded(authority_bytes),
                "pointer_name": pointer_file.name,
                "pointer": pointer,
            }
            atomic_write_json(journal_file, journal)
            self._checkpoint("claim:journal-prepared")
            atomic_write_json(self._state_path(office_id), occupied)
            self._checkpoint("claim:office")
            atomic_write_bytes(authority_file, authority_bytes)
            self._checkpoint("claim:authority")
            atomic_write_json(pointer_file, pointer)
            self._checkpoint("claim:pointer")
            journal["phase"] = "committed"
            atomic_write_json(journal_file, journal)
            self._checkpoint("claim:journal-committed")
            journal_file.unlink()
            return authority_file

    def _checked_authority_path(self, value) -> Path:
        try:
            path = Path(value)
            validate_segment(path.name)
            expected = self._authorities.resolve(strict=True)
            resolved = path.resolve(strict=True)
            if resolved.parent != expected or resolved.is_symlink() or not resolved.is_file():
                raise ValueError("authority path is outside protected storage")
            if os.name == "nt":
                require_within(open_identity(resolved), open_identity(expected))
            return resolved
        except (OSError, TypeError, ValueError) as error:
            raise PoolError("unauthorized") from error

    def _load_authority(self, value) -> tuple[Path, bytes, dict]:
        path = self._checked_authority_path(value)
        raw = path.read_bytes()
        try:
            record = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PoolError("unauthorized") from error
        if not isinstance(record, dict) or set(record) != AUTHORITY_FIELDS:
            raise PoolError("unauthorized")
        return path, raw, record

    def _authorize(self, value) -> tuple[Path, bytes, dict, dict]:
        path, raw, record = self._load_authority(value)
        office_id = record.get("office_id")
        if office_id not in OFFICE_IDS:
            raise PoolError("unauthorized")
        state = self._read_state(office_id)
        if state["status"] == "recovery-required":
            raise PoolError("recovery-required")
        if record.get("generation") != state.get("generation"):
            raise PoolError("stale-generation")
        comparisons = {
            "holder_digest",
            "task_digest",
            "project_path",
            "project_volume",
            "project_file_id",
            "mode",
        }
        if (
            state["status"] != "occupied"
            or path.name != state.get("authority_name")
            or any(record.get(field) != state.get(field) for field in comparisons)
            or _bytes_digest(raw) != state.get("authority_digest")
        ):
            raise PoolError("unauthorized")
        self._validate_project_record(record)
        return path, raw, record, state

    def resume(self, receipt_path):
        self._ensure_initialized()
        with pool_lock(self._lock_path):
            self._ensure_initialized()
            self._reconcile()
            authority, _, record, state = self._authorize(receipt_path)
            if self._unknown_paths(record["office_id"]):
                self._mark_recovery(record["office_id"], state, "unknown-residue")
                raise PoolError("recovery-required")
            pointer_file = self._pointer_path(record["holder_digest"])
            pointer = {
                "schema_version": 1,
                "holder_digest": record["holder_digest"],
                "office_id": record["office_id"],
                "generation": record["generation"],
                "authority_name": authority.name,
            }
            if not pointer_file.exists():
                atomic_write_json(pointer_file, pointer)
            else:
                try:
                    if read_json(pointer_file) != pointer:
                        raise ValueError("pointer mismatch")
                except (OSError, ValueError, json.JSONDecodeError):
                    self._mark_recovery(record["office_id"], state, "corrupt-pointer")
                    raise PoolError("recovery-required")
            return authority

    def release(self, receipt_path) -> None:
        self._ensure_initialized()
        with pool_lock(self._lock_path):
            self._ensure_initialized()
            self._reconcile()
            authority, authority_bytes, record, state = self._authorize(receipt_path)
            office_id = record["office_id"]
            if self._unknown_paths(office_id):
                self._mark_recovery(office_id, state, "dirty-release")
                raise PoolError("recovery-required")
            pointer_file = self._pointer_path(record["holder_digest"])
            pointer_exists = pointer_file.exists()
            pointer_bytes = pointer_file.read_bytes() if pointer_exists else b""
            operation_id = uuid.uuid4().hex
            journal_file = self._journal_path(operation_id)
            journal = {
                "schema_version": 1,
                "operation_id": operation_id,
                "kind": "release",
                "phase": "prepared",
                "office_id": office_id,
                "before_state": state,
                "after_state": self._free_state(office_id, state["generation"]),
                "authority_name": authority.name,
                "authority_bytes": _encoded(authority_bytes),
                "pointer_name": pointer_file.name,
                "pointer_existed": pointer_exists,
                "pointer_bytes": _encoded(pointer_bytes),
            }
            atomic_write_json(journal_file, journal)
            self._checkpoint("release:journal-prepared")
            authority.unlink()
            self._checkpoint("release:authority")
            pointer_file.unlink(missing_ok=True)
            self._checkpoint("release:pointer")
            atomic_write_json(self._state_path(office_id), journal["after_state"])
            self._checkpoint("release:office")
            journal["phase"] = "committed"
            atomic_write_json(journal_file, journal)
            self._checkpoint("release:journal-committed")
            journal_file.unlink()

    def recover(self, key_path, office_id, generation) -> None:
        if office_id not in OFFICE_IDS:
            raise PoolError("invalid-office")
        if type(generation) is not int or generation < 0:
            raise PoolError("stale-generation")
        try:
            supplied = Path(key_path).read_bytes()
        except (OSError, TypeError) as error:
            raise PoolError("unauthorized") from error
        self._ensure_initialized()
        with pool_lock(self._lock_path):
            self._ensure_initialized()
            self._reconcile()
            try:
                digests = read_json(self._runtime / "recovery-authority.json")["digests"]
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
                raise PoolError("recovery-required") from error
            if not secrets.compare_digest(_bytes_digest(supplied), digests.get(office_id, "")):
                raise PoolError("unauthorized")
            state = self._read_state(office_id)
            if state["generation"] != generation:
                raise PoolError("stale-generation")
            if state["status"] != "recovery-required":
                raise PoolError("recovery-not-required")
            operation_id = uuid.uuid4().hex
            archive = self._office(office_id) / "history" / f"recovery-g{generation}-{operation_id}"
            moves = []
            if state.get("corrupt_state") and self._state_path(office_id).exists():
                moves.append(
                    (
                        self._state_path(office_id),
                        archive / "unknown-office-state.json",
                        "state",
                    )
                )
            for source in self._unknown_paths(office_id):
                moves.append((source, archive / "residue" / source.name, "residue"))
            authority_name = state.get("authority_name")
            if authority_name:
                source = self._authorities / authority_name
                if source.exists():
                    moves.append((source, archive / "authority.json", "authority"))
            holder = state.get("holder_digest")
            if holder:
                source = self._pointer_path(holder)
                if source.exists():
                    moves.append((source, archive / "pointer.json", "pointer"))
            evidence_entries = []
            for source, _, kind in moves:
                if source.is_file():
                    raw = source.read_bytes()
                    evidence_entries.append(
                        {"kind": kind, "sha256": _bytes_digest(raw), "size": len(raw)}
                    )
            journal_file = self._journal_path(operation_id)
            journal = {
                "schema_version": 1,
                "operation_id": operation_id,
                "kind": "recover",
                "phase": "prepared",
                "office_id": office_id,
                "before_state": state,
                "after_state": self._free_state(office_id, generation),
                "moves": [
                    {"source": str(source), "destination": str(destination), "kind": kind}
                    for source, destination, kind in moves
                ],
                "evidence": {
                    "schema_version": 1,
                    "office_id": office_id,
                    "generation": generation,
                    "entries": evidence_entries,
                },
                "archive": str(archive),
            }
            atomic_write_json(journal_file, journal)
            self._checkpoint("recover:journal-prepared")
            for source, destination, kind in moves:
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(source, destination)
                if kind == "authority":
                    self._checkpoint("recover:authority")
                elif kind == "pointer":
                    self._checkpoint("recover:pointer")
            archive.mkdir(parents=True, exist_ok=True)
            atomic_write_json(archive / "recovery.json", journal["evidence"])
            atomic_write_json(self._state_path(office_id), journal["after_state"])
            self._marker_path(office_id).unlink(missing_ok=True)
            self._checkpoint("recover:office")
            journal["phase"] = "committed"
            atomic_write_json(journal_file, journal)
            self._checkpoint("recover:journal-committed")
            journal_file.unlink()

    def _reconcile(self) -> None:
        for journal_file in sorted(self._journals.glob("*.json")):
            try:
                journal = read_json(journal_file)
                kind = journal["kind"]
                phase = journal["phase"]
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
                raise PoolError("recovery-required") from error
            self._validate_journal(journal_file, journal)
            if kind == "claim":
                self._reconcile_claim(journal, phase == "committed")
            elif kind == "release":
                self._reconcile_release(journal, phase == "committed")
            elif kind == "recover":
                self._reconcile_recover(journal, phase == "committed")
            else:
                raise PoolError("recovery-required")
            journal_file.unlink()

    def _validate_journal(self, journal_file: Path, journal: dict) -> None:
        common = {
            "schema_version",
            "operation_id",
            "kind",
            "phase",
            "office_id",
            "before_state",
            "after_state",
        }
        fields = {
            "claim": common
            | {"authority_name", "authority_bytes", "pointer_name", "pointer"},
            "release": common
            | {
                "authority_name",
                "authority_bytes",
                "pointer_name",
                "pointer_existed",
                "pointer_bytes",
            },
            "recover": common | {"moves", "evidence", "archive"},
        }
        operation_id = journal.get("operation_id")
        if (
            journal.get("schema_version") != 1
            or journal.get("kind") not in fields
            or set(journal) != fields[journal["kind"]]
            or journal.get("phase") not in {"prepared", "committed"}
            or journal.get("office_id") not in OFFICE_IDS
            or not isinstance(operation_id, str)
            or len(operation_id) != 32
            or any(character not in "0123456789abcdef" for character in operation_id)
            or journal_file.stem != operation_id
        ):
            raise PoolError("recovery-required")
        if journal["kind"] in {"claim", "release"}:
            try:
                validate_segment(journal["authority_name"])
                validate_segment(journal["pointer_name"])
                authority_id = journal["authority_name"].removesuffix(".receipt.json")
                holder = journal["pointer_name"].removesuffix(".json")
                if (
                    len(authority_id) != 64
                    or any(character not in "0123456789abcdef" for character in authority_id)
                    or len(holder) != 64
                    or any(character not in "0123456789abcdef" for character in holder)
                ):
                    raise ValueError("invalid protected member name")
                _decoded(journal["authority_bytes"])
                _decoded(journal.get("pointer_bytes", ""))
            except (TypeError, ValueError):
                raise PoolError("recovery-required") from None
        else:
            self._validate_recovery_journal(journal)

    def _validate_recovery_journal(self, journal: dict) -> None:
        office_id = journal["office_id"]
        generation = journal["after_state"].get("generation")
        archive = self._office(office_id) / "history" / (
            f"recovery-g{generation}-{journal['operation_id']}"
        )
        if Path(journal["archive"]) != archive or not isinstance(journal["moves"], list):
            raise PoolError("recovery-required")
        office = self._office(office_id)
        for item in journal["moves"]:
            if not isinstance(item, dict) or set(item) != {"source", "destination", "kind"}:
                raise PoolError("recovery-required")
            source = Path(item["source"])
            destination = Path(item["destination"])
            try:
                destination.resolve(strict=False).relative_to(archive.resolve(strict=False))
            except (OSError, ValueError):
                raise PoolError("recovery-required") from None
            source_resolved = source.resolve(strict=False)
            allowed = (
                source == self._state_path(office_id)
                or source_resolved.parent in {
                    (office / "work").resolve(strict=False),
                    self._authorities.resolve(strict=False),
                    self._pointers.resolve(strict=False),
                }
                or (
                    source_resolved.parent == office.resolve(strict=False)
                    and source.name not in {"office-state.json", "work", "history"}
                )
            )
            if not allowed:
                raise PoolError("recovery-required")

    def _reconcile_claim(self, journal: dict, committed: bool) -> None:
        office_id = journal["office_id"]
        authority = self._authorities / journal["authority_name"]
        pointer = self._pointers / journal["pointer_name"]
        expected_authority = _decoded(journal["authority_bytes"])
        state = self._read_state(office_id)
        if state not in (journal["before_state"], journal["after_state"]):
            self._quarantine_journal(journal, "unknown-office-state")
        if authority.exists() and authority.read_bytes() != expected_authority:
            self._quarantine_journal(journal, "unknown-authority-bytes")
        if pointer.exists():
            try:
                if read_json(pointer) != journal["pointer"]:
                    self._quarantine_journal(journal, "unknown-pointer-bytes")
            except (OSError, ValueError, json.JSONDecodeError):
                self._quarantine_journal(journal, "unknown-pointer-bytes")
        if committed:
            atomic_write_json(self._state_path(office_id), journal["after_state"])
            atomic_write_bytes(authority, expected_authority)
            atomic_write_json(pointer, journal["pointer"])
        else:
            authority.unlink(missing_ok=True)
            pointer.unlink(missing_ok=True)
            atomic_write_json(self._state_path(office_id), journal["before_state"])

    def _reconcile_release(self, journal: dict, committed: bool) -> None:
        office_id = journal["office_id"]
        authority = self._authorities / journal["authority_name"]
        pointer = self._pointers / journal["pointer_name"]
        expected_authority = _decoded(journal["authority_bytes"])
        state = self._read_state(office_id)
        if state not in (journal["before_state"], journal["after_state"]):
            self._quarantine_journal(journal, "unknown-office-state")
        if authority.exists() and authority.read_bytes() != expected_authority:
            self._quarantine_journal(journal, "unknown-authority-bytes")
        if pointer.exists() and journal["pointer_existed"]:
            if pointer.read_bytes() != _decoded(journal["pointer_bytes"]):
                self._quarantine_journal(journal, "unknown-pointer-bytes")
        if committed:
            authority.unlink(missing_ok=True)
            pointer.unlink(missing_ok=True)
            atomic_write_json(self._state_path(office_id), journal["after_state"])
        else:
            atomic_write_bytes(authority, _decoded(journal["authority_bytes"]))
            if journal["pointer_existed"]:
                atomic_write_bytes(pointer, _decoded(journal["pointer_bytes"]))
            else:
                pointer.unlink(missing_ok=True)
            atomic_write_json(self._state_path(office_id), journal["before_state"])

    def _reconcile_recover(self, journal: dict, committed: bool) -> None:
        moves = [(Path(item["source"]), Path(item["destination"])) for item in journal["moves"]]
        archive = Path(journal["archive"])
        if committed:
            for source, destination in moves:
                if source.exists() and not destination.exists():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(source, destination)
            archive.mkdir(parents=True, exist_ok=True)
            atomic_write_json(archive / "recovery.json", journal["evidence"])
            atomic_write_json(self._state_path(journal["office_id"]), journal["after_state"])
            self._marker_path(journal["office_id"]).unlink(missing_ok=True)
        else:
            for source, destination in reversed(moves):
                if destination.exists() and not source.exists():
                    source.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(destination, source)
            shutil.rmtree(archive, ignore_errors=True)
            if not journal["before_state"].get("corrupt_state"):
                atomic_write_json(self._state_path(journal["office_id"]), journal["before_state"])

    def public_status(self) -> dict:
        self._ensure_initialized()
        with pool_lock(self._lock_path):
            self._ensure_initialized()
            offices = []
            for office_id in OFFICE_IDS:
                state = self._read_state(office_id)
                status = state["status"]
                if status == "free" and self._unknown_paths(office_id):
                    status = "recovery-required"
                offices.append(
                    {
                        "office_id": office_id,
                        "status": status,
                        "generation": state["generation"],
                    }
                )
            return {"schema_version": 1, "offices": offices}
