import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from internal.transactions import LockError, atomic_write_bytes, atomic_write_json, pool_lock, read_json
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
GOVERNANCE_ISSUANCE_FIELDS = frozenset(
    {"schema_version", "witness_id", "authority_digest", "artifact_sha256"}
)
GOVERNANCE_COMPLETION_FIELDS = frozenset(
    {
        "schema_version",
        "witness_id",
        "authority_digest",
        "request_digest",
        "execution_id",
        "execution_sha256",
        "tag",
    }
)


class PoolError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class InjectedCrash(RuntimeError):
    pass


@dataclass(frozen=True, eq=False, init=False)
class AuthorityLease:
    authority_path: Path
    authority_bytes: bytes
    authority: dict

    def __init__(self, *_args, **_kwargs):
        raise PoolError("unauthorized")

    def require_active(self) -> None:
        self._checker(self)


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
        abrupt_crash: bool = False,
    ):
        if not isinstance(root, Path):
            raise TypeError("root must be a pathlib.Path")
        self.root = root.resolve(strict=False)
        self.runtime_version = validate_segment(runtime_version)
        self.crash_after = crash_after
        self.abrupt_crash = abrupt_crash

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

    @property
    def _generations_path(self) -> Path:
        return self._runtime / "generations.json"

    @property
    def _recovery_authority_path(self) -> Path:
        return self._runtime / "recovery-authority.json"

    @property
    def _witness_key_path(self) -> Path:
        return self.root / "operator-secrets" / "governance-witness.key"

    @property
    def _governance_state(self) -> Path:
        return self._runtime / "governance"

    @property
    def _runtime_update_state_path(self) -> Path:
        return self._runtime / "runtime-update-state.json"

    def _governance_marker_path(
        self, lease: AuthorityLease, kind: str, witness_id: str, authority_digest: str
    ) -> Path:
        lease.require_active()
        if kind not in {"consumed", "issued", "revoked"}:
            raise PoolError("unauthorized")
        if (
            len(authority_digest) != 64
            or any(character not in "0123456789abcdef" for character in authority_digest)
            or not witness_id.startswith("witness-")
            or len(witness_id) != 40
            or any(character not in "0123456789abcdef" for character in witness_id[8:])
        ):
            raise PoolError("unauthorized")
        return self._governance_state / kind / f"{authority_digest}-{witness_id}"

    def _governance_marker_exists(
        self, lease: AuthorityLease, kind: str, witness_id: str, authority_digest: str
    ) -> bool:
        path = self._governance_marker_path(
            lease, kind, witness_id, authority_digest
        )
        try:
            information = path.stat(follow_symlinks=False)
            return stat.S_ISREG(information.st_mode) and information.st_nlink == 1
        except FileNotFoundError:
            return False
        except OSError as error:
            raise PoolError("recovery-required") from error

    def _create_governance_marker(
        self, lease: AuthorityLease, kind: str, witness_id: str, authority_digest: str
    ) -> bool:
        path = self._governance_marker_path(
            lease, kind, witness_id, authority_digest
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            return False
        except OSError as error:
            raise PoolError("recovery-required") from error
        try:
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
            os.write(descriptor, b"1\n")
            os.fsync(descriptor)
        except BaseException:
            os.close(descriptor)
            path.unlink(missing_ok=True)
            raise
        os.close(descriptor)
        if os.name != "nt":
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        return True

    def _validate_witness_key(self) -> None:
        descriptor = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._witness_key_path, flags)
            information = os.fstat(descriptor)
            value = os.read(descriptor, 33)
            if (
                not stat.S_ISREG(information.st_mode)
                or information.st_nlink != 1
                or (os.name != "nt" and stat.S_IMODE(information.st_mode) != 0o600)
                or len(value) != 32
            ):
                raise ValueError("unsafe witness key")
        except (OSError, ValueError) as error:
            raise PoolError("recovery-required") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _governance_issuance(
        self, lease: AuthorityLease, witness_id: str
    ) -> tuple[bytes, dict] | None:
        authority_digest = _bytes_digest(lease.authority_bytes)
        path = self._governance_marker_path(
            lease, "issued", witness_id, authority_digest
        )
        descriptor = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            information = os.fstat(descriptor)
            raw = os.read(descriptor, 513)
            if (
                not stat.S_ISREG(information.st_mode)
                or information.st_nlink != 1
                or len(raw) > 512
            ):
                raise ValueError("unsafe governance issuance")
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as error:
            raise PoolError("recovery-required") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        try:
            value = json.loads(raw)
            expected = {
                "schema_version": 1,
                "witness_id": witness_id,
                "authority_digest": authority_digest,
                "artifact_sha256": value["artifact_sha256"],
            }
            if (
                not isinstance(value, dict)
                or set(value) != GOVERNANCE_ISSUANCE_FIELDS
                or value != expected
                or not isinstance(value["artifact_sha256"], str)
                or len(value["artifact_sha256"]) != 64
                or any(character not in "0123456789abcdef" for character in value["artifact_sha256"])
                or raw != (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
            ):
                raise ValueError("invalid governance issuance")
        except (KeyError, TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            raise PoolError("recovery-required") from error
        return raw, value

    def _governance_witness_tag(
        self, lease: AuthorityLease, witness_id: str
    ) -> bytes:
        issuance = self._governance_issuance(lease, witness_id)
        if issuance is None:
            raise PoolError("unauthorized")
        return self._governance_tag(issuance[0]) + b"\n"

    def _governance_tag(self, payload: bytes) -> bytes:
        descriptor = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._witness_key_path, flags)
            information = os.fstat(descriptor)
            key = os.read(descriptor, 33)
            if (
                not stat.S_ISREG(information.st_mode)
                or information.st_nlink != 1
                or (os.name != "nt" and stat.S_IMODE(information.st_mode) != 0o600)
                or len(key) != 32
            ):
                raise ValueError("unsafe witness key")
            return hmac.new(key, payload, hashlib.sha256).hexdigest().encode("ascii")
        except (OSError, ValueError) as error:
            raise PoolError("recovery-required") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _write_runtime_update_state(self, completed: dict) -> None:
        payload = {"schema_version": 1, "completed": completed}
        value = {
            **payload,
            "state_tag": self._governance_tag(
                b"runtime-update-state\0"
                + (
                    json.dumps(payload, sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode("utf-8")
            ).decode("ascii"),
        }
        atomic_write_json(self._runtime_update_state_path, value)

    def _validate_runtime_update_state(self) -> None:
        try:
            raw = self._read_governance_marker(
                self._runtime_update_state_path, 16 * 1024 * 1024
            )
            value = json.loads(raw)
            completed = value["completed"]
            payload = {"schema_version": 1, "completed": completed}
            expected_tag = self._governance_tag(
                b"runtime-update-state\0"
                + (
                    json.dumps(payload, sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode("utf-8")
            ).decode("ascii")
            if (
                not isinstance(value, dict)
                or set(value) != {"schema_version", "completed", "state_tag"}
                or value["schema_version"] != 1
                or not isinstance(completed, dict)
                or any(
                    not isinstance(operation, str)
                    or len(operation) != 32
                    or any(
                        character not in "0123456789abcdef"
                        for character in operation
                    )
                    or not isinstance(entry, dict)
                    or set(entry) != {"journal_tag", "outcome"}
                    or not isinstance(entry["journal_tag"], str)
                    or len(entry["journal_tag"]) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in entry["journal_tag"]
                    )
                    or entry["outcome"] not in {"committed", "restored"}
                    for operation, entry in completed.items()
                )
                or not isinstance(value["state_tag"], str)
                or not hmac.compare_digest(value["state_tag"], expected_tag)
                or raw
                != (
                    json.dumps(value, sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode("utf-8")
            ):
                raise ValueError("invalid runtime update state")
        except (
            OSError,
            KeyError,
            TypeError,
            ValueError,
            UnicodeError,
            json.JSONDecodeError,
        ) as error:
            raise PoolError("recovery-required") from error

    @staticmethod
    def _read_governance_marker(path: Path, limit: int = 2048) -> bytes:
        descriptor = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            before = os.fstat(descriptor)
            raw = os.read(descriptor, limit + 1)
            after = os.fstat(descriptor)
            stable = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or len(raw) > limit
                or any(
                    getattr(before, name) != getattr(after, name)
                    for name in stable
                )
            ):
                raise ValueError("unsafe governance marker")
            return raw
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _consume_governance_execution(
        self,
        lease: AuthorityLease,
        witness_id: str,
        authority_digest: str,
        request_digest: str,
    ):
        lease.require_active()
        if (
            not isinstance(request_digest, str)
            or len(request_digest) != 64
            or any(character not in "0123456789abcdef" for character in request_digest)
        ):
            raise PoolError("unauthorized")
        if not self._create_governance_marker(
            lease, "consumed", witness_id, authority_digest
        ):
            return None
        path = self._governance_marker_path(
            lease, "consumed", witness_id, authority_digest
        )

        def complete(validated) -> None:
            lease.require_active()
            if not callable(validated):
                raise PoolError("unauthorized")
            value = validated()
            try:
                if not isinstance(value, dict) or set(value) != {
                    "record",
                    "execution_sha256",
                }:
                    raise ValueError("invalid execution completion")
                record = value["record"]
                execution_sha256 = value["execution_sha256"]
                expected = {
                    "request_digest": request_digest,
                    "authority_digest": authority_digest,
                    "office_id": lease.authority["office_id"],
                    "generation": lease.authority["generation"],
                    "project_path": lease.authority["project_path"],
                    "target_path": lease.authority["project_path"],
                    "phase": "completed",
                    "diagnostics": {
                        "status": "accepted",
                        "run_id": record["run_id"],
                    },
                    "exit_code": 0,
                    "failure_code": None,
                }
                if (
                    not isinstance(record, dict)
                    or any(record.get(name) != member for name, member in expected.items())
                    or not isinstance(record.get("execution_id"), str)
                    or not record["execution_id"].startswith("execution-")
                    or len(record["execution_id"]) != 42
                    or any(
                        character not in "0123456789abcdef"
                        for character in record["execution_id"][10:]
                    )
                    or not isinstance(execution_sha256, str)
                    or len(execution_sha256) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in execution_sha256
                    )
                    or self._read_governance_marker(path) != b"1\n"
                ):
                    raise ValueError("invalid execution completion")
                payload = {
                    "schema_version": 1,
                    "witness_id": witness_id,
                    "authority_digest": authority_digest,
                    "request_digest": request_digest,
                    "execution_id": record["execution_id"],
                    "execution_sha256": execution_sha256,
                }
                raw = (
                    json.dumps(payload, sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode("utf-8")
                commitment = {
                    **payload,
                    "tag": self._governance_tag(
                        b"governance-execution-completion\0" + raw
                    ).decode("ascii"),
                }
                atomic_write_json(path, commitment)
                if not self.validate_governance_execution(
                    lease,
                    witness_id,
                    authority_digest,
                    request_digest,
                    record["execution_id"],
                    execution_sha256,
                ):
                    raise ValueError("execution completion readback mismatch")
            except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise PoolError("recovery-required") from error

        return complete

    def validate_governance_execution(
        self,
        lease: AuthorityLease,
        witness_id: str,
        authority_digest: str,
        request_digest: str,
        execution_id: str,
        execution_sha256: str,
    ) -> bool:
        lease.require_active()
        path = self._governance_marker_path(
            lease, "consumed", witness_id, authority_digest
        )
        try:
            raw = self._read_governance_marker(path)
            value = json.loads(raw)
            expected = {
                "schema_version": 1,
                "witness_id": witness_id,
                "authority_digest": authority_digest,
                "request_digest": request_digest,
                "execution_id": execution_id,
                "execution_sha256": execution_sha256,
            }
            payload_raw = (
                json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            return (
                isinstance(value, dict)
                and set(value) == GOVERNANCE_COMPLETION_FIELDS
                and all(value.get(name) == member for name, member in expected.items())
                and isinstance(value.get("tag"), str)
                and hmac.compare_digest(
                    value["tag"],
                    self._governance_tag(
                        b"governance-execution-completion\0" + payload_raw
                    ).decode("ascii"),
                )
                and raw
                == (
                    json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode("utf-8")
            )
        except FileNotFoundError:
            return False
        except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
            raise PoolError("recovery-required") from error

    def issue_governance_witness(
        self, receipt: Path, objective: str, artifacts, *, lifetime_seconds: int = 60
    ):
        from internal.governance_witness import issue_witness

        if not isinstance(receipt, Path):
            raise PoolError("unauthorized")
        with self.authority_lease(receipt) as lease:
            def authenticate(validated) -> bytes | None:
                if not callable(validated):
                    raise PoolError("unauthorized")
                value = validated()
                authority_digest = _bytes_digest(lease.authority_bytes)
                if (
                    not isinstance(value, dict)
                    or set(value) != GOVERNANCE_ISSUANCE_FIELDS
                    or value.get("schema_version") != 1
                    or value.get("authority_digest") != authority_digest
                    or not isinstance(value.get("witness_id"), str)
                    or not isinstance(value.get("artifact_sha256"), str)
                    or len(value["artifact_sha256"]) != 64
                    or any(character not in "0123456789abcdef" for character in value["artifact_sha256"])
                ):
                    raise PoolError("unauthorized")
                raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
                path = self._governance_marker_path(
                    lease, "issued", value["witness_id"], authority_digest
                )
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    descriptor = os.open(path, flags, 0o600)
                except FileExistsError:
                    return None
                except OSError as error:
                    raise PoolError("recovery-required") from error
                try:
                    if os.name != "nt":
                        os.fchmod(descriptor, 0o600)
                    view = memoryview(raw)
                    while view:
                        count = os.write(descriptor, view)
                        if count <= 0:
                            raise OSError("governance issuance write made no progress")
                        view = view[count:]
                    os.fsync(descriptor)
                except BaseException:
                    os.close(descriptor)
                    path.unlink(missing_ok=True)
                    raise
                os.close(descriptor)
                if os.name != "nt":
                    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(parent)
                    finally:
                        os.close(parent)
                return self._governance_witness_tag(lease, value["witness_id"])

            return issue_witness(
                receipt,
                objective,
                artifacts,
                lifetime_seconds=lifetime_seconds,
                _lease=lease,
                _authenticate=authenticate,
            )

    def consume_governance_witness(
        self, lease: AuthorityLease, witness_id: str, artifact_sha256: str, tag: bytes
    ) -> bool:
        if (
            not isinstance(witness_id, str)
            or not isinstance(artifact_sha256, str)
            or not isinstance(tag, bytes)
            or len(tag) != 65
        ):
            return False
        issuance = self._governance_issuance(lease, witness_id)
        if issuance is None or not hmac.compare_digest(
            issuance[1]["artifact_sha256"], artifact_sha256
        ):
            return False
        return hmac.compare_digest(tag, self._governance_witness_tag(lease, witness_id))

    def _checkpoint(self, name: str) -> None:
        if self.crash_after == name:
            if self.abrupt_crash:
                os._exit(97)
            raise InjectedCrash(name)

    def _create_witness_key(self) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self._witness_key_path, flags, 0o600)
        try:
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
            os.write(descriptor, secrets.token_bytes(32))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _migrate_governance_storage(self) -> None:
        runtime_names = {path.name for path in self._runtime.iterdir()}
        legacy = {
            "receipts", "pointers", "transactions", "recovery",
            "generations.json", "recovery-authority.json",
        }
        if runtime_names - {"runtime-update-state.json"} not in (
            legacy,
            legacy | {"governance"},
        ):
            raise PoolError("recovery-required")
        if self._governance_state.exists():
            if (
                not self._governance_state.is_dir()
                or {path.name for path in self._governance_state.iterdir()}
                not in ({"consumed", "revoked"}, {"consumed", "issued", "revoked"})
            ):
                raise PoolError("recovery-required")
            if not (self._governance_state / "issued").exists():
                (self._governance_state / "issued").mkdir()
        else:
            self._governance_state.mkdir()
            (self._governance_state / "consumed").mkdir()
            (self._governance_state / "issued").mkdir()
            (self._governance_state / "revoked").mkdir()
        if self._witness_key_path.exists() or self._witness_key_path.is_symlink():
            self._validate_witness_key()
        else:
            self._create_witness_key()
            self._validate_witness_key()
        if (
            self._runtime_update_state_path.exists()
            or self._runtime_update_state_path.is_symlink()
        ):
            self._validate_runtime_update_state()
        else:
            self._write_runtime_update_state({})
            self._validate_runtime_update_state()

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

    @contextmanager
    def _locked(self, *, allow_missing: bool = False):
        self._preflight_lock(allow_missing=allow_missing)
        try:
            with pool_lock(self._lock_path, self.root):
                self._validate_protected_paths(allow_missing=allow_missing)
                if (self.root / "updates" / "runtime-transaction.json").exists():
                    try:
                        from internal.runtime_update import recover_pending_runtime_update

                        recover_pending_runtime_update(self)
                    except Exception as error:
                        raise PoolError("recovery-required") from error
                yield
        except LockError as error:
            raise PoolError("recovery-required") from error

    def initialize(self, count: int = 5) -> None:
        if type(count) is not int or count != 5:
            raise PoolError("invalid-count")
        validate_segment(self.runtime_version)
        self._preflight_existing_root()
        with self._locked(allow_missing=True):
            pool_path = self.root / "pool.json"
            if pool_path.exists():
                self._migrate_governance_storage()
                self._validate_protected_paths()
                self._ensure_initialized()
                return
            self._runtime.mkdir(parents=True, exist_ok=True)
            self._authorities.mkdir(exist_ok=True)
            self._pointers.mkdir(exist_ok=True)
            self._journals.mkdir(exist_ok=True)
            (self._runtime / "recovery").mkdir(exist_ok=True)
            self._governance_state.mkdir(exist_ok=True)
            (self._governance_state / "consumed").mkdir(exist_ok=True)
            (self._governance_state / "issued").mkdir(exist_ok=True)
            (self._governance_state / "revoked").mkdir(exist_ok=True)
            operator = self.root / "operator-secrets"
            operator.mkdir(exist_ok=True)
            if not self._witness_key_path.exists():
                self._create_witness_key()
            self._validate_witness_key()
            if (
                self._runtime_update_state_path.exists()
                or self._runtime_update_state_path.is_symlink()
            ):
                self._validate_runtime_update_state()
            else:
                self._write_runtime_update_state({})
                self._validate_runtime_update_state()
            authority_digests = {}
            generations = {office_id: 0 for office_id in OFFICE_IDS}
            if self._generations_path.exists():
                try:
                    existing_generations = read_json(self._generations_path)
                except (OSError, ValueError, json.JSONDecodeError) as error:
                    raise PoolError("recovery-required") from error
                if existing_generations != {"schema_version": 1, "generations": generations}:
                    raise PoolError("recovery-required")
            else:
                atomic_write_json(
                    self._generations_path,
                    {"schema_version": 1, "generations": generations},
                )
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
            recovery_authority = {"schema_version": 1, "digests": authority_digests}
            if self._recovery_authority_path.exists():
                try:
                    if read_json(self._recovery_authority_path) != recovery_authority:
                        raise ValueError("unexpected recovery authority")
                except (OSError, ValueError, json.JSONDecodeError) as error:
                    raise PoolError("recovery-required") from error
            else:
                atomic_write_json(self._recovery_authority_path, recovery_authority)
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
            self._validate_protected_paths()

    def _preflight_lock(self, *, allow_missing: bool = False) -> None:
        path = self._lock_path
        if path.is_symlink():
            raise PoolError("recovery-required")
        if not path.exists():
            if allow_missing:
                return
            raise PoolError("recovery-required")
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError("invalid pool lock")
            path.resolve(strict=True).relative_to(self.root.resolve(strict=True))
            if os.name == "nt":
                require_within(open_identity(path), open_identity(self.root))
        except (OSError, ValueError) as error:
            raise PoolError("recovery-required") from error

    def _validate_protected_paths(self, *, allow_missing: bool = False) -> None:
        try:
            root = self.root.resolve(strict=True)
            paths = [self.root, self._lock_path]
            for parent in (
                self._runtime,
                self.root / "offices",
                self.root / "operator-secrets",
                self.root / "components",
                self.root / "updates",
            ):
                if parent.name in {"components", "updates"} and not (
                    parent.exists() or parent.is_symlink()
                ):
                    continue
                paths.append(parent)
                if not parent.is_symlink():
                    for directory, names, files in os.walk(parent, followlinks=False):
                        base = Path(directory)
                        paths.extend(base / name for name in names)
                        paths.extend(base / name for name in files)
            paths.append(self.root / "pool.json")
            paths.append(self._witness_key_path)
            root_identity = open_identity(self.root) if os.name == "nt" else None
            for path in paths:
                if path.is_symlink():
                    raise ValueError("protected path is a link")
                if allow_missing and not path.exists():
                    continue
                path.resolve(strict=True).relative_to(root)
                if os.name == "nt":
                    require_within(open_identity(path), root_identity)
        except (OSError, ValueError) as error:
            raise PoolError("recovery-required") from error

    def _preflight_existing_root(self) -> None:
        if os.name != "nt" or not self.root.exists():
            return
        try:
            root_identity = open_identity(self.root)
            require_within(root_identity, root_identity)
            for path in (
                self._runtime,
                self.root / "offices",
                self.root / "components",
                self.root / "updates",
            ):
                if path.exists():
                    require_within(open_identity(path), root_identity)
        except (OSError, ValueError) as error:
            raise PoolError("recovery-required") from error

    def _verify_runtime_containment(self) -> None:
        if os.name != "nt":
            return
        try:
            root_identity = open_identity(self.root)
            for path in (
                self._runtime,
                self.root / "offices",
                self.root / "components",
                self.root / "updates",
            ):
                if path.exists():
                    require_within(open_identity(path), root_identity)
        except (OSError, ValueError) as error:
            raise PoolError("recovery-required") from error

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
        self._validate_witness_key()
        self._validate_runtime_update_state()
        self._generation_registry()
        self._validate_runtime_members()
        return value

    @staticmethod
    def _hex_name(name: str, suffix: str, length: int) -> bool:
        stem = name.removesuffix(suffix)
        return (
            name.endswith(suffix)
            and len(stem) == length
            and all(character in "0123456789abcdef" for character in stem)
        )

    def _validate_runtime_members(self) -> None:
        expected = {
            "receipts",
            "pointers",
            "transactions",
            "recovery",
            "governance",
            "generations.json",
            "recovery-authority.json",
            "runtime-update-state.json",
        }
        if {path.name for path in self._runtime.iterdir()} != expected:
            raise PoolError("recovery-required")
        rules = {
            self._authorities: lambda name: self._hex_name(name, ".receipt.json", 64),
            self._pointers: lambda name: self._hex_name(name, ".json", 64),
            self._journals: lambda name: self._hex_name(name, ".json", 32),
            self._runtime / "recovery": lambda name: name in {
                f"{office_id}.json" for office_id in OFFICE_IDS
            },
            self._governance_state / "consumed": self._valid_governance_marker,
            self._governance_state / "issued": self._valid_governance_marker,
            self._governance_state / "revoked": self._valid_governance_marker,
        }
        if (
            not self._governance_state.is_dir()
            or {path.name for path in self._governance_state.iterdir()}
            != {"consumed", "issued", "revoked"}
        ):
            raise PoolError("recovery-required")
        for directory, accepted in rules.items():
            if not directory.is_dir() or any(
                not path.is_file() or not accepted(path.name) for path in directory.iterdir()
            ):
                raise PoolError("recovery-required")

    @staticmethod
    def _valid_governance_marker(name: str) -> bool:
        authority, separator, witness = name.partition("-")
        return (
            bool(separator)
            and len(authority) == 64
            and all(character in "0123456789abcdef" for character in authority)
            and witness.startswith("witness-")
            and len(witness) == 40
            and all(character in "0123456789abcdef" for character in witness[8:])
        )

    def _generation_registry(self) -> dict:
        try:
            value = read_json(self._generations_path)
            generations = value["generations"]
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
            raise PoolError("recovery-required") from error
        if (
            set(value) != {"schema_version", "generations"}
            or value["schema_version"] != 1
            or set(generations) != set(OFFICE_IDS)
            or any(type(number) is not int or number < 0 for number in generations.values())
        ):
            raise PoolError("recovery-required")
        return generations

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
        generation = self._generation_registry()[office_id]
        try:
            value = read_json(self._state_path(office_id))
            if (
                type(value.get("generation")) is int
                and value["generation"] >= 0
                and value["generation"] != generation
            ):
                raise PoolError("recovery-required")
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
        for path in office.iterdir():
            if path.name in {"office-state.json", "work", "history"}:
                continue
            if path.name != "runtime" or not self._valid_office_runtime(path):
                paths.append(path)
        return sorted(paths, key=lambda path: path.name)

    def _valid_office_runtime(self, runtime: Path) -> bool:
        executable = "ao2.exe" if os.name == "nt" else "ao2"
        version = runtime / "versions" / self.runtime_version
        expected = {runtime, runtime / "versions", version, version / executable}
        try:
            valid = (
                all(path.is_dir() for path in expected - {version / executable})
                and (version / executable).is_file()
                and set(runtime.rglob("*")) == expected - {runtime}
            )
            if valid and os.name == "nt":
                root_identity = open_identity(runtime)
                for path in expected:
                    require_within(open_identity(path), root_identity)
            return valid
        except OSError:
            return False

    def _mark_recovery(self, office_id: str, state: dict, reason: str) -> None:
        value = dict(state)
        value["status"] = "recovery-required"
        value["reason"] = reason
        atomic_write_json(self._state_path(office_id), value)

    def _quarantine_journal(self, journal: dict, reason: str) -> None:
        office_id = journal["office_id"]
        state = self._read_state(office_id)
        marker = self._marker_path(office_id)
        if not marker.exists():
            atomic_write_json(
                marker,
                {
                    "schema_version": 1,
                    "office_id": office_id,
                    "generation": state["generation"],
                    "reason": reason,
                },
            )
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
        with self._locked():
            self._ensure_initialized()
            self._reconcile()
            states = {office_id: self._read_state(office_id) for office_id in OFFICE_IDS}
            self._validate_registry_ownership(states)
            if any(
                state.get("holder_digest") == holder and state["status"] != "free"
                for state in states.values()
            ):
                raise PoolError("already-claimed")
            if self._pointer_path(holder).exists():
                raise PoolError("recovery-required")
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
            generations = self._generation_registry()
            generation = generations[office_id] + 1
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
            generations[office_id] = generation
            atomic_write_json(
                self._generations_path,
                {"schema_version": 1, "generations": generations},
            )
            self._checkpoint("claim:generation")
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
        with self._locked():
            self._ensure_initialized()
            authority, _, record, state = self._authorize(receipt_path)
            self._reconcile()
            authority, _, record, state = self._authorize(authority)
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

    @contextmanager
    def _authority_lease_locked(self, receipt_path: Path):
        self._ensure_initialized()
        self._reconcile()
        path, raw, authority, state = self._authorize(receipt_path)
        if self._unknown_paths(authority["office_id"]):
            self._mark_recovery(authority["office_id"], state, "unknown-residue")
            raise PoolError("recovery-required")
        lease = object.__new__(AuthorityLease)
        object.__setattr__(lease, "authority_path", path)
        object.__setattr__(lease, "authority_bytes", raw)
        object.__setattr__(lease, "authority", authority)
        active = True

        def require(candidate) -> None:
            if not active or candidate is not lease:
                raise PoolError("unauthorized")

        object.__setattr__(lease, "_checker", require)
        try:
            yield lease
        finally:
            active = False

    @contextmanager
    def authority_lease(self, receipt_path: Path):
        with self._locked():
            with self._authority_lease_locked(receipt_path) as lease:
                yield lease

    def release(self, receipt_path) -> None:
        with self._locked():
            self._ensure_initialized()
            try:
                authority, _, _, _ = self._authorize(receipt_path)
            except PoolError as error:
                if error.code != "unauthorized":
                    raise
                journal_file, journal = self._pending_release(receipt_path)
                committed = journal["phase"] == "committed"
                self._reconcile_entry(journal)
                journal_file.unlink()
                if committed:
                    return
                authority = Path(receipt_path)
            else:
                self._reconcile()
            authority, authority_bytes, record, state = self._authorize(authority)
            office_id = record["office_id"]
            if self._unknown_paths(office_id):
                self._mark_recovery(office_id, state, "dirty-release")
                raise PoolError("recovery-required")
            pointer_file = self._pointer_path(record["holder_digest"])
            expected_pointer = {
                "schema_version": 1,
                "holder_digest": record["holder_digest"],
                "office_id": office_id,
                "generation": record["generation"],
                "authority_name": authority.name,
            }
            if pointer_file.exists():
                try:
                    if read_json(pointer_file) != expected_pointer:
                        raise ValueError("unexpected pointer")
                except (OSError, ValueError, json.JSONDecodeError):
                    self._mark_recovery(office_id, state, "corrupt-pointer")
                    raise PoolError("recovery-required")
            else:
                atomic_write_json(pointer_file, expected_pointer)
            pointer_bytes = pointer_file.read_bytes()
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
                "pointer_existed": True,
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
        with self._locked():
            self._ensure_initialized()
            try:
                supplied = Path(key_path).read_bytes()
            except (OSError, TypeError) as error:
                raise PoolError("unauthorized") from error
            try:
                digests = read_json(self._recovery_authority_path)["digests"]
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
                raise PoolError("recovery-required") from error
            if not secrets.compare_digest(_bytes_digest(supplied), digests.get(office_id, "")):
                raise PoolError("unauthorized")
            pending = self._pending_recovery(office_id, generation)
            if pending is not None:
                journal_file, journal = pending
                committed = journal["phase"] == "committed"
                self._reconcile_entry(journal)
                journal_file.unlink()
                if committed:
                    return
            state = self._read_state(office_id)
            if state["generation"] != generation:
                raise PoolError("stale-generation")
            if state["status"] != "recovery-required":
                raise PoolError("recovery-not-required")
            self._reconcile()
            state = self._read_state(office_id)
            if state["generation"] != generation or state["status"] != "recovery-required":
                raise PoolError("recovery-required")
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
                location = "work" if source.parent == self._office(office_id) / "work" else "office"
                moves.append(
                    (
                        source,
                        archive / "residue" / location / source.name,
                        "residue",
                    )
                )
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
                if kind == "state":
                    self._checkpoint("recover:state")
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
        members = sorted(self._journals.iterdir(), key=lambda path: path.name)
        if any(not path.is_file() or path.suffix != ".json" for path in members):
            raise PoolError("recovery-required")
        for journal_file in members:
            try:
                journal = read_json(journal_file)
                kind = journal["kind"]
                phase = journal["phase"]
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
                raise PoolError("recovery-required") from error
            try:
                self._validate_journal(journal_file, journal)
            except PoolError:
                if journal.get("office_id") in OFFICE_IDS:
                    self._quarantine_journal(journal, "invalid-journal")
                raise
            self._reconcile_entry(journal)
            journal_file.unlink()

    def _pending_release(self, receipt_path) -> tuple[Path, dict]:
        try:
            path = Path(receipt_path)
            validate_segment(path.name)
            if path.is_symlink() or path.parent.resolve(strict=True) != self._authorities.resolve(
                strict=True
            ):
                raise ValueError("receipt path is outside protected storage")
            if os.name == "nt":
                require_within(open_identity(path.parent), open_identity(self._authorities))
        except (OSError, TypeError, ValueError) as error:
            raise PoolError("unauthorized") from error
        for journal_file in self._journal_members():
            try:
                journal = read_json(journal_file)
                self._validate_journal(journal_file, journal)
            except (OSError, ValueError, KeyError, json.JSONDecodeError, PoolError):
                raise PoolError("recovery-required") from None
            if journal["kind"] == "release" and journal["authority_name"] == path.name:
                authority = json.loads(_decoded(journal["authority_bytes"]))
                self._validate_project_record(authority)
                return journal_file, journal
        raise PoolError("unauthorized")

    def _pending_recovery(self, office_id: str, generation: int):
        match = None
        for journal_file in self._journal_members():
            try:
                journal = read_json(journal_file)
                self._validate_journal(journal_file, journal)
            except (OSError, ValueError, KeyError, json.JSONDecodeError, PoolError):
                raise PoolError("recovery-required") from None
            if (
                journal["kind"] == "recover"
                and journal["office_id"] == office_id
                and journal["before_state"].get("generation") == generation
            ):
                if match is not None:
                    raise PoolError("recovery-required")
                match = journal_file, journal
        return match

    def _journal_members(self) -> list[Path]:
        members = sorted(self._journals.iterdir(), key=lambda path: path.name)
        if any(not path.is_file() or path.suffix != ".json" for path in members):
            raise PoolError("recovery-required")
        return members

    def _reconcile_entry(self, journal: dict) -> None:
        committed = journal["phase"] == "committed"
        if journal["kind"] == "claim":
            self._reconcile_claim(journal, committed)
        elif journal["kind"] == "release":
            self._reconcile_release(journal, committed)
        elif journal["kind"] == "recover":
            self._reconcile_recover(journal, committed)
        else:
            raise PoolError("recovery-required")

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
                authority_bytes = _decoded(journal["authority_bytes"])
                authority = json.loads(authority_bytes)
                if not isinstance(authority, dict) or set(authority) != AUTHORITY_FIELDS:
                    raise ValueError("invalid authority")
                if (
                    authority["schema_version"] != 1
                    or authority["authority_id"] != authority_id
                    or authority["holder_digest"] != holder
                    or authority["office_id"] != journal["office_id"]
                    or type(authority["generation"]) is not int
                    or authority["generation"] < 1
                    or authority["mode"] not in MODES
                    or any(
                        not isinstance(authority[field], str)
                        or len(authority[field]) != 64
                        or any(character not in "0123456789abcdef" for character in authority[field])
                        for field in ("holder_digest", "task_digest")
                    )
                    or not isinstance(authority["project_path"], str)
                    or type(authority["project_volume"]) is not int
                    or not isinstance(authority["project_file_id"], str)
                ):
                    raise ValueError("incoherent authority")
                expected_pointer = {
                    "schema_version": 1,
                    "holder_digest": authority["holder_digest"],
                    "office_id": authority["office_id"],
                    "generation": authority["generation"],
                    "authority_name": journal["authority_name"],
                }
                expected_after = dict(authority)
                expected_after.pop("authority_id")
                expected_after["status"] = "occupied"
                expected_after["authority_name"] = journal["authority_name"]
                expected_after["authority_digest"] = _bytes_digest(authority_bytes)
                before = journal["before_state"]
                after = journal["after_state"]
                if journal["kind"] == "claim":
                    registry_generation = self._generation_registry()[journal["office_id"]]
                    minimum_registry = after["generation"] - (
                        1 if journal["phase"] == "prepared" else 0
                    )
                    if (
                        not self._valid_state(before, "free")
                        or before["office_id"] != journal["office_id"]
                        or after != expected_after
                        or not self._valid_state(after, "occupied")
                        or after["generation"] <= before["generation"]
                        or registry_generation < minimum_registry
                        or journal["pointer"] != expected_pointer
                    ):
                        raise ValueError("illegal claim transition")
                else:
                    pointer_bytes = _decoded(journal["pointer_bytes"])
                    if (
                        not self._valid_state(before, "occupied")
                        or before != expected_after
                        or journal["pointer_existed"] is not True
                        or json.loads(pointer_bytes) != expected_pointer
                        or after != self._free_state(journal["office_id"], before["generation"])
                    ):
                        raise ValueError("illegal release transition")
            except (KeyError, TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
                raise PoolError("recovery-required") from None
        else:
            self._validate_recovery_journal(journal)
        self._validate_journal_prefix(journal)

    @staticmethod
    def _file_matches(path: Path, expected: bytes) -> bool:
        return path.is_file() and path.read_bytes() == expected

    def _validate_journal_prefix(self, journal: dict) -> None:
        office_id = journal["office_id"]
        before = journal["before_state"]
        after = journal["after_state"]
        committed = journal["phase"] == "committed"
        if journal["kind"] != "recover" or not before.get("corrupt_state"):
            try:
                state = self._read_state_file(self._state_path(office_id))
            except (OSError, ValueError, json.JSONDecodeError):
                raise PoolError("recovery-required") from None
        if journal["kind"] == "claim":
            authority = self._authorities / journal["authority_name"]
            pointer = self._pointers / journal["pointer_name"]
            authority_present = self._file_matches(
                authority, _decoded(journal["authority_bytes"])
            )
            pointer_present = self._file_matches(
                pointer,
                (
                    json.dumps(journal["pointer"], sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode("utf-8"),
            )
            registry = self._generation_registry()[office_id]
            prefixes = {
                (after["generation"] - 1, self._state_key(before), False, False),
                (after["generation"], self._state_key(before), False, False),
                (after["generation"], self._state_key(after), False, False),
                (after["generation"], self._state_key(after), True, False),
                (after["generation"], self._state_key(after), True, True),
            }
            current = (registry, self._state_key(state), authority_present, pointer_present)
            fully_durable = current == (
                after["generation"],
                self._state_key(after),
                True,
                True,
            )
        elif journal["kind"] == "release":
            authority = self._authorities / journal["authority_name"]
            pointer = self._pointers / journal["pointer_name"]
            authority_present = self._file_matches(
                authority, _decoded(journal["authority_bytes"])
            )
            pointer_present = self._file_matches(pointer, _decoded(journal["pointer_bytes"]))
            prefixes = {
                (self._state_key(before), True, True),
                (self._state_key(before), False, True),
                (self._state_key(before), False, False),
                (self._state_key(after), False, False),
            }
            current = (self._state_key(state), authority_present, pointer_present)
            fully_durable = current == (self._state_key(after), False, False)
        else:
            moves = [
                (Path(item["source"]), Path(item["destination"]), item["kind"])
                for item in journal["moves"]
            ]
            moved = []
            corrupt_before = before.get("corrupt_state") is True
            state_path = self._state_path(office_id)
            state_stage = None
            for source, destination, kind in moves:
                source_present = source.exists()
                destination_present = destination.exists()
                replacement_state = (
                    corrupt_before
                    and kind == "state"
                    and source == state_path
                    and destination_present
                    and source_present
                    and self._file_matches(
                        source,
                        (
                            json.dumps(after, sort_keys=True, separators=(",", ":"))
                            + "\n"
                        ).encode("utf-8"),
                    )
                )
                if source_present == destination_present and not replacement_state:
                    raise PoolError("recovery-required")
                moved.append(destination_present)
                if corrupt_before and kind == "state":
                    if replacement_state:
                        state_stage = "after"
                    elif destination_present:
                        state_stage = "missing"
                    else:
                        try:
                            self._read_state_file(source)
                        except (OSError, ValueError, json.JSONDecodeError):
                            state_stage = "before"
                        else:
                            raise PoolError("recovery-required")
            if moved != sorted(moved, reverse=True):
                raise PoolError("recovery-required")
            evidence = Path(journal["archive"]) / "recovery.json"
            expected_evidence = (
                json.dumps(journal["evidence"], sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
            evidence_present = self._file_matches(evidence, expected_evidence)
            marker_present = self._marker_path(office_id).exists()
            all_moved = all(moved)
            if corrupt_before:
                if state_stage not in {"before", "missing", "after"}:
                    raise PoolError("recovery-required")
                state_is_after = state_stage == "after"
            else:
                if state not in (before, after):
                    raise PoolError("recovery-required")
                state_is_after = state == after
            if evidence_present and not all_moved:
                raise PoolError("recovery-required")
            if state_is_after and not evidence_present:
                raise PoolError("recovery-required")
            prefixes = {True}
            current = True
            fully_durable = (
                all_moved and evidence_present and state_is_after and not marker_present
            )
        if (committed and not fully_durable) or (not committed and current not in prefixes):
            raise PoolError("recovery-required")

    @staticmethod
    def _state_key(value: dict) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _valid_state(value, status: str) -> bool:
        if not isinstance(value, dict) or value.get("status") != status:
            return False
        fields = set(value)
        expected = {
            "free": FREE_STATE_FIELDS,
            "occupied": OCCUPIED_STATE_FIELDS,
            "recovery-required": FREE_STATE_FIELDS | {"reason"},
        }[status]
        if status == "recovery-required" and fields == OCCUPIED_STATE_FIELDS | {"reason"}:
            expected = fields
        return (
            fields == expected
            and value.get("schema_version") == 1
            and value.get("office_id") in OFFICE_IDS
            and type(value.get("generation")) is int
            and value["generation"] >= 0
        )

    def _validate_recovery_journal(self, journal: dict) -> None:
        office_id = journal["office_id"]
        before = journal["before_state"]
        after = journal["after_state"]
        corrupt_before = (
            isinstance(before, dict)
            and before.get("corrupt_state") is True
            and set(before) == FREE_STATE_FIELDS | {"corrupt_state"}
            and before.get("status") == "recovery-required"
        )
        if not (self._valid_state(before, "recovery-required") or corrupt_before):
            raise PoolError("recovery-required")
        generation = before.get("generation")
        if after != self._free_state(office_id, generation):
            raise PoolError("recovery-required")
        archive = self._office(office_id) / "history" / (
            f"recovery-g{generation}-{journal['operation_id']}"
        )
        evidence = journal.get("evidence")
        if (
            Path(journal["archive"]) != archive
            or not isinstance(journal["moves"], list)
            or not isinstance(evidence, dict)
            or set(evidence) != {"schema_version", "office_id", "generation", "entries"}
            or evidence["schema_version"] != 1
            or evidence["office_id"] != office_id
            or evidence["generation"] != generation
            or not isinstance(evidence["entries"], list)
        ):
            raise PoolError("recovery-required")
        office = self._office(office_id)
        kinds = {"state", "residue", "authority", "pointer"}
        actual_entries = []
        seen_sources = set()
        seen_destinations = set()
        for item in journal["moves"]:
            if (
                not isinstance(item, dict)
                or set(item) != {"source", "destination", "kind"}
                or item["kind"] not in kinds
            ):
                raise PoolError("recovery-required")
            source = Path(item["source"])
            destination = Path(item["destination"])
            try:
                destination.resolve(strict=False).relative_to(archive.resolve(strict=False))
            except (OSError, ValueError):
                raise PoolError("recovery-required") from None
            source_resolved = source.resolve(strict=False)
            work = (office / "work").resolve(strict=False)
            office_resolved = office.resolve(strict=False)
            source_kind = None
            expected_destination = None
            if corrupt_before and source == self._state_path(office_id):
                source_kind = "state"
                expected_destination = archive / "unknown-office-state.json"
            elif before.get("authority_name") and source == (
                self._authorities / before["authority_name"]
            ):
                source_kind = "authority"
                expected_destination = archive / "authority.json"
            elif before.get("holder_digest") and source == self._pointer_path(
                before["holder_digest"]
            ):
                source_kind = "pointer"
                expected_destination = archive / "pointer.json"
            elif source_resolved.parent == work:
                source_kind = "residue"
                expected_destination = archive / "residue" / "work" / source.name
            elif (
                source_resolved.parent == office_resolved
                and source.name not in {"office-state.json", "work", "history"}
            ):
                source_kind = "residue"
                expected_destination = archive / "residue" / "office" / source.name
            if (
                source_kind != item["kind"]
                or destination != expected_destination
                or source in seen_sources
                or destination in seen_destinations
            ):
                raise PoolError("recovery-required")
            seen_sources.add(source)
            seen_destinations.add(destination)
            candidate = destination if destination.is_file() else source
            if candidate.is_file():
                raw = candidate.read_bytes()
                actual_entries.append(
                    {"kind": item["kind"], "sha256": _bytes_digest(raw), "size": len(raw)}
                )
        for entry in evidence["entries"]:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"kind", "sha256", "size"}
                or entry["kind"] not in kinds
                or not isinstance(entry["sha256"], str)
                or len(entry["sha256"]) != 64
                or type(entry["size"]) is not int
                or entry["size"] < 0
            ):
                raise PoolError("recovery-required")
        if sorted(evidence["entries"], key=lambda entry: (entry["kind"], entry["sha256"])) != sorted(
            actual_entries, key=lambda entry: (entry["kind"], entry["sha256"])
        ):
            raise PoolError("recovery-required")

    def _validate_registry_ownership(self, states: dict[str, dict]) -> None:
        authorities = {
            state["authority_name"]
            for state in states.values()
            if state.get("status") != "free" and "authority_name" in state
        }
        pointers = {
            f"{state['holder_digest']}.json"
            for state in states.values()
            if state.get("status") != "free" and "holder_digest" in state
        }
        if (
            {path.name for path in self._authorities.iterdir()} != authorities
            or {path.name for path in self._pointers.iterdir()} != pointers
        ):
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
        evidence_path = archive / "recovery.json"
        expected_evidence = (
            json.dumps(journal["evidence"], sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if evidence_path.exists() and evidence_path.read_bytes() != expected_evidence:
            self._quarantine_journal(journal, "unknown-recovery-evidence")
        if archive.exists():
            destinations = [destination.resolve(strict=False) for _, destination in moves]
            for path in archive.rglob("*"):
                if path == evidence_path:
                    continue
                resolved = path.resolve(strict=False)
                if not any(
                    resolved == destination
                    or destination in resolved.parents
                    or resolved in destination.parents
                    for destination in destinations
                ):
                    self._quarantine_journal(journal, "unknown-recovery-archive")
        if committed:
            for source, destination in moves:
                if source.exists() and destination.exists():
                    if source != self._state_path(journal["office_id"]) or not self._file_matches(
                        source,
                        (
                            json.dumps(
                                journal["after_state"],
                                sort_keys=True,
                                separators=(",", ":"),
                            )
                            + "\n"
                        ).encode("utf-8"),
                    ):
                        self._quarantine_journal(journal, "recovery-move-collision")
                    continue
                if source.exists():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(source, destination)
                elif not destination.exists():
                    self._quarantine_journal(journal, "missing-recovery-bytes")
            archive.mkdir(parents=True, exist_ok=True)
            atomic_write_json(archive / "recovery.json", journal["evidence"])
            atomic_write_json(self._state_path(journal["office_id"]), journal["after_state"])
            self._marker_path(journal["office_id"]).unlink(missing_ok=True)
        else:
            for source, destination in reversed(moves):
                if destination.exists() and source.exists():
                    if source == self._state_path(journal["office_id"]):
                        try:
                            if read_json(source) != journal["after_state"]:
                                raise ValueError("unknown replacement state")
                        except (OSError, ValueError, json.JSONDecodeError):
                            self._quarantine_journal(journal, "recovery-move-collision")
                        source.unlink()
                    else:
                        self._quarantine_journal(journal, "recovery-move-collision")
                if destination.exists():
                    source.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(destination, source)
                elif not source.exists():
                    self._quarantine_journal(journal, "missing-recovery-bytes")
            evidence_path.unlink(missing_ok=True)
            if archive.exists():
                for directory in sorted(
                    (path for path in archive.rglob("*") if path.is_dir()),
                    key=lambda path: len(path.parts),
                    reverse=True,
                ):
                    directory.rmdir()
                archive.rmdir()
            if not journal["before_state"].get("corrupt_state"):
                atomic_write_json(self._state_path(journal["office_id"]), journal["before_state"])

    def public_status(self) -> dict:
        with self._locked():
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
