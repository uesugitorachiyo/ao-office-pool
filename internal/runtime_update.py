import hashlib
import hmac
import json
import os
import shutil
import stat
import uuid
from contextlib import nullcontext
from pathlib import Path

from internal.mission_bridge import _validate_schema
from internal.pool import OFFICE_IDS, Pool, PoolError
from internal.transactions import atomic_write_json, read_json
from internal.windows_identity import retain_identities
from internal.windows_paths import validate_segment


RUNTIME_SCHEMA = Path(__file__).parents[1] / "schemas/runtime-package.schema.json"
_MANIFEST = "runtime-package.json"
_ASSET = "ao2"
_ANCHOR = "runtime-anchor.json"
_MAX_ASSET = 64 * 1024 * 1024
_COMPONENT_FIELDS = {
    "name", "version", "repository", "commit", "asset", "license", "sha256"
}


class RuntimeUpdateError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_object(raw: bytes) -> dict:
    def unique(pairs):
        value = {}
        for name, member in pairs:
            if name in value:
                raise ValueError("duplicate JSON field")
            value[name] = member
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def _read_regular(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError("unsafe package member")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        identity = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) > limit or any(getattr(before, name) != getattr(after, name) for name in identity):
            raise ValueError("package member changed")
        return raw
    finally:
        os.close(descriptor)


def _create_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError("write made no progress")
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


class RuntimeUpdate:
    def __init__(
        self,
        root: Path,
        *,
        crash_after: str | None = None,
        abrupt_crash: bool = False,
    ):
        if not isinstance(root, Path):
            raise TypeError("root must be a pathlib.Path")
        self.root = root.resolve(strict=False)
        self.crash_after = crash_after
        self.abrupt_crash = abrupt_crash

    @property
    def _lock_manifest(self) -> Path:
        return self.root / "manifests" / "components.lock.json"

    @property
    def _journal(self) -> Path:
        return self.root / "updates" / "runtime-transaction.json"

    @property
    def _journal_key(self) -> Path:
        return self.root / "operator-secrets" / "governance-witness.key"

    def _journal_key_bytes(self) -> bytes:
        try:
            key = _read_regular(self._journal_key, 32)
            if len(key) != 32:
                raise ValueError("invalid runtime journal key")
            return key
        except (OSError, ValueError) as error:
            raise RuntimeUpdateError("runtime-recovery-required") from error

    def _pool(self) -> Pool:
        try:
            metadata = read_json(self.root / "pool.json")
            return Pool(self.root, runtime_version=metadata["runtime_version"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeUpdateError("runtime-update-not-initialized") from error

    def _checkpoint(self, name: str) -> None:
        if self.crash_after == name:
            if self.abrupt_crash:
                os._exit(98)
            raise RuntimeUpdateError("runtime-update-interrupted")

    def _package(self, candidate: Path) -> tuple[dict, bytes, bytes]:
        try:
            if not isinstance(candidate, Path) or candidate.is_symlink():
                raise ValueError("unsafe candidate")
            candidate = candidate.resolve(strict=True)
            members = (candidate / _MANIFEST, candidate / _ASSET)
            retained = (
                retain_identities(candidate, members)
                if os.name == "nt"
                else nullcontext()
            )
            with retained:
                if not candidate.is_dir() or {path.name for path in candidate.iterdir()} != {_MANIFEST, _ASSET}:
                    raise ValueError("unexpected package members")
                manifest_raw = _read_regular(candidate / _MANIFEST, 64 * 1024)
                asset_raw = _read_regular(candidate / _ASSET, _MAX_ASSET)
            manifest = _strict_object(manifest_raw)
            _validate_schema(manifest, RUNTIME_SCHEMA)
            validate_segment(manifest["version"])
            if manifest_raw != _canonical(manifest) or not asset_raw or _digest(asset_raw) != manifest["sha256"]:
                raise ValueError("package digest mismatch")
            return manifest, manifest_raw, asset_raw
        except RuntimeUpdateError:
            raise
        except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeUpdateError("runtime-package-invalid") from error

    def _component_authority(self) -> tuple[dict, bytes]:
        raw = _read_regular(self._lock_manifest, 1024 * 1024)
        lock = _strict_object(raw)
        if (
            set(lock) != {"schema_version", "components"}
            or lock["schema_version"] != 1
            or not isinstance(lock["components"], list)
        ):
            raise ValueError("invalid component lock")
        return lock, raw

    @staticmethod
    def _anchored_component(manifest: dict, lock: dict) -> None:
        matches = [
            row
            for row in lock["components"]
            if isinstance(row, dict) and row.get("name") == "ao2"
        ]
        if len(matches) != 1 or set(matches[0]) != _COMPONENT_FIELDS:
            raise ValueError("missing independent AO2 anchor")
        component = matches[0]
        expected = {
            name: component[name]
            for name in ("name", "version", "commit", "asset", "sha256")
        }
        if manifest != {"schema_version": 1, **expected}:
            raise ValueError("package differs from component lock")

    def _anchor(
        self,
        version: str,
        manifest_raw: bytes,
        asset_raw: bytes,
        components_raw: bytes,
    ) -> dict:
        payload = {
            "schema_version": 1,
            "version": version,
            "manifest_sha256": _digest(manifest_raw),
            "asset_sha256": _digest(asset_raw),
            "components_sha256": _digest(components_raw),
        }
        return {
            **payload,
            "anchor_tag": hmac.new(
                self._journal_key_bytes(),
                b"runtime-package-anchor\0" + _canonical(payload),
                hashlib.sha256,
            ).hexdigest(),
        }

    def stage(self, candidate: Path) -> Path:
        pool = self._pool()
        try:
            with pool._locked():
                pool._ensure_initialized()
                self._recover(pool)
                manifest, manifest_raw, asset_raw = self._package(candidate)
                try:
                    component_lock, components_raw = self._component_authority()
                    self._anchored_component(manifest, component_lock)
                except (
                    OSError,
                    KeyError,
                    TypeError,
                    ValueError,
                    json.JSONDecodeError,
                ) as error:
                    raise RuntimeUpdateError(
                        "runtime-package-incompatible"
                    ) from error
                version = manifest["version"]
                target = self.root / "components" / "ao2" / version
                if target.exists() or target.is_symlink():
                    raise RuntimeUpdateError("runtime-version-exists")
                parent = target.parent
                parent.mkdir(parents=True, exist_ok=True)
                temporary = parent / f".{version}.{uuid.uuid4().hex}.tmp"
                temporary.mkdir()
                try:
                    _create_bytes(temporary / _MANIFEST, manifest_raw)
                    _create_bytes(temporary / _ASSET, asset_raw)
                    _create_bytes(
                        temporary / _ANCHOR,
                        _canonical(
                            self._anchor(
                                version,
                                manifest_raw,
                                asset_raw,
                                components_raw,
                            )
                        ),
                    )
                    self._checkpoint("stage:prepared")
                    os.rename(temporary, target)
                    return target
                finally:
                    if temporary.exists():
                        shutil.rmtree(temporary)
        except RuntimeUpdateError:
            raise
        except PoolError as error:
            raise RuntimeUpdateError("runtime-recovery-required") from error
        except (OSError, ValueError) as error:
            raise RuntimeUpdateError("runtime-stage-failed") from error

    def _staged(self, version: str) -> tuple[dict, bytes, bytes]:
        try:
            version = validate_segment(version)
            target = self.root / "components" / "ao2" / version
            members = tuple(
                target / name for name in (_MANIFEST, _ASSET, _ANCHOR)
            )
            retained = (
                retain_identities(target, members)
                if os.name == "nt"
                else nullcontext()
            )
            with retained:
                if target.is_symlink() or not target.is_dir() or {path.name for path in target.iterdir()} != {_MANIFEST, _ASSET, _ANCHOR}:
                    raise ValueError("missing staged package")
                manifest_raw = _read_regular(target / _MANIFEST, 64 * 1024)
                asset_raw = _read_regular(target / _ASSET, _MAX_ASSET)
                anchor_raw = _read_regular(target / _ANCHOR, 2048)
            manifest = _strict_object(manifest_raw)
            _validate_schema(manifest, RUNTIME_SCHEMA)
            anchor = _strict_object(anchor_raw)
            component_lock, components_raw = self._component_authority()
            self._anchored_component(manifest, component_lock)
            expected_anchor = self._anchor(
                version,
                manifest_raw,
                asset_raw,
                components_raw,
            )
            if (
                manifest["version"] != version
                or manifest_raw != _canonical(manifest)
                or not asset_raw
                or _digest(asset_raw) != manifest["sha256"]
                or anchor != expected_anchor
                or anchor_raw != _canonical(anchor)
            ):
                raise ValueError("staged package changed")
            return manifest, asset_raw, components_raw
        except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeUpdateError("runtime-package-tampered") from error

    @staticmethod
    def _runtime_tree(path: Path, version: str, asset: bytes) -> None:
        executable = path / "versions" / version / ("ao2.exe" if os.name == "nt" else "ao2")
        executable.parent.mkdir(parents=True)
        _create_bytes(executable, asset)

    @staticmethod
    def _runtime_digest(path: Path, version: str) -> str | None:
        executable = path / "versions" / version / ("ao2.exe" if os.name == "nt" else "ao2")
        expected = {path / "versions", path / "versions" / version, executable}
        try:
            if path.is_symlink() or not path.is_dir() or set(path.rglob("*")) != expected:
                return None
            return _digest(_read_regular(executable, _MAX_ASSET))
        except (OSError, ValueError):
            return None

    @classmethod
    def _runtime_matches(cls, path: Path, version: str, digest: str) -> bool:
        return hmac.compare_digest(cls._runtime_digest(path, version) or "", digest)

    def _validated_journal(self) -> dict:
        try:
            journal = read_json(self._journal)
            fields = {"schema_version", "operation_id", "phase", "previous_version", "previous_sha256", "target_version", "target_sha256", "previous_present", "replaced", "journal_tag"}
            operation = journal["operation_id"]
            supplied_tag = journal.get("journal_tag")
            if (
                set(journal) != fields
                or journal["schema_version"] != 1
                or journal["phase"] not in {"applying", "committed"}
                or not isinstance(operation, str)
                or len(operation) != 32
                or any(character not in "0123456789abcdef" for character in operation)
                or validate_segment(journal["previous_version"]) != journal["previous_version"]
                or validate_segment(journal["target_version"]) != journal["target_version"]
                or not isinstance(journal["target_sha256"], str)
                or len(journal["target_sha256"]) != 64
                or not isinstance(supplied_tag, str)
                or len(supplied_tag) != 64
                or set(journal["previous_present"]) != set(OFFICE_IDS)
                or any(type(value) is not bool for value in journal["previous_present"].values())
                or set(journal["previous_sha256"]) != set(OFFICE_IDS)
                or any(
                    (value is not None)
                    and (
                        not isinstance(value, str)
                        or len(value) != 64
                        or any(
                            character not in "0123456789abcdef"
                            for character in value
                        )
                    )
                    for value in journal["previous_sha256"].values()
                )
                or any(
                    journal["previous_present"][office]
                    != (journal["previous_sha256"][office] is not None)
                    for office in OFFICE_IDS
                )
                or not isinstance(journal["replaced"], list)
                or len(journal["replaced"]) != len(set(journal["replaced"]))
                or any(office not in OFFICE_IDS for office in journal["replaced"])
            ):
                raise ValueError("invalid runtime journal")
            payload = {name: member for name, member in journal.items() if name != "journal_tag"}
            expected_tag = hmac.new(
                self._journal_key_bytes(),
                b"runtime-update-journal\0" + _canonical(payload),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(supplied_tag, expected_tag):
                raise ValueError("unauthenticated runtime journal")
            return journal
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeUpdateError("runtime-recovery-required") from error

    def _write_journal(self, journal: dict) -> None:
        payload = {name: member for name, member in journal.items() if name != "journal_tag"}
        journal["journal_tag"] = hmac.new(
            self._journal_key_bytes(),
            b"runtime-update-journal\0" + _canonical(payload),
            hashlib.sha256,
        ).hexdigest()
        atomic_write_json(self._journal, journal)

    def _transaction_root(self, journal: dict) -> Path:
        return self.root / "updates" / "runtime-transactions" / journal["operation_id"]

    def _validate_transaction(self, journal: dict) -> Path:
        transaction = self._transaction_root(journal)
        try:
            if (
                transaction.is_symlink()
                or not transaction.is_dir()
                or not transaction.resolve(strict=True).is_relative_to(
                    self.root.resolve(strict=True)
                )
            ):
                raise ValueError("missing runtime transaction")
            return transaction
        except (OSError, ValueError) as error:
            raise RuntimeUpdateError("runtime-recovery-required") from error

    def _recovery_state(self, journal: dict) -> str:
        try:
            metadata = read_json(self.root / "pool.json")
            version = metadata.get("runtime_version")
            if version == journal["target_version"]:
                if all(
                    self._runtime_matches(
                        self.root / "offices" / office / "runtime",
                        journal["target_version"],
                        journal["target_sha256"],
                    )
                    for office in OFFICE_IDS
                ):
                    return "final"
                raise ValueError("partial final runtime state")
            if version != journal["previous_version"]:
                raise ValueError("unrelated runtime metadata")

            exact_prior = True
            for office in OFFICE_IDS:
                runtime = self.root / "offices" / office / "runtime"
                if journal["previous_present"][office]:
                    prior = self._runtime_matches(
                        runtime,
                        journal["previous_version"],
                        journal["previous_sha256"][office],
                    )
                else:
                    prior = not (runtime.exists() or runtime.is_symlink())
                if prior:
                    continue
                exact_prior = False
                if not self._runtime_matches(
                    runtime,
                    journal["target_version"],
                    journal["target_sha256"],
                ):
                    raise ValueError("unrelated office runtime state")
            return "prior" if exact_prior else "applying"
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeUpdateError("runtime-recovery-required") from error

    def _validate_final_state(self, journal: dict, outcome: str) -> None:
        try:
            metadata = read_json(self.root / "pool.json")
            version = (
                journal["target_version"]
                if outcome == "committed"
                else journal["previous_version"]
            )
            if metadata.get("runtime_version") != version:
                raise ValueError("runtime metadata mismatch")
            for office_id in OFFICE_IDS:
                runtime = self.root / "offices" / office_id / "runtime"
                if outcome == "committed":
                    valid = self._runtime_matches(
                        runtime,
                        journal["target_version"],
                        journal["target_sha256"],
                    )
                elif journal["previous_present"][office_id]:
                    valid = self._runtime_matches(
                        runtime,
                        journal["previous_version"],
                        journal["previous_sha256"][office_id],
                    )
                else:
                    valid = not (runtime.exists() or runtime.is_symlink())
                if not valid:
                    raise ValueError("runtime final state mismatch")
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeUpdateError("runtime-recovery-required") from error

    def _complete_transaction(self, journal: dict, outcome: str) -> None:
        self._validate_final_state(journal, outcome)
        transaction = self._transaction_root(journal)
        try:
            if transaction.exists() or transaction.is_symlink():
                if transaction.is_symlink() or not transaction.is_dir():
                    raise ValueError("unsafe runtime transaction")
                shutil.rmtree(transaction)
            if transaction.exists() or transaction.is_symlink():
                raise OSError("runtime transaction cleanup incomplete")
            self._journal.unlink()
            if os.name != "nt":
                parent = os.open(self._journal.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
        except (OSError, ValueError) as error:
            raise RuntimeUpdateError("runtime-recovery-required") from error

    def _remove_new_runtime(self, runtime: Path, journal: dict) -> None:
        if not self._runtime_matches(runtime, journal["target_version"], journal["target_sha256"]):
            raise RuntimeUpdateError("runtime-recovery-required")
        shutil.rmtree(runtime)

    def _restore(self, journal: dict) -> None:
        state = self._recovery_state(journal)
        if state == "final":
            self._complete_transaction(journal, "committed")
            return
        if journal["phase"] != "applying":
            raise RuntimeUpdateError("runtime-recovery-required")
        if state == "prior":
            self._complete_transaction(journal, "restored")
            return
        transaction = self._validate_transaction(journal)
        for office_id in reversed(OFFICE_IDS):
            runtime = self.root / "offices" / office_id / "runtime"
            backup = transaction / f"{office_id}.old"
            previous_digest = journal["previous_sha256"][office_id]
            if backup.exists() or backup.is_symlink():
                if not self._runtime_matches(
                    backup, journal["previous_version"], previous_digest
                ):
                    raise RuntimeUpdateError("runtime-recovery-required")
                if runtime.exists() or runtime.is_symlink():
                    self._remove_new_runtime(runtime, journal)
                os.replace(backup, runtime)
            elif journal["previous_present"][office_id]:
                if not self._runtime_matches(
                    runtime, journal["previous_version"], previous_digest
                ):
                    raise RuntimeUpdateError("runtime-recovery-required")
            elif runtime.exists() or runtime.is_symlink():
                self._remove_new_runtime(runtime, journal)
        atomic_write_json(
            self.root / "pool.json",
            {
                "schema_version": 1,
                "office_count": 5,
                "offices": list(OFFICE_IDS),
                "runtime_version": journal["previous_version"],
            },
        )
        self._complete_transaction(journal, "restored")

    def _finish_committed(self, journal: dict) -> None:
        metadata = read_json(self.root / "pool.json")
        if metadata.get("runtime_version") != journal["target_version"]:
            raise RuntimeUpdateError("runtime-recovery-required")
        for office_id in OFFICE_IDS:
            runtime = self.root / "offices" / office_id / "runtime"
            if not self._runtime_matches(runtime, journal["target_version"], journal["target_sha256"]):
                raise RuntimeUpdateError("runtime-recovery-required")
        self._complete_transaction(journal, "committed")

    def _recover(self, pool: Pool) -> None:
        if not self._journal.exists():
            return
        journal = self._validated_journal()
        state = self._recovery_state(journal)
        if state == "final":
            self._finish_committed(journal)
        elif journal["phase"] == "committed":
            raise RuntimeUpdateError("runtime-recovery-required")
        else:
            self._restore(journal)
        pool.runtime_version = read_json(self.root / "pool.json")["runtime_version"]

    def _change(self, version: str) -> None:
        try:
            version = validate_segment(version)
        except (TypeError, ValueError) as error:
            raise RuntimeUpdateError("runtime-version-invalid") from error
        pool = self._pool()
        try:
            with pool._locked():
                pool._ensure_initialized()
                self._recover(pool)
                metadata = pool._ensure_initialized()
                if metadata["runtime_version"] == version:
                    raise RuntimeUpdateError("runtime-already-active")
                states = {office: pool._read_state(office) for office in OFFICE_IDS}
                if any(state["status"] != "free" for state in states.values()):
                    raise RuntimeUpdateError("runtime-update-occupied")
                if any(pool._unknown_paths(office) for office in OFFICE_IDS):
                    raise RuntimeUpdateError("runtime-recovery-required")
                manifest, asset, _ = self._staged(version)
                operation = uuid.uuid4().hex
                previous_sha256 = {}
                for office in OFFICE_IDS:
                    runtime = self.root / "offices" / office / "runtime"
                    if runtime.exists():
                        digest = self._runtime_digest(
                            runtime, metadata["runtime_version"]
                        )
                        if digest is None:
                            raise RuntimeUpdateError("runtime-recovery-required")
                        previous_sha256[office] = digest
                    else:
                        previous_sha256[office] = None
                journal = {
                    "schema_version": 1,
                    "operation_id": operation,
                    "phase": "applying",
                    "previous_version": metadata["runtime_version"],
                    "target_version": version,
                    "target_sha256": manifest["sha256"],
                    "previous_present": {
                        office: previous_sha256[office] is not None
                        for office in OFFICE_IDS
                    },
                    "previous_sha256": previous_sha256,
                    "replaced": [],
                    "journal_tag": "0" * 64,
                }
                transaction = self._transaction_root(journal)
                transaction.mkdir(parents=True)
                for office_id in OFFICE_IDS:
                    self._runtime_tree(transaction / f"{office_id}.new", version, asset)
                self._write_journal(journal)
                try:
                    for office_id in OFFICE_IDS:
                        runtime = self.root / "offices" / office_id / "runtime"
                        backup = transaction / f"{office_id}.old"
                        if runtime.exists():
                            os.replace(runtime, backup)
                        os.replace(transaction / f"{office_id}.new", runtime)
                        self._checkpoint(f"activate:office:{office_id}")
                        journal["replaced"].append(office_id)
                        self._write_journal(journal)
                    atomic_write_json(
                        self.root / "pool.json",
                        {**metadata, "runtime_version": version},
                    )
                    self._checkpoint("activate:pool")
                    journal["phase"] = "committed"
                    self._write_journal(journal)
                    self._finish_committed(journal)
                except BaseException as error:
                    try:
                        current = self._validated_journal()
                        if current["phase"] == "applying":
                            self._restore(current)
                    except BaseException as recovery_error:
                        raise RuntimeUpdateError("runtime-recovery-required") from recovery_error
                    if isinstance(error, RuntimeUpdateError):
                        raise
                    raise RuntimeUpdateError("runtime-update-interrupted") from error
        except RuntimeUpdateError:
            raise
        except PoolError as error:
            raise RuntimeUpdateError("runtime-recovery-required") from error
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeUpdateError("runtime-update-failed") from error

    def activate(self, version: str) -> None:
        self._change(version)

    def rollback(self, version: str) -> None:
        self._change(version)


def recover_pending_runtime_update(pool: Pool) -> None:
    RuntimeUpdate(pool.root)._recover(pool)
