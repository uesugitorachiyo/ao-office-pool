import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import stat
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from unittest import mock

import internal.pool as pool_module
from internal.pool import AuthorityLease, Pool, PoolError


def _claim_worker(arguments):
    root, project, number = arguments
    try:
        authority = Pool(Path(root)).claim(
            f"holder-{number}", f"task-{number}", Path(project), "pinned"
        )
        return "ok", authority.name
    except PoolError as error:
        return error.code, ""


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(tempfile.gettempdir()).resolve()
        )
        self.base = Path(self.temporary_directory.name).resolve()
        self.root = self.base / "pool"
        self.project = self.base / "project"
        self.project.mkdir()
        self.pool = Pool(self.root)
        self.pool.initialize()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _snapshot(self):
        return {
            path.relative_to(self.root).as_posix(): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file() and path.name != ".pool.lock"
        }

    def test_atomic_first_free_claims(self):
        # MUTATION: selecting an office outside the pool lock duplicates an office.
        arguments = [(str(self.root), str(self.project), number) for number in range(6)]
        with ProcessPoolExecutor(max_workers=6) as executor:
            results = list(executor.map(_claim_worker, arguments))
        self.assertEqual([code for code, _ in results].count("ok"), 5)
        self.assertEqual([code for code, _ in results].count("pool-full"), 1)
        names = [name for code, name in results if code == "ok"]
        self.assertEqual(len(set(names)), 5)
        self.assertEqual(
            self.pool.public_status(),
            {
                "schema_version": 1,
                "offices": [
                    {"office_id": f"O{number}", "status": "occupied", "generation": 1}
                    for number in range(1, 6)
                ],
            },
        )

    def test_exact_authorization(self):
        # MUTATION: trusting edited authority fields releases another allocation.
        authority = self.pool.claim("holder-a", "task-a", self.project, "pinned")
        original = authority.read_bytes()
        accepted = json.loads(original)
        mutations = {
            "holder_digest": "0" * 64,
            "task_digest": "1" * 64,
            "project_path": str(self.base / "other"),
            "office_id": "O2",
            "generation": 2,
            "authority_id": "2" * 64,
        }
        before = self._snapshot()
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = dict(accepted)
                changed[field] = value
                authority.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaises(PoolError) as raised:
                    self.pool.release(authority)
                self.assertIn(raised.exception.code, {"unauthorized", "stale-generation"})
                authority.write_bytes(original)
                self.assertEqual(self._snapshot(), before)

    def test_private_same_task_resume(self):
        # MUTATION: requiring a pointer for authorization strands a valid authority.
        authority = self.pool.claim("holder-a", "task-a", self.project, "pinned")
        pointer = next((self.root / "runtime" / "pointers").iterdir())
        pointer.unlink()
        self.assertEqual(self.pool.resume(authority), authority)
        self.assertTrue(pointer.exists())
        with self.assertRaises(PoolError) as raised:
            self.pool.claim("holder-a", "task-a", self.project, "pinned")
        self.assertEqual(raised.exception.code, "already-claimed")

    def test_public_status_is_secret_free_and_nonmutating(self):
        # MUTATION: recursive state serialization leaks protected allocation fields.
        self.pool.claim("holder-secret", "task-secret", self.project, "pinned")
        before = self._snapshot()
        status = self.pool.public_status()
        encoded = json.dumps(status, sort_keys=True)
        self.assertEqual(set(status), {"schema_version", "offices"})
        self.assertEqual(set(status["offices"][0]), {"office_id", "status", "generation"})
        for forbidden in ("holder-secret", "task-secret", str(self.project), "authority"):
            self.assertNotIn(forbidden, encoded)
        self.assertEqual(self._snapshot(), before)

    def test_witness_key_is_private_and_stable(self):
        key_path = self.root / "operator-secrets" / "governance-witness.key"
        original = key_path.read_bytes()
        self.assertEqual(len(original), 32)

        self.pool.initialize()

        self.assertEqual(key_path.read_bytes(), original)
        encoded = json.dumps(self.pool.public_status(), sort_keys=True)
        self.assertNotIn(original.hex(), encoded)
        self.assertNotIn(key_path.name, encoded)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)

    def test_witness_key_rejects_hard_links_and_permissive_mode(self):
        key_path = self.root / "operator-secrets" / "governance-witness.key"
        original_mode = stat.S_IMODE(key_path.stat().st_mode)
        linked = self.base / "linked-witness-key"
        os.link(key_path, linked)
        try:
            with self.assertRaises(PoolError) as raised:
                self.pool.public_status()
            self.assertEqual(raised.exception.code, "recovery-required")
        finally:
            linked.unlink()
        if os.name != "nt":
            key_path.chmod(0o644)
            try:
                with self.assertRaises(PoolError) as raised:
                    self.pool.public_status()
                self.assertEqual(raised.exception.code, "recovery-required")
            finally:
                key_path.chmod(original_mode)

    def test_constructed_or_expired_authority_lease_is_not_a_capability(self):
        self.assertFalse(hasattr(pool_module, "_activate_lease"))
        self.assertFalse(hasattr(pool_module, "_LEASE_SENTINEL"))
        self.assertFalse(hasattr(pool_module, "_register_lease"))
        self.assertFalse(hasattr(Pool, "_open_witness_key"))
        authority = self.pool.claim("holder-capability", "task-capability", self.project, "pinned")
        with self.pool.authority_lease(authority) as active:
            with self.assertRaises(PoolError):
                AuthorityLease(active.authority_path, active.authority_bytes, active.authority)
            tag = active.sign_witness(b"payload")
            self.assertTrue(active.verify_witness(b"payload", tag))
            forged = object.__new__(AuthorityLease)
            for name in ("authority_path", "authority_bytes", "authority", "_checker", "_signer", "_verifier"):
                object.__setattr__(forged, name, getattr(active, name))
            with self.assertRaises(PoolError):
                forged.sign_witness(b"payload")
        with self.assertRaises(PoolError):
            active.sign_witness(b"payload")

    def test_legacy_pool_migrates_governance_storage_once_without_rotation(self):
        key = self.root / "operator-secrets/governance-witness.key"
        governance_state = self.root / "runtime/governance"
        shutil.rmtree(governance_state)
        key.unlink()
        self.pool.initialize()
        created = key.read_bytes()
        self.assertEqual(len(created), 32)
        self.assertEqual(
            {path.name for path in governance_state.iterdir()}, {"consumed", "revoked"}
        )
        self.pool.initialize()
        self.assertEqual(key.read_bytes(), created)

    def test_legacy_migration_never_hides_a_corrupt_existing_key(self):
        shutil.rmtree(self.root / "runtime/governance")
        key = self.root / "operator-secrets/governance-witness.key"
        key.write_bytes(b"corrupt")
        with self.assertRaises(PoolError) as raised:
            self.pool.initialize()
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(key.read_bytes(), b"corrupt")

    def test_windows_key_creation_does_not_call_posix_fchmod(self):
        with (
            mock.patch("internal.pool.os.name", "nt"),
            mock.patch("internal.pool.os.open", return_value=19),
            mock.patch("internal.pool.os.write", return_value=32),
            mock.patch("internal.pool.os.fsync"),
            mock.patch("internal.pool.os.close"),
            mock.patch("internal.pool.os.fchmod") as fchmod,
        ):
            self.pool._create_witness_key()
        fchmod.assert_not_called()

    def test_authoritative_marker_fsyncs_file_and_parent_directory(self):
        authority = self.pool.claim("marker-holder", "marker-task", self.project, "pinned")
        with self.pool.authority_lease(authority) as lease:
            with mock.patch("internal.pool.os.fsync", wraps=os.fsync) as fsync:
                self.assertTrue(
                    self.pool._create_governance_marker(
                        lease, "consumed", "witness-" + "a" * 32, "b" * 64
                    )
                )
        self.assertGreaterEqual(fsync.call_count, 2)

    def test_invalid_witness_key_requires_recovery(self):
        key_path = self.root / "operator-secrets" / "governance-witness.key"
        original = key_path.read_bytes()
        outside = self.base / "outside-witness.key"
        outside.write_bytes(original)
        mutations = (
            lambda: key_path.unlink(),
            lambda: key_path.write_bytes(b"short"),
            lambda: (key_path.unlink(), key_path.symlink_to(outside)),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                key_path.unlink(missing_ok=True)
                key_path.write_bytes(original)
                try:
                    mutate()
                except OSError as error:
                    self.skipTest(str(error))
                with self.assertRaises(PoolError) as raised:
                    self.pool.public_status()
                self.assertEqual(raised.exception.code, "recovery-required")

    def test_authority_lease_holds_release_lock(self):
        authority = self.pool.claim("holder-a", "task-a", self.project, "pinned")
        started = threading.Event()
        finished = threading.Event()

        def release():
            started.set()
            self.pool.release(authority)
            finished.set()

        with self.pool.authority_lease(authority) as lease:
            thread = threading.Thread(target=release)
            thread.start()
            self.assertTrue(started.wait(1))
            self.assertFalse(finished.wait(0.1))
            self.assertEqual(lease.authority_path, authority.resolve())
            self.assertEqual(lease.authority_bytes, authority.read_bytes())
            self.assertEqual(lease.authority["office_id"], "O1")
            with self.assertRaises((AttributeError, TypeError)):
                lease.authority_path = self.base
        thread.join(2)
        self.assertTrue(finished.is_set())

    def test_runtime_containment_value_error_requires_recovery(self):
        with (
            mock.patch("internal.pool.os.name", "nt"),
            mock.patch("internal.pool.open_identity", return_value=object()),
            mock.patch("internal.pool.require_within", side_effect=ValueError("changed")),
        ):
            with self.assertRaises(PoolError) as raised:
                self.pool._verify_runtime_containment()
        self.assertEqual(raised.exception.code, "recovery-required")

    def test_pinned_work_does_not_expire(self):
        # MUTATION: timestamp-based expiry silently frees pinned work.
        for number in range(5):
            self.pool.claim(f"holder-{number}", f"task-{number}", self.project, "pinned")
        for state in (self.root / "offices").glob("*/office-state.json"):
            os.utime(state, (1, 1))
        time.sleep(0.01)
        with self.assertRaises(PoolError) as raised:
            Pool(self.root).claim("late", "late-task", self.project, "pinned")
        self.assertEqual(raised.exception.code, "pool-full")

    def test_emergency_release_requires_exact_authority(self):
        # MUTATION: checking only an office id permits unauthorized recovery.
        authority = self.pool.claim("holder-a", "task-a", self.project, "pinned")
        residue = self.root / "offices" / "O1" / "work" / "unknown.bin"
        residue.write_bytes(b"unknown\x00bytes")
        with self.assertRaises(PoolError) as raised:
            self.pool.release(authority)
        self.assertEqual(raised.exception.code, "recovery-required")
        generation = self.pool.public_status()["offices"][0]["generation"]
        wrong = self.base / "wrong.key"
        wrong.write_text("wrong", encoding="utf-8")
        before = self._snapshot()
        for key_path, office_id, supplied_generation in (
            (wrong, "O1", generation),
            (self.root / "operator-secrets" / "recovery-key-O1", "O2", generation),
            (self.root / "operator-secrets" / "recovery-key-O1", "O1", generation + 1),
        ):
            with self.subTest(office_id=office_id, generation=supplied_generation):
                with self.assertRaises(PoolError):
                    self.pool.recover(key_path, office_id, supplied_generation)
                self.assertEqual(self._snapshot(), before)
        self.pool.recover(
            self.root / "operator-secrets" / "recovery-key-O1", "O1", generation
        )
        self.assertEqual(self.pool.public_status()["offices"][0]["status"], "free")
        preserved = list((self.root / "offices" / "O1" / "history").rglob("unknown.bin"))
        self.assertEqual([path.read_bytes() for path in preserved], [b"unknown\x00bytes"])
        evidence = next((self.root / "offices" / "O1" / "history").rglob("recovery.json"))
        text = evidence.read_text(encoding="utf-8")
        self.assertNotIn("wrong", text)
        self.assertNotIn("holder-a", text)

    def test_recovery_preserves_same_named_residue_from_distinct_locations(self):
        # MUTATION: flattening recovery residue paths overwrites one same-named source.
        authority = self.pool.claim("holder-a", "task-a", self.project, "pinned")
        work_copy = self.root / "offices" / "O1" / "work" / "duplicate.bin"
        office_copy = self.root / "offices" / "O1" / "duplicate.bin"
        work_copy.write_bytes(b"work-copy")
        office_copy.write_bytes(b"office-copy")
        with self.assertRaises(PoolError):
            self.pool.release(authority)
        self.pool.recover(
            self.root / "operator-secrets" / "recovery-key-O1", "O1", 1
        )
        preserved = sorted(
            path.read_bytes()
            for path in (self.root / "offices" / "O1" / "history").rglob(
                "duplicate.bin"
            )
        )
        self.assertEqual(preserved, [b"office-copy", b"work-copy"])

    def test_runtime_version_is_contained(self):
        # MUTATION: joining an unchecked version segment escapes the runtime root.
        bad_root = self.base / "bad-pool"
        with self.assertRaises((TypeError, ValueError)):
            Pool(bad_root, runtime_version="../escape").initialize()
        self.assertFalse(bad_root.exists())

    def test_corrupt_pointer_cannot_duplicate_claim(self):
        # MUTATION: pointer-only allocation lookup creates a duplicate claim.
        authority = self.pool.claim("holder-a", "task-a", self.project, "pinned")
        pointer = next((self.root / "runtime" / "pointers").iterdir())
        pointer.write_bytes(b"not json\x00")
        with self.assertRaises(PoolError) as raised:
            self.pool.claim("holder-a", "task-a", self.project, "pinned")
        self.assertEqual(raised.exception.code, "already-claimed")
        self.assertEqual(pointer.read_bytes(), b"not json\x00")
        self.assertTrue(authority.exists())

    def test_unowned_pointer_bytes_stop_claim_before_overwrite(self):
        # MUTATION: deterministic pointer creation overwrites unowned residue.
        holder = hashlib.sha256(b"holder-a").hexdigest()
        pointer = self.root / "runtime" / "pointers" / f"{holder}.json"
        pointer.write_bytes(b"unknown-pointer\x00")
        before = self._snapshot()
        with self.assertRaises(PoolError) as raised:
            self.pool.claim("holder-a", "task-a", self.project, "pinned")
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(self._snapshot(), before)

    def test_release_preserves_unexpected_pointer_bytes(self):
        # MUTATION: release journals and deletes arbitrary pointer bytes.
        authority = self.pool.claim("holder-a", "task-a", self.project, "pinned")
        pointer = next((self.root / "runtime" / "pointers").iterdir())
        pointer.write_bytes(b"foreign-pointer\x00")
        with self.assertRaises(PoolError) as raised:
            self.pool.release(authority)
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(pointer.read_bytes(), b"foreign-pointer\x00")
        self.assertTrue(authority.exists())

    def test_initialize_preserves_existing_recovery_authority(self):
        # MUTATION: initialization overwrites an unknown recovery authority record.
        root = self.base / "partial"
        record = root / "runtime" / "recovery-authority.json"
        record.parent.mkdir(parents=True)
        record.write_bytes(b"unknown-authority\x00")
        with self.assertRaises(PoolError) as raised:
            Pool(root).initialize()
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(record.read_bytes(), b"unknown-authority\x00")

    def test_initialize_revalidates_partial_protected_paths_before_mutation(self):
        # MUTATION: partial initialization follows protected redirects before final validation.
        cases = (
            ("runtime", True),
            ("offices", True),
            ("operator-secrets", True),
            ("runtime/recovery-authority.json", False),
        )
        for number, (relative, is_directory) in enumerate(cases):
            with self.subTest(path=relative):
                root = self.base / f"partial-redirect-{number}"
                root.mkdir()
                protected = root / relative
                protected.parent.mkdir(parents=True, exist_ok=True)
                outside = self.base / f"partial-outside-{number}"
                if is_directory:
                    outside.mkdir()
                    before = []
                else:
                    outside.write_bytes(b"outside-original")
                    before = b"outside-original"
                try:
                    protected.symlink_to(outside, target_is_directory=is_directory)
                except OSError as error:
                    self.skipTest(str(error))

                with self.assertRaises(PoolError) as raised:
                    Pool(root).initialize()
                self.assertEqual(raised.exception.code, "recovery-required")
                if is_directory:
                    self.assertEqual(list(outside.iterdir()), before)
                else:
                    self.assertEqual(outside.read_bytes(), before)

    def test_every_protected_path_is_revalidated_before_mutation(self):
        # MUTATION: omitting any protected member follows its redirected bytes.
        static_paths = (
            ("runtime", True),
            ("runtime/receipts", True),
            ("runtime/pointers", True),
            ("runtime/transactions", True),
            ("runtime/recovery", True),
            ("offices", True),
            ("offices/O1", True),
            ("offices/O1/work", True),
            ("offices/O1/history", True),
            ("operator-secrets", True),
            ("pool.json", False),
            ("runtime/generations.json", False),
            ("runtime/recovery-authority.json", False),
            ("operator-secrets/governance-witness.key", False),
            ("operator-secrets/recovery-key-O1", False),
            ("offices/O1/office-state.json", False),
        )
        generated_paths = (
            "runtime/receipts/generated.receipt.json",
            "runtime/pointers/generated.json",
            "runtime/transactions/generated.bin",
            "runtime/recovery/generated.json",
            "offices/O1/work/generated.bin",
            "offices/O1/history/generated.bin",
        )
        cases = static_paths + tuple((path, False) for path in generated_paths)

        for number, (relative, is_directory) in enumerate(cases):
            with self.subTest(path=relative):
                root = self.base / f"redirected-{number}"
                pool = Pool(root)
                pool.initialize()
                protected = root / relative
                if relative in generated_paths or not protected.exists():
                    protected.write_bytes(b"protected-original")
                outside = self.base / f"outside-{number}"
                protected.rename(outside)
                if is_directory:
                    expected = {
                        path.relative_to(outside).as_posix(): path.read_bytes()
                        for path in outside.rglob("*")
                        if path.is_file()
                    }
                else:
                    expected = outside.read_bytes()
                try:
                    protected.symlink_to(outside, target_is_directory=is_directory)
                except OSError as error:
                    self.skipTest(str(error))
                with self.assertRaises(PoolError) as raised:
                    pool.claim(f"holder-{number}", f"task-{number}", self.project, "pinned")
                self.assertEqual(raised.exception.code, "recovery-required")
                if is_directory:
                    actual = {
                        path.relative_to(outside).as_posix(): path.read_bytes()
                        for path in outside.rglob("*")
                        if path.is_file()
                    }
                    self.assertEqual(actual, expected)
                else:
                    self.assertEqual(outside.read_bytes(), expected)

    def test_swapped_lock_path_stops_before_state_mutation(self):
        # MUTATION: opening an unchecked lock symlink locks an unrelated file.
        root = self.base / "lock-redirect"
        pool = Pool(root)
        pool.initialize()
        outside = self.base / "outside.lock"
        outside.write_bytes(b"outside-lock")
        lock = root / ".pool.lock"
        lock.unlink()
        try:
            lock.symlink_to(outside)
        except OSError as error:
            self.skipTest(str(error))
        before = self._snapshot()
        with self.assertRaises(PoolError) as raised:
            pool.claim("holder", "task", self.project, "pinned")
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(self._snapshot(), before)
        self.assertEqual(outside.read_bytes(), b"outside-lock")

    def test_lock_swap_between_preflight_and_open_never_touches_target(self):
        # MUTATION: pathname validation before open leaves a swap race at the lock syscall.
        root = self.base / "lock-open-race"
        pool = Pool(root)
        pool.initialize()
        lock = root / ".pool.lock"
        outside = self.base / "outside-race.lock"
        outside.write_bytes(b"outside-race-original")
        before = {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file() and path != lock
        }
        swapped = False
        if os.name == "nt":
            from internal import windows_identity

            real_kernel32 = windows_identity._kernel32
            library = real_kernel32()

            class SwapLibrary:
                def __getattr__(self, name):
                    return getattr(library, name)

                def CreateFileW(self, *arguments):
                    nonlocal swapped
                    if not swapped:
                        swapped = True
                        lock.unlink()
                        lock.symlink_to(outside)
                    return library.CreateFileW(*arguments)

            patcher = mock.patch(
                "internal.windows_identity._kernel32", return_value=SwapLibrary()
            )
        else:
            real_open = os.open

            def swap_then_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                if Path(path) == lock and not swapped:
                    swapped = True
                    lock.unlink()
                    lock.symlink_to(outside)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            patcher = mock.patch("internal.transactions.os.open", side_effect=swap_then_open)
        with patcher:
            with self.assertRaises(PoolError) as raised:
                pool.claim("holder", "task", self.project, "pinned")
        self.assertTrue(swapped)
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(outside.read_bytes(), b"outside-race-original")
        after = {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file() and path != lock
        }
        self.assertEqual(after, before)

    def test_claim_hides_owner_key(self):
        # MUTATION: returning protected holder material alongside the authority path.
        authority = self.pool.claim("raw-holder-value", "task-a", self.project, "pinned")
        self.assertIsInstance(authority, Path)
        self.assertNotIn("raw-holder-value", str(authority))
        self.assertNotIn("raw-holder-value", authority.read_text(encoding="utf-8"))

    def test_dirty_release_requires_recovery(self):
        # MUTATION: clean release deletes or reuses unknown work bytes.
        authority = self.pool.claim("holder-a", "task-a", self.project, "pinned")
        residue = self.root / "offices" / "O1" / "work" / "partial.dat"
        residue.write_bytes(b"partial-result")
        with self.assertRaises(PoolError) as raised:
            self.pool.release(authority)
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(residue.read_bytes(), b"partial-result")
        self.assertEqual(self.pool.public_status()["offices"][0]["status"], "recovery-required")
        with self.assertRaises(PoolError) as second:
            self.pool.resume(authority)
        self.assertEqual(second.exception.code, "recovery-required")

    def test_public_claim_requires_project_binding(self):
        # MUTATION: accepting absent or non-directory roots creates unbound work.
        for project in (self.base / "missing", self.base / "file"):
            if project.name == "file":
                project.write_text("not a directory", encoding="utf-8")
            before = self._snapshot()
            with self.subTest(project=project):
                with self.assertRaises(PoolError) as raised:
                    self.pool.claim("holder", "task", project, "pinned")
                self.assertEqual(raised.exception.code, "invalid-project")
                self.assertEqual(self._snapshot(), before)

    def test_initialize_requires_exactly_five_offices(self):
        # MUTATION: generalized office counts silently change the product boundary.
        for count in (0, 1, 4, 6, True):
            root = self.base / f"count-{count}"
            with self.subTest(count=count):
                with self.assertRaises(PoolError) as raised:
                    Pool(root).initialize(count=count)
                self.assertEqual(raised.exception.code, "invalid-count")
                self.assertFalse(root.exists())

    def test_no_automatic_office_lifecycle(self):
        # MUTATION: an implicit queue or service accepts a sixth allocation later.
        for number in range(5):
            self.pool.claim(f"holder-{number}", f"task-{number}", self.project, "conversation")
        with self.assertRaises(PoolError) as raised:
            Pool(self.root).claim("sixth", "sixth-task", self.project, "conversation")
        self.assertEqual(raised.exception.code, "pool-full")

    def test_schemas_accept_only_persisted_contract_fields(self):
        # MUTATION: adding recursive/private fields widens a serialized boundary.
        cases = {
            "pool.schema.json": self.root / "pool.json",
            "office-state.schema.json": self.root / "offices" / "O1" / "office-state.json",
        }
        self.pool.claim("holder-a", "task-a", self.project, "pinned")
        cases["claim-receipt.schema.json"] = next(
            (self.root / "runtime" / "receipts").iterdir()
        )
        schema_root = Path(__file__).parents[1] / "schemas"
        for name, artifact in cases.items():
            with self.subTest(name=name):
                schema = json.loads(schema_root.joinpath(name).read_text(encoding="utf-8"))
                value = json.loads(artifact.read_text(encoding="utf-8"))
                self.assertFalse(schema["additionalProperties"])
                self.assertLessEqual(set(value), set(schema["properties"]))
                if "required" in schema:
                    self.assertLessEqual(set(schema["required"]), set(value))
                else:
                    self.assertTrue(any(set(value) == set(branch["required"]) for branch in schema["oneOf"]))

    def test_office_schema_has_exact_status_specific_shapes(self):
        # MUTATION: a flat schema accepts free/occupied field combinations.
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas" / "office-state.schema.json").read_text()
        )
        branches = schema["oneOf"]

        def accepts(value):
            matches = 0
            for branch in branches:
                required = set(branch["required"])
                status = branch["properties"]["status"]["const"]
                if (
                    value.get("status") == status
                    and set(value) == required
                    and branch["minProperties"] == branch["maxProperties"] == len(value)
                ):
                    matches += 1
            return matches == 1

        free = {"schema_version": 1, "office_id": "O1", "generation": 0, "status": "free"}
        occupied = {
            "schema_version": 1,
            "office_id": "O1",
            "generation": 1,
            "status": "occupied",
            "holder_digest": "0" * 64,
            "task_digest": "1" * 64,
            "project_path": "/project",
            "project_volume": 1,
            "project_file_id": "2",
            "mode": "pinned",
            "authority_name": "a.receipt.json",
            "authority_digest": "3" * 64,
        }
        self.assertTrue(accepts(free))
        self.assertTrue(accepts(occupied))
        self.assertFalse(accepts(free | {"holder_digest": "0" * 64}))
        invalid_occupied = dict(occupied)
        invalid_occupied.pop("authority_name")
        self.assertFalse(accepts(invalid_occupied))


if __name__ == "__main__":
    unittest.main()
