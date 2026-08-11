import hashlib
import json
import os
import tempfile
import time
import unittest
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from internal.pool import Pool, PoolError


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
                self.assertLessEqual(set(schema["required"]), set(value))
                self.assertLessEqual(set(value), set(schema["properties"]))


if __name__ == "__main__":
    unittest.main()
