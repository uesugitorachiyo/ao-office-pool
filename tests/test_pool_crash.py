import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from internal.pool import InjectedCrash, Pool, PoolError


class PoolCrashTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(tempfile.gettempdir()).resolve()
        )
        self.base = Path(self.temporary_directory.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _pool(self, name):
        root = self.base / name
        pool = Pool(root)
        pool.initialize()
        return root, pool

    def test_unknown_residue_requires_recovery(self):
        # MUTATION: a free-office scan ignores unknown bytes and reuses the office.
        root, pool = self._pool("unknown")
        residue = root / "offices" / "O1" / "work" / "orphan.bin"
        residue.write_bytes(b"orphan\x00bytes")
        authority = pool.claim("holder", "task", self.project, "pinned")
        self.assertEqual(authority.parent.parent.parent, root)
        status = pool.public_status()["offices"]
        self.assertEqual(status[0]["status"], "recovery-required")
        self.assertEqual(status[1]["status"], "occupied")
        self.assertEqual(residue.read_bytes(), b"orphan\x00bytes")

    def test_unknown_state_fields_are_preserved_before_reuse(self):
        # MUTATION: permissive state parsing overwrites bytes with unknown semantics.
        root, pool = self._pool("unknown-state")
        state_path = root / "offices" / "O1" / "office-state.json"
        original = state_path.read_bytes().rstrip()[:-1] + b',"future":"unknown"}\n'
        state_path.write_bytes(original)
        pool.claim("holder", "task", self.project, "pinned")
        status = pool.public_status()["offices"]
        self.assertEqual(status[0]["status"], "recovery-required")
        self.assertEqual(status[1]["status"], "occupied")
        self.assertEqual(state_path.read_bytes(), original)

    def test_claim_transitions_are_restart_safe(self):
        # MUTATION: any unjournaled claim write leaves partial accepted authority.
        stages = (
            "claim:journal-prepared",
            "claim:office",
            "claim:authority",
            "claim:pointer",
            "claim:journal-committed",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                root, _ = self._pool(stage.replace(":", "-"))
                with self.assertRaises(InjectedCrash):
                    Pool(root, crash_after=stage).claim(
                        "holder", "task", self.project, "pinned"
                    )
                authority = Pool(root).claim("next", "next-task", self.project, "pinned")
                occupied = [
                    item for item in Pool(root).public_status()["offices"]
                    if item["status"] == "occupied"
                ]
                self.assertIn(len(occupied), (1, 2))
                self.assertTrue(authority.exists())

    def test_unknown_journal_bytes_are_quarantined_without_overwrite(self):
        # MUTATION: rollback unlinks a foreign replacement at an expected path.
        root, _ = self._pool("foreign-journal-bytes")
        with self.assertRaises(InjectedCrash):
            Pool(root, crash_after="claim:authority").claim(
                "holder", "task", self.project, "pinned"
            )
        authority = next((root / "runtime" / "receipts").iterdir())
        authority.write_bytes(b"foreign\x00bytes")
        with self.assertRaises(PoolError) as raised:
            Pool(root).claim("next", "next-task", self.project, "pinned")
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(authority.read_bytes(), b"foreign\x00bytes")
        self.assertEqual(Pool(root).public_status()["offices"][0]["status"], "recovery-required")

    def test_untrusted_journal_paths_stop_before_mutation(self):
        # MUTATION: replaying unvalidated journal member paths deletes an unrelated file.
        root, _ = self._pool("journal-path")
        victim = self.base / "victim.bin"
        victim.write_bytes(b"preserve-me")
        operation_id = "a" * 32
        state = json.loads((root / "offices" / "O1" / "office-state.json").read_text())
        value = {
            "schema_version": 1,
            "operation_id": operation_id,
            "kind": "claim",
            "phase": "prepared",
            "office_id": "O1",
            "before_state": state,
            "after_state": state,
            "authority_name": "../../../victim.bin",
            "authority_bytes": base64.b64encode(victim.read_bytes()).decode("ascii"),
            "pointer_name": "safe.json",
            "pointer": {},
        }
        journal = root / "runtime" / "transactions" / f"{operation_id}.json"
        journal.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(PoolError) as raised:
            Pool(root).claim("holder", "task", self.project, "pinned")
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(victim.read_bytes(), b"preserve-me")
        self.assertTrue(journal.exists())

    def test_release_retires_receipt_and_pointer_atomically(self):
        # MUTATION: deleting authority and pointer without a journal strands ownership.
        stages = (
            "release:journal-prepared",
            "release:authority",
            "release:pointer",
            "release:office",
            "release:journal-committed",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                root, pool = self._pool(stage.replace(":", "-"))
                authority = pool.claim("holder", "task", self.project, "pinned")
                with self.assertRaises(InjectedCrash):
                    Pool(root, crash_after=stage).release(authority)
                restarted = Pool(root)
                if stage == "release:journal-committed":
                    replacement = restarted.claim("next", "next-task", self.project, "pinned")
                    self.assertEqual(restarted.public_status()["offices"][0]["status"], "occupied")
                    self.assertTrue(replacement.exists())
                    self.assertFalse(authority.exists())
                else:
                    self.assertEqual(restarted.resume(authority), authority)
                    self.assertTrue(authority.exists())
                    self.assertEqual(len(list((root / "runtime" / "pointers").iterdir())), 1)

    def test_recovery_transitions_preserve_every_unknown_byte(self):
        # MUTATION: interrupted recovery deletes residue instead of preserving it.
        stages = (
            "recover:journal-prepared",
            "recover:authority",
            "recover:pointer",
            "recover:office",
            "recover:journal-committed",
        )
        payload = b"crash-residue\x00\xff"
        for stage in stages:
            with self.subTest(stage=stage):
                root, pool = self._pool(stage.replace(":", "-"))
                authority = pool.claim("holder", "task", self.project, "pinned")
                residue = root / "offices" / "O1" / "work" / "partial.bin"
                residue.write_bytes(payload)
                with self.assertRaises(PoolError):
                    pool.release(authority)
                generation = pool.public_status()["offices"][0]["generation"]
                with self.assertRaises(InjectedCrash):
                    Pool(root, crash_after=stage).recover(
                        root / "operator-secrets" / "recovery-key-O1", "O1", generation
                    )
                restarted = Pool(root)
                try:
                    restarted.claim("next", "next-task", self.project, "pinned")
                except PoolError as error:
                    self.assertEqual(error.code, "recovery-required")
                copies = [path.read_bytes() for path in root.rglob("partial.bin")]
                self.assertEqual(copies, [payload])
                self.assertEqual(hashlib.sha256(copies[0]).hexdigest(), hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    unittest.main()
