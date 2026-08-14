import hashlib
import json
import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from internal.pool import OFFICE_IDS, Pool, PoolError
from internal.runtime_update import RuntimeUpdate, RuntimeUpdateError


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _abrupt_activation(root: str) -> None:
    RuntimeUpdate(
        Path(root),
        crash_after="activate:office:O3",
        abrupt_crash=True,
    ).activate("v2")


class RuntimeUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name).resolve()
        self.root = self.base / "pool"
        Pool(self.root, runtime_version="v1").initialize()
        self.old_bytes = b"accepted runtime v1\n"
        for office_id in OFFICE_IDS:
            executable = (
                self.root
                / "offices"
                / office_id
                / "runtime"
                / "versions"
                / "v1"
                / ("ao2.exe" if os.name == "nt" else "ao2")
            )
            executable.parent.mkdir(parents=True)
            executable.write_bytes(self.old_bytes)
        self.new_bytes = b"accepted runtime v2\n"
        self.candidate = self._candidate("v2", self.new_bytes)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _component(self, version: str, data: bytes) -> dict:
        return {
            "name": "ao2",
            "version": version,
            "repository": "https://example.invalid/ao2",
            "commit": "a" * 40,
            "asset": "ao2",
            "license": "Apache-2.0",
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def _candidate(self, version: str, data: bytes) -> Path:
        candidate = self.base / ("candidate-" + hashlib.sha256(version.encode()).hexdigest()[:8])
        candidate.mkdir(exist_ok=True)
        component = self._component(version, data)
        _write_json(
            self.root / "manifests" / "components.lock.json",
            {"schema_version": 1, "components": [component]},
        )
        _write_json(
            candidate / "runtime-package.json",
            {
                "schema_version": 1,
                "name": component["name"],
                "version": component["version"],
                "commit": component["commit"],
                "asset": component["asset"],
                "sha256": component["sha256"],
            },
        )
        (candidate / "ao2").write_bytes(data)
        return candidate

    def _runtime_bytes(self, version: str) -> list[bytes]:
        executable = "ao2.exe" if os.name == "nt" else "ao2"
        return [
            (
                self.root
                / "offices"
                / office_id
                / "runtime"
                / "versions"
                / version
                / executable
            ).read_bytes()
            for office_id in OFFICE_IDS
        ]

    def _assert_v1_unchanged(self):
        self.assertEqual(json.loads((self.root / "pool.json").read_text())["runtime_version"], "v1")
        self.assertEqual(self._runtime_bytes("v1"), [self.old_bytes] * 5)
        self.assertFalse(any((self.root / "offices" / office / "runtime" / "versions" / "v2").exists() for office in OFFICE_IDS))

    def test_valid_update_stages_and_activates_five_independent_equal_copies(self):
        # MUTATION: updating pool.json before all five copies makes partial bytes active.
        updater = RuntimeUpdate(self.root)
        staged = updater.stage(self.candidate)
        self.assertEqual(staged, self.root / "components" / "ao2" / "v2")

        updater.activate("v2")

        self.assertEqual(json.loads((self.root / "pool.json").read_text())["runtime_version"], "v2")
        self.assertEqual(self._runtime_bytes("v2"), [self.new_bytes] * 5)
        if os.name != "nt":
            inodes = [
                (self.root / "offices" / office / "runtime" / "versions" / "v2" / "ao2").stat().st_ino
                for office in OFFICE_IDS
            ]
            self.assertEqual(len(set(inodes)), 5)

    def test_rejects_unsafe_versions_and_malformed_manifests_before_staging(self):
        # MUTATION: accepting a relative version lets a package escape its version root.
        updater = RuntimeUpdate(self.root)
        for version in ("..", "v2/escape", "CON", "name. "):
            value = json.loads((self.candidate / "runtime-package.json").read_text())
            value["version"] = version
            _write_json(self.candidate / "runtime-package.json", value)
            with self.subTest(version=version), self.assertRaises(RuntimeUpdateError):
                updater.stage(self.candidate)
        self.candidate = self._candidate("v2", self.new_bytes)
        value = json.loads((self.candidate / "runtime-package.json").read_text())
        value["uncontrolled"] = True
        _write_json(self.candidate / "runtime-package.json", value)
        with self.assertRaises(RuntimeUpdateError):
            updater.stage(self.candidate)
        self.assertFalse((self.root / "components" / "ao2" / "v2").exists())

    def test_incompatible_or_tampered_package_fails_closed(self):
        # MUTATION: trusting a self-consistent package manifest defeats the independent lock.
        value = json.loads((self.candidate / "runtime-package.json").read_text())
        tampered = b"attacker runtime\n"
        value["sha256"] = hashlib.sha256(tampered).hexdigest()
        _write_json(self.candidate / "runtime-package.json", value)
        (self.candidate / "ao2").write_bytes(tampered)

        with self.assertRaises(RuntimeUpdateError) as raised:
            RuntimeUpdate(self.root).stage(self.candidate)

        self.assertEqual(raised.exception.code, "runtime-package-incompatible")
        self._assert_v1_unchanged()

    def test_independent_trust_anchor_detects_substitution(self):
        # MUTATION: rechecking only the staged manifest accepts executable-plus-manifest replacement.
        updater = RuntimeUpdate(self.root)
        staged = updater.stage(self.candidate)
        replacement = b"substituted after stage\n"
        manifest = json.loads((staged / "runtime-package.json").read_text())
        manifest["sha256"] = hashlib.sha256(replacement).hexdigest()
        _write_json(staged / "runtime-package.json", manifest)
        (staged / "ao2").write_bytes(replacement)

        with self.assertRaises(RuntimeUpdateError) as raised:
            updater.activate("v2")

        self.assertEqual(raised.exception.code, "runtime-package-tampered")
        self._assert_v1_unchanged()

    def test_occupied_activation_is_rejected_without_runtime_mutation(self):
        # MUTATION: checking office occupancy outside the pool lock races claims.
        updater = RuntimeUpdate(self.root)
        updater.stage(self.candidate)
        project = self.base / "project"
        project.mkdir()
        Pool(self.root, runtime_version="v1").claim("chat", "task", project, "conversation")

        with self.assertRaises(RuntimeUpdateError) as raised:
            updater.activate("v2")

        self.assertEqual(raised.exception.code, "runtime-update-occupied")
        self._assert_v1_unchanged()

    def test_activation_rolls_back_all_offices(self):
        # MUTATION: restoring only the last replaced office leaves mixed active runtimes.
        for office_id in OFFICE_IDS:
            with self.subTest(office_id=office_id):
                updater = RuntimeUpdate(self.root)
                if not (self.root / "components" / "ao2" / "v2").exists():
                    updater.stage(self.candidate)
                updater.crash_after = f"activate:office:{office_id}"
                with self.assertRaises(RuntimeUpdateError) as raised:
                    updater.activate("v2")
                self.assertEqual(raised.exception.code, "runtime-update-interrupted")
                self._assert_v1_unchanged()

    def test_rollback_reactivates_a_previously_anchored_version(self):
        # MUTATION: requiring the current component lock makes accepted rollback bytes unusable.
        updater = RuntimeUpdate(self.root)
        updater.stage(self.candidate)
        updater.activate("v2")

        old_candidate = self._candidate("v1", self.old_bytes)
        updater.stage(old_candidate)
        updater.rollback("v1")

        self.assertEqual(json.loads((self.root / "pool.json").read_text())["runtime_version"], "v1")
        self.assertEqual(self._runtime_bytes("v1"), [self.old_bytes] * 5)

    def test_abrupt_partial_activation_is_recovered_before_any_pool_caller(self):
        # MUTATION: updater-only reconciliation lets a normal claim observe mixed runtimes.
        RuntimeUpdate(self.root).stage(self.candidate)
        process = multiprocessing.Process(target=_abrupt_activation, args=(str(self.root),))
        process.start()
        process.join(10)
        self.assertEqual(process.exitcode, 98)

        status = Pool(self.root, runtime_version="v1").public_status()

        self.assertTrue(all(office["status"] == "free" for office in status["offices"]))
        self._assert_v1_unchanged()

    def test_linked_component_root_never_receives_staged_bytes(self):
        # MUTATION: lexical component containment writes a verified package through a link.
        outside = self.base / "outside-components"
        outside.mkdir()
        try:
            (self.root / "components").symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(str(error))

        with self.assertRaises(RuntimeUpdateError):
            RuntimeUpdate(self.root).stage(self.candidate)

        self.assertEqual(list(outside.iterdir()), [])

    def test_linked_forged_transaction_journal_is_not_replayed(self):
        # MUTATION: following a journal link lets external bytes authorize reconciliation.
        updates = self.root / "updates"
        updates.mkdir()
        outside = self.base / "forged-journal.json"
        _write_json(
            outside,
            {
                "schema_version": 1,
                "operation_id": "0" * 32,
                "phase": "applying",
                "previous_version": "v1",
                "target_version": "v2",
                "target_sha256": hashlib.sha256(self.new_bytes).hexdigest(),
                "previous_present": {office: True for office in OFFICE_IDS},
                "replaced": [],
            },
        )
        try:
            (updates / "runtime-transaction.json").symlink_to(outside)
        except OSError as error:
            self.skipTest(str(error))

        with self.assertRaises(PoolError) as raised:
            Pool(self.root, runtime_version="v1").public_status()

        self.assertEqual(raised.exception.code, "recovery-required")
        self._assert_v1_unchanged()

    def test_forged_regular_transaction_journal_is_not_replayed(self):
        # MUTATION: structural validation alone lets a local file forge rollback authority.
        updates = self.root / "updates"
        updates.mkdir()
        _write_json(
            updates / "runtime-transaction.json",
            {
                "schema_version": 1,
                "operation_id": "0" * 32,
                "phase": "applying",
                "previous_version": "v1",
                "target_version": "v2",
                "target_sha256": hashlib.sha256(self.new_bytes).hexdigest(),
                "previous_present": {office: True for office in OFFICE_IDS},
                "replaced": [],
            },
        )

        with self.assertRaises(PoolError) as raised:
            Pool(self.root, runtime_version="v1").public_status()

        self.assertEqual(raised.exception.code, "recovery-required")
        self._assert_v1_unchanged()

    def test_authenticated_completed_transaction_cannot_be_replayed(self):
        # MUTATION: an HMAC without durable-prefix validation accepts a copied old journal.
        updater = RuntimeUpdate(self.root, crash_after="activate:office:O1")
        updater.stage(self.candidate)
        captured = []
        restore = updater._restore

        def capture_then_restore(journal):
            captured.append((self.root / "updates" / "runtime-transaction.json").read_bytes())
            restore(journal)

        with mock.patch.object(updater, "_restore", side_effect=capture_then_restore):
            with self.assertRaises(RuntimeUpdateError):
                updater.activate("v2")
        self.assertEqual(len(captured), 1)
        journal = self.root / "updates" / "runtime-transaction.json"
        journal.parent.mkdir(parents=True, exist_ok=True)
        journal.write_bytes(captured[0])

        with self.assertRaises(PoolError) as raised:
            Pool(self.root, runtime_version="v1").public_status()

        self.assertEqual(raised.exception.code, "recovery-required")
        self._assert_v1_unchanged()


if __name__ == "__main__":
    unittest.main()
