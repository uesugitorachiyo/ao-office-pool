import hashlib
import hmac
import json
import multiprocessing
import os
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from internal import runtime_update as runtime_update_module
from internal.pool import OFFICE_IDS, Pool, PoolError
from internal.runtime_update import RuntimeUpdate, RuntimeUpdateError


def _canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


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


def _abrupt_stage(root: str, candidate: str) -> None:
    RuntimeUpdate(
        Path(root),
        crash_after="stage:prepared",
        abrupt_crash=True,
    ).stage(Path(candidate))


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

    def _runtime_snapshot(self) -> dict[str, list[tuple[str, bytes]]]:
        return {
            office: [
                (path.relative_to(self.root / "offices" / office).as_posix(), path.read_bytes())
                for path in sorted((self.root / "offices" / office).rglob("*"))
                if path.is_file()
            ]
            for office in OFFICE_IDS
        }

    def _assert_v1_unchanged(self):
        self.assertEqual(json.loads((self.root / "pool.json").read_text())["runtime_version"], "v1")
        self.assertEqual(self._runtime_bytes("v1"), [self.old_bytes] * 5)
        self.assertFalse(any((self.root / "offices" / office / "runtime" / "versions" / "v2").exists() for office in OFFICE_IDS))

    def _captured_rolled_back_journal(self) -> bytes:
        updater = RuntimeUpdate(self.root, crash_after="activate:office:O1")
        updater.stage(self.candidate)
        captured = []
        restore = updater._restore

        def capture_then_restore(journal):
            captured.append(
                (self.root / "updates" / "runtime-transaction.json").read_bytes()
            )
            restore(journal)

        with mock.patch.object(updater, "_restore", side_effect=capture_then_restore):
            with self.assertRaises(RuntimeUpdateError):
                updater.activate("v2")
        self.assertEqual(len(captured), 1)
        return captured[0]

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

    def test_stage_normalizes_pool_recovery_failures(self):
        # MUTATION: protected-root Pool errors must not be reported as ordinary stage failure.
        with mock.patch.object(
            Pool,
            "_ensure_initialized",
            side_effect=PoolError("recovery-required"),
        ):
            with self.assertRaises(RuntimeUpdateError) as raised:
                RuntimeUpdate(self.root).stage(self.candidate)

        self.assertEqual(raised.exception.code, "runtime-recovery-required")

    def test_windows_candidate_root_reparse_ancestors_fail_closed(self):
        # MUTATION: resolve plus leaf checks do not reject a junction ancestor on Windows.
        updater = RuntimeUpdate(self.root)
        paths = (
            self.candidate,
            self.candidate / "runtime-package.json",
            self.candidate / "ao2",
        )
        identities = {path: object() for path in paths}
        with (
            mock.patch("internal.runtime_update.os.name", "nt"),
            mock.patch(
                "internal.runtime_update.open_identity",
                side_effect=lambda path: identities[path],
                create=True,
            ) as opened,
            mock.patch("internal.runtime_update.require_within", create=True) as contained,
        ):
            manifest, _, _ = updater._package(self.candidate)
        self.assertEqual(manifest["version"], "v2")
        self.assertEqual(opened.call_args_list, [mock.call(path) for path in paths])
        expected_containment = [
            mock.call(identities[paths[0]], identities[paths[0]]),
            mock.call(identities[paths[1]], identities[paths[0]]),
            mock.call(identities[paths[2]], identities[paths[0]]),
        ]
        self.assertEqual(
            contained.call_args_list,
            expected_containment + expected_containment,
        )

        identity = object()
        with (
            mock.patch("internal.runtime_update.os.name", "nt"),
            mock.patch(
                "internal.runtime_update.open_identity", return_value=identity, create=True
            ),
            mock.patch(
                "internal.runtime_update.require_within",
                side_effect=ValueError("reparse-point ancestor"),
                create=True,
            ),
        ):
            with self.assertRaises(RuntimeUpdateError) as raised:
                updater._package(self.candidate)

        self.assertEqual(raised.exception.code, "runtime-package-invalid")

    def test_windows_candidate_member_replacement_after_read_fails_closed(self):
        # MUTATION: entry-only containment accepts a manifest replaced after
        # its identity was captured but before the package is consumed.
        updater = RuntimeUpdate(self.root)
        paths = (
            self.candidate,
            self.candidate / "runtime-package.json",
            self.candidate / "ao2",
        )
        identities = {path: object() for path in paths}
        manifest_checks = 0

        def reject_replaced_manifest(child, _root):
            nonlocal manifest_checks
            if child is identities[paths[1]]:
                manifest_checks += 1
                if manifest_checks == 2:
                    raise ValueError("manifest identity changed")

        with (
            mock.patch("internal.runtime_update.os.name", "nt"),
            mock.patch(
                "internal.runtime_update.open_identity",
                side_effect=lambda path: identities[path],
            ),
            mock.patch(
                "internal.runtime_update.require_within",
                side_effect=reject_replaced_manifest,
            ),
        ):
            with self.assertRaises(RuntimeUpdateError) as raised:
                updater._package(self.candidate)

        self.assertEqual(raised.exception.code, "runtime-package-invalid")

    def test_windows_staged_package_retains_root_and_member_identities(self):
        # MUTATION: descriptor stability alone does not retain the Windows
        # physical identities of the staged root and its named members.
        updater = RuntimeUpdate(self.root)
        staged = updater.stage(self.candidate)
        paths = (
            staged,
            staged / "runtime-package.json",
            staged / "ao2",
            staged / "runtime-anchor.json",
        )
        identities = {path: object() for path in paths}

        with (
            mock.patch("internal.runtime_update.os.name", "nt"),
            mock.patch(
                "internal.runtime_update.open_identity",
                side_effect=lambda path: identities[path],
            ) as opened,
            mock.patch("internal.runtime_update.require_within") as contained,
        ):
            manifest, _, _ = updater._staged("v2")

        self.assertEqual(manifest["version"], "v2")
        self.assertEqual(opened.call_args_list, [mock.call(path) for path in paths])
        expected_containment = [
            mock.call(identities[paths[0]], identities[paths[0]]),
            *[
                mock.call(identities[path], identities[paths[0]])
                for path in paths[1:]
            ],
        ]
        self.assertEqual(
            contained.call_args_list,
            expected_containment + expected_containment,
        )

    def test_windows_staged_anchor_replacement_after_read_fails_closed(self):
        # MUTATION: omitting the final staged-member identity check accepts an
        # anchor path replaced after its descriptor read.
        updater = RuntimeUpdate(self.root)
        staged = updater.stage(self.candidate)
        paths = (
            staged,
            staged / "runtime-package.json",
            staged / "ao2",
            staged / "runtime-anchor.json",
        )
        identities = {path: object() for path in paths}
        anchor_checks = 0

        def reject_replaced_anchor(child, _root):
            nonlocal anchor_checks
            if child is identities[paths[3]]:
                anchor_checks += 1
                if anchor_checks == 2:
                    raise ValueError("anchor identity changed")

        with (
            mock.patch("internal.runtime_update.os.name", "nt"),
            mock.patch(
                "internal.runtime_update.open_identity",
                side_effect=lambda path: identities[path],
            ),
            mock.patch(
                "internal.runtime_update.require_within",
                side_effect=reject_replaced_anchor,
            ),
        ):
            with self.assertRaises(RuntimeUpdateError) as raised:
                updater._staged("v2")

        self.assertEqual(raised.exception.code, "runtime-package-tampered")

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

    def test_stage_publishes_package_and_anchor_in_one_rename(self):
        # MUTATION: publishing the package before its anchor leaves a visible half-stage.
        process = multiprocessing.Process(
            target=_abrupt_stage,
            args=(str(self.root), str(self.candidate)),
        )
        process.start()
        process.join(10)
        self.assertFalse(process.is_alive())
        self.assertEqual(process.exitcode, 98)
        target = self.root / "components" / "ao2" / "v2"
        self.assertFalse(target.exists())

        staged = RuntimeUpdate(self.root).stage(self.candidate)
        self.assertEqual(
            {path.name for path in staged.iterdir()},
            {"runtime-package.json", "ao2", "runtime-anchor.json"},
        )

    def test_stage_captures_package_and_component_authority_inside_pool_lock(self):
        # MUTATION: reading either input before the Pool lock permits a stale
        # candidate/authority pair to be staged after a concurrent transition.
        updater = RuntimeUpdate(self.root)
        real_locked = Pool._locked
        real_package = updater._package
        real_read_regular = runtime_update_module._read_regular
        state = {"lock_depth": 0, "package": False, "component_lock": False}

        @contextmanager
        def tracked_locked(pool, *args, **kwargs):
            with real_locked(pool, *args, **kwargs):
                state["lock_depth"] += 1
                try:
                    yield
                finally:
                    state["lock_depth"] -= 1

        def tracked_package(candidate):
            self.assertGreater(state["lock_depth"], 0)
            state["package"] = True
            return real_package(candidate)

        def tracked_read_regular(path, limit):
            if Path(path) == updater._lock_manifest:
                self.assertGreater(state["lock_depth"], 0)
                state["component_lock"] = True
            return real_read_regular(path, limit)

        with (
            mock.patch.object(Pool, "_locked", new=tracked_locked),
            mock.patch.object(updater, "_package", side_effect=tracked_package),
            mock.patch(
                "internal.runtime_update._read_regular",
                side_effect=tracked_read_regular,
            ),
        ):
            updater.stage(self.candidate)

        self.assertTrue(state["package"])
        self.assertTrue(state["component_lock"])

    def test_activation_rejects_component_authority_drift_after_stage(self):
        # MUTATION: authenticating only the staged manifest and asset lets an
        # obsolete installed component authority activate later.
        updater = RuntimeUpdate(self.root)
        updater.stage(self.candidate)
        replacement = b"future runtime v3\n"
        _write_json(
            self.root / "manifests" / "components.lock.json",
            {
                "schema_version": 1,
                "components": [self._component("v3", replacement)],
            },
        )

        with self.assertRaises(RuntimeUpdateError) as raised:
            updater.activate("v2")

        self.assertEqual(raised.exception.code, "runtime-package-tampered")
        self._assert_v1_unchanged()

    def test_staged_anchor_is_authenticated_against_coordinated_substitution(self):
        # MUTATION: an unkeyed digest anchor can be rewritten with package and executable.
        updater = RuntimeUpdate(self.root)
        staged = updater.stage(self.candidate)
        replacement = b"coordinated substituted runtime\n"
        manifest = json.loads((staged / "runtime-package.json").read_bytes())
        manifest["sha256"] = hashlib.sha256(replacement).hexdigest()
        _write_json(staged / "runtime-package.json", manifest)
        (staged / "ao2").write_bytes(replacement)
        anchor = {
            "schema_version": 1,
            "version": "v2",
            "manifest_sha256": hashlib.sha256(
                (staged / "runtime-package.json").read_bytes()
            ).hexdigest(),
            "asset_sha256": hashlib.sha256(replacement).hexdigest(),
        }
        anchor_path = staged / "runtime-anchor.json"
        if not anchor_path.exists():
            anchor_path = (
                self.root / "operator-secrets" / "runtime-anchors" / "v2.json"
            )
        _write_json(anchor_path, anchor)

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

    def test_pending_recovery_rejects_empty_rekeyed_hmac_before_runtime_mutation(self):
        # MUTATION: validating the exact key only after recovery lets an empty key
        # authenticate a rewritten journal and mutate runtime bytes before rejection.
        RuntimeUpdate(self.root).stage(self.candidate)
        process = multiprocessing.Process(target=_abrupt_activation, args=(str(self.root),))
        process.start()
        process.join(10)
        self.assertEqual(process.exitcode, 98)

        key = self.root / "operator-secrets" / "governance-witness.key"
        key.write_bytes(b"")
        journal_path = self.root / "updates" / "runtime-transaction.json"
        journal = json.loads(journal_path.read_bytes())
        journal_payload = {
            name: member for name, member in journal.items() if name != "journal_tag"
        }
        journal["journal_tag"] = hmac.new(
            b"",
            b"runtime-update-journal\0" + _canonical(journal_payload),
            hashlib.sha256,
        ).hexdigest()
        _write_json(journal_path, journal)

        state_path = self.root / "runtime" / "runtime-update-state.json"
        state = json.loads(state_path.read_bytes())
        state_payload = {"schema_version": 1, "completed": state["completed"]}
        state["state_tag"] = hmac.new(
            b"",
            b"runtime-update-state\0" + _canonical(state_payload),
            hashlib.sha256,
        ).hexdigest()
        _write_json(state_path, state)
        before = self._runtime_snapshot()

        with self.assertRaises(PoolError) as raised:
            Pool(self.root, runtime_version="v1").public_status()

        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(self._runtime_snapshot(), before)

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
        captured = self._captured_rolled_back_journal()
        journal = self.root / "updates" / "runtime-transaction.json"
        journal.parent.mkdir(parents=True, exist_ok=True)
        journal.write_bytes(captured)

        status = Pool(self.root, runtime_version="v1").public_status()

        self.assertTrue(
            all(office["status"] == "free" for office in status["offices"])
        )
        self.assertFalse(journal.exists())
        self._assert_v1_unchanged()

    def test_authenticated_journal_with_recreated_empty_prefix_cannot_replay(self):
        # MUTATION: recreating an operation directory must not revive a completed journal.
        captured = self._captured_rolled_back_journal()
        RuntimeUpdate(self.root).activate("v2")
        value = json.loads(captured)
        transaction = (
            self.root
            / "updates"
            / "runtime-transactions"
            / value["operation_id"]
        )
        transaction.mkdir(parents=True)
        (self.root / "updates" / "runtime-transaction.json").write_bytes(captured)

        status = Pool(self.root, runtime_version="v2").public_status()

        self.assertTrue(all(office["status"] == "free" for office in status["offices"]))
        self.assertEqual(
            json.loads((self.root / "pool.json").read_text())["runtime_version"],
            "v2",
        )
        self.assertEqual(self._runtime_bytes("v2"), [self.new_bytes] * 5)
        self.assertFalse(transaction.exists())
        self.assertFalse(
            (self.root / "updates" / "runtime-transaction.json").exists()
        )

    def test_applying_journal_and_rolled_back_registry_cannot_rewind_exact_target(self):
        # MUTATION: choosing restore from an applying phase plus rollbackable
        # registry absence rewinds a later state that exactly matches the target.
        updater = RuntimeUpdate(self.root, crash_after="activate:office:O5")
        updater.stage(self.candidate)
        captured = self.base / "captured-runtime-transaction"
        evidence = {}
        restore = updater._restore

        def capture_then_restore(journal):
            evidence["journal"] = (
                self.root / "updates" / "runtime-transaction.json"
            ).read_bytes()
            evidence["state"] = (
                self.root / "runtime" / "runtime-update-state.json"
            ).read_bytes()
            shutil.copytree(updater._transaction_root(journal), captured)
            restore(journal)

        with mock.patch.object(updater, "_restore", side_effect=capture_then_restore):
            with self.assertRaises(RuntimeUpdateError):
                updater.activate("v2")

        RuntimeUpdate(self.root).activate("v2")
        journal = json.loads(evidence["journal"])
        transaction = (
            self.root
            / "updates"
            / "runtime-transactions"
            / journal["operation_id"]
        )
        shutil.copytree(captured, transaction)
        (self.root / "updates" / "runtime-transaction.json").write_bytes(
            evidence["journal"]
        )
        (self.root / "runtime" / "runtime-update-state.json").write_bytes(
            evidence["state"]
        )

        status = Pool(self.root, runtime_version="v2").public_status()

        self.assertTrue(all(office["status"] == "free" for office in status["offices"]))
        self.assertEqual(
            json.loads((self.root / "pool.json").read_bytes())["runtime_version"],
            "v2",
        )
        self.assertEqual(self._runtime_bytes("v2"), [self.new_bytes] * 5)
        self.assertFalse(transaction.exists())
        self.assertFalse(
            (self.root / "updates" / "runtime-transaction.json").exists()
        )

    def test_missing_required_backup_cannot_authorize_restore(self):
        # MUTATION: previous_present=True is not proof when its backup has disappeared.
        updater = RuntimeUpdate(self.root, crash_after="activate:office:O1")
        updater.stage(self.candidate)
        restore = updater._restore

        def discard_then_restore(journal):
            shutil.rmtree(updater._transaction_root(journal) / "O1.old")
            restore(journal)

        with mock.patch.object(updater, "_restore", side_effect=discard_then_restore):
            with self.assertRaises(RuntimeUpdateError) as raised:
                updater.activate("v2")

        self.assertEqual(raised.exception.code, "runtime-recovery-required")

    def test_transaction_cleanup_failure_is_recovery_required(self):
        # MUTATION: deleting the journal before ignored cleanup abandons replayable state.
        updater = RuntimeUpdate(self.root)
        updater.stage(self.candidate)
        real_rmtree = shutil.rmtree

        def fail_transaction_cleanup(path, *args, **kwargs):
            if Path(path).parent.name == "runtime-transactions":
                raise OSError("transaction cleanup denied")
            return real_rmtree(path, *args, **kwargs)

        with mock.patch(
            "internal.runtime_update.shutil.rmtree",
            side_effect=fail_transaction_cleanup,
        ):
            with self.assertRaises(RuntimeUpdateError) as raised:
                updater.activate("v2")

        self.assertEqual(raised.exception.code, "runtime-recovery-required")
        self.assertTrue((self.root / "updates" / "runtime-transaction.json").exists())


if __name__ == "__main__":
    unittest.main()
