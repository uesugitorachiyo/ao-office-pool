import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from internal import readback as readback_module
from internal.qualification import Qualification
from internal.readback import protected_record, public_record
from internal.runtime_update import RuntimeUpdate
from internal.support_bundle import SupportBundleError, support_record, write_support_bundle
from tests import test_qualification as qualification_tests


def _private_seed():
    return {
        "raw_" + "receipt": "authority-value-that-must-not-leave-protected-storage",
        "operator_" + "secret": "operator-value-that-must-not-leave-protected-storage",
        "host" + "name": "private-workstation",
        "local_" + "path": "/" + "Users" + "/private/connected-project",
        "raw_" + "credential": "credential-value-that-must-not-leave-protected-storage",
        "uncontrolled_" + "evidence": {"model-output": "private"},
    }


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.root = Path("/unit-readback-root")
        self.status = {
            "schema_version": 1,
            "offices": [
                {"office_id": "O1", "status": "occupied", "generation": 3, **_private_seed()},
                *[
                    {"office_id": f"O{number}", "status": "free", "generation": 0}
                    for number in range(2, 6)
                ],
            ],
            **_private_seed(),
        }
        self.qualification = {
            "schema_version": 1,
            "runtime_version": "v2",
            "runtime_sha256": "a" * 64,
            "runtime_state": "activated",
            "qualification_state": "candidate",
            "semantic_fingerprint": "b" * 64,
            "record_digest": "c" * 64,
            **_private_seed(),
        }
        self.active_snapshot = mock.patch(
            "internal.readback._active_snapshot",
            side_effect=lambda _root, status, qualification: (
                readback_module._qualification(qualification),
                readback_module._offices(status),
            ),
        )
        self.active_snapshot.start()
        self.addCleanup(self.active_snapshot.stop)
        self.active_support = mock.patch(
            "internal.support_bundle._require_active_support"
        )
        self.active_support.start()
        self.addCleanup(self.active_support.stop)

    def test_public_and_protected_records_are_exact_field_constructors(self):
        # MUTATION: copying caller dictionaries recursively leaks newly added private fields.
        public = public_record(self.root, self.status, self.qualification)
        protected = protected_record(self.root, self.status, self.qualification)

        self.assertEqual(
            set(public),
            {"schema_version", "runtime_version", "qualification_state", "offices"},
        )
        self.assertEqual(
            set(protected),
            {"schema_version", "runtime", "qualification", "offices"},
        )
        self.assertEqual(set(protected["runtime"]), {"version", "sha256", "state"})
        self.assertEqual(
            set(protected["qualification"]),
            {"state", "semantic_fingerprint", "record_digest"},
        )
        self.assertTrue(all(set(office) == {"office_id", "status", "generation"} for office in public["offices"]))
        encoded = json.dumps({"public": public, "protected": protected}, sort_keys=True)
        for value in _private_seed().values():
            if isinstance(value, str):
                self.assertNotIn(value, encoded)

    def test_support_record_redacts_private_seeds_and_allowlists_actionable_codes(self):
        # MUTATION: exporting arbitrary diagnostic messages discloses host and authority data.
        diagnostics = [
            {"code": "recovery-required", "message": json.dumps(_private_seed())},
            {"code": "runtime-update-failed", **_private_seed()},
            {"code": "attacker-controlled-code", **_private_seed()},
            {"code": "recovery-required"},
        ]

        value = support_record(self.root, self.status, self.qualification, diagnostics)

        self.assertEqual(
            value["diagnostics"],
            [
                {"code": "recovery-required", "count": 2},
                {"code": "runtime-update-failed", "count": 1},
            ],
        )
        self.assertEqual(
            set(value),
            {"schema_version", "runtime_version", "qualification_state", "offices", "diagnostics"},
        )
        encoded = json.dumps(value, sort_keys=True)
        for forbidden in (
            "authority-value-that-must-not-leave-protected-storage",
            "operator-value-that-must-not-leave-protected-storage",
            "private-workstation",
            "/" + "Users" + "/private/connected-project",
            "credential-value-that-must-not-leave-protected-storage",
            "model-output",
            "attacker-controlled-code",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_unhashable_diagnostic_codes_are_ignored(self):
        # MUTATION: membership lookup before type validation leaks an uncontrolled TypeError.
        value = support_record(
            self.root,
            self.status,
            self.qualification,
            [{"code": []}, {"code": "recovery-required"}],
        )

        self.assertEqual(
            value["diagnostics"],
            [{"code": "recovery-required", "count": 1}],
        )

    def test_support_bundle_is_create_only_canonical_allowlisted_json(self):
        # MUTATION: overwriting an existing bundle destroys prior diagnostic evidence.
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "support.json"
            record = support_record(
                self.root,
                self.status,
                self.qualification,
                [{"code": "qualification-failed", **_private_seed()}],
            )
            self.assertEqual(
                write_support_bundle(self.root, destination, record), destination
            )
            self.assertEqual(
                destination.read_bytes(),
                (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            )
            with self.assertRaises(SupportBundleError):
                write_support_bundle(self.root, destination, record)

    def test_support_bundle_writer_rejects_non_allowlisted_nested_fields(self):
        # MUTATION: validating only top-level fields lets private diagnostics reach disk.
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "support.json"
            record = support_record(
                self.root,
                self.status,
                self.qualification,
                [{"code": "recovery-required"}],
            )
            record["diagnostics"][0].update(_private_seed())

            with self.assertRaises(SupportBundleError):
                write_support_bundle(self.root, destination, record)

            self.assertFalse(destination.exists())

    def test_support_bundle_open_failure_preserves_a_racing_file(self):
        # MUTATION: unconditional failure cleanup can delete a path the writer did not create.
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "support.json"
            sentinel = b"created by another writer\n"
            record = support_record(self.root, self.status, self.qualification, [])
            real_open = os.open

            def fail_after_race(path, flags, mode=0o777):
                if Path(path) == destination:
                    destination.write_bytes(sentinel)
                    raise OSError("injected open failure")
                return real_open(path, flags, mode)

            with mock.patch("internal.support_bundle.os.open", side_effect=fail_after_race):
                with self.assertRaises(SupportBundleError):
                    write_support_bundle(self.root, destination, record)

            self.assertEqual(destination.read_bytes(), sentinel)

    def test_support_bundle_failure_removes_only_the_created_identity(self):
        # MUTATION: a created boolean can delete a replacement after mid-write failure.
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "support.json"
            replacement = Path(directory) / "replacement.json"
            sentinel = b"replacement owned by another writer\n"
            replacement.write_bytes(sentinel)
            record = support_record(self.root, self.status, self.qualification, [])

            def replace_then_fail(_descriptor, _data):
                os.replace(replacement, destination)
                raise OSError("injected write failure")

            with mock.patch(
                "internal.support_bundle.os.write",
                side_effect=replace_then_fail,
            ):
                with self.assertRaises(SupportBundleError):
                    write_support_bundle(self.root, destination, record)

            self.assertEqual(destination.read_bytes(), sentinel)

    def test_support_bundle_success_requires_retained_path_identity(self):
        # MUTATION: successful descriptor writes do not prove the pathname still names it.
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "support.json"
            replacement = Path(directory) / "replacement.json"
            sentinel = b"replacement owned by another writer\n"
            replacement.write_bytes(sentinel)
            record = support_record(self.root, self.status, self.qualification, [])
            real_write = os.write
            replaced = False

            def replace_after_write(descriptor, data):
                nonlocal replaced
                count = real_write(descriptor, data)
                if not replaced:
                    os.replace(replacement, destination)
                    replaced = True
                return count

            with mock.patch(
                "internal.support_bundle.os.write",
                side_effect=replace_after_write,
            ):
                with self.assertRaises(SupportBundleError):
                    write_support_bundle(self.root, destination, record)

            self.assertEqual(destination.read_bytes(), sentinel)

    def test_support_bundle_failure_removes_its_unchanged_created_file(self):
        # Legitimate control: failed private output does not leave partial bytes.
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "support.json"
            record = support_record(self.root, self.status, self.qualification, [])
            with mock.patch(
                "internal.support_bundle.os.write",
                side_effect=OSError("injected write failure"),
            ):
                with self.assertRaises(SupportBundleError):
                    write_support_bundle(self.root, destination, record)

            self.assertFalse(destination.exists())

    def test_unknown_status_or_qualification_values_fail_closed(self):
        # MUTATION: reflecting uncontrolled status text turns a safe field into a leak channel.
        changed = json.loads(json.dumps(self.status))
        changed["offices"][0]["status"] = "private-workstation"
        with self.assertRaises(ValueError):
            public_record(self.root, changed, self.qualification)
        changed = dict(self.qualification)
        changed["qualification_state"] = "unreviewed-private-state"
        with self.assertRaises(ValueError):
            protected_record(self.root, self.status, changed)
        changed = dict(self.qualification)
        changed["runtime_version"] = "/" + "Users" + "/private/runtime"
        with self.assertRaises(ValueError):
            public_record(self.root, self.status, changed)


class ActiveReadbackTests(unittest.TestCase):
    def setUp(self):
        self.fixture = qualification_tests.QualificationTests(
            "test_exact_qualification_binding_promotes_candidate"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.pool = self.fixture.pool
        self.record_path = Qualification(self.root).promote(
            self.fixture.evidence, "candidate"
        )
        self.qualification = json.loads(self.record_path.read_bytes())
        self.status = self.pool.public_status()
        self._stage(
            self.fixture._component()["version"],
            self.fixture.runtime_bytes,
            self.fixture._component()["commit"],
        )
        self.support = support_record(
            self.root, self.status, self.qualification, []
        )

    def _stage(self, version: str, asset: bytes, commit: str) -> None:
        component_lock = json.loads(
            (self.root / "manifests/components.lock.json").read_bytes()
        )
        ao2 = next(
            component
            for component in component_lock["components"]
            if component["name"] == "ao2"
        )
        ao2.update(
            {
                "version": version,
                "commit": commit,
                "sha256": hashlib.sha256(asset).hexdigest(),
            }
        )
        (self.root / "manifests/components.lock.json").write_bytes(
            (json.dumps(component_lock, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        candidate = self.fixture.base / ("readback-" + version)
        candidate.mkdir()
        manifest = {
            "schema_version": 1,
            "name": "ao2",
            "version": version,
            "commit": commit,
            "asset": "ao2",
            "sha256": hashlib.sha256(asset).hexdigest(),
        }
        (candidate / "runtime-package.json").write_bytes(
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        (candidate / "ao2").write_bytes(asset)
        RuntimeUpdate(self.root).stage(candidate)

    def _change_runtime(self, version: str, operation) -> None:
        self.pool.release(self.fixture.claim_path)
        self._stage(version, (version + " runtime\n").encode(), "b" * 40)
        operation(version)

    def _assert_stale_exports_fail(self) -> None:
        with self.assertRaises(ValueError):
            public_record(self.root, self.status, self.qualification)
        with self.assertRaises(ValueError):
            protected_record(self.root, self.status, self.qualification)
        with self.assertRaises(ValueError):
            support_record(self.root, self.status, self.qualification, [])
        destination = self.fixture.base / "stale-support.json"
        with self.assertRaises(SupportBundleError):
            write_support_bundle(self.root, destination, self.support)
        self.assertFalse(destination.exists())

    def test_same_active_runtime_allows_readback_and_support_export(self):
        public = public_record(self.root, self.status, self.qualification)
        protected = protected_record(self.root, self.status, self.qualification)
        support = support_record(self.root, self.status, self.qualification, [])
        destination = self.fixture.base / "active-support.json"

        self.assertEqual(public["runtime_version"], self.qualification["runtime_version"])
        self.assertEqual(protected["runtime"]["sha256"], self.qualification["runtime_sha256"])
        self.assertEqual(
            write_support_bundle(self.root, destination, support), destination
        )

    def test_activation_invalidates_detached_qualification_exports(self):
        self._change_runtime("v0.5.12", RuntimeUpdate(self.root).activate)
        self._assert_stale_exports_fail()

    def test_rollback_invalidates_detached_qualification_exports(self):
        self._change_runtime("v0.5.10", RuntimeUpdate(self.root).rollback)
        self._assert_stale_exports_fail()


if __name__ == "__main__":
    unittest.main()
