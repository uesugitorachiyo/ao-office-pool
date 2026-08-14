import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from internal.readback import protected_record, public_record
from internal.support_bundle import SupportBundleError, support_record, write_support_bundle


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

    def test_public_and_protected_records_are_exact_field_constructors(self):
        # MUTATION: copying caller dictionaries recursively leaks newly added private fields.
        public = public_record(self.status, self.qualification)
        protected = protected_record(self.status, self.qualification)

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

        value = support_record(self.status, self.qualification, diagnostics)

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

    def test_support_bundle_is_create_only_canonical_allowlisted_json(self):
        # MUTATION: overwriting an existing bundle destroys prior diagnostic evidence.
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "support.json"
            record = support_record(
                self.status,
                self.qualification,
                [{"code": "qualification-failed", **_private_seed()}],
            )
            self.assertEqual(write_support_bundle(destination, record), destination)
            self.assertEqual(
                destination.read_bytes(),
                (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            )
            with self.assertRaises(SupportBundleError):
                write_support_bundle(destination, record)

    def test_support_bundle_writer_rejects_non_allowlisted_nested_fields(self):
        # MUTATION: validating only top-level fields lets private diagnostics reach disk.
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "support.json"
            record = support_record(
                self.status,
                self.qualification,
                [{"code": "recovery-required"}],
            )
            record["diagnostics"][0].update(_private_seed())

            with self.assertRaises(SupportBundleError):
                write_support_bundle(destination, record)

            self.assertFalse(destination.exists())

    def test_support_bundle_open_failure_preserves_a_racing_file(self):
        # MUTATION: unconditional failure cleanup can delete a path the writer did not create.
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "support.json"
            sentinel = b"created by another writer\n"
            record = support_record(self.status, self.qualification, [])
            real_open = os.open

            def fail_after_race(path, flags, mode=0o777):
                if Path(path) == destination:
                    destination.write_bytes(sentinel)
                    raise OSError("injected open failure")
                return real_open(path, flags, mode)

            with mock.patch("internal.support_bundle.os.open", side_effect=fail_after_race):
                with self.assertRaises(SupportBundleError):
                    write_support_bundle(destination, record)

            self.assertEqual(destination.read_bytes(), sentinel)

    def test_unknown_status_or_qualification_values_fail_closed(self):
        # MUTATION: reflecting uncontrolled status text turns a safe field into a leak channel.
        changed = json.loads(json.dumps(self.status))
        changed["offices"][0]["status"] = "private-workstation"
        with self.assertRaises(ValueError):
            public_record(changed, self.qualification)
        changed = dict(self.qualification)
        changed["qualification_state"] = "unreviewed-private-state"
        with self.assertRaises(ValueError):
            protected_record(self.status, changed)
        changed = dict(self.qualification)
        changed["runtime_version"] = "/" + "Users" + "/private/runtime"
        with self.assertRaises(ValueError):
            public_record(self.status, changed)


if __name__ == "__main__":
    unittest.main()
