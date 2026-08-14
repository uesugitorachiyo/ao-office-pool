import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from internal.pool import OFFICE_IDS, Pool
from internal.qualification import Qualification, QualificationError


def _canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest_value(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name).resolve()
        self.root = self.base / "pool"
        self.project = self.base / "connected-project"
        self.project.mkdir()
        self.runtime_bytes = b"qualified ao2\n"
        self.runtime_sha256 = hashlib.sha256(self.runtime_bytes).hexdigest()
        Pool(self.root, runtime_version="v2").initialize()
        for office_id in OFFICE_IDS:
            path = self.root / "offices" / office_id / "runtime" / "versions" / "v2" / ("ao2.exe" if os.name == "nt" else "ao2")
            path.parent.mkdir(parents=True)
            path.write_bytes(self.runtime_bytes)
        installed_lock = self.root / "manifests" / "components.lock.json"
        installed_lock.parent.mkdir(parents=True)
        installed_lock.write_bytes(
            _canonical({"schema_version": 1, "components": [self._component()]})
        )
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        self._write_evidence()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _write(self, name: str, value: dict) -> bytes:
        raw = _canonical(value)
        (self.evidence / name).write_bytes(raw)
        return raw

    def _component(self):
        return {
            "name": "ao2",
            "version": "v2",
            "repository": "https://example.invalid/ao2",
            "commit": "a" * 40,
            "asset": "ao2",
            "license": "Apache-2.0",
            "sha256": self.runtime_sha256,
        }

    def _write_evidence(self):
        runtime = {
            "schema_version": 1,
            "name": "ao2",
            "version": "v2",
            "commit": "a" * 40,
            "asset": "ao2",
            "sha256": self.runtime_sha256,
        }
        component_lock = {"schema_version": 1, "components": [self._component()]}
        project_information = self.project.stat()
        authority = {
            "schema_version": 1,
            "authority_id": "1" * 64,
            "office_id": "O1",
            "generation": 4,
            "holder_digest": "2" * 64,
            "task_digest": "3" * 64,
            "project_path": str(self.project),
            "project_volume": project_information.st_dev,
            "project_file_id": str(project_information.st_ino),
            "mode": "conversation",
        }
        authority_raw = _canonical(authority)
        authority_digest = hashlib.sha256(authority_raw).hexdigest()
        mission = {
            "schema_version": 1,
            "mission_id": "mission-0123456789abcdef",
            "objective_digest": "sha256:" + authority["task_digest"],
            "authority_digest": authority_digest,
            "chat_digest": authority["holder_digest"],
            "task_digest": authority["task_digest"],
            "office_id": authority["office_id"],
            "generation": authority["generation"],
            "project_path": authority["project_path"],
            "mission_status": "active",
            "current_route": "ao-forge",
        }
        source_requirements = Path(__file__).parents[1] / "manifests" / "requirements.json"
        requirements = json.loads(source_requirements.read_text(encoding="utf-8"))
        requirements_raw = _canonical(requirements)
        blocker_rows = [row for row in requirements["requirements"] if row["id"].startswith("B")]
        blocker_bindings = {row["id"]: row["test_id"] for row in blocker_rows}
        requirements_evidence = {
            "requirements_sha256": hashlib.sha256(requirements_raw).hexdigest(),
            "test_bindings_sha256": _digest_value(blocker_bindings),
            "requirement_ids": [f"B{number:02d}" for number in range(1, 20)],
        }
        producer_artifacts = {
            "ao-blueprint": self._producer("4"),
            "ao-atlas": self._producer("5"),
            "ao-forge": self._producer("6"),
            "ao-covenant": self._producer("7"),
        }
        route = {
            "decision_digest": "8" * 64,
            "route": "ao-forge",
            "atlas_required": True,
            "execution_candidate": True,
        }
        target = {
            "canonical_path": authority["project_path"],
            "volume": authority["project_volume"],
            "file_id": authority["project_file_id"],
        }
        ao2 = {"name": "ao2", "commit": "a" * 40, "asset": "ao2", "sha256": self.runtime_sha256}
        request = {
            "authority_digest": authority_digest,
            "mission_id": mission["mission_id"],
            "route_digest": route["decision_digest"],
            "target": target,
            "workflow_digest": "9" * 64,
            "run_id": "run-0123456789abcdef",
            "producer_artifacts": producer_artifacts,
            "requirements_evidence_digest": _digest_value(requirements_evidence),
            "ao2": ao2,
        }
        governance = {
            "schema_version": 1,
            "witness_id": "witness-0123456789abcdef0123456789abcdef",
            "state": "ready",
            "authority_digest": authority_digest,
            "office_id": authority["office_id"],
            "generation": authority["generation"],
            "runtime_version": "v2",
            "project_path": authority["project_path"],
            "project_volume": authority["project_volume"],
            "project_file_id": authority["project_file_id"],
            "mission": {"mission_id": mission["mission_id"], "objective_digest": mission["objective_digest"], "status": mission["mission_status"], "current_route": mission["current_route"]},
            "route": route,
            "task_digest": authority["task_digest"],
            "request_digest": _digest_value(request),
            "target": target,
            "workflow_digest": request["workflow_digest"],
            "run_id": request["run_id"],
            "producer_artifacts": producer_artifacts,
            "covenant": {"decision": "authorized", "scope": authority["project_path"], "expires_at": "2026-08-13T23:59:59Z", "revoked": False},
            "requirements_evidence_digest": request["requirements_evidence_digest"],
            "ao2": ao2,
            "created_at": "2026-08-13T00:00:00Z",
            "expires_at": "2026-08-13T00:05:00Z",
            "payload_digest": "0" * 64,
        }
        governance["payload_digest"] = _digest_value({key: value for key, value in governance.items() if key != "payload_digest"})
        execution = {
            "schema_version": 1,
            "execution_id": "execution-0123456789abcdef0123456789abcdef",
            "phase": "completed",
            "request_digest": governance["request_digest"],
            "mission_id": mission["mission_id"],
            "objective_digest": mission["objective_digest"],
            "route_digest": route["decision_digest"],
            "authority_digest": authority_digest,
            "office_id": authority["office_id"],
            "generation": authority["generation"],
            "project_path": authority["project_path"],
            "target_path": authority["project_path"],
            "workflow_path": str(self.project / ".ao" / "governance" / "office-pool" / "workflows" / request["workflow_digest"]),
            "workflow_sha256": request["workflow_digest"],
            "run_id": request["run_id"],
            "blueprint_digest": producer_artifacts["ao-blueprint"]["artifact_sha256"],
            "atlas_digest": producer_artifacts["ao-atlas"]["artifact_sha256"],
            "forge_digest": producer_artifacts["ao-forge"]["artifact_sha256"],
            "covenant_digest": producer_artifacts["ao-covenant"]["artifact_sha256"],
            "ao2_sha256": self.runtime_sha256,
            "diagnostics": {"status": "accepted", "run_id": request["run_id"]},
            "exit_code": 0,
            "failure_code": None,
            "record_digest": "0" * 64,
        }
        execution["record_digest"] = _digest_value({key: value for key, value in execution.items() if key != "record_digest"})
        matrix = {
            "schema_version": 1,
            "assertions": [{"requirement_id": row["id"], "test_id": row["test_id"]} for row in blocker_rows],
        }
        values = {
            "runtime-package.json": runtime,
            "components.lock.json": component_lock,
            "claim-receipt.json": authority,
            "mission-record.json": mission,
            "governance-envelope.json": governance,
            "execution-record.json": execution,
            "requirements.json": requirements,
            "critical-matrix.json": matrix,
        }
        fingerprints = []
        for name, value in values.items():
            raw = self._write(name, value)
            fingerprints.append({"name": name, "sha256": hashlib.sha256(raw).hexdigest()})
        self._write("semantic-inputs.json", {"schema_version": 1, "inputs": fingerprints})

    @staticmethod
    def _producer(digit: str):
        return {
            "commit": digit * 40,
            "asset": "producer",
            "binary_sha256": digit * 64,
            "command_contract": "producer run",
            "artifact_sha256": digit * 64,
        }

    def _rewrite_semantic_manifest(self):
        inputs = []
        for path in sorted(self.evidence.glob("*.json")):
            if path.name == "semantic-inputs.json":
                continue
            inputs.append({"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        self._write("semantic-inputs.json", {"schema_version": 1, "inputs": inputs})

    def _record(self):
        return json.loads((self.root / "updates" / "qualification.json").read_text(encoding="utf-8"))

    def test_exact_qualification_binding_promotes_candidate(self):
        # MUTATION: omitting one cross-record identity accepts unrelated execution evidence.
        record_path = Qualification(self.root).promote(self.evidence, "candidate")
        record = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(record["qualification_state"], "candidate")
        self.assertEqual(record["runtime_version"], "v2")
        self.assertEqual(record["runtime_sha256"], self.runtime_sha256)
        self.assertEqual(record["mission_id"], "mission-0123456789abcdef")
        self.assertEqual(record["witness_id"], "witness-0123456789abcdef0123456789abcdef")
        self.assertEqual(record["execution_id"], "execution-0123456789abcdef0123456789abcdef")
        self.assertEqual(record["assertion_count"], 19)
        self.assertNotIn(str(self.project), json.dumps(record))

    def test_fingerprint_binds_semantic_inputs(self):
        # MUTATION: hashing only a wrapper lets a consumed evidence file change undetected.
        execution = self.evidence / "execution-record.json"
        execution.write_bytes(execution.read_bytes() + b" ")
        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")
        self.assertEqual(raised.exception.code, "qualification-fingerprint-mismatch")

    def test_promotion_state_is_hash_bound(self):
        # MUTATION: a direct write can leave a new state with an old evidence digest.
        qualification = Qualification(self.root)
        qualification.promote(self.evidence, "candidate")
        before = (self.root / "updates" / "qualification.json").read_bytes()
        with mock.patch("internal.qualification.atomic_write_json", side_effect=OSError("interrupted")):
            with self.assertRaises(QualificationError):
                qualification.promote(self.evidence, "pilot-qualified")
        self.assertEqual((self.root / "updates" / "qualification.json").read_bytes(), before)
        record = self._record()
        digest = record.pop("record_digest")
        self.assertEqual(digest, _digest_value(record))

    def test_critical_matrix_is_exact(self):
        # MUTATION: set inclusion accepts a stale or extra critical assertion.
        matrix_path = self.evidence / "critical-matrix.json"
        matrix = json.loads(matrix_path.read_text())
        matrix["assertions"].pop()
        self._write("critical-matrix.json", matrix)
        self._rewrite_semantic_manifest()
        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")
        self.assertEqual(raised.exception.code, "qualification-critical-matrix-mismatch")

    def test_readability_gates_preserve_semantics(self):
        # MUTATION: dropping B14 from the exact matrix silently drops its semantic gate.
        matrix_path = self.evidence / "critical-matrix.json"
        matrix = json.loads(matrix_path.read_text())
        matrix["assertions"] = [row for row in matrix["assertions"] if row["requirement_id"] != "B14"]
        self._write("critical-matrix.json", matrix)
        self._rewrite_semantic_manifest()
        with self.assertRaises(QualificationError):
            Qualification(self.root).promote(self.evidence, "candidate")

    def test_root_authority_order(self):
        # MUTATION: rebinding B15 to another assertion loses the recorded authority gate.
        self._replace_binding("B15", "tests.test_pool.PoolTests.test_atomic_first_free_claims")
        with self.assertRaises(QualificationError):
            Qualification(self.root).promote(self.evidence, "candidate")

    def test_specifications_bind_real_code_and_tests(self):
        # MUTATION: a plausible but absent method cannot qualify an acceptance row.
        self._replace_binding("B16", "tests.test_qualification.QualificationTests.test_absent")
        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")
        self.assertEqual(raised.exception.code, "qualification-test-binding-mismatch")

    def test_acceptance_rows_bind_existing_modules(self):
        # MUTATION: checking only dotted syntax accepts a nonexistent test module.
        self._replace_binding("B17", "tests.test_missing.MissingTests.test_missing")
        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")
        self.assertEqual(raised.exception.code, "qualification-test-binding-mismatch")

    def test_lifecycle_authorities_agree(self):
        # MUTATION: accepting execution evidence for another runtime breaks durable lifecycle agreement.
        execution = json.loads((self.evidence / "execution-record.json").read_text())
        execution["ao2_sha256"] = "f" * 64
        execution["record_digest"] = _digest_value({key: value for key, value in execution.items() if key != "record_digest"})
        self._write("execution-record.json", execution)
        self._rewrite_semantic_manifest()
        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")
        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

    def test_component_identity_is_bound_to_the_installed_independent_lock(self):
        # MUTATION: checking only self-consistent evidence lets every component identity be replaced.
        replacement = "b" * 40
        runtime = json.loads((self.evidence / "runtime-package.json").read_text())
        runtime["commit"] = replacement
        self._write("runtime-package.json", runtime)
        components = json.loads((self.evidence / "components.lock.json").read_text())
        components["components"][0]["commit"] = replacement
        self._write("components.lock.json", components)
        governance = json.loads((self.evidence / "governance-envelope.json").read_text())
        governance["ao2"]["commit"] = replacement
        request = {
            "authority_digest": governance["authority_digest"],
            "mission_id": governance["mission"]["mission_id"],
            "route_digest": governance["route"]["decision_digest"],
            "target": governance["target"],
            "workflow_digest": governance["workflow_digest"],
            "run_id": governance["run_id"],
            "producer_artifacts": governance["producer_artifacts"],
            "requirements_evidence_digest": governance["requirements_evidence_digest"],
            "ao2": governance["ao2"],
        }
        governance["request_digest"] = _digest_value(request)
        governance["payload_digest"] = _digest_value(
            {key: value for key, value in governance.items() if key != "payload_digest"}
        )
        self._write("governance-envelope.json", governance)
        execution = json.loads((self.evidence / "execution-record.json").read_text())
        execution["request_digest"] = governance["request_digest"]
        execution["record_digest"] = _digest_value(
            {key: value for key, value in execution.items() if key != "record_digest"}
        )
        self._write("execution-record.json", execution)
        self._rewrite_semantic_manifest()

        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

    def test_malformed_component_rows_fail_with_a_controlled_error(self):
        # MUTATION: assuming every component row is an object leaks an AttributeError.
        components = json.loads((self.evidence / "components.lock.json").read_text())
        components["components"].append(None)
        self._write("components.lock.json", components)
        self._rewrite_semantic_manifest()

        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

    def test_capability_states_are_truthful(self):
        # MUTATION: candidate evidence must not be described as release-qualified or routed capability.
        Qualification(self.root).promote(self.evidence, "candidate")
        record = self._record()
        self.assertEqual(record["runtime_state"], "activated")
        self.assertEqual(record["qualification_state"], "candidate")
        self.assertNotIn("routed", record.values())

    def test_semantic_evidence_omissions_and_extra_files_fail_closed(self):
        # MUTATION: optional semantic inputs let qualification silently ignore missing evidence.
        (self.evidence / "mission-record.json").unlink()
        with self.assertRaises(QualificationError):
            Qualification(self.root).promote(self.evidence, "candidate")
        self._write_evidence()
        (self.evidence / "uncontrolled.json").write_text("{}\n")
        with self.assertRaises(QualificationError):
            Qualification(self.root).promote(self.evidence, "candidate")

    def test_linked_qualification_state_root_never_receives_a_record(self):
        # MUTATION: lexical state containment writes the promotion through a linked updates root.
        outside = self.base / "outside-updates"
        outside.mkdir()
        try:
            (self.root / "updates").symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(str(error))

        with self.assertRaises(QualificationError):
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(list(outside.iterdir()), [])

    def _replace_binding(self, requirement_id: str, replacement: str):
        requirements = json.loads((self.evidence / "requirements.json").read_text())
        for row in requirements["requirements"]:
            if row["id"] == requirement_id:
                row["test_id"] = replacement
        self._write("requirements.json", requirements)
        matrix = json.loads((self.evidence / "critical-matrix.json").read_text())
        for row in matrix["assertions"]:
            if row["requirement_id"] == requirement_id:
                row["test_id"] = replacement
        self._write("critical-matrix.json", matrix)
        self._rewrite_semantic_manifest()


if __name__ == "__main__":
    unittest.main()
