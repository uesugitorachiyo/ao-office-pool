import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from internal import qualification as qualification_module
from internal.execution import execute
from internal.governance_witness import issue_witness
from internal.pool import OFFICE_IDS, Pool
from internal.qualification import Qualification, QualificationError
from scripts.build_release import build_release
from tests import test_execution as execution_tests


def _canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest_value(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class QualificationTests(unittest.TestCase):
    @staticmethod
    def _release_contract_module():
        try:
            return importlib.import_module("scripts.verify_release_contract")
        except ModuleNotFoundError as error:
            raise AssertionError("release contract verifier is missing") from error

    def setUp(self):
        self.execution_fixture = execution_tests.ExecutionTests(
            "test_executes_only_envelope_bound_objects_and_relative_target"
        )
        self.execution_fixture.setUp()
        self.addCleanup(self.execution_fixture.doCleanups)
        self.harness = self.execution_fixture.harness
        self.base = self.execution_fixture.base
        self.root = self.harness.pool_root
        self.pool = self.harness.pool
        self.project = self.execution_fixture.project
        self.claim_path = self.execution_fixture.claim_path
        component = self._component()
        old_runtime = self.execution_fixture.executable.parent
        new_runtime = old_runtime.with_name(component["version"])
        old_runtime.rename(new_runtime)
        self.execution_fixture.executable = new_runtime / self.execution_fixture.executable.name
        self.pool.runtime_version = component["version"]
        (self.root / "pool.json").write_bytes(
            _canonical(
                {
                    "schema_version": 1,
                    "office_count": 5,
                    "offices": list(OFFICE_IDS),
                    "runtime_version": component["version"],
                }
            )
        )
        self.harness._write_mission("ao-foundry")
        self.envelope_path = issue_witness(
            self.claim_path,
            self.harness.task_text,
            self.harness.valid_artifacts(atlas=True),
        )
        result = execute(self.claim_path, self.envelope_path)
        self.execution_path = result.record
        self.runtime_bytes = self.execution_fixture.executable.read_bytes()
        self.runtime_sha256 = hashlib.sha256(self.runtime_bytes).hexdigest()
        for office_id in OFFICE_IDS:
            path = self.root / "offices" / office_id / "runtime" / "versions" / component["version"] / ("ao2.exe" if os.name == "nt" else "ao2")
            path.parent.mkdir(parents=True, exist_ok=True)
            if path != self.execution_fixture.executable:
                shutil.copy2(self.execution_fixture.executable, path)
        installed_lock = self.root / "manifests" / "components.lock.json"
        installed_lock.parent.mkdir(parents=True)
        installed_lock.write_bytes(self.harness.lock.read_bytes())
        self.authority = json.loads(self.claim_path.read_bytes())
        self.mission_path = next(
            (self.project / ".ao" / "mission" / "office-pool").glob("*.json")
        )
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        self._write_evidence()

    def _write(self, name: str, value: dict) -> bytes:
        raw = _canonical(value)
        (self.evidence / name).write_bytes(raw)
        return raw

    def _component(self):
        return next(
            component
            for component in self.harness.components
            if component["name"] == "ao2"
        )

    def _write_evidence(self):
        component = self._component()
        runtime = {
            "schema_version": 1,
            "name": "ao2",
            "version": component["version"],
            "commit": component["commit"],
            "asset": component["asset"],
            "sha256": self.runtime_sha256,
        }
        source_requirements = Path(__file__).parents[1] / "manifests" / "requirements.json"
        requirements_raw = source_requirements.read_bytes()
        requirements = json.loads(requirements_raw)
        blocker_rows = [row for row in requirements["requirements"] if row["id"].startswith("B")]
        matrix = {
            "schema_version": 1,
            "assertions": [{"requirement_id": row["id"], "test_id": row["test_id"]} for row in blocker_rows],
        }
        sources = {
            "runtime-package.json": _canonical(runtime),
            "components.lock.json": self.harness.lock.read_bytes(),
            "claim-receipt.json": self.claim_path.read_bytes(),
            "mission-record.json": self.mission_path.read_bytes(),
            "governance-envelope.json": self.envelope_path.read_bytes(),
            "execution-record.json": self.execution_path.read_bytes(),
            "requirements.json": requirements_raw,
            "critical-matrix.json": _canonical(matrix),
        }
        fingerprints = []
        for name, raw in sources.items():
            (self.evidence / name).write_bytes(raw)
            fingerprints.append({"name": name, "sha256": hashlib.sha256(raw).hexdigest()})
        self._write("semantic-inputs.json", {"schema_version": 1, "inputs": fingerprints})

    def _rewrite_semantic_manifest(self):
        inputs = []
        for path in sorted(self.evidence.glob("*.json")):
            if path.name == "semantic-inputs.json":
                continue
            inputs.append({"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        self._write("semantic-inputs.json", {"schema_version": 1, "inputs": inputs})

    def _record(self):
        return json.loads((self.root / "updates" / "qualification.json").read_text(encoding="utf-8"))

    def _governance_marker(self, kind: str) -> Path:
        governance = json.loads(self.envelope_path.read_bytes())
        authority_digest = hashlib.sha256(self.claim_path.read_bytes()).hexdigest()
        return (
            self.root
            / "runtime"
            / "governance"
            / kind
            / f"{authority_digest}-{governance['witness_id']}"
        )

    def test_exact_qualification_binding_promotes_candidate(self):
        # MUTATION: omitting one cross-record identity accepts unrelated execution evidence.
        record_path = Qualification(self.root).promote(self.evidence, "candidate")
        record = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(record["qualification_state"], "candidate")
        self.assertEqual(record["runtime_version"], self._component()["version"])
        self.assertEqual(record["runtime_sha256"], self.runtime_sha256)
        self.assertEqual(record["mission_id"], "mission-0123456789abcdef")
        self.assertEqual(
            record["witness_id"],
            json.loads(self.envelope_path.read_bytes())["witness_id"],
        )
        self.assertEqual(
            record["execution_id"],
            json.loads(self.execution_path.read_bytes())["execution_id"],
        )
        self.assertEqual(record["assertion_count"], 19)
        self.assertNotIn(str(self.project), json.dumps(record))

    def test_detached_invented_task_six_artifacts_cannot_qualify(self):
        # MUTATION: self-consistent copied JSON must not replace a live Pool authority.
        self.pool.release(self.claim_path)

        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

    def test_missing_live_mission_authentication_cannot_qualify(self):
        # MUTATION: parsing the copied Mission record ignores its live detached HMAC.
        self.mission_path.with_suffix(".hmac").unlink()

        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

    def test_forged_live_mission_authentication_cannot_qualify(self):
        # MUTATION: trusting Mission fields accepts a record rejected by its authority HMAC.
        self.mission_path.with_suffix(".hmac").write_bytes(b"f" * 64 + b"\n")

        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

    def test_missing_live_governance_authentication_cannot_qualify(self):
        # MUTATION: copied envelope JSON is not proof that Pool authenticated its issuance.
        self.envelope_path.with_suffix(".hmac").unlink()

        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

    def test_forged_live_governance_authentication_cannot_qualify(self):
        # MUTATION: the unkeyed payload digest cannot substitute for the detached HMAC.
        self.envelope_path.with_suffix(".hmac").write_bytes(b"f" * 64 + b"\n")

        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

    def test_missing_pool_governance_issuance_cannot_qualify(self):
        # MUTATION: a detached HMAC copied beside an envelope is not Pool issuance.
        self._governance_marker("issued").unlink()

        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

    def test_consumption_without_pool_execution_completion_cannot_qualify(self):
        # MUTATION: one-use consumption proves an attempt, not accepted completion.
        self._governance_marker("consumed").write_bytes(b"1\n")

        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

    def test_failed_execution_record_cannot_qualify(self):
        # MUTATION: schema validity and cross-record digests do not imply accepted execution.
        execution_path = self.evidence / "execution-record.json"
        execution = json.loads(execution_path.read_bytes())
        execution.update(
            {
                "phase": "failed",
                "diagnostics": {},
                "exit_code": None,
                "failure_code": "execution-failed",
            }
        )
        execution["record_digest"] = _digest_value(
            {name: value for name, value in execution.items() if name != "record_digest"}
        )
        self._write("execution-record.json", execution)
        self._rewrite_semantic_manifest()

        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

    def test_nonreleased_producer_identity_cannot_qualify(self):
        # MUTATION: internally consistent producer claims do not override released pins.
        governance_path = self.evidence / "governance-envelope.json"
        governance = json.loads(governance_path.read_bytes())
        governance["producer_artifacts"]["ao-blueprint"]["commit"] = "f" * 40
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
            {name: value for name, value in governance.items() if name != "payload_digest"}
        )
        self._write("governance-envelope.json", governance)
        execution = json.loads((self.evidence / "execution-record.json").read_bytes())
        execution["request_digest"] = governance["request_digest"]
        execution["record_digest"] = _digest_value(
            {name: value for name, value in execution.items() if name != "record_digest"}
        )
        self._write("execution-record.json", execution)
        self._rewrite_semantic_manifest()

        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

    def test_installed_lock_drift_after_capture_rejects_promotion(self):
        # MUTATION: trusting only the captured installed lock promotes after
        # the live component authority has changed.
        qualification = Qualification(self.root)
        capture = qualification._evidence

        def capture_then_replace(evidence_set):
            snapshot = capture(evidence_set)
            (self.root / "manifests/components.lock.json").write_text(
                "{}\n", encoding="utf-8"
            )
            return snapshot

        with mock.patch.object(
            qualification,
            "_evidence",
            side_effect=capture_then_replace,
        ):
            with self.assertRaises(QualificationError) as raised:
                qualification.promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")
        self.assertFalse(qualification._record_path.exists())

    def test_evidence_capture_occurs_while_pool_lock_is_held(self):
        # MUTATION: pre-lock capture permits an activation or rollback to split authority.
        qualification = Qualification(self.root)
        capture = qualification._evidence
        locked = False
        pool_locked = Pool._locked

        @contextmanager
        def tracked_lock(pool, *args, **kwargs):
            nonlocal locked
            with pool_locked(pool, *args, **kwargs):
                locked = True
                try:
                    yield
                finally:
                    locked = False

        def require_lock(evidence_set):
            self.assertTrue(locked)
            return capture(evidence_set)

        with (
            mock.patch.object(Pool, "_locked", tracked_lock),
            mock.patch.object(
                qualification,
                "_evidence",
                side_effect=require_lock,
            ),
        ):
            record = qualification.promote(self.evidence, "candidate")

        self.assertTrue(record.is_file())

    def test_windows_evidence_root_reparse_ancestors_fail_closed(self):
        # MUTATION: a resolved evidence root can still traverse a Windows junction.
        qualification = Qualification(self.root)
        member_names = tuple(sorted({*qualification_module._INPUTS, "semantic-inputs.json"}))
        paths = (self.evidence, *(self.evidence / name for name in member_names))
        identities = {path: object() for path in paths}
        with (
            mock.patch("internal.qualification.os.name", "nt"),
            mock.patch(
                "internal.qualification.open_identity",
                side_effect=lambda path: identities[path],
                create=True,
            ) as opened,
            mock.patch("internal.qualification.require_within", create=True) as contained,
        ):
            values, _, _, _ = qualification._evidence(self.evidence)
        self.assertEqual(values["runtime-package.json"]["name"], "ao2")
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

        identity = object()
        with (
            mock.patch("internal.qualification.os.name", "nt"),
            mock.patch(
                "internal.qualification.open_identity", return_value=identity, create=True
            ),
            mock.patch(
                "internal.qualification.require_within",
                side_effect=ValueError("reparse-point ancestor"),
                create=True,
            ),
        ):
            with self.assertRaises(QualificationError) as raised:
                qualification._evidence(self.evidence)

        self.assertEqual(
            raised.exception.code, "qualification-evidence-set-mismatch"
        )

    def test_windows_semantic_manifest_replacement_after_read_fails_closed(self):
        # MUTATION: entry-only evidence containment accepts a semantic manifest
        # replaced after its identity was captured.
        qualification = Qualification(self.root)
        member_names = tuple(sorted({*qualification_module._INPUTS, "semantic-inputs.json"}))
        paths = (self.evidence, *(self.evidence / name for name in member_names))
        identities = {path: object() for path in paths}
        semantic = self.evidence / "semantic-inputs.json"
        semantic_checks = 0

        def reject_replaced_semantic(child, _root):
            nonlocal semantic_checks
            if child is identities[semantic]:
                semantic_checks += 1
                if semantic_checks == 2:
                    raise ValueError("semantic manifest identity changed")

        with (
            mock.patch("internal.qualification.os.name", "nt"),
            mock.patch(
                "internal.qualification.open_identity",
                side_effect=lambda path: identities[path],
            ),
            mock.patch(
                "internal.qualification.require_within",
                side_effect=reject_replaced_semantic,
            ),
        ):
            with self.assertRaises(QualificationError) as raised:
                qualification._evidence(self.evidence)

        self.assertEqual(
            raised.exception.code, "qualification-evidence-set-mismatch"
        )

    def test_source_ast_names_are_not_qualification_authority(self):
        # MUTATION: authenticated Task 6 bindings must not depend on later source parsing.
        with mock.patch("ast.parse", side_effect=SyntaxError("source unavailable")):
            record = Qualification(self.root).promote(self.evidence, "candidate")

        self.assertTrue(record.is_file())

    def test_every_released_component_row_is_authoritative(self):
        # MUTATION: checking only AO2 lets a producer row drift from Task 6 authority.
        evidence_lock = json.loads(
            (self.evidence / "components.lock.json").read_bytes()
        )
        installed_lock = json.loads(
            (self.root / "manifests/components.lock.json").read_bytes()
        )
        for value in (evidence_lock, installed_lock):
            producer = next(
                row for row in value["components"] if row["name"] == "ao-blueprint"
            )
            producer["commit"] = "f" * 40
        self._write("components.lock.json", evidence_lock)
        (self.root / "manifests/components.lock.json").write_bytes(
            _canonical(installed_lock)
        )
        self._rewrite_semantic_manifest()

        with self.assertRaises(QualificationError) as raised:
            Qualification(self.root).promote(self.evidence, "candidate")

        self.assertEqual(raised.exception.code, "qualification-identity-mismatch")

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
        # MUTATION: a token-only gate permits unreadable physical-line compression.
        verifier = self._release_contract_module()
        repository = Path(__file__).parents[1]
        metrics = verifier.verify_instruction_contract(repository)
        root_metrics = metrics["AGENTS.md"]
        self.assertLessEqual(root_metrics["lines"], 200)
        self.assertLessEqual(root_metrics["words"], 2000)
        self.assertLessEqual(root_metrics["max_line"], 100)

        original = (repository / "AGENTS.md").read_text(encoding="utf-8")
        lines = original.splitlines()
        violations = {
            "physical-lines": "\n".join(lines + [""] * (201 - len(lines))) + "\n",
            "word-count": original + (("word " * 19 + "word\n") * 100),
            "line-length": original + ("x" * 101 + "\n"),
        }
        for name, content in violations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                sample = Path(directory)
                (sample / "AGENTS.md").write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    verifier.verify_instruction_contract(sample)

    def test_root_authority_order(self):
        # MUTATION: allowing a descendant to override root authority weakens
        # repository-wide privacy and verification rules.
        verifier = self._release_contract_module()
        repository = Path(__file__).parents[1]
        verifier.verify_instruction_contract(repository)

        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory)
            shutil.copy2(repository / "AGENTS.md", sample / "AGENTS.md")
            leaf = sample / "internal" / "AGENTS.md"
            leaf.parent.mkdir()
            leaf.write_text(
                "# Internal scope\n\n"
                "Authority: inherit-root\n"
                "Descendants: narrow-only\n\n"
                "- Require focused internal tests.\n",
                encoding="utf-8",
            )
            verifier.verify_instruction_contract(sample)
            leaf.write_text(
                "# Internal scope\n\n"
                "Authority: override-root\n"
                "Descendants: may-weaken\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                verifier.verify_instruction_contract(sample)

    def test_specifications_bind_real_code_and_tests(self):
        # MUTATION: naming an abstract builder without executing the release
        # surface lets the specification drift from the produced archive.
        verifier = self._release_contract_module()
        repository = Path(__file__).parents[1]
        contract = verifier.verify_release_contract(repository)
        self.assertEqual(
            contract["surfaces"]["manifest_builder"],
            "scripts.build_release.build_release",
        )
        self.assertEqual(
            contract["surfaces"]["builder_tests"],
            "tests.test_release_tree.BuildReleaseTests",
        )

        with tempfile.TemporaryDirectory(
            dir=Path(tempfile.gettempdir()).resolve()
        ) as directory:
            workspace = Path(directory)
            source = workspace / "source"
            (source / "scripts").mkdir(parents=True)
            (source / "tests").mkdir()
            shutil.copy2(repository / "AGENTS.md", source / "AGENTS.md")
            shutil.copy2(
                repository / "scripts" / "build_release.py",
                source / "scripts" / "build_release.py",
            )
            shutil.copy2(
                repository / "tests" / "test_release_tree.py",
                source / "tests" / "test_release_tree.py",
            )
            allowlist = workspace / "public-tree.json"
            allowlist.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "tracked_root_files": ["AGENTS.md"],
                        "tracked_roots": ["scripts", "tests"],
                        "excluded_roots": [],
                        "excluded_names": [],
                        "excluded_patterns": [],
                    }
                ),
                encoding="utf-8",
            )
            archive_path = workspace / "release.zip"
            build_release(source, archive_path, allowlist)
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(
                    archive.namelist(),
                    [
                        "AGENTS.md",
                        "scripts/build_release.py",
                        "tests/test_release_tree.py",
                    ],
                )

    def test_acceptance_rows_bind_existing_modules(self):
        # MUTATION: validating dotted syntax alone accepts missing methods or
        # extra blocker rows that never execute.
        verifier = self._release_contract_module()
        contract = verifier.verify_release_contract(Path(__file__).parents[1])
        blockers = tuple(f"B{number:02d}" for number in range(1, 20))
        self.assertEqual(contract["blockers"], blockers)
        self.assertEqual(len(contract["test_ids"]), 19)
        self.assertEqual(len(set(contract["test_ids"])), 19)
        self.assertTrue(all(contract["callable_tests"].values()))
        command = subprocess.run(
            [
                sys.executable,
                str(
                    Path(__file__).parents[1]
                    / "scripts"
                    / "verify_release_contract.py"
                ),
            ],
            cwd=Path(__file__).parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(command.returncode, 0, command.stderr)
        self.assertEqual(
            tuple(json.loads(command.stdout)["blockers"]), blockers
        )

    def test_lifecycle_authorities_agree(self):
        # MUTATION: architecture that omits the verifier, runtime finalizer, or
        # qualification lifecycle can accept evidence for another runtime.
        verifier = self._release_contract_module()
        contract = verifier.verify_release_contract(Path(__file__).parents[1])
        self.assertEqual(
            contract["surfaces"]["contract_verifier"],
            "scripts.verify_release_contract.verify_release_contract",
        )
        self.assertEqual(
            contract["surfaces"]["runtime_finalizer"],
            "internal.runtime_update.RuntimeUpdate",
        )
        self.assertEqual(
            contract["surfaces"]["qualification_lifecycle"],
            "internal.qualification.Qualification",
        )

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
