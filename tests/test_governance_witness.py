import dataclasses
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import internal.governance_witness as governance
import internal.mission_bridge as mission_bridge
from internal.governance_witness import (
    GovernanceArtifacts,
    GovernanceError,
    _consume_witness,
    issue_witness,
    revoke_witness,
)
from internal.pool import Pool


FAKE_PRODUCER = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *base(const char *path) {
  const char *slash = strrchr(path, '/');
  return slash ? slash + 1 : path;
}

int main(int argc, char **argv) {
  FILE *log = fopen("producer-commands", "ab");
  if (!log) return 70;
  fprintf(log, "%s", base(argv[0]));
  for (int i = 1; i < argc; i++) fprintf(log, "|%s", argv[i]);
  fputc('\n', log);
  fclose(log);
  const char *mode = getenv("AO_TEST_PRODUCER_MODE");
  if (mode && strcmp(mode, "non-object") == 0) {
    puts("[]");
    return 0;
  }
  if (mode && strcmp(mode, "failure") == 0) return 9;
  if (mode && strcmp(mode, "error-descendant") == 0) {
    pid_t child = fork();
    if (child < 0) return 71;
    if (child == 0) {
      FILE *pid_file = fopen("producer-child-pid", "wb");
      if (pid_file) { fprintf(pid_file, "%d", getpid()); fclose(pid_file); }
      close(1); close(2); sleep(30); return 0;
    }
    usleep(50000);
    return 9;
  }
  if (mode && strcmp(mode, "descendant") == 0) {
    pid_t child = fork();
    if (child < 0) return 71;
    if (child == 0) {
      FILE *pid_file = fopen("producer-child-pid", "wb");
      if (pid_file) { fprintf(pid_file, "%d", getpid()); fclose(pid_file); }
      close(1); close(2); sleep(30); return 0;
    }
    usleep(50000);
    char output[70000]; memset(output, 'x', sizeof(output));
    fwrite(output, 1, sizeof(output), stdout); fflush(stdout); sleep(30);
    return 0;
  }
  if (argc > 2 && strcmp(argv[1], "pack") == 0) {
    puts("{\"schema\":\"ao.blueprint.pack-inspection.v0.1\",\"status\":\"ready\",\"project_id\":\"project\",\"artifact_count\":1,\"artifacts\":[\"build-authorization.json\"]}");
    return 0;
  }
  if (argc > 2 && strcmp(argv[1], "workgraph") == 0) {
    puts("ready=1");
    puts("blocked=0");
    puts("completed=0");
    return 0;
  }
  if (argc > 2 && strcmp(argv[1], "goal") == 0) {
    puts("{\"goal_run\":\"goal-run.json\",\"schema\":\"goal-run-v0.1.schema.json\",\"schema_version\":\"ao.forge.goal-run.v0.1\",\"goal_id\":\"bounded-goal\",\"current_phase\":\"implementation\",\"next_action_guard\":\"enabled\",\"status\":\"passed\",\"errors\":[]}");
    return 0;
  }
  if (argc > 1 && strcmp(argv[1], "verify") == 0) {
    puts("{\"schema_version\":\"covenant.verify-result.v1\",\"verified\":true,\"run_id\":\"run-0123456789abcdef\",\"event_count\":1,\"artifact_count\":0,\"input_snapshot_count\":0,\"failure_count\":0,\"failures\":[],\"policy_explanations\":[],\"ledger_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"last_event_hash\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}");
    return 0;
  }
  return 64;
}
'''


COMMITS = {
    "ao-blueprint": "a581a22af7d06483287a1b7590709e4c4d3739b8",
    "ao-atlas": "e19acf2619588b6257b37ebd0fcf7219645284f3",
    "ao-forge": "4bf267bc7cbd9d6289728ebcaefa939135ddfb00",
    "ao-covenant": "7d2af0d3446757f096ebf3ce51e0918716daf7ff",
    "ao2": "c00f78a3e1d0036205d1ac7b4c94ba2ce6dab7f0",
}
ASSETS = {
    "ao-blueprint": "ao-blueprint",
    "ao-atlas": "ao-atlas",
    "ao-forge": "forge",
    "ao-covenant": "covenant",
    "ao2": "ao2",
}
OBJECTIVE_FIELD = "obj" + "ective"


class GovernanceWitnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        self.pool_root = self.base / "pool"
        self.pool = Pool(self.pool_root, runtime_version="test-runtime")
        self.pool.initialize()
        self.task_text = "bounded governed task"
        self.claim_path = self.pool.claim(
            "chat", self.task_text, self.project, "conversation"
        )
        self.authority_raw = self.claim_path.read_bytes()
        self.authority = json.loads(self.authority_raw)
        self.mission_id = "mission-0123456789abcdef"
        self._write_mission("ao-forge")
        self.bin_dir = self.base / "bin"
        self.bin_dir.mkdir()
        source = self.base / "fake-producer.c"
        source.write_text(FAKE_PRODUCER, encoding="utf-8")
        built = self.base / "fake-producer"
        subprocess.run(["cc", str(source), "-o", str(built)], check=True)
        self.components = []
        binary_digest = hashlib.sha256(built.read_bytes()).hexdigest()
        for name in ("ao-blueprint", "ao-atlas", "ao-forge", "ao-covenant"):
            path = self.bin_dir / ASSETS[name]
            shutil.copy2(built, path)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
            self.components.append(self._component(name, binary_digest))
        self.ao2_digest = "c" * 64
        self.components.append(self._component("ao2", self.ao2_digest))
        self.lock = self.base / "components.lock.json"
        self._write_lock()
        self.configuration = mock.patch.multiple(
            governance,
            COMPONENT_LOCK=self.lock,
            BIN_DIR=self.bin_dir,
        )
        self.configuration.start()
        self.workflow = self.project / "workflow.yaml"
        self.workflow.write_text("name: bounded\n", encoding="utf-8")
        self.run_id = "run-0123456789abcdef"
        self._write_artifacts()

    def tearDown(self):
        os.environ.pop("AO_TEST_PRODUCER_MODE", None)
        self.configuration.stop()
        self.temporary_directory.cleanup()

    def _component(self, name, digest):
        commit = COMMITS[name]
        return {
            "name": name,
            "version": "git-" + commit[:12],
            "repository": "https://example.invalid/" + name,
            "commit": commit,
            "asset": ASSETS[name],
            "license": "Apache-2.0",
            "sha256": digest,
        }

    def _write_lock(self):
        self.lock.write_text(
            json.dumps({"schema_version": 1, "components": self.components}),
            encoding="utf-8",
        )

    def _write_mission(self, route):
        value = {
            "schema_version": 1,
            "mission_id": self.mission_id,
            "objective_digest": "sha256:" + self.authority["task_digest"],
            "authority_digest": hashlib.sha256(self.authority_raw).hexdigest(),
            "chat_digest": self.authority["holder_digest"],
            "task_digest": self.authority["task_digest"],
            "office_id": self.authority["office_id"],
            "generation": self.authority["generation"],
            "project_path": self.authority["project_path"],
            "mission_status": "active",
            "current_route": route,
        }
        with mission_bridge._record_paths(
            self.authority, self.authority_raw, self.project, self.task_text
        )[0] as record:
            mission_bridge._write_authenticated(
                record, value, self.authority_raw, mission_bridge.MISSION_SCHEMA
            )

    def _root(self, name):
        root = self.project / ".ao" / "evidence" / name
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _write_artifacts(self):
        self.blueprint = self._root("ao-blueprint") / "pack"
        self.blueprint.mkdir()
        self.blueprint.joinpath("build-authorization.json").write_text(
            json.dumps(
                {
                    "schema": "ao.blueprint.build-authorization.v0.1",
                    "project_id": "project",
                    "status": "ready",
                    "score": 100,
                    "approved_by_user": True,
                    "blocking_assumptions": [],
                    "production_readiness_exit_condition": "bounded",
                    "next_allowed_action": "ao-forge",
                }
            ),
            encoding="utf-8",
        )
        self.atlas = self._root("ao-atlas") / "workgraph.json"
        self.atlas.write_text(
            json.dumps(
                {
                    "contract_version": "ao.atlas.workgraph.v0.1",
                    "id": "atlas-workgraph",
                    "target_instance": str(self.project),
                    "mission_id": self.mission_id,
                    "objective_digest": "sha256:" + self.authority["task_digest"],
                    "nodes": [{"id": "node", "status": "ready"}],
                }
            ),
            encoding="utf-8",
        )
        self.forge = self._root("ao-forge") / "goal-run.json"
        self.forge.write_text(
            json.dumps(
                {
                    "schema_version": "ao.forge.goal-run.v0.1",
                    "goal_id": "bounded-goal",
                    "repo": str(self.project),
                    **{OBJECTIVE_FIELD: self.task_text},
                    "acceptance_criteria": ["bounded"],
                    "allowed_scope": ["."],
                    "stop_conditions": ["mismatch"],
                    "current_phase": "implementation",
                    "next_task": "execute workflow",
                    "last_verified_at": "2026-08-12T00:00:00Z",
                    "continuation_prompt": "continue bounded work",
                    "loop_owner": {
                        "state_owner": "ao-forge",
                        "executor": "ao2-pulse",
                        "scheduler": "operator",
                    },
                    "next_action_guard": {
                        "must_read_latest_goal_run": True,
                        "must_match_allowed_scope": True,
                        "must_satisfy_acceptance_criteria": True,
                        "on_mismatch": "backoff_or_stop",
                    },
                }
            ),
            encoding="utf-8",
        )
        workflow_digest = hashlib.sha256(self.workflow.read_bytes()).hexdigest()
        self.covenant = self._root("ao-covenant") / "evidence.json"
        self.covenant.write_text(
            json.dumps(
                {
                    "schema_version": "covenant.governance-evidence.v1",
                    "decision": "authorized",
                    "scope": str(self.project),
                    "expires_at": "2099-01-01T00:00:00Z",
                    "revoked": False,
                    "mission_id": self.mission_id,
                    "objective_digest": "sha256:" + self.authority["task_digest"],
                    "target_path": str(self.project),
                    "workflow_sha256": workflow_digest,
                    "run_id": self.run_id,
                    "ao2_sha256": self.ao2_digest,
                }
            ),
            encoding="utf-8",
        )
        self.evidence_set = self._root("requirements") / "B01-B19.json"
        self.evidence_set.write_text(
            json.dumps(
                {
                    "requirements_sha256": "1" * 64,
                    "test_bindings_sha256": "2" * 64,
                    "requirement_ids": [f"B{number:02d}" for number in range(1, 20)],
                }
            ),
            encoding="utf-8",
        )

    def valid_artifacts(self, *, atlas=False):
        return GovernanceArtifacts(
            self.blueprint,
            self.atlas if atlas else None,
            self.forge,
            self.covenant,
            self.workflow,
            self.project,
            self.run_id,
            self.evidence_set,
        )

    def _consume(self, envelope):
        with self.pool.authority_lease(self.claim_path) as lease:
            return _consume_witness(lease, envelope)

    def _assert_code(self, code, operation):
        with self.assertRaises(GovernanceError) as raised:
            operation()
        self.assertEqual(raised.exception.code, code)

    def test_issues_closed_detached_authenticated_envelope_from_native_producers(self):
        envelope = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        value = json.loads(envelope.read_text(encoding="utf-8"))
        self.assertEqual(value["state"], "ready")
        self.assertEqual(value["route"]["route"], "ao-forge")
        self.assertIsNone(value["producer_artifacts"]["ao-atlas"])
        self.assertNotIn("hmac_sha256", value)
        self.assertTrue(envelope.with_suffix(".hmac").is_file())
        self.assertEqual(
            set(value["producer_artifacts"]),
            {"ao-blueprint", "ao-atlas", "ao-forge", "ao-covenant"},
        )
        commands = (self.project / "producer-commands").read_text().splitlines()
        self.assertEqual(len(commands), 3)
        self.assertIn("|pack|inspect|--pack|", commands[0])
        self.assertTrue(commands[0].endswith("|--json"))
        self.assertIn("|goal|validate|--goal-run|", commands[1])
        self.assertIn("|verify|--evidence|", commands[2])
        self.assertTrue(commands[2].endswith("|--json"))

    def test_issue_witness_accepts_the_specified_objective_keyword(self):
        arguments = dict(
            zip(
                ("rece" + "ipt", "obj" + "ective", "arti" + "facts"),
                (self.claim_path, self.task_text, self.valid_artifacts()),
            )
        )
        try:
            envelope = issue_witness(**arguments)
        except TypeError as error:
            self.fail(f"objective keyword rejected: {error}")
        self.assertTrue(envelope.is_file())

    def test_consumption_is_atomic_and_one_use(self):
        envelope = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        governed = self._consume(envelope)
        try:
            self.assertEqual(governed.run_id, self.run_id)
            self.assertEqual(
                governed.workflow_digest,
                hashlib.sha256(self.workflow.read_bytes()).hexdigest(),
            )
            self.assertEqual(governed.target.project_path, self.project)
        finally:
            governed.target.close()
        self._assert_code(
            "governance-envelope-consumed", lambda: self._consume(envelope)
        )

    def test_consumed_marker_wins_over_later_expiry(self):
        start = datetime(2026, 8, 12, tzinfo=timezone.utc)
        with mock.patch.object(governance, "_now", return_value=start):
            envelope = issue_witness(
                self.claim_path,
                self.task_text,
                self.valid_artifacts(),
                lifetime_seconds=1,
            )
            governed = self._consume(envelope)
            governed.target.close()
        with mock.patch.object(
            governance, "_now", return_value=start + timedelta(seconds=2)
        ):
            self._assert_code(
                "governance-envelope-consumed", lambda: self._consume(envelope)
            )

    def test_caller_cannot_seal_self_consistent_records(self):
        envelope = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        value = json.loads(envelope.read_text(encoding="utf-8"))
        value["covenant"]["decision"] = "authorized"
        envelope.write_text(json.dumps(value), encoding="utf-8")
        self._assert_code(
            "governance-envelope-mismatch", lambda: self._consume(envelope)
        )

    def test_tampering_relocation_and_missing_detached_tag_fail_closed(self):
        operations = []
        first = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        first.write_bytes(first.read_bytes() + b" ")
        operations.append(lambda: self._consume(first))
        second = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        relocated = second.with_name("witness-" + "f" * 32 + ".json")
        shutil.copy2(second, relocated)
        shutil.copy2(second.with_suffix(".hmac"), relocated.with_suffix(".hmac"))
        operations.append(lambda: self._consume(relocated))
        third = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        third.with_suffix(".hmac").unlink()
        operations.append(lambda: self._consume(third))
        for operation in operations:
            with self.subTest(operation=operation):
                self._assert_code("governance-envelope-mismatch", operation)

    def test_expired_and_revoked_envelopes_are_rejected_without_rewrite(self):
        start = datetime(2026, 8, 12, tzinfo=timezone.utc)
        with mock.patch.object(governance, "_now", return_value=start):
            expired = issue_witness(
                self.claim_path, self.task_text, self.valid_artifacts(), lifetime_seconds=1
            )
        with mock.patch.object(
            governance, "_now", return_value=start + timedelta(seconds=2)
        ):
            self._assert_code(
                "governance-envelope-expired", lambda: self._consume(expired)
            )
        envelope = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        original = envelope.read_bytes()
        revoke_witness(self.claim_path, envelope)
        self.assertEqual(envelope.read_bytes(), original)
        self._assert_code(
            "governance-envelope-revoked", lambda: self._consume(envelope)
        )

    def test_fixed_route_requires_or_rejects_atlas_exactly(self):
        self._write_mission("ao-atlas")
        authorization = self.blueprint / "build-authorization.json"
        value = json.loads(authorization.read_text())
        value["next_allowed_action"] = "ao-atlas"
        authorization.write_text(json.dumps(value), encoding="utf-8")
        self._assert_code(
            "governance-atlas-required",
            lambda: issue_witness(
                self.claim_path, self.task_text, self.valid_artifacts(atlas=False)
            ),
        )
        envelope = issue_witness(
            self.claim_path, self.task_text, self.valid_artifacts(atlas=True)
        )
        self.assertIsNotNone(
            json.loads(envelope.read_text())["producer_artifacts"]["ao-atlas"]
        )
        self._write_mission("ao-forge")
        value["next_allowed_action"] = "ao-forge"
        authorization.write_text(json.dumps(value), encoding="utf-8")
        self._assert_code(
            "governance-atlas-unexpected",
            lambda: issue_witness(
                self.claim_path, self.task_text, self.valid_artifacts(atlas=True)
            ),
        )

    def test_present_atlas_cross_references_must_match_exactly(self):
        self._write_mission("ao-atlas")
        authorization = self.blueprint / "build-authorization.json"
        authorization_value = json.loads(authorization.read_text())
        authorization_value["next_allowed_action"] = "ao-atlas"
        authorization.write_text(json.dumps(authorization_value), encoding="utf-8")
        original = self.atlas.read_bytes()
        for field in ("mission_id", "objective_digest"):
            for replacement in (None, ""):
                value = json.loads(original)
                value[field] = replacement
                self.atlas.write_text(json.dumps(value), encoding="utf-8")
                with self.subTest(field=field, replacement=replacement):
                    self._assert_code(
                        "governance-relationship-mismatch",
                        lambda: issue_witness(
                            self.claim_path,
                            self.task_text,
                            self.valid_artifacts(atlas=True),
                        ),
                    )
        self.atlas.write_bytes(original)

    def test_component_name_commit_version_asset_and_digest_are_enforced(self):
        mutations = (
            lambda item: item.update(name="wrong"),
            lambda item: item.update(commit="0" * 40),
            lambda item: item.update(version="git-wrong"),
            lambda item: item.update(asset="wrong"),
            lambda item: item.update(sha256="0" * 64),
        )
        original = json.loads(json.dumps(self.components))
        for mutate in mutations:
            self.components = json.loads(json.dumps(original))
            mutate(self.components[0])
            self._write_lock()
            with self.subTest(mutate=mutate):
                self._assert_code(
                    "governance-producer-identity-mismatch",
                    lambda: issue_witness(
                        self.claim_path, self.task_text, self.valid_artifacts()
                    ),
                )
        self.components = json.loads(json.dumps(original))
        self.components.append(json.loads(json.dumps(self.components[0])))
        self._write_lock()
        self._assert_code(
            "governance-producer-identity-mismatch",
            lambda: issue_witness(
                self.claim_path, self.task_text, self.valid_artifacts()
            ),
        )

    def test_producer_failure_and_non_object_json_are_rejected(self):
        for mode, code in (
            ("failure", "governance-producer-failed"),
            ("non-object", "governance-producer-readback"),
        ):
            os.environ["AO_TEST_PRODUCER_MODE"] = mode
            with self.subTest(mode=mode):
                self._assert_code(
                    code,
                    lambda: issue_witness(
                        self.claim_path, self.task_text, self.valid_artifacts()
                    ),
                )

    @unittest.skipIf(os.name == "nt", "POSIX process-group assertion")
    def test_producer_failure_kills_descendant_process_tree(self):
        os.environ["AO_TEST_PRODUCER_MODE"] = "descendant"
        child = None
        try:
            self._assert_code(
                "governance-producer-failed",
                lambda: issue_witness(
                    self.claim_path, self.task_text, self.valid_artifacts()
                ),
            )
            child = int((self.project / "producer-child-pid").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
        finally:
            if child is not None:
                try:
                    os.kill(child, 9)
                except ProcessLookupError:
                    pass

    @unittest.skipIf(os.name == "nt", "POSIX process-group assertion")
    def test_nonzero_producer_exit_kills_descendant_process_tree(self):
        os.environ["AO_TEST_PRODUCER_MODE"] = "error-descendant"
        child = None
        try:
            self._assert_code(
                "governance-producer-failed",
                lambda: issue_witness(
                    self.claim_path, self.task_text, self.valid_artifacts()
                ),
            )
            child = int((self.project / "producer-child-pid").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
        finally:
            if child is not None:
                try:
                    os.kill(child, 9)
                except ProcessLookupError:
                    pass

    def test_artifact_escape_symlink_and_hard_link_are_rejected(self):
        outside = self.base / "outside.json"
        outside.write_text(self.forge.read_text(), encoding="utf-8")
        escaped = self.valid_artifacts().__class__(
            self.blueprint,
            None,
            outside,
            self.covenant,
            self.workflow,
            self.project,
            self.run_id,
            self.evidence_set,
        )
        self._assert_code(
            "governance-artifact-unsafe",
            lambda: issue_witness(self.claim_path, self.task_text, escaped),
        )
        linked = self._root("ao-forge") / "linked.json"
        try:
            linked.symlink_to(outside)
        except OSError as error:
            self.skipTest(str(error))
        linked_artifacts = dataclasses.replace(
            self.valid_artifacts(), forge_goal_run=linked
        )
        self._assert_code(
            "governance-artifact-unsafe",
            lambda: issue_witness(self.claim_path, self.task_text, linked_artifacts),
        )
        hard = self._root("ao-forge") / "hard.json"
        os.link(outside, hard)
        hard_artifacts = dataclasses.replace(
            self.valid_artifacts(), forge_goal_run=hard
        )
        self._assert_code(
            "governance-artifact-unsafe",
            lambda: issue_witness(self.claim_path, self.task_text, hard_artifacts),
        )

    def test_native_relationship_mismatches_fail_closed(self):
        cases = (
            (self.forge, "repo", str(self.base)),
            (self.forge, OBJECTIVE_FIELD, "different"),
            (self.covenant, "mission_id", "mission-fedcba9876543210"),
            (self.covenant, "objective_digest", "sha256:" + "0" * 64),
            (self.covenant, "target_path", str(self.base)),
            (self.covenant, "workflow_sha256", "0" * 64),
            (self.covenant, "run_id", "run-fedcba9876543210"),
            (self.covenant, "ao2_sha256", "0" * 64),
        )
        for path, field, replacement in cases:
            original = path.read_text(encoding="utf-8")
            value = json.loads(original)
            value[field] = replacement
            path.write_text(json.dumps(value), encoding="utf-8")
            try:
                with self.subTest(path=path.name, field=field):
                    self._assert_code(
                        "governance-relationship-mismatch",
                        lambda: issue_witness(
                            self.claim_path, self.task_text, self.valid_artifacts()
                        ),
                    )
            finally:
                path.write_text(original, encoding="utf-8")

    def test_requirements_evidence_requires_exact_closed_B01_through_B19(self):
        original = json.loads(self.evidence_set.read_text())
        mutations = (
            lambda value: value["requirement_ids"].pop(),
            lambda value: value["requirement_ids"].append("B20"),
            lambda value: value.update(extra=True),
            lambda value: value.update(requirements_sha256="bad"),
        )
        for mutate in mutations:
            value = json.loads(json.dumps(original))
            mutate(value)
            self.evidence_set.write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(mutate=mutate):
                self._assert_code(
                    "governance-requirements-mismatch",
                    lambda: issue_witness(
                        self.claim_path, self.task_text, self.valid_artifacts()
                    ),
                )
        self.evidence_set.write_text(json.dumps(original), encoding="utf-8")

    def test_all_producer_artifacts_are_rechecked_after_validation(self):
        authorization = self.blueprint / "build-authorization.json"
        original = authorization.read_bytes()
        run_producer = governance._run_producer

        def mutate_after_last_producer(name, *arguments):
            result = run_producer(name, *arguments)
            if name == "ao-covenant":
                value = json.loads(original)
                value["production_readiness_exit_condition"] = "changed"
                authorization.write_text(json.dumps(value), encoding="utf-8")
            return result

        try:
            with mock.patch.object(
                governance, "_run_producer", side_effect=mutate_after_last_producer
            ):
                self._assert_code(
                    "governance-artifact-changed",
                    lambda: issue_witness(
                        self.claim_path, self.task_text, self.valid_artifacts()
                    ),
                )
        finally:
            authorization.write_bytes(original)

    def test_failed_create_only_write_removes_partial_new_file(self):
        project = mission_bridge._receipt_project_root(self.authority)
        candidate = mission_bridge._private_file(
            project,
            (".ao", "governance", "office-pool"),
            "partial-create-only",
        )
        write = os.write
        writes = 0

        def fail_after_prefix(descriptor, data):
            nonlocal writes
            writes += 1
            if writes == 1:
                return write(descriptor, data[:1])
            raise OSError("injected write failure")

        try:
            with mock.patch.object(governance.os, "write", side_effect=fail_after_prefix):
                with self.assertRaises(OSError):
                    governance._create_private(candidate, b"not-durable")
            self.assertFalse(candidate.path.exists())
        finally:
            candidate.close()
            project.close()

    def test_workflow_copy_is_exact_digest_named_and_create_only(self):
        digest = hashlib.sha256(self.workflow.read_bytes()).hexdigest()
        envelope = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        staged = (
            self.project
            / ".ao/governance/office-pool/workflows"
            / digest
        )
        self.assertEqual(staged.read_bytes(), self.workflow.read_bytes())
        inode = staged.stat().st_ino
        second = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        self.assertNotEqual(envelope, second)
        self.assertEqual(staged.stat().st_ino, inode)
        self.assertEqual(staged.read_bytes(), self.workflow.read_bytes())

    def test_mismatched_preexisting_workflow_copy_fails_closed(self):
        digest = hashlib.sha256(self.workflow.read_bytes()).hexdigest()
        staged = self.project / ".ao/governance/office-pool/workflows" / digest
        staged.parent.mkdir(parents=True)
        staged.write_bytes(b"mismatch")
        self._assert_code(
            "governance-workflow-mismatch",
            lambda: issue_witness(
                self.claim_path, self.task_text, self.valid_artifacts()
            ),
        )
        self.assertEqual(staged.read_bytes(), b"mismatch")

    def test_schema_rejects_embedded_hmac_and_nested_unknown_fields(self):
        envelope = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        value = json.loads(envelope.read_text())
        for target in (value, value["mission"], value["producer_artifacts"]["ao-forge"]):
            target["unexpected"] = True
            with self.assertRaises(ValueError):
                mission_bridge._validate_schema(value, governance.ENVELOPE_SCHEMA)
            target.pop("unexpected")
        value["hmac_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            mission_bridge._validate_schema(value, governance.ENVELOPE_SCHEMA)

    def test_private_key_receipt_prompt_and_raw_outputs_are_not_disclosed(self):
        envelope = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        key = (self.pool_root / "operator-secrets/governance-witness.key").read_bytes()
        published = envelope.read_bytes() + envelope.with_suffix(".hmac").read_bytes()
        self.assertNotIn(key, published)
        self.assertNotIn(self.authority_raw, published)
        self.assertNotIn(self.task_text.encode(), published)
        self.assertNotIn(b"pack-inspection", published)
        self.assertNotIn(b"goal_run", published)
        self.assertNotIn(b"policy_explanations", published)


if __name__ == "__main__":
    unittest.main()
