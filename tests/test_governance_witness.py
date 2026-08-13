import dataclasses
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import time
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
from internal.pool import AuthorityLease, Pool, PoolError
from tests.windows_crt import windows_text_mode


TEST_FORGE_SCHEMA = b"test-forge-goal-run-schema\n"


FAKE_PRODUCER = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *base(const char *path) {
  const char *slash = strrchr(path, '/');
  const char *backslash = strrchr(path, '\\');
  if (!slash || (backslash && backslash > slash)) slash = backslash;
  return slash ? slash + 1 : path;
}

static int valid_forge_schema(void) {
  const char expected[] = "test-forge-goal-run-schema\n";
  char buffer[sizeof(expected)] = {0};
  FILE *schema = fopen("docs/contracts/goal-run-v0.1.schema.json", "rb");
  if (!schema) return 0;
  size_t count = fread(buffer, 1, sizeof(buffer), schema);
  int trailing = fgetc(schema);
  fclose(schema);
  return count == sizeof(expected) - 1
    && trailing == EOF
    && memcmp(buffer, expected, sizeof(expected) - 1) == 0;
}

int main(int argc, char **argv) {
  FILE *log = fopen("producer-commands", "ab");
  if (!log) return 70;
  fprintf(log, "%s", base(argv[0]));
  for (int i = 1; i < argc; i++) fprintf(log, "|%s", argv[i]);
  fputc('\n', log);
  fclose(log);
  char mode_buffer[64] = {0};
  FILE *mode_file = fopen("producer-mode", "rb");
  if (mode_file) { fscanf(mode_file, "%63s", mode_buffer); fclose(mode_file); }
  const char *mode = mode_buffer[0] ? mode_buffer : NULL;
  FILE *environment = fopen("producer-environment", "ab");
  if (environment) {
    fprintf(environment, "DYLD=%s LD=%s PYTHON=%s TEST=%s\n",
      getenv("DYLD_INSERT_LIBRARIES") ? "set" : "unset",
      getenv("LD_PRELOAD") ? "set" : "unset",
      getenv("PYTHONPATH") ? "set" : "unset",
      getenv("AO_TEST_PRODUCER_MODE") ? "set" : "unset");
    fclose(environment);
  }
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
  if (mode && (strcmp(mode, "descendant") == 0 || strcmp(mode, "success-descendant") == 0)) {
    pid_t child = fork();
    if (child < 0) return 71;
    if (child == 0) {
      FILE *pid_file = fopen("producer-child-pid", "wb");
      if (pid_file) { fprintf(pid_file, "%d", getpid()); fclose(pid_file); }
      close(1); close(2); sleep(30); return 0;
    }
    usleep(50000);
    if (strcmp(mode, "success-descendant") == 0) mode = NULL;
    else {
    char output[70000]; memset(output, 'x', sizeof(output));
    fwrite(output, 1, sizeof(output), stdout); fflush(stdout); sleep(30);
    return 0;
    }
  }
  if (argc > 2 && strcmp(argv[1], "authorize") == 0) {
    const char *out = NULL;
    for (int i = 2; i + 1 < argc; i++) if (strcmp(argv[i], "--out") == 0) out = argv[i + 1];
    if (!out) return 64;
    FILE *authorization = fopen(out, "wb");
    if (!authorization) return 65;
    if (mode && strcmp(mode, "large-authorization") == 0) {
      for (int i = 0; i < 70000; i++) fputc('x', authorization);
    } else {
      fputs("{\"schema\":\"ao.blueprint.build-authorization.v0.1\",\"project_id\":\"project\",\"status\":\"ready\",\"score\":100,\"approved_by_user\":true,\"blocking_assumptions\":[],\"production_readiness_exit_condition\":\"bounded\",\"next_allowed_action\":\"ao-forge\"}\n", authorization);
    }
    fclose(authorization);
    return 0;
  }
  if (argc > 2 && strcmp(argv[1], "workgraph") == 0) {
    puts("status=valid");
    return 0;
  }
  if (argc > 2 && strcmp(argv[1], "goal") == 0) {
    if (!valid_forge_schema()) return 66;
    puts("{\"goal_run\":\"goal-run.json\",\"schema\":\"goal-run-v0.1.schema.json\",\"schema_version\":\"ao.forge.goal-run.v0.1\",\"goal_id\":\"bounded-goal\",\"current_phase\":\"implementation\",\"next_action_guard\":\"enabled\",\"status\":\"passed\",\"errors\":[]}");
    return 0;
  }
  if (argc > 1 && strcmp(argv[1], "verify") == 0) {
    int ledger = 0, evidence = 0;
    for (int i = 2; i < argc; i++) {
      if (strcmp(argv[i], "--ledger") == 0 && i + 1 < argc) ledger = 1;
      if (strcmp(argv[i], "--evidence") == 0 && i + 1 < argc) evidence = 1;
    }
    if (!ledger || !evidence) return 64;
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


class ForgeRuntimePackageTests(unittest.TestCase):
    def test_packaged_schema_matches_pinned_forge_contract(self):
        schema = governance.FORGE_RUNTIME_ROOT.joinpath(
            *governance._FORGE_SCHEMA_PARTS
        )
        expected = "68a0fb154124fb4c219cc68eeffcc432e2c5c445765e9dbe24b19718fb98d74c"
        self.assertEqual(governance.FORGE_SCHEMA_SHA256, expected)
        self.assertEqual(hashlib.sha256(schema.read_bytes()).hexdigest(), expected)


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
        self.forge_runtime = self.base / "forge-runtime"
        self.forge_schema = (
            self.forge_runtime
            / "docs"
            / "contracts"
            / "goal-run-v0.1.schema.json"
        )
        self.forge_schema.parent.mkdir(parents=True)
        self.forge_schema.write_bytes(TEST_FORGE_SCHEMA)
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
            FORGE_RUNTIME_ROOT=self.forge_runtime,
            FORGE_SCHEMA_SHA256=hashlib.sha256(TEST_FORGE_SCHEMA).hexdigest(),
            create=True,
        )
        self.configuration.start()
        self.workflow = self.project / "workflow.yaml"
        self.workflow.write_text("name: bounded\n", encoding="utf-8")
        self.run_id = "run-0123456789abcdef"
        self._write_artifacts()

    def tearDown(self):
        for name in ("AO_TEST_PRODUCER_MODE", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "PYTHONPATH"):
            os.environ.pop(name, None)
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
        self.blueprint.joinpath("project-brief.md").write_text("# project\n")
        self.atlas = self._root("ao-atlas") / "workgraph.json"
        self.atlas.write_text(
            json.dumps(
                {
                    "contract_version": "ao.atlas.workgraph.v0.1",
                    "id": "atlas-workgraph",
                    "target_instance": self.authority["project_path"],
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
                    "repo": self.authority["project_path"],
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
        self.covenant_ledger = self._root("ao-covenant") / "ledger.jsonl"
        self.covenant_ledger.write_text('{"event":"authorized"}\n', encoding="utf-8")
        self.covenant.write_text(
            json.dumps(
                {
                    "schema_version": "covenant.governance-evidence.v1",
                    "decision": "authorized",
                    "scope": self.authority["project_path"],
                    "expires_at": "2099-01-01T00:00:00Z",
                    "revoked": False,
                    "mission_id": self.mission_id,
                    "objective_digest": "sha256:" + self.authority["task_digest"],
                    "target_path": self.authority["project_path"],
                    "workflow_sha256": workflow_digest,
                    "run_id": self.run_id,
                    "ao2_sha256": self.ao2_digest,
                }
            ),
            encoding="utf-8",
        )
        requirements_raw = governance.REQUIREMENTS_MANIFEST.read_bytes()
        requirements_value = json.loads(requirements_raw)
        bindings = {
            row["id"]: row["test_id"]
            for row in requirements_value["requirements"]
            if row["id"].startswith("B")
        }
        self.evidence_set = self._root("requirements") / "B01-B19.json"
        self.evidence_set.write_text(
            json.dumps(
                {
                    "requirements_sha256": hashlib.sha256(requirements_raw).hexdigest(),
                    "test_bindings_sha256": hashlib.sha256(
                        json.dumps(bindings, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
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
            self.covenant_ledger,
            self.covenant,
            self.workflow,
            self.project,
            self.run_id,
            self.evidence_set,
        )

    def test_fixture_artifacts_use_authority_canonical_project_path(self):
        # MUTATION: host-path fixture values break Windows authority cross-references.
        canonical = "C:\\fixture\\canonical-project"
        self.authority["project_path"] = canonical
        shutil.rmtree(self.project / ".ao" / "evidence")
        self._write_artifacts()
        self.assertEqual(
            json.loads(self.atlas.read_text(encoding="utf-8"))["target_instance"],
            canonical,
        )
        self.assertEqual(
            json.loads(self.forge.read_text(encoding="utf-8"))["repo"], canonical
        )
        covenant = json.loads(self.covenant.read_text(encoding="utf-8"))
        self.assertEqual(covenant["scope"], canonical)
        self.assertEqual(covenant["target_path"], canonical)

    def _consume(self, envelope):
        with self.pool.authority_lease(self.claim_path) as lease:
            return _consume_witness(lease, envelope)

    def _assert_code(self, code, operation):
        with self.assertRaises(GovernanceError) as raised:
            operation()
        self.assertEqual(raised.exception.code, code)

    def _mode(self, value):
        (self.project / "producer-mode").write_text(value, encoding="utf-8")

    def _producer_commands(self):
        commands = {}
        for root in (self.project, self.forge_runtime):
            path = root / "producer-commands"
            if path.is_file():
                for line in path.read_text(encoding="utf-8").splitlines():
                    commands[line.split("|", 1)[0]] = line
        return commands

    def _producer_environment(self):
        lines = []
        for root in (self.project, self.forge_runtime):
            path = root / "producer-environment"
            if path.is_file():
                lines.extend(path.read_text(encoding="utf-8").splitlines())
        return lines

    def test_forge_uses_hash_bound_packaged_runtime_outside_connected_project(self):
        self.assertFalse((self.project / "docs").exists())
        envelope = issue_witness(
            self.claim_path, self.task_text, self.valid_artifacts()
        )
        self.assertTrue(envelope.is_file())
        self.assertFalse((self.project / "docs").exists())
        project_commands = (
            self.project / "producer-commands"
        ).read_text(encoding="utf-8").splitlines()
        runtime_commands = (
            self.forge_runtime / "producer-commands"
        ).read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            {line.split("|", 1)[0] for line in project_commands},
            {"ao-blueprint", "covenant"},
        )
        self.assertEqual(len(runtime_commands), 1)
        self.assertIn("|goal|validate|--goal-run|", runtime_commands[0])
        goal_run = runtime_commands[0].split("|--goal-run|", 1)[1].split("|", 1)[0]
        self.assertTrue(Path(goal_run).is_absolute())

    def test_missing_forge_runtime_schema_fails_before_forge_launch(self):
        self.forge_schema.unlink()
        self._assert_code(
            "governance-producer-identity-mismatch",
            lambda: issue_witness(
                self.claim_path, self.task_text, self.valid_artifacts()
            ),
        )
        self.assertNotIn("forge", self._producer_commands())
        self.assertFalse((self.project / "docs").exists())

    def test_substituted_forge_runtime_schema_fails_before_forge_launch(self):
        self.forge_schema.write_bytes(b"x" * len(TEST_FORGE_SCHEMA))
        self._assert_code(
            "governance-producer-identity-mismatch",
            lambda: issue_witness(
                self.claim_path, self.task_text, self.valid_artifacts()
            ),
        )
        self.assertNotIn("forge", self._producer_commands())
        self.assertFalse((self.project / "docs").exists())

    def test_forge_runtime_schema_substitution_during_launch_fails_closed(self):
        run_output = governance._run_output

        def substitute_before_launch(arguments, *args, **kwargs):
            if arguments[:2] == ["goal", "validate"]:
                before = self.forge_schema.read_bytes()
                identity = (
                    self.forge_schema.stat().st_dev,
                    self.forge_schema.stat().st_ino,
                )
                if os.name == "nt":
                    with self.assertRaises(PermissionError):
                        self.forge_schema.write_bytes(b"x" * len(before))
                    self.assertEqual(self.forge_schema.read_bytes(), before)
                    self.assertEqual(
                        (
                            self.forge_schema.stat().st_dev,
                            self.forge_schema.stat().st_ino,
                        ),
                        identity,
                    )
                else:
                    self.forge_schema.write_bytes(b"x" * len(before))
            return run_output(arguments, *args, **kwargs)

        try:
            with mock.patch.object(
                governance, "_run_output", side_effect=substitute_before_launch
            ):
                if os.name == "nt":
                    envelope = issue_witness(
                        self.claim_path, self.task_text, self.valid_artifacts()
                    )
                    self.assertEqual(
                        json.loads(envelope.read_text(encoding="utf-8"))["state"],
                        "ready",
                    )
                else:
                    self._assert_code(
                        "governance-producer-identity-mismatch",
                        lambda: issue_witness(
                            self.claim_path, self.task_text, self.valid_artifacts()
                        ),
                    )
                    self.assertNotIn("forge", self._producer_commands())
        finally:
            self.forge_schema.write_bytes(TEST_FORGE_SCHEMA)

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
        commands = self._producer_commands()
        self.assertEqual(len(commands), 3)
        self.assertIn("|authorize|--pack|", commands["ao-blueprint"])
        self.assertIn("|--out|", commands["ao-blueprint"])
        self.assertIn("|goal|validate|--goal-run|", commands["forge"])
        self.assertIn("|verify|--ledger|", commands["covenant"])
        self.assertIn("|--evidence|", commands["covenant"])
        self.assertTrue(commands["covenant"].endswith("|--json"))

    def test_arbitrary_envelope_sealer_and_forged_lease_are_rejected(self):
        self.assertFalse(hasattr(governance, "_seal"))
        self.assertFalse(hasattr(governance, "_issue_authenticated_record"))
        envelope = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        with self.pool.authority_lease(self.claim_path) as real:
            with self.assertRaises(PoolError):
                AuthorityLease(real.authority_path, real.authority_bytes, real.authority)

    def test_blueprint_authorization_is_created_by_the_pinned_producer(self):
        forged = self.blueprint / "build-authorization.json"
        forged.write_text('{"next_allowed_action":"blocked"}', encoding="utf-8")
        envelope = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        value = json.loads(envelope.read_text())
        self.assertEqual(value["route"]["route"], "ao-forge")
        self.assertNotEqual(
            value["producer_artifacts"]["ao-blueprint"]["artifact_sha256"],
            hashlib.sha256(forged.read_bytes()).hexdigest(),
        )

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

    def test_non_executable_atlas_route_cannot_mint_authority(self):
        self._write_mission("ao-atlas")
        self._assert_code(
            "governance-route-not-executable",
            lambda: issue_witness(
                self.claim_path, self.task_text, self.valid_artifacts(atlas=False)
            ),
        )
        self._assert_code(
            "governance-route-not-executable",
            lambda: issue_witness(
                self.claim_path, self.task_text, self.valid_artifacts(atlas=True)
            ),
        )
        self._write_mission("ao-forge")
        self._assert_code(
            "governance-atlas-unexpected",
            lambda: issue_witness(
                self.claim_path, self.task_text, self.valid_artifacts(atlas=True)
            ),
        )

    def test_atlas_native_readback_is_exact_status_valid(self):
        self.assertEqual(
            governance._readback("ao-atlas", b"status=valid\n"),
            {"status": "valid"},
        )
        for raw in (b"ready=1\nblocked=0\ncompleted=0\n", b"status=invalid\n"):
            with self.assertRaises(GovernanceError):
                governance._readback("ao-atlas", raw)

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
            self._mode(mode)
            with self.subTest(mode=mode):
                self._assert_code(
                    code,
                    lambda: issue_witness(
                        self.claim_path, self.task_text, self.valid_artifacts()
                    ),
                )

    @unittest.skipIf(os.name == "nt", "POSIX process-group assertion")
    def test_producer_failure_kills_descendant_process_tree(self):
        self._mode("descendant")
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
        self._mode("error-descendant")
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
            self.covenant_ledger,
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
            lambda value: value["requirement_ids"].append("B19"),
            lambda value: value.update(extra=True),
            lambda value: value.update(requirements_sha256="0" * 64),
            lambda value: value.update(test_bindings_sha256="0" * 64),
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
        reordered = json.loads(json.dumps(original))
        reordered["requirement_ids"].reverse()
        self.evidence_set.write_text(json.dumps(reordered), encoding="utf-8")
        self.assertTrue(
            issue_witness(self.claim_path, self.task_text, self.valid_artifacts()).is_file()
        )
        self.evidence_set.write_text(json.dumps(original), encoding="utf-8")

    def test_all_producer_artifacts_are_rechecked_after_validation(self):
        original = self.forge.read_bytes()
        run_producer = governance._run_producer

        def mutate_after_last_producer(name, *arguments):
            result = run_producer(name, *arguments)
            if name == "ao-covenant":
                value = json.loads(original)
                value["next_task"] = "changed"
                self.forge.write_text(json.dumps(value), encoding="utf-8")
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
            self.forge.write_bytes(original)

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

    def test_producer_uses_retained_staged_bytes_across_a_b_a_swap(self):
        original = self.forge.read_bytes()
        replacement = json.dumps({"schema_version": "ao.forge.goal-run.v0.1"}).encode()
        run_output = mission_bridge._run_output

        def swap_during_launch(*arguments, **keywords):
            self.forge.write_bytes(replacement)
            self.forge.write_bytes(original)
            return run_output(*arguments, **keywords)

        with mock.patch.object(mission_bridge, "_run_output", side_effect=swap_during_launch):
            envelope = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        self.assertNotIn(str(self.forge), "\n".join(self._producer_commands().values()))
        self.assertTrue(envelope.is_file())

    def test_staged_candidate_a_b_a_swap_fails_closed(self):
        run_producer = governance._run_producer

        def swap_staged(name, component, artifact, project, *rest):
            result = run_producer(name, component, artifact, project, *rest)
            if name == "ao-forge":
                original = artifact.private.path
                parked = original.with_name(original.name + ".parked")
                before = original.read_bytes()
                identity = (original.stat().st_dev, original.stat().st_ino)
                if os.name == "nt":
                    with self.assertRaises(PermissionError):
                        original.rename(parked)
                    self.assertEqual(original.read_bytes(), before)
                    self.assertEqual(
                        (original.stat().st_dev, original.stat().st_ino), identity
                    )
                    return result
                original.rename(parked)
                original.write_bytes(b"replacement")
                original.unlink()
                parked.rename(original)
            return result

        with mock.patch.object(governance, "_run_producer", side_effect=swap_staged):
            if os.name == "nt":
                envelope = issue_witness(
                    self.claim_path, self.task_text, self.valid_artifacts()
                )
                self.assertEqual(
                    json.loads(envelope.read_text(encoding="utf-8"))["state"], "ready"
                )
            else:
                self._assert_code(
                    "governance-artifact-changed",
                    lambda: issue_witness(
                        self.claim_path, self.task_text, self.valid_artifacts()
                    ),
                )

    def test_blueprint_child_content_a_b_a_mutation_is_detected(self):
        run_producer = governance._run_producer

        def mutate_child(name, component, artifact, project, *rest):
            result = run_producer(name, component, artifact, project, *rest)
            if name == "ao-blueprint":
                child = artifact.children[0]
                original = child.private.path.read_bytes()
                child.private.directory.path.chmod(0o700)
                child.private.path.chmod(0o600)
                child.private.path.write_bytes(b"temporary replacement")
                child.private.path.write_bytes(original)
            return result

        with mock.patch.object(governance, "_run_producer", side_effect=mutate_child):
            self._assert_code(
                "governance-artifact-changed",
                lambda: issue_witness(
                    self.claim_path, self.task_text, self.valid_artifacts()
                ),
            )

    def test_blueprint_output_path_swap_fails_closed(self):
        run_producer = governance._run_producer

        def swap_output(name, component, artifact, project, *rest):
            result = run_producer(name, component, artifact, project, *rest)
            if name == "ao-blueprint":
                output = rest[1]
                original = output.private.path
                parked = original.with_name(original.name + ".parked")
                before = original.read_bytes()
                identity = (original.stat().st_dev, original.stat().st_ino)
                if os.name == "nt":
                    with self.assertRaises(PermissionError):
                        original.rename(parked)
                    self.assertEqual(original.read_bytes(), before)
                    self.assertEqual(
                        (original.stat().st_dev, original.stat().st_ino), identity
                    )
                    return result
                original.rename(parked)
                original.write_bytes(b"replacement")
                original.unlink()
                parked.rename(original)
            return result

        with mock.patch.object(governance, "_run_producer", side_effect=swap_output):
            if os.name == "nt":
                envelope = issue_witness(
                    self.claim_path, self.task_text, self.valid_artifacts()
                )
                self.assertEqual(
                    json.loads(envelope.read_text(encoding="utf-8"))["state"], "ready"
                )
            else:
                self._assert_code(
                    "governance-artifact-changed",
                    lambda: issue_witness(
                        self.claim_path, self.task_text, self.valid_artifacts()
                    ),
                )

    def test_project_marker_deletion_does_not_restore_authority(self):
        consumed = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        governed = self._consume(consumed)
        governed.target.close()
        consumed.with_suffix(".consumed").unlink()
        self._assert_code("governance-envelope-consumed", lambda: self._consume(consumed))

        revoked = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        revoke_witness(self.claim_path, revoked)
        revoked.with_suffix(".revoked").unlink()
        self._assert_code("governance-envelope-revoked", lambda: self._consume(revoked))

    def test_producer_environment_strips_injection_variables(self):
        os.environ.update(
            DYLD_INSERT_LIBRARIES="malicious",
            LD_PRELOAD="malicious",
            PYTHONPATH="malicious",
            AO_TEST_PRODUCER_MODE="failure",
        )
        issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        lines = self._producer_environment()
        self.assertEqual(len(lines), 3)
        self.assertEqual(set(lines), {"DYLD=unset LD=unset PYTHON=unset TEST=unset"})

    @unittest.skipIf(os.name == "nt", "POSIX process-group assertion")
    def test_successful_producer_kills_descendant_process_tree(self):
        self._mode("success-descendant")
        child = None
        try:
            issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
            child = int((self.project / "producer-child-pid").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
        finally:
            if child is not None:
                try:
                    os.kill(child, 9)
                except ProcessLookupError:
                    pass

    def test_oversized_inputs_and_producer_output_fail_bounded(self):
        oversized = self._root("ao-forge") / "oversized.json"
        with oversized.open("wb") as stream:
            stream.truncate(governance._MAX_ARTIFACT + 1)
        self._assert_code(
            "governance-artifact-unsafe",
            lambda: issue_witness(
                self.claim_path,
                self.task_text,
                dataclasses.replace(self.valid_artifacts(), forge_goal_run=oversized),
            ),
        )
        self._mode("large-authorization")
        self._assert_code(
            "governance-producer-readback",
            lambda: issue_witness(self.claim_path, self.task_text, self.valid_artifacts()),
        )

    def test_oversized_blueprint_aggregate_and_workflow_fail_bounded(self):
        first = self.blueprint / "first.bin"
        second = self.blueprint / "second.bin"
        with first.open("wb") as stream:
            stream.truncate(governance._MAX_ARTIFACT // 2 + 1)
        with second.open("wb") as stream:
            stream.truncate(governance._MAX_ARTIFACT // 2 + 1)
        self._assert_code(
            "governance-artifact-unsafe",
            lambda: issue_witness(self.claim_path, self.task_text, self.valid_artifacts()),
        )
        first.unlink()
        second.unlink()
        with self.workflow.open("wb") as stream:
            stream.truncate(governance._MAX_ARTIFACT + 1)
        self._assert_code(
            "governance-workflow-mismatch",
            lambda: issue_witness(self.claim_path, self.task_text, self.valid_artifacts()),
        )

    def test_governed_execution_authenticated_mappings_are_immutable(self):
        envelope = issue_witness(self.claim_path, self.task_text, self.valid_artifacts())
        governed = self._consume(envelope)
        try:
            with self.assertRaises(TypeError):
                governed.ao2["sha256"] = "0" * 64
            with self.assertRaises(TypeError):
                governed.producer_artifacts["ao-forge"]["asset"] = "forged"
        finally:
            governed.target.close()

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

    def test_windows_create_private_and_workflow_preserve_physical_bytes(self):
        # MUTATION: text-mode create expands both LF and the LF in CRLF.
        payload = b"\x00\xffLF\nCRLF\r\nCTRL-Z\x1aEND\rTAIL"
        digest = hashlib.sha256(payload).hexdigest()
        project = mission_bridge._receipt_project_root(self.authority)
        candidate = mission_bridge._private_file(
            project, (*governance._PRIVATE_PARTS, "producer-input"), "binary-private"
        )
        try:
            with windows_text_mode():
                governance._create_private(candidate, payload)
            physical = candidate.path.read_bytes()
            self.assertEqual(physical, payload)
            self.assertEqual(len(physical), len(payload))
            self.assertEqual(hashlib.sha256(physical).hexdigest(), digest)

            with (
                windows_text_mode(),
                mock.patch.object(governance, "_read_file", return_value=payload),
                mock.patch.object(
                    governance,
                    "_read_private_bytes",
                    side_effect=lambda path, _limit: path.path.read_bytes(),
                ),
            ):
                self.assertEqual(governance._stage_workflow(project, self.workflow), digest)
            workflow = project.joinpath(
                *governance._PRIVATE_PARTS, "workflows", digest
            )
            physical = workflow.read_bytes()
            self.assertEqual(physical, payload)
            self.assertEqual(len(physical), len(payload))
            self.assertEqual(hashlib.sha256(physical).hexdigest(), digest)
        finally:
            candidate.close()
            project.close()

    def test_windows_retained_file_and_directory_staging_preserve_bytes(self):
        # MUTATION: retained staging descriptors read CRLF/Ctrl-Z in text mode.
        payload = b"\x00\xffLF\nCRLF\r\nCTRL-Z\x1aEND\rTAIL"
        digest = hashlib.sha256(payload).hexdigest()
        project = mission_bridge._receipt_project_root(self.authority)
        retained_file = retained_directory = None
        try:
            staged = mission_bridge._private_file(
                project,
                (*governance._PRIVATE_PARTS, "producer-input"),
                f"binary-{digest}",
            )
            staged.path.write_bytes(payload)
            staged.close()
            with (
                windows_text_mode(),
                mock.patch.object(governance, "_read_file", return_value=payload),
                mock.patch.object(
                    governance,
                    "_read_private_bytes",
                    side_effect=lambda path, _limit: path.path.read_bytes(),
                ),
            ):
                retained_file, staged_digest = governance._stage_file(
                    project, self.forge, governance._ROOTS["ao-forge"], "binary"
                )
                readback = retained_file.read(governance._MAX_ARTIFACT)
            self.assertEqual(staged_digest, digest)
            self.assertEqual(readback, payload)
            self.assertEqual(len(readback), len(payload))
            self.assertEqual(hashlib.sha256(readback).hexdigest(), digest)
            self.assertEqual(retained_file.private.path.read_bytes(), payload)

            source = self._root("binary-directory") / "payload.bin"
            source.write_bytes(payload)
            directory_digest = "d" * 64
            destination = (
                self.project
                / ".ao/governance/office-pool/producer-input/blueprint"
                / directory_digest
            )
            destination.mkdir(parents=True)
            destination.joinpath(source.name).write_bytes(payload)
            with (
                windows_text_mode(),
                mock.patch.object(governance, "_directory_digest", return_value=directory_digest),
                mock.patch.object(governance, "_read_file", return_value=payload),
                mock.patch.object(
                    governance,
                    "_read_private_bytes",
                    side_effect=lambda path, _limit: path.path.read_bytes(),
                ),
            ):
                retained_directory, observed_digest = governance._stage_directory(
                    project, source.parent, (".ao", "evidence", "binary-directory")
                )
                child_readback = retained_directory.children[0].read(
                    governance._MAX_ARTIFACT
                )
            self.assertEqual(observed_digest, directory_digest)
            self.assertEqual(child_readback, payload)
            self.assertEqual(len(child_readback), len(payload))
            self.assertEqual(hashlib.sha256(child_readback).hexdigest(), digest)
            self.assertEqual(retained_directory.children[0].private.path.read_bytes(), payload)
        finally:
            if retained_directory is not None:
                retained_directory.close()
            if retained_file is not None:
                retained_file.close()
            project.close()

    def test_windows_retained_producer_output_preserves_physical_bytes(self):
        # MUTATION: a text-mode producer-output descriptor expands and truncates bytes.
        payload = b"\x00\xffLF\nCRLF\r\nCTRL-Z\x1aEND\rTAIL"
        digest = hashlib.sha256(payload).hexdigest()
        project = mission_bridge._receipt_project_root(self.authority)
        retained = None
        try:
            with windows_text_mode():
                retained = governance._retained_output(project)
                self.assertEqual(os.write(retained.descriptor, payload), len(payload))
                os.fsync(retained.descriptor)
                readback = retained.read(governance._MAX_ARTIFACT)
            physical = retained.private.path.read_bytes()
            self.assertEqual(physical, payload)
            self.assertEqual(len(physical), len(payload))
            self.assertEqual(hashlib.sha256(physical).hexdigest(), digest)
            self.assertEqual(readback, payload)
        finally:
            if retained is not None:
                retained.close()
            project.close()

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
