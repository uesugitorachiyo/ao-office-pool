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
TEST_FORGE_REPLACEMENT = b"unverified-forge-goal-schema\n"
NATIVE_COVENANT_LEDGER_SHA256 = (
    "08ca3faea6377927367ff652d408903d61d6992d189a3ac16ef969158aa2b2fd"
)
NATIVE_COVENANT_LEDGER = """{"schema_version":"covenant.event.v1","event_id":"event-000001","sequence":1,"run_id":"run-0123456789abcdef","previous_event_hash":"0000000000000000000000000000000000000000000000000000000000000000","event_hash":"15600c28ba513add58d310f1f77e097fb0b79954f586decb01c5a51d15037b6c","type":"run_started","status":"success","message":"governed run started"}
{"schema_version":"covenant.event.v1","event_id":"event-000002","sequence":2,"run_id":"run-0123456789abcdef","previous_event_hash":"15600c28ba513add58d310f1f77e097fb0b79954f586decb01c5a51d15037b6c","event_hash":"5f376ca9f52ec7a744fb144930afebb2c0a820c874a78e55583ce90e6a6be82a","type":"task_started","task_id":"bounded-task","status":"success","message":"bounded task started"}
{"schema_version":"covenant.event.v1","event_id":"event-000003","sequence":3,"run_id":"run-0123456789abcdef","previous_event_hash":"5f376ca9f52ec7a744fb144930afebb2c0a820c874a78e55583ce90e6a6be82a","event_hash":"cc2c55bf69085ea0163448b97106498f616789b924c3632d4a39eb007409d845","type":"policy_decided","task_id":"bounded-task","status":"success","message":"bounded read allowed","decision_id":"policy-bounded-1","decision":"allow","effect_type":"file.read","resource":".ao/workflow.yaml"}
{"schema_version":"covenant.event.v1","event_id":"event-000004","sequence":4,"run_id":"run-0123456789abcdef","previous_event_hash":"cc2c55bf69085ea0163448b97106498f616789b924c3632d4a39eb007409d845","event_hash":"7020feaf562ad793a44e52b6c68710f746aabbd41f62dfc2c67f4bc63f182718","type":"task_finished","task_id":"bounded-task","status":"success","message":"bounded task finished"}
{"schema_version":"covenant.event.v1","event_id":"event-000005","sequence":5,"run_id":"run-0123456789abcdef","previous_event_hash":"7020feaf562ad793a44e52b6c68710f746aabbd41f62dfc2c67f4bc63f182718","event_hash":"ca601d701cc1b732f3ae2043c8f4cbbffec537bf1d7efaa4a984c9836ee510b2","type":"run_finished","status":"success","message":"governed run completed"}
"""


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

static int valid_forge_schema(const char *expected) {
  char buffer[128] = {0};
  FILE *schema = fopen("docs/contracts/goal-run-v0.1.schema.json", "rb");
  if (!schema) return 0;
  size_t count = fread(buffer, 1, sizeof(buffer), schema);
  int trailing = fgetc(schema);
  fclose(schema);
  return count == strlen(expected)
    && trailing == EOF
    && memcmp(buffer, expected, count) == 0;
}

static int create_marker(const char *path) {
  FILE *marker = fopen(path, "wb");
  if (!marker) return 0;
  fclose(marker);
  return 1;
}

static int starts_object(const char *path) {
  FILE *stream = fopen(path, "rb");
  if (!stream) return 0;
  int first = fgetc(stream);
  fclose(stream);
  return first == '{';
}

static int starts_object_twice(const char *path) {
  return starts_object(path) && starts_object(path);
}

static int contains_attacker(const char *path) {
  char buffer[4096] = {0};
  FILE *stream = fopen(path, "rb");
  if (!stream) return 0;
  size_t count = fread(buffer, 1, sizeof(buffer) - 1, stream);
  fclose(stream);
  buffer[count] = '\0';
  return strstr(buffer, "attacker") != NULL;
}

static int wait_for_marker(const char *path) {
  for (int i = 0; i < 1000; i++) {
    if (access(path, F_OK) == 0) return 1;
    usleep(10000);
  }
  return 0;
}

int main(int argc, char **argv) {
  FILE *log = fopen("producer-logs/commands", "ab");
  if (!log) return 70;
  fprintf(log, "%s", base(argv[0]));
  for (int i = 1; i < argc; i++) fprintf(log, "|%s", argv[i]);
  fputc('\n', log);
  fclose(log);
  char mode_buffer[64] = {0};
  FILE *mode_file = fopen("producer-sync/mode", "rb");
  if (mode_file) { fscanf(mode_file, "%63s", mode_buffer); fclose(mode_file); }
  const char *mode = mode_buffer[0] ? mode_buffer : NULL;
  FILE *environment = fopen("producer-logs/environment", "ab");
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
    const char *workgraph = NULL;
    for (int i = 2; i + 1 < argc; i++) if (strcmp(argv[i], "--workgraph") == 0) workgraph = argv[i + 1];
    if (!workgraph || !starts_object(workgraph)) return 65;
    puts("status=valid");
    return 0;
  }
  if (argc > 2 && strcmp(argv[1], "goal") == 0) {
    const char *goal_run = NULL;
    for (int i = 2; i + 1 < argc; i++) if (strcmp(argv[i], "--goal-run") == 0) goal_run = argv[i + 1];
    int artifact_aba = mode && (
      strcmp(mode, "staged-ancestor-aba") == 0
      || strcmp(mode, "project-parent-aba") == 0);
    if (artifact_aba) {
      if (!create_marker("producer-sync/artifact-ready")
          || !wait_for_marker("producer-sync/artifact-swapped")) return 69;
    }
    if (!goal_run || !starts_object_twice(goal_run)) return 65;
    if (mode && strcmp(mode, "project-parent-aba") == 0
        && contains_attacker(goal_run)
        && !create_marker("producer-sync/attacker-read")) return 69;
    if (artifact_aba) {
      if (!create_marker("producer-sync/artifact-read")
          || !wait_for_marker("producer-sync/artifact-restored")) return 69;
    }
    const char *expected = "test-forge-goal-run-schema\n";
    if (mode && strcmp(mode, "forge-parent-aba") == 0) {
      if (!create_marker("producer-sync/schema-ready")
          || !wait_for_marker("producer-sync/schema-continue")) return 67;
      if (access("producer-sync/schema-denied", F_OK) != 0) {
        expected = "unverified-forge-goal-schema\n";
      }
    }
    if (!valid_forge_schema(expected)) return 66;
    if (mode && strcmp(mode, "forge-parent-aba") == 0) {
      if (!create_marker("producer-sync/schema-read")
          || !wait_for_marker("producer-sync/schema-restored")) return 68;
    }
    puts("{\"goal_run\":\"goal-run.json\",\"schema\":\"goal-run-v0.1.schema.json\",\"schema_version\":\"ao.forge.goal-run.v0.1\",\"goal_id\":\"bounded-goal\",\"current_phase\":\"implementation\",\"next_action_guard\":\"enabled\",\"status\":\"passed\",\"errors\":[]}");
    return 0;
  }
  if (argc > 1 && strcmp(argv[1], "verify") == 0) {
    const char *ledger = NULL, *evidence = NULL;
    for (int i = 2; i < argc; i++) {
      if (strcmp(argv[i], "--ledger") == 0 && i + 1 < argc) ledger = argv[i + 1];
      if (strcmp(argv[i], "--evidence") == 0 && i + 1 < argc) evidence = argv[i + 1];
    }
    if (!ledger || !evidence || !starts_object(ledger) || !starts_object_twice(evidence)) return 64;
    puts("{\"schema_version\":\"covenant.verify-result.v1\",\"verified\":true,\"run_id\":\"run-0123456789abcdef\",\"event_count\":5,\"artifact_count\":0,\"input_snapshot_count\":0,\"failure_count\":0,\"failures\":[],\"policy_explanations\":[{\"decision_id\":\"policy-bounded-1\",\"task_id\":\"bounded-task\",\"effect_type\":\"file.read\",\"resource\":\".ao/workflow.yaml\",\"decision\":\"allow\",\"reason\":\"bounded read allowed\",\"summary\":\"allow file.read on .ao/workflow.yaml\",\"detail\":\"bounded read allowed\"}],\"ledger_digest\":\"08ca3faea6377927367ff652d408903d61d6992d189a3ac16ef969158aa2b2fd\",\"last_event_hash\":\"ca601d701cc1b732f3ae2043c8f4cbbffec537bf1d7efaa4a984c9836ee510b2\"}");
    return 0;
  }
  return 64;
}
'''


COMMITS = {
    "ao-blueprint": "a581a22af7d06483287a1b7590709e4c4d3739b8",
    "ao-atlas": "2bf243ce8d8c71d845754398238b14d1ab77d0e6",
    "ao-forge": "e104b47c2e14b6c0927b885e137907ad227aeb5c",
    "ao-covenant": "2fd72a0426a747868826581612fa1dc9727b53b9",
    "ao2": "8307795b3434af920f6cef088e56ca8fcc76775b",
}
VERSIONS = {
    "ao-blueprint": "git-a581a22af7d0",
    "ao-atlas": "v0.2.0",
    "ao-forge": "v0.1.4",
    "ao-covenant": "v0.1.1",
    "ao2": "v0.5.11",
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

    def test_witness_uses_the_released_component_lock_identities(self):
        expected = {
            "ao-blueprint": ("git-a581a22af7d0", "a581a22af7d06483287a1b7590709e4c4d3739b8"),
            "ao-atlas": ("v0.2.0", "2bf243ce8d8c71d845754398238b14d1ab77d0e6"),
            "ao-forge": ("v0.1.4", "e104b47c2e14b6c0927b885e137907ad227aeb5c"),
            "ao-covenant": ("v0.1.1", "2fd72a0426a747868826581612fa1dc9727b53b9"),
            "ao2": ("v0.5.11", "8307795b3434af920f6cef088e56ca8fcc76775b"),
        }
        components = governance._locked_components()
        self.assertEqual(
            {name: (value["version"], value["commit"]) for name, value in components.items()},
            expected,
        )


class GovernanceWitnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        self.project.joinpath("producer-logs").mkdir()
        self.project.joinpath("producer-sync").mkdir()
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
        self.forge_runtime.joinpath("producer-logs").mkdir()
        self.forge_runtime.joinpath("producer-sync").mkdir()
        self.private_forge_runtime = self.project.joinpath(
            ".ao/governance/office-pool/producer-runtime/ao-forge"
        )
        self.private_forge_runtime.joinpath("producer-logs").mkdir(parents=True)
        self.private_forge_runtime.joinpath("producer-sync").mkdir()
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
            "version": VERSIONS[name],
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
                    "nodes": [
                        {
                            "id": "node",
                            "status": "ready",
                            "dependencies": [],
                            "blockers": [],
                            "stitch_task": False,
                            "factory_task": {
                                "contract_version": "ao.atlas.factory-task.v0.1",
                                "id": "bounded-task",
                                OBJECTIVE_FIELD: self.task_text,
                                "target_factory_repo": "project",
                                "factory_folder": "factory/bounded-task",
                                "acceptance_criteria": ["bounded"],
                                "non_goals": ["no publication"],
                                "write_scope": ["."],
                                "verification_commands": ["provider-free-check"],
                                "required_evidence": ["bounded-evidence"],
                                "safety_limits": ["no provider calls"],
                                "dependency_refs": [],
                                "context_pack_refs": [],
                            },
                        }
                    ],
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
        self.covenant = self._root("ao-covenant") / "evidence.json"
        self.covenant_ledger = self._root("ao-covenant") / "ledger.jsonl"
        self._write_native_covenant()

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

    def _write_native_covenant(self):
        self.covenant_ledger.write_bytes(NATIVE_COVENANT_LEDGER.encode("utf-8"))
        self.covenant.write_text(
            json.dumps(
                {
                    "schema_version": "covenant.evidence-pack.v1",
                    "run_id": self.run_id,
                    "contract_digest": "c" * 64,
                    "ledger_digest": NATIVE_COVENANT_LEDGER_SHA256,
                    "run_status": "success",
                    "artifact_manifest": [],
                    "input_snapshots": [],
                    "policy_decisions": [
                        {
                            "schema_version": "covenant.policy-decision.v1",
                            "decision_id": "policy-bounded-1",
                            "task_id": "bounded-task",
                            "effect_type": "file.read",
                            "resource": ".ao/workflow.yaml",
                            "decision": "allow",
                            "reason": "bounded read allowed",
                        }
                    ],
                    "failures": [],
                    "closure_matrix": {
                        "schema_version": "covenant.closure-matrix.v1",
                        "run_id": self.run_id,
                        "contract_digest": "c" * 64,
                        "status": "accepted",
                        "rows": [
                            {
                                "obligation_id": "bounded-obligation",
                                "required": True,
                                "status": "closed",
                                "task_ids": ["bounded-task"],
                                "artifact_ids": [],
                                "policy_decision_ids": ["policy-bounded-1"],
                                "reason": "bounded policy evidence verified",
                            }
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )

    def _write_covenant_events(self, event_fields, *, trailing_newline=True):
        previous = "0" * 64
        encoded = []
        final_hash = None
        for ordinal, source_fields in enumerate(event_fields, 1):
            fields = dict(source_fields)
            sequence = fields.pop("_sequence", ordinal)
            event_id = fields.pop("_event_id", f"event-{ordinal:06d}")
            hash_payload = {
                "schema_version": "covenant.event.v1",
                "event_id": event_id,
                "sequence": sequence,
                "run_id": self.run_id,
                "previous_event_hash": previous,
                **fields,
            }
            final_hash = hashlib.sha256(
                json.dumps(hash_payload, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            event = {
                "schema_version": "covenant.event.v1",
                "event_id": event_id,
                "sequence": sequence,
                "run_id": self.run_id,
                "previous_event_hash": previous,
                "event_hash": final_hash,
                **fields,
            }
            encoded.append(
                json.dumps(event, separators=(",", ":")).encode("utf-8")
            )
            previous = final_hash
        raw = b"\n".join(encoded) + (b"\n" if trailing_newline else b"")
        self.covenant_ledger.write_bytes(raw)
        covenant = json.loads(self.covenant.read_text(encoding="utf-8"))
        covenant["ledger_digest"] = hashlib.sha256(raw).hexdigest()
        self.covenant.write_text(json.dumps(covenant), encoding="utf-8")
        return raw, final_hash

    def _native_success_events(self):
        return [
            {
                "type": "run_started",
                "status": "success",
                "message": "governed run started",
            },
            {
                "type": "task_started",
                "task_id": "bounded-task",
                "status": "success",
                "message": "bounded task started",
            },
            {
                "type": "policy_decided",
                "task_id": "bounded-task",
                "status": "success",
                "message": "bounded read allowed",
                "decision_id": "policy-bounded-1",
                "decision": "allow",
                "effect_type": "file.read",
                "resource": ".ao/workflow.yaml",
            },
            {
                "type": "task_finished",
                "task_id": "bounded-task",
                "status": "success",
                "message": "bounded task finished",
            },
            {
                "type": "run_finished",
                "status": "success",
                "message": "governed run completed",
            },
        ]

    def _assert_ledger_rejected_after_verified_readback(
        self, event_fields, *, transform=None, trailing_newline=True
    ):
        raw, final_hash = self._write_covenant_events(
            event_fields, trailing_newline=trailing_newline
        )
        if transform is not None:
            raw = transform(raw)
            self.covenant_ledger.write_bytes(raw)
            covenant = json.loads(self.covenant.read_text(encoding="utf-8"))
            covenant["ledger_digest"] = hashlib.sha256(raw).hexdigest()
            self.covenant.write_text(json.dumps(covenant), encoding="utf-8")
        run_producer = governance._run_producer

        def verified_readback(name, *arguments):
            result = run_producer(name, *arguments)
            if name == "ao-covenant":
                result = dict(result)
                result["event_count"] = len(event_fields)
                result["ledger_digest"] = hashlib.sha256(raw).hexdigest()
                result["last_event_hash"] = final_hash
            return result

        with mock.patch.object(
            governance, "_run_producer", side_effect=verified_readback
        ):
            self._assert_code(
                "governance-relationship-mismatch",
                lambda: issue_witness(
                    self.claim_path, self.task_text, self.valid_artifacts()
                ),
            )

    def _write_legacy_covenant(self):
        workflow_digest = hashlib.sha256(self.workflow.read_bytes()).hexdigest()
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
        self.assertNotIn("scope", covenant)
        self.assertNotIn("target_path", covenant)

    def _consume(self, envelope):
        with self.pool.authority_lease(self.claim_path) as lease:
            return _consume_witness(lease, envelope)

    def _assert_code(self, code, operation):
        with self.assertRaises(GovernanceError) as raised:
            operation()
        self.assertEqual(raised.exception.code, code)

    def _mode(self, value):
        (self.project / "producer-sync/mode").write_text(value, encoding="utf-8")
        if "descendant" in value:
            (self.project / "producer-child-pid").touch()

    def _producer_commands(self):
        commands = {}
        for root in (self.project, self.private_forge_runtime):
            path = root / "producer-logs/commands"
            if path.is_file():
                for line in path.read_text(encoding="utf-8").splitlines():
                    commands[line.split("|", 1)[0]] = line
        return commands

    def _producer_environment(self):
        lines = []
        for root in (self.project, self.private_forge_runtime):
            path = root / "producer-logs/environment"
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
            self.project / "producer-logs/commands"
        ).read_text(encoding="utf-8").splitlines()
        runtime_commands = (
            self.private_forge_runtime / "producer-logs/commands"
        ).read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            {line.split("|", 1)[0] for line in project_commands},
            {"ao-blueprint", "covenant"},
        )
        self.assertEqual(len(runtime_commands), 1)
        self.assertIn("|goal|validate|--goal-run|", runtime_commands[0])
        goal_run = runtime_commands[0].split("|--goal-run|", 1)[1].split("|", 1)[0]
        self.assertTrue(self.private_forge_runtime.resolve().is_relative_to(self.project))
        self.assertFalse(Path(goal_run).is_absolute())
        self.assertTrue(
            self.private_forge_runtime.joinpath(goal_run)
            .resolve()
            .is_relative_to(self.project)
        )

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

    def test_forge_runtime_parent_directory_aba_during_launch_fails_closed(self):
        sync = self.private_forge_runtime / "producer-sync"
        sync.joinpath("mode").write_text("forge-parent-aba", encoding="utf-8")
        docs = self.forge_runtime / "docs"
        contracts = docs / "contracts"
        parked = self.forge_runtime / "docs-parked"
        before_changes = tuple(
            path.stat().st_ctime_ns for path in (self.forge_runtime, docs, contracts)
        )
        run_output = governance._run_output
        attacker = None
        attack_errors = []

        def wait_for(path):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if path.exists():
                    return
                time.sleep(0.01)
            raise AssertionError(f"timed out waiting for {path.name}")

        def attack():
            try:
                wait_for(sync / "schema-ready")
                if os.name == "nt":
                    identity = (docs.stat().st_dev, docs.stat().st_ino)
                    with self.assertRaises(PermissionError):
                        docs.rename(parked)
                    self.assertEqual((docs.stat().st_dev, docs.stat().st_ino), identity)
                    sync.joinpath("schema-denied").touch()
                else:
                    docs.rename(parked)
                    replacement = docs / "contracts/goal-run-v0.1.schema.json"
                    replacement.parent.mkdir(parents=True)
                    replacement.write_bytes(TEST_FORGE_REPLACEMENT)
                    sync.joinpath("schema-denied").touch()
                sync.joinpath("schema-continue").touch()
                wait_for(sync / "schema-read")
                if os.name != "nt":
                    shutil.rmtree(docs)
                    parked.rename(docs)
                sync.joinpath("schema-restored").touch()
            except BaseException as error:
                attack_errors.append(error)
                sync.joinpath("schema-continue").touch()
                sync.joinpath("schema-restored").touch()

        def attack_during_run(arguments, *args, **kwargs):
            nonlocal attacker
            if arguments[:2] == ["goal", "validate"]:
                attacker = threading.Thread(target=attack)
                attacker.start()
            try:
                return run_output(arguments, *args, **kwargs)
            finally:
                if attacker is not None:
                    attacker.join(timeout=6)

        try:
            with mock.patch.object(
                governance, "_run_output", side_effect=attack_during_run
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
            self.assertIsNotNone(attacker)
            self.assertFalse(attacker.is_alive())
            if attack_errors:
                raise attack_errors[0]
            self.assertTrue(sync.joinpath("schema-read").is_file())
            self.assertEqual(self.forge_schema.read_bytes(), TEST_FORGE_SCHEMA)
            if os.name != "nt":
                after_changes = tuple(
                    path.stat().st_ctime_ns
                    for path in (self.forge_runtime, docs, contracts)
                )
                self.assertNotEqual(after_changes, before_changes)
        finally:
            if parked.exists():
                if docs.exists():
                    shutil.rmtree(docs)
                parked.rename(docs)

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

    def test_native_covenant_pack_and_ledger_are_bound_after_locked_verification(self):
        start = datetime(2026, 8, 13, tzinfo=timezone.utc)
        with mock.patch.object(governance, "_now", return_value=start):
            envelope = issue_witness(
                self.claim_path,
                self.task_text,
                self.valid_artifacts(),
                lifetime_seconds=37,
            )
        value = json.loads(envelope.read_text(encoding="utf-8"))
        self.assertEqual(value["covenant"]["expires_at"], "2026-08-13T00:00:37Z")
        self.assertEqual(value["covenant"]["expires_at"], value["expires_at"])
        self.assertEqual(
            value["producer_artifacts"]["ao-covenant"]["artifact_sha256"],
            hashlib.sha256(self.covenant.read_bytes()).hexdigest(),
        )

    def test_legacy_covenant_authority_object_is_not_native_evidence(self):
        self._write_legacy_covenant()
        self._assert_code(
            "governance-relationship-mismatch",
            lambda: issue_witness(
                self.claim_path, self.task_text, self.valid_artifacts()
            ),
        )

    def test_synthetic_one_line_ledger_cannot_qualify_as_native_evidence(self):
        self.covenant_ledger.write_text('{"event":"authorized"}\n', encoding="utf-8")
        self._assert_code(
            "governance-relationship-mismatch",
            lambda: issue_witness(
                self.claim_path, self.task_text, self.valid_artifacts()
            ),
        )

    def test_covenant_native_success_policy_and_closure_are_required(self):
        def failed(value):
            value["failures"] = [{"failure_id": "failure-000001"}]

        def denied(value):
            value["policy_decisions"][0]["decision"] = "deny"

        def rejected(value):
            value["closure_matrix"]["status"] = "rejected"

        def open_required(value):
            value["closure_matrix"]["rows"][0]["status"] = "open"

        original = json.loads(self.covenant.read_text(encoding="utf-8"))
        for mutate in (failed, denied, rejected, open_required):
            value = json.loads(json.dumps(original))
            mutate(value)
            self.covenant.write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(mutate=mutate.__name__):
                self._assert_code(
                    "governance-relationship-mismatch",
                    lambda: issue_witness(
                        self.claim_path, self.task_text, self.valid_artifacts()
                    ),
                )
        self.covenant.write_text(json.dumps(original), encoding="utf-8")

    def test_covenant_native_readback_requires_verified_success(self):
        valid = {
            "schema_version": "covenant.verify-result.v1",
            "verified": True,
            "run_id": self.run_id,
            "event_count": 5,
            "artifact_count": 0,
            "input_snapshot_count": 0,
            "failure_count": 0,
            "failures": [],
            "policy_explanations": [],
            "ledger_digest": NATIVE_COVENANT_LEDGER_SHA256,
            "last_event_hash": "c" * 64,
        }
        for field, replacement in (
            ("verified", False),
            ("event_count", 0),
            ("failure_count", 1),
            ("failures", [{"failure_id": "failure-000001"}]),
        ):
            value = dict(valid)
            value[field] = replacement
            with self.subTest(field=field):
                self._assert_code(
                    "governance-producer-readback",
                    lambda value=value: governance._readback(
                        "ao-covenant", json.dumps(value).encode()
                    ),
                )

    def test_covenant_policy_events_exactly_match_pack_decisions(self):
        mutations = {
            "decision": lambda event: event.update(decision="deny"),
            "task_id": lambda event: event.update(task_id="other-task"),
            "effect_type": lambda event: event.update(effect_type="process.spawn"),
            "resource": lambda event: event.update(resource="other-resource"),
            "reason": lambda event: event.update(message="different reason"),
            "approval_ticket": lambda event: event.update(
                approval_ticket_id="approval-bounded-1"
            ),
        }
        for name, mutate in mutations.items():
            events = self._native_success_events()
            mutate(events[2])
            with self.subTest(field=name):
                self._assert_ledger_rejected_after_verified_readback(events)

    def test_covenant_ledger_requires_successful_terminal_and_no_failed_events(self):
        cases = {}
        failed_task = self._native_success_events()
        failed_task[3]["status"] = "failed"
        cases["failed_event"] = failed_task
        failed_terminal = self._native_success_events()
        failed_terminal[-1]["status"] = "failed"
        cases["failed_terminal"] = failed_terminal
        missing_terminal = self._native_success_events()
        missing_terminal[-1]["type"] = "task_finished"
        missing_terminal[-1]["task_id"] = "bounded-task"
        cases["missing_terminal"] = missing_terminal
        after_terminal = self._native_success_events()
        after_terminal.append(
            {
                "type": "task_finished",
                "task_id": "bounded-task",
                "status": "success",
                "message": "event after terminal",
            }
        )
        cases["event_after_terminal"] = after_terminal
        for name, events in cases.items():
            with self.subTest(case=name):
                self._assert_ledger_rejected_after_verified_readback(events)

    def test_covenant_ledger_requires_strict_ndjson_and_sequential_unique_events(self):
        missing_newline = self._native_success_events()
        duplicate_identity = self._native_success_events()
        duplicate_identity[3]["_sequence"] = 3
        duplicate_identity[3]["_event_id"] = "event-000003"
        cases = (
            ("missing_final_newline", missing_newline, None, False),
            (
                "blank_line",
                self._native_success_events(),
                lambda raw: raw.replace(b"\n", b"\n\n", 1),
                True,
            ),
            ("duplicate_identity", duplicate_identity, None, True),
        )
        for name, events, transform, trailing_newline in cases:
            with self.subTest(case=name):
                self._assert_ledger_rejected_after_verified_readback(
                    events,
                    transform=transform,
                    trailing_newline=trailing_newline,
                )

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
            (self.covenant, "run_id", "run-fedcba9876543210"),
            (self.covenant, "ledger_digest", "0" * 64),
            (self.covenant, "run_status", "failed"),
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

    @unittest.skipIf(os.name == "nt", "POSIX ancestor rename race")
    def test_staged_ancestor_a_b_a_during_producer_open_fails_closed(self):
        sync = self.private_forge_runtime / "producer-sync"
        sync.joinpath("mode").write_text("staged-ancestor-aba", encoding="utf-8")
        office_pool = self.project / ".ao/governance/office-pool"
        parked = office_pool.with_name("office-pool-parked")
        replacement = office_pool.with_name("office-pool-replacement")
        attacker = None
        attack_errors = []

        def wait_for(path):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if path.exists():
                    return
                time.sleep(0.01)
            raise AssertionError(f"timed out waiting for {path.name}")

        def attack():
            try:
                wait_for(sync / "artifact-ready")
                shutil.copytree(office_pool, replacement)
                staged = tuple(
                    replacement.joinpath("producer-input").glob("ao-forge-*")
                )
                self.assertEqual(len(staged), 1)
                staged[0].chmod(0o600)
                staged[0].write_text(
                    '{"schema_version":"ao.forge.goal-run.v0.1","goal_id":"attacker"}',
                    encoding="utf-8",
                )
                office_pool.rename(parked)
                replacement.rename(office_pool)
                parked_sync = parked / "producer-runtime/ao-forge/producer-sync"
                parked_sync.joinpath("artifact-swapped").touch()
                wait_for(parked_sync / "artifact-read")
                office_pool.rename(replacement)
                parked.rename(office_pool)
                sync.joinpath("artifact-restored").touch()
            except BaseException as error:
                attack_errors.append(error)
                for root in (parked, office_pool):
                    candidate = root / "producer-runtime/ao-forge/producer-sync"
                    if candidate.is_dir():
                        candidate.joinpath("artifact-swapped").touch()
                        candidate.joinpath("artifact-restored").touch()

        run_output = governance._run_output

        def attack_during_run(arguments, *args, **kwargs):
            nonlocal attacker
            if arguments[:2] == ["goal", "validate"]:
                attacker = threading.Thread(target=attack)
                attacker.start()
            try:
                return run_output(arguments, *args, **kwargs)
            finally:
                if attacker is not None:
                    attacker.join(timeout=6)

        try:
            with mock.patch.object(
                governance, "_run_output", side_effect=attack_during_run
            ):
                self._assert_code(
                    "governance-artifact-changed",
                    lambda: issue_witness(
                        self.claim_path, self.task_text, self.valid_artifacts()
                    ),
                )
            self.assertIsNotNone(attacker)
            self.assertFalse(attacker.is_alive())
            if attack_errors:
                raise attack_errors[0]
            self.assertTrue(sync.joinpath("artifact-read").is_file())
        finally:
            if parked.exists():
                if office_pool.exists():
                    for path in office_pool.rglob("*"):
                        path.chmod(0o700 if path.is_dir() else 0o600)
                    office_pool.chmod(0o700)
                    shutil.rmtree(office_pool)
                parked.rename(office_pool)
            if replacement.exists():
                for path in replacement.rglob("*"):
                    path.chmod(0o700 if path.is_dir() else 0o600)
                replacement.chmod(0o700)
                shutil.rmtree(replacement)

    @unittest.skipIf(os.name == "nt", "POSIX ancestor rename race")
    def test_project_parent_a_b_a_keeps_producer_on_retained_project_bytes(self):
        sync = self.private_forge_runtime / "producer-sync"
        sync.joinpath("mode").write_text("project-parent-aba", encoding="utf-8")
        parked = self.base.with_name(self.base.name + "-parked")
        replacement = self.base.with_name(self.base.name + "-replacement")
        attacker = None
        attack_errors = []

        def wait_for(path):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if path.exists():
                    return
                time.sleep(0.01)
            raise AssertionError(f"timed out waiting for {path.name}")

        def remove_tree(path):
            for child in path.rglob("*"):
                child.chmod(0o700 if child.is_dir() else 0o600)
            path.chmod(0o700)
            shutil.rmtree(path)

        def attack():
            try:
                wait_for(sync / "artifact-ready")
                shutil.copytree(self.base, replacement)
                staged = tuple(
                    replacement.joinpath(
                        "project/.ao/governance/office-pool/producer-input"
                    ).glob("ao-forge-*")
                )
                self.assertEqual(len(staged), 1)
                value = json.loads(staged[0].read_text(encoding="utf-8"))
                value["continuation_prompt"] = "attacker replacement bytes"
                staged[0].chmod(0o600)
                staged[0].write_text(json.dumps(value), encoding="utf-8")

                self.base.rename(parked)
                replacement.rename(self.base)
                parked_sync = parked.joinpath(
                    "project/.ao/governance/office-pool/producer-runtime/ao-forge/producer-sync"
                )
                parked_sync.joinpath("artifact-swapped").touch()
                wait_for(parked_sync / "artifact-read")
                self.base.rename(replacement)
                parked.rename(self.base)
                sync.joinpath("artifact-restored").touch()
            except BaseException as error:
                attack_errors.append(error)
                for root in (parked, self.base):
                    candidate = root.joinpath(
                        "project/.ao/governance/office-pool/producer-runtime/ao-forge/producer-sync"
                    )
                    if candidate.is_dir():
                        candidate.joinpath("artifact-swapped").touch()
                        candidate.joinpath("artifact-restored").touch()

        run_output = governance._run_output

        def attack_during_run(arguments, *args, **kwargs):
            nonlocal attacker
            if arguments[:2] == ["goal", "validate"]:
                attacker = threading.Thread(target=attack)
                attacker.start()
            try:
                return run_output(arguments, *args, **kwargs)
            finally:
                if attacker is not None:
                    attacker.join(timeout=6)

        try:
            with mock.patch.object(
                governance, "_run_output", side_effect=attack_during_run
            ):
                envelope = issue_witness(
                    self.claim_path, self.task_text, self.valid_artifacts()
                )
            self.assertIsNotNone(attacker)
            self.assertFalse(attacker.is_alive())
            if attack_errors:
                raise attack_errors[0]
            self.assertTrue(sync.joinpath("artifact-read").is_file())
            self.assertFalse(sync.joinpath("attacker-read").exists())
            self.assertEqual(
                json.loads(envelope.read_text(encoding="utf-8"))["producer_artifacts"]
                ["ao-forge"]["artifact_sha256"],
                hashlib.sha256(self.forge.read_bytes()).hexdigest(),
            )
        finally:
            if parked.exists():
                if self.base.exists():
                    if replacement.exists():
                        remove_tree(replacement)
                    self.base.rename(replacement)
                parked.rename(self.base)
            if replacement.exists():
                remove_tree(replacement)

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
