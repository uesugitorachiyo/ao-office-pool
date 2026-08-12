import dataclasses
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import internal.execution as execution_module
import internal.mission_bridge as mission_bridge
from internal.execution import (
    AtlasWorkgraph,
    BlueprintAuthorization,
    CovenantDecision,
    ExecutionError,
    ExecutionRequest,
    ForgePacket,
    execute,
)
from internal.mission_bridge import MissionReadback
from internal.planning_routes import select_route
from internal.pool import Pool, PoolError


FAKE_AO2 = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  const char *target = NULL, *run = NULL;
  for (int i = 1; i + 1 < argc; i++) {
    if (strcmp(argv[i], "--target") == 0) target = argv[i + 1];
    if (strcmp(argv[i], "--run-id") == 0) run = argv[i + 1];
  }
  if (!target || !run) return 64;
  const char *mode = getenv("AO_TEST_FAKE_AO2_MODE");
  if (mode && strcmp(mode, "sleep") == 0) sleep(5);
  if (mode && strcmp(mode, "large") == 0) {
    for (int i = 0; i < 70000; i++) fputc('x', stdout);
    fflush(stdout);
    sleep(5);
  }
  char path[4096];
  snprintf(path, sizeof(path), "%s/ao2-arguments.txt", target);
  FILE *arguments = fopen(path, "wb");
  if (!arguments) return 65;
  for (int i = 1; i < argc; i++) fprintf(arguments, "%s\n", argv[i]);
  fclose(arguments);
  snprintf(path, sizeof(path), "%s/ao2-output.txt", target);
  FILE *out = fopen(path, "wb");
  if (!out) return 66;
  fputs("executed\n", out);
  fclose(out);
  if (mode && strcmp(mode, "native-readback") == 0) {
    printf("run_id=%s\nstatus=Accepted\nrun_record=ignored\nevidence_dir=ignored\nreplay_state=accepted\nevidence_pack=ignored\nreport=ignored\n", run);
    return 0;
  }
  printf("{\"status\":\"accepted\",\"run_id\":\"%s\"}\n", run);
  return 0;
}
'''


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


@unittest.skipIf(os.name == "nt" and not os.environ.get("AO_TEST_FAKE_AO2"), "native fake AO2 required")
class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        self.pool_root = self.base / "pool"
        self.pool = Pool(self.pool_root, runtime_version="test-runtime")
        self.pool.initialize()
        self.task_text = "bounded task"
        self.claim_path = self.pool.claim("chat", self.task_text, self.project, "conversation")
        self.authority_raw = self.claim_path.read_bytes()
        self.authority = json.loads(self.authority_raw)
        self.project_path = Path(self.authority["project_path"])
        self.mission = self._mission()
        runtime = self.pool_root / "offices" / "O1" / "runtime" / "versions" / "test-runtime"
        runtime.mkdir(parents=True)
        self.executable = runtime / ("ao2.exe" if os.name == "nt" else "ao2")
        supplied = os.environ.get("AO_TEST_FAKE_AO2")
        if supplied:
            shutil.copy2(supplied, self.executable)
        else:
            source = self.base / "fake-ao2.c"
            source.write_text(FAKE_AO2, encoding="utf-8")
            subprocess.run(["cc", str(source), "-o", str(self.executable)], check=True)
        self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
        self.executable_digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.component_lock = self.base / "components.lock.json"
        self.component_lock.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "components": [
                        {
                            "name": "ao2",
                            "asset": "ao2",
                            "sha256": self.executable_digest,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.configuration = mock.patch.object(
            execution_module, "COMPONENT_LOCK", self.component_lock, create=True
        )
        self.configuration.start()
        self.workflow = self.project / "workflow.yaml"
        self.workflow.write_text("name: bounded\n", encoding="utf-8")
        self.request = self._request()

    def tearDown(self):
        self.configuration.stop()
        self.temporary_directory.cleanup()

    def _mission(self, route="ao-forge"):
        value = {
            "schema_version": 1,
            "mission_id": "mission-0123456789abcdef",
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
                record,
                value,
                self.authority_raw,
                mission_bridge.MISSION_SCHEMA,
            )
            record_path = record.path
        return MissionReadback(
            mission_id=value["mission_id"],
            objective_digest=value["objective_digest"],
            status="active",
            current_route=route,
            record=record_path,
            resumed=True,
        )

    @staticmethod
    def _replace(instance, field, value):
        return type(instance)(
            *(value if item.name == field else getattr(instance, item.name) for item in dataclasses.fields(instance))
        )

    def _request(self, *, target=None, workflow=None, authority=None, route=None):
        target = target or self.project_path
        route = route or select_route(self.mission)
        blueprint_value = {
            "schema_version": 1,
            "authorization_id": "blueprint-0123456789abcdef",
            "mission_id": self.mission.mission_id,
            "objective_digest": self.mission.objective_digest,
            "project_path": str(self.project_path),
            "decision": "authorized",
        }
        blueprint = BlueprintAuthorization(**blueprint_value, authorization_digest=digest(blueprint_value))
        forge_value = {
            "schema_version": 1,
            "packet_id": "forge-0123456789abcdef",
            "mission_id": self.mission.mission_id,
            "objective_digest": self.mission.objective_digest,
            "blueprint_digest": blueprint.authorization_digest,
            "atlas_digest": None,
            "project_path": str(self.project_path),
            "target_path": str(target),
            "workflow_path": str(workflow or self.workflow),
            "workflow_sha256": hashlib.sha256(
                (workflow or self.workflow).read_bytes()
            ).hexdigest(),
            "run_id": "run-0123456789abcdef",
        }
        forge = ForgePacket(**forge_value, packet_digest=digest(forge_value))
        covenant_value = {
            "schema_version": 1,
            "decision_id": "covenant-0123456789abcdef",
            "forge_digest": forge.packet_digest,
            "objective_digest": self.mission.objective_digest,
            "project_path": str(self.project_path),
            "target_path": str(target),
            "ao2_sha256": self.executable_digest,
            "decision": "authorized",
        }
        covenant = CovenantDecision(**covenant_value, decision_digest=digest(covenant_value))
        return ExecutionRequest(
            self.task_text,
            self.mission,
            route,
            authority or self.claim_path,
            blueprint,
            None,
            forge,
            covenant,
            self.executable,
            getattr(self, "executable_digest", "0" * 64),
            2,
        )

    def test_executes_exact_argument_array_and_records_bounded_result(self):
        result = execute(self.request)
        self.assertEqual(result.status, "accepted")
        self.assertEqual((self.project / "ao2-output.txt").read_text(), "executed\n")
        self.assertEqual(
            (self.project / "ao2-arguments.txt").read_text().splitlines(),
            [
                "run",
                str(self.workflow),
                "--target",
                str(self.project_path),
                "--run-id",
                "run-0123456789abcdef",
            ],
        )
        self.assertTrue(result.record.is_relative_to(self.project / ".ao"))
        record = json.loads(result.record.read_text())
        self.assertEqual(record["request_digest"], result.request_digest)
        self.assertEqual(record["ao2_sha256"], self.executable_digest)
        self.assertNotIn("stdout", record)
        self.assertEqual(set(record["diagnostics"]), {"status", "run_id"})

    def test_pool_accepts_only_the_exact_office_runtime_layout(self):
        self.pool.resume(self.claim_path)
        rogue = self.executable.parent / "unverified.bin"
        rogue.write_bytes(b"unverified")
        with self.assertRaises(PoolError) as raised:
            self.pool.resume(self.claim_path)
        self.assertEqual(raised.exception.code, "recovery-required")

    def test_wrong_receipt_generation_or_project_fails_before_launch(self):
        other_project = self.base / "other-project"
        other_project.mkdir()
        other_pool = Pool(self.base / "other-pool")
        other_pool.initialize()
        wrong_receipt = other_pool.claim("other", self.task_text, other_project, "conversation")
        cases = [
            self._request(authority=wrong_receipt),
            self._replace(self.request, "task_text", "wrong"),
        ]
        for request in cases:
            with self.subTest(request=request):
                with self.assertRaises(ExecutionError):
                    execute(request)
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_atlas_workgraph_is_required_and_digest_bound_when_routed(self):
        routed = self._mission("ao-atlas")
        route = select_route(routed)
        request = dataclasses.replace(self.request, mission=routed, route=route)
        with self.assertRaises(ExecutionError) as raised:
            execute(request)
        self.assertEqual(raised.exception.code, "atlas-required")
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_validated_atlas_workgraph_can_reach_governed_execution(self):
        mission = self._mission("ao-atlas")
        route = select_route(mission)
        atlas_value = {
            "schema_version": 1,
            "workgraph_id": "atlas-0123456789abcdef",
            "mission_id": mission.mission_id,
            "objective_digest": mission.objective_digest,
            "blueprint_digest": self.request.blueprint.authorization_digest,
            "project_path": str(self.project_path),
            "status": "validated",
        }
        atlas = AtlasWorkgraph(
            **atlas_value, workgraph_digest=digest(atlas_value)
        )
        forge_value = dataclasses.asdict(self.request.forge)
        forge_value.pop("packet_digest")
        forge_value["atlas_digest"] = atlas.workgraph_digest
        forge = ForgePacket(**forge_value, packet_digest=digest(forge_value))
        covenant_value = dataclasses.asdict(self.request.covenant)
        covenant_value.pop("decision_digest")
        covenant_value["forge_digest"] = forge.packet_digest
        covenant = CovenantDecision(
            **covenant_value, decision_digest=digest(covenant_value)
        )
        result = execute(
            dataclasses.replace(
                self.request,
                mission=mission,
                route=route,
                atlas=atlas,
                forge=forge,
                covenant=covenant,
            )
        )
        self.assertEqual(result.status, "accepted")

    def test_connected_project_output_identity(self):
        sibling = self.base / "sibling"
        sibling.mkdir()
        with self.assertRaises(ExecutionError) as raised:
            execute(self._request(target=sibling))
        self.assertEqual(raised.exception.code, "target-mismatch")
        self.assertFalse((sibling / "ao2-output.txt").exists())

    def test_pool_and_sibling_targets_are_rejected(self):
        for target in (self.pool_root, self.pool_root / "offices" / "O2", self.base):
            with self.subTest(target=target):
                with self.assertRaises(ExecutionError):
                    execute(self._request(target=target))

    def test_path_option_escape_is_rejected(self):
        escaped = self.project / "--target"
        escaped.write_text("x", encoding="utf-8")
        with self.assertRaises(ExecutionError) as raised:
            execute(self._request(workflow=escaped))
        self.assertEqual(raised.exception.code, "unsafe-argument")

    def test_workflow_digest_tampering_fails_before_launch(self):
        self.workflow.write_text("name: substituted\n", encoding="utf-8")
        with self.assertRaises(ExecutionError) as raised:
            execute(self.request)
        self.assertEqual(raised.exception.code, "forge-mismatch")
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_shell_metacharacters_are_literal_arguments(self):
        marker = self.base / "marker"
        workflow = self.project / f"workflow;touch {marker.name}.yaml"
        workflow.write_text("name: literal\n", encoding="utf-8")
        result = execute(self._request(workflow=workflow))
        self.assertEqual(result.status, "accepted")
        self.assertFalse(marker.exists())

    def test_native_ao2_allowlisted_readback_is_accepted(self):
        old = os.environ.get("AO_TEST_FAKE_AO2_MODE")
        os.environ["AO_TEST_FAKE_AO2_MODE"] = "native-readback"
        try:
            result = execute(self.request)
        finally:
            if old is None:
                os.environ.pop("AO_TEST_FAKE_AO2_MODE", None)
            else:
                os.environ["AO_TEST_FAKE_AO2_MODE"] = old
        self.assertEqual(result.status, "accepted")
        self.assertEqual(
            result.diagnostics,
            {"status": "accepted", "run_id": "run-0123456789abcdef"},
        )

    def test_timeout_kills_process_and_records_failure(self):
        old = os.environ.get("AO_TEST_FAKE_AO2_MODE")
        os.environ["AO_TEST_FAKE_AO2_MODE"] = "sleep"
        try:
            request = dataclasses.replace(self.request, timeout_seconds=1)
            with self.assertRaises(ExecutionError) as raised:
                execute(request)
            self.assertEqual(raised.exception.code, "execution-timeout")
        finally:
            if old is None:
                os.environ.pop("AO_TEST_FAKE_AO2_MODE", None)
            else:
                os.environ["AO_TEST_FAKE_AO2_MODE"] = old
        failures = list((self.project / ".ao" / "evidence" / "office-pool").glob("*.json"))
        self.assertEqual(len(failures), 1)
        self.assertEqual(json.loads(failures[0].read_text())["phase"], "failed")

    def test_runtime_tampering_fails_before_launch(self):
        self.executable.write_bytes(self.executable.read_bytes() + b"tamper")
        with self.assertRaises(ExecutionError) as raised:
            execute(self.request)
        self.assertEqual(raised.exception.code, "ao2-identity-mismatch")
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_runtime_and_request_cannot_substitute_the_locked_ao2(self):
        self.executable.write_bytes(self.executable.read_bytes() + b"substitution")
        substituted = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        value = dataclasses.asdict(self.request.covenant)
        value.pop("decision_digest")
        value["ao2_sha256"] = substituted
        covenant = CovenantDecision(**value, decision_digest=digest(value))
        request = dataclasses.replace(
            self.request, ao2_sha256=substituted, covenant=covenant
        )
        with self.assertRaises(ExecutionError) as raised:
            execute(request)
        self.assertEqual(raised.exception.code, "ao2-identity-mismatch")
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_route_decision_cannot_bypass_the_fixed_rule_table(self):
        route = dataclasses.replace(
            select_route(self.mission),
            route="ao-blueprint",
            execution_candidate=False,
        )
        request = dataclasses.replace(self.request, route=route)
        with self.assertRaises(ExecutionError) as raised:
            execute(request)
        self.assertEqual(raised.exception.code, "route-mismatch")
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_caller_mission_route_cannot_override_authenticated_record(self):
        # MUTATION: deriving authority from this caller value accepts an Atlas route.
        mission = dataclasses.replace(self.mission, current_route="ao-atlas")
        request = dataclasses.replace(
            self.request, mission=mission, route=select_route(mission)
        )
        with self.assertRaises(ExecutionError) as raised:
            execute(request)
        self.assertEqual(raised.exception.code, "mission-mismatch")
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_covenant_digest_mismatch_fails_before_launch(self):
        bad = dataclasses.replace(self.request.covenant, forge_digest="0" * 64)
        with self.assertRaises(ExecutionError) as raised:
            execute(dataclasses.replace(self.request, covenant=bad))
        self.assertEqual(raised.exception.code, "covenant-mismatch")
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_unknown_evidence_fields_are_impossible(self):
        with self.assertRaises(TypeError):
            BlueprintAuthorization(
                schema_version=1,
                authorization_id="blueprint-0123456789abcdef",
                mission_id=self.mission.mission_id,
                objective_digest=self.mission.objective_digest,
                project_path=str(self.project_path),
                decision="authorized",
                authorization_digest="0" * 64,
                extra=True,
            )

    def test_malformed_evidence_fails_closed_before_launch(self):
        value = dataclasses.asdict(self.request.blueprint)
        value.pop("authorization_digest")
        value["authorization_id"] = 1
        blueprint = BlueprintAuthorization(
            **value, authorization_digest=digest(value)
        )
        with self.assertRaises(ExecutionError) as raised:
            execute(dataclasses.replace(self.request, blueprint=blueprint))
        self.assertEqual(raised.exception.code, "blueprint-mismatch")
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_json_boolean_cannot_replace_integer_schema_version(self):
        value = dataclasses.asdict(self.request.blueprint)
        value.pop("authorization_digest")
        value["schema_version"] = True
        blueprint = BlueprintAuthorization(
            **value, authorization_digest=digest(value)
        )
        with self.assertRaises(ExecutionError) as raised:
            execute(dataclasses.replace(self.request, blueprint=blueprint))
        self.assertEqual(raised.exception.code, "blueprint-mismatch")

    @unittest.skipIf(os.name == "nt", "verified copy is POSIX-only")
    def test_verified_copy_digest_must_match_locked_source_before_launch(self):
        # MUTATION: hashing only the retained source can launch different copied bytes.
        real_write = execution_module.os.write
        adulterated = False

        def adulterate(descriptor, data):
            nonlocal adulterated
            value = bytes(data)
            if not adulterated:
                value = bytes([value[0] ^ 0xFF]) + value[1:]
                adulterated = True
            return real_write(descriptor, value)

        with mock.patch.object(execution_module.os, "write", side_effect=adulterate):
            with self.assertRaises(ExecutionError) as raised:
                execute(self.request)
        self.assertEqual(raised.exception.code, "ao2-identity-mismatch")
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_verified_copy_handles_partial_writes(self):
        real_write = execution_module.os.write

        def partial(descriptor, data):
            return real_write(descriptor, data[: max(1, len(data) // 2)])

        with mock.patch.object(execution_module.os, "write", side_effect=partial):
            result = execute(self.request)
        self.assertEqual(result.status, "accepted")

    def test_live_oversized_output_is_killed_and_recorded(self):
        old = os.environ.get("AO_TEST_FAKE_AO2_MODE")
        os.environ["AO_TEST_FAKE_AO2_MODE"] = "large"
        try:
            with self.assertRaises(ExecutionError) as raised:
                execute(self.request)
        finally:
            if old is None:
                os.environ.pop("AO_TEST_FAKE_AO2_MODE", None)
            else:
                os.environ["AO_TEST_FAKE_AO2_MODE"] = old
        self.assertEqual(raised.exception.code, "execution-output-too-large")
        self.assertEqual(json.loads(raised.exception.record.read_text())["phase"], "failed")

    def test_repeated_request_preserves_both_execution_records(self):
        first = execute(self.request)
        second = execute(self.request)
        self.assertNotEqual(first.record, second.record)
        self.assertTrue(first.record.is_file())
        self.assertTrue(second.record.is_file())


if __name__ == "__main__":
    unittest.main()
