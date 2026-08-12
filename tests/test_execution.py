import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import internal.execution as execution_module
import internal.mission_bridge as mission_bridge
from internal.execution import ExecutionError, execute
from internal.governance_witness import issue_witness
from tests import test_governance_witness as witness_tests


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
  if (argc < 3 || !target || !run) return 64;
  const char *mode = getenv("AO_TEST_FAKE_AO2_MODE");
  if (mode && (strcmp(mode, "child-timeout") == 0 || strcmp(mode, "child-large") == 0)) {
    pid_t child = fork();
    if (child < 0) return 71;
    if (child == 0) {
      FILE *pid_file = fopen("ao2-child-pid", "wb");
      if (pid_file) { fprintf(pid_file, "%d", getpid()); fclose(pid_file); }
      close(1); close(2); sleep(30); return 0;
    }
    usleep(50000);
    if (strcmp(mode, "child-timeout") == 0) sleep(30);
    char output[70000]; memset(output, 'x', sizeof(output));
    fwrite(output, 1, sizeof(output), stdout); fflush(stdout); sleep(30);
  }
  FILE *arguments = fopen("ao2-arguments.txt", "wb");
  if (!arguments) return 65;
  for (int i = 1; i < argc; i++) fprintf(arguments, "%s\n", argv[i]);
  fclose(arguments);
  FILE *workflow = fopen(argv[2], "rb");
  FILE *workflow_copy = fopen("ao2-workflow.txt", "wb");
  if (!workflow || !workflow_copy) return 66;
  int byte;
  while ((byte = fgetc(workflow)) != EOF) fputc(byte, workflow_copy);
  fclose(workflow); fclose(workflow_copy);
  FILE *out = fopen("ao2-output.txt", "wb");
  if (!out) return 67;
  fputs("executed\n", out);
  fclose(out);
  if (mode && strcmp(mode, "native-readback") == 0) {
    printf("run_id=%s\nstatus=Accepted\nrun_record=ignored\nevidence_dir=ignored\nreplay_state=accepted\nevidence_pack=ignored\nreport=ignored\n", run);
    return 0;
  }
  if (mode && strcmp(mode, "json-list") == 0) { puts("[]"); return 0; }
  if (mode && strcmp(mode, "wrong-types") == 0) {
    printf("{\"status\":1,\"run_id\":%s}\n", "true"); return 0;
  }
  if (mode && strcmp(mode, "invalid-utf8") == 0) {
    fputc(0xff, stdout); return 0;
  }
  printf("{\"status\":\"accepted\",\"run_id\":\"%s\"}\n", run);
  return 0;
}
'''


@unittest.skipIf(
    os.name == "nt" and not os.environ.get("AO_TEST_FAKE_AO2"),
    "native fake AO2 required",
)
class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.harness = witness_tests.GovernanceWitnessTests(
            "test_consumption_is_atomic_and_one_use"
        )
        self.harness.setUp()
        self.addCleanup(self.harness.tearDown)
        self.addCleanup(os.environ.pop, "AO_TEST_FAKE_AO2_MODE", None)
        self.base = self.harness.base
        self.project = self.harness.project
        self.pool = self.harness.pool
        self.claim_path = self.harness.claim_path
        runtime = (
            self.harness.pool_root
            / "offices"
            / self.harness.authority["office_id"]
            / "runtime"
            / "versions"
            / "test-runtime"
        )
        runtime.mkdir(parents=True)
        self.executable = runtime / ("ao2.exe" if os.name == "nt" else "ao2")
        supplied = os.environ.get("AO_TEST_FAKE_AO2")
        if supplied:
            shutil.copy2(supplied, self.executable)
        else:
            self._compile(FAKE_AO2, self.executable)
        self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
        self.executable_digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        for component in self.harness.components:
            if component["name"] == "ao2":
                component["sha256"] = self.executable_digest
        self.harness._write_lock()
        covenant = json.loads(self.harness.covenant.read_text(encoding="utf-8"))
        covenant["ao2_sha256"] = self.executable_digest
        self.harness.covenant.write_text(json.dumps(covenant), encoding="utf-8")
        self.malicious = self.base / ("malicious.exe" if os.name == "nt" else "malicious")
        if supplied:
            shutil.copy2(supplied, self.malicious)
        else:
            self._compile(
                FAKE_AO2.replace('fputs("executed\\n", out);', 'fputs("substituted\\n", out);'),
                self.malicious,
            )
        self.malicious.chmod(self.malicious.stat().st_mode | stat.S_IXUSR)
        self.envelope = self._witness()

    def _compile(self, source: str, output: Path) -> None:
        source_path = self.base / (output.stem + "-source.c")
        source_path.write_text(source, encoding="utf-8")
        subprocess.run(["cc", str(source_path), "-o", str(output)], check=True)

    def _witness(self) -> Path:
        return issue_witness(
            self.claim_path,
            self.harness.task_text,
            self.harness.valid_artifacts(),
        )

    def _replace_verified_copy(self, verified) -> None:
        replacement = verified.path.with_name("replacement-" + verified.path.name)
        shutil.copy2(self.malicious, replacement)
        os.replace(replacement, verified.path)

    def _replace_workflow_stage(self) -> None:
        staging = (
            self.project
            / ".ao"
            / "governance"
            / "office-pool"
            / "staging"
            / hashlib.sha256(self.harness.workflow.read_bytes()).hexdigest()
        )
        replacement = staging.with_name("replacement-workflow")
        replacement.write_text("name: substituted\n", encoding="utf-8")
        os.replace(replacement, staging)

    def _assert_child_dead(self) -> None:
        child = int((self.project / "ao2-child-pid").read_text(encoding="utf-8"))
        try:
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
        finally:
            try:
                os.kill(child, 9)
            except ProcessLookupError:
                pass

    def test_executes_only_envelope_bound_objects_and_relative_target(self):
        # MUTATION: reopening caller paths exposes absolute workflow/target pathnames.
        result = execute(self.claim_path, self.envelope, timeout_seconds=30)
        self.assertEqual(result.status, "accepted")
        arguments = (self.project / "ao2-arguments.txt").read_text().splitlines()
        self.assertEqual(arguments[0], "run")
        self.assertEqual(arguments[2:], ["--target", ".", "--run-id", self.harness.run_id])
        if os.name == "nt":
            self.assertEqual(Path(arguments[1]).name, self.harness.workflow_digest if hasattr(self.harness, "workflow_digest") else hashlib.sha256(self.harness.workflow.read_bytes()).hexdigest())
        else:
            self.assertTrue(
                arguments[1].startswith(
                    "/dev/fd/" if sys.platform == "darwin" else "/proc/self/fd/"
                ),
                arguments[1],
            )
        self.assertEqual((self.project / "ao2-workflow.txt").read_bytes(), self.harness.workflow.read_bytes())
        record = json.loads(result.record.read_text(encoding="utf-8"))
        self.assertEqual(record["request_digest"], result.request_digest)
        self.assertEqual(record["ao2_sha256"], self.executable_digest)
        self.assertNotIn("stdout", record)

    def test_verified_ao2_path_replacement_never_runs_substituted_bytes(self):
        # MUTATION: pathname launch after verification runs attacker replacement bytes.
        real_run = mission_bridge._run_output

        def replace_then_run(arguments, project, executable, **options):
            try:
                self._replace_verified_copy(executable)
            except OSError:
                pass
            return real_run(arguments, project, executable, **options)

        with mock.patch.object(execution_module, "_run_output", replace_then_run):
            if sys.platform == "darwin":
                with self.assertRaises(ExecutionError) as raised:
                    execute(self.claim_path, self.envelope)
                self.assertEqual(raised.exception.code, "execution-launch-failed")
            else:
                execute(self.claim_path, self.envelope)
        output = self.project / "ao2-output.txt"
        self.assertFalse(output.exists() and output.read_text() == "substituted\n")

    def test_project_delete_recreate_never_redirects_child_cwd(self):
        # MUTATION: pathname cwd after verification redirects AO2 into a replacement project.
        parked = self.project.with_name("retained-project")

        def replace_project():
            try:
                os.replace(self.project, parked)
                self.project.mkdir()
            except OSError:
                pass

        if sys.platform == "darwin":
            real_verify = mission_bridge._darwin_verify_suspended

            def replace_after_spawn(pid, project_descriptor, executable):
                replace_project()
                return real_verify(pid, project_descriptor, executable)

            patcher = mock.patch.object(
                mission_bridge, "_darwin_verify_suspended", replace_after_spawn
            )
        else:
            real_popen = mission_bridge.subprocess.Popen

            def replace_before_create(*arguments, **options):
                replace_project()
                return real_popen(*arguments, **options)

            patcher = mock.patch.object(mission_bridge.subprocess, "Popen", replace_before_create)
        with patcher:
            execute(self.claim_path, self.envelope)
        retained = parked if parked.exists() else self.project
        self.assertTrue((retained / "ao2-output.txt").is_file())
        if parked.exists():
            self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_authenticated_target_substitution_is_rejected_before_launch(self):
        # MUTATION: trusting a caller-edited target redirects governed execution.
        value = json.loads(self.envelope.read_text(encoding="utf-8"))
        value["target"]["canonical_path"] = str(self.base / "substituted")
        payload = dict(value)
        payload.pop("payload_digest")
        value["payload_digest"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.envelope.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        with self.assertRaises(ExecutionError):
            execute(self.claim_path, self.envelope)
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_workflow_path_replacement_uses_retained_digest_copy(self):
        # MUTATION: reopening the staging pathname launches a substituted workflow.
        real_run = mission_bridge._run_output

        def replace_then_run(arguments, project, executable, **options):
            try:
                self._replace_workflow_stage()
            except OSError:
                pass
            return real_run(arguments, project, executable, **options)

        with mock.patch.object(execution_module, "_run_output", replace_then_run):
            execute(self.claim_path, self.envelope)
        self.assertEqual(
            (self.project / "ao2-workflow.txt").read_bytes(),
            self.harness.workflow.read_bytes(),
        )

    @unittest.skipIf(os.name == "nt", "POSIX process-group assertion")
    def test_timeout_kills_complete_process_tree(self):
        # MUTATION: killing only the AO2 leader leaves its child alive.
        os.environ["AO_TEST_FAKE_AO2_MODE"] = "child-timeout"
        with self.assertRaises(ExecutionError) as raised:
            execute(self.claim_path, self.envelope, timeout_seconds=1)
        self.assertEqual(raised.exception.code, "execution-timeout")
        self._assert_child_dead()
        self.assertEqual(json.loads(raised.exception.record.read_text())["phase"], "failed")

    @unittest.skipIf(os.name == "nt", "POSIX process-group assertion")
    def test_output_overflow_kills_complete_process_tree(self):
        # MUTATION: killing only the AO2 leader on overflow leaves its child alive.
        os.environ["AO_TEST_FAKE_AO2_MODE"] = "child-large"
        with self.assertRaises(ExecutionError) as raised:
            execute(self.claim_path, self.envelope)
        self.assertEqual(raised.exception.code, "execution-output-too-large")
        self._assert_child_dead()
        self.assertEqual(json.loads(raised.exception.record.read_text())["phase"], "failed")

    def test_envelope_is_one_use(self):
        # MUTATION: omitting atomic consumption permits replayed execution.
        execute(self.claim_path, self.envelope)
        with self.assertRaises(ExecutionError) as raised:
            execute(self.claim_path, self.envelope)
        self.assertEqual(raised.exception.code, "governance-envelope-consumed")

    def test_native_ao2_allowlisted_readback_is_accepted(self):
        os.environ["AO_TEST_FAKE_AO2_MODE"] = "native-readback"
        result = execute(self.claim_path, self.envelope)
        self.assertEqual(
            result.diagnostics,
            {"status": "accepted", "run_id": self.harness.run_id},
        )

    def test_malformed_ao2_output_is_normalized_and_recorded(self):
        # MUTATION: assuming decoded JSON is a dict leaks TypeError/AttributeError.
        for mode in ("json-list", "wrong-types", "invalid-utf8"):
            with self.subTest(mode=mode):
                envelope = self.envelope if mode == "json-list" else self._witness()
                os.environ["AO_TEST_FAKE_AO2_MODE"] = mode
                with self.assertRaises(ExecutionError) as raised:
                    execute(self.claim_path, envelope)
                self.assertEqual(raised.exception.code, "invalid-execution-readback")
                self.assertEqual(
                    json.loads(raised.exception.record.read_text())["phase"], "failed"
                )

    def test_runtime_tampering_fails_before_launch(self):
        # MUTATION: trusting only the envelope AO2 name accepts changed runtime bytes.
        self.executable.write_bytes(self.executable.read_bytes() + b"tamper")
        with self.assertRaises(ExecutionError) as raised:
            execute(self.claim_path, self.envelope)
        self.assertEqual(raised.exception.code, "ao2-identity-mismatch")
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_fresh_witnesses_preserve_distinct_execution_records(self):
        # MUTATION: a fixed record name overwrites the prior governed result.
        first = execute(self.claim_path, self.envelope)
        second = execute(self.claim_path, self._witness())
        self.assertNotEqual(first.record, second.record)
        self.assertTrue(first.record.is_file())
        self.assertTrue(second.record.is_file())


if __name__ == "__main__":
    unittest.main()
