import ctypes
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "scripts" / "run_windows_tests.py"


def _is_running(pid):
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong()
        if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return False
        return exit_code.value == 259
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


@unittest.skipUnless(os.name == "nt", "Windows runner requires Windows")
class WindowsTestRunnerTests(unittest.TestCase):
    def run_runner(self, root, test_name, *, timeout):
        evidence = root / "evidence"
        task_root = root / "task"
        pid_file = root / "child.pid"
        environment = os.environ.copy()
        environment["AO_RUNNER_FIXTURE_PID_FILE"] = str(pid_file)
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(RUNNER),
                "--evidence-dir",
                str(evidence),
                "--task-root",
                str(task_root),
                "--test-timeout",
                str(timeout),
                "--sample-interval",
                "0.1",
                test_name,
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
        )
        return completed, evidence, pid_file

    def test_success_writes_machine_readable_test_and_resource_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            completed, evidence, _pid_file = self.run_runner(
                Path(temporary),
                "tests.fixtures.runner_cases.RunnerCases.test_fast",
                timeout=5,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = json.loads((evidence / "summary.json").read_text(encoding="utf-8"))
            events = [
                json.loads(line)
                for line in (evidence / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            samples = [
                json.loads(line)
                for line in (evidence / "samples.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(summary["result"], "PASS")
            self.assertFalse(summary["task_root_residue"])
            self.assertEqual(events[-1]["outcome"], "success")
            self.assertTrue(samples)
            self.assertIn(summary["worker_pid"], samples[0]["process_ids"])
            self.assertGreater(samples[0]["handle_count"], 0)
            self.assertGreater(samples[0]["private_bytes"], 0)

    def test_each_skipped_subtest_keeps_its_identity_and_reason(self):
        with tempfile.TemporaryDirectory() as temporary:
            completed, evidence, _pid_file = self.run_runner(
                Path(temporary),
                "tests.fixtures.runner_cases.RunnerCases.test_multiple_skipped_subtests",
                timeout=5,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            events = [
                json.loads(line)
                for line in (evidence / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            skips = [event for event in events if event["event"] == "skip"]
            self.assertEqual(
                [(event["test"], event["skip_reason"]) for event in skips],
                [
                    (
                        "tests.fixtures.runner_cases.RunnerCases."
                        "test_multiple_skipped_subtests (name='first')",
                        "reason-first",
                    ),
                    (
                        "tests.fixtures.runner_cases.RunnerCases."
                        "test_multiple_skipped_subtests (name='second')",
                        "reason-second",
                    ),
                ],
            )

    def test_timeout_names_active_test_and_ends_the_worker_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            completed, evidence, pid_file = self.run_runner(
                Path(temporary),
                "tests.fixtures.runner_cases.RunnerCases.test_hangs_with_child",
                timeout=1,
            )

            self.assertEqual(completed.returncode, 124, completed.stderr)
            summary = json.loads((evidence / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["result"], "TIMEOUT")
            self.assertEqual(
                summary["active_test"],
                "tests.fixtures.runner_cases.RunnerCases.test_hangs_with_child",
            )
            self.assertTrue(summary["worker_tree_ended"])
            child_pid = int(pid_file.read_text(encoding="utf-8"))
            self.assertFalse(_is_running(child_pid))


if __name__ == "__main__":
    unittest.main()
