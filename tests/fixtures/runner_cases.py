import os
import subprocess
import sys
import time
import unittest
from pathlib import Path


class RunnerCases(unittest.TestCase):
    def test_fast(self):
        time.sleep(0.2)
        self.assertTrue(True)

    def test_multiple_skipped_subtests(self):
        for name in ("first", "second"):
            with self.subTest(name=name):
                self.skipTest(f"reason-{name}")

    def test_hangs_with_child(self):
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
        )
        Path(os.environ["AO_RUNNER_FIXTURE_PID_FILE"]).write_text(
            str(child.pid), encoding="utf-8"
        )
        time.sleep(30)
