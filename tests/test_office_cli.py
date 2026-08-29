import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from internal.pool import Pool, PoolError


REPOSITORY_ROOT = Path(__file__).parents[1]
CLI = REPOSITORY_ROOT / "cmd" / "ao_office_pool.py"


class OfficeCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name).resolve()
        self.root = self.base / "pool"
        self.project = self.base / "project"
        self.project.mkdir()
        Pool(self.root, runtime_version="v-test").initialize()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-B", str(CLI), "--root", str(self.root), *arguments],
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )

    def success(self, completed, command):
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        value = json.loads(completed.stdout)
        self.assertEqual(value["schema_version"], 1)
        self.assertEqual(value["command"], command)
        self.assertEqual(value["status"], "ok")
        self.assertEqual(completed.stdout.count("\n"), 1)
        return value

    def error(self, completed, command, code, returncode=2):
        self.assertEqual(completed.returncode, returncode)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(
            json.loads(completed.stderr),
            {
                "schema_version": 1,
                "command": command,
                "status": "error",
                "code": code,
            },
        )
        self.assertNotIn("Traceback", completed.stderr)
        self.assertEqual(completed.stderr.count("\n"), 1)

    def claim(self, owner="owner-a", task="task-a"):
        return self.success(
            self.cli(
                "claim",
                "--owner",
                owner,
                "--task",
                task,
                "--project",
                str(self.project),
                "--mode",
                "pinned",
            ),
            "claim",
        )

    def test_status_reports_the_five_free_offices(self):
        value = self.success(self.cli("status"), "status")
        self.assertEqual(
            value["offices"],
            [
                {"office_id": f"O{number}", "status": "free", "generation": 0}
                for number in range(1, 6)
            ],
        )

    def test_claim_resume_and_release_use_the_protected_receipt(self):
        claimed = self.claim()
        self.assertEqual(claimed["office_id"], "O1")
        self.assertEqual(claimed["generation"], 1)
        authority_path = claimed["authority_path"]

        resumed = self.success(self.cli("resume", "--receipt", authority_path), "resume")
        self.assertEqual(resumed["authority_path"], authority_path)
        self.assertEqual(resumed["office_id"], "O1")
        self.assertEqual(resumed["generation"], 1)

        released = self.success(self.cli("release", "--receipt", authority_path), "release")
        self.assertEqual(released, {"schema_version": 1, "command": "release", "status": "ok"})
        self.assertEqual(self.success(self.cli("status"), "status")["offices"][0]["status"], "free")

    def test_sixth_claim_fails_closed_as_pool_full(self):
        for number in range(5):
            self.claim(f"owner-{number}", f"task-{number}")
        self.error(
            self.cli(
                "claim",
                "--owner",
                "owner-6",
                "--task",
                "task-6",
                "--project",
                str(self.project),
                "--mode",
                "pinned",
            ),
            "claim",
            "pool-full",
        )

    def test_recover_requires_the_exact_office_key_and_generation(self):
        claimed = self.claim()
        authority_path = Path(claimed["authority_path"])
        residue = self.root / "offices" / "O1" / "work" / "unknown.bin"
        residue.write_bytes(b"unknown")
        with self.assertRaises(PoolError):
            Pool(self.root, runtime_version="v-test").release(authority_path)

        value = self.success(
            self.cli(
                "recover",
                "--key",
                str(self.root / "operator-secrets" / "recovery-key-O1"),
                "--office",
                "O1",
                "--generation",
                "1",
            ),
            "recover",
        )
        self.assertEqual(value["office_id"], "O1")
        self.assertEqual(value["generation"], 1)

    def test_run_failure_is_bounded_json_without_a_traceback(self):
        authority_path = self.claim()["authority_path"]
        missing = self.base / "missing-envelope.json"
        self.error(
            self.cli("run", "--receipt", authority_path, "--envelope", str(missing)),
            "run",
            "governance-envelope-mismatch",
        )

    def test_malformed_arguments_are_bounded_json(self):
        self.error(self.cli("claim"), "claim", "invalid-arguments")


if __name__ == "__main__":
    unittest.main()
