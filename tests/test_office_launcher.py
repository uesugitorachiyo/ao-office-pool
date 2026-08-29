import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from internal.pool import Pool


ROOT = Path(__file__).parents[1]
LAUNCHER = ROOT / "bin" / "ao-office-pool.ps1"


class OfficeLauncherTests(unittest.TestCase):
    def test_launcher_uses_python_312_and_its_own_installation_root(self):
        text = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("sys.version_info[:2] == (3, 12)", text)
        self.assertIn("$PSScriptRoot", text)
        self.assertIn("cmd\\ao_office_pool.py", text)
        self.assertIn("exit $LASTEXITCODE", text)

    def test_launcher_forwards_status_from_an_unrelated_directory(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("PowerShell is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            install = base / "install"
            shutil.copytree(ROOT / "cmd", install / "cmd")
            shutil.copytree(ROOT / "internal", install / "internal")
            shutil.copytree(ROOT / "schemas", install / "schemas")
            (install / "bin").mkdir()
            shutil.copy2(LAUNCHER, install / "bin" / LAUNCHER.name)
            Pool(install, runtime_version="v-test").initialize()
            unrelated = base / "unrelated"
            unrelated.mkdir()
            completed = subprocess.run(
                [powershell, "-NoProfile", "-File", str(install / "bin" / LAUNCHER.name), "status"],
                cwd=unrelated,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["command"], "status")

    def test_install_and_verify_preflight_python_312(self):
        for relative in (
            "packaging/Install-AOOfficePool.ps1",
            "packaging/Verify-AOOfficePool.ps1",
        ):
            with self.subTest(relative=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn("sys.version_info[:2] == (3, 12)", text)
                self.assertIn("requires Python 3.12", text)


if __name__ == "__main__":
    unittest.main()
