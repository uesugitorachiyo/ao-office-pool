import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = "ao-office-pool-v0.1.1-windows-x86_64.zip"
SIDECAR = f"{ARCHIVE}.sha256"


class StableReleaseDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.readme_first = (ROOT / "README-FIRST.md").read_text(encoding="utf-8")
        cls.quickstart = (ROOT / "docs" / "QUICKSTART.md").read_text(encoding="utf-8")
        cls.runbook = (ROOT / "docs" / "AI_OPERATOR_RUNBOOK.md").read_text(encoding="utf-8")
        cls.guide = (ROOT / "docs" / "OPERATOR_GUIDE.md").read_text(encoding="utf-8")
        cls.installer = (ROOT / "scripts" / "Install-And-Verify.ps1").read_text(
            encoding="utf-8"
        )
        cls.governance = (ROOT / "internal" / "governance_witness.py").read_text(
            encoding="utf-8"
        )
        cls.packager = (ROOT / "packaging" / "Install-AOOfficePool.ps1").read_text(
            encoding="utf-8"
        )

    def test_primary_install_path_is_public_and_single_command(self):
        self.assertIn("# AO Office Pool v0.1.1", self.readme)
        blocks = re.findall(r"```powershell\n(.*?)\n```", self.readme, re.DOTALL)
        self.assertGreaterEqual(len(blocks), 1)
        self.assertEqual(
            blocks[0].splitlines(),
            [
                "git clone https://github.com/uesugitorachiyo/ao-office-pool.git",
                "Set-Location .\\ao-office-pool",
                "pwsh -File .\\scripts\\Install-And-Verify.ps1",
            ],
        )
        primary = self.readme.split("## Contributor source qualification", 1)[0]
        self.assertNotIn("GITHUB_TOKEN", primary)
        self.assertNotIn("api.github.com", primary)
        self.assertNotIn("Visual Studio", primary)

    def test_readme_identifies_independent_project(self):
        self.assertIn("independent project", self.readme)
        self.assertIn(
            "not currently an official member of the AO Stack family", self.readme
        )

    def test_ai_prompt_runs_the_same_public_script_unchanged(self):
        self.assertIn(
            "Read README.md and docs/AI_OPERATOR_RUNBOOK.md completely", self.readme
        )
        self.assertIn("run scripts/Install-And-Verify.ps1 unchanged", self.readme)
        self.assertIn("return HOLD with the exact reported reason code", self.readme)

    def test_end_user_documents_name_current_assets_and_public_script(self):
        for name, text in {
            "README-FIRST.md": self.readme_first,
            "docs/QUICKSTART.md": self.quickstart,
            "docs/AI_OPERATOR_RUNBOOK.md": self.runbook,
            "docs/OPERATOR_GUIDE.md": self.guide,
        }.items():
            with self.subTest(document=name):
                self.assertIn(ARCHIVE, text)
                self.assertIn(SIDECAR, text)
                self.assertIn("Install-And-Verify.ps1", text)

    def test_user_path_states_exact_runtime_prerequisites_and_outcomes(self):
        primary = self.readme.split("## Contributor source qualification", 1)[0]
        for marker in (
            "Windows x86-64",
            "PowerShell 7",
            "Python 3.12",
            "Git",
            "VCRUNTIME140.dll",
            "does not verify a redistributable product or version",
            "READY FOR USE",
            "HOLD [",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, primary)

    def test_installed_command_examples_cover_the_lifecycle(self):
        primary = self.readme.split("## Contributor source qualification", 1)[0]
        for command in ("status", "claim", "resume", "run", "release", "recover"):
            with self.subTest(command=command):
                self.assertIn(f"& $Office {command}", primary)
        self.assertIn("outside the AO Office Pool installation", primary)
        self.assertIn("recovery-required", primary)

    def test_visual_studio_is_source_qualification_only(self):
        contributor = self.readme.split("## Contributor source qualification", 1)[1]
        self.assertIn("Visual Studio Build Tools 2022", contributor)
        self.assertIn("source qualification only", contributor)
        self.assertIn("not required to install or use", contributor)

    def test_advanced_documents_keep_public_install_as_the_entry_point(self):
        self.assertIn("../README.md#install", self.guide)
        self.assertNotIn("../README.md#acquire-the-private-release", self.guide)
        self.assertIn("READY FOR USE", self.runbook)
        self.assertIn("all five offices", self.runbook)
        self.assertIn("connected project", self.runbook)

    def test_run_uses_the_implementation_bound_governance_witness_path(self):
        self.assertIn('_PRIVATE_PARTS = (".ao", "governance", "office-pool")', self.governance)
        self.assertIn(r'_WITNESS = re.compile(r"^witness-[0-9a-f]{32}$")', self.governance)
        lifecycle = self.readme + "\n" + self.guide
        self.assertNotIn(".ao\\governance-envelope.json", lifecycle)
        self.assertIn(".ao\\governance\\office-pool", lifecycle)
        self.assertIn("witness-<32-lowercase-hex>.json", lifecycle)
        self.assertIn("exact witness path returned", lifecycle)
        self.assertIn("--envelope $Envelope", lifecycle)

    def test_runtime_dll_requirement_matches_the_installer_check(self):
        self.assertIn("[Environment]::SystemDirectory", self.installer)
        self.assertIn("VCRUNTIME140.dll", self.installer)
        end_user = "\n".join(
            (self.readme.split("## Contributor source qualification", 1)[0], self.readme_first, self.quickstart, self.runbook, self.guide)
        )
        self.assertNotIn("latest supported", end_user.casefold())
        self.assertNotIn("Microsoft Visual C++ v14 Redistributable", end_user)
        self.assertIn("presence of `VCRUNTIME140.dll` in the Windows system directory", end_user)
        self.assertIn("does not verify a redistributable product or version", end_user)

    def test_hold_guidance_applies_to_non_prerequisite_failures(self):
        self.assertIn("$failureCode = 'installation-failed'", self.installer)
        combined = self.readme + "\n" + self.runbook
        self.assertIn("exact reported reason code", combined)
        self.assertIn("next safe corrective action for that reason code", combined)
        self.assertIn("`installation-failed`", combined)
        self.assertNotIn("next safe prerequisite action", combined)

    def test_update_and_rollback_require_the_existing_install_root(self):
        self.assertIn("update or rollback requires an existing install", self.packager)
        advanced = self.guide.split("## Verified offline install, update, and rollback", 1)[1]
        self.assertIn("Install requires a new `InstallRoot`", advanced)
        self.assertIn("Update and Rollback require the existing `InstallRoot`", advanced)
        self.assertNotIn("use new drive-absolute local NTFS paths", advanced)

    def test_source_qualification_does_not_clobber_python_environment_state(self):
        contributor = self.readme.split("## Contributor source qualification", 1)[1]
        self.assertNotIn("PYTHONDONTWRITEBYTECODE", contributor)
        for command in re.findall(r"(?m)^\s*& \$Python (.+)$", contributor):
            if command.startswith('-c "import sys;'):
                continue
            self.assertTrue(command.startswith("-B "), command)

    def test_recovery_uses_the_claimed_office_and_generation(self):
        lifecycle = self.readme + "\n" + self.guide
        self.assertNotIn("--generation 1", lifecycle)
        self.assertIn("--office $Claim.office_id --generation $Claim.generation", lifecycle)
        self.assertIn("recovery-key-$($Claim.office_id)", lifecycle)

    def test_ai_returns_the_exact_usable_launcher_without_publishing_it(self):
        self.assertIn("Write-Output ('Launcher: & \"'", self.installer)
        self.assertIn("return the exact self-contained `Launcher:` line unchanged", self.runbook)
        self.assertIn("Do not publish or share that private local-path command", self.runbook)
        self.assertNotIn("sanitized launcher command", self.runbook)

    def test_source_qualification_is_repeatable_with_evidence_outside_checkout(self):
        contributor = self.readme.split("## Contributor source qualification", 1)[1]
        self.assertNotIn('.local/qualification', contributor)
        self.assertIn('$EvidenceRoot = Join-Path $QualificationRoot', contributor)
        self.assertIn('from scripts.build_release import build_release', contributor)
        self.assertIn('scripts/scan_public_tree.py $PublicTree', contributor)
        self.assertNotIn('scripts/scan_public_tree.py .', contributor)


if __name__ == "__main__":
    unittest.main()
