import json
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote

from scripts.verify_bootstrap_contract import verify_bootstrap_tree, verify_release_manifest


ROOT = Path(__file__).parents[1]
DOCUMENTS = (
    "README.md",
    "README-FIRST.md",
    "docs/QUICKSTART.md",
    "docs/AI_OPERATOR_RUNBOOK.md",
    "docs/OPERATOR_GUIDE.md",
)


class BootstrapContractTests(unittest.TestCase):
    def test_public_release_allowlist_admits_the_installed_launcher(self):
        value = json.loads(
            (ROOT / "manifests/public-tree.json").read_text(encoding="utf-8")
        )
        self.assertIn("bin", value["tracked_roots"])

    def test_build_time_verifier_accepts_the_portable_bootstrap_tree(self):
        result = verify_bootstrap_tree(ROOT)
        self.assertEqual(result["documents"], len(DOCUMENTS))
        self.assertEqual(result["bootstrap_members"], 13)

    def test_bootstrap_documents_are_relative_complete_and_truthful(self):
        texts = {
            name: (ROOT / name).read_text(encoding="utf-8") for name in DOCUMENTS
        }
        combined = "\n".join(texts.values())
        self.assertNotIn(
            "does not contain a Production pool or a qualified Windows release",
            combined,
        )
        self.assertIsNone(
            re.search(r"[A-Za-z]:\\|/[U]sers/|/[V]olumes/|/[h]ome/", combined)
        )
        for phrase in (
            "Windows x86-64",
            "local NTFS",
            "GITHUB_TOKEN",
            "Get-AOOfficePoolRelease.ps1",
            "Install-AOOfficePool.ps1",
            "Verify-AOOfficePool.ps1",
            "Uninstall-AOOfficePool.ps1",
            "CONTINUE",
            "REPAIR",
            "HOLD",
        ):
            self.assertIn(phrase, combined)

    def test_readme_has_copy_paste_fresh_clone_and_ai_setup_paths(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        for phrase in (
            "## Fresh clone: validate the source checkout",
            "git clone https://github.com/uesugitorachiyo/ao-office-pool.git",
            "python -m tests.windows_compiler",
            "python -B scripts/run_windows_tests.py",
            "--evidence-dir $evidence",
            "--task-root $taskRoot",
            '"task_root_residue": false',
            "compiler-dependent skips do not qualify",
            "## Copy-paste prompt for Windows Codex",
            "If the private release is unavailable",
            "Do not substitute locally built or unverified assets",
            "Continue proactively through every safe documented step",
        ):
            self.assertIn(phrase, text)

    def test_documents_expose_the_installed_windows_lifecycle_command(self):
        texts = {
            name: (ROOT / name).read_text(encoding="utf-8") for name in DOCUMENTS
        }
        combined = "\n".join(texts.values())
        for obsolete in (
            "does not yet expose a user-facing office lifecycle command",
            "no user-facing office lifecycle command",
            "does not provide a user-facing office lifecycle command",
        ):
            self.assertNotIn(obsolete, combined)
        for phrase in (
            'python -c "import sys; assert sys.version_info[:2] == (3, 12)"',
            '& "$InstallRoot\\bin\\ao-office-pool.ps1" status',
            " claim ",
            " resume ",
            " run ",
            " release ",
            " recover ",
            "outside the AO Office Pool installation",
            "O1-first",
            "Installation alone does not authorize office work",
        ):
            self.assertIn(phrase, combined)
        ai = texts["docs/AI_OPERATOR_RUNBOOK.md"]
        self.assertIn('& "$InstallRoot\\bin\\ao-office-pool.ps1" status', ai)
        self.assertIn("Do not begin O1-first dogfood", ai)

    def test_every_relative_markdown_link_resolves(self):
        for name in DOCUMENTS:
            path = ROOT / name
            text = path.read_text(encoding="utf-8")
            for raw_target in re.findall(r"!?\[[^]]*\]\(([^)]+)\)", text):
                target = raw_target.strip().strip("<>").split("#", 1)[0]
                if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
                    continue
                resolved = (path.parent / unquote(target)).resolve()
                self.assertTrue(resolved.exists(), f"broken link in {name}: {raw_target}")

    def test_ai_runbook_has_closed_gate_fields(self):
        text = (ROOT / "docs/AI_OPERATOR_RUNBOOK.md").read_text(encoding="utf-8")
        matches = list(re.finditer(r"(?m)^## (G\d{2})\b", text))
        self.assertEqual([match.group(1) for match in matches], [f"G{x:02d}" for x in range(10)])
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            block = text[match.end() : end]
            for label in ("Authority", "Command", "Expected", "Stop", "Evidence", "Next"):
                self.assertIn(f"**{label}:**", block, f"{match.group(1)} lacks {label}")

    def test_extracted_entry_point_does_not_repeat_control_checkout_acquisition(self):
        read_first = (ROOT / "README-FIRST.md").read_text(encoding="utf-8")
        runbook = (ROOT / "docs/AI_OPERATOR_RUNBOOK.md").read_text(encoding="utf-8")
        read_first_words = " ".join(read_first.split())
        runbook_words = " ".join(runbook.split())
        self.assertIn("start at G06", read_first_words)
        self.assertIn("Do not rerun G00 through G05", read_first_words)
        self.assertIn("G00 through G05 require the release-control checkout", runbook_words)
        self.assertIn("G06 through G09 run from the verified extraction", runbook_words)

    def test_required_operator_skills_are_discoverable_from_readme_first(self):
        read_first = (ROOT / "README-FIRST.md").read_text(encoding="utf-8")
        for relative in (
            "skills/thought-experiment/SKILL.md",
            "skills/engineering-research/SKILL.md",
            "skills/scope-to-deliverable-workflow/SKILL.md",
        ):
            self.assertIn(f"]({relative})", read_first)

    def test_tracked_release_manifest_is_the_closed_private_v03_contract(self):
        result = verify_release_manifest(
            ROOT / "manifests/developer-preview-release.json"
        )
        self.assertEqual(result["repository"], "uesugitorachiyo/ao-office-pool")
        self.assertEqual(result["visibility"], "private")
        self.assertEqual(result["architecture"], "windows-x86_64")
        self.assertEqual(result["tag"], "developer-preview-v03")
        self.assertEqual(len(result["asset_names"]), 8)
        self.assertEqual(
            result["candidate_manifest"]["name"], "candidate-manifest.json"
        )
        self.assertEqual(
            result["product_source_commit"],
            "1b6bfe9255912270940064408e303e1165104c79",
        )

    def test_release_manifest_rejects_unknown_fields_and_duplicate_asset_names(self):
        source = json.loads(
            (ROOT / "manifests/developer-preview-release.json").read_text()
        )
        for label, mutation in (
            ("unknown", lambda value: value.update(extra=True)),
            (
                "duplicate",
                lambda value: value["asset_names"].append(
                    value["asset_names"][0]
                ),
            ),
            ("visibility", lambda value: value.update(visibility="public")),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                value = json.loads(json.dumps(source))
                mutation(value)
                path = Path(temporary) / "contract.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(ValueError):
                    verify_release_manifest(path)


if __name__ == "__main__":
    unittest.main()
