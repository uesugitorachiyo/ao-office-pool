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
            "e2a3c9eac00caa42cec15bdbee669f2f1638bcb5",
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
