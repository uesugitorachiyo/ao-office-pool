import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RepositoryLayoutTests(unittest.TestCase):
    def test_development_workflow_trees_are_absent_and_ignored(self):
        ignored = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
        for relative, pattern in (
            (".github", "/.github/"),
            (".superpowers", "/.superpowers/"),
            ("docs/superpowers", "/docs/superpowers/"),
        ):
            with self.subTest(relative=relative):
                self.assertFalse((ROOT / relative).exists())
                self.assertIn(pattern, ignored)

    def test_public_tree_omits_github_automation(self):
        manifest = json.loads(
            (ROOT / "manifests" / "public-tree.json").read_text(encoding="utf-8")
        )
        self.assertNotIn(".github", manifest["tracked_roots"])

    def test_release_contract_uses_durable_design_path(self):
        design = ROOT / "docs" / "contracts" / "ao-office-pool-design.md"
        verifier = (ROOT / "scripts" / "verify_release_contract.py").read_text(
            encoding="utf-8"
        )
        self.assertTrue(design.is_file())
        self.assertIn(
            'Path("docs/contracts/ao-office-pool-design.md")', verifier
        )
        self.assertNotIn("docs/superpowers", verifier)
        design_text = design.read_text(encoding="utf-8")
        self.assertNotIn(".github/", design_text)
        self.assertIn("](../STACK_LAYOUT.md)", design_text)
        self.assertNotIn("](../../STACK_LAYOUT.md)", design_text)


if __name__ == "__main__":
    unittest.main()
