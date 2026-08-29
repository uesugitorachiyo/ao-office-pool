import re
import unittest
from pathlib import Path

from scripts.scan_public_tree import scan_tree


ROOT = Path(__file__).parents[1]
SKILLS = (
    "thought-experiment",
    "engineering-research",
    "scope-to-deliverable-workflow",
)
REQUIRED = (
    "## Trigger",
    "## Authority",
    "## Inputs",
    "## Evidence",
    "## Procedure",
    "## Outputs",
    "## Stop conditions",
    "## Privacy",
    "## Handoff",
)


class ProductSkillTests(unittest.TestCase):
    def test_required_product_skills_are_complete_and_portable(self):
        for name in SKILLS:
            path = ROOT / "skills" / name / "SKILL.md"
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\nname:"))
            self.assertTrue(all(section in text for section in REQUIRED))
            self.assertIsNone(
                re.search(r"[A-Za-z]:\\|/[U]sers/|/[V]olumes/|/[h]ome/", text)
            )
            self.assertLessEqual(len(text.splitlines()), 200)

    def test_product_skills_pass_the_privacy_scanner(self):
        findings = scan_tree(ROOT / "skills")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
