import os
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    from internal.windows_identity import FileIdentity, open_identity, require_within
except ImportError:
    FileIdentity = open_identity = require_within = None


class WindowsIdentityApiTests(unittest.TestCase):
    def test_api_exists(self):
        self.assertIsNotNone(FileIdentity)
        self.assertIsNotNone(open_identity)
        self.assertIsNotNone(require_within)

    @unittest.skipIf(open_identity is None or os.name == "nt", "off-Windows behavior only")
    def test_identity_operations_fail_closed_off_windows(self):
        # MUTATION: a portable stat/path fallback would make this trust-boundary call pass.
        with self.assertRaises(OSError):
            open_identity(Path.cwd())
        with self.assertRaises(OSError):
            require_within(None, None)


@unittest.skipUnless(os.name == "nt", "physical NTFS tests require Windows")
class WindowsIdentityPhysicalTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name)
        self.root = self.base / "project"
        self.outside = self.base / "outside"
        self.root.mkdir()
        self.outside.mkdir()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_accepts_real_descendants_and_rejects_prefix_siblings(self):
        # MUTATION: string-prefix containment accepts project-sibling as project content.
        child = self.root / "output.txt"
        sibling = self.base / "project-sibling"
        child.write_text("inside", encoding="utf-8")
        sibling.write_text("outside", encoding="utf-8")
        self.assertIsNone(require_within(open_identity(child), open_identity(self.root)))
        with self.assertRaises(ValueError):
            require_within(open_identity(sibling), open_identity(self.root))

    def test_case_aliases_have_the_same_file_identity(self):
        # MUTATION: case-sensitive path identity makes the alternate spelling differ.
        path = self.root / "MixedCase.TXT"
        path.write_text("case", encoding="utf-8")
        first = open_identity(path)
        alias = open_identity(self.root / "mixedcase.txt")
        self.assertEqual(first, alias)
        self.assertIsNone(require_within(alias, open_identity(self.root)))

    def test_rejects_hard_link_alias(self):
        # MUTATION: checking ancestry alone admits an outside file hard-linked inside.
        original = self.outside / "original.txt"
        alias = self.root / "alias.txt"
        original.write_text("outside", encoding="utf-8")
        os.link(original, alias)
        original_identity = open_identity(original)
        alias_identity = open_identity(alias)
        self.assertEqual(original_identity, alias_identity)
        self.assertGreater(alias_identity.link_count, 1)
        with self.assertRaises(ValueError):
            require_within(alias_identity, open_identity(self.root))

    def test_rejects_file_symlink_escape(self):
        # MUTATION: following a leaf symlink without recording reparse traversal passes.
        target = self.outside / "target.txt"
        link = self.root / "link.txt"
        target.write_text("outside", encoding="utf-8")
        os.symlink(target, link)
        identity = open_identity(link)
        self.assertTrue(identity.traversed_reparse_point)
        with self.assertRaises(ValueError):
            require_within(identity, open_identity(self.root))

    def test_rejects_junction_escape(self):
        # MUTATION: canonical text ancestry through a junction accepts the target child.
        target_child = self.outside / "target.txt"
        junction = self.root / "junction"
        target_child.write_text("outside", encoding="utf-8")
        subprocess.run(
            ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(self.outside)],
            check=True,
            capture_output=True,
            text=True,
        )
        identity = open_identity(junction / "target.txt")
        self.assertTrue(identity.traversed_reparse_point)
        with self.assertRaises(ValueError):
            require_within(identity, open_identity(self.root))

    def test_rejects_generic_directory_reparse_point(self):
        # MUTATION: checking only leaf attributes misses a reparse-point ancestor.
        target = self.outside / "directory"
        link = self.root / "reparse"
        target.mkdir()
        target.joinpath("target.txt").write_text("outside", encoding="utf-8")
        os.symlink(target, link, target_is_directory=True)
        identity = open_identity(link / "target.txt")
        self.assertTrue(identity.traversed_reparse_point)
        with self.assertRaises(ValueError):
            require_within(identity, open_identity(self.root))

    def test_rejects_deleted_and_recreated_child_identity(self):
        # MUTATION: trusting the remembered pathname admits a replacement file.
        path = self.root / "output.txt"
        path.write_text("first", encoding="utf-8")
        stale = open_identity(path)
        path.unlink()
        path.write_text("replacement", encoding="utf-8")
        self.assertNotEqual(stale, open_identity(path))
        with self.assertRaises(ValueError):
            require_within(stale, open_identity(self.root))

    def test_rejects_deleted_and_recreated_root_identity(self):
        # MUTATION: trusting root text instead of its file id admits a replacement root.
        stale_root = open_identity(self.root)
        self.root.rmdir()
        self.root.mkdir()
        child = self.root / "output.txt"
        child.write_text("replacement", encoding="utf-8")
        with self.assertRaises(ValueError):
            require_within(open_identity(child), stale_root)


if __name__ == "__main__":
    unittest.main()
