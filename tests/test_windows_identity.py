import os
import subprocess
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from unittest import mock

import internal.windows_identity as windows_identity

try:
    from internal.windows_identity import FileIdentity, open_identity, require_within
except ImportError:
    FileIdentity = open_identity = require_within = None

RetainedIdentity = getattr(windows_identity, "RetainedIdentity", None)
open_retained_identity = getattr(windows_identity, "open_retained_identity", None)
require_path_identity = getattr(windows_identity, "require_path_identity", None)
require_retained_within = getattr(windows_identity, "require_retained_within", None)
retain_identities = getattr(windows_identity, "retain_identities", None)

try:
    from internal.mission_bridge import (
        _PrivateDirectory,
        _open_retained_file,
        _open_windows_directory,
        _private_file,
    )
except ImportError:
    _PrivateDirectory = _open_retained_file = _open_windows_directory = _private_file = None


class WindowsIdentityApiTests(unittest.TestCase):
    def test_api_exists(self):
        self.assertIsNotNone(FileIdentity)
        self.assertIsNotNone(open_identity)
        self.assertIsNotNone(require_within)
        self.assertIsNotNone(RetainedIdentity)
        self.assertIsNotNone(open_retained_identity)
        self.assertIsNotNone(require_path_identity)
        self.assertIsNotNone(require_retained_within)
        self.assertIsNotNone(retain_identities)
        self.assertIsNotNone(_open_retained_file)

    @unittest.skipIf(open_identity is None or os.name == "nt", "off-Windows behavior only")
    def test_identity_operations_fail_closed_off_windows(self):
        # MUTATION: a portable stat/path fallback would make this trust-boundary call pass.
        with self.assertRaises(OSError):
            open_identity(Path.cwd())
        with self.assertRaises(OSError):
            require_within(None, None)


@unittest.skipIf(
    open_retained_identity is None,
    "retained Windows identity API is missing",
)
class RetainedWindowsIdentityTests(unittest.TestCase):
    @staticmethod
    def _identity(path: Path, marker: int, *, directory: bool = False):
        key = (marker, marker.to_bytes(16, "big"))
        return FileIdentity(
            path=path,
            final_path=PureWindowsPath("C:/fixture") / path.name,
            volume_serial_number=key[0],
            file_id=key[1],
            ancestor_ids=(key,),
            link_count=1,
            is_directory=directory,
            traversed_reparse_point=False,
        )

    def test_retained_handle_denies_write_delete_sharing_and_closes(self):
        # MUTATION: permitting write/delete sharing reopens the ABA window.
        path = Path("C:/fixture/candidate.json")
        identity = self._identity(path, 7)
        library = mock.Mock()
        library.CloseHandle.return_value = 1
        with (
            mock.patch("internal.windows_identity._require_windows"),
            mock.patch(
                "internal.windows_identity._open_handle",
                return_value=(library, 41),
            ) as opened,
            mock.patch(
                "internal.windows_identity._identity_from_handle",
                return_value=identity,
            ),
        ):
            with open_retained_identity(path) as retained:
                self.assertEqual(retained.identity, identity)

        opened.assert_called_once_with(
            PureWindowsPath("C:/fixture/candidate.json"),
            share_mode=windows_identity._FILE_SHARE_READ,
        )
        library.CloseHandle.assert_called_once_with(41)

    def test_identity_failure_closes_the_new_native_handle(self):
        # MUTATION: an exception during identity capture leaks the blocking handle.
        library = mock.Mock()
        library.CloseHandle.return_value = 1
        with (
            mock.patch("internal.windows_identity._require_windows"),
            mock.patch(
                "internal.windows_identity._open_handle",
                return_value=(library, 52),
            ),
            mock.patch(
                "internal.windows_identity._identity_from_handle",
                side_effect=OSError("identity failed"),
            ),
        ):
            with self.assertRaises(OSError):
                open_retained_identity(Path("C:/fixture/member.json"))

        library.CloseHandle.assert_called_once_with(52)

    def test_aba_snapshots_match_but_path_to_retained_handle_rejects(self):
        # MUTATION: comparing only equal pre/post path snapshots accepts bytes
        # read from a replacement that was restored before the second snapshot.
        path = Path("C:/fixture/member.json")
        original = self._identity(path, 11)
        replacement = self._identity(path, 12)
        library = mock.Mock()
        library.CloseHandle.return_value = 1
        with (
            mock.patch("internal.windows_identity._require_windows"),
            mock.patch(
                "internal.windows_identity._open_handle",
                return_value=(library, 63),
            ),
            mock.patch(
                "internal.windows_identity._identity_from_handle",
                return_value=replacement,
            ),
            mock.patch(
                "internal.windows_identity._handle_snapshot",
                return_value=(
                    replacement.key,
                    replacement.final_path,
                    0,
                    replacement.link_count,
                ),
            ),
        ):
            with open_retained_identity(path) as retained:
                before = original
                replacement_bytes = b"malicious replacement bytes"
                after = original
                self.assertEqual(before, after)
                self.assertNotEqual(replacement_bytes, b"original bytes")
                with mock.patch(
                    "internal.windows_identity.open_identity",
                    return_value=after,
                ):
                    with self.assertRaises(ValueError):
                        require_path_identity(retained)


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

    def test_unicode_spelling_does_not_alias_a_different_sibling(self):
        # MUTATION: full Unicode casefold opens Strasse.txt for Straße.txt.
        sharp_s = self.root / "Straße.txt"
        expanded_s = self.root / "Strasse.txt"
        sharp_s.write_text("sharp", encoding="utf-8")
        expanded_s.write_text("expanded", encoding="utf-8")
        self.assertNotEqual(open_identity(sharp_s), open_identity(expanded_s))

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
        try:
            os.symlink(target, link)
        except OSError as error:
            self.skipTest(str(error))
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
        try:
            os.symlink(target, link, target_is_directory=True)
        except OSError as error:
            self.skipTest(str(error))
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

    def test_retained_workflow_handle_blocks_write_and_delete(self):
        # MUTATION: write/delete sharing permits pathname substitution before AO2 opens it.
        workflow = self.root / "workflow.yaml"
        workflow.write_text("name: bounded\n", encoding="utf-8")
        retained_root = _PrivateDirectory(
            self.root,
            self.root,
            handles=(_open_windows_directory(self.root),),
        )
        private = _private_file(retained_root, (), workflow.name)
        try:
            with _open_retained_file(private):
                with self.assertRaises(OSError):
                    workflow.write_text("name: substituted\n", encoding="utf-8")
                with self.assertRaises(OSError):
                    workflow.unlink()
        finally:
            private.close()
            retained_root.close()

    def test_strict_project_handle_blocks_path_replacement(self):
        # MUTATION: delete sharing permits replacement cwd after target verification.
        parked = self.root.with_name("project-parked")
        handle = _open_windows_directory(self.root, share_write=False)
        try:
            with self.assertRaises(OSError):
                os.replace(self.root, parked)
        finally:
            from internal.windows_identity import _kernel32

            _kernel32().CloseHandle(handle)


if __name__ == "__main__":
    unittest.main()
