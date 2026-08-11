import unittest
from pathlib import PureWindowsPath

try:
    from internal.windows_paths import canonical_windows_path, validate_segment
except ImportError:
    canonical_windows_path = validate_segment = None


class WindowsPathTests(unittest.TestCase):
    def test_api_exists(self):
        self.assertIsNotNone(validate_segment)
        self.assertIsNotNone(canonical_windows_path)

    @unittest.skipIf(validate_segment is None, "implementation not available")
    def test_validate_segment_accepts_safe_names_unchanged(self):
        # MUTATION: normalizing or truncating a valid segment changes a literal result.
        for value in ("ao2-1.2.0", "Office_01", "release candidate", "é", "a" * 255):
            with self.subTest(value=value):
                self.assertEqual(validate_segment(value), value)

    @unittest.skipIf(validate_segment is None, "implementation not available")
    def test_validate_segment_rejects_unsafe_names(self):
        # MUTATION: deleting any validation branch admits at least one literal below.
        values = (
            "",
            ".",
            "..",
            "C:\\absolute",
            "\\rooted",
            "/rooted",
            "two/parts",
            "two\\parts",
            "bad:name",
            "bad*name",
            "bad?name",
            "bad\x00name",
            "bad\x1fname",
            "trailing.",
            "trailing ",
            "CON",
            "con.txt",
            "PRN.log",
            "AUX",
            "NUL.bin",
            "COM1",
            "com9.txt",
            "LPT1",
            "lpt9.log",
            "CONIN$",
            "conout$.txt",
            "PROGRA~1",
            "DOCUME~2.txt",
            "a" * 256,
            "😀" * 128,
        )
        for value in values:
            with self.subTest(value=repr(value)):
                with self.assertRaises((TypeError, ValueError)):
                    validate_segment(value)

    @unittest.skipIf(validate_segment is None, "implementation not available")
    def test_validate_segment_rejects_non_strings(self):
        for value in (None, 1, b"name"):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    validate_segment(value)

    @unittest.skipIf(canonical_windows_path is None, "implementation not available")
    def test_canonicalizes_drive_unc_extended_case_and_separators(self):
        # MUTATION: preserving case, extended aliases, or mixed separators breaks a row.
        cases = (
            (r"C:\AO\Runtime", r"c:\ao\runtime"),
            (r"c:/AO\Runtime/File.TXT", r"c:\ao\runtime\file.txt"),
            (r"\\Server\Share\Folder\File", r"\\server\share\folder\file"),
            (r"\\?\C:\AO\Runtime", r"c:\ao\runtime"),
            (r"\\?\UNC\Server\Share\Folder", r"\\server\share\folder"),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                result = canonical_windows_path(value)
                self.assertIsInstance(result, PureWindowsPath)
                self.assertEqual(str(result), expected)

    @unittest.skipIf(canonical_windows_path is None, "implementation not available")
    def test_canonical_path_allows_long_absolute_paths(self):
        # MUTATION: applying the obsolete MAX_PATH total-length limit rejects this path.
        value = "C:\\" + "\\".join(("a" * 100, "b" * 100, "c" * 100))
        self.assertEqual(str(canonical_windows_path(value)), value.lower())

    @unittest.skipIf(canonical_windows_path is None, "implementation not available")
    def test_canonical_path_rejects_ambiguous_or_unsafe_inputs(self):
        # MUTATION: PureWindowsPath parsing without pre-validation admits these aliases.
        values = (
            "",
            "relative\\path",
            r"C:drive-relative",
            r"\root-relative",
            r"C:\safe\..\escape",
            r"C:\safe\.\file",
            r"C:\safe\\file",
            r"C:\safe\CON.txt",
            r"C:\safe\trailing.\file",
            r"C:\PROGRA~1\file",
            r"\\server",
            r"\\.\C:\device",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\file",
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    canonical_windows_path(value)


if __name__ == "__main__":
    unittest.main()
