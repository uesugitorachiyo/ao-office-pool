import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.windows_crt import windows_text_mode


class WindowsCrtTests(unittest.TestCase):
    def test_native_binary_flag_reaches_real_open_without_emulation(self):
        # MUTATION: replacing the native bit then stripping it leaves Windows text-mode.
        payload = b"\x00\xffLF\nCRLF\r\nCTRL-Z\x1aEND\rTAIL"
        host_binary = getattr(os, "O_BINARY", 0)
        native_binary = host_binary or 0x8000
        actual_open = os.open
        received_flags = []

        def recording_open(path, flags, mode=0o777, *, dir_fd=None):
            received_flags.append(flags)
            host_flags = flags if host_binary else flags & ~native_binary
            return actual_open(path, host_flags, mode, dir_fd=dir_fd)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "native.bin"
            with (
                mock.patch.object(os, "O_BINARY", native_binary, create=True),
                mock.patch.object(os, "open", recording_open),
                windows_text_mode(),
            ):
                observed_binary = os.O_BINARY
                descriptor = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY,
                    0o600,
                )
                try:
                    self.assertEqual(os.write(descriptor, payload), len(payload))
                finally:
                    os.close(descriptor)

            self.assertEqual(observed_binary, native_binary)
            self.assertTrue(received_flags[0] & native_binary)
            self.assertEqual(path.read_bytes(), payload)

    @unittest.skipIf(hasattr(os, "O_BINARY"), "off-Windows emulation only")
    def test_off_windows_emulation_exposes_missing_binary_flag(self):
        payload = b"\x00\xffLF\nCRLF\r\nCTRL-Z\x1aEND\rTAIL"
        with tempfile.TemporaryDirectory() as temporary:
            written = Path(temporary) / "written.bin"
            source = Path(temporary) / "source.bin"
            source.write_bytes(payload)

            with windows_text_mode():
                descriptor = os.open(
                    written, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                try:
                    self.assertEqual(os.write(descriptor, payload), len(payload))
                finally:
                    os.close(descriptor)

                descriptor = os.open(source, os.O_RDONLY)
                try:
                    readback = os.read(descriptor, len(payload) + 1)
                finally:
                    os.close(descriptor)

            self.assertNotEqual(written.read_bytes(), payload)
            self.assertEqual(readback, b"\x00\xffLF\nCRLF\nCTRL-Z")


if __name__ == "__main__":
    unittest.main()
