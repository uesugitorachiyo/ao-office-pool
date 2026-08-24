import json
import tempfile
import unittest
import zipfile
from pathlib import Path


class PackageBuilderTests(unittest.TestCase):
    def test_build_preview_emits_manifest_and_five_identical_ao2_copies(self):
        from scripts.build_preview import build_preview

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "app.txt").write_text("application\n", encoding="utf-8")
            ao2 = root / "ao2.exe"
            ao2.write_bytes(b"verified ao2")
            archive = root / "preview.zip"
            build_preview(source, ao2, "v0.5.12", archive)
            with zipfile.ZipFile(archive) as package:
                manifest = json.loads(package.read("developer-preview-manifest.json"))
                paths = {row["path"] for row in manifest["files"]}
                self.assertEqual(manifest["runtime_version"], "v0.5.12")
                self.assertTrue(all(f"offices/O{number}/runtime/versions/v0.5.12/ao2.exe" in paths for number in range(1, 6)))
