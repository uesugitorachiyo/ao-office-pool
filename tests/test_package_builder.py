import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


class PackageBuilderTests(unittest.TestCase):
    def s01_components(self):
        root = Path(r"D:\ao-office-pool\.local\missions\windows-latest-stack-private-release-v01\extracted-v2")
        return {
            "ao2": ("v0.5.12", root / "ao2-0.5.12-windows-x86_64.tar/bin/ao2.exe"),
            "ao-mission": ("v0.1.6", root / "ao-mission-0.1.6-windows-x86_64/ao-mission.exe"),
            "ao-command": ("v0.1.3", root / "ao-command-0.1.3-windows-x86_64/ao-command.exe"),
            "ao-atlas": ("v0.2.1", root / "ao-atlas-v0.2.1-windows-x86_64.tar/ao-atlas.exe"),
            "ao-forge": ("v0.1.5", root / "ao-forge_Windows_x86_64/forge.exe"),
            "ao-covenant": ("v0.1.1", root / "ao-covenant_v0.1.1_windows_amd64/ao-covenant_v0.1.1_windows_amd64.exe"),
            "ao2-control-plane": ("v0.1.19", root / "ao2-control-plane-0.1.19-windows-x86_64.tar/bin/ao2-cp-server.exe"),
            "ao-blueprint": ("git-ec6a80b60b54", root / "ao-blueprint-source-exception/ao-blueprint.exe"),
        }

    def test_build_preview_requires_the_closed_s01_component_map(self):
        from scripts.build_preview import build_preview

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()

            with self.assertRaisesRegex(ValueError, "component map"):
                build_preview(source, root / "ao2.exe", "v0.5.12", root / "preview.zip")

    def test_build_preview_rejects_lock_binary_name_drift(self):
        import scripts.build_preview as builder

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            lock = json.loads((Path(__file__).parents[1] / "manifests/components.lock.json").read_text())
            lock["components"][0]["asset"] = "unbound.exe"
            lock_path = root / "components.lock.json"
            lock_path.write_text(json.dumps(lock))

            with mock.patch.object(builder, "_LOCK_PATH", lock_path), self.assertRaisesRegex(ValueError, "lock identity"):
                builder.build_preview(source, self.s01_components()["ao2"][1], "v0.5.12", root / "preview.zip", self.s01_components())

    def test_build_preview_rejects_lock_repository_drift(self):
        import scripts.build_preview as builder

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            lock = json.loads((Path(__file__).parents[1] / "manifests/components.lock.json").read_text())
            lock["components"][0]["repository"] = "https://example.invalid/ao2.git"
            lock_path = root / "components.lock.json"
            lock_path.write_text(json.dumps(lock))

            with mock.patch.object(builder, "_LOCK_PATH", lock_path), self.assertRaisesRegex(ValueError, "lock identity"):
                builder.build_preview(source, self.s01_components()["ao2"][1], "v0.5.12", root / "preview.zip", self.s01_components())

    def test_build_preview_rejects_missing_extra_duplicate_version_and_hash_lock_drift(self):
        import scripts.build_preview as builder

        for label, mutate in (
            ("missing", lambda components: components.pop()),
            ("extra", lambda components: components.append(components[0].copy() | {"name": "extra"})),
            ("duplicate", lambda components: components.append(components[0].copy())),
            ("version", lambda components: components[0].update(version="v9.9.9")),
            ("hash", lambda components: components[0].update(sha256="0" * 64)),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "source"
                source.mkdir()
                lock = json.loads((Path(__file__).parents[1] / "manifests/components.lock.json").read_text())
                mutate(lock["components"])
                lock_path = root / "components.lock.json"
                lock_path.write_text(json.dumps(lock))

                with mock.patch.object(builder, "_LOCK_PATH", lock_path), self.assertRaises(ValueError):
                    builder.build_preview(source, self.s01_components()["ao2"][1], "v0.5.12", root / "preview.zip", self.s01_components())

    def test_build_preview_rejects_reparse_ancestor(self):
        import scripts.build_preview as builder

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            ao2 = self.s01_components()["ao2"][1]
            original = Path.is_symlink

            with mock.patch.object(Path, "is_symlink", autospec=True, side_effect=lambda path: path == ao2.parent or original(path)), self.assertRaisesRegex(ValueError, "verified S01"):
                builder.build_preview(source, ao2, "v0.5.12", root / "preview.zip", self.s01_components())

    def test_build_preview_rejects_case_insensitive_duplicate_binary_input_paths(self):
        from scripts.build_preview import build_preview

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            components = self.s01_components()
            components["ao-mission"] = ("v0.1.6", components["ao2"][1])

            with self.assertRaisesRegex(ValueError, "duplicate"):
                build_preview(source, components["ao2"][1], "v0.5.12", root / "preview.zip", components)

    def test_build_preview_rejects_components_outside_the_s01_map(self):
        from scripts.build_preview import build_preview

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            ao2 = root / "ao2.exe"
            ao2.write_bytes(b"ao2")
            extra = root / "unbound.exe"
            extra.write_bytes(b"unbound")

            with self.assertRaisesRegex(ValueError, "component map"):
                build_preview(
                    source,
                    ao2,
                    "v0.5.12",
                    root / "preview.zip",
                    components={"unexpected": ("v1.0.0", extra)},
                )

    def test_build_preview_emits_manifest_and_five_identical_ao2_copies(self):
        from scripts.build_preview import build_preview

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "app.txt").write_text("application\n", encoding="utf-8")
            components = self.s01_components()
            ao2 = components["ao2"][1]
            archive = root / "preview.zip"
            build_preview(source, ao2, "v0.5.12", archive, components=components)
            with zipfile.ZipFile(archive) as package:
                manifest = json.loads(package.read("developer-preview-manifest.json"))
                paths = {row["path"] for row in manifest["files"]}
                self.assertEqual(manifest["runtime_version"], "v0.5.12")
                self.assertTrue(all(f"offices/O{number}/runtime/versions/v0.5.12/ao2.exe" in paths for number in range(1, 6)))
                self.assertTrue(all(f"components/{name}/{version}/{binary.name}" in paths for name, (version, binary) in components.items()))
                self.assertTrue(all(f"offices/O{number}/history/" in package.namelist() for number in range(1, 6)))
