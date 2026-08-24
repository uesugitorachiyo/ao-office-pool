import json
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


class PackageBuilderTests(unittest.TestCase):
    def portable_components(self, root):
        import scripts.build_preview as builder

        component_root = root / "component-root"
        component_root.mkdir()
        identities = json.loads(json.dumps(builder._S01_LOCKS))
        components = {}
        for index, (name, identity) in enumerate(sorted(identities.items())):
            data = f"portable {name} {index}\n".encode()
            identity["sha256"] = hashlib.sha256(data).hexdigest()
            binary = component_root / name / identity["asset"]
            binary.parent.mkdir()
            binary.write_bytes(data)
            components[name] = (identity["version"], binary)
        lock_path = root / "components.lock.json"
        lock_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "qualified_slice": "S01",
                    "components": list(identities.values()),
                }
            ),
            encoding="utf-8",
        )
        return component_root, components, lock_path, identities

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
            component_root, components, lock_path, identities = self.portable_components(root)
            lock = json.loads(lock_path.read_text())
            lock["components"][0]["asset"] = "unbound.exe"
            lock_path.write_text(json.dumps(lock))

            with mock.patch.object(builder, "_LOCK_PATH", lock_path), mock.patch.object(builder, "_S01_LOCKS", identities), self.assertRaisesRegex(ValueError, "lock identity"):
                builder.build_preview(source, components["ao2"][1], "v0.5.12", root / "preview.zip", components, component_root)

    def test_build_preview_rejects_lock_repository_drift(self):
        import scripts.build_preview as builder

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            component_root, components, lock_path, identities = self.portable_components(root)
            lock = json.loads(lock_path.read_text())
            lock["components"][0]["repository"] = "https://example.invalid/ao2.git"
            lock_path.write_text(json.dumps(lock))

            with mock.patch.object(builder, "_LOCK_PATH", lock_path), mock.patch.object(builder, "_S01_LOCKS", identities), self.assertRaisesRegex(ValueError, "lock identity"):
                builder.build_preview(source, components["ao2"][1], "v0.5.12", root / "preview.zip", components, component_root)

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
                component_root, components, lock_path, identities = self.portable_components(root)
                lock = json.loads(lock_path.read_text())
                mutate(lock["components"])
                lock_path.write_text(json.dumps(lock))

                with mock.patch.object(builder, "_LOCK_PATH", lock_path), mock.patch.object(builder, "_S01_LOCKS", identities), self.assertRaises(ValueError):
                    builder.build_preview(source, components["ao2"][1], "v0.5.12", root / "preview.zip", components, component_root)

    def test_build_preview_rejects_reparse_ancestor(self):
        import scripts.build_preview as builder

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            component_root, components, lock_path, identities = self.portable_components(root)
            ao2 = components["ao2"][1]
            original = Path.is_symlink

            with mock.patch.object(builder, "_LOCK_PATH", lock_path), mock.patch.object(builder, "_S01_LOCKS", identities), mock.patch.object(Path, "is_symlink", autospec=True, side_effect=lambda path: path == ao2.parent or original(path)), self.assertRaisesRegex(ValueError, "verified S01"):
                builder.build_preview(source, ao2, "v0.5.12", root / "preview.zip", components, component_root)

    def test_build_preview_rejects_case_insensitive_duplicate_binary_input_paths(self):
        from scripts.build_preview import build_preview

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            component_root, components, lock_path, identities = self.portable_components(root)
            components["ao-mission"] = ("v0.1.6", components["ao2"][1])

            with mock.patch("scripts.build_preview._LOCK_PATH", lock_path), mock.patch("scripts.build_preview._S01_LOCKS", identities), self.assertRaisesRegex(ValueError, "duplicate"):
                build_preview(source, components["ao2"][1], "v0.5.12", root / "preview.zip", components, component_root)

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
                    component_root=root,
                )

    def test_build_preview_emits_manifest_and_five_identical_ao2_copies(self):
        from scripts.build_preview import build_preview

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "app.txt").write_text("application\n", encoding="utf-8")
            component_root, components, lock_path, identities = self.portable_components(root)
            ao2 = components["ao2"][1]
            archive = root / "preview.zip"
            with mock.patch("scripts.build_preview._LOCK_PATH", lock_path), mock.patch("scripts.build_preview._S01_LOCKS", identities):
                build_preview(source, ao2, "v0.5.12", archive, components=components, component_root=component_root)
            with zipfile.ZipFile(archive) as package:
                manifest = json.loads(package.read("developer-preview-manifest.json"))
                paths = {row["path"] for row in manifest["files"]}
                self.assertEqual(manifest["runtime_version"], "v0.5.12")
                self.assertTrue(all(f"offices/O{number}/runtime/versions/v0.5.12/ao2.exe" in paths for number in range(1, 6)))
                self.assertTrue(all(f"components/{name}/{version}/{binary.name}" in paths for name, (version, binary) in components.items()))
                self.assertTrue(all(f"offices/O{number}/history/" in package.namelist() for number in range(1, 6)))

    def test_build_preview_accepts_a_caller_supplied_component_root(self):
        import scripts.build_preview as builder

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            component_root, components, lock_path, identities = self.portable_components(root)
            archive = root / "preview.zip"
            with (
                mock.patch.object(builder, "_LOCK_PATH", lock_path),
                mock.patch.object(builder, "_S01_LOCKS", identities),
            ):
                builder.build_preview(
                    source,
                    components["ao2"][1],
                    "v0.5.12",
                    archive,
                    components=components,
                    component_root=component_root,
                )
            self.assertTrue(archive.is_file())

    def test_build_preview_rejects_a_component_outside_the_caller_root(self):
        import scripts.build_preview as builder

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            component_root, components, lock_path, identities = self.portable_components(root)
            outside = root / "outside" / components["ao2"][1].name
            outside.parent.mkdir()
            outside.write_bytes(components["ao2"][1].read_bytes())
            components["ao2"] = (components["ao2"][0], outside)
            with (
                mock.patch.object(builder, "_LOCK_PATH", lock_path),
                mock.patch.object(builder, "_S01_LOCKS", identities),
                self.assertRaisesRegex(
                    ValueError, "component input must be within component root"
                ),
            ):
                builder.build_preview(
                    source,
                    outside,
                    "v0.5.12",
                    root / "preview.zip",
                    components=components,
                    component_root=component_root,
                )
