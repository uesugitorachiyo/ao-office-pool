import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_components import verify_lock


COMPONENT_NAMES = (
    "ao-architecture", "ao-mission", "ao2", "ao2-control-plane", "ao-blueprint",
    "ao-atlas", "ao-foundry", "ao-forge", "ao-covenant", "ao-command", "ao-arena",
    "ao-crucible", "ao-sentinel", "ao-promoter",
)


class VerifyLockTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.component_root = Path(self.temporary_directory.name)
        self.asset_bytes = b"verified component asset\n"
        for name in COMPONENT_NAMES:
            self.write_asset(name)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def write_asset(self, name, asset="component.zip"):
        path = self.component_root / name / "1.0.0" / asset
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.asset_bytes)
        return path

    def components(self):
        digest = hashlib.sha256(self.asset_bytes).hexdigest()
        return [
            {
                "name": name,
                "version": "1.0.0",
                "repository": f"https://github.com/example/{name}",
                "commit": "a" * 40,
                "asset": "component.zip",
                "license": "MIT",
                "sha256": digest,
            }
            for name in COMPONENT_NAMES
        ]

    def lock(self, components=None):
        path = self.component_root / "components.lock.json"
        path.write_text(json.dumps({"schema_version": 1, "components": self.components() if components is None else components}))
        return path

    def test_returns_component_digests_for_the_exact_component_set(self):
        digest = hashlib.sha256(self.asset_bytes).hexdigest()
        self.assertEqual(verify_lock(self.lock(), self.component_root), dict.fromkeys(COMPONENT_NAMES, digest))

    def test_rejects_a_missing_expected_component(self):
        components = self.components()
        components.pop()

        with self.assertRaises(ValueError):
            verify_lock(self.lock(components), self.component_root)

    def test_rejects_an_unexpected_component_name(self):
        components = self.components()
        components[-1]["name"] = "unexpected"
        self.write_asset("unexpected")

        with self.assertRaises(ValueError):
            verify_lock(self.lock(components), self.component_root)

    def test_rejects_duplicate_component_names(self):
        components = self.components()
        components.append(components[0].copy())

        with self.assertRaises(ValueError):
            verify_lock(self.lock(components), self.component_root)

    def test_rejects_malformed_commit(self):
        components = self.components()
        components[0]["commit"] = "not-a-commit"

        with self.assertRaises(ValueError):
            verify_lock(self.lock(components), self.component_root)

    def test_rejects_non_https_repository(self):
        components = self.components()
        components[0]["repository"] = "http://example.com/ao-mission"

        with self.assertRaises(ValueError):
            verify_lock(self.lock(components), self.component_root)

    def test_rejects_missing_or_whitespace_license(self):
        for license in (None, " \t"):
            with self.subTest(license=license):
                components = self.components()
                if license is None:
                    del components[0]["license"]
                else:
                    components[0]["license"] = license
                with self.assertRaises(ValueError):
                    verify_lock(self.lock(components), self.component_root)

    def test_rejects_a_wrong_asset_digest(self):
        components = self.components()
        components[0]["sha256"] = "0" * 64

        with self.assertRaises(ValueError):
            verify_lock(self.lock(components), self.component_root)

    def test_rejects_unknown_fields(self):
        components = self.components()
        components[0]["unreviewed"] = True

        with self.assertRaises(ValueError):
            verify_lock(self.lock(components), self.component_root)

    def test_rejects_an_asset_outside_the_component_root(self):
        components = self.components()
        components[0]["asset"] = "../component.zip"

        with self.assertRaises(ValueError):
            verify_lock(self.lock(components), self.component_root)

    def test_rejects_backslash_asset_names_on_every_platform(self):
        asset = r"nested\component.zip"
        self.write_asset("ao-architecture", asset)
        self.write_asset("ao-architecture", "nested/component.zip")
        components = self.components()
        components[0]["asset"] = asset

        with self.assertRaises(ValueError):
            verify_lock(self.lock(components), self.component_root)

    def test_rejects_non_string_component_fields_as_value_errors(self):
        for field, value in (("name", []), ("version", 1), ("repository", []), ("commit", 1), ("sha256", []), ("asset", [])):
            with self.subTest(field=field):
                components = self.components()
                components[0][field] = value
                with self.assertRaises(ValueError):
                    verify_lock(self.lock(components), self.component_root)


if __name__ == "__main__":
    unittest.main()
