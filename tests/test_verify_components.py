import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_components import verify_lock


class VerifyLockTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.component_root = Path(self.temporary_directory.name)
        self.asset = self.component_root / "ao-mission" / "1.0.0" / "ao-mission.zip"
        self.asset.parent.mkdir(parents=True)
        self.asset.write_bytes(b"verified component asset\n")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def lock(self, component=None):
        component = component or {
            "name": "ao-mission",
            "version": "1.0.0",
            "repository": "https://github.com/example/ao-mission",
            "commit": "a" * 40,
            "asset": "ao-mission.zip",
            "license": "MIT",
            "sha256": hashlib.sha256(self.asset.read_bytes()).hexdigest(),
        }
        path = self.component_root / "components.lock.json"
        path.write_text(json.dumps({"schema_version": 1, "components": [component]}))
        return path

    def test_returns_component_digests_for_a_valid_lock(self):
        self.assertEqual(
            verify_lock(self.lock(), self.component_root),
            {"ao-mission": hashlib.sha256(self.asset.read_bytes()).hexdigest()},
        )

    def test_rejects_duplicate_component_names(self):
        path = self.lock()
        data = json.loads(path.read_text())
        data["components"].append(data["components"][0].copy())
        path.write_text(json.dumps(data))

        with self.assertRaises(ValueError):
            verify_lock(path, self.component_root)

    def test_rejects_malformed_commit(self):
        component = {**json.loads(self.lock().read_text())["components"][0], "commit": "not-a-commit"}

        with self.assertRaises(ValueError):
            verify_lock(self.lock(component), self.component_root)

    def test_rejects_non_https_repository(self):
        component = {**json.loads(self.lock().read_text())["components"][0], "repository": "http://example.com/ao-mission"}

        with self.assertRaises(ValueError):
            verify_lock(self.lock(component), self.component_root)

    def test_rejects_missing_license(self):
        component = json.loads(self.lock().read_text())["components"][0]
        del component["license"]

        with self.assertRaises(ValueError):
            verify_lock(self.lock(component), self.component_root)

    def test_rejects_a_wrong_asset_digest(self):
        component = {**json.loads(self.lock().read_text())["components"][0], "sha256": "0" * 64}

        with self.assertRaises(ValueError):
            verify_lock(self.lock(component), self.component_root)

    def test_rejects_unknown_fields(self):
        component = {**json.loads(self.lock().read_text())["components"][0], "unreviewed": True}

        with self.assertRaises(ValueError):
            verify_lock(self.lock(component), self.component_root)

    def test_rejects_an_asset_outside_the_component_root(self):
        component = {**json.loads(self.lock().read_text())["components"][0], "asset": "../ao-mission.zip"}

        with self.assertRaises(ValueError):
            verify_lock(self.lock(component), self.component_root)


if __name__ == "__main__":
    unittest.main()
