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

RELEASED_LOCK_VALUES = {
    "ao2": ("v0.5.11", "8307795b3434af920f6cef088e56ca8fcc76775b", "ao2", "6cba9a1ded758506bb0a4b6d6377687e29b9d35950c799c2a0b4efb51c6f1bd7"),
    "ao2-control-plane": ("v0.1.19", "5de3541e9007e12d95b125e7f911c02932e21479", "ao2-cp-server", "91e04f5ffa2517908d0961eb42513c2cb1629b76f8433207e5c65afa346689aa"),
    "ao-mission": ("v0.1.4", "cee287597024b5a1e990c6e272518236bc9e32fa", "ao-mission", "dec18e71b4a98ec72e4713fe5e3a11d3c1d11cd1051f629f84ab09fa7b1aa6b4"),
    "ao-atlas": ("v0.2.0", "2bf243ce8d8c71d845754398238b14d1ab77d0e6", "ao-atlas", "e6968aeeb11bc19eb77fe3f87ca71414697dc92736556e726abe89c74f874bea"),
    "ao-command": ("v0.1.2", "a728d90077c1340e295468e5017b5e166bc5bc7a", "ao-command", "3b90ddfe5cd3f43c4e9ad301aaf235f8732d6c33069acb2d327b469b5b53681b"),
    "ao-forge": ("v0.1.4", "e104b47c2e14b6c0927b885e137907ad227aeb5c", "forge", "823ee61771608c7893287532c00929710ee1ff1149e06c13d40ff7296e937ba1"),
    "ao-covenant": ("v0.1.1", "2fd72a0426a747868826581612fa1dc9727b53b9", "covenant", "9a5ca7c6920c44b6e120d6c5bd8baf190b66e188d43485639c6fc5355190868e"),
}

UNRELEASED_LOCK_OBJECTS = {
    "ao-architecture": b'    {"name":"ao-architecture","version":"git-60313323e56b","repository":"https://github.com/uesugitorachiyo/ao-architecture.git","commit":"60313323e56b52095a39445c93367c29787131a9","asset":"ao","license":"Apache-2.0","sha256":"89eca8a6309b1314d2d500e8a0599690019ae2ba3098a412c605794b6ade63d8"},\n',
    "ao-blueprint": b'    {"name":"ao-blueprint","version":"git-a581a22af7d0","repository":"https://github.com/uesugitorachiyo/ao-blueprint.git","commit":"a581a22af7d06483287a1b7590709e4c4d3739b8","asset":"ao-blueprint","license":"Apache-2.0","sha256":"f86f221351069bbece0bd2afacdf964c812081018d71a94286bb0103927cafec"},\n',
    "ao-foundry": b'    {"name":"ao-foundry","version":"git-028ec4d50847","repository":"https://github.com/uesugitorachiyo/ao-foundry.git","commit":"028ec4d50847247ee48c1d8d4560a4eda3422550","asset":"foundry","license":"Apache-2.0","sha256":"42fd3ec7a471ef508e81768b772cf812d420db540fea9c086456c4ccc55d6ddb"},\n',
    "ao-arena": b'    {"name":"ao-arena","version":"git-e5d600108582","repository":"https://github.com/uesugitorachiyo/ao-arena.git","commit":"e5d60010858242b1dc5bdee9fbf1bcf1975e4ec9","asset":"ao-arena","license":"Apache-2.0","sha256":"e1d1e7bbd44856076f02fbac3e26ce67e88906caadc1680321676c4d266af724"},\n',
    "ao-crucible": b'    {"name":"ao-crucible","version":"git-64227e3ee305","repository":"https://github.com/uesugitorachiyo/ao-crucible.git","commit":"64227e3ee305cc3399063b567e02a548b5bc1855","asset":"ao-crucible","license":"Apache-2.0","sha256":"a4804dd244121d20b4516d0f44cde1b4fb59cae97df8ac2bffb5aedcdfdbb600"},\n',
    "ao-sentinel": b'    {"name":"ao-sentinel","version":"git-c301b1192c77","repository":"https://github.com/uesugitorachiyo/ao-sentinel.git","commit":"c301b1192c77a6b1833c49a5c9230491be50a258","asset":"ao-sentinel","license":"Apache-2.0","sha256":"6e0d60c7e885de127b1211bbaee8632ed6639046dcd70050c705b28ace4e7d2a"},\n',
    "ao-promoter": b'    {"name":"ao-promoter","version":"git-5b103a66476e","repository":"https://github.com/uesugitorachiyo/ao-promoter.git","commit":"5b103a66476e45bcf0c7fdcf4fffdb82b415ff72","asset":"ao-promoter","license":"Apache-2.0","sha256":"5fb55aa61d49328d3c1a02ac90754ab4eb0ce903d3520c3c04577a10a09e9ba1"}\n',
}


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

    def test_tracked_lock_repins_coherent_release_without_changing_unreleased_objects(self):
        lock_path = Path(__file__).parents[1] / "manifests/components.lock.json"
        lock_bytes = lock_path.read_bytes()
        components = {component["name"]: component for component in json.loads(lock_bytes)["components"]}
        actual_released = {
            name: tuple(components[name][field] for field in ("version", "commit", "asset", "sha256"))
            for name in RELEASED_LOCK_VALUES
        }
        raw_objects = {
            json.loads(line.rstrip(b"\r\n").removesuffix(b","))["name"]: line
            for line in lock_bytes.splitlines(keepends=True)
            if line.lstrip().startswith(b'{"name":')
        }

        self.assertEqual(actual_released, RELEASED_LOCK_VALUES)
        self.assertEqual({name: raw_objects[name] for name in UNRELEASED_LOCK_OBJECTS}, UNRELEASED_LOCK_OBJECTS)

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
