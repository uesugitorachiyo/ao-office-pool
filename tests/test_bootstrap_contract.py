import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_bootstrap_contract import verify_release_manifest


ROOT = Path(__file__).parents[1]


class BootstrapContractTests(unittest.TestCase):
    def test_tracked_release_manifest_is_the_closed_private_v02_contract(self):
        result = verify_release_manifest(
            ROOT / "manifests/developer-preview-release.json"
        )
        self.assertEqual(result["repository"], "uesugitorachiyo/ao-office-pool")
        self.assertEqual(result["visibility"], "private")
        self.assertEqual(result["architecture"], "windows-x86_64")
        self.assertEqual(len(result["asset_names"]), 8)
        self.assertEqual(
            result["candidate_manifest"]["name"], "candidate-manifest.json"
        )
        self.assertEqual(
            result["product_source_commit"],
            "4bf8db6469a00dac69d2ddd7d103b501f797d7f6",
        )

    def test_release_manifest_rejects_unknown_fields_and_duplicate_asset_names(self):
        source = json.loads(
            (ROOT / "manifests/developer-preview-release.json").read_text()
        )
        for label, mutation in (
            ("unknown", lambda value: value.update(extra=True)),
            (
                "duplicate",
                lambda value: value["asset_names"].append(
                    value["asset_names"][0]
                ),
            ),
            ("visibility", lambda value: value.update(visibility="public")),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                value = json.loads(json.dumps(source))
                mutation(value)
                path = Path(temporary) / "contract.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(ValueError):
                    verify_release_manifest(path)


if __name__ == "__main__":
    unittest.main()
