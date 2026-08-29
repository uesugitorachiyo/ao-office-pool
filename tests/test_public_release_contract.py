import hashlib
import json
import re
import shutil
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from scripts.verify_bootstrap_contract import (
    verify_bootstrap_tree,
    verify_public_release_contract,
)

try:
    import jsonschema
except ImportError:  # The standard-library checks below remain authoritative.
    jsonschema = None


ROOT = Path(__file__).parents[1]
SCHEMA_PATH = ROOT / "schemas" / "public-release.schema.json"
ASSET_NAMES = [
    "ao-office-pool-v0.1.1-windows-x86_64.zip",
    "ao-office-pool-v0.1.1-windows-x86_64.zip.sha256",
]


class PublicReleaseContractTests(unittest.TestCase):
    def public_asset_fixture(self, root):
        asset_root = root / "assets"
        asset_root.mkdir()
        archive = asset_root / ASSET_NAMES[0]
        archive.write_bytes(b"public archive\n")
        archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        sidecar = asset_root / ASSET_NAMES[1]
        sidecar.write_bytes(f"{archive_digest}  {archive.name}\n".encode("ascii"))
        contract = self.valid_contract_fixture()
        contract["assets"] = [
            {
                "name": archive.name,
                "size": archive.stat().st_size,
                "sha256": archive_digest,
            },
            {
                "name": sidecar.name,
                "size": sidecar.stat().st_size,
                "sha256": hashlib.sha256(sidecar.read_bytes()).hexdigest(),
            },
        ]
        contract_path = root / "public-release.json"
        contract_path.write_text(
            json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        return contract_path, asset_root, archive, sidecar

    def test_public_release_verifier_binds_exact_archive_and_sidecar(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract, asset_root, archive, sidecar = self.public_asset_fixture(root)

            result = verify_public_release_contract(contract, asset_root)

            self.assertEqual(result["source_commit"], "1" * 40)
            self.assertEqual(
                [asset["name"] for asset in result["assets"]], ASSET_NAMES
            )
            self.assertEqual(result["assets"][0]["size"], archive.stat().st_size)
            self.assertEqual(result["assets"][1]["size"], sidecar.stat().st_size)

    def test_public_release_verifier_rejects_asset_and_sidecar_drift(self):
        for label, mutate in (
            ("archive-bytes", lambda archive, sidecar: archive.write_bytes(b"drift")),
            (
                "sidecar-semantics",
                lambda archive, sidecar: sidecar.write_text(
                    "0" * 64 + f"  {archive.name}\n", encoding="ascii"
                ),
            ),
            (
                "extra-asset",
                lambda archive, sidecar: (archive.parent / "extra.bin").write_bytes(
                    b"extra"
                ),
            ),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                contract, asset_root, archive, sidecar = self.public_asset_fixture(root)
                mutate(archive, sidecar)
                with self.assertRaises(ValueError):
                    verify_public_release_contract(contract, asset_root)

    def test_bootstrap_tree_rejects_invalid_public_release_contract_when_present(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "tree"
            shutil.copytree(
                ROOT,
                root,
                ignore=shutil.ignore_patterns(".git", ".local", "__pycache__"),
            )
            contract = root / "manifests" / "public-release.json"
            contract.write_text("{}\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                verify_bootstrap_tree(root)

    def test_maintainer_publication_runbook_contains_every_release_gate(self):
        path = ROOT / "docs" / "MAINTAINER_PUBLICATION.md"
        self.assertTrue(path.is_file())
        text = path.read_text(encoding="utf-8")
        for phrase in (
            "v0.1.0 is unsupported and superseded",
            "tests.windows_compiler",
            "scan_public_tree.py",
            "scan_git_history.py",
            "run_windows_tests.py",
            "build_public_release.py",
            "deterministic dual build",
            "verify_public_release_contract",
            "schema parse",
            "extracted archive scan",
            "GitHub-visible surfaces",
            "redistribution rights",
            "annotated `v0.1.1` tag",
            "release readback",
            "secret scanning and push protection",
            "unauthenticated clean clone",
            "Rollback",
            "READY_FOR_PUBLICATION",
        ):
            self.assertIn(phrase, text)

    def valid_contract_fixture(self):
        return {
            "schema_version": 1,
            "repository": "uesugitorachiyo/ao-office-pool",
            "visibility": "public",
            "tag": "v0.1.1",
            "source_commit": "1" * 40,
            "architecture": "windows-x86_64",
            "assets": [
                {"name": ASSET_NAMES[0], "size": 1, "sha256": "2" * 64},
                {"name": ASSET_NAMES[1], "size": 2, "sha256": "3" * 64},
            ],
        }

    def assert_exact_contract(self, contract):
        self.assertIs(type(contract), dict)
        self.assertEqual(
            set(contract),
            {
                "schema_version",
                "repository",
                "visibility",
                "tag",
                "source_commit",
                "architecture",
                "assets",
            },
        )
        self.assertIs(type(contract["schema_version"]), int)
        self.assertEqual(contract["schema_version"], 1)
        self.assertEqual(contract["repository"], "uesugitorachiyo/ao-office-pool")
        self.assertEqual(contract["visibility"], "public")
        self.assertEqual(contract["tag"], "v0.1.1")
        self.assertIs(type(contract["source_commit"]), str)
        self.assertTrue(re.fullmatch(r"[0-9a-f]{40}", contract["source_commit"]))
        self.assertNotEqual(contract["source_commit"], "0" * 40)
        self.assertEqual(contract["architecture"], "windows-x86_64")
        self.assertIs(type(contract["assets"]), list)
        self.assertEqual(len(contract["assets"]), 2)
        self.assertEqual([asset["name"] for asset in contract["assets"]], ASSET_NAMES)
        for asset in contract["assets"]:
            self.assertIs(type(asset), dict)
            self.assertEqual(set(asset), {"name", "size", "sha256"})
            self.assertIs(type(asset["size"]), int)
            self.assertGreater(asset["size"], 0)
            self.assertIs(type(asset["sha256"]), str)
            self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]))
            self.assertNotEqual(asset["sha256"], "0" * 64)

    def assert_invalid_contract(self, contract):
        with self.assertRaises((AssertionError, KeyError, TypeError)):
            self.assert_exact_contract(contract)
        if jsonschema is not None and SCHEMA_PATH.is_file():
            schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(contract, schema)

    def test_public_contract_schema_accepts_only_exact_v011_shape(self):
        contract = self.valid_contract_fixture()
        self.assert_exact_contract(contract)
        self.assertTrue(SCHEMA_PATH.is_file(), f"missing schema: {SCHEMA_PATH}")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        if jsonschema is not None:
            jsonschema.validate(contract, schema)

    def test_public_contract_rejects_top_level_field_and_type_mutations(self):
        mutations = {
            "top-level-wrong-type": [],
            "unknown-field": {**self.valid_contract_fixture(), "unknown": True},
            "schema-version-bool": {**self.valid_contract_fixture(), "schema_version": True},
            "schema-version-wrong": {**self.valid_contract_fixture(), "schema_version": 2},
            "repository-drift": {**self.valid_contract_fixture(), "repository": "other/repository"},
            "visibility-drift": {**self.valid_contract_fixture(), "visibility": "private"},
            "tag-drift": {**self.valid_contract_fixture(), "tag": "v0.1.2"},
            "architecture-drift": {**self.valid_contract_fixture(), "architecture": "linux-x86_64"},
            "assets-wrong-type": {**self.valid_contract_fixture(), "assets": {}},
        }
        for field in self.valid_contract_fixture():
            mutations[f"missing-{field}"] = {
                key: value
                for key, value in self.valid_contract_fixture().items()
                if key != field
            }
        for name, contract in mutations.items():
            with self.subTest(name=name):
                self.assert_invalid_contract(contract)

    def test_public_contract_rejects_source_commit_mutations(self):
        for value in (
            "A" * 40,
            "1" * 39,
            "1" * 41,
            "g" * 40,
            "0" * 40,
            "1" * 40 + "\n",
            "1" * 40 + "\r\n",
            None,
        ):
            with self.subTest(value=value):
                contract = self.valid_contract_fixture()
                contract["source_commit"] = value
                self.assert_invalid_contract(contract)

    def test_public_contract_rejects_asset_field_value_and_type_mutations(self):
        mutations = []
        for index, field in (
            (index, field)
            for index in range(2)
            for field in ("name", "size", "sha256")
        ):
            contract = self.valid_contract_fixture()
            del contract["assets"][index][field]
            mutations.append((f"asset-{index}-missing-{field}", contract))
        for index in range(2):
            contract = self.valid_contract_fixture()
            contract["assets"][index] = []
            mutations.append((f"asset-{index}-wrong-type", contract))
            contract = self.valid_contract_fixture()
            contract["assets"][index]["unknown"] = True
            mutations.append((f"asset-{index}-unknown-field", contract))
            for value in (
                "",
                "A" * 64,
                "1" * 63,
                "1" * 65,
                "g" * 64,
                "0" * 64,
                "1" * 64 + "\n",
                "1" * 64 + "\r\n",
                None,
            ):
                contract = self.valid_contract_fixture()
                contract["assets"][index]["sha256"] = value
                mutations.append((f"asset-{index}-hash-{value!r}", contract))
            for value in (0, -1, True, "1"):
                contract = self.valid_contract_fixture()
                contract["assets"][index]["size"] = value
                mutations.append((f"asset-{index}-size-{value!r}", contract))
        for name, contract in mutations:
            with self.subTest(name=name):
                self.assert_invalid_contract(contract)

    def test_public_contract_rejects_asset_array_mutations(self):
        contracts = {}
        contract = self.valid_contract_fixture()
        contract["assets"].reverse()
        contracts["reordered"] = contract
        contract = self.valid_contract_fixture()
        contract["assets"].pop()
        contracts["missing"] = contract
        contract = self.valid_contract_fixture()
        contract["assets"].append(deepcopy(contract["assets"][1]))
        contracts["extra"] = contract
        contract = self.valid_contract_fixture()
        contract["assets"][1] = deepcopy(contract["assets"][0])
        contracts["duplicate"] = contract
        for index in range(2):
            contract = self.valid_contract_fixture()
            contract["assets"][index]["name"] = "renamed.zip"
            contracts[f"asset-{index}-renamed"] = contract
        for name, contract in contracts.items():
            with self.subTest(name=name):
                self.assert_invalid_contract(contract)

    def test_license_is_apache_2_0(self):
        license_bytes = (ROOT / "LICENSE").read_bytes()
        license_text = license_bytes.decode("utf-8")
        canonical_license_bytes = license_bytes.replace(b"\r\n", b"\n")

        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)
        self.assertEqual(
            hashlib.sha256(canonical_license_bytes).hexdigest(),
            "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
        )

    def test_notice_declares_project_identity_and_relationship(self):
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")

        self.assertIn("AO Office Pool", notice)
        self.assertIn("independent project", notice)
        self.assertIn(
            "not currently an official member of the AO Stack family", notice
        )

    def test_locked_components_are_apache_2_0_and_named_in_notice(self):
        components = json.loads(
            (ROOT / "manifests/components.lock.json").read_text(encoding="utf-8")
        )["components"]
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        notice_components = {
            line[2:] for line in notice.splitlines() if line.startswith("- ")
        }

        for component in components:
            with self.subTest(component=component["name"]):
                self.assertEqual(component["license"], "Apache-2.0")
        self.assertEqual(
            notice_components, {component["name"] for component in components}
        )
