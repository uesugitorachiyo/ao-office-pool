import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.verify_bootstrap_contract import verify_asset_directory


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "packaging" / "Get-AOOfficePoolRelease.ps1"
ASSET_NAMES = (
    "candidate-manifest.json",
    "ao-office-pool-developer-preview.zip",
    "ao-office-pool-developer-preview.zip.sha256",
    "member-inventory.json",
    "provenance.json",
    "RELEASE-NOTES.md",
    "SBOM.json",
    "SHA256SUMS",
)


class BootstrapAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.destination = self.root / "destination"
        self.contract = self.make_fixture(self.source)
        self.shell = shutil.which("pwsh") or shutil.which("powershell")
        if self.shell is None:
            self.skipTest("PowerShell is unavailable")

    def tearDown(self):
        self.temporary.cleanup()

    def make_fixture(self, source):
        source.mkdir()
        lock_path = ROOT / "manifests" / "components.lock.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        rows = []
        for index, name in enumerate(ASSET_NAMES[1:]):
            data = f"fixture {index} {name}\n".encode()
            (source / name).write_bytes(data)
            rows.append(
                {
                    "name": name,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        manifest = {
            "schema_version": 1,
            "candidate_id": "windows-ai-bootstrap-v99-1111111",
            "label": "developer-preview",
            "architecture": "windows-x86_64",
            "source": {"commit": "1" * 40, "clean": True},
            "component_lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
            "archive": rows[0],
            "components": lock["components"],
            "metadata": rows,
            "installer": {
                "acquire": "packaging/Get-AOOfficePoolRelease.ps1",
                "ai_runbook": "docs/AI_OPERATOR_RUNBOOK.md",
                "install": "packaging/Install-AOOfficePool.ps1",
                "read_first": "README-FIRST.md",
                "uninstall": "packaging/Uninstall-AOOfficePool.ps1",
                "verify": "packaging/Verify-AOOfficePool.ps1",
            },
            "immutable": True,
            "authority": {
                "publication_authorized": False,
                "release_visibility": "private",
                "tag_target": "1" * 40,
            },
        }
        manifest_bytes = (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode()
        (source / ASSET_NAMES[0]).write_bytes(manifest_bytes)
        contract = {
            "schema_version": 1,
            "repository": "uesugitorachiyo/ao-office-pool",
            "visibility": "private",
            "tag": "developer-preview-v99",
            "product_source_commit": "1" * 40,
            "architecture": "windows-x86_64",
            "asset_names": list(ASSET_NAMES),
            "candidate_manifest": {
                "name": ASSET_NAMES[0],
                "size": len(manifest_bytes),
                "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            },
        }
        contract_path = self.root / "contract.json"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        return contract_path

    def run_acquisition(self, source=None, destination=None):
        return subprocess.run(
            [
                self.shell,
                "-NoProfile",
                "-File",
                str(SCRIPT),
                "-Contract",
                str(self.contract),
                "-OfflineAssetRoot",
                str(source or self.source),
                "-Destination",
                str(destination or self.destination),
            ],
            text=True,
            env=os.environ | {"AO_OFFICE_POOL_TEST_MODE": "1"},
            capture_output=True,
            check=False,
        )

    def write_candidate(self, value):
        raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        (self.source / ASSET_NAMES[0]).write_bytes(raw)
        contract = json.loads(self.contract.read_text(encoding="utf-8"))
        contract["candidate_manifest"] = {
            "name": ASSET_NAMES[0],
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        self.contract.write_text(json.dumps(contract), encoding="utf-8")

    def make_metadata_fixture(self):
        contract = json.loads(self.contract.read_text(encoding="utf-8"))
        candidate = json.loads(
            (self.source / "candidate-manifest.json").read_text(encoding="utf-8")
        )
        identities = [contract["candidate_manifest"], *candidate["metadata"]]
        release = {
            "tag_name": contract["tag"],
            "target_commitish": contract["product_source_commit"],
            "draft": False,
            "prerelease": True,
            "assets": [
                {
                    "name": row["name"],
                    "size": row["size"],
                    "url": f"https://api.github.com/repos/uesugitorachiyo/ao-office-pool/releases/assets/{index + 1}",
                }
                for index, row in enumerate(identities)
            ],
        }
        return {
            "repository": {
                "full_name": "uesugitorachiyo/ao-office-pool",
                "private": True,
                "visibility": "private",
            },
            "release": release,
            "tag_objects": [
                {
                    "ref": f"refs/tags/{contract['tag']}",
                    "object": {
                        "type": "commit",
                        "sha": contract["product_source_commit"],
                        "url": f"https://api.github.com/repos/uesugitorachiyo/ao-office-pool/git/commits/{contract['product_source_commit']}",
                    },
                }
            ],
            "redirects": [
                {
                    "name": row["name"],
                    "url": f"https://objects.githubusercontent.com/fixture/{index + 1}",
                }
                for index, row in enumerate(identities)
            ],
            "candidate_manifest_path": str(self.source / "candidate-manifest.json"),
        }

    def run_metadata_fixture(self, fixture, test_mode="1"):
        fixture_path = self.root / "metadata-fixture.json"
        fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
        environment = os.environ | {
            "AO_OFFICE_POOL_METADATA_FIXTURE": str(fixture_path),
            "AO_OFFICE_POOL_TEST_MODE": test_mode,
        }
        return subprocess.run(
            [
                self.shell,
                "-NoProfile",
                "-Command",
                f". '{SCRIPT}' -Contract '{self.contract}'",
            ],
            text=True,
            env=environment,
            capture_output=True,
            check=False,
        )

    def test_offline_acquisition_copies_exact_closed_set(self):
        result = self.run_acquisition()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["mode"], "offline")
        self.assertEqual([row["name"] for row in report["assets"]], list(ASSET_NAMES))
        self.assertEqual({path.name for path in self.destination.iterdir()}, set(ASSET_NAMES))
        self.assertNotIn(str(self.source), result.stdout + result.stderr)

    def test_authenticated_assets_stream_to_create_only_atomic_staging(self):
        script = SCRIPT.read_text(encoding="utf-8")
        start = script.index("function Invoke-GitHubAsset")
        end = script.index("function Invoke-MetadataFixture")
        asset_path = script[start:end]
        self.assertIn("ResponseHeadersRead", asset_path)
        self.assertIn("ReadAsStreamAsync", asset_path)
        self.assertIn("[IO.FileMode]::CreateNew", script)
        self.assertIn("TransformBlock", script)
        self.assertNotIn("ReadAsByteArrayAsync", asset_path)
        self.assertIn("[IO.Directory]::Move", script)

    def test_offline_acquisition_rejects_wrong_hash_without_writes(self):
        (self.source / ASSET_NAMES[-1]).write_bytes(b"changed\n")
        result = self.run_acquisition()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.destination.exists())

    def test_candidate_manifest_rejects_every_nested_contract_drift(self):
        original_candidate = json.loads((self.source / ASSET_NAMES[0]).read_text(encoding="utf-8"))
        original_contract = json.loads(self.contract.read_text(encoding="utf-8"))
        mutations = (
            ("schema-type", lambda value: value.update(schema_version="1")),
            ("schema-bool", lambda value: value.update(schema_version=True)),
            ("immutable-type", lambda value: value.update(immutable=1)),
            ("clean-type", lambda value: value["source"].update(clean=1)),
            ("candidate-id", lambda value: value.update(candidate_id="fixture")),
            ("label", lambda value: value.update(label="fixture")),
            ("lock", lambda value: value.update(component_lock_sha256="2" * 64)),
            ("archive", lambda value: value["archive"].update(sha256="3" * 64)),
            ("components", lambda value: value.update(components=[])),
            ("installer", lambda value: value["installer"].update(install="install.ps1")),
            ("authority", lambda value: value["authority"].update(publication_authorized=True)),
            ("authority-type", lambda value: value["authority"].update(publication_authorized=0)),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                value = json.loads(json.dumps(original_candidate))
                mutate(value)
                self.write_candidate(value)
                with self.assertRaises(ValueError):
                    verify_asset_directory(self.source, self.contract)
                result = self.run_acquisition(destination=self.root / f"destination-{label}")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.contract.write_text(json.dumps(original_contract), encoding="utf-8")
                self.write_candidate(original_candidate)

    def test_offline_acquisition_rejects_unexpected_source_file(self):
        (self.source / "unexpected.bin").write_bytes(b"extra\n")
        result = self.run_acquisition()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.destination.exists())

    def test_offline_acquisition_rejects_hardlinked_assets(self):
        original = self.source / ASSET_NAMES[-1]
        outside = self.root / "outside"
        outside.mkdir()
        replacement = outside / original.name
        original.unlink()
        replacement.write_bytes(b"hardlinked\n")
        try:
            os.link(replacement, original)
        except OSError as error:
            self.skipTest(str(error))
        candidate = json.loads((self.source / ASSET_NAMES[0]).read_text(encoding="utf-8"))
        data = original.read_bytes()
        candidate["metadata"][-1].update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.write_candidate(candidate)
        with self.assertRaises(ValueError):
            verify_asset_directory(self.source, self.contract)
        self.assertNotEqual(self.run_acquisition().returncode, 0)

    def test_offline_acquisition_preserves_preexisting_destination_bytes(self):
        self.destination.mkdir()
        existing = self.destination / "keep.bin"
        existing.write_bytes(b"keep\n")
        result = self.run_acquisition()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(existing.read_bytes(), b"keep\n")
        self.assertEqual(list(self.destination.iterdir()), [existing])

    def test_offline_acquisition_rejects_reparse_ancestors(self):
        real_source = self.root / "real-source"
        real_destination = self.root / "real-destination"
        self.make_fixture(real_source)
        real_destination.mkdir()
        source_link = self.root / "source-link"
        destination_link = self.root / "destination-link"
        try:
            source_link.symlink_to(real_source, target_is_directory=True)
            destination_link.symlink_to(real_destination, target_is_directory=True)
        except OSError as error:
            self.skipTest(str(error))
        for source, destination in (
            (source_link, self.destination),
            (self.source, destination_link / "child"),
        ):
            with self.subTest(source=source.name, destination=destination.name):
                result = self.run_acquisition(source, destination)
                self.assertNotEqual(result.returncode, 0)

    def test_build_time_verifier_accepts_the_closed_fixture(self):
        verified = verify_asset_directory(self.source, self.contract)
        self.assertEqual([row["name"] for row in verified], list(ASSET_NAMES))

    def test_build_time_verifier_rejects_asset_drift(self):
        (self.source / ASSET_NAMES[-1]).write_bytes(b"drift\n")
        with self.assertRaisesRegex(ValueError, "asset identity"):
            verify_asset_directory(self.source, self.contract)

    def test_authenticated_metadata_fixture_accepts_closed_release(self):
        result = self.run_metadata_fixture(self.make_metadata_fixture())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"metadata": "valid"})

    def test_authenticated_metadata_requires_the_tag_ref_to_peel_to_the_pinned_commit(self):
        contract = json.loads(self.contract.read_text(encoding="utf-8"))
        pinned = contract["product_source_commit"]
        annotated = self.make_metadata_fixture()
        annotated["tag_objects"] = [
            {
                "ref": f"refs/tags/{contract['tag']}",
                "object": {
                    "type": "tag",
                    "sha": "a" * 40,
                    "url": "https://api.github.com/repos/uesugitorachiyo/ao-office-pool/git/tags/" + "a" * 40,
                },
            },
            {
                "sha": "a" * 40,
                "object": {
                    "type": "commit",
                    "sha": pinned,
                    "url": "https://api.github.com/repos/uesugitorachiyo/ao-office-pool/git/commits/" + pinned,
                },
            },
        ]
        self.assertEqual(self.run_metadata_fixture(annotated).returncode, 0)
        cases = {
            "missing": [],
            "moved": [{"ref": f"refs/tags/{contract['tag']}", "object": {"type": "commit", "sha": "f" * 40, "url": "https://api.github.com/repos/uesugitorachiyo/ao-office-pool/git/commits/" + "f" * 40}}],
            "invalid": [{"ref": f"refs/tags/{contract['tag']}", "object": {"type": "tree", "sha": pinned, "url": "https://api.github.com/invalid"}}],
            "cyclic": [
                {"ref": f"refs/tags/{contract['tag']}", "object": {"type": "tag", "sha": "a" * 40, "url": "https://api.github.com/repos/uesugitorachiyo/ao-office-pool/git/tags/" + "a" * 40}},
                {"sha": "a" * 40, "object": {"type": "tag", "sha": "a" * 40, "url": "https://api.github.com/repos/uesugitorachiyo/ao-office-pool/git/tags/" + "a" * 40}},
            ],
        }
        for label, objects in cases.items():
            with self.subTest(label=label):
                fixture = self.make_metadata_fixture()
                fixture["tag_objects"] = objects
                self.assertNotEqual(self.run_metadata_fixture(fixture).returncode, 0)

    def test_authenticated_metadata_rejects_identity_and_host_drift(self):
        cases = {
            "visibility": lambda value: value["repository"].update(private=False),
            "repository": lambda value: value["repository"].update(
                full_name="other/repository"
            ),
            "tag": lambda value: value["release"].update(tag_name="preview-v1"),
            "target": lambda value: value["release"].update(target_commitish=""),
            "asset-set": lambda value: value["release"]["assets"].pop(),
            "size": lambda value: value["release"]["assets"][0].update(
                size=value["release"]["assets"][0]["size"] + 1
            ),
            "asset-host": lambda value: value["release"]["assets"][0].update(
                url="https://example.invalid/releases/assets/1"
            ),
            "redirect-host": lambda value: value["redirects"][0].update(
                url="https://example.invalid/download/1"
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                fixture = self.make_metadata_fixture()
                mutate(fixture)
                result = self.run_metadata_fixture(fixture)
                self.assertNotEqual(result.returncode, 0)

    def test_metadata_fixture_is_rejected_outside_exact_test_mode(self):
        result = self.run_metadata_fixture(self.make_metadata_fixture(), test_mode="true")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
