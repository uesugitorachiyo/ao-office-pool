import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import scripts.build_preview as builder
from tests.test_bootstrap_acquisition import ASSET_NAMES
from tests.test_package_builder import REQUIRED_BOOTSTRAP_MEMBERS


ROOT = Path(__file__).parents[1]
ACQUISITION = ROOT / "packaging" / "Get-AOOfficePoolRelease.ps1"


class BootstrapCleanDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.shell = shutil.which("pwsh") or shutil.which("powershell")
        if self.shell is None:
            self.skipTest("PowerShell is unavailable")

    def tearDown(self):
        self.temporary.cleanup()

    def build_archive(self):
        source = self.root / "product-source"
        for relative in REQUIRED_BOOTSTRAP_MEMBERS | {
            "manifests/developer-preview-release.json"
        }:
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / relative).read_bytes())

        component_root = self.root / "components"
        identities = json.loads(json.dumps(builder._S01_LOCKS))
        components = {}
        for index, (name, identity) in enumerate(sorted(identities.items())):
            data = f"clean bootstrap {name} {index}\n".encode()
            identity["sha256"] = hashlib.sha256(data).hexdigest()
            binary = component_root / name / identity["asset"]
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(data)
            components[name] = (identity["version"], binary)
        lock_path = self.root / "components.lock.json"
        lock_path.write_text(
            json.dumps({"components": list(identities.values())}), encoding="utf-8"
        )
        archive = self.root / "ao-office-pool-developer-preview.zip"
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
        return archive

    def make_release_assets(self, archive):
        source = self.root / "release-assets"
        source.mkdir()
        archive_target = source / ASSET_NAMES[1]
        shutil.copy2(archive, archive_target)
        archive_digest = hashlib.sha256(archive_target.read_bytes()).hexdigest()
        (source / ASSET_NAMES[2]).write_text(
            f"{archive_digest} *{ASSET_NAMES[1]}\n", encoding="utf-8"
        )
        for index, name in enumerate(ASSET_NAMES[3:], start=3):
            (source / name).write_bytes(f"metadata {index} {name}\n".encode())

        rows = []
        for name in ASSET_NAMES[1:]:
            data = (source / name).read_bytes()
            rows.append(
                {
                    "name": name,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        candidate = {
            "schema_version": 1,
            "candidate_id": "clean-directory",
            "label": "developer-preview",
            "architecture": "windows-x86_64",
            "source": {"commit": "3" * 40, "clean": True},
            "component_lock_sha256": "4" * 64,
            "archive": rows[0],
            "components": [],
            "metadata": rows,
            "installer": {},
            "immutable": True,
            "authority": {},
        }
        candidate_bytes = (
            json.dumps(candidate, indent=2, sort_keys=True) + "\n"
        ).encode()
        (source / ASSET_NAMES[0]).write_bytes(candidate_bytes)
        contract = {
            "schema_version": 1,
            "repository": "uesugitorachiyo/ao-office-pool",
            "visibility": "private",
            "tag": "developer-preview-v98",
            "product_source_commit": "3" * 40,
            "architecture": "windows-x86_64",
            "asset_names": list(ASSET_NAMES),
            "candidate_manifest": {
                "name": ASSET_NAMES[0],
                "size": len(candidate_bytes),
                "sha256": hashlib.sha256(candidate_bytes).hexdigest(),
            },
        }
        contract_path = self.root / "release-contract.json"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        return source, contract_path

    def run_powershell(self, arguments, cwd, environment=None):
        return subprocess.run(
            [self.shell, "-NoProfile", "-File", *map(str, arguments)],
            cwd=cwd,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_readme_first_drives_clean_install_verify_and_uninstall(self):
        archive = self.build_archive()
        release_assets, contract = self.make_release_assets(archive)
        operator = self.root / "operator"
        operator.mkdir()
        downloads = operator / "downloads"
        acquisition = self.run_powershell(
            [
                ACQUISITION,
                "-Contract",
                contract,
                "-OfflineAssetRoot",
                release_assets,
                "-Destination",
                downloads,
            ],
            operator,
            os.environ | {"AO_OFFICE_POOL_TEST_MODE": "1"},
        )
        self.assertEqual(acquisition.returncode, 0, acquisition.stderr)
        self.assertEqual(json.loads(acquisition.stdout)["mode"], "offline")

        bootstrap = operator / "bootstrap"
        with zipfile.ZipFile(downloads / ASSET_NAMES[1]) as package:
            names = set(package.namelist())
            self.assertNotIn("manifests/developer-preview-release.json", names)
            package.extractall(bootstrap)
        readme = (bootstrap / "README-FIRST.md").read_text(encoding="utf-8")
        scripts = sorted(set(re.findall(r"\./(packaging/[A-Za-z-]+\.ps1)", readme)))
        self.assertEqual(
            scripts,
            [
                "packaging/Install-AOOfficePool.ps1",
                "packaging/Uninstall-AOOfficePool.ps1",
                "packaging/Verify-AOOfficePool.ps1",
            ],
        )
        self.assertTrue(all((bootstrap / relative).is_file() for relative in scripts))

        if platform.system() != "Windows":
            return
        install_root = operator / "installed" / "AOOfficePool"
        archive_path = downloads / ASSET_NAMES[1]
        sidecar = downloads / ASSET_NAMES[2]
        install = self.run_powershell(
            [
                bootstrap / scripts[0],
                "-Action",
                "Install",
                "-Archive",
                archive_path,
                "-ChecksumFile",
                sidecar,
                "-InstallRoot",
                install_root,
            ],
            bootstrap,
        )
        self.assertEqual(install.returncode, 0, install.stderr)
        verify = self.run_powershell(
            [
                bootstrap / scripts[2],
                "-InstallRoot",
                install_root,
                "-Archive",
                archive_path,
                "-ChecksumFile",
                sidecar,
            ],
            bootstrap,
        )
        self.assertEqual(verify.returncode, 0, verify.stderr)
        uninstall = self.run_powershell(
            [
                bootstrap / scripts[1],
                "-InstallRoot",
                install_root,
                "-Archive",
                archive_path,
                "-ChecksumFile",
                sidecar,
            ],
            bootstrap,
        )
        self.assertEqual(uninstall.returncode, 0, uninstall.stderr)
        self.assertFalse(install_root.exists())
        preserved = list(install_root.parent.glob(install_root.name + ".uninstalled.*"))
        self.assertEqual(len(preserved), 1)


if __name__ == "__main__":
    unittest.main()
