import copy
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).parents[1]
ARCHIVE_NAME = "ao-office-pool-v0.1.2-windows-x86_64.zip"
SIDECAR_NAME = ARCHIVE_NAME + ".sha256"


class PublicAcquisitionTests(unittest.TestCase):
    def setUp(self):
        if shutil.which("pwsh") is None:
            self.skipTest("PowerShell 7 is required")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.script = ROOT / "packaging" / "Get-AOOfficePoolPublicRelease.ps1"
        self.contract = self.root / "public-release.json"
        self.fixture_path = self.root / "fixture.json"
        self.archive = self.root / ARCHIVE_NAME
        self.sidecar = self.root / SIDECAR_NAME
        self.destination = self.root / "published"
        self.archive.write_bytes(b"public archive fixture\x00\x01")
        archive_hash = self.sha256(self.archive.read_bytes())
        self.sidecar.write_bytes(f"{archive_hash}  {ARCHIVE_NAME}\n".encode("utf-8"))
        self.write_contract()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def sha256(value):
        return hashlib.sha256(value).hexdigest()

    def contract_value(self):
        return {
            "schema_version": 1,
            "repository": "uesugitorachiyo/ao-office-pool",
            "visibility": "public",
            "tag": "v0.1.2",
            "source_commit": "1" * 40,
            "architecture": "windows-x86_64",
            "assets": [
                {
                    "name": ARCHIVE_NAME,
                    "size": self.archive.stat().st_size,
                    "sha256": self.sha256(self.archive.read_bytes()),
                },
                {
                    "name": SIDECAR_NAME,
                    "size": self.sidecar.stat().st_size,
                    "sha256": self.sha256(self.sidecar.read_bytes()),
                },
            ],
        }

    def write_contract(self, value=None, path=None):
        (path or self.contract).write_text(
            json.dumps(self.contract_value() if value is None else value), encoding="utf-8"
        )

    def metadata_fixture(self):
        contract = self.contract_value()
        assets = [
            {
                "name": identity["name"],
                "size": identity["size"],
                "browser_download_url": (
                    "https://github.com/uesugitorachiyo/ao-office-pool/releases/download/"
                    f"v0.1.2/{identity['name']}"
                ),
            }
            for identity in contract["assets"]
        ]
        return {
            "repository": {
                "full_name": "uesugitorachiyo/ao-office-pool",
                "private": False,
                "visibility": "public",
            },
            "release": {
                "tag_name": "v0.1.2",
                "draft": False,
                "prerelease": False,
                "assets": assets,
            },
            "downloads": [
                {
                    "name": ARCHIVE_NAME,
                    "source_path": str(self.archive.resolve()),
                    "final_url": assets[0]["browser_download_url"],
                },
                {
                    "name": SIDECAR_NAME,
                    "source_path": str(self.sidecar.resolve()),
                    "final_url": (
                        "https://objects.githubusercontent.com/release-assets/"
                        + SIDECAR_NAME
                    ),
                },
            ],
        }

    def run_public_acquisition(
        self, fixture=None, contract=None, destination=None, env_updates=None, cwd=None
    ):
        fixture = copy.deepcopy(
            self.metadata_fixture() if fixture is None else fixture
        )
        self.fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
        environment = os.environ.copy()
        environment.pop("GITHUB_TOKEN", None)
        environment.update(
            {
                "AO_OFFICE_POOL_TEST_MODE": "1",
                "AO_OFFICE_POOL_PUBLIC_RELEASE_FIXTURE": str(
                    self.fixture_path.resolve()
                ),
            }
        )
        if env_updates:
            environment.update(env_updates)
        return subprocess.run(
            [
                "pwsh",
                "-NoLogo",
                "-NoProfile",
                "-File",
                str(self.script),
                "-Contract",
                str(contract or self.contract),
                "-Destination",
                str(destination or self.destination),
            ],
            cwd=cwd or ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def assert_rejected(self, fixture=None, contract=None, destination=None, env=None):
        result = self.run_public_acquisition(
            fixture=fixture, contract=contract, destination=destination, env_updates=env
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((destination or self.destination).exists())
        self.assertNotIn(str(self.root), result.stdout + result.stderr)
        self.assert_no_owned_staging()

    def assert_no_owned_staging(self):
        self.assertEqual(
            [],
            list(self.root.glob(".ao-office-pool-public-staging-*")),
            "owned staging residue remains",
        )

    def test_accepts_exact_closed_public_release_atomically_and_reports_identities(self):
        result = self.run_public_acquisition()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            sorted(path.name for path in self.destination.iterdir()),
            sorted((ARCHIVE_NAME, SIDECAR_NAME)),
        )
        self.assertEqual(self.archive.read_bytes(), (self.destination / ARCHIVE_NAME).read_bytes())
        self.assertEqual(self.sidecar.read_bytes(), (self.destination / SIDECAR_NAME).read_bytes())
        report = json.loads(result.stdout)
        self.assertEqual(
            set(report),
            {"mode", "repository", "tag", "architecture", "destination", "assets"},
        )
        self.assertEqual(report["mode"], "public")
        self.assertEqual(report["destination"], self.destination.name)
        self.assertEqual(report["assets"], self.contract_value()["assets"])

    def test_accepts_release_assets_in_arbitrary_metadata_order(self):
        fixture = self.metadata_fixture()
        fixture["release"]["assets"].reverse()
        result = self.run_public_acquisition(fixture=fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["assets"], self.contract_value()["assets"])
        self.assertEqual(
            [ARCHIVE_NAME, SIDECAR_NAME],
            [path.name for path in self.destination.iterdir()],
        )

    def test_accepts_official_github_release_asset_redirect_host(self):
        fixture = self.metadata_fixture()
        for download in fixture["downloads"]:
            download["final_url"] = (
                "https://release-assets.githubusercontent.com/github-production-release-asset/"
                f"123456/{download['name']}"
            )
        result = self.run_public_acquisition(fixture=fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            sorted((ARCHIVE_NAME, SIDECAR_NAME)),
            sorted(path.name for path in self.destination.iterdir()),
        )

    def test_public_acquisition_never_requires_or_emits_github_token(self):
        result = self.run_public_acquisition()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("GITHUB_TOKEN", result.stdout + result.stderr)
        source = self.script.read_text(encoding="utf-8")
        self.assertNotIn("Authorization", source)
        self.assertNotIn("Credential", source)
        self.assertNotIn(str(self.root), result.stdout + result.stderr)

    def test_reports_stable_privacy_safe_failure_reasons(self):
        contract = self.contract_value()
        contract["repository"] = "other/repository"
        self.write_contract(contract)
        result = self.run_public_acquisition()
        self.assertEqual(
            result.stderr,
            "AO office pool public acquisition failed [contract-invalid]: "
            "contract validation failed\n",
        )
        self.assertFalse(self.destination.exists())

        self.write_contract()
        fixture = self.metadata_fixture()
        fixture["repository"]["private"] = True
        result = self.run_public_acquisition(fixture=fixture)
        self.assertEqual(
            result.stderr,
            "AO office pool public acquisition failed [repository-metadata-invalid]: "
            "repository metadata validation failed\n",
        )
        self.assertFalse(self.destination.exists())

        fixture = self.metadata_fixture()
        fixture["release"]["assets"].append(
            copy.deepcopy(fixture["release"]["assets"][0])
        )
        result = self.run_public_acquisition(fixture=fixture)
        self.assertEqual(
            result.stderr,
            "AO office pool public acquisition failed [release-assets-invalid]: "
            "release asset set validation failed\n",
        )
        self.assertFalse(self.destination.exists())

        fixture = self.metadata_fixture()
        self.archive.write_bytes(b"drift")
        result = self.run_public_acquisition(fixture=fixture)
        self.assertEqual(
            result.stderr,
            "AO office pool public acquisition failed [asset-content-invalid]: "
            "downloaded asset verification failed\n",
        )
        self.assertFalse(self.destination.exists())

        self.destination.mkdir()
        result = self.run_public_acquisition()
        self.assertEqual(
            result.stderr,
            "AO office pool public acquisition failed [destination-exists]: "
            "choose an absent destination\n",
        )

    def test_incomplete_release_assets_report_stable_failure_reason(self):
        valid_asset = self.metadata_fixture()["release"]["assets"][0]
        cases = [("null", None), ("empty", {})]
        for field in ("name", "size", "browser_download_url"):
            asset = copy.deepcopy(valid_asset)
            del asset[field]
            cases.append((f"missing-{field}", asset))

        for name, asset in cases:
            with self.subTest(name=name):
                fixture = self.metadata_fixture()
                fixture["release"]["assets"][0] = asset
                result = self.run_public_acquisition(fixture=fixture)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(
                    result.stderr,
                    "AO office pool public acquisition failed [release-assets-invalid]: "
                    "release asset set validation failed\n",
                )
                self.assertFalse(self.destination.exists())
                self.assertNotIn(str(self.root), result.stdout + result.stderr)
                self.assert_no_owned_staging()

    def test_incomplete_repository_and_release_metadata_report_stable_reasons(self):
        cases = []
        for name, value in (
            ("null", None),
            ("empty", {}),
            ("array", []),
            ("string", "object"),
            ("boolean", False),
            ("number", 1),
        ):
            fixture = self.metadata_fixture()
            fixture["repository"] = value
            cases.append((f"repository-{name}", fixture, "repository-metadata-invalid"))
        for field in ("full_name", "private", "visibility"):
            fixture = self.metadata_fixture()
            del fixture["repository"][field]
            cases.append((f"repository-missing-{field}", fixture, "repository-metadata-invalid"))

        for name, value in (
            ("null", None),
            ("empty", {}),
            ("array", []),
            ("string", "object"),
            ("boolean", False),
            ("number", 1),
        ):
            fixture = self.metadata_fixture()
            fixture["release"] = value
            cases.append((f"release-{name}", fixture, "release-metadata-invalid"))
        for field in ("tag_name", "draft", "prerelease"):
            fixture = self.metadata_fixture()
            del fixture["release"][field]
            cases.append((f"release-missing-{field}", fixture, "release-metadata-invalid"))
        fixture = self.metadata_fixture()
        del fixture["release"]["assets"]
        cases.append(("release-missing-assets", fixture, "release-assets-invalid"))

        reasons = {
            "repository-metadata-invalid": "repository metadata validation failed",
            "release-metadata-invalid": "release metadata validation failed",
            "release-assets-invalid": "release asset set validation failed",
        }
        for name, fixture, code in cases:
            with self.subTest(name=name):
                result = self.run_public_acquisition(fixture=fixture)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(
                    result.stderr,
                    f"AO office pool public acquisition failed [{code}]: "
                    f"{reasons[code]}\n",
                )
                self.assertFalse(self.destination.exists())
                self.assertNotIn(str(self.root), result.stdout + result.stderr)
                self.assert_no_owned_staging()

    def test_rejects_repository_and_release_metadata_drift(self):
        mutations = (
            lambda v: v["repository"].update(full_name="other/repo"),
            lambda v: v["repository"].update(private=True),
            lambda v: v["repository"].update(visibility="private"),
            lambda v: v["release"].update(tag_name="v0.1.3"),
            lambda v: v["release"].update(draft=True),
            lambda v: v["release"].update(prerelease=True),
            lambda v: v["release"]["assets"].pop(),
            lambda v: v["release"]["assets"].append(copy.deepcopy(v["release"]["assets"][0])),
            lambda v: v["release"]["assets"][1].update(name=ARCHIVE_NAME),
            lambda v: v["release"]["assets"][0].update(name="renamed.zip"),
            lambda v: v["release"]["assets"][0].update(size=2),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                fixture = self.metadata_fixture()
                mutate(fixture)
                self.assert_rejected(fixture=fixture)

    def test_rejects_falsey_and_wrong_scalar_types_without_publication(self):
        string_values = ([], {}, None, False, 1, ["expected", "extra"])
        bool_values = ([], {}, None, 0, "false", [False, False])
        integer_values = ([], {}, None, False, 1.5, "1", [1, 1])
        cases = []
        for field in ("repository", "visibility", "tag", "source_commit", "architecture"):
            for value in string_values:
                contract = self.contract_value()
                contract[field] = value
                cases.append((f"contract-{field}-{value!r}", contract, None))
        for value in integer_values:
            contract = self.contract_value()
            contract["schema_version"] = value
            cases.append((f"contract-schema-{value!r}", contract, None))
        for index in range(2):
            for field in ("name", "sha256"):
                for value in string_values:
                    contract = self.contract_value()
                    contract["assets"][index][field] = value
                    cases.append((f"contract-asset-{index}-{field}-{value!r}", contract, None))
            for value in integer_values:
                contract = self.contract_value()
                contract["assets"][index]["size"] = value
                cases.append((f"contract-asset-{index}-size-{value!r}", contract, None))
        for field in ("full_name", "visibility"):
            for value in string_values:
                fixture = self.metadata_fixture()
                fixture["repository"][field] = value
                cases.append((f"repository-{field}-{value!r}", None, fixture))
        for value in bool_values:
            fixture = self.metadata_fixture()
            fixture["repository"]["private"] = value
            cases.append((f"repository-private-{value!r}", None, fixture))
        for field in ("tag_name",):
            for value in string_values:
                fixture = self.metadata_fixture()
                fixture["release"][field] = value
                cases.append((f"release-{field}-{value!r}", None, fixture))
        for field in ("draft", "prerelease"):
            for value in bool_values:
                fixture = self.metadata_fixture()
                fixture["release"][field] = value
                cases.append((f"release-{field}-{value!r}", None, fixture))
        for index in range(2):
            for field in ("name", "browser_download_url"):
                for value in string_values:
                    fixture = self.metadata_fixture()
                    fixture["release"]["assets"][index][field] = value
                    cases.append((f"release-asset-{index}-{field}-{value!r}", None, fixture))
            for value in integer_values:
                fixture = self.metadata_fixture()
                fixture["release"]["assets"][index]["size"] = value
                cases.append((f"release-asset-{index}-size-{value!r}", None, fixture))
            for field in ("name", "source_path", "final_url"):
                for value in string_values:
                    fixture = self.metadata_fixture()
                    fixture["downloads"][index][field] = value
                    cases.append((f"download-{index}-{field}-{value!r}", None, fixture))

        for case_index, (name, contract, fixture) in enumerate(cases):
            with self.subTest(name=name):
                contract_path = self.contract
                if contract is not None:
                    contract_path = self.root / f"scalar-{case_index}.json"
                    self.write_contract(contract, contract_path)
                destination = self.root / f"scalar-destination-{case_index}"
                result = self.run_public_acquisition(
                    fixture=fixture, contract=contract_path, destination=destination
                )
                self.assertNotEqual(result.returncode, 0, name)
                self.assertFalse(destination.exists(), name)
                self.assert_no_owned_staging()

    def test_rejects_download_url_and_redirect_identity_drift(self):
        urls = (
            "http://github.com/uesugitorachiyo/ao-office-pool/releases/download/v0.1.2/" + ARCHIVE_NAME,
            "https://user@github.com/uesugitorachiyo/ao-office-pool/releases/download/v0.1.2/" + ARCHIVE_NAME,
            "https://github.com:444/uesugitorachiyo/ao-office-pool/releases/download/v0.1.2/" + ARCHIVE_NAME,
            "https://example.invalid/" + ARCHIVE_NAME,
            "https://objects.githubusercontent.com/release-assets/" + ARCHIVE_NAME,
            "https://release-assets.githubusercontent.com/github-production-release-asset/123456/" + ARCHIVE_NAME,
            "https://github.com/other/repo/releases/download/v0.1.2/" + ARCHIVE_NAME,
            "https://github.com/uesugitorachiyo/ao-office-pool/releases/download/v0.1.3/" + ARCHIVE_NAME,
            "https://github.com/uesugitorachiyo/ao-office-pool/releases/download/v0.1.2/renamed.zip",
        )
        for url in urls:
            with self.subTest(url=url):
                fixture = self.metadata_fixture()
                fixture["release"]["assets"][0]["browser_download_url"] = url
                self.assert_rejected(fixture=fixture)
        for url in (
            "https://example.invalid/" + ARCHIVE_NAME,
            "https://release-assets.githubusercontent.com.example.invalid/x/" + ARCHIVE_NAME,
            "http://objects.githubusercontent.com/x/" + ARCHIVE_NAME,
            "https://user@objects.githubusercontent.com/x/" + ARCHIVE_NAME,
            "https://objects.githubusercontent.com:444/x/" + ARCHIVE_NAME,
            "https://objects.githubusercontent.com/x/renamed.zip",
        ):
            with self.subTest(final_url=url):
                fixture = self.metadata_fixture()
                fixture["downloads"][0]["final_url"] = url
                self.assert_rejected(fixture=fixture)

    def test_rejects_contract_shape_identity_and_tuple_mutations(self):
        mutations = []
        base = self.contract_value()
        mutations.extend(([], {"unknown": True}))
        for field in base:
            mutations.append({key: value for key, value in base.items() if key != field})
        for field, value in (
            ("schema_version", True),
            ("repository", "other/repo"),
            ("visibility", "private"),
            ("tag", "v0.1.3"),
            ("source_commit", "0" * 40),
            ("source_commit", "A" * 40),
            ("architecture", "linux-x86_64"),
        ):
            candidate = copy.deepcopy(base); candidate[field] = value; mutations.append(candidate)
        candidate = copy.deepcopy(base); candidate["unknown"] = 1; mutations.append(candidate)
        candidate = copy.deepcopy(base); candidate["assets"].reverse(); mutations.append(candidate)
        candidate = copy.deepcopy(base); candidate["assets"][0]["name"] = "wrong.zip"; mutations.append(candidate)
        candidate = copy.deepcopy(base); candidate["assets"][0]["size"] = True; mutations.append(candidate)
        candidate = copy.deepcopy(base); candidate["assets"][0]["sha256"] = "0" * 64; mutations.append(candidate)
        candidate = copy.deepcopy(base); candidate["assets"][0]["unknown"] = 1; mutations.append(candidate)
        for index, value in enumerate(mutations):
            with self.subTest(index=index):
                path = self.root / f"contract-{index}.json"
                self.write_contract(value, path)
                self.assert_rejected(contract=path)

    def test_rejects_asset_hash_size_and_sidecar_content_drift(self):
        mutations = (
            lambda: self.archive.write_bytes(b"drift"),
            lambda: self.sidecar.write_bytes(b"0" * 64 + b"  " + ARCHIVE_NAME.encode() + b"\n"),
            lambda: self.sidecar.write_bytes((self.sha256(self.archive.read_bytes()) + " *" + ARCHIVE_NAME + "\n").encode()),
            lambda: self.sidecar.write_bytes((self.sha256(self.archive.read_bytes()) + "  " + ARCHIVE_NAME + "\r\n").encode()),
            lambda: self.sidecar.write_bytes(b"\xef\xbb\xbf" + self.sidecar.read_bytes()),
        )
        original_archive = self.archive.read_bytes()
        original_sidecar = self.sidecar.read_bytes()
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.archive.write_bytes(original_archive)
                self.sidecar.write_bytes(original_sidecar)
                mutate()
                self.assert_rejected()

    def test_rejects_contract_bound_sidecar_with_wrong_semantics(self):
        archive_hash = self.sha256(self.archive.read_bytes())
        self.sidecar.write_bytes(f"{archive_hash} *{ARCHIVE_NAME}\n".encode("utf-8"))
        contract = self.contract_value()
        self.write_contract(contract)
        self.assert_rejected()

    def test_rejects_fixture_download_mapping_drift(self):
        mutations = (
            lambda v: v["downloads"].pop(),
            lambda v: v["downloads"].append(copy.deepcopy(v["downloads"][0])),
            lambda v: v["downloads"].reverse(),
            lambda v: v["downloads"][0].update(name=SIDECAR_NAME),
            lambda v: v["downloads"][0].update(unknown=True),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                fixture = self.metadata_fixture()
                mutate(fixture)
                self.assert_rejected(fixture=fixture)

    def test_rejects_non_array_collections_and_non_object_nested_values(self):
        cases = []
        for value in ({}, None, False, 1, "assets", [self.contract_value()["assets"][0]]):
            contract = self.contract_value()
            contract["assets"] = value
            cases.append(("contract-assets", contract, None))
        for value in ([], {}, None, False, 1, "object"):
            contract = self.contract_value()
            contract["assets"][0] = value
            cases.append(("contract-asset-object", contract, None))
        for field in ("repository", "release"):
            for value in ([], {}, None, False, 1, "object"):
                fixture = self.metadata_fixture()
                fixture[field] = value
                cases.append((f"fixture-{field}", None, fixture))
        for value in ({}, None, False, 1, "assets", [self.metadata_fixture()["release"]["assets"][0]]):
            fixture = self.metadata_fixture()
            fixture["release"]["assets"] = value
            cases.append(("release-assets", None, fixture))
        for value in ([], {}, None, False, 1, "object"):
            fixture = self.metadata_fixture()
            fixture["release"]["assets"][0] = value
            cases.append(("release-asset-object", None, fixture))
        for value in ({}, None, False, 1, "downloads", [self.metadata_fixture()["downloads"][0]]):
            fixture = self.metadata_fixture()
            fixture["downloads"] = value
            cases.append(("fixture-downloads", None, fixture))
        for value in ([], {}, None, False, 1, "object"):
            fixture = self.metadata_fixture()
            fixture["downloads"][0] = value
            cases.append(("fixture-download-object", None, fixture))

        for case_index, (name, contract, fixture) in enumerate(cases):
            with self.subTest(name=name, index=case_index):
                contract_path = self.contract
                if contract is not None:
                    contract_path = self.root / f"shape-{case_index}.json"
                    self.write_contract(contract, contract_path)
                destination = self.root / f"shape-destination-{case_index}"
                result = self.run_public_acquisition(
                    fixture=fixture, contract=contract_path, destination=destination
                )
                self.assertNotEqual(result.returncode, 0, name)
                self.assertFalse(destination.exists(), name)
                self.assert_no_owned_staging()

    def test_rejects_relative_contract_destination_fixture_and_asset_paths(self):
        work = self.root / "relative-work"
        work.mkdir()
        parent_contract = self.root / "parent-contract.json"
        self.write_contract(path=parent_contract)
        parent_fixture = self.root / "parent-fixture.json"
        parent_fixture.write_text(json.dumps(self.metadata_fixture()), encoding="utf-8")
        parent_archive = self.root / "parent-archive.zip"
        parent_archive.write_bytes(self.archive.read_bytes())
        relative_cases = (".\\public-release.json", "public-release.json", "..\\parent-contract.json")
        (work / "public-release.json").write_bytes(self.contract.read_bytes())
        for index, relative in enumerate(relative_cases):
            with self.subTest(kind="contract", relative=relative):
                destination = self.root / f"relative-contract-destination-{index}"
                result = self.run_public_acquisition(
                    contract=relative, destination=destination, cwd=work
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(destination.exists())
                self.assert_no_owned_staging()
        for index, relative in enumerate((".\\published", "published", "..\\published-parent")):
            with self.subTest(kind="destination", relative=relative):
                result = self.run_public_acquisition(destination=relative, cwd=work)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((work / relative).resolve().exists())
                self.assert_no_owned_staging()
        (work / "fixture.json").write_bytes(self.fixture_path.read_bytes() if self.fixture_path.exists() else json.dumps(self.metadata_fixture()).encode())
        for index, relative in enumerate((".\\fixture.json", "fixture.json", "..\\parent-fixture.json")):
            with self.subTest(kind="fixture", relative=relative):
                destination = self.root / f"relative-fixture-destination-{index}"
                result = self.run_public_acquisition(
                    destination=destination,
                    cwd=work,
                    env_updates={"AO_OFFICE_POOL_PUBLIC_RELEASE_FIXTURE": relative},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(destination.exists())
                self.assert_no_owned_staging()
        (work / ARCHIVE_NAME).write_bytes(self.archive.read_bytes())
        for index, relative in enumerate((f".\\{ARCHIVE_NAME}", ARCHIVE_NAME, "..\\parent-archive.zip")):
            with self.subTest(kind="asset", relative=relative):
                fixture = self.metadata_fixture()
                fixture["downloads"][0]["source_path"] = relative
                destination = self.root / f"relative-asset-destination-{index}"
                result = self.run_public_acquisition(
                    fixture=fixture, destination=destination, cwd=work
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(destination.exists())
                self.assert_no_owned_staging()

    def test_staging_attacks_fail_closed_without_deleting_unowned_paths(self):
        staging_name = ".ao-office-pool-public-staging-" + "a" * 32
        staging = self.root / staging_name
        staging.mkdir()
        marker = staging / "preexisting.txt"
        marker.write_text("keep", encoding="utf-8")
        collision = self.run_public_acquisition(
            env_updates={
                "AO_OFFICE_POOL_PUBLIC_RELEASE_TEST_STAGING_NAME": staging_name,
                "AO_OFFICE_POOL_PUBLIC_RELEASE_TEST_HOOK": "collision",
            }
        )
        with self.subTest(hook="collision"):
            self.assertNotEqual(collision.returncode, 0)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")
            self.assertFalse(self.destination.exists())
        marker.unlink(missing_ok=True)
        if staging.exists():
            staging.rmdir()

        for hook in ("extra-file", "subdirectory", "reparse", "replace-file"):
            with self.subTest(hook=hook):
                destination = self.root / f"hook-destination-{hook}"
                result = self.run_public_acquisition(
                    destination=destination,
                    env_updates={
                        "AO_OFFICE_POOL_PUBLIC_RELEASE_TEST_STAGING_NAME": staging_name,
                        "AO_OFFICE_POOL_PUBLIC_RELEASE_TEST_HOOK": hook,
                    },
                )
                self.assertNotEqual(result.returncode, 0, hook)
                self.assertFalse(destination.exists(), hook)
                self.assertFalse(staging.exists(), hook)

        replacement_destination = self.root / "hook-destination-replace-directory"
        replaced = self.run_public_acquisition(
            destination=replacement_destination,
            env_updates={
                "AO_OFFICE_POOL_PUBLIC_RELEASE_TEST_STAGING_NAME": staging_name,
                "AO_OFFICE_POOL_PUBLIC_RELEASE_TEST_HOOK": "replace-directory",
            },
        )
        with self.subTest(hook="replace-directory"):
            self.assertNotEqual(replaced.returncode, 0)
            self.assertFalse(replacement_destination.exists())
            self.assertTrue(staging.is_dir())
            if staging.is_dir():
                self.assertEqual(
                    (staging / "replacement.txt").read_text(encoding="utf-8"),
                    "keep",
                )
            self.assertTrue((self.root / (staging_name + ".displaced")).is_dir())

    def run_identity_boundary_hook(self, hook, fixture=None):
        staging_name = ".ao-office-pool-public-staging-" + "c" * 32
        result = self.run_public_acquisition(
            fixture=fixture,
            env_updates={
                "AO_OFFICE_POOL_PUBLIC_RELEASE_TEST_STAGING_NAME": staging_name,
                "AO_OFFICE_POOL_PUBLIC_RELEASE_TEST_HOOK": hook,
            },
        )
        staging = self.root / staging_name
        observed = self.root / (staging_name + ".hook-observed")
        replacement_created = self.root / (
            staging_name + ".replacement-created"
        )
        self.assertTrue(observed.is_file(), f"{hook} boundary was not exercised")
        return result, staging, replacement_created

    def test_create_to_lease_replacement_never_publishes_replacement_state(self):
        result, _, _ = self.run_identity_boundary_hook(
            "replace-between-create-and-lease"
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        if self.destination.exists():
            self.assertEqual(
                (self.destination / "replacement.txt").read_text(encoding="utf-8"),
                "keep",
            )

    def test_final_validation_to_publish_replacement_never_publishes(self):
        result, _, _ = self.run_identity_boundary_hook(
            "replace-between-validation-and-publish"
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        if self.destination.exists():
            self.assertEqual(
                (self.destination / "replacement.txt").read_text(encoding="utf-8"),
                "keep",
            )

    def test_final_validation_to_publish_injection_never_publishes(self):
        result, _, _ = self.run_identity_boundary_hook(
            "inject-between-validation-and-publish"
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        if self.destination.exists():
            self.assertEqual(
                (self.destination / "injected.txt").read_text(encoding="utf-8"),
                "keep",
            )

    def test_cleanup_identity_to_delete_replacement_is_never_deleted(self):
        fixture = self.metadata_fixture()
        fixture["downloads"][1]["source_path"] = str(self.archive.resolve())
        result, _, replacement_created = self.run_identity_boundary_hook(
            "replace-between-cleanup-check-and-delete", fixture=fixture
        )
        self.assertNotEqual(result.returncode, 0)
        if replacement_created.exists():
            self.assertEqual(
                (self.destination / "replacement.txt").read_text(encoding="utf-8"),
                "keep",
            )
        else:
            self.assertFalse(self.destination.exists())

    def test_rejects_existing_destination_without_altering_it(self):
        self.destination.mkdir()
        marker = self.destination / "keep.txt"
        marker.write_text("untouched", encoding="utf-8")
        result = self.run_public_acquisition()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "untouched")
        self.assertEqual([marker], list(self.destination.iterdir()))

    def test_rejects_non_ntfs_destination_when_available(self):
        if os.name != "nt":
            self.skipTest("Windows volume semantics")
        volume = ctypes.create_unicode_buffer(260)
        if not ctypes.windll.kernel32.GetVolumePathNameW(
            str(ROOT), volume, len(volume)
        ):
            self.skipTest("workspace volume unavailable")
        filesystem = ctypes.create_unicode_buffer(32)
        if not ctypes.windll.kernel32.GetVolumeInformationW(
            volume.value, None, 0, None, None, None, filesystem, len(filesystem)
        ):
            self.skipTest("workspace filesystem unavailable")
        if filesystem.value == "NTFS":
            self.skipTest("no non-NTFS workspace volume")
        local = ROOT / ".local"
        local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=local) as temporary:
            destination = Path(temporary) / "published"
            result = self.run_public_acquisition(destination=destination)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                result.stderr,
                "AO office pool public acquisition failed [unsupported-platform]: "
                "Windows local NTFS transaction support is required\n",
            )
            self.assertFalse(destination.exists())
            self.assertNotIn(str(self.root), result.stdout + result.stderr)

    def test_fixture_controls_require_exact_test_mode(self):
        for mode in ("", "0", "01", "true", "True", " 1"):
            with self.subTest(mode=mode):
                self.assert_rejected(env={"AO_OFFICE_POOL_TEST_MODE": mode})
        self.assert_rejected(
            env={
                "AO_OFFICE_POOL_TEST_MODE": "0",
                "AO_OFFICE_POOL_PUBLIC_RELEASE_FIXTURE": str(self.fixture_path),
            }
        )
        self.assert_rejected(
            env={
                "AO_OFFICE_POOL_TEST_MODE": "0",
                "AO_OFFICE_POOL_PUBLIC_RELEASE_TEST_HOOK": "extra-file",
                "AO_OFFICE_POOL_PUBLIC_RELEASE_TEST_STAGING_NAME": (
                    ".ao-office-pool-public-staging-" + "b" * 32
                ),
            }
        )

    def test_rejects_reparse_ancestors_when_supported(self):
        target = self.root / "real-parent"; target.mkdir()
        link = self.root / "linked-parent"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"directory symlinks unavailable: {error}")
        destination = link / "published"
        self.assert_rejected(destination=destination)

    def test_rejects_junction_ancestor_without_symlink_privilege(self):
        if os.name != "nt":
            self.skipTest("Windows junction semantics")
        target = self.root / "junction-target"
        target.mkdir()
        link = self.root / "junction-parent"
        environment = os.environ.copy()
        environment["AO_T3_JUNCTION_LINK"] = str(link)
        environment["AO_T3_JUNCTION_TARGET"] = str(target)
        created = subprocess.run(
            [
                "pwsh",
                "-NoLogo",
                "-NoProfile",
                "-Command",
                "$ErrorActionPreference='Stop'; "
                "New-Item -ItemType Junction -Path $env:AO_T3_JUNCTION_LINK "
                "-Target $env:AO_T3_JUNCTION_TARGET | Out-Null",
            ],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        if created.returncode != 0:
            self.skipTest("directory junctions unavailable")
        try:
            self.assert_rejected(destination=link / "published")
            self.assertTrue(target.is_dir())
        finally:
            os.rmdir(link)

    def test_rejects_hard_linked_regular_inputs_when_supported(self):
        cases = ((self.contract, "contract-link.json", "contract"), (self.fixture_path, "fixture-link.json", "fixture"), (self.archive, "archive-link.zip", "archive"))
        for source, link_name, kind in cases:
            with self.subTest(kind=kind):
                if source == self.fixture_path:
                    self.fixture_path.write_text(json.dumps(self.metadata_fixture()), encoding="utf-8")
                link = self.root / link_name
                try:
                    os.link(source, link)
                except OSError as error:
                    self.skipTest(f"hard links unavailable: {error}")
                fixture = self.metadata_fixture()
                contract = self.contract
                if kind == "contract": contract = link
                elif kind == "fixture":
                    fixture = json.loads(link.read_text(encoding="utf-8"))
                else: fixture["downloads"][0]["source_path"] = str(link)
                result = self.run_public_acquisition(fixture=fixture, contract=contract)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse(self.destination.exists())
                link.unlink()


class InstallAndVerifyOrchestrationTests(unittest.TestCase):
    def setUp(self):
        if os.name != "nt" or shutil.which("pwsh") is None:
            self.skipTest("native Windows PowerShell is required")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.distribution = self.root / "distribution"
        (self.distribution / "scripts").mkdir(parents=True)
        (self.distribution / "manifests").mkdir()
        self.script = self.distribution / "scripts" / "Install-And-Verify.ps1"
        shutil.copy2(ROOT / "scripts" / "Install-And-Verify.ps1", self.script)
        self.contract = self.distribution / "manifests" / "public-release.json"
        self.local_app_data = self.root / "local-app-data"
        self.local_app_data.mkdir()
        self.private_anchor = self.local_app_data / ".ao-office-pool-private"
        self.install_root = self.private_anchor / "installed"
        self.download_root = self.private_anchor / "downloads"
        self.fixture_root = self.root / "fixture"
        self.fixture_root.mkdir()
        self.event_log = self.root / "events.txt"
        self.archive = self.fixture_root / ARCHIVE_NAME
        self.sidecar = self.fixture_root / SIDECAR_NAME
        self.acquire = self.fixture_root / "acquire.ps1"
        self.replacement_archive = self.fixture_root / "replacement.zip"
        self.replacement_pair_root = self.root / "replacement-pair"
        self.replacement_pair_root.mkdir()
        self.replacement_pair_archive = self.replacement_pair_root / ARCHIVE_NAME
        self.replacement_pair_sidecar = self.replacement_pair_root / SIDECAR_NAME
        self.replacement_installer = self.fixture_root / "replacement-installer.ps1"
        self.replacement_launcher = self.fixture_root / "replacement-launcher.ps1"
        self.replacement_helper = self.fixture_root / "replacement-helper.txt"
        self._write_fixture_archive()
        self.replacement_archive.write_bytes(b"not the verified archive")
        self.replacement_installer.write_text(
            "Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value 'malicious'\n",
            encoding="utf-8",
        )
        self.replacement_launcher.write_text(
            "Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value 'malicious'\nexit 7\n",
            encoding="utf-8",
        )
        self.replacement_helper.write_text("malicious-helper", encoding="utf-8")
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.sidecar.write_text(f"{digest}  {ARCHIVE_NAME}\n", encoding="utf-8")
        self._write_public_contract()
        with zipfile.ZipFile(self.archive) as source:
            malicious = {name: source.read(name) for name in source.namelist()}
        malicious["packaging/Install-AOOfficePool.ps1"] = (
            b"Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value 'malicious'\nexit 7\n"
        )
        with zipfile.ZipFile(
            self.replacement_pair_archive, "w", compression=zipfile.ZIP_STORED
        ) as archive:
            for name, content in malicious.items():
                archive.writestr(name, content)
        malicious_digest = hashlib.sha256(self.replacement_pair_archive.read_bytes()).hexdigest()
        self.replacement_pair_sidecar.write_text(
            f"{malicious_digest}  {ARCHIVE_NAME}\n", encoding="utf-8"
        )
        self.acquire.write_text(
            """param([string]$Contract,[string]$Destination)
$ErrorActionPreference='Stop'
if ($env:AO_T4_FAIL_EVENT -ceq 'acquire') { exit 7 }
Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value 'acquire'
New-Item -ItemType Directory -Path $Destination | Out-Null
Copy-Item -LiteralPath $env:AO_T4_ARCHIVE -Destination (Join-Path $Destination 'ao-office-pool-v0.1.2-windows-x86_64.zip')
Copy-Item -LiteralPath $env:AO_T4_SIDECAR -Destination (Join-Path $Destination 'ao-office-pool-v0.1.2-windows-x86_64.zip.sha256')
[pscustomobject]@{mode='public'} | ConvertTo-Json -Compress
""",
            encoding="utf-8",
        )

    def _write_public_contract(self):
        assets = []
        for path in (self.archive, self.sidecar):
            content = path.read_bytes()
            assets.append(
                {
                    "name": path.name,
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )
        self.contract.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "repository": "uesugitorachiyo/ao-office-pool",
                    "visibility": "public",
                    "tag": "v0.1.2",
                    "source_commit": "1" * 40,
                    "architecture": "windows-x86_64",
                    "assets": assets,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )

    def _mutate_preview_manifest(self, mutation):
        with zipfile.ZipFile(self.archive) as source:
            members = {name: source.read(name) for name in source.namelist()}
        manifest = json.loads(members["developer-preview-manifest.json"])
        mutation(manifest)
        members["developer-preview-manifest.json"] = (
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, content in members.items():
                archive.writestr(name, content)
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.sidecar.write_text(f"{digest}  {ARCHIVE_NAME}\n", encoding="utf-8")
        self._write_public_contract()

    def _mutate_public_contract(self, mutation):
        contract = json.loads(self.contract.read_text(encoding="utf-8"))
        mutation(contract)
        self.contract.write_text(
            json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def _write_fixture_archive(self):
        install = r"""param([string]$Action,[string]$Archive,[string]$ChecksumFile,[string]$InstallRoot)
$ErrorActionPreference='Stop'
if ($env:AO_T4_FAIL_EVENT -ceq 'install') { exit 7 }
if ($env:AO_T4_FAIL_EVENT -ceq 'install-partial') {
  New-Item -ItemType Directory -Path (Join-Path $InstallRoot 'bin') | Out-Null
  Set-Content -LiteralPath (Join-Path $InstallRoot 'bin\partial.txt') -Value 'partial'
  exit 7
}
Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value 'install'
New-Item -ItemType Directory -Path (Join-Path $InstallRoot 'bin') | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\bin\ao-office-pool.ps1') -Destination (Join-Path $InstallRoot 'bin\ao-office-pool.ps1')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\bin\helper.txt') -Destination (Join-Path $InstallRoot 'bin\helper.txt')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\developer-preview-manifest.json') -Destination (Join-Path $InstallRoot 'developer-preview-manifest.json')
"""
        verify = r"""param([string]$InstallRoot,[string]$Archive,[string]$ChecksumFile)
if ($env:AO_T4_FAIL_EVENT -ceq 'verify') { exit 7 }
Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value 'verify'
if (Test-Path -LiteralPath (Join-Path $InstallRoot 'unexpected.txt')) { exit 7 }
if ((Get-Content -LiteralPath (Join-Path $InstallRoot 'bin\helper.txt') -Raw) -cne 'trusted-helper') { exit 7 }
"""
        launcher = r"""param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
$command = $Arguments[0]
if ($env:AO_T4_FAIL_EVENT -ceq $command) { exit 7 }
switch ($command) {
  'status' {
    $count = @(Get-Content -LiteralPath $env:AO_T4_EVENT_LOG -ErrorAction SilentlyContinue | Where-Object { $_ -ceq 'status:free' }).Count
    $mutation = $env:AO_T4_MUTATION
    $events = @(Get-Content -LiteralPath $env:AO_T4_EVENT_LOG -ErrorAction SilentlyContinue)
    $recovered = @($events | Where-Object { $_ -ceq 'recover:ok' }).Count -gt 0
    $cleanupStatus = $env:AO_T4_CLEANUP_STATUS
    $cleanupCheck = $env:AO_T4_MUTATION -ceq 'resume-other' -and @($events | Where-Object { $_ -ceq 'release:ok' }).Count -gt 0
    if ($cleanupCheck -and -not $recovered -and $cleanupStatus -ceq 'malformed') {
      Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value 'status:malformed'
      'not-json'
      break
    }
    if ($cleanupCheck -and -not $recovered -and $cleanupStatus -ceq 'nonzero') {
      Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value 'status:nonzero'
      exit 7
    }
    $claimed = @($events | Where-Object { $_ -like 'claim:*' }).Count -gt (@($events | Where-Object { $_ -in @('release:ok','recover:ok') }).Count)
    $cleanupBusy = $cleanupCheck -and $cleanupStatus -in @('busy','busy-after-recover') -and ($cleanupStatus -ceq 'busy-after-recover' -or -not $recovered)
    $free = -not $claimed -and -not (($mutation -ceq 'initial-status' -and $count -eq 0) -or ($mutation -ceq 'final-status' -and $count -eq 1 -and -not $recovered) -or $cleanupBusy)
    Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value $(if ($free) { 'status:free' } else { 'status:busy' })
    $offices = 1..5 | ForEach-Object { [pscustomobject]@{office_id="O$_";status=$(if ($free -or $_ -ne 1) {'free'} else {'busy'})} }
    [pscustomobject]@{schema_version=1;command='status';status='ok';offices=$offices} | ConvertTo-Json -Depth 4 -Compress
  }
  'claim' {
    $office = $(if ($env:AO_T4_MUTATION -ceq 'claim-other') {'O2'} else {'O1'})
    Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value "claim:$office"
    [pscustomobject]@{schema_version=1;command='claim';status='ok';office_id=$office;generation=1;authority_path='fixture-receipt'} | ConvertTo-Json -Compress
  }
  'resume' {
    $office = $(if ($env:AO_T4_MUTATION -ceq 'resume-other') {'O2'} else {'O1'})
    Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value "resume $office"
    [pscustomobject]@{schema_version=1;command='resume';status='ok';office_id=$office;authority_path='fixture-receipt'} | ConvertTo-Json -Compress
  }
  'release' {
    $ok = $env:AO_T4_MUTATION -cne 'release-bad'
    Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value $(if ($ok) {'release:ok'} else {'release:bad'})
    [pscustomobject]@{schema_version=1;command='release';status=$(if ($ok) {'ok'} else {'error'})} | ConvertTo-Json -Compress
  }
  'recover' {
    Add-Content -LiteralPath $env:AO_T4_EVENT_LOG -Value 'recover:ok'
    [pscustomobject]@{schema_version=1;command='recover';status='ok';office_id='O1';generation=1} | ConvertTo-Json -Compress
  }
}
"""
        payloads = {
            "packaging/Install-AOOfficePool.ps1": install,
            "packaging/Verify-AOOfficePool.ps1": verify,
            "bin/ao-office-pool.ps1": launcher,
            "bin/helper.txt": "trusted-helper",
        }
        installed = ("bin/ao-office-pool.ps1", "bin/helper.txt")
        manifest = {
            "schema_version": 1,
            "label": "developer-preview",
            "architecture": "windows-x86_64",
            "runtime_version": "fixture-runtime",
            "files": [
                {
                    "path": name,
                    "sha256": hashlib.sha256(payloads[name].encode()).hexdigest(),
                    "size": len(payloads[name].encode()),
                }
                for name in installed
            ],
        }
        payloads["developer-preview-manifest.json"] = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ) + "\n"
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, content in payloads.items():
                archive.writestr(name, content)

    def run_installer(self, mutation="", fail_event="", hook="", prerequisite="", use_defaults=False, cleanup_status="", install_root=None, download_root=None):
        environment = os.environ.copy()
        environment.update(
            {
                "LOCALAPPDATA": str(self.local_app_data),
                "AO_OFFICE_POOL_TEST_MODE": "1",
                "AO_OFFICE_POOL_INSTALL_VERIFY_ACQUIRE_SCRIPT": str(self.acquire),
                "AO_T4_EVENT_LOG": str(self.event_log),
                "AO_T4_ARCHIVE": str(self.archive),
                "AO_T4_SIDECAR": str(self.sidecar),
                "AO_T4_MUTATION": mutation,
                "AO_T4_FAIL_EVENT": fail_event,
                "AO_T4_CLEANUP_STATUS": cleanup_status,
                "AO_OFFICE_POOL_INSTALL_VERIFY_TEST_HOOK": hook,
                "AO_OFFICE_POOL_INSTALL_VERIFY_TEST_REPLACEMENT_ARCHIVE": str(self.replacement_archive),
                "AO_OFFICE_POOL_INSTALL_VERIFY_TEST_REPLACEMENT_PAIR_ARCHIVE": str(self.replacement_pair_archive),
                "AO_OFFICE_POOL_INSTALL_VERIFY_TEST_REPLACEMENT_PAIR_SIDECAR": str(self.replacement_pair_sidecar),
                "AO_OFFICE_POOL_INSTALL_VERIFY_TEST_REPLACEMENT_INSTALLER": str(self.replacement_installer),
                "AO_OFFICE_POOL_INSTALL_VERIFY_TEST_REPLACEMENT_LAUNCHER": str(self.replacement_launcher),
                "AO_OFFICE_POOL_INSTALL_VERIFY_TEST_REPLACEMENT_HELPER": str(self.replacement_helper),
                "AO_OFFICE_POOL_INSTALL_VERIFY_TEST_PREREQUISITE": prerequisite,
            }
        )
        command = ["pwsh", "-NoLogo", "-NoProfile", "-File", str(self.script)]
        if not use_defaults:
            command.extend(
                [
                    "-InstallRoot", str(self.install_root if install_root is None else install_root),
                    "-DownloadRoot", str(self.download_root if download_root is None else download_root),
                ]
            )
        return subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def events(self):
        if not self.event_log.exists():
            return []
        return self.event_log.read_text(encoding="utf-8").splitlines()

    def test_runs_exact_install_and_lifecycle_sequence(self):
        result = self.run_installer()
        self.assertEqual(
            result.returncode,
            0,
            f"{result.stderr}\nevents={self.events()} final={self.install_root.exists()} "
            f"staging={list(self.local_app_data.glob('.ao-office-pool-install-*'))} children={list(self.root.iterdir())}",
        )
        self.assertEqual(
            self.events(),
            [
                "acquire", "install", "verify", "status:free", "claim:O1",
                "resume O1", "release:ok", "status:free", "verify", "status:free",
            ],
        )
        self.assertIn("READY FOR USE", result.stdout)
        self.assertNotIn(str(self.fixture_root), result.stdout + result.stderr)
        for installed_file in self.install_root.rglob("*"):
            if installed_file.is_file():
                self.assertNotIn(b".ao-office-pool-install-", installed_file.read_bytes())

    def test_acquisition_return_assets_must_match_the_trusted_public_contract(self):
        result = self.run_installer(hook="replace-assets-after-acquisition")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "HOLD [archive-invalid]\n")
        self.assertEqual(self.events(), ["acquire"])
        self.assertNotIn("malicious", self.events())
        self.assertFalse(self.install_root.exists())

    def test_trusted_public_contract_is_closed_strictly_typed_and_identity_bound(self):
        archive_size = self.archive.stat().st_size
        cases = (
            ("extra-field", lambda value: value.__setitem__("extra", 1)),
            ("schema-string", lambda value: value.__setitem__("schema_version", "1")),
            ("schema-bool", lambda value: value.__setitem__("schema_version", True)),
            ("schema-double", lambda value: value.__setitem__("schema_version", 1.0)),
            ("repository-null", lambda value: value.__setitem__("repository", None)),
            ("visibility-bool", lambda value: value.__setitem__("visibility", True)),
            ("tag-number", lambda value: value.__setitem__("tag", 1)),
            ("source-null", lambda value: value.__setitem__("source_commit", None)),
            ("architecture-null", lambda value: value.__setitem__("architecture", None)),
            ("assets-object", lambda value: value.__setitem__("assets", {})),
            ("asset-extra", lambda value: value["assets"][0].__setitem__("extra", 1)),
            ("asset-name-null", lambda value: value["assets"][0].__setitem__("name", None)),
            ("asset-size-string", lambda value: value["assets"][0].__setitem__("size", str(archive_size))),
            ("asset-size-bool", lambda value: value["assets"][0].__setitem__("size", True)),
            ("asset-size-double", lambda value: value["assets"][0].__setitem__("size", float(archive_size))),
            ("asset-size-zero", lambda value: value["assets"][0].__setitem__("size", 0)),
            ("asset-size-range", lambda value: value["assets"][0].__setitem__("size", 2**80)),
            ("asset-sha-null", lambda value: value["assets"][0].__setitem__("sha256", None)),
            ("asset-order", lambda value: value["assets"].reverse()),
        )
        for name, mutation in cases:
            with self.subTest(name=name):
                self._write_public_contract()
                self._mutate_public_contract(mutation)
                self.event_log.unlink(missing_ok=True)
                shutil.rmtree(self.install_root, ignore_errors=True)
                shutil.rmtree(self.download_root, ignore_errors=True)
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0, name)
                self.assertEqual(result.stderr, "HOLD [archive-invalid]\n")
                self.assertEqual(self.events(), [])

        self._write_public_contract()
        self.event_log.unlink(missing_ok=True)
        shutil.rmtree(self.install_root, ignore_errors=True)
        shutil.rmtree(self.download_root, ignore_errors=True)
        result = self.run_installer(hook="replace-contract-after-read")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events(), [])
        self.assertFalse(self.install_root.exists())

    def test_hard_linked_trusted_public_contract_is_rejected_when_supported(self):
        original = self.contract.with_suffix(".original.json")
        self.contract.replace(original)
        try:
            os.link(original, self.contract)
        except OSError as error:
            original.replace(self.contract)
            self.skipTest(f"hard links unavailable: {error}")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "HOLD [archive-invalid]\n")
        self.assertEqual(self.events(), [])

    def test_preview_manifest_authority_types_are_exact(self):
        size = len("trusted-helper".encode())
        cases = (
            ("schema-string", lambda value: value.__setitem__("schema_version", "1")),
            ("schema-bool", lambda value: value.__setitem__("schema_version", True)),
            ("schema-double", lambda value: value.__setitem__("schema_version", 1.0)),
            ("schema-fraction", lambda value: value.__setitem__("schema_version", 1.5)),
            ("schema-null", lambda value: value.__setitem__("schema_version", None)),
            ("schema-negative", lambda value: value.__setitem__("schema_version", -1)),
            ("schema-range", lambda value: value.__setitem__("schema_version", 2**80)),
            ("size-string", lambda value: value["files"][1].__setitem__("size", str(size))),
            ("size-bool", lambda value: value["files"][1].__setitem__("size", True)),
            ("size-double", lambda value: value["files"][1].__setitem__("size", float(size))),
            ("size-fraction", lambda value: value["files"][1].__setitem__("size", size + 0.25)),
            ("size-null", lambda value: value["files"][1].__setitem__("size", None)),
            ("size-negative", lambda value: value["files"][1].__setitem__("size", -1)),
            ("size-range", lambda value: value["files"][1].__setitem__("size", 2**80)),
            ("runtime-number", lambda value: value.__setitem__("runtime_version", 7)),
            ("runtime-null", lambda value: value.__setitem__("runtime_version", None)),
            ("label-null", lambda value: value.__setitem__("label", None)),
            ("architecture-bool", lambda value: value.__setitem__("architecture", True)),
            ("path-null", lambda value: value["files"][0].__setitem__("path", None)),
            ("sha-null", lambda value: value["files"][0].__setitem__("sha256", None)),
        )
        for name, mutation in cases:
            with self.subTest(name=name):
                self._write_fixture_archive()
                self._mutate_preview_manifest(mutation)
                self.event_log.unlink(missing_ok=True)
                shutil.rmtree(self.install_root, ignore_errors=True)
                shutil.rmtree(self.download_root, ignore_errors=True)
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0, f"{name}: {self.events()}")
                self.assertEqual(result.stderr, "HOLD [extraction-failed]\n")
                self.assertEqual(self.events(), ["acquire"])
                self.assertFalse(self.install_root.exists())

    def test_failed_install_or_lifecycle_can_retry_immediately_with_same_download_root(self):
        for fail_event in ("install", "claim"):
            with self.subTest(fail_event=fail_event):
                first = self.run_installer(fail_event=fail_event)
                self.assertNotEqual(first.returncode, 0)
                self.assertTrue(self.download_root.is_dir())
                self.event_log.unlink(missing_ok=True)
                second = self.run_installer()
                self.assertEqual(second.returncode, 0, second.stderr)
                self.assertIn("READY FOR USE", second.stdout)
                shutil.rmtree(self.install_root)
                shutil.rmtree(self.download_root)

    def test_existing_download_base_is_preserved_and_usable(self):
        first = self.run_installer()
        self.assertEqual(first.returncode, 0, first.stderr)
        shutil.rmtree(self.install_root)
        self.event_log.unlink(missing_ok=True)
        marker = self.download_root / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep")
        self.assertTrue(any(path.is_dir() for path in self.download_root.iterdir()))

    def test_unowned_download_run_replacement_is_preserved_on_failed_cleanup(self):
        result = self.run_installer(
            fail_event="install", hook="replace-download-run-before-cleanup"
        )
        self.assertNotEqual(result.returncode, 0)
        replacements = list(self.download_root.glob(".ao-office-pool-download-*/keep.txt"))
        self.assertEqual(len(replacements), 1)
        self.assertEqual(replacements[0].read_text(encoding="utf-8"), "keep")
        self.assertFalse(self.install_root.exists())

    def test_every_sensitive_create_to_first_lease_boundary_rejects_replacement_or_weak_acl(self):
        hooks = (
            "replace-download-run-before-lease",
            "weaken-extract-root-before-lease",
            "replace-install-container-before-lease",
            "replace-install-stage-before-lease",
            "replace-project-before-lease",
            "weaken-final-root-before-acl-validation",
        )
        for hook in hooks:
            with self.subTest(hook=hook):
                self.event_log.unlink(missing_ok=True)
                shutil.rmtree(self.install_root, ignore_errors=True)
                shutil.rmtree(self.download_root, ignore_errors=True)
                result = self.run_installer(hook=hook)
                self.assertNotEqual(result.returncode, 0, hook)
                self.assertNotIn("READY FOR USE", result.stdout + result.stderr)
                self.assertFalse(self.install_root.exists())
                self.assertEqual(
                    list(self.local_app_data.glob(".ao-office-pool-install-*")), []
                )

    def test_custom_roots_outside_private_local_app_data_fail_before_mutation(self):
        shutil.rmtree(self.local_app_data)
        outside = self.root / "outside"
        outside.mkdir()
        marker = outside / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        result = self.run_installer(
            install_root=outside / "installed", download_root=outside / "downloads"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "HOLD [prerequisite-path]\n")
        self.assertEqual(self.events(), [])
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep")
        self.assertFalse(self.local_app_data.exists())
        self.assertFalse((outside / "installed").exists())
        self.assertFalse((outside / "downloads").exists())

    def test_lifecycle_semantic_mutations_fail_closed(self):
        for mutation in (
            "initial-status", "claim-other", "resume-other", "release-bad", "final-status",
        ):
            with self.subTest(mutation=mutation):
                self.event_log.unlink(missing_ok=True)
                shutil.rmtree(self.install_root, ignore_errors=True)
                shutil.rmtree(self.download_root, ignore_errors=True)
                result = self.run_installer(mutation=mutation)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("READY FOR USE", result.stdout + result.stderr)
                self.assertNotIn(str(self.root), result.stdout + result.stderr)

    def test_every_child_exit_failure_fails_closed(self):
        for event in ("acquire", "install", "verify", "status", "claim", "resume", "release"):
            with self.subTest(event=event):
                self.event_log.unlink(missing_ok=True)
                shutil.rmtree(self.install_root, ignore_errors=True)
                shutil.rmtree(self.download_root, ignore_errors=True)
                result = self.run_installer(fail_event=event)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("READY FOR USE", result.stdout + result.stderr)
                self.assertNotIn(str(self.root), result.stdout + result.stderr)

    def test_rejects_existing_install_root_without_altering_it(self):
        first = self.run_installer()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.event_log.unlink(missing_ok=True)
        marker = self.install_root / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep")
        self.assertNotIn("READY FOR USE", result.stdout + result.stderr)
        self.assertNotIn(str(self.root), result.stdout + result.stderr)

    def test_partial_install_failure_rolls_back_owned_staging_without_residue(self):
        result = self.run_installer(fail_event="install-partial")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "HOLD [installation-failed]\n")
        self.assertFalse(self.install_root.exists())
        self.assertEqual(list(self.private_anchor.glob(".ao-office-pool-install-*")), [])

    def test_archive_execution_and_cleanup_identity_races_fail_closed(self):
        for hook in (
            "replace-archive-after-hash",
            "replace-sidecar-after-validation",
            "replace-installer-after-extract",
            "replace-extract-root-before-cleanup",
            "replace-cleanup-quarantine-before-delete",
        ):
            with self.subTest(hook=hook):
                self.event_log.unlink(missing_ok=True)
                shutil.rmtree(self.install_root, ignore_errors=True)
                shutil.rmtree(self.download_root, ignore_errors=True)
                result = self.run_installer(hook=hook)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("READY FOR USE", result.stdout + result.stderr)
                self.assertNotIn("malicious", self.events())
                self.assertFalse(self.install_root.exists())
                if hook == "replace-extract-root-before-cleanup":
                    self.assertIn("cleanup-replacement-preserved", self.events())
                    replacements = list(self.private_anchor.glob(".ao-office-pool-extract-*/keep.txt"))
                    self.assertEqual(len(replacements), 1)
                    self.assertEqual(replacements[0].read_text(encoding="utf-8"), "keep")
                if hook == "replace-cleanup-quarantine-before-delete":
                    self.assertIn("cleanup-delete-race-blocked", self.events())

    def test_every_extracted_consumed_member_is_leased_before_use(self):
        for hook in ("replace-launcher-after-extract", "replace-helper-after-extract"):
            with self.subTest(hook=hook):
                self.event_log.unlink(missing_ok=True)
                shutil.rmtree(self.install_root, ignore_errors=True)
                shutil.rmtree(self.download_root, ignore_errors=True)
                result = self.run_installer(hook=hook)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("malicious", self.events())
                self.assertFalse(self.install_root.exists())
                self.assertEqual(list(self.private_anchor.glob(".ao-office-pool-install-*")), [])

    def test_missing_expected_installed_member_after_verification_fails_before_lifecycle(self):
        result = self.run_installer(hook="remove-installed-helper-after-verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events(), ["acquire", "install", "verify"])
        self.assertFalse(self.install_root.exists())
        self.assertEqual(list(self.private_anchor.glob(".ao-office-pool-install-*")), [])

    def test_install_publication_boundary_races_fail_closed_without_residue(self):
        for hook in (
            "replace-install-stage-before-publish",
            "inject-install-stage-before-publish",
        ):
            with self.subTest(hook=hook):
                self.event_log.unlink(missing_ok=True)
                shutil.rmtree(self.install_root, ignore_errors=True)
                shutil.rmtree(self.download_root, ignore_errors=True)
                result = self.run_installer(hook=hook)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("READY FOR USE", result.stdout + result.stderr)
                self.assertFalse(self.install_root.exists())
                staging = list(self.private_anchor.glob(".ao-office-pool-install-*"))
                self.assertEqual(staging, [])

    def test_claimed_office_is_released_or_recovered_on_late_failure(self):
        for mutation, failure in (
            ("resume-other", ""),
            ("", "resume"),
            ("release-bad", ""),
            ("final-status", ""),
        ):
            with self.subTest(mutation=mutation, failure=failure):
                self.event_log.unlink(missing_ok=True)
                shutil.rmtree(self.install_root, ignore_errors=True)
                shutil.rmtree(self.download_root, ignore_errors=True)
                result = self.run_installer(mutation=mutation, fail_event=failure)
                self.assertNotEqual(result.returncode, 0)
                events = self.events()
                self.assertTrue("release:ok" in events or "recover:ok" in events, events)
                self.assertEqual(events[-1], "status:free", events)
                self.assertFalse(self.install_root.exists())

    def test_cleanup_requires_terminal_all_free_or_recovers_then_rechecks(self):
        expected_tails = {
            "": ["release:ok", "status:free"],
            "busy": ["release:ok", "status:busy", "recover:ok", "status:free"],
            "malformed": ["release:ok", "status:malformed", "recover:ok", "status:free"],
            "nonzero": ["release:ok", "status:nonzero", "recover:ok", "status:free"],
        }
        for cleanup_status, expected in expected_tails.items():
            with self.subTest(cleanup_status=cleanup_status):
                self.event_log.unlink(missing_ok=True)
                shutil.rmtree(self.install_root, ignore_errors=True)
                shutil.rmtree(self.download_root, ignore_errors=True)
                result = self.run_installer(mutation="resume-other", cleanup_status=cleanup_status)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.events()[-len(expected):], expected)
                self.assertFalse(self.install_root.exists())
                self.assertEqual(list(self.private_anchor.glob(".ao-office-pool-install-*")), [])

        self.event_log.unlink(missing_ok=True)
        shutil.rmtree(self.download_root, ignore_errors=True)
        result = self.run_installer(mutation="final-status")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events()[-3:], ["status:busy", "recover:ok", "status:free"])
        self.assertFalse(self.install_root.exists())

    def test_cleanup_without_terminal_all_free_is_recovery_failure_and_retry_safe(self):
        result = self.run_installer(mutation="resume-other", cleanup_status="busy-after-recover")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "HOLD [recovery-failed]\n")
        self.assertEqual(self.events()[-4:], ["release:ok", "status:busy", "recover:ok", "status:busy"])
        self.assertFalse(self.install_root.exists())
        self.assertEqual(list(self.private_anchor.glob(".ao-office-pool-install-*")), [])

    def test_failures_have_stable_actionable_privacy_safe_hold_codes(self):
        cases = (
            ({"prerequisite": "platform"}, "prerequisite-platform"),
            ({"prerequisite": "git"}, "prerequisite-git"),
            ({"prerequisite": "python"}, "prerequisite-python"),
            ({"prerequisite": "vcruntime"}, "prerequisite-vcruntime"),
            ({"prerequisite": "path"}, "prerequisite-path"),
            ({"fail_event": "acquire"}, "acquisition-failed"),
            ({"fail_event": "install"}, "installation-failed"),
            ({"fail_event": "verify"}, "verification-failed"),
            ({"fail_event": "claim"}, "lifecycle-failed"),
            ({"mutation": "release-bad", "fail_event": "recover"}, "recovery-failed"),
        )
        for arguments, code in cases:
            with self.subTest(code=code):
                self.event_log.unlink(missing_ok=True)
                shutil.rmtree(self.install_root, ignore_errors=True)
                shutil.rmtree(self.download_root, ignore_errors=True)
                result = self.run_installer(**arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr, f"HOLD [{code}]\n")
                self.assertNotIn(str(self.root), result.stdout + result.stderr)

        self.event_log.unlink(missing_ok=True)
        shutil.rmtree(self.download_root, ignore_errors=True)
        self.sidecar.write_text(f"{'0' * 64}  {ARCHIVE_NAME}\n", encoding="utf-8")
        result = self.run_installer()
        self.assertEqual(result.stderr, "HOLD [archive-invalid]\n")

        shutil.rmtree(self.download_root, ignore_errors=True)
        self.archive.write_bytes(b"not a zip archive")
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.sidecar.write_text(f"{digest}  {ARCHIVE_NAME}\n", encoding="utf-8")
        self._write_public_contract()
        result = self.run_installer()
        self.assertEqual(result.stderr, "HOLD [extraction-failed]\n")

        self._write_fixture_archive()
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.sidecar.write_text(f"{digest}  {ARCHIVE_NAME}\n", encoding="utf-8")
        self._write_public_contract()
        shutil.rmtree(self.download_root, ignore_errors=True)
        result = self.run_installer(hook="replace-extract-root-before-cleanup")
        self.assertEqual(result.stderr, "HOLD [cleanup-failed]\n")

    def test_success_prints_self_contained_launcher_for_custom_install_root(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = f'& "{self.install_root}\\bin\\ao-office-pool.ps1" status'
        self.assertIn(expected, result.stdout)
        self.assertNotIn("$InstallRoot", result.stdout)

    def test_success_prints_self_contained_launcher_for_default_install_root(self):
        result = self.run_installer(use_defaults=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = f'& "{self.private_anchor}\\AOOfficePool\\bin\\ao-office-pool.ps1" status'
        self.assertIn(expected, result.stdout)
        self.assertNotIn("$InstallRoot", result.stdout)


if __name__ == "__main__":
    unittest.main()
