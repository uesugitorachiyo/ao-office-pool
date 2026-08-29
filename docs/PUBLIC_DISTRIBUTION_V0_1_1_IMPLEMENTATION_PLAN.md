# AO Office Pool v0.1.1 Public Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish AO Office Pool v0.1.1 as an independently licensed, checksum-bound Windows release that an unauthenticated user or Codex task can install and verify with one command.

**Architecture:** Keep the installed product and existing private/offline acquisition code intact. Add a narrow public acquisition script, a one-command orchestration script, and a tracked public-release contract that pins the immutable v0.1.1 assets. Keep publication and repository visibility behind complete local-history, release-asset, and GitHub-surface audits.

**Tech Stack:** PowerShell 7, Python 3.12 standard library, `unittest`, Git, GitHub Releases, deterministic ZIP archives, SHA-256, Apache License 2.0.

---

## File map

**Create**

- `LICENSE` — canonical Apache License 2.0 text for AO Office Pool.
- `NOTICE` — independent-project statement and bundled AO component notices.
- `schemas/public-release.schema.json` — closed v0.1.1 public-release contract schema.
- `manifests/public-release.json` — exact public tag, source, filenames, sizes, and hashes; finalized only after immutable assets exist.
- `packaging/Get-AOOfficePoolPublicRelease.ps1` — unauthenticated, fail-closed public asset acquisition.
- `scripts/Install-And-Verify.ps1` — ordinary-user orchestration and O1 lifecycle smoke test.
- `scripts/build_public_release.py` — exact maintainer CLI that admits the public tree and invokes the deterministic binary package builder.
- `scripts/scan_git_history.py` — standard-library scan of every blob reachable from every Git ref.
- `tests/test_public_installer.py` — PowerShell acquisition/orchestration behavior.
- `tests/test_public_release_contract.py` — schema, manifest, licensing, and archive contract.
- `tests/test_scan_git_history.py` — complete-history scanner behavior.
- `docs/MAINTAINER_PUBLICATION.md` — owner-only v0.1.1 build, audit, publication, visibility, and rollback procedure.

**Modify**

- `README.md` — one public copy-paste command and one AI prompt first; contributor qualification later.
- `README-FIRST.md` — public v0.1.1 identity and entry point.
- `docs/QUICKSTART.md` — short public path only.
- `docs/AI_OPERATOR_RUNBOOK.md` — use the public orchestration script unchanged.
- `docs/OPERATOR_GUIDE.md` — link public acquisition and retain advanced lifecycle details.
- `scripts/build_preview.py` — require and package `LICENSE` and `NOTICE` in the installed archive.
- `scripts/verify_bootstrap_contract.py` — verify the public release contract and new entry points.
- `scripts/scan_public_tree.py` — expose reusable byte-level content checks without weakening current tree scanning.
- `manifests/public-tree.json` — admit only the intentionally public files above.
- `tests/test_package_builder.py` — license/notice membership and deterministic packaging tests.
- `tests/test_bootstrap_contract.py` — public clone and AI contract assertions.
- `tests/test_stable_release_docs.py` — v0.1.1 public documentation assertions.

The existing `packaging/Get-AOOfficePoolRelease.ps1` remains the private/offline compatibility path and is not the ordinary public entry point.

## Task 1: Add the independent Apache-2.0 licensing contract

**Files:**

- Create: `LICENSE`
- Create: `NOTICE`
- Create: `tests/test_public_release_contract.py`
- Modify: `tests/test_package_builder.py`
- Modify: `scripts/build_preview.py`

- [ ] **Step 1: Write the failing licensing and archive-membership tests**

Add these tests to `tests/test_public_release_contract.py`:

```python
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


class PublicReleaseContractTests(unittest.TestCase):
    def test_repository_has_apache_license_and_independent_notice(self):
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)
        self.assertIn("AO Office Pool", notice)
        self.assertIn("independent project", notice)
        self.assertIn("not currently an official member of the AO Stack family", notice)

    def test_notice_names_every_locked_component_and_license(self):
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        lock = json.loads((ROOT / "manifests/components.lock.json").read_text(encoding="utf-8"))
        for component in lock["components"]:
            with self.subTest(component=component["name"]):
                self.assertEqual(component["license"], "Apache-2.0")
                self.assertIn(component["name"], notice)
```

Extend `PackageBuilderTests.REQUIRED_BOOTSTRAP_MEMBERS` with `LICENSE` and `NOTICE`, then add:

```python
def test_public_package_contains_license_and_notice(self):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source = self.bootstrap_source(root)
        component_root, components, lock_path, identities = self.portable_components(root)
        archive = root / "preview.zip"
        with mock.patch("scripts.build_preview._LOCK_PATH", lock_path), mock.patch(
            "scripts.build_preview._S01_LOCKS", identities
        ):
            builder.build_preview(
                source,
                components["ao2"][1],
                identities["ao2"]["version"],
                archive,
                components,
                component_root,
            )
        with zipfile.ZipFile(archive) as package:
            self.assertIn("LICENSE", package.namelist())
            self.assertIn("NOTICE", package.namelist())
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
python -B -m unittest tests.test_public_release_contract `
  tests.test_package_builder.PackageBuilderTests.test_public_package_contains_license_and_notice -v
```

Expected: failure because `LICENSE` and `NOTICE` do not exist and the package fixture does not require them.

- [ ] **Step 3: Add canonical license and exact notice content**

Create `LICENSE` from the unmodified canonical Apache License 2.0 text at `https://www.apache.org/licenses/LICENSE-2.0.txt`.

Create `NOTICE` with this exact project-specific structure:

```text
AO Office Pool
Copyright 2026 Torachiyo Uesugi

Licensed under the Apache License, Version 2.0. See LICENSE.

AO Office Pool is an independent project. It integrates with AO Stack
components but is not currently an official member of the AO Stack family.

The Windows distribution includes these Apache-2.0 components:
- ao2
- ao-mission
- ao-command
- ao-atlas
- ao-forge
- ao-covenant
- ao2-control-plane
- ao-blueprint

Exact versions, source repositories, commits, asset names, and SHA-256 values
are recorded in manifests/components.lock.json.
```

Add `LICENSE` and `NOTICE` to `_REQUIRED_BOOTSTRAP_MEMBERS` in `scripts/build_preview.py` and to the test fixture's `REQUIRED_BOOTSTRAP_MEMBERS`.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run the Step 2 command.

Expected: all selected tests pass.

- [ ] **Step 5: Commit the licensing slice**

```powershell
git add LICENSE NOTICE scripts/build_preview.py tests/test_package_builder.py tests/test_public_release_contract.py
git commit -m "Add Apache licensing to public package"
```

## Task 2: Define the closed public-release contract

**Files:**

- Create: `schemas/public-release.schema.json`
- Modify: `tests/test_public_release_contract.py`

- [ ] **Step 1: Write the failing schema and verifier tests**

Use a temporary, nonzero contract fixture in the tests; do not add a tracked release manifest before the final archive identities exist. Add:

```python
def test_public_contract_schema_accepts_only_exact_v011_shape(self):
    contract = self.valid_contract_fixture()
    self.assertEqual(
        set(contract),
        {"schema_version", "repository", "visibility", "tag", "source_commit", "architecture", "assets"},
    )
    self.assertEqual(contract["schema_version"], 1)
    self.assertEqual(contract["repository"], "uesugitorachiyo/ao-office-pool")
    self.assertEqual(contract["visibility"], "public")
    self.assertEqual(contract["tag"], "v0.1.1")
    self.assertRegex(contract["source_commit"], r"^[0-9a-f]{40}$")
    self.assertEqual(contract["architecture"], "windows-x86_64")
    self.assertEqual(
        [asset["name"] for asset in contract["assets"]],
        [
            "ao-office-pool-v0.1.1-windows-x86_64.zip",
            "ao-office-pool-v0.1.1-windows-x86_64.zip.sha256",
        ],
    )
    for asset in contract["assets"]:
        self.assertEqual(set(asset), {"name", "size", "sha256"})
        self.assertGreater(asset["size"], 0)
        self.assertRegex(asset["sha256"], r"^[0-9a-f]{64}$")
```

Add tests that validate the temporary contract against `schemas/public-release.schema.json` with `jsonschema` when the bundled dependency is available, and always perform the exact field/type checks above without relying on the schema implementation. Mutation tests must reject unknown fields, missing fields, zero hashes, zero size, a zero source commit, any tag except `v0.1.1`, any visibility except `public`, and an asset list different from the exact two names.

- [ ] **Step 2: Verify RED**

Run:

```powershell
python -B -m unittest tests.test_public_release_contract -v
```

Expected: failure because the schema does not exist.

- [ ] **Step 3: Add the closed schema without a provisional tracked manifest**

The schema must use `additionalProperties: false`, require all seven top-level fields, require exactly two assets, constrain `visibility` to `public`, `tag` to `v0.1.1`, architecture to `windows-x86_64`, commits to lowercase 40-hex, and hashes to lowercase 64-hex.

Keep all synthetic identities inside temporary test directories. Task 7 creates `manifests/public-release.json` once, using hashes and sizes computed from the final dual build. This avoids committing a knowingly invalid bootstrap contract.

- [ ] **Step 4: Verify GREEN**

Run:

```powershell
python -B -m unittest tests.test_public_release_contract -v
```

Expected: all schema and mutation tests pass.

- [ ] **Step 5: Commit the contract slice**

```powershell
git add schemas/public-release.schema.json tests/test_public_release_contract.py
git commit -m "Define public v0.1.1 release contract"
```

## Task 3: Add unauthenticated, fail-closed public acquisition

**Files:**

- Create: `packaging/Get-AOOfficePoolPublicRelease.ps1`
- Create: `tests/test_public_installer.py`

- [ ] **Step 1: Write fixture-driven RED tests**

Create a temporary contract, archive, sidecar, and metadata fixture in `tests/test_public_installer.py`. Run PowerShell with `AO_OFFICE_POOL_TEST_MODE=1` and `AO_OFFICE_POOL_PUBLIC_RELEASE_FIXTURE=<fixture path>`. Test these observable behaviors:

```python
def test_public_acquisition_never_requires_or_emits_github_token(self):
    result = self.run_public_acquisition()
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertNotIn("GITHUB_TOKEN", result.stdout + result.stderr)
    self.assertNotIn("Authorization", self.script.read_text(encoding="utf-8"))

def test_public_acquisition_rejects_repository_tag_visibility_and_asset_drift(self):
    for mutate in (
        lambda value: value["repository"].update(full_name="other/repo"),
        lambda value: value["repository"].update(private=True, visibility="private"),
        lambda value: value["release"].update(tag_name="v0.1.2"),
        lambda value: value["release"]["assets"].pop(),
        lambda value: value["release"]["assets"][0].update(size=2),
        lambda value: value["release"]["assets"][0].update(
            browser_download_url="https://example.invalid/archive.zip"
        ),
    ):
        with self.subTest(mutate=mutate):
            fixture = self.metadata_fixture()
            mutate(fixture)
            result = self.run_public_acquisition(fixture=fixture)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.destination.exists())

def test_public_acquisition_rejects_hash_drift_without_publishing_partial_files(self):
    self.archive.write_bytes(b"drift")
    result = self.run_public_acquisition()
    self.assertNotEqual(result.returncode, 0)
    self.assertFalse(self.destination.exists())
```

- [ ] **Step 2: Run and verify RED**

```powershell
python -B -m unittest tests.test_public_installer -v
```

Expected: failure because `Get-AOOfficePoolPublicRelease.ps1` does not exist.

- [ ] **Step 3: Implement the minimal public acquisition boundary**

The script parameters are:

```powershell
[CmdletBinding()]
param(
  [string]$Contract = (Join-Path $PSScriptRoot '..\manifests\public-release.json'),
  [Parameter(Mandatory = $true)]
  [string]$Destination
)
```

Implement these exact controls:

- Resolve and reject reparse/hard-linked contract, destination ancestors, and pre-existing destination.
- Parse an exact-field contract and reject all-zero identities.
- Fetch `https://api.github.com/repos/uesugitorachiyo/ao-office-pool` and `/releases/tags/v0.1.1` with only `Accept` and GitHub API-version headers.
- Require repository `full_name`, `private=false`, and `visibility=public`.
- Require release `draft=false`, `prerelease=false`, exact tag, exact two-asset set, exact sizes, and download URLs hosted only on `github.com` or `objects.githubusercontent.com` after redirects.
- Stream each asset into create-only staging while hashing; reject size or SHA drift before a single directory rename publishes the closed set.
- Permit metadata fixtures only when `AO_OFFICE_POOL_TEST_MODE` is exactly `1`.
- Print a compact JSON report containing mode `public`, repository, tag, architecture, destination basename, and asset identities; never print absolute private paths.

Use `[Net.Http.HttpCompletionOption]::ResponseHeadersRead`, `[IO.FileMode]::CreateNew`, incremental SHA-256, and `[IO.Directory]::Move` as in the existing private acquisition script. Do not copy credential handling into this script.

- [ ] **Step 4: Run focused acquisition tests**

Run the Step 2 command.

Expected: all tests pass without network access.

- [ ] **Step 5: Commit public acquisition**

```powershell
git add packaging/Get-AOOfficePoolPublicRelease.ps1 tests/test_public_installer.py
git commit -m "Add unauthenticated public release acquisition"
```

## Task 4: Add one-command install, verification, and lifecycle smoke

**Files:**

- Create: `scripts/Install-And-Verify.ps1`
- Modify: `tests/test_public_installer.py`

- [ ] **Step 1: Write orchestration RED tests**

Add fixture-mode tests requiring the script to call the public acquisition, installer, verifier, and launcher in order. Use temporary PowerShell stub scripts that append only these semantic events to a fixture log:

```text
acquire
install
verify
status:free
claim:O1
resume O1
release:ok
status:free
```

Add assertions for:

```python
self.assertEqual(events, [
    "acquire", "install", "verify", "status:free", "claim:O1",
    "resume O1", "release:ok", "status:free",
])
self.assertIn("READY FOR USE", result.stdout)
self.assertNotIn(str(self.root), result.stdout + result.stderr)
```

Mutation cases must return nonzero and omit `READY FOR USE` when initial status is not exactly O1-O5 free, claim returns another office, resume differs, release is not `ok`, final status is not all free, or any child command exits nonzero.

- [ ] **Step 2: Run and verify RED**

```powershell
python -B -m unittest tests.test_public_installer -v
```

Expected: orchestration tests fail because the script does not exist.

- [ ] **Step 3: Implement the public entry point**

Use this interface:

```powershell
[CmdletBinding()]
param(
  [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'AOOfficePool'),
  [string]$DownloadRoot = (Join-Path $env:LOCALAPPDATA 'AOOfficePoolDownloads\v0.1.1')
)
```

The script must:

- enforce PowerShell 7+, Windows x64, exactly Python 3.12, fixed local NTFS paths, path budget, and `VCRUNTIME140.dll`;
- reject an existing install root rather than overwrite it;
- call `Get-AOOfficePoolPublicRelease.ps1` with the closed destination;
- independently validate the sidecar filename/digest and archive hash;
- extract into a new temporary directory;
- invoke `Install-AOOfficePool.ps1` and `Verify-AOOfficePool.ps1`, checking every exit code;
- create a disposable Git repository on NTFS;
- require exact O1-O5 all-free status before and after O1 claim/resume/release;
- clear receipt-bearing variables in `finally`; and
- print only the portable install location, launcher command examples, and `READY FOR USE`.

Factor status validation into one local function:

```powershell
function Assert-AllFreeStatus {
  param([object]$Status)
  $expected = @('O1','O2','O3','O4','O5')
  $actual = @($Status.offices)
  if ($actual.Count -ne 5 -or
      (@($actual.office_id) -join ',') -cne ($expected -join ',') -or
      @($actual | Where-Object status -CNE 'free').Count -ne 0) {
    throw 'office-status-not-all-free'
  }
}
```

- [ ] **Step 4: Run focused tests**

Run the Step 2 command.

Expected: all acquisition and orchestration tests pass.

- [ ] **Step 5: Commit the one-command installer**

```powershell
git add scripts/Install-And-Verify.ps1 tests/test_public_installer.py
git commit -m "Add one-command Windows installation and verification"
```

## Task 5: Rewrite the user and AI documentation around the script

**Files:**

- Modify: `README.md`
- Modify: `README-FIRST.md`
- Modify: `docs/QUICKSTART.md`
- Modify: `docs/AI_OPERATOR_RUNBOOK.md`
- Modify: `docs/OPERATOR_GUIDE.md`
- Modify: `tests/test_stable_release_docs.py`
- Modify: `tests/test_bootstrap_contract.py`

- [ ] **Step 1: Replace private-flow assertions with public-flow RED tests**

Set `ARCHIVE` to `ao-office-pool-v0.1.1-windows-x86_64.zip`. Require the first README install block to contain exactly the clone, location, and script invocation. Add:

```python
def test_primary_install_path_is_public_and_single_command(self):
    self.assertIn("# AO Office Pool v0.1.1", self.readme)
    self.assertIn("pwsh -File .\\scripts\\Install-And-Verify.ps1", self.readme)
    primary = self.readme.split("## Contributor source qualification", 1)[0]
    self.assertNotIn("GITHUB_TOKEN", primary)
    self.assertNotIn("api.github.com", primary)
    self.assertNotIn("Visual Studio", primary)

def test_readme_identifies_independent_project(self):
    self.assertIn("independent project", self.readme)
    self.assertIn("not currently an official member of the AO Stack family", self.readme)

def test_ai_prompt_runs_the_same_public_script_unchanged(self):
    self.assertIn("Read README.md and docs/AI_OPERATOR_RUNBOOK.md completely", self.readme)
    self.assertIn("run scripts/Install-And-Verify.ps1 unchanged", self.readme)
    self.assertIn("return HOLD with the first exact blocker", self.readme)
```

- [ ] **Step 2: Run documentation tests and verify RED**

```powershell
python -B -m unittest tests.test_stable_release_docs tests.test_bootstrap_contract -v
```

Expected: failures for v0.1.0, private acquisition, and duplicated manual commands.

- [ ] **Step 3: Rewrite documents with one source of operational truth**

README order:

1. Product statement, Windows-only scope, independent-project disclaimer.
2. Prerequisites: PowerShell 7+, Python 3.12, VC++ v14 x64 runtime, Git.
3. Three-line install block calling `scripts/Install-And-Verify.ps1`.
4. Copy-paste AI prompt calling the same script unchanged.
5. Installed command examples for status, claim, resume, run, release, recover.
6. Contributor source qualification and Visual Studio-only distinction.
7. Links to advanced operator and maintainer documents.

Delete the README's embedded private GitHub API acquisition block. Keep authenticated/offline compatibility documented only in `docs/MAINTAINER_PUBLICATION.md` and the advanced operator guide.

- [ ] **Step 4: Run documentation tests and scanner**

```powershell
python -B -m unittest tests.test_stable_release_docs tests.test_bootstrap_contract -v
python -B scripts/scan_public_tree.py .
```

Expected: all tests pass and `public-tree findings=0` in the isolated worktree.

- [ ] **Step 5: Commit public documentation**

```powershell
git add README.md README-FIRST.md docs/QUICKSTART.md docs/AI_OPERATOR_RUNBOOK.md `
  docs/OPERATOR_GUIDE.md tests/test_stable_release_docs.py tests/test_bootstrap_contract.py
git commit -m "Make public installation the primary user path"
```

## Task 6: Add complete Git-history privacy scanning

**Files:**

- Create: `scripts/scan_git_history.py`
- Create: `tests/test_scan_git_history.py`
- Modify: `scripts/scan_public_tree.py`

- [ ] **Step 1: Write RED tests with deleted-secret history**

Create a temporary Git repository, commit a safe file, commit a synthetic secret marker, delete it in a third commit, then assert the scanner still finds the second commit's blob. Also test a clean multi-branch/tag repository and a blob containing an absolute Windows user path.

```python
completed = subprocess.run(
    [sys.executable, str(SCRIPT), str(repository)],
    text=True,
    capture_output=True,
    check=False,
)
self.assertEqual(completed.returncode, 1)
self.assertIn("history findings=1", completed.stderr)
self.assertNotIn(str(repository), completed.stdout + completed.stderr)
```

- [ ] **Step 2: Run and verify RED**

```powershell
python -B -m unittest tests.test_scan_git_history -v
```

Expected: failure because the scanner does not exist.

- [ ] **Step 3: Extract a reusable content-scan function and implement history scanning**

In `scan_public_tree.py`, add a pure function:

```python
def scan_content(relative: str, data: bytes) -> list[Finding]:
    path = Path(relative)
    if path.suffix.casefold() in {".exe", ".dll"}:
        return []
    text = data.decode("utf-8", errors="ignore")
    return [Finding(relative, "content", "private")] if any(
        rule.search(text) for rule in RULES
    ) else []
```

Preserve Python AST label scanning by moving the existing logic into this function. `scan_tree` must call it without changing current outputs.

`scan_git_history.py` must run Git with `-c core.quotepath=false`, enumerate `git rev-list --objects --all`, deduplicate object IDs, use `git cat-file --batch-check` to retain blobs only, and use `git cat-file --batch` to read exact bytes. It must report only object ID, safe repository-relative historical name when known, rule, and `private`; never print blob content or local absolute paths.

- [ ] **Step 4: Run focused and existing scanner tests**

```powershell
python -B -m unittest tests.test_scan_git_history tests.test_scan_public_tree -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit history scanning**

```powershell
git add scripts/scan_git_history.py scripts/scan_public_tree.py `
  tests/test_scan_git_history.py tests/test_scan_public_tree.py
git commit -m "Scan every reachable Git blob before publication"
```

## Task 7: Build immutable v0.1.1 assets and finalize the contract

**Files:**

- Create: `scripts/build_public_release.py`
- Create: `manifests/public-release.json`
- Modify: `scripts/verify_bootstrap_contract.py`
- Create: `docs/MAINTAINER_PUBLICATION.md`
- Modify: `manifests/public-tree.json`
- Test: `tests/test_public_release_contract.py`
- Test: `tests/test_package_builder.py`

- [ ] **Step 1: Add release-CLI, final-identity, and deterministic-archive tests**

Add a subprocess test for `scripts/build_public_release.py` using the existing portable component fixture and a temporary public-tree manifest. Require two invocations from the same source to emit identical bytes, include only allowlisted source members plus initialized runtime members and pinned component binaries, and include `LICENSE` and `NOTICE`. Tests must also reject an unclean source tree, component hash drift, all-zero release identities, mismatched sidecar filename/hash, archive size/hash drift, and an archive source commit different from the release contract.

- [ ] **Step 2: Run the focused tests and retain RED output**

```powershell
python -B -m unittest tests.test_public_release_contract tests.test_package_builder -v
```

Expected: failure because the release CLI and final manifest do not exist.

- [ ] **Step 3: Implement the exact release-builder CLI**

The CLI interface is:

```text
python -B scripts/build_public_release.py \
  --source <clean-detached-source> \
  --component-root <verified-component-root> \
  --output <new-zip-path>
```

Implement it with only the standard library and existing builders:

1. Require absolute, regular, non-reparse source, component-root, and output-parent paths; require the output not to exist.
2. Require `git -C <source> status --porcelain` to be empty and capture `git rev-parse HEAD`.
3. Call `verify_lock(source / "manifests/components.lock.json", component_root)`.
4. Use `build_release` and `source / "manifests/public-tree.json"` to create a temporary source-only ZIP, then extract it into a new temporary regular directory. Do not pass `.git` or unlisted files to the binary builder.
5. Load the lock and construct the component map exactly as `<component-root>/<name>/<version>/<asset>`.
6. Call `build_preview(staged_source, components["ao2"][1], locked_ao2_version, output, components, component_root)`.
7. Print one JSON object containing only `source_commit`, output basename, size, and SHA-256; do not print absolute paths.

Do not add networking, credential handling, or release mutation to this CLI.

- [ ] **Step 4: Verify and commit the payload builder**

Run the release-CLI and existing package tests that do not require the final tracked manifest, then commit the builder and its tests:

```powershell
python -B -m unittest tests.test_package_builder -v
python -B scripts/scan_public_tree.py .
git diff --check
git add scripts/build_public_release.py manifests/public-tree.json `
  tests/test_package_builder.py
git commit -m "Add deterministic public release builder"
```

Expected: tests pass, the tree scan reports zero findings, and the commit contains no archive bytes.

- [ ] **Step 5: Freeze the clean payload commit and build twice**

Commit all payload changes before building. Require compiler ready, current-tree scan zero, history scan zero, focused tests, and the full supervised Windows suite. Create a clean detached worktree at that exact commit and build twice with the exact pinned component root:

```powershell
$SourceCommit = (git rev-parse HEAD).Trim()
$SourceRoot = Join-Path $env:LOCALAPPDATA "AOOfficePoolSource-$SourceCommit"
$BuildA = Join-Path $env:LOCALAPPDATA "AOOfficePoolBuildA-$SourceCommit"
$BuildB = Join-Path $env:LOCALAPPDATA "AOOfficePoolBuildB-$SourceCommit"
$ComponentRoot = (Resolve-Path -LiteralPath $env:AO_OFFICE_POOL_COMPONENT_ROOT).Path
git worktree add --detach $SourceRoot $SourceCommit
New-Item -ItemType Directory -Path $BuildA,$BuildB | Out-Null
python -B scripts/build_public_release.py `
  --source $SourceRoot `
  --component-root $ComponentRoot `
  --output (Join-Path $BuildA 'ao-office-pool-v0.1.1-windows-x86_64.zip')
python -B scripts/build_public_release.py `
  --source $SourceRoot `
  --component-root $ComponentRoot `
  --output (Join-Path $BuildB 'ao-office-pool-v0.1.1-windows-x86_64.zip')
$ArchiveA = Join-Path $BuildA 'ao-office-pool-v0.1.1-windows-x86_64.zip'
$ArchiveB = Join-Path $BuildB 'ao-office-pool-v0.1.1-windows-x86_64.zip'
if ((Get-FileHash -Algorithm SHA256 $ArchiveA).Hash -cne
    (Get-FileHash -Algorithm SHA256 $ArchiveB).Hash) {
  throw 'nondeterministic-release-archive'
}
$Digest = (Get-FileHash -Algorithm SHA256 $ArchiveA).Hash.ToLowerInvariant()
$Sidecar = "$Digest  ao-office-pool-v0.1.1-windows-x86_64.zip`n"
[IO.File]::WriteAllText("$ArchiveA.sha256", $Sidecar, [Text.UTF8Encoding]::new($false))
```

Require `AO_OFFICE_POOL_COMPONENT_ROOT` to be an already populated absolute local NTFS directory; the build CLI re-verifies every byte against `manifests/components.lock.json`. Remove the detached worktree with `git worktree remove $SourceRoot` only after both builds and evidence capture succeed.

- [ ] **Step 6: Finalize exact nonzero identities**

Create `manifests/public-release.json` with `$SourceCommit`, exact asset sizes, archive SHA-256, and sidecar SHA-256. Update the verifier to validate the manifest against the closed schema and require those exact identities. The source commit deliberately precedes this metadata-only contract commit; the v0.1.1 tag will point to `$SourceCommit`. Do not add the release archive or sidecar to Git.

- [ ] **Step 7: Write the maintainer procedure**

`docs/MAINTAINER_PUBLICATION.md` must record exact commands and gates for clean source, compiler, current-tree scan, history scan, full suite, deterministic dual build, schema parsing, archive extraction scan, asset creation, GitHub-surface audit, release readback, visibility change, secret-protection enablement, clean public clone, and rollback. It must label v0.1.0 unsupported and superseded without deleting or replacing its bytes.

- [ ] **Step 8: Verify GREEN and commit finalized contract**

```powershell
python -B -m unittest tests.test_public_release_contract tests.test_package_builder -v
python -B scripts/verify_bootstrap_contract.py .
python -B scripts/scan_public_tree.py .
git diff --check
git add manifests/public-release.json scripts/verify_bootstrap_contract.py `
  docs/MAINTAINER_PUBLICATION.md tests/test_public_release_contract.py
git commit -m "Finalize public v0.1.1 release contract"
```

Expected: all commands pass and no release binary is tracked.

## Task 8: Complete repository and GitHub exposure audits

**Files:**

- Evidence only under ignored `.local/publication-v0.1.1/`

- [ ] **Step 1: Run local tracked-tree and complete-history scans**

```powershell
python -B scripts/scan_public_tree.py .
python -B scripts/scan_git_history.py .
```

Expected: `public-tree findings=0` and `history findings=0`.

- [ ] **Step 2: Scan release archives and assets**

Inventory every release through the GitHub API without printing authenticated headers. Download every asset into a new ignored audit root, record names/sizes/SHA-256, extract archives without executing content, and run the public-tree scanner against each extracted tree. Record v0.1.0 as unsupported because its archive has no project `LICENSE` or `NOTICE`; require v0.1.1 to contain both.

- [ ] **Step 3: Audit GitHub-visible surfaces**

Using the repository owner's authenticated browser or API session, inspect issues, pull requests, discussions, wiki, Actions logs/artifacts/caches, packages, Pages, environments, deploy keys, webhooks, releases, and repository settings. Record each surface as `clean`, `absent`, or `blocked` with a reason in `.local/publication-v0.1.1/github-surface-audit.md`.

- [ ] **Step 4: Stop on any finding**

Do not change visibility if any audit row is unresolved. For a secret, revoke it first. For historical private data, produce an exact object/ref remediation plan and obtain explicit approval before rewriting history or deleting remote artifacts.

- [ ] **Step 5: Record the clean audit decision**

Write `.local/publication-v0.1.1/PUBLICATION_AUDIT.md` with source commit, tag candidate, scanner results, asset inventory digests, GitHub surface table, licensing decision, and `READY_FOR_PUBLICATION` only when every gate is clean.

No commit is made because audit evidence can contain repository administration details and remains ignored.

## Task 9: Publish v0.1.1, change visibility, and verify a public clone

**Files:**

- External GitHub state and ignored evidence only

- [ ] **Step 1: Re-run the final local gate immediately before mutation**

Require clean main at the reviewed commit, contract verification, current-tree and history scans zero, full Windows summary `PASS`, exact asset digests, and `READY_FOR_PUBLICATION` audit state.

- [ ] **Step 2: Push source and create the immutable v0.1.1 tag and release**

Push the reviewed commit, create an annotated `v0.1.1` tag at the exact contract source commit, push the tag, and create a non-draft, non-prerelease release containing exactly the archive and sidecar. Read back the tag target, release metadata, asset names, sizes, and downloaded hashes. Stop on drift.

- [ ] **Step 3: Verify the already-finalized bootstrap contract on the pushed default branch**

Require the pushed default branch to contain the reviewed, finalized `manifests/public-release.json` commit from Task 7. Read the manifest back from GitHub and compare it byte-for-byte with the local reviewed file. Stop on drift. Do not move the v0.1.1 tag, replace release bytes, or create an ad-hoc post-release metadata commit.

- [ ] **Step 4: Label v0.1.0 historical and unsupported**

Edit only the v0.1.0 release title/body to say it was a private preview, lacks the public package license/notice, is unsupported, and is superseded by v0.1.1. Do not replace its assets or move its tag.

- [ ] **Step 5: Change repository visibility to public and enable protections**

Use the repository owner's authenticated GitHub settings. Change only `uesugitorachiyo/ao-office-pool` from private to public. Enable secret scanning and push protection when GitHub exposes those settings. Read back repository `private=false`, `visibility=public`, default branch, release, and tag.

- [ ] **Step 6: Run a genuinely unauthenticated clean Windows installation**

In a new fixed local NTFS directory with `GITHUB_TOKEN` removed:

```powershell
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
git clone https://github.com/uesugitorachiyo/ao-office-pool.git
Set-Location ao-office-pool
pwsh -File .\scripts\Install-And-Verify.ps1
```

Expected: `READY FOR USE`, exactly O1-O5 initially and finally free, and no credential prompt.

- [ ] **Step 7: Record final readback and keep the branch clean**

Record public repository metadata, source commit, release tag, exact asset hashes, clean-clone test result, installation verifier output, lifecycle smoke output, and final all-free state under `.local/publication-v0.1.1/FINAL_PUBLICATION_HANDBACK.md`. Confirm no temporary processes or task roots remain and the tracked tree is clean.

## Final verification matrix

Before claiming completion, run and retain fresh output from:

```powershell
python -B -m unittest tests.test_public_release_contract `
  tests.test_public_installer tests.test_scan_git_history `
  tests.test_stable_release_docs tests.test_bootstrap_contract `
  tests.test_package_builder tests.test_scan_public_tree -v
python -B -m tests.windows_compiler
python -B scripts/scan_public_tree.py .
python -B scripts/scan_git_history.py .
python -B scripts/verify_bootstrap_contract.py .
python -B scripts/run_windows_tests.py `
  --evidence-dir ".local/publication-v0.1.1/native" `
  --task-root (Join-Path $env:USERPROFILE "AOQ/public-v011")
git diff --check
git status --short
```

Completion requires focused tests green, compiler ready, both scanners at zero findings, bootstrap contract valid, full native runner `PASS` with no residue, deterministic archive identity, clean Git status, clean GitHub-surface audit, public repository readback, and unauthenticated clean-install `READY FOR USE`.
