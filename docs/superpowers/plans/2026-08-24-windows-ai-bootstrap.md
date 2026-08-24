# Windows AI-Operable Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a new private Windows AO Office Pool candidate that an AI or human can acquire, verify, install, inspect, recover, and uninstall from a clean directory using only relative, documented commands.

**Architecture:** A closed JSON release contract binds acquisition to one private repository, tag target, architecture, and exact asset set. A PowerShell acquisition script uses that contract, while build-time Python validation, portable component-root handling, actionable privacy scanning, packaged operator skills, and a clean-directory acceptance harness keep the candidate deterministic and fail closed.

**Tech Stack:** Python 3.12 standard library and `unittest`, PowerShell 7/Windows PowerShell, JSON Schema, deterministic ZIP construction, Git.

---

## File map

- `README.md`: truthful private Windows entry point.
- `README-FIRST.md`: minimum archive-root bootstrap sequence.
- `docs/QUICKSTART.md`: concise human clean-machine procedure.
- `docs/AI_OPERATOR_RUNBOOK.md`: normative AI gate/decision contract.
- `docs/OPERATOR_GUIDE.md`: detailed installer, recovery, and uninstall reference.
- `manifests/developer-preview-release.json`: control-plane pin for the external candidate manifest and closed asset names; excluded from preview bytes.
- `schemas/developer-preview-release.schema.json`: closed schema for that authority.
- `scripts/verify_bootstrap_contract.py`: build-time manifest and documentation validator.
- `packaging/Get-AOOfficePoolRelease.ps1`: authenticated acquisition and offline verification entry point.
- `scripts/build_preview.py`: deterministic preview builder with caller-supplied component root.
- `scripts/scan_public_tree.py`: deterministic actionable privacy diagnostics.
- `skills/thought-experiment/SKILL.md`: hidden-failure/repeat-use analysis contract.
- `skills/engineering-research/SKILL.md`: local/external evidence research contract.
- `skills/scope-to-deliverable-workflow/SKILL.md`: full reusable/high-impact delivery contract.
- `tests/test_bootstrap_contract.py`: release contract and documentation tests.
- `tests/test_bootstrap_acquisition.py`: PowerShell acquisition behavior tests.
- `tests/test_bootstrap_clean_directory.py`: archive-relative clean-directory acceptance.
- `tests/test_package_builder.py`: portable component-root regression tests.
- `tests/test_scan_public_tree.py`: scanner CLI output regressions.
- `tests/test_product_skills.py`: product skill contract and privacy tests.

## Task 1: Add the closed private-release contract

**Files:**
- Create: `schemas/developer-preview-release.schema.json`
- Create: `manifests/developer-preview-release.json`
- Create: `scripts/verify_bootstrap_contract.py`
- Create: `tests/test_bootstrap_contract.py`

- [ ] **Step 1: Write the failing closed-schema tests**

Create `tests/test_bootstrap_contract.py` with a temporary-contract helper and these initial behaviors:

```python
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
        self.assertEqual(result["candidate_manifest"]["name"], "candidate-manifest.json")
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
            ("duplicate", lambda value: value["asset_names"].append(value["asset_names"][0])),
            ("visibility", lambda value: value.update(visibility="public")),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                value = json.loads(json.dumps(source))
                mutation(value)
                path = Path(temporary) / "contract.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(ValueError):
                    verify_release_manifest(path)
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```powershell
python -m unittest tests.test_bootstrap_contract -v
```

Expected: import failure because `scripts.verify_bootstrap_contract` does not exist.

- [ ] **Step 3: Add the schema, exact v02 contract, and minimal validator**

The schema must set `additionalProperties` to `false` at every object layer and require these root fields exactly:

```json
{
  "schema_version": 1,
  "repository": "uesugitorachiyo/ao-office-pool",
  "visibility": "private",
  "tag": "developer-preview-v02",
  "product_source_commit": "4bf8db6469a00dac69d2ddd7d103b501f797d7f6",
  "architecture": "windows-x86_64",
  "asset_names": [
    "candidate-manifest.json",
    "ao-office-pool-developer-preview.zip",
    "ao-office-pool-developer-preview.zip.sha256",
    "member-inventory.json",
    "provenance.json",
    "RELEASE-NOTES.md",
    "SBOM.json",
    "SHA256SUMS"
  ],
  "candidate_manifest": {
    "name": "candidate-manifest.json",
    "size": 4131,
    "sha256": "e291850f960ac66391163fd79dc30118bc65e666aef5a5def655521d7c37342f"
  }
}
```

Use the exact approved v02 values as the initial immutable baseline. Implement `verify_release_manifest(path: Path) -> dict` using the standard library. It must reject links, non-files, non-UTF-8 JSON, wrong field sets/types, unsafe asset names, duplicate or case-fold duplicate names, invalid candidate-manifest size/hash, non-private visibility, and any asset name set other than the approved eight names.

Use constants for the exact root field tuple and approved asset-name tuple; derive duplicate and type checks independently from parsed data. Also validate the downloaded candidate manifest's closed field shapes and require that its seven `metadata` names plus its own name equal `asset_names`. Return a normalized dictionary only after every check passes.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run:

```powershell
python -m unittest tests.test_bootstrap_contract -v
```

Expected: both tests pass.

- [ ] **Step 5: Parse the JSON schema and contract**

Run:

```powershell
python -c "import json,pathlib; [json.loads(pathlib.Path(p).read_text()) for p in ('schemas/developer-preview-release.schema.json','manifests/developer-preview-release.json')]"
```

Expected: exit `0` with no output.

- [ ] **Step 6: Commit the release authority**

```powershell
git add schemas/developer-preview-release.schema.json manifests/developer-preview-release.json scripts/verify_bootstrap_contract.py tests/test_bootstrap_contract.py
git commit -m "feat: add closed private release contract"
```

## Task 2: Remove the private component-build path

**Files:**
- Modify: `scripts/build_preview.py`
- Modify: `tests/test_package_builder.py`

- [ ] **Step 1: Replace the real-drive test fixture with temporary component bytes**

Add a helper that creates one temporary root containing all eight component files. Derive each file name, version, and byte digest from a temporary lock rather than the private drive. Patch `_LOCK_PATH` and `_S01_LOCKS` only with values created inside the test.

Add this behavior-focused test:

```python
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
```

Add a second test that places one valid hash-bound component outside `component_root` and expects `ValueError("component input must be within component root")`.

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
python -m unittest tests.test_package_builder.PackageBuilderTests.test_build_preview_accepts_a_caller_supplied_component_root tests.test_package_builder.PackageBuilderTests.test_build_preview_rejects_a_component_outside_the_caller_root -v
```

Expected: `build_preview()` rejects the unknown `component_root` keyword.

- [ ] **Step 3: Implement the minimal portable path contract**

Delete `_S01_ROOT` and the path component from `_S01_COMPONENTS`. Add `component_root: Path | None = None` to `build_preview` and `_validate_s01_components`. Require a caller-supplied regular, non-reparse directory. For every component:

```python
root = Path(component_root)
binary = Path(binary)
try:
    binary.relative_to(root)
except ValueError as error:
    raise ValueError("component input must be within component root") from error
```

Retain original-spelling reparse checks before and after reading, exact closed component names, case-insensitive duplicate checks, version/file/hash checks, and `_S01_LOCKS` equality. Do not resolve a path before validating its original ancestor chain.

- [ ] **Step 4: Verify GREEN and run all package-builder tests**

Run:

```powershell
python -m unittest tests.test_package_builder -v
```

Expected: all package-builder tests pass without reading any developer absolute path.

- [ ] **Step 5: Prove the tracked builder and tests have no absolute developer paths**

Run:

```powershell
rg -n "[A-Za-z]:\\|/[U]sers/|/[V]olumes/|/[h]ome/" scripts/build_preview.py tests/test_package_builder.py
```

Expected: no matches, exit `1` from `rg`.

- [ ] **Step 6: Commit the portable builder**

```powershell
git add scripts/build_preview.py tests/test_package_builder.py
git commit -m "fix: make preview component input portable"
```

## Task 3: Make privacy scanner failures actionable and deterministic

**Files:**
- Modify: `scripts/scan_public_tree.py`
- Modify: `tests/test_scan_public_tree.py`

- [ ] **Step 1: Write failing CLI-output tests**

Use `contextlib.redirect_stdout`, `redirect_stderr`, and `mock.patch.object(sys, "argv", ...)` to add:

```python
def test_cli_names_sorted_cache_findings_and_prints_summary(self):
    self.write("z/__pycache__/b.pyc", "")
    self.write("a.pyc", "")
    stdout, stderr = io.StringIO(), io.StringIO()
    with (
        mock.patch.object(sys, "argv", ["scan_public_tree.py", str(self.root)]),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        self.assertEqual(main(), 1)
    rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
    self.assertEqual([row["path"] for row in rows], ["a.pyc", "z/__pycache__/b.pyc"])
    self.assertEqual(stderr.getvalue(), "public-tree findings=2\n")

def test_cli_prints_clean_summary(self):
    self.write("README.md")
    # capture streams as above
    self.assertEqual(main(), 0)
    self.assertEqual(stdout.getvalue(), "")
    self.assertEqual(stderr.getvalue(), "public-tree findings=0\n")
```

Add an error test that patches `scan_tree` to raise `OSError` and asserts a bounded JSON error without the absolute temporary path.

- [ ] **Step 2: Run the new tests and verify RED**

Run:

```powershell
python -m unittest tests.test_scan_public_tree.ScanPublicTreeTests.test_cli_names_sorted_cache_findings_and_prints_summary tests.test_scan_public_tree.ScanPublicTreeTests.test_cli_prints_clean_summary tests.test_scan_public_tree.ScanPublicTreeTests.test_cli_reports_bounded_scan_errors -v
```

Expected: failures because `main()` prints nothing.

- [ ] **Step 3: Implement deterministic CLI output**

Sort findings in `scan_tree` before return:

```python
return sorted(out, key=lambda finding: (finding.path, finding.rule, finding.detail))
```

In `main`, emit each finding with canonical `json.dumps(..., sort_keys=True, separators=(",", ":"))`, print `public-tree findings=N` to standard error, and return `1` when findings exist. Catch `OSError` and `ValueError`, print only `{"error":"scan-failed","kind":"<ExceptionName>"}` plus `public-tree scan-error=1`, and return `2`. Do not print the exception string because it may contain a private absolute path.

- [ ] **Step 4: Verify GREEN and run the scanner suite**

Run:

```powershell
python -m unittest tests.test_scan_public_tree -v
python scripts/scan_public_tree.py .
```

Expected: tests pass; source scan prints `public-tree findings=0` and exits `0`.

- [ ] **Step 5: Commit actionable scanner output**

```powershell
git add scripts/scan_public_tree.py tests/test_scan_public_tree.py
git commit -m "fix: report deterministic privacy findings"
```

## Task 4: Package the three required product skills

**Required execution skill:** Use `writing-skills` while creating and verifying these skill packages.

**Files:**
- Create: `skills/thought-experiment/SKILL.md`
- Create: `skills/engineering-research/SKILL.md`
- Create: `skills/scope-to-deliverable-workflow/SKILL.md`
- Create: `tests/test_product_skills.py`
- Remove: `skills/.gitkeep`

- [ ] **Step 1: Write the failing product-skill contract test**

Create `tests/test_product_skills.py`:

```python
import re
import unittest
from pathlib import Path

from scripts.scan_public_tree import scan_tree


ROOT = Path(__file__).parents[1]
SKILLS = (
    "thought-experiment",
    "engineering-research",
    "scope-to-deliverable-workflow",
)
REQUIRED = (
    "## Trigger",
    "## Authority",
    "## Inputs",
    "## Evidence",
    "## Procedure",
    "## Outputs",
    "## Stop conditions",
    "## Privacy",
    "## Handoff",
)


class ProductSkillTests(unittest.TestCase):
    def test_required_product_skills_are_complete_and_portable(self):
        for name in SKILLS:
            path = ROOT / "skills" / name / "SKILL.md"
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\nname:"))
            self.assertTrue(all(section in text for section in REQUIRED))
            self.assertIsNone(re.search(r"[A-Za-z]:\\\\|/[U]sers/|/[V]olumes/|/[h]ome/", text))
            self.assertLessEqual(len(text.splitlines()), 200)

    def test_product_skills_pass_the_privacy_scanner(self):
        findings = scan_tree(ROOT / "skills")
        self.assertEqual(findings, [])
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
python -m unittest tests.test_product_skills -v
```

Expected: file-not-found errors for the three skills.

- [ ] **Step 3: Create the minimal complete skills**

Follow the approved design and the `writing-skills` instructions. Each file must have YAML frontmatter with its exact directory name and a one-sentence description. Implement these distinctions:

- Thought Experiment: trigger only for material hidden-failure or repeat-use uncertainty; deterministic evidence first; output scenarios, invariant threats, and a decision impact.
- Engineering Research: Mode A uses local supplied evidence; Mode B permits external authoritative sources only when requested/necessary; output sources, claims, uncertainty, and decision relevance.
- Scope-to-Deliverable Workflow: trigger for Tier 4 or explicitly full reusable/high-impact work; output scope, deliverables, gates, dependencies, verification, and handoff.

All three must deny authority expansion, provider calls, publishing, credentials, and raw private-state persistence unless separately authorized by the task.

- [ ] **Step 4: Verify GREEN and run scanner tests**

Run:

```powershell
python -m unittest tests.test_product_skills tests.test_scan_public_tree -v
python scripts/scan_public_tree.py skills
```

Expected: tests and scan pass with zero findings.

- [ ] **Step 5: Commit the product skills**

```powershell
git rm skills/.gitkeep
git add skills tests/test_product_skills.py
git commit -m "feat: package required AO operator skills"
```

## Task 5: Add authenticated acquisition and offline verification

**Files:**
- Create: `packaging/Get-AOOfficePoolRelease.ps1`
- Create: `tests/test_bootstrap_acquisition.py`
- Modify: `scripts/verify_bootstrap_contract.py`

- [ ] **Step 1: Write failing offline acquisition tests**

Build an eight-file temporary fixture containing a candidate manifest plus its seven metadata rows. The temporary control contract pins only that candidate manifest and the closed eight names. Fixture contracts are accepted only when the test-mode environment variable is exact. Invoke PowerShell through `subprocess.run`:

```python
def run_acquisition(self, contract: Path, source: Path, destination: Path):
    return subprocess.run(
        [
            "pwsh", "-NoProfile", "-File",
            str(ROOT / "packaging/Get-AOOfficePoolRelease.ps1"),
            "-Contract", str(contract),
            "-OfflineAssetRoot", str(source),
            "-Destination", str(destination),
        ],
        text=True,
        env=os.environ | {"AO_OFFICE_POOL_TEST_MODE": "1"},
        capture_output=True,
        check=False,
    )
```

Add tests for success, wrong hash, unexpected source file, pre-existing destination file, and a source or destination reparse ancestor. Success must return one JSON object, copy exactly the closed set, and never include an absolute source path in output. Failures must be nonzero and preserve pre-existing bytes.

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
python -m unittest tests.test_bootstrap_acquisition -v
```

Expected: PowerShell reports that `Get-AOOfficePoolRelease.ps1` does not exist.

- [ ] **Step 3: Implement the offline verifier first**

Create the script with mutually exclusive parameter sets:

```powershell
[CmdletBinding(DefaultParameterSetName='Authenticated')]
param(
    [string]$Contract = (Join-Path $PSScriptRoot '..\manifests\developer-preview-release.json'),
    [string]$Destination = (Join-Path (Get-Location) 'downloads'),
    [Parameter(ParameterSetName='Offline', Mandatory=$true)]
    [string]$OfflineAssetRoot,
    [Parameter(ParameterSetName='Authenticated')]
    [string]$Repository,
    [Parameter(ParameterSetName='Authenticated')]
    [string]$Tag
)
```

In normal mode, require `Contract` to be the package-owned path derived from `$PSScriptRoot`; accept another contract path only when `AO_OFFICE_POOL_TEST_MODE` is exactly `1`. Validate the contract's exact fields and types in PowerShell, validate original path spelling and every existing ancestor, require a fixed local NTFS destination on Windows, verify the candidate manifest before trusting its seven metadata rows, require the resulting closed source set in offline mode, copy through unique create-only temporary files, hash before atomic rename, and emit canonical compressed JSON containing `schema_version`, `mode`, `repository`, `tag`, `product_source_commit`, `architecture`, `destination`, and asset name/size/hash rows. Report `destination` relative to the invocation directory when contained there; otherwise use only the final directory name, never a developer absolute path.

- [ ] **Step 4: Verify offline GREEN**

Run:

```powershell
python -m unittest tests.test_bootstrap_acquisition -v
```

Expected: all offline acquisition tests pass.

- [ ] **Step 5: Add authenticated metadata tests and implementation**

Factor metadata validation into a PowerShell function that accepts already-parsed repository and release objects. Add a test-only invocation route by dot-sourcing the script with `$env:AO_OFFICE_POOL_METADATA_FIXTURE` naming a local JSON fixture; the script must reject this variable unless `$env:AO_OFFICE_POOL_TEST_MODE -ceq '1'`. Tests cover wrong visibility, repository, tag, target, asset set, size, asset API host, and redirect host.

Authenticated mode requires `GITHUB_TOKEN`, sends it only in an `Authorization` header, sets GitHub's JSON accept header, validates repository visibility and release metadata before downloading, requests asset bytes from the API URL, disallows redirects, and applies the same temporary-file/hash/rename gate as offline mode. Clear the local token variable in `finally`; never print headers, exceptions containing headers, or response bodies.

- [ ] **Step 6: Run acquisition and contract suites**

Run:

```powershell
python -m unittest tests.test_bootstrap_acquisition tests.test_bootstrap_contract -v
```

Expected: all tests pass without network access.

- [ ] **Step 7: Commit acquisition**

```powershell
git add packaging/Get-AOOfficePoolRelease.ps1 scripts/verify_bootstrap_contract.py tests/test_bootstrap_acquisition.py
git commit -m "feat: add verified private release acquisition"
```

## Task 6: Replace onboarding with relative AI-operable instructions

**Files:**
- Modify: `README.md`
- Create: `README-FIRST.md`
- Create: `docs/QUICKSTART.md`
- Create: `docs/AI_OPERATOR_RUNBOOK.md`
- Modify: `docs/OPERATOR_GUIDE.md`
- Modify: `tests/test_bootstrap_contract.py`

- [ ] **Step 1: Write failing documentation-contract tests**

Add tests that load all five documents and assert:

```python
DOCUMENTS = (
    "README.md",
    "README-FIRST.md",
    "docs/QUICKSTART.md",
    "docs/AI_OPERATOR_RUNBOOK.md",
    "docs/OPERATOR_GUIDE.md",
)

def test_bootstrap_documents_are_relative_complete_and_truthful(self):
    texts = {name: (ROOT / name).read_text(encoding="utf-8") for name in DOCUMENTS}
    combined = "\n".join(texts.values())
    self.assertNotIn("does not contain a Production pool or a qualified Windows release", combined)
    self.assertIsNone(re.search(r"[A-Za-z]:\\\\|/[U]sers/|/[V]olumes/|/[h]ome/", combined))
    for phrase in (
        "Windows x86-64", "local NTFS", "GITHUB_TOKEN",
        "Get-AOOfficePoolRelease.ps1", "Install-AOOfficePool.ps1",
        "Verify-AOOfficePool.ps1", "Uninstall-AOOfficePool.ps1",
        "CONTINUE", "REPAIR", "HOLD",
    ):
        self.assertIn(phrase, combined)

def test_every_relative_markdown_link_resolves(self):
    # Parse local Markdown link targets, ignore https links and anchors,
    # resolve against each document parent, and assert target exists.
```

Add a runbook structure test requiring for every gate: `Authority`, `Command`, `Expected`, `Stop`, `Evidence`, and `Next` labels.

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
python -m unittest tests.test_bootstrap_contract.BootstrapContractTests.test_bootstrap_documents_are_relative_complete_and_truthful tests.test_bootstrap_contract.BootstrapContractTests.test_every_relative_markdown_link_resolves tests.test_bootstrap_contract.BootstrapContractTests.test_ai_runbook_has_closed_gate_fields -v
```

Expected: missing files and stale README assertion failures.

- [ ] **Step 3: Write the minimum human onboarding documents**

Rewrite `README.md` to lead with the private Windows preview, supported boundary, exact eight components, and links to `README-FIRST.md`, `docs/QUICKSTART.md`, and `docs/AI_OPERATOR_RUNBOOK.md`.

`README-FIRST.md` begins only after the acquisition script has verified the archive against the pinned external candidate manifest. It must contain this relative install flow from the verified extraction:

```powershell
$BootstrapRoot = (Get-Location).Path
$DownloadRoot = (Resolve-Path (Join-Path $BootstrapRoot '..\downloads')).Path
$InstallRoot = Join-Path $env:LOCALAPPDATA 'AOOfficePool'

./packaging/Install-AOOfficePool.ps1 -Action Install `
  -Archive (Join-Path $DownloadRoot 'ao-office-pool-developer-preview.zip') `
  -ChecksumFile (Join-Path $DownloadRoot 'ao-office-pool-developer-preview.zip.sha256') `
  -InstallRoot $InstallRoot
./packaging/Verify-AOOfficePool.ps1 -InstallRoot $InstallRoot `
  -Archive (Join-Path $DownloadRoot 'ao-office-pool-developer-preview.zip') `
  -ChecksumFile (Join-Path $DownloadRoot 'ao-office-pool-developer-preview.zip.sha256')
```

It must say the archive was authenticated before extraction, must not claim to authenticate itself, and installation is not operational office authorization. `README.md` and `docs/QUICKSTART.md` contain the earlier repository-root acquisition command.

- [ ] **Step 4: Write the normative AI runbook**

Use gates `G00` through `G09`: authority, prerequisites, workspace isolation, authentication, acquisition, asset verification, NTFS install-root selection, install, verify/status, evidence/cleanup. Every gate has the six required labels and an explicit decision. Token values and raw API responses are never evidence.

Document the offline/manual authenticated path separately and require the same manifest/hash gate. Include bounded recovery for partial downloads, occupied destinations, installer recovery markers, unknown files, and digest disagreement.

- [ ] **Step 5: Correct and cross-link the operator guide**

Preserve detailed installer mechanics, but replace drive-specific examples with `$DownloadRoot` and `$InstallRoot`. Add prerequisites, acquisition link, expected machine-readable output, and the explicit lifecycle limitation.

- [ ] **Step 6: Verify documentation GREEN and scan it**

Run:

```powershell
python -m unittest tests.test_bootstrap_contract -v
python scripts/scan_public_tree.py .
```

Expected: tests and both scans pass.

- [ ] **Step 7: Commit onboarding**

```powershell
git add README.md README-FIRST.md docs/QUICKSTART.md docs/AI_OPERATOR_RUNBOOK.md docs/OPERATOR_GUIDE.md tests/test_bootstrap_contract.py
git commit -m "docs: add AI-operable Windows bootstrap"
```

## Task 7: Bind onboarding and skills into the preview archive

**Files:**
- Modify: `manifests/public-tree.json` only if a new tracked root file is not already admitted
- Modify: `scripts/build_preview.py`
- Create: `tests/test_bootstrap_clean_directory.py`
- Modify: `tests/test_package_builder.py`

- [ ] **Step 1: Write the failing archive-content test**

Build a preview from a controlled source and assert the immutable manifest and ZIP contain:

```python
REQUIRED_BOOTSTRAP_MEMBERS = {
    "README.md",
    "README-FIRST.md",
    "docs/QUICKSTART.md",
    "docs/AI_OPERATOR_RUNBOOK.md",
    "docs/OPERATOR_GUIDE.md",
    "packaging/Install-AOOfficePool.ps1",
    "packaging/Verify-AOOfficePool.ps1",
    "packaging/Uninstall-AOOfficePool.ps1",
    "schemas/developer-preview-release.schema.json",
    "skills/thought-experiment/SKILL.md",
    "skills/engineering-research/SKILL.md",
    "skills/scope-to-deliverable-workflow/SKILL.md",
}
```

Assert each member is listed by `developer-preview-manifest.json` with the exact archive bytes, size, and digest.

- [ ] **Step 2: Run and verify RED**

Run:

```powershell
python -m unittest tests.test_package_builder.PackageBuilderTests.test_preview_contains_the_complete_bootstrap_contract -v
```

Expected: missing bootstrap members from the controlled source/preview.

- [ ] **Step 3: Make preview construction require the bootstrap members**

Before copying the source, validate that each required bootstrap path is a regular non-link file. Exclude `manifests/developer-preview-release.json` from the copied preview because it is the later control-plane pin for the already-built candidate. After copy, ensure every required member appears in the immutable manifest and the excluded control contract does not. Fail with `ValueError("source is missing bootstrap contract")` before creating output if any required member is absent.

- [ ] **Step 4: Write the clean-directory acceptance test**

`tests/test_bootstrap_clean_directory.py` must begin in a new operator directory, run offline acquisition from the repository-root script against controlled assets, extract the verified archive into a new bootstrap child, set that extraction as the process working directory, and then use only paths parsed from `README-FIRST.md`. It must:

- assert every referenced relative script exists;
- prove the exact control contract is absent from preview members, preventing self-reference;
- install to a separate new temporary child on Windows;
- run verify against the same archive/sidecar;
- run uninstall and assert the active install path is absent while exactly one preserved `.uninstalled.*` sibling exists;
- skip only the native install portion off Windows while still checking archive/document layout.

- [ ] **Step 5: Run acceptance and package suites**

Run:

```powershell
python -m unittest tests.test_bootstrap_clean_directory tests.test_package_builder tests.test_pilot_matrix -v
```

Expected: all applicable tests pass; only privilege/platform-specific cases skip with named reasons.

- [ ] **Step 6: Commit preview binding**

```powershell
git add manifests/public-tree.json scripts/build_preview.py tests/test_bootstrap_clean_directory.py tests/test_package_builder.py
git commit -m "test: bind preview to clean bootstrap contract"
```

## Task 8: Verify, build, and hand off the new private candidate

**Files:**
- Modify: `docs/ROADMAP_MONTHS_7_12.md` only to record the bootstrap repair gate if the native result requires it
- Create ignored evidence under `.local/` only; do not track candidate bytes or private handbacks

- [ ] **Step 1: Run all focused bootstrap suites**

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest tests.test_bootstrap_contract tests.test_bootstrap_acquisition tests.test_bootstrap_clean_directory tests.test_package_builder tests.test_product_skills tests.test_scan_public_tree tests.test_release_tree tests.test_pilot_matrix -v
```

Expected: zero failures; only named Windows privilege/platform skips.

- [ ] **Step 2: Run the complete repository suite**

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -v
```

Expected: zero failures.

- [ ] **Step 3: Parse every tracked schema and manifest**

```powershell
python -c "import json,pathlib; files=list(pathlib.Path('schemas').glob('*.json'))+list(pathlib.Path('manifests').glob('*.json')); [json.loads(p.read_text(encoding='utf-8')) for p in files]; print(len(files))"
```

Expected: prints the exact file count and exits `0`.

- [ ] **Step 4: Run privacy and tracked-tree checks**

```powershell
python scripts/scan_public_tree.py .
git diff --check origin/main...HEAD
git status --short
python scripts/verify_bootstrap_contract.py .
```

Expected: scanner zero findings; diff check clean; status clean after commits; the bootstrap verifier reports no tracked developer absolute paths or broken relative links.

- [ ] **Step 5: Build twice from the same verified component root**

Record `product_source_commit = git rev-parse HEAD`. Use a fresh task-local ignored component root and pass it explicitly to `build_preview`. Build two archives in separate ignored output directories, then compare:

```powershell
(Get-FileHash -Algorithm SHA256 ./first/ao-office-pool-developer-preview.zip).Hash
(Get-FileHash -Algorithm SHA256 ./second/ao-office-pool-developer-preview.zip).Hash
```

Expected: identical hashes and member inventories.

- [ ] **Step 6: Scan both generated trees and archives**

Extract each archive to a separate ignored directory, run `scripts/scan_public_tree.py` on both trees, and compare sorted ZIP member name, size, CRC, and content SHA-256 rows. Expected: zero findings and exact equality.

- [ ] **Step 7: Generate the external candidate manifest and v03 control contract**

Generate `candidate-manifest.json` outside the archive. It must name `windows-ai-bootstrap-v03-<short product source>`, bind the full product-source commit, archive identity, component lock, eight component identities, installer paths, and seven metadata rows while excluding itself. Compute its size and SHA-256, then update tracked `manifests/developer-preview-release.json` to tag `developer-preview-v03`, the recorded product-source commit, the exact eight names, and that candidate-manifest identity.

Run:

```powershell
python -m unittest tests.test_bootstrap_contract tests.test_bootstrap_acquisition -v
git add manifests/developer-preview-release.json
git commit -m "release: bind Windows AI bootstrap candidate"
```

Expected: tests pass and the new control commit is later than, and distinct from, the product-source commit. A future private release tag targets the product-source commit; private `main` may contain the later control commit. Do not create or publish the tag in this task.

- [ ] **Step 8: Commit any final evidence-binding documentation only**

Do not commit candidate archives, tokens, authenticated API metadata, absolute paths, process data, or live install state. If no tracked documentation change is required, make no empty commit.

- [ ] **Step 9: Request independent review**

Use the `requesting-code-review` skill. Review the complete branch against the approved design and this plan, with special attention to token handling, path identity, release asset closure, installer bootstrap circularity, scanner privacy, and documentation truthfulness. Resolve every validated finding with a RED/GREEN cycle.

- [ ] **Step 10: Dispatch native clean-directory qualification**

Create an ignored Windows handoff that identifies the exact product-source commit, later control commit, candidate-manifest identity, and candidate archive digest. The new Windows task must start in an empty directory, use only the repository `README.md` through acquisition and then the extracted `README-FIRST.md`, authenticate without exposing the token, download/verify the closed assets, install/verify/uninstall, and return an ignored `WINDOWS_AI_BOOTSTRAP_HANDBACK.md` with `ADVANCE`, `REPAIR`, or `HOLD`.

- [ ] **Step 11: Stop before lifecycle implementation**

Do not add `status`, `claim`, `resume`, `execute`, `release`, or `recover` commands in this slice. After bootstrap `ADVANCE`, begin a separate brainstorming/spec/plan cycle for the operational lifecycle command and endurance runner.
