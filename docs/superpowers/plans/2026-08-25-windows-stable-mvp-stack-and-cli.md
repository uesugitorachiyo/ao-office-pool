# Windows Stable MVP Stack and CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind the coherent August 2026 Windows AO Stack through one manifest authority and deliver an installed Python 3.12 lifecycle command for the existing five-office core.

**Architecture:** `manifests/components.lock.json` remains the only accepted stack identity; builders and scanners derive their expectations from it instead of copied constants. A thin `cmd/ao_office_pool.py` adapter exposes existing pool and governed-execution methods, while `bin/ao-office-pool.ps1` discovers the installation root and enforces Python 3.12.

**Tech Stack:** Python 3.12 standard library, PowerShell 7, existing native Windows/NTFS coordination code, `unittest`, deterministic ZIP packaging.

---

## Boundaries

- Execute from the isolated `codex/windows-stable-release-closure-roadmap`
  worktree and confirm that branch before each commit.
- Do not run development inside an AO Office Pool office.
- Do not publish, change repository visibility, or acquire credentials.
- Preserve the existing pool, receipt, journal, recovery, and governance semantics.
- This plan ends with a buildable CLI candidate. Clean-install dogfood, O1-first qualification, O2-O5 expansion, and the one-to-two-hour soak receive a separate execution plan after these bytes pass source qualification.

### Task 1: Preserve the completed Windows harness repair

**Files:**
- Modify: `README.md`
- Modify: `tests/test_bootstrap_contract.py`
- Modify: `tests/test_pool_crash.py`
- Modify: `tests/test_runtime_update.py`
- Create: `scripts/run_windows_tests.py`
- Create: `tests/process_control.py`
- Create: `tests/test_process_control.py`
- Create: `tests/test_windows_test_runner.py`
- Create: `tests/fixtures/__init__.py`
- Create: `tests/fixtures/runner_cases.py`

- [ ] **Step 1: Run the focused repair tests**

Run:

```powershell
python -B -m unittest -v tests.test_process_control tests.test_windows_test_runner
```

Expected: five tests pass, including worker-tree termination and distinct skipped-subtest evidence.

- [ ] **Step 2: Check the repair diff**

Run:

```powershell
git diff --check
git diff -- README.md tests/test_bootstrap_contract.py tests/test_pool_crash.py tests/test_runtime_update.py scripts/run_windows_tests.py tests/process_control.py tests/test_process_control.py tests/test_windows_test_runner.py tests/fixtures
```

Expected: no whitespace errors; changes are limited to deterministic child cleanup, the durable Windows runner, tests, and documented invocation.

- [ ] **Step 3: Commit the repair separately**

```powershell
git add README.md tests/test_bootstrap_contract.py tests/test_pool_crash.py tests/test_runtime_update.py scripts/run_windows_tests.py tests/process_control.py tests/test_process_control.py tests/test_windows_test_runner.py tests/fixtures
git commit -m "test: make Windows qualification process-safe"
```

### Task 2: Make the component lock the single stack authority

**Files:**
- Create: `internal/component_lock.py`
- Modify: `scripts/build_preview.py`
- Modify: `scripts/scan_public_tree.py`
- Modify: `internal/governance_witness.py`
- Test: `tests/test_verify_components.py`
- Test: `tests/test_package_builder.py`
- Test: `tests/test_scan_public_tree.py`
- Test: `tests/test_governance_witness.py`

- [ ] **Step 1: Write failing lock-authority tests**

Add tests asserting that changing a temporary lock changes the builder's accepted versions and scanner's manifest-bound binary paths without patching a Python constant:

```python
def test_builder_derives_component_identity_only_from_lock(self):
    component_root, components, lock_path, _identities = self.portable_components(self.root)
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    ao2 = next(row for row in lock["components"] if row["name"] == "ao2")
    ao2["version"] = "v9.1.0"
    components["ao2"] = ("v9.1.0", components["ao2"][1])
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    with mock.patch.object(builder, "_LOCK_PATH", lock_path):
        builder.build_preview(source, components["ao2"][1], "v9.1.0", archive,
                              components, component_root)
    self.assertEqual(json.loads(zipfile.ZipFile(archive).read(
        "developer-preview-manifest.json"))["runtime_version"], "v9.1.0")
```

Add a lock parser test that rejects duplicate names, unknown fields, unsafe assets, malformed commits, non-GitHub repositories, and a non-eight-component set.

- [ ] **Step 2: Run the tests and confirm RED**

Run:

```powershell
python -B -m unittest -v tests.test_verify_components tests.test_package_builder tests.test_scan_public_tree tests.test_governance_witness
```

Expected: the new derivation test fails because `_S01_LOCKS` and scanner constants still override the temporary lock.

- [ ] **Step 3: Add the minimal shared parser**

Create `internal/component_lock.py`:

```python
import json
import re
from pathlib import Path

NAMES = frozenset({"ao2", "ao-mission", "ao-command", "ao-atlas", "ao-forge",
                   "ao-covenant", "ao2-control-plane", "ao-blueprint"})
FIELDS = frozenset({"name", "version", "repository", "commit", "asset", "license", "sha256"})
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")

def load_component_lock(path: Path) -> dict[str, dict]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = value.get("components") if isinstance(value, dict) and set(value) == {"schema_version", "components"} and value.get("schema_version") == 1 else None
    if not isinstance(rows, list):
        raise ValueError("component lock is malformed")
    result = {}
    for row in rows:
        if (not isinstance(row, dict) or set(row) != FIELDS or
                any(not isinstance(row[name], str) or not row[name] for name in FIELDS) or
                row["name"] in result or row["name"] not in NAMES or
                not row["repository"].startswith("https://github.com/uesugitorachiyo/") or
                not HEX40.fullmatch(row["commit"]) or not HEX64.fullmatch(row["sha256"]) or
                Path(row["asset"]).name != row["asset"] or row["asset"] in {".", ".."}):
            raise ValueError("component lock is malformed")
        result[row["name"]] = row
    if set(result) != NAMES:
        raise ValueError("component lock is not the coherent Windows stack")
    return result
```

- [ ] **Step 4: Remove copied product identities**

In `scripts/build_preview.py`, replace `_S01_LOCKS` use with `load_component_lock(_LOCK_PATH)`. Validate `runtime_version == locked["ao2"]["version"]`, exact component names, version, asset name, and downloaded-byte digest.

In `scripts/scan_public_tree.py`, derive permitted component and O1-O5 AO2 binary paths from the lock. In `internal/governance_witness.py`, keep only the required governed component-name set and compare those rows to the shared lock parser.

- [ ] **Step 5: Run focused GREEN tests**

Run:

```powershell
python -B -m unittest -v tests.test_verify_components tests.test_package_builder tests.test_scan_public_tree tests.test_governance_witness
```

Expected: all focused tests pass; no test patches `_S01_LOCKS` because it no longer exists.

- [ ] **Step 6: Confirm the tracked lock matches authoritative releases**

Query the seven released components, compare tag and commit to the lock, and
record only public metadata:

```powershell
$Headers = @{ Accept='application/vnd.github+json'; 'User-Agent'='ao-office-pool-qualification' }
$Released = 'ao2','ao-mission','ao-command','ao-atlas','ao-forge','ao-covenant','ao2-control-plane'
foreach ($Name in $Released) {
  $Base = "https://api.github.com/repos/uesugitorachiyo/$Name"
  Invoke-RestMethod -Headers $Headers -Uri "$Base/releases/latest" |
    Select-Object tag_name,published_at,target_commitish
  Invoke-RestMethod -Headers $Headers -Uri "$Base/tags?per_page=5" |
    Select-Object -First 5 name,@{n='commit';e={$_.commit.sha}}
}
```

AO Blueprint is checked against its locked source commit because the
repository has no GitHub Release.

Materialize the already-verified Windows executables into a new ignored root
with the exact lock layout, then verify the bytes:

```powershell
$ComponentRoot = Join-Path (Get-Location) '.local\staging\windows-stable-mvp\components'
python -B scripts/verify_components.py manifests/components.lock.json $ComponentRoot
```

Expected: all eight rows match their exact Windows executable bytes. AO Blueprint remains explicitly commit-bound because it has no GitHub Release.

- [ ] **Step 7: Commit the lock-authority change**

```powershell
git add internal/component_lock.py internal/governance_witness.py scripts/build_preview.py scripts/scan_public_tree.py tests/test_verify_components.py tests/test_package_builder.py tests/test_scan_public_tree.py tests/test_governance_witness.py
git commit -m "build: make component lock the stack authority"
```

### Task 3: Add the lifecycle CLI adapter

**Files:**
- Create: `cmd/ao_office_pool.py`
- Create: `tests/test_office_cli.py`

- [ ] **Step 1: Write failing CLI behavior tests**

Create subprocess tests for exact success JSON and stable failure JSON. Cover `status`, first-free `claim`, `resume`, `release`, `recover`, pool-full, malformed arguments, and no traceback. Use a temporary initialized `Pool` and patch only the CLI root factory when the real NTFS root is not needed.

Representative assertion:

```python
completed = self.cli("status")
self.assertEqual(completed.returncode, 0)
self.assertEqual(json.loads(completed.stdout), {
    "schema_version": 1, "command": "status", "status": "ok",
    "offices": [{"office_id": f"O{n}", "status": "free", "generation": 0}
                for n in range(1, 6)],
})
self.assertEqual(completed.stderr, "")
```

- [ ] **Step 2: Run the CLI tests and confirm RED**

```powershell
python -B -m unittest -v tests.test_office_cli
```

Expected: import or file-not-found failure because `cmd/ao_office_pool.py` does not exist.

- [ ] **Step 3: Implement the complete thin adapter**

Create `cmd/ao_office_pool.py` with `argparse` subparsers, an installation-root default of `Path(__file__).parents[1]`, a `_pool()` factory that reads `pool.json` only to select the runtime version before `Pool` revalidates it, and one dispatch branch per command:

```python
def dispatch(args, root):
    pool = installed_pool(root)
    if args.command == "status":
        return pool.public_status()
    if args.command == "claim":
        authority_path = pool.claim(args.owner, args.task, Path(args.project), args.mode)
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        return {"receipt": str(authority_path), "office_id": authority["office_id"],
                "generation": authority["generation"]}
    if args.command == "resume":
        authority_path = pool.resume(Path(args.receipt))
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        return {"receipt": str(authority_path), "office_id": authority["office_id"],
                "generation": authority["generation"]}
    if args.command == "run":
        result = execute(Path(args.receipt), Path(args.envelope),
                         timeout_seconds=args.timeout)
        return {"execution_status": result.status, "record": str(result.record),
                "request_digest": result.request_digest}
    if args.command == "release":
        pool.release(Path(args.receipt))
        return {}
    pool.recover(Path(args.key), args.office, args.generation)
    return {"office_id": args.office, "generation": args.generation}
```

`main()` wraps success as `{"schema_version":1,"command":...,"status":"ok",...}`. It catches `PoolError` and `ExecutionError`, emits `{"schema_version":1,"command":...,"status":"error","code":error.code}` to stderr, and returns `2`. All other exceptions emit the same object with `code` equal to `internal-error` and return `3`; exception text and tracebacks are omitted.

- [ ] **Step 4: Run focused GREEN tests**

```powershell
python -B -m unittest -v tests.test_office_cli tests.test_pool tests.test_execution
```

Expected: CLI, pool, and governed execution tests pass.

- [ ] **Step 5: Commit the CLI adapter**

```powershell
git add cmd/ao_office_pool.py tests/test_office_cli.py
git commit -m "feat: add Windows office lifecycle CLI"
```

### Task 4: Add the installed PowerShell command and Python preflight

**Files:**
- Create: `bin/ao-office-pool.ps1`
- Modify: `packaging/Install-AOOfficePool.ps1`
- Modify: `packaging/Verify-AOOfficePool.ps1`
- Create: `tests/test_office_launcher.py`
- Modify: `tests/test_package_builder.py`

- [ ] **Step 1: Write failing launcher and package tests**

Assert that the launcher rejects Python other than 3.12, forwards arguments and exit status, resolves the root from `$PSScriptRoot`, and works from an unrelated current directory. Assert the preview archive includes `bin/ao-office-pool.ps1`, `cmd/ao_office_pool.py`, and every imported `internal/*.py` member.

- [ ] **Step 2: Run and confirm RED**

```powershell
python -B -m unittest -v tests.test_office_launcher tests.test_package_builder
```

Expected: launcher/member tests fail because the installed command is absent.

- [ ] **Step 3: Implement the launcher**

Create `bin/ao-office-pool.ps1`:

```powershell
$ErrorActionPreference = 'Stop'
$Python = (Get-Command python.exe -ErrorAction Stop).Source
& $Python -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) { throw 'AO Office Pool requires Python 3.12' }
$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
& $Python -B (Join-Path $Root 'cmd\ao_office_pool.py') @args
exit $LASTEXITCODE
```

Add the same bounded Python 3.12 preflight to install and verify before reporting success. Do not download Python or mutate PATH.

- [ ] **Step 4: Run focused GREEN tests**

```powershell
python -B -m unittest -v tests.test_office_launcher tests.test_package_builder
```

Expected: launcher and archive tests pass.

- [ ] **Step 5: Commit the installed command**

```powershell
git add bin/ao-office-pool.ps1 packaging/Install-AOOfficePool.ps1 packaging/Verify-AOOfficePool.ps1 tests/test_office_launcher.py tests/test_package_builder.py
git commit -m "packaging: install the office lifecycle command"
```

### Task 5: Document the stable MVP bootstrap and AI workflow

**Files:**
- Modify: `README.md`
- Modify: `README-FIRST.md`
- Modify: `docs/QUICKSTART.md`
- Modify: `docs/AI_OPERATOR_RUNBOOK.md`
- Modify: `docs/OPERATOR_GUIDE.md`
- Modify: `docs/STACK_LAYOUT.md`
- Modify: `tests/test_bootstrap_contract.py`

- [ ] **Step 1: Write failing documentation-contract assertions**

Require copy-and-paste commands for Python 3.12 verification, installed `status`, claim/resume/run/release/recover examples, the outside-pool bootstrap boundary, O1-first dogfood, and the rule that installation alone does not authorize work.

- [ ] **Step 2: Run and confirm RED**

```powershell
python -B -m unittest -v tests.test_bootstrap_contract
```

Expected: new lifecycle-command assertions fail against the preview-era limitation text.

- [ ] **Step 3: Replace obsolete limitation text with exact commands**

Document relative commands beginning with:

```powershell
python -c "import sys; assert sys.version_info[:2] == (3, 12)"
& "$InstallRoot\bin\ao-office-pool.ps1" status
```

Document `claim`, `resume`, governed `run`, `release`, and explicit `recover` using variables rather than developer-absolute paths. The AI block must stop before dogfood unless checksum-bound installation and verification have passed.

- [ ] **Step 4: Run focused GREEN tests and privacy scan**

```powershell
python -B -m unittest -v tests.test_bootstrap_contract tests.test_bootstrap_clean_directory
python -B scripts/scan_public_tree.py .
```

Expected: documentation contracts pass and `public-tree findings=0`.

- [ ] **Step 5: Commit the operator contract**

```powershell
git add README.md README-FIRST.md docs/QUICKSTART.md docs/AI_OPERATOR_RUNBOOK.md docs/OPERATOR_GUIDE.md docs/STACK_LAYOUT.md tests/test_bootstrap_contract.py
git commit -m "docs: add Windows stable lifecycle quickstart"
```

### Task 6: Complete source qualification and prepare the installed-test plan

**Files:**
- Create: `docs/superpowers/plans/2026-08-25-windows-stable-mvp-installed-qualification.md`

- [ ] **Step 1: Run component, CLI, package, and bootstrap regressions through the durable runner**

```powershell
$RunId = 'windows-stable-mvp-source-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
python -B scripts/run_windows_tests.py `
  --evidence-dir (Join-Path '.local\qualification' $RunId) `
  --task-root (Join-Path $env:LOCALAPPDATA "AOOfficePoolQualification\$RunId") `
  tests.test_verify_components tests.test_package_builder tests.test_office_cli `
  tests.test_office_launcher tests.test_bootstrap_contract
```

Expected: `PASS`, no timeout, worker tree ended, and no task-root residue.

- [ ] **Step 2: Run the complete Windows suite once**

```powershell
$RunId = 'windows-stable-mvp-full-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
python -B scripts/run_windows_tests.py `
  --evidence-dir (Join-Path '.local\qualification' $RunId) `
  --task-root (Join-Path $env:LOCALAPPDATA "AOOfficePoolQualification\$RunId")
```

Expected: `PASS`; every skip has a machine-readable identity and reason; compiler-dependent skips are zero; privilege skips remain explicit and do not qualify their native branch.

- [ ] **Step 3: Run final static gates**

```powershell
python -B scripts/verify_bootstrap_contract.py
python -B scripts/scan_public_tree.py .
python -c "import json,pathlib; [json.loads(p.read_text(encoding='utf-8')) for p in [*pathlib.Path('schemas').glob('*.json'),*pathlib.Path('manifests').glob('*.json')]]"
git diff --check
git status --short
```

Expected: bootstrap counts match, privacy findings are zero, every JSON file parses, diff check is clean, and only intended tracked changes remain.

- [ ] **Step 4: Write the next qualification plan**

The installed plan must name exact candidate inputs and cover: deterministic build, independent checksum verification, clean NTFS install, `status`, O1 claim/resume/governed run/release/recovery, unchanged-byte verification, O2-O5 operation, sixth-claim `pool-full`, crash recovery, one-to-two-hour soak metrics, cleanup, privacy audit, and `RELEASE_READY`/`REPAIR`/`HOLD` handback. It must not publish.

- [ ] **Step 5: Commit the source-qualified slice and next plan**

```powershell
git add docs/superpowers/plans/2026-08-25-windows-stable-mvp-installed-qualification.md
git commit -m "docs: plan installed Windows MVP qualification"
```
