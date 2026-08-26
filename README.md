# AO Office Pool private Windows preview

AO Office Pool is a Windows x86-64 coordination package for five isolated AO
offices over one pinned AO stack. This repository is private. The current
developer preview is built for a fixed directory on a local NTFS volume; macOS
and Linux are outside the supported product boundary.

The closed stack contains exactly these eight components:

| Component | Pinned identity |
| --- | --- |
| AO2 | `v0.5.12` |
| AO Mission | `v0.1.6` |
| AO Command | `v0.1.3` |
| AO Atlas | `v0.2.1` |
| AO Forge | `v0.1.5` |
| AO Covenant | `v0.1.1` |
| AO2 Control Plane | `v0.1.19` |
| AO Blueprint | `git-ec6a80b60b54` |

## Fresh clone: validate the source checkout

Run this copy-paste block in PowerShell 7 on Windows x86-64. It needs Git,
Python 3, and Visual Studio Build Tools with the Desktop development with C++
workload, but no third-party Python package. Set `AO_TEST_VCVARS64` to a valid
`vcvars64.bat` only when automatic Visual Studio discovery is unavailable.
Source validation can run before a private release is published; installing
the packaged preview additionally requires a new directory on a fixed local
NTFS volume.

```powershell
git clone https://github.com/uesugitorachiyo/ao-office-pool.git
Set-Location ./ao-office-pool

if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion.Major -lt 7) {
  throw 'Run this project with PowerShell 7 or newer.'
}
if (-not [Environment]::Is64BitOperatingSystem) {
  throw 'AO Office Pool requires Windows x86-64.'
}

python --version
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m tests.windows_compiler
python scripts/scan_public_tree.py .
python scripts/verify_bootstrap_contract.py .
$runId = [Guid]::NewGuid().ToString('N')
$evidence = Join-Path (Get-Location) ".local/qualification/$runId"
$taskRoot = Join-Path $env:LOCALAPPDATA "AOOfficePoolQualification/$runId"
python -B scripts/run_windows_tests.py `
  --evidence-dir $evidence `
  --task-root $taskRoot
if ($LASTEXITCODE -ne 0) {
  throw "Windows source suite failed; inspect $evidence/summary.json"
}
Get-Content (Join-Path $evidence 'summary.json')
Remove-Item Env:PYTHONDONTWRITEBYTECODE
```

Expected results are `windows-c-compiler=ready`, `public-tree findings=0`, a
bootstrap summary with 13 members and 5 documents, and a runner summary with
`"result": "PASS"`, `"worker_exit": 0`, and `"task_root_residue": false`.
Privilege-dependent symlink tests may be reported as skips on Windows. Other
compiler-dependent skips do not qualify the checkout. A missing compiler or
any other failure is a stop signal; do not continue to release installation by
bypassing it.

The runner discovers tests in the same order as `unittest`, records each test's
identity, UTC boundaries, duration, outcome, and skip reason, samples the exact
worker process tree and task-root storage, retains only bounded output, and
fails with the active test identity if a test exceeds the default ten-minute
limit. Machine-readable evidence stays below the ignored `.local/qualification`
tree. Mutable test state stays in the unique fixed-local-NTFS task root and the
runner removes that root on clean completion.

## Copy-paste prompt for Windows Codex

Open a new Windows Codex task in the freshly cloned repository and paste this
entire prompt:

```text
Set up and validate this AO Office Pool checkout for me. Work only on Windows
x86-64 and use PowerShell 7. Continue proactively through every safe documented step.

First read README.md, README-FIRST.md, docs/QUICKSTART.md,
docs/AI_OPERATOR_RUNBOOK.md, docs/OPERATOR_GUIDE.md, and
manifests/developer-preview-release.json completely. Treat those tracked files
as authority. Use only relative repository paths in commands and evidence.

Confirm Git, Python 3, PowerShell 7, Windows x86-64, and the documented Windows
C compiler preflight. Set PYTHONDONTWRITEBYTECODE=1, then run the compiler
preflight, public-tree scanner, bootstrap-contract verifier, and complete
instrumented suite exactly as README.md specifies. Report commands, exit codes,
runner summary, test totals, and every skip grouped by exact reason. Treat a
missing compiler or compiler-dependent skip as HOLD rather than native
qualification. Stop on any unexpected failure; do not weaken a gate.

After source validation, determine whether the pinned private release is
available. Use GITHUB_TOKEN only if it already exists in the process
environment; never print, persist, or include it or private response bodies in
evidence. If the private release is unavailable or the credential is missing,
finish the source-validation report and state the exact release-acquisition
blocker. Do not substitute locally built or unverified assets.

If the release is available, run packaging/Get-AOOfficePoolRelease.ps1 into a
new relative downloads directory. Require the exact closed eight-file set and
all pinned hashes. Extract the authenticated archive into a new directory,
switch authority to its README-FIRST.md, select a new fixed local NTFS install
directory, install, and run Verify-AOOfficePool.ps1. Confirm all five offices
are free and that fresh install-local governance and recovery state was
created. Do not start office work, uninstall the verified installation,
publish a release, push changes, or change repository visibility.

Return the checkout commit, environment checks, source-test results, release
availability, acquired identities when applicable, install path, verification
state, limitations, and the exact next action. Do not claim publication,
production readiness, or office-operation coverage.
```

## Acquire the private release

Start in a clean clone of this repository. Use PowerShell 7 on Windows, provide
a GitHub credential with read access to the private repository through
`GITHUB_TOKEN`, and do not print or save its value in evidence.

```powershell
$env:GITHUB_TOKEN = Read-Host 'GitHub read credential' -MaskInput
./packaging/Get-AOOfficePoolRelease.ps1 -Destination (Join-Path (Get-Location) 'downloads')
Remove-Item Env:GITHUB_TOKEN
```

The acquisition script pins the private repository, release tag, source commit,
Windows architecture, candidate-manifest identity, and exact eight release
asset names. It validates GitHub metadata before downloading, verifies the
external candidate manifest before trusting its seven metadata rows, and
copies only hash-matching assets with create-only writes.

On success, extract the already authenticated archive into a new sibling
directory and switch to its archive-first instructions:

```powershell
Expand-Archive -LiteralPath ./downloads/ao-office-pool-developer-preview.zip `
  -DestinationPath ./verified-preview
Set-Location ./verified-preview
Get-Content ./README-FIRST.md
```

Continue with [README-FIRST](README-FIRST.md). For a short path use the
[quickstart](docs/QUICKSTART.md); an AI operator must follow the normative
[AI operator runbook](docs/AI_OPERATOR_RUNBOOK.md). Installer internals and
recovery behavior are in the [operator guide](docs/OPERATOR_GUIDE.md).

## Supported boundary

- Private GitHub release; no public release or public repository workflow.
- Windows x86-64 and PowerShell 7.
- Fixed local NTFS installation directory, never a share, link, junction,
  reparse point, volume root, or ambiguous alias.
- Five offices named O1 through O5.
- Manual, authenticated acquisition and explicit install/verify/uninstall.

This preview does not provide a user-facing office lifecycle command or a
standardized endurance runner. Installation verifies package integrity; it
does not grant operational office authority, start work, or publish anything.
The archive contains no initialized mutable office state or reusable secrets;
the installer creates fresh per-install governance and recovery material on the
target machine.

## Release assets

The private release is a closed set: `candidate-manifest.json`, the preview ZIP,
its checksum sidecar, member inventory, provenance, release notes, SBOM, and
`SHA256SUMS`. Unexpected, missing, linked, renamed, or changed assets stop the
bootstrap.

Git tracks source, schemas, tests, sanitized fixtures, documentation, and
release contracts. It excludes credentials, private work state, raw API
responses, operator history, recovery material, and generated evidence.
