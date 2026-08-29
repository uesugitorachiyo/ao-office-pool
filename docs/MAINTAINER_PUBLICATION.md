# AO Office Pool v0.1.1 maintainer publication

This is an owner-only release procedure. End users should follow `README.md`.
Do not put credentials, authenticated headers, local absolute paths, audit
receipts, or raw GitHub administration output in Git.

`v0.1.0 is unsupported and superseded` by v0.1.1. Preserve its tag and asset
bytes. Change only its release title and description after v0.1.1 exists.

## Required environment

- Windows x86-64, Python 3.12, PowerShell 7, Git, and a fixed local NTFS task
  root.
- Visual Studio Build Tools 2022 with Desktop development with C++ for source
  qualification only.
- An absolute, regular, non-reparse component root containing the eight exact
  files in `manifests/components.lock.json` at
  `<root>/<name>/<version>/<asset>`.
- Repository-owner GitHub access for the external mutation steps. Keep tokens
  outside commands and evidence. A signed-in browser is acceptable.
- New empty build, evidence, extraction, installation, and clone directories.

Stop on any nonzero command, unexpected skip, scanner finding, hash drift,
unresolved audit row, residue, or repository-state mismatch.

## 1. Freeze and qualify source

Start in the candidate repository root. Require a clean default branch and
record the exact source commit without printing unrelated configuration:

```powershell
$Python = (Get-Command python.exe -CommandType Application -ErrorAction Stop |
  Select-Object -First 1).Source
& $Python -c "import sys; assert sys.version_info[:2] == (3, 12)"
if ($LASTEXITCODE -ne 0) { throw 'python-version' }

$SourceRoot = (Resolve-Path .).Path
$SourceCommit = (git rev-parse HEAD).Trim()
if (git status --porcelain) { throw 'source-not-clean' }

& $Python -B -m tests.windows_compiler
if ($LASTEXITCODE -ne 0) { throw 'compiler-not-ready' }
& $Python -B scripts/scan_public_tree.py .
if ($LASTEXITCODE -ne 0) { throw 'current-tree-not-clean' }
& $Python -B scripts/scan_git_history.py .
if ($LASTEXITCODE -ne 0) { throw 'history-not-clean' }
```

Both scanners must report zero findings. The complete-history result is a hard
gate; do not hand-curate around a finding.

Run the supervised native suite with a new short task root on fixed local NTFS:

```powershell
$RunId = [Guid]::NewGuid().ToString('N')
$QualificationRoot = Join-Path $env:USERPROFILE 'AOQ'
$EvidenceRoot = Join-Path $QualificationRoot "$RunId-evidence"
$TaskRoot = Join-Path $QualificationRoot "$RunId-task"
& $Python -B scripts/run_windows_tests.py `
  --evidence-dir $EvidenceRoot `
  --task-root $TaskRoot
if ($LASTEXITCODE -ne 0) { throw 'native-suite-failed' }
```

Require `result=PASS`, `worker_exit=0`, `worker_tree_ended=true`, and
`task_root_residue=false` in `summary.json`. Outcome skips must match the
documented platform or privilege cases; compiler-dependent skips do not
qualify.

## 2. Deterministic dual build

Use the qualified commit from a clean detached worktree. The component root and
all output paths must be absolute, regular, and non-reparse. Each output file
must be absent before invocation.

```powershell
$ComponentRoot = (Resolve-Path -LiteralPath `
  $env:AO_OFFICE_POOL_COMPONENT_ROOT).Path
$DetachedRoot = Join-Path $env:LOCALAPPDATA "AOOfficePoolSource-$SourceCommit"
$BuildA = Join-Path $env:LOCALAPPDATA "AOOfficePoolBuildA-$SourceCommit"
$BuildB = Join-Path $env:LOCALAPPDATA "AOOfficePoolBuildB-$SourceCommit"
$AssetName = 'ao-office-pool-v0.1.1-windows-x86_64.zip'

git worktree add --detach $DetachedRoot $SourceCommit
New-Item -ItemType Directory -Path $BuildA,$BuildB | Out-Null
& $Python -B scripts/build_public_release.py `
  --source $DetachedRoot --component-root $ComponentRoot `
  --output (Join-Path $BuildA $AssetName)
& $Python -B scripts/build_public_release.py `
  --source $DetachedRoot --component-root $ComponentRoot `
  --output (Join-Path $BuildB $AssetName)
if ($LASTEXITCODE -ne 0) { throw 'release-build-failed' }

$ArchiveA = Join-Path $BuildA $AssetName
$ArchiveB = Join-Path $BuildB $AssetName
$DigestA = (Get-FileHash -Algorithm SHA256 $ArchiveA).Hash.ToLowerInvariant()
$DigestB = (Get-FileHash -Algorithm SHA256 $ArchiveB).Hash.ToLowerInvariant()
if ($DigestA -cne $DigestB) { throw 'nondeterministic-release-hash' }
& "$env:SystemRoot\System32\fc.exe" /b $ArchiveA $ArchiveB
if ($LASTEXITCODE -ne 0) { throw 'nondeterministic-release-bytes' }
```

This deterministic dual build must also return the exact same `source_commit`
on both invocations.

Create the checksum sidecar with LF and no BOM:

```powershell
$Sidecar = "$DigestA  $AssetName`n"
[IO.File]::WriteAllText(
  "$ArchiveA.sha256", $Sidecar, [Text.UTF8Encoding]::new($false)
)
```

## 3. Freeze and verify the public contract

Create `manifests/public-release.json` as canonical UTF-8 JSON with exactly the
schema fields, `$SourceCommit`, archive size/hash, and sidecar size/hash. The
source commit precedes this metadata-only contract commit. Never add the ZIP or
sidecar to Git.

Run a schema parse for every shipped JSON schema and validate the exact assets:

```powershell
& $Python -B -c "import json,pathlib; [json.loads(p.read_text(encoding='utf-8')) for p in pathlib.Path('schemas').glob('*.json')]; print('schema parse=ok')"
& $Python -B -c "from pathlib import Path; from scripts.verify_bootstrap_contract import verify_public_release_contract; verify_public_release_contract(Path('manifests/public-release.json'), Path(r'$BuildA')); print('public-release-contract=verified')"
if ($LASTEXITCODE -ne 0) { throw 'public-contract-failed' }
```

Create a new extraction directory, expand the archive without executing it,
then perform the extracted archive scan and release-contract verification:

```powershell
$Extracted = Join-Path $env:LOCALAPPDATA "AOOfficePoolExtract-$SourceCommit"
Expand-Archive -LiteralPath $ArchiveA -DestinationPath $Extracted
& $Python -B scripts/scan_public_tree.py $Extracted
& $Python -B scripts/verify_release_contract.py $Extracted
if ($LASTEXITCODE -ne 0) { throw 'archive-verification-failed' }
```

Commit the finalized contract and maintainer documentation. Re-run focused
tests, compiler preflight, both scanners, bootstrap verification, the full
native suite, `git diff --check`, and require a clean worktree.

## 4. Private audit evidence

Keep audit evidence only under ignored `.local/publication-v0.1.1/`. Inventory
every existing release asset by name, size, and SHA-256. Extract archives
without execution and scan each tree. Record v0.1.0 as unsupported because its
old package lacks the final public licensing payload.

Inspect all GitHub-visible surfaces and record each as `clean`, `absent`, or
`blocked`: repository files and complete history, releases, tags, issues, pull
requests, discussions, wiki, Actions logs/artifacts/caches, packages, Pages,
environments, deploy keys, webhooks, branch rules, and repository settings.

Confirm redistribution rights for every locked AO Stack binary from its
authoritative repository/release and retain the source URL, version, commit,
license, asset name, and digest in private evidence. A lock-file license label
alone is insufficient.

Run the final security diff/repository review and privacy scan. Revoke any
secret before remediation. Do not publish while any row is unresolved. Write
`READY_FOR_PUBLICATION` only after every local, archive, license, security, and
GitHub-surface gate is clean.

## 5. Publish and read back

Immediately before mutation, repeat the clean-source, compiler, current-tree,
history, contract, deterministic-asset, and audit gates.

1. Push the reviewed default branch containing the finalized contract commit.
2. Create and push an annotated `v0.1.1` tag at `$SourceCommit`, not at the
   later metadata-only commit.
3. Create a non-draft, non-prerelease v0.1.1 release with exactly the archive
   and sidecar.
4. Perform release readback: tag peel target, release state, exact asset names,
   sizes, and freshly downloaded SHA-256 values.
5. Read `manifests/public-release.json` from the pushed default branch and
   compare it byte-for-byte with the reviewed local file.
6. Mark v0.1.0 historical, unsupported, and superseded without moving its tag
   or replacing its bytes.
7. Change only this repository to public. Enable secret scanning and push
   protection when GitHub exposes those settings, then read back visibility,
   default branch, tag, and release.

The required protection gate is `secret scanning and push protection`.

Stop on any readback drift. Never move the tag or replace published v0.1.1
asset bytes.

## 6. Unauthenticated Windows acceptance

Use a new fixed-local-NTFS directory and an unauthenticated clean clone. Ensure
the token variable is absent from the child environment; never print a token.

```powershell
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
git clone https://github.com/uesugitorachiyo/ao-office-pool.git
Set-Location ao-office-pool
pwsh -File .\scripts\Install-And-Verify.ps1
```

Require `READY FOR USE`, no credential prompt, exactly O1-O5, a successful O1
claim/resume/release smoke, and a final all-free status. Record the public
repository metadata, source/tag/asset identities, installer/verifier output,
lifecycle output, and residue check in the ignored final handback.

## Rollback

Before visibility changes, stop and leave the repository private. After public
exposure, assume exposed bytes were copied: changing visibility is containment,
not erasure. Revoke exposed credentials first. Mark a defective release as
withdrawn without replacing assets or moving its tag, return the repository to
private if containment is needed, preserve evidence, fix forward under a new
version, and repeat every gate. Never rewrite published history merely to hide
a functional defect.
