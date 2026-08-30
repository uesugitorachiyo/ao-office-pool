# AO Office Pool v0.1.3

AO Office Pool coordinates five isolated offices, O1 through O5, over one
immutable AO Stack runtime. It supports Windows x86-64 only; macOS and Linux
are outside the supported boundary.

AO Office Pool is an independent project and not currently an official member of the AO Stack family.

## Requirements

- Windows x86-64 on a fixed local NTFS volume
- PowerShell 7 or newer (`pwsh`)
- Exactly Python 3.12 (`python.exe`)
- Git for Windows (`git.exe`)
- `VCRUNTIME140.dll` present in the Windows system directory (normally
  supplied by the
  [Microsoft Visual C++ x64 Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170))

The installer checks for the presence of `VCRUNTIME140.dll` in the Windows system directory; it does not verify a redistributable product or version. It
also checks the platform, executable versions, and paths before installation.
Use ordinary local, non-reparse paths under the current user's local
application-data directory. The defaults are on the same fixed local NTFS
volume and require a new installation root.

## Install

Open PowerShell 7 and paste this block:

```powershell
git clone https://github.com/uesugitorachiyo/ao-office-pool.git
Set-Location .\ao-office-pool
pwsh -File .\scripts\Install-And-Verify.ps1
```

That one script acquires the two public v0.1.3 assets, independently checks the
release contract, archive, and sidecar, installs into a new private local root,
verifies the installed bytes, creates a disposable Git project, and exercises
an O1 claim/resume/release lifecycle. The assets are:

- `ao-office-pool-v0.1.3-windows-x86_64.zip`
- `ao-office-pool-v0.1.3-windows-x86_64.zip.sha256`

Exact success ends with a self-contained `Launcher:` command, the command list,
and `READY FOR USE`. Any incomplete or unsafe result exits nonzero and writes a
privacy-safe `HOLD [reason-code]` line. Stop at that first reason code; do not
edit metadata, bypass verification, or substitute another archive.

The ordinary public path needs no GitHub credential, authenticated API call,
or compiler toolchain.

## Copy-paste prompt for a Windows AI

After cloning the repository, paste this prompt into a Windows AI task opened
in the clone:

```text
Install and verify AO Office Pool v0.1.3 for this Windows user.

Read README.md and docs/AI_OPERATOR_RUNBOOK.md completely before acting. Work
only in this checkout and in the installer-created local paths. Confirm this is
Windows x86-64 and that PowerShell 7, exactly Python 3.12, Git, a fixed local
NTFS volume, and VCRUNTIME140.dll are available.

Then run scripts/Install-And-Verify.ps1 unchanged from PowerShell 7. Do not
reimplement acquisition, extraction, installation, verification, or the smoke
lifecycle. Do not request credentials, call an authenticated API, install a
contributor compiler toolchain, replace manifests, or weaken a failed check.

If the script exits zero and ends with READY FOR USE, return its exact
self-contained Launcher command unchanged and confirm that O1 through O5
finished free. Otherwise return HOLD with the exact reported reason code and
the next safe corrective action for that reason code. This applies to
non-prerequisite failures such as `installation-failed`, not only missing
prerequisites. Keep absolute developer paths, receipts, recovery keys, secrets,
and raw child output out of the response.
```

## Use the five offices

The installer prints a `Launcher:` line that is ready to paste into a new
PowerShell shell. With the default installation, the equivalent setup is:

```powershell
$InstallRoot = Join-Path $env:USERPROFILE '.ao-office-pool-private\AOOfficePool'
$Office = Join-Path $InstallRoot 'bin\ao-office-pool.ps1'
```

Use a real Git project outside the AO Office Pool installation. A fresh pool
uses O1-first allocation. `claim` returns JSON containing `authority_path`,
`office_id`, and `generation`; retain that receipt only until release.

```powershell
& $Office status
$Claim = & $Office claim --owner 'operator-1' --task 'work-item-1' --project (Resolve-Path .).Path --mode conversation | ConvertFrom-Json
& $Office resume --receipt $Claim.authority_path
$Envelope = (Resolve-Path -LiteralPath (Read-Host 'Exact witness path returned by AO governance')).Path
& $Office run --receipt $Claim.authority_path --envelope $Envelope --timeout 30
& $Office release --receipt $Claim.authority_path
```

`run` requires the exact witness path returned by the AO governance issuance
workflow for this claim. The path must be under
`.ao\governance\office-pool` in the claimed project and its filename has the
form `witness-<32-lowercase-hex>.json`; do not invent or guess it.

`recover` is not a normal release command. Only after an exact
`recovery-required` result, use the office and generation returned by that
claim:

```powershell
$RecoveryKey = Join-Path $InstallRoot "operator-secrets\recovery-key-$($Claim.office_id)"
& $Office recover --key $RecoveryKey --office $Claim.office_id --generation $Claim.generation
& $Office status
```

Check `status` after work and require exactly O1 through O5 to be free.

See [the quickstart](docs/QUICKSTART.md) for the shortest reminder and
[the operator guide](docs/OPERATOR_GUIDE.md) for lifecycle, recovery, update,
rollback, and uninstall details.

## Contributor source qualification

Visual Studio Build Tools 2022 with the Desktop development with C++ workload
is for source qualification only. It is not required to install or use the
published AO Office Pool package. Source qualification compiles native test
fixtures; the end-user runtime check only requires the DLL presence described
above.

From a clean source checkout, use a new short task root on fixed local NTFS:

```powershell
$Python = (Get-Command python.exe -CommandType Application -ErrorAction Stop |
  Select-Object -First 1).Source
& $Python -c "import sys; assert sys.version_info[:2] == (3, 12)"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 is required.' }

$QualificationRoot = Join-Path $env:USERPROFILE 'AOQ'
$QualificationDrive = [IO.DriveInfo]::new(
  [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($QualificationRoot))
)
if (-not $QualificationDrive.IsReady -or
    $QualificationDrive.DriveType -ne [IO.DriveType]::Fixed -or
    $QualificationDrive.DriveFormat -cne 'NTFS') {
  throw 'task-root-volume-not-fixed-ntfs'
}
$RunId = [Guid]::NewGuid().ToString('N')
$SourceRoot = (Resolve-Path .).Path
$EvidenceRoot = Join-Path $QualificationRoot "$RunId-evidence"
$TaskRoot = Join-Path $QualificationRoot "$RunId-task"
$PublicArchive = Join-Path $QualificationRoot "$RunId-public.zip"
$PublicTree = Join-Path $QualificationRoot "$RunId-public"
New-Item -ItemType Directory -Path $QualificationRoot -Force | Out-Null
foreach ($Path in @($EvidenceRoot, $TaskRoot, $PublicArchive, $PublicTree)) {
  if (Test-Path -LiteralPath $Path) { throw 'qualification path already exists' }
}

& $Python -B -m tests.windows_compiler
if ($LASTEXITCODE -ne 0) { throw 'Windows compiler preflight failed.' }
& $Python -B -c "import sys; from pathlib import Path; from scripts.build_release import build_release; build_release(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))" `
  $SourceRoot $PublicArchive (Join-Path $SourceRoot 'manifests\public-tree.json')
if ($LASTEXITCODE -ne 0) { throw 'Public projection build failed.' }
Expand-Archive -LiteralPath $PublicArchive -DestinationPath $PublicTree
& $Python -B scripts/scan_public_tree.py $PublicTree
if ($LASTEXITCODE -ne 0) { throw 'Public-tree scan failed.' }
& $Python -B scripts/verify_bootstrap_contract.py $PublicTree
if ($LASTEXITCODE -ne 0) { throw 'Bootstrap verification failed.' }
& $Python -B scripts/run_windows_tests.py `
  --evidence-dir $EvidenceRoot `
  --task-root $TaskRoot
if ($LASTEXITCODE -ne 0) { throw 'Supervised Windows test run failed.' }
```

Qualification requires `windows-c-compiler=ready`, `public-tree findings=0`,
and a runner summary with result `PASS`, zero worker exit, and no task-root
residue. Compiler-dependent skips do not qualify. `task-root-too-long` or
`task-root-volume-not-fixed-ntfs` means choose a new shorter drive-absolute
fixed-local-NTFS root and rerun from the beginning. Each run uses a new ID and
keeps its evidence and manifest-built public projection outside the checkout,
so a failed run does not contaminate the next public-tree scan.

Advanced publication and deep qualification are maintainer concerns, not
installation steps. AI operators should follow
[the AI operator runbook](docs/AI_OPERATOR_RUNBOOK.md); archive readers should
start with [README-FIRST.md](README-FIRST.md).
