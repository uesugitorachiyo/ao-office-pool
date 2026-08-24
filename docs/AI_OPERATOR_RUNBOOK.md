# Normative AI operator runbook

This runbook is the closed Windows bootstrap procedure. Execute gates G00
through G09 in order. At every gate choose exactly one result: `CONTINUE`,
`REPAIR`, or `HOLD`. Never treat a later success as evidence that a skipped
gate passed.

## G00 Authority

**Authority:** Read local files and perform the explicitly requested private
bootstrap. Publishing, provider changes, new credentials, and office work are
not implied.

**Command:** `Get-Content ./docs/AI_OPERATOR_RUNBOOK.md`

**Expected:** The task identifies Windows bootstrap as the outcome and permits
the necessary local install actions.

**Stop:** Choose `HOLD` if the requested destination, credential use, install,
or cleanup exceeds stated authority.

**Evidence:** A sanitized statement of permitted actions and exclusions.

**Next:** `CONTINUE` to G01, or `HOLD` for missing authority. Do not invent
authority as a repair.

## G01 Prerequisites

**Authority:** Read host and tool properties only.

**Command:**

```powershell
$PSVersionTable.PSVersion
[Runtime.InteropServices.RuntimeInformation]::OSArchitecture
```

**Expected:** PowerShell 7 or newer on Windows x86-64.

**Stop:** Choose `HOLD` for another platform or architecture. Choose `REPAIR`
only if installing an approved PowerShell version is already authorized.

**Evidence:** Version and architecture text without user paths or process data.

**Next:** `CONTINUE` to G02 when prerequisites match.

## G02 Workspace isolation

**Authority:** Create one new task directory; do not remove or reuse unknown
content.

**Command:**

```powershell
$BootstrapRoot = (Get-Location).Path
Get-ChildItem -LiteralPath $BootstrapRoot -Force
```

**Expected:** A clean private repository checkout with no downloads,
installation state, recovery siblings, or unknown generated files.

**Stop:** Choose `HOLD` for links, junctions, reparse points, unknown files, or
an occupied destination. Choose `REPAIR` by selecting a new empty directory.

**Evidence:** Repository commit identity and a sanitized relative file list.

**Next:** `CONTINUE` to G03 only from an isolated workspace.

## G03 Authentication

**Authority:** Use one existing GitHub read credential for the named private
repository. Do not broaden its permissions or store it in a file.

**Command:**

```powershell
$env:GITHUB_TOKEN = Read-Host 'GitHub read credential' -MaskInput
```

**Expected:** The environment value is non-empty and is never displayed.

**Stop:** Choose `HOLD` if access is unavailable or needs a new authorization.
Choose `REPAIR` only by obtaining an approved least-privilege credential.

**Evidence:** Record only that authentication was supplied, never its value or
a raw authenticated response.

**Next:** `CONTINUE` to G04 with the credential confined to this process.

## G04 Acquisition

**Authority:** Read GitHub metadata and release bytes from the contract-pinned
private repository and tag.

**Command:**

```powershell
$DownloadRoot = Join-Path $BootstrapRoot 'downloads'
./packaging/Get-AOOfficePoolRelease.ps1 -Destination $DownloadRoot
```

**Expected:** One compressed JSON object reports authenticated mode, the pinned
repository/tag/source identity, Windows architecture, a portable destination,
and exactly eight asset rows.

**Stop:** Choose `HOLD` for metadata drift, unexpected hosts, digest mismatch,
or a nonempty destination. Partial downloads are not accepted evidence.

**Evidence:** The sanitized JSON result plus exit code; exclude credential
values, headers, response bodies, and developer-absolute paths.

**Next:** `CONTINUE` to G05 on an exact success. `REPAIR` uses a new empty
destination after diagnosing a bounded local cause.

## G05 Asset verification

**Authority:** Re-read only the acquired local assets and create a separate
verified copy.

**Command:**

```powershell
$VerifiedRoot = Join-Path $BootstrapRoot 'verified-assets'
./packaging/Get-AOOfficePoolRelease.ps1 -OfflineAssetRoot $DownloadRoot `
  -Destination $VerifiedRoot
```

**Expected:** One compressed JSON object reports offline mode and the same
eight names, sizes, and SHA-256 values. The candidate manifest is verified
before its seven metadata rows are trusted.

**Stop:** Choose `HOLD` for any missing, extra, linked, renamed, or changed
asset. Digest disagreement is never repaired by editing a manifest or checksum.

**Evidence:** Offline verifier output and exit code. The files themselves remain
the independent evidence anchor.

**Next:** `CONTINUE` to G06 on exact agreement; otherwise reacquire into new
directories under `REPAIR` or choose `HOLD`.

## G06 NTFS install-root selection

**Authority:** Inspect and select a package-owned local installation directory.

**Command:**

```powershell
$InstallRoot = Join-Path $env:LOCALAPPDATA 'AOOfficePool'
$InstallDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($InstallRoot))
$InstallDrive.DriveType
$InstallDrive.DriveFormat
```

**Expected:** A fixed local NTFS drive and an absent install path. The path is
not a volume root, share, link, junction, reparse point, or short-name alias.

**Stop:** Choose `HOLD` for an occupied or ambiguous path. Choose `REPAIR` by
selecting a new authorized empty local NTFS directory, never by deleting
unknown bytes.

**Evidence:** Drive type, format, and a portable final directory name.

**Next:** `CONTINUE` to G07 when the boundary is unambiguous.

## G07 Install

**Authority:** Install immutable package files and initialize only the
package-owned five-office layout.

**Command:**

```powershell
$Archive = Join-Path $VerifiedRoot 'ao-office-pool-developer-preview.zip'
$Sidecar = Join-Path $VerifiedRoot 'ao-office-pool-developer-preview.zip.sha256'
Expand-Archive -LiteralPath $Archive -DestinationPath (Join-Path $BootstrapRoot 'verified-preview')
Set-Location (Join-Path $BootstrapRoot 'verified-preview')
./packaging/Install-AOOfficePool.ps1 -Action Install -Archive $Archive `
  -ChecksumFile $Sidecar -InstallRoot $InstallRoot
```

**Expected:** Installation succeeds after checksum, archive, immutable manifest,
exact-tree, all-free, path, and local NTFS checks.

**Stop:** Choose `HOLD` for a recovery marker, active office, unknown file,
runtime mismatch, or manifest disagreement. Do not merge staged trees.

**Evidence:** Sanitized installer result, source commit, archive digest, and
install action; omit live office state.

**Next:** `CONTINUE` to G08. Use `REPAIR` only through the installer's documented
recovery behavior in the [operator guide](OPERATOR_GUIDE.md).

## G08 Verify and status boundary

**Authority:** Verify installed bytes and read the documented capability
boundary; do not start office work.

**Command:**

```powershell
./packaging/Verify-AOOfficePool.ps1 -InstallRoot $InstallRoot `
  -Archive $Archive -ChecksumFile $Sidecar
```

**Expected:** Verification succeeds against the retained archive and checksum,
and all five offices have the accepted free-state shape.

**Stop:** Choose `HOLD` for any drift or unavailable independent anchor. A
successful install is not a substitute for this gate.

**Evidence:** Verifier result and immutable identities. The preview has no
user-facing lifecycle status command, so do not fabricate one.

**Next:** `CONTINUE` to G09 when verified. Choose `REPAIR` through an authorized
rollback or clean reinstall; otherwise `HOLD`.

## G09 Evidence and cleanup

**Authority:** Remove the process credential and retain only sanitized release
evidence. Do not uninstall unless separately requested.

**Command:**

```powershell
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath $VerifiedRoot | Select-Object -ExpandProperty Name
```

**Expected:** No GitHub credential remains in the process. Evidence identifies
the product commit, candidate identity, archive digest, gate decisions, and
known limitations without private state.

**Stop:** Choose `HOLD` if evidence contains credential material, raw API data,
developer-absolute paths, or live office data. Sanitize under `REPAIR` without
altering the immutable release anchors.

**Evidence:** A bounded gate summary with source identities and `CONTINUE`,
`REPAIR`, or `HOLD` as the final decision.

**Next:** Hand off the verified installation. Publication and operational
office authorization remain separate actions.

## Offline or manually authenticated acquisition

When another authorized mechanism has downloaded the eight private release
assets, place only those files in a new directory and run the G05 offline
command with that directory as `-OfflineAssetRoot`. Test mode is not used. The
same package-owned contract, candidate-manifest identity, closed asset set,
sizes, and hashes are mandatory. Manual acquisition does not weaken any gate.

## Bounded recovery

| Symptom | Required decision |
| --- | --- |
| Partial download or failed network request | `REPAIR` by reacquiring all assets into a new empty directory; never merge sets. |
| Occupied acquisition or install destination | `HOLD`, inspect ownership, then select a new empty authorized directory. |
| Installer recovery marker | `HOLD` and follow the accepted prior-tree recovery described in the operator guide. |
| Unknown file or reparse point | `HOLD`; preserve it for investigation and do not delete it as bootstrap cleanup. |
| Any digest disagreement | `HOLD`; reacquire from the pinned release or escalate. Never rewrite trusted metadata. |

The handoff must identify the gate reached, direct evidence, exact bounded
blocker, next safe action, and whether the final decision is `CONTINUE`,
`REPAIR`, or `HOLD`.
