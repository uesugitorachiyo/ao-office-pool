# AO Office Pool v0.1.3 operator guide

Begin with the public [installation block](../README.md#install). The supported
entry point is `scripts/Install-And-Verify.ps1`; it acquires and authenticates
`ao-office-pool-v0.1.3-windows-x86_64.zip` and
`ao-office-pool-v0.1.3-windows-x86_64.zip.sha256`, installs, verifies, and
proves an all-free O1 lifecycle before reporting `READY FOR USE`.

The normal user path needs no credential or authenticated API. Maintainers with
already retained assets may use the lower-level packaging scripts for audited
offline, update, rollback, or recovery work, but those are not substitutes for
the ordinary public installation path.

## Installed launcher

Paste the exact self-contained `Launcher:` command printed by the installer.
For the default installation it resolves to:

```powershell
$InstallRoot = Join-Path $env:USERPROFILE '.ao-office-pool-private\AOOfficePool'
$Office = Join-Path $InstallRoot 'bin\ao-office-pool.ps1'
& $Office status
```

The launcher requires exactly Python 3.12. Commands emit one bounded JSON object
and use exit zero for success, 2 for an operational error, and 3 for an internal
error.

## Claim, resume, run, and release

Use a Git connected project outside the AO Office Pool installation. A new pool
allocates O1 first. Keep the returned `authority_path` private and retain it only
for the claim lifetime.

```powershell
$ProjectRoot = (Resolve-Path .).Path
$Claim = & $Office claim --owner 'operator-1' --task 'work-item-1' --project $ProjectRoot --mode conversation | ConvertFrom-Json
& $Office resume --receipt $Claim.authority_path
$Envelope = (Resolve-Path -LiteralPath (Read-Host 'Exact witness path returned by AO governance')).Path
& $Office run --receipt $Claim.authority_path --envelope $Envelope --timeout 30
& $Office release --receipt $Claim.authority_path
& $Office status
```

`run` requires the exact witness path returned by the AO governance issuance
workflow. It must be under `.ao\governance\office-pool` in the claimed project
and named `witness-<32-lowercase-hex>.json`; never guess a witness path.
Installation alone does not authorize office work. Release promptly and
confirm O1, O2, O3, O4, and O5 are all free.

## Recovery

`recover` is exceptional. Use it only after the lifecycle returns
`recovery-required`, with the exact current office and generation and the
install-local key:

```powershell
$RecoveryKey = Join-Path $InstallRoot "operator-secrets\recovery-key-$($Claim.office_id)"
& $Office recover --key $RecoveryKey --office $Claim.office_id --generation $Claim.generation
& $Office status
```

Preserve incident evidence without copying the key or receipt. Recovery is not
a way to bypass receipt, generation, or identity checks.

## Verified offline install, update, and rollback

Advanced maintainers may supply an independently retained trusted archive and
sidecar to the packaging scripts. Keep both outside the extraction and install
roots. Install requires a new `InstallRoot`. Update and Rollback require the existing `InstallRoot`. Every supplied path must be drive-absolute on local
NTFS:

```powershell
./packaging/Install-AOOfficePool.ps1 -Action Install -Archive $Archive -ChecksumFile $Sidecar -InstallRoot $InstallRoot
./packaging/Verify-AOOfficePool.ps1 -InstallRoot $InstallRoot -Archive $Archive -ChecksumFile $Sidecar
./packaging/Install-AOOfficePool.ps1 -Action Update -Archive $Archive -ChecksumFile $Sidecar -InstallRoot $InstallRoot
./packaging/Install-AOOfficePool.ps1 -Action Rollback -Archive $Archive -ChecksumFile $Sidecar -InstallRoot $InstallRoot
```

These commands do not acquire or establish trust in assets. The archive and
sidecar must already be contract-bound and authenticated. Update and rollback
require all offices free and preserve governed mutable state. Retain any prior
or rejected sibling until verification and incident review finish.

## Uninstall

Uninstall is not part of setup. Verify first and require all five offices free:

```powershell
./packaging/Verify-AOOfficePool.ps1 -InstallRoot $InstallRoot -Archive $Archive -ChecksumFile $Sidecar
./packaging/Uninstall-AOOfficePool.ps1 -InstallRoot $InstallRoot -Archive $Archive -ChecksumFile $Sidecar
```

Uninstall renames the installation to a recovery sibling. Deleting that sibling
is a separate retention decision.

## Qualification boundary

Windows x86-64, PowerShell 7, exactly Python 3.12, Git, `VCRUNTIME140.dll`
present in the Windows system directory, and fixed local NTFS are runtime
prerequisites. The installer checks DLL presence, not a redistributable product
or version.
Visual Studio Build Tools 2022 is source-qualification-only and is not required
to install or use the published package.

The `source-present` state does not establish executable, tested, accepted,
activated, routed, or authorized capability.
