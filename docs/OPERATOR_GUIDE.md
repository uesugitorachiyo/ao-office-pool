# AO Office Pool developer-preview operator guide

This guide describes installer mechanics for the private Windows x86-64
developer preview. Begin with repository-root [authenticated
acquisition](../README.md#acquire-the-private-release), or use the closed gates
in the [AI operator runbook](AI_OPERATOR_RUNBOOK.md). The guide grants no
authority to publish, call unrelated providers, or start office work.

## Prerequisites and paths

Use PowerShell 7 and a fixed local NTFS drive. Do not use a volume root, UNC
path, link, junction, reparse point, or short-name alias. Keep the verified
archive and checksum outside both the extraction and installation.

From the verified extraction establish portable variables:

```powershell
$BootstrapRoot = (Get-Location).Path
$DownloadRoot = (Resolve-Path (Join-Path $BootstrapRoot '..\verified-assets')).Path
$InstallRoot = Join-Path $env:LOCALAPPDATA 'AOOfficePool'
$Archive = Join-Path $DownloadRoot 'ao-office-pool-developer-preview.zip'
$Sidecar = Join-Path $DownloadRoot 'ao-office-pool-developer-preview.zip.sha256'
```

Acquisition emits one compressed JSON object with schema version, mode,
repository, tag, product source commit, architecture, portable destination,
and exact name/size/hash rows. Installer and verifier commands exit nonzero on
failure; their successful structured results may be retained after removing
private paths and live state.

## Integrity model

The sidecar contains one SHA-256 digest and archive filename. The archive root
contains `developer-preview-manifest.json`, which binds every immutable member
except itself by relative path, size, and digest. Governed mutable state is
checked separately for exactly O1, O2, O3, O4, and O5 in the all-free shape.
The archive contains only the empty mutable directory template. During staging,
the installer creates fresh governance and recovery keys, authenticated runtime
state, generations, office states, pool metadata, and the pool lock. No
install-local authority material is shared between builds or installations.

The scripts reject missing or extra immutable files, changed size or digest,
traversal, duplicate names, reparse points, path ambiguity, a pending runtime
transaction, or an occupied office. The `source-present` state does not establish executable,
accepted, activated, routed, or authorized capability.

## Install and verify

```powershell
./packaging/Install-AOOfficePool.ps1 -Action Install -Archive $Archive `
  -ChecksumFile $Sidecar -InstallRoot $InstallRoot
./packaging/Verify-AOOfficePool.ps1 -InstallRoot $InstallRoot `
  -Archive $Archive -ChecksumFile $Sidecar
```

The installer keeps one checked archive handle through member validation and
extraction, verifies staged immutable bytes, takes the pool byte-range lock,
checks all offices free again, and records a private sibling recovery
transaction before replacement. A later invocation restores the accepted
prior tree when it finds an interrupted replacement.

Installation does not start a service, create a queue, schedule work, or grant
operational office authority. This preview has no user-facing office lifecycle
command and no standardized endurance runner.

## Update and rollback

An update uses a newly acquired and verified private archive. Rollback uses a
previously accepted archive and sidecar:

```powershell
./packaging/Install-AOOfficePool.ps1 -Action Update -Archive $Archive `
  -ChecksumFile $Sidecar -InstallRoot $InstallRoot
./packaging/Install-AOOfficePool.ps1 -Action Rollback -Archive $Archive `
  -ChecksumFile $Sidecar -InstallRoot $InstallRoot
```

The archive runtime version must equal the active governed runtime version.
Package activation does not change that version. Update and rollback replace
immutable members only, preserving accepted mutable bytes and the physical pool
lock identity.

After replacement, retain the reported prior tree until verification and the
authorized pilot finish. If replacement fails after the first rename, the
installer restores the prior tree and preserves the rejected staging sibling.
Do not merge or delete either tree before recording the private incident.

## Recovery stops

Stop for an occupied office, `recovery-required`, a pending runtime transition,
unknown bytes, checksum mismatch, or path ambiguity. Do not edit trusted
metadata to make a changed tree pass. Keep unknown bytes in place, use the
accepted prior archive for rollback, and record only sanitized evidence.

There is no network or background updater. Every archive is supplied and
verified explicitly.

## Uninstall

Verify first, then uninstall only while all five offices are free:

```powershell
./packaging/Verify-AOOfficePool.ps1 -InstallRoot $InstallRoot `
  -Archive $Archive -ChecksumFile $Sidecar
./packaging/Uninstall-AOOfficePool.ps1 -InstallRoot $InstallRoot `
  -Archive $Archive -ChecksumFile $Sidecar
```

Uninstall verifies manifest-bound bytes and all-free state, then atomically
renames the installation to a private recovery sibling. Deleting that preserved
tree requires a separate retention decision.

## Qualification limit

Portable tests establish structure and fail-closed ordering. Only native
Windows execution on the required local NTFS boundary establishes filesystem
identity behavior. A successful bootstrap proves package acquisition,
integrity, installation, and verification only; it does not prove or authorize
end-to-end office work.
