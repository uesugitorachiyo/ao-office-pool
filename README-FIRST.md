# Start here after verified acquisition

This directory was extracted only after
`packaging/Get-AOOfficePoolRelease.ps1` authenticated the private release and
verified the archive against the pinned external `candidate-manifest.json`.
This file does not authenticate the archive by itself. If you received only an
unverified ZIP, stop and return to the repository-root [acquisition
instructions](README.md#acquire-the-private-release).

## Install and verify

Requirements are Windows x86-64, PowerShell 7, and a fixed local NTFS install
directory. Run these commands from this verified extraction:

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

Both commands must finish successfully. Verification binds installed immutable
bytes to the independently retained archive and checksum. Installation does
not authorize operational office work, create a queue, start a service, or
publish a release. The archive carries no initialized mutable state or reusable
keys; installation creates fresh local authority and recovery material before
the new tree becomes active.

For an AI-driven setup, follow every gate in the [AI operator
runbook](docs/AI_OPERATOR_RUNBOOK.md). Humans may use the
[quickstart](docs/QUICKSTART.md) and consult the detailed
[operator guide](docs/OPERATOR_GUIDE.md).

## Remove the preview

Uninstall only when all five offices are free and verification succeeds:

```powershell
./packaging/Uninstall-AOOfficePool.ps1 -InstallRoot $InstallRoot `
  -Archive (Join-Path $DownloadRoot 'ao-office-pool-developer-preview.zip') `
  -ChecksumFile (Join-Path $DownloadRoot 'ao-office-pool-developer-preview.zip.sha256')
```

The uninstall script preserves the removed tree as a private recovery sibling.
Retention or deletion of that tree is a separate operator decision.

## Honest limitation

The package coordinates and verifies the five-office runtime layout, but it
does not yet expose a user-facing office lifecycle command or standardized
endurance runner. Do not invent a command, infer work authorization from
installation, or report an office operation that was not directly observed.
