# Windows private-preview quickstart

Use Windows x86-64, PowerShell 7, a clean repository checkout, and a fixed
local NTFS destination. This path acquires a private release; it does not
publish or authorize office work.

## 1. Acquire from the repository root

Give `GITHUB_TOKEN` read access to the private repository without printing it:

```powershell
$env:GITHUB_TOKEN = Read-Host 'GitHub read credential' -MaskInput
./packaging/Get-AOOfficePoolRelease.ps1 -Destination (Join-Path (Get-Location) 'downloads')
Remove-Item Env:GITHUB_TOKEN
```

The command succeeds only when repository visibility, tag, source commit,
asset hosts, candidate identity, the exact eight-asset set, sizes, and hashes
match the package-owned contract.

If no `GITHUB_TOKEN` is available, use an already authenticated private GitHub
browser or approved GitHub client to download all eight release assets into one
new directory. Download no source snapshot and add no extra file. Then run the
same verifier/acquirer without test mode:

```powershell
./packaging/Get-AOOfficePoolRelease.ps1 `
  -OfflineAssetRoot ./manual-private-download `
  -Destination (Join-Path (Get-Location) 'downloads')
```

This is only an alternate authenticated transport. The package-owned contract,
tag/source binding, candidate manifest, exact asset set, sizes, and hashes are
still mandatory.

## 2. Extract only the verified archive

```powershell
Expand-Archive -LiteralPath ./downloads/ao-office-pool-developer-preview.zip `
  -DestinationPath ./verified-preview
Set-Location ./verified-preview
```

The external candidate manifest authenticated the archive before extraction.
Continue with [README-FIRST](../README-FIRST.md), which contains the relative
`Install-AOOfficePool.ps1`, `Verify-AOOfficePool.ps1`, and
`Uninstall-AOOfficePool.ps1` commands.

## 3. Decide from evidence

Use [the AI runbook](AI_OPERATOR_RUNBOOK.md) for a machine-operated setup. Each
gate ends in exactly one decision:

- `CONTINUE` when the expected deterministic evidence is present.
- `REPAIR` when an authorized, bounded, reversible correction is available.
- `HOLD` when evidence conflicts, privacy fails, or more authority is needed.

Keep the verified downloads outside the extraction and installation so they
remain an independent anchor. Never use credential values or raw API responses
as evidence.
