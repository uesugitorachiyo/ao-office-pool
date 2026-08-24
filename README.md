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

## Release assets

The private release is a closed set: `candidate-manifest.json`, the preview ZIP,
its checksum sidecar, member inventory, provenance, release notes, SBOM, and
`SHA256SUMS`. Unexpected, missing, linked, renamed, or changed assets stop the
bootstrap.

Git tracks source, schemas, tests, sanitized fixtures, documentation, and
release contracts. It excludes credentials, private work state, raw API
responses, operator history, recovery material, and generated evidence.
